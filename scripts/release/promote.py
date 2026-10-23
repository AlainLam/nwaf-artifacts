#!/usr/bin/env python3
"""Promote an authenticated source-bridge receipt in the public artifact repository."""
import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import tempfile
import urllib.request

from evidence import ASSETS, POLICY, REPOSITORY, load_candidate, read, require, timestamp, verify_evidence
from github import GitHub
from handoff import TRANSFER_FILES, verify_receipt


def check_environment(github):
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY and os.environ.get('GITHUB_REF') == 'refs/heads/main',
            'stable promotion must run on the public artifact repository main branch')
    environment = github.request('GET', 'environments/release-stable')
    require(environment.get('deployment_branch_policy') and any(
        r.get('type') == 'required_reviewers' and r.get('reviewers') for r in environment.get('protection_rules', [])),
        'stable promotion requires branch protection and manual environment reviewers')


def current_candidate(github, directory, ref):
    for name in ('candidate.json', 'manifest.json', 'inventory.json', 'qualification-policy.json'):
        require(github.content('candidate/' + name, ref)[0] == (directory / name).read_bytes(),
                'current public candidate differs from the qualified receipt')


def promote(github, directory, receipt_sha256):
    receipt = verify_receipt(directory, receipt_sha256)
    candidate, manifest, _ = load_candidate(directory)
    now = datetime.now(timezone.utc)
    require(timestamp(read(directory / 'evidence.json')['created_at']) <= timestamp(receipt['verified_at']) <= now + timedelta(minutes=5),
            'source bridge receipt timestamp is invalid')
    verify_evidence(directory, directory / 'evidence.json', candidate['source_commit'],
                    verified_reports=dict(receipt['verified_reports']))
    snapshot = github.request('GET', 'git/ref/heads/main')['object']['sha']
    current_candidate(github, directory, snapshot)
    for bundle in manifest['bundles']:
        github.asset(github.release(bundle['version'], create=False), bundle)
    current_candidate(github, directory, snapshot)
    return github.update_files({'stable/manifest.json': (directory / 'manifest.json').read_bytes()},
                               'Promote qualified bundle catalog', expected_parent=snapshot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--qualification-tag', required=True)
    parser.add_argument('--receipt-sha256', required=True)
    args = parser.parse_args()
    require(re.fullmatch(r'qualification-[1-9][0-9]*-[1-9][0-9]*', args.qualification_tag), 'invalid qualification receipt tag')
    github = GitHub(REPOSITORY, os.environ.get('GITHUB_TOKEN'))
    check_environment(github)
    release = github.named_release(args.qualification_tag, create=False)
    require(release.get('author', {}).get('login') == read(POLICY)['bridge']['publisher_login'], 'unapproved receipt publisher')
    names = (*TRANSFER_FILES, 'producer-receipt.json')
    require(len(release['assets']) == len(names) and {a['name'] for a in release['assets']} == set(names),
            'qualification release must contain only the approved metadata files')
    with tempfile.TemporaryDirectory(prefix='nwaf-stable-receipt-') as temporary:
        directory = Path(temporary)
        for asset in release['assets']:
            url = ASSETS + args.qualification_tag + '/' + asset['name']
            require(asset.get('state') == 'uploaded' and asset['browser_download_url'] == url, 'invalid receipt asset')
            # Public downloads never carry a token through object-storage redirects.
            with urllib.request.urlopen(url, timeout=120) as response:
                data = response.read((8 << 20) + 1)
            require(len(data) <= 8 << 20, 'qualification metadata exceeds 8 MiB')
            (directory / asset['name']).write_bytes(data)
        receipt = verify_receipt(directory, args.receipt_sha256)
        bridge = receipt['source_bridge']
        require(args.qualification_tag == f'qualification-{bridge["run_id"]}-{bridge["run_attempt"]}',
                'qualification tag differs from source bridge attempt')
        commit = promote(github, directory, args.receipt_sha256)
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        output.write('commit_sha=' + commit + '\n')
    print('Promoted the exact catalog; deploy Pages from commit ' + commit)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        raise SystemExit(str(error)) from None
