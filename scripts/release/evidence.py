#!/usr/bin/env python3
"""Verify exact artifact evidence without access to private application sources."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / 'build/release/qualification-policy.json'
REPOSITORY = 'AlainLam/nwaf-artifacts'
ASSETS = 'https://github.com/' + REPOSITORY + '/releases/download/'
DISTROS = ('debian12', 'debian13', 'ubuntu24.04', 'ubuntu26.04')
ARCHES = ('amd64', 'arm64')
CHECKSUM = re.compile(r'[0-9a-f]{64}')
COMMIT = re.compile(r'[0-9a-f]{40}')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def read(path):
    return decode(Path(path).read_bytes())


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def timestamp(value):
    require(isinstance(value, str), 'timestamp is required')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('timestamp must use ISO 8601 with a timezone') from None
    require(parsed.tzinfo is not None, 'timestamp must have a timezone')
    return parsed.astimezone(timezone.utc)


def dependencies(value):
    require(isinstance(value, list), 'runtime_dependencies must be an explicit array')
    result = {}
    for item in value:
        require(set(item) == {'name', 'version'} and isinstance(item['name'], str)
                and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', item['name'])
                and isinstance(item['version'], str) and item['version'].strip()
                and item['name'] not in result, 'invalid runtime dependency')
        result[item['name']] = item['version']
    return result


def supports(installed, needed):
    return all(name in installed and subprocess.run(
        ['dpkg', '--compare-versions', installed[name], 'ge', version], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
               for name, version in needed.items())


def load_candidate(directory, source=None, expected_note_gates=None):
    candidate = read(directory / 'candidate.json')
    require(candidate.get('schema_version') == 1 and COMMIT.fullmatch(candidate.get('source_commit', '')),
            'invalid candidate identity')
    if source:
        require(candidate['source_commit'] == source, 'candidate source is stale')
    for name in ('manifest', 'inventory'):
        require(candidate.get(name + '_sha256') == digest(directory / (name + '.json')),
                'candidate ' + name + ' checksum mismatch')
    require(candidate.get('policy_sha256') == digest(directory / 'qualification-policy.json') == digest(POLICY),
            'qualification policy is stale')
    if expected_note_gates is not None:
        require(candidate.get('note_gates') == expected_note_gates, 'active release requirements are stale')
    require(isinstance(candidate.get('note_gates'), list) and candidate['note_gates']
            and all(set(g) == {'id'} and re.fullmatch(r'note-[0-9a-f]{16}', g['id'])
                    for g in candidate['note_gates']), 'invalid active release gate identities')
    manifest, inventory = read(directory / 'manifest.json'), read(directory / 'inventory.json')
    require(manifest.get('panels') == [] and manifest.get('images') == [] and manifest.get('bundles'),
            'public catalog must contain only bundles')
    require(inventory.get('source_commit') == candidate['source_commit']
            and inventory.get('panel_version') == candidate['panel_version'], 'inventory identity mismatch')
    require({b['sha256'] for b in inventory['bundles']} == {b['sha256'] for b in manifest['bundles']},
            'inventory bundle set differs')
    return candidate, manifest, inventory


def contexts(inventory):
    result = {'global': {'scope': 'global', 'combination': None}}
    for combo in inventory['combinations']:
        identity = '/'.join((combo['deployment'], combo['distro'], combo['arch'], combo['bundle_version']))
        result['combination/' + identity] = {'scope': 'combination', 'combination': combo}
        if combo['distro'] == 'debian13':
            scope = 'native' if combo['deployment'] == 'host' else 'docker'
            result[scope + '/' + identity] = {'scope': scope, 'combination': combo}
        if combo['deployment'] != 'host':
            continue
        scopes = []
        if combo['arch'] == 'amd64' and combo['distro'] == 'debian13':
            scopes = ['reference', 'public']
        elif combo['arch'] == 'amd64' and combo['distro'] == 'debian12':
            scopes = ['minimum']
        elif combo['arch'] == 'arm64' and combo['distro'] == 'debian13':
            scopes = ['arm-smoke']
        for scope in scopes:
            result[scope + '/' + identity] = {'scope': scope, 'combination': combo}
    return result


def evidence_template(directory, expected_note_gates=None):
    candidate, _, inventory = load_candidate(directory, expected_note_gates=expected_note_gates)
    policy = read(POLICY)
    results = []
    for name, context in contexts(inventory).items():
        gates = list(policy['gates'][context['scope']])
        if name == 'global':
            gates += [g['id'] for g in candidate['note_gates']]
        for gate in gates:
            combo = context['combination'] or {}
            results.append({'context': name, 'gate': gate, 'result': 'blocked',
                            'bundle_sha256': combo.get('bundle_sha256'), 'panel_sha256': combo.get('panel_sha256'),
                            'command': [], 'completed_at': None, 'configuration_sha256': None,
                            'environment': {}, 'report': {'path': None, 'sha256': None}})
    return {'schema_version': 1, 'source_commit': candidate['source_commit'],
            'frozen_source_commit': candidate['source_commit'], 'candidate_sha256': digest(directory / 'candidate.json'),
            'manifest_sha256': candidate['manifest_sha256'], 'inventory_sha256': candidate['inventory_sha256'],
            'policy_sha256': candidate['policy_sha256'], 'created_at': None,
            'producer': {**policy['producer'], 'source_commit': candidate['source_commit'],
                         'run_id': None, 'run_attempt': None}, 'results': results,
            'deferred': [{'id': gate, 'result': 'deferred', 'reason': None} for gate in policy['deferred']]}


def verify_evidence(directory, path, source=None, now=None, expected_note_gates=None, verified_reports=None):
    """Fail closed on incomplete, stale or differently bound artifact evidence."""
    candidate, _, inventory = load_candidate(directory, source, expected_note_gates)
    expected = evidence_template(directory, expected_note_gates)
    evidence, policy = read(path), read(POLICY)
    require(evidence.get('schema_version') == 1, 'unsupported evidence schema')
    for key in ('source_commit', 'frozen_source_commit', 'candidate_sha256', 'manifest_sha256', 'inventory_sha256', 'policy_sha256'):
        require(evidence.get(key) == expected[key], 'evidence identity mismatch: ' + key)
    producer = evidence.get('producer', {})
    require(all(producer.get(k) == v for k, v in policy['producer'].items())
            and producer.get('source_commit') == candidate['source_commit']
            and str(producer.get('run_id', '')).isdigit()
            and str(producer.get('run_attempt', '')).isdigit() and int(producer['run_attempt']) > 0,
            'evidence producer identity is missing or unapproved')
    now = now or datetime.now(timezone.utc)
    created, generated = timestamp(evidence.get('created_at')), timestamp(candidate['generated_at'])
    # Allow bounded clock skew between the qualification host and the Actions runner.
    require(generated <= created <= now + timedelta(minutes=5), 'evidence is stale or future-dated')
    expected_rows = {(r['context'], r['gate']): r for r in expected['results']}
    found = set()
    all_contexts = contexts(inventory)
    for row in evidence.get('results', []):
        key = (row.get('context'), row.get('gate'))
        require(key in expected_rows and key not in found, 'unknown or duplicate evidence gate')
        found.add(key)
        require(row.get('result') == 'passed', 'nonpassing evidence: ' + '/'.join(key))
        for field in ('bundle_sha256', 'panel_sha256'):
            require(row.get(field) == expected_rows[key][field], 'evidence artifact mismatch: ' + field)
        completed = timestamp(row.get('completed_at'))
        require(generated <= completed <= created, 'gate evidence is stale')
        require(isinstance(row.get('command'), list) and row['command']
                and all(isinstance(a, str) and a.strip() for a in row['command']), 'test command is required')
        require(CHECKSUM.fullmatch(row.get('configuration_sha256') or ''), 'configuration checksum is required')
        report, env = row.get('report', {}), row.get('environment', {})
        require(isinstance(report.get('path'), str) and report['path'].strip()
                and CHECKSUM.fullmatch(report.get('sha256') or ''), 'bound test report is required')
        if verified_reports is None:
            report_path = path.parent / report['path']
            require(not Path(report['path']).is_absolute() and report_path.resolve().is_relative_to(path.parent.resolve())
                    and report_path.is_file() and not report_path.is_symlink()
                    and digest(report_path) == report['sha256'], 'test report is missing or its checksum differs')
        else:
            require(verified_reports.get(report['path']) == report['sha256'],
                    'report was not verified by the trusted source bridge')
        require(all(isinstance(env.get(k), str) and env[k].strip() for k in ('id', 'os', 'kernel')),
                'test environment identity is required')
        context = all_contexts[row['context']]
        combo = context['combination']
        if combo:
            require(all(env.get(k) == combo[k] for k in ('distro', 'arch', 'deployment')),
                    'test environment platform differs from artifact')
            require(supports(dependencies(env.get('runtime_packages')), dependencies(combo['runtime_dependencies'])),
                    'tested runtime packages do not satisfy bundle')
            if context['scope'] in ('reference', 'minimum', 'arm-smoke'):
                require(env.get('profile') == context['scope'], 'measurement profile differs')
                require(all(k in env for k in ('cpu', 'vcpus', 'memory_bytes', 'hypervisor', 'network')),
                        'measurement hardware/network context is required')
            if context['scope'] in ('reference', 'minimum'):
                require(all(env.get(k) == v for k, v in policy['profiles'][context['scope']].items()),
                        'measurement hardware differs from the fixed release profile')
                generator = env.get('generator', {})
                require(generator.get('physical_host') and env.get('physical_host')
                        and generator['physical_host'] != env['physical_host']
                        and generator.get('calibrated') is True and env.get('other_workloads_idle') is True,
                        'independent calibrated generator and idle target host are required')
        if row['gate'] == 'switch-downgrade-and-offline-rollback':
            related = row.get('related_bundle_sha256', [])
            require(isinstance(related, list) and len(set(related)) >= 2
                    and row['bundle_sha256'] in related and all(CHECKSUM.fullmatch(s) for s in related),
                    'switching evidence requires two exact bundle identities')
    require(found == set(expected_rows), 'required evidence gates are missing')
    deferred = evidence.get('deferred', [])
    require(len(deferred) == len(policy['deferred']) and {r.get('id') for r in deferred} == set(policy['deferred'])
            and all(r.get('result') == 'deferred' and isinstance(r.get('reason'), str) and r['reason'].strip()
                    for r in deferred), 'deferred findings require an explicit disposition')
    print(f'Qualified {len(found)} bound gates for the exact candidate.')

