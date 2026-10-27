"""Minimal GitHub artifact-repository transport shared by publication automation."""
import base64
import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

from evidence import ASSETS, ROOT, digest, require

PUBLIC_AUTOMATION = {
    '.github/workflows/pages.yml': 'build/release/pages.yml',
    '.github/workflows/promotion.yml': 'build/release/promotion.yml',
    'build/release/qualification-policy.json': 'build/release/qualification-policy.json',
    **{f'scripts/release/{name}.py': f'scripts/release/{name}.py'
       for name in ('evidence', 'handoff', 'github', 'promote')},
}


class GitHub:
    """Use an explicitly supplied Actions token without consulting local credentials."""

    def __init__(self, repository, token):
        require(bool(token), 'the publication token is unavailable')
        self.repository = repository
        self.token = token
        self.created_releases = set()

    def request(self, method, path, value=None, binary=None, missing=False):
        url = 'https://api.github.com/repos/' + self.repository + ('/' + path if path else '')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'NWAF release workflow'}
        data = None
        if value is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(value).encode()
        if binary is not None:
            url = 'https://uploads.github.com/repos/' + self.repository + '/' + path
            headers['Content-Type'] = 'application/octet-stream'
            data = binary
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                raw = response.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            # API response bodies can contain request data; never print credentials or raw responses.
            raise ValueError(f'GitHub {method} request failed with HTTP {error.code}') from None

    def preflight(self):
        repository = self.request('GET', '')
        require(repository.get('private') is False and repository.get('permissions', {}).get('push') is True,
                'publication requires write access to the public artifact repository')
        for remote, local in PUBLIC_AUTOMATION.items():
            value, _ = self.content(remote)
            require(value == (ROOT / local).read_bytes(),
                    'install the exact reviewed public release automation before publication: ' + remote)

    def content(self, path, ref='main'):
        response = self.request('GET', 'contents/' + path + '?ref=' + urllib.parse.quote(ref, safe=''), missing=True)
        if response is None:
            return None, None
        require(response.get('encoding') == 'base64' and response.get('type') == 'file', 'invalid remote catalog')
        return base64.b64decode(response['content']), response['sha']

    def update_files(self, files, message, expected_parent=None):
        """Commit one channel snapshot atomically, refusing a concurrent branch update."""
        parent = self.request('GET', 'git/ref/heads/main')['object']['sha']
        require(expected_parent is None or parent == expected_parent, 'artifact repository changed during verification')
        tree = self.request('GET', 'git/commits/' + parent)['tree']['sha']
        entries = []
        for path, content in files.items():
            blob = self.request('POST', 'git/blobs', {'encoding': 'base64',
                                                      'content': base64.b64encode(content).decode()})
            entries.append({'path': path, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']})
        tree = self.request('POST', 'git/trees', {'base_tree': tree, 'tree': entries})['sha']
        commit = self.request('POST', 'git/commits', {'message': message, 'tree': tree, 'parents': [parent]})['sha']
        self.request('PATCH', 'git/refs/heads/main', {'sha': commit, 'force': False})
        return commit

    def release(self, version, create):
        return self.named_release('nginx-' + version, create)

    def named_release(self, tag, create):
        release = self.request('GET', 'releases/tags/' + tag, missing=True)
        if release is None and create:
            release = self.request('POST', 'releases', {'tag_name': tag, 'name': tag,
                                                       'draft': False, 'prerelease': False})
            self.created_releases.add(release['id'])
        require(release and release.get('tag_name') == tag and not release.get('draft'),
                'published bundle release is missing')
        return release

    def asset(self, release, bundle, path=None):
        name = urllib.parse.urlsplit(bundle['url']).path.rsplit('/', 1)[1]
        require(bundle['url'] == ASSETS + release['tag_name'] + '/' + name, 'unexpected public asset URL')
        assets, page = [], 1
        while True:
            batch = self.request('GET', f'releases/{release["id"]}/assets?per_page=100&page={page}')
            assets.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        existing = [a for a in assets if a['name'] == name]
        require(len(existing) <= 1, 'ambiguous remote asset')
        if existing:
            require(existing[0].get('state') == 'uploaded', 'remote asset upload is incomplete')
            require(existing[0]['browser_download_url'] == bundle['url'], 'remote asset URL differs')
            require(download_digest(bundle['url']) == bundle['sha256'],
                    'immutable asset already exists with different bytes; use a new bundle revision')
            return
        require(path is not None, 'qualified public asset is missing; promotion never uploads')
        require(release['id'] in self.created_releases,
                'asset is missing from an existing immutable revision; publish a new bundle revision')
        require(digest(path) == bundle['sha256'], 'local archive checksum mismatch')
        self.request('POST', f'releases/{release["id"]}/assets?name={urllib.parse.quote(name)}',
                     binary=path.read_bytes())
        require(download_digest(bundle['url']) == bundle['sha256'], 'uploaded archive checksum mismatch')


def download_digest(url):
    """Download public assets without forwarding any repository credential to redirects."""
    with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'NWAF release workflow'}), timeout=300) as response:
        return hashlib.file_digest(response, 'sha256').hexdigest()

