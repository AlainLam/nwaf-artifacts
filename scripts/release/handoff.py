"""Create a strictly limited public receipt from privately verified qualification data."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from evidence import ARCHES, CHECKSUM, COMMIT, DISTROS, POLICY, digest, read, require

TRANSFER_FILES = ('candidate.json', 'manifest.json', 'inventory.json', 'qualification-policy.json', 'evidence.json')
SAFE_EXECUTABLES = {'bash', 'sh', 'python', 'python3', 'node', 'go', 'nwaf', 'vegeta', 'wrk', 'wrk2',
                    'curl', 'docker', 'pnpm', 'npm', 'make', 'ssh'}
SAFE_WORDS = {'test', 'run', 'install', 'load', 'save', 'create', 'restore', 'nginx', 'validate-config',
              'serve', 'init', 'info', 'build', 'exec', 'all', './...', '[redacted]', '[private-command]'}


def opaque(prefix, value):
    text = str(value)
    if re.fullmatch(prefix + r'-[0-9a-f]{16}', text):
        return text
    return prefix + '-' + hashlib.sha256(text.encode()).hexdigest()[:16]


def public_command(command):
    """Retain tool/script identities; never publish literal arguments or credentials."""
    result = []
    redact_next = False
    for index, argument in enumerate(command):
        name = Path(argument).name
        if redact_next:
            result.append('[redacted]')
            redact_next = False
        elif index == 0:
            result.append(name if name in SAFE_EXECUTABLES else '[private-command]')
        elif argument in SAFE_WORDS or argument in SAFE_EXECUTABLES:
            result.append(argument)
        elif re.fullmatch(r'--?[a-zA-Z][a-zA-Z0-9-]*', argument):
            result.append(argument)
            redact_next = True
        elif re.fullmatch(r'--?[a-zA-Z][a-zA-Z0-9-]*=.*', argument):
            result.append(argument.split('=', 1)[0] + '=[redacted]')
        elif (re.fullmatch(r'(?:test|scripts|deploy|build)/[a-zA-Z0-9_./-]+\.(?:py|mjs|sh)', argument)
              and '..' not in Path(argument).parts and '.env' not in argument
              and not any(part.startswith('alx-') for part in Path(argument).parts)):
            result.append(argument)
        else:
            result.append('[redacted]')
    return result


def public_environment(environment):
    """Publish platform facts and opaque machine identities, excluding free-form diagnostics."""
    kernel = environment['kernel']
    require(isinstance(kernel, str) and re.fullmatch(r'[0-9][a-zA-Z0-9.+_-]{0,127}', kernel),
            'kernel identity must be a plain version, without paths or diagnostics')
    result = {'id': opaque('environment', environment['id']), 'os': environment.get('distro', 'qualification'),
              'kernel': kernel}
    public_values = {'distro': DISTROS, 'arch': ARCHES, 'deployment': ('host', 'docker'),
                     'profile': ('reference', 'minimum', 'arm-smoke')}
    for key, allowed in public_values.items():
        if key in environment:
            require(environment[key] in allowed, 'environment contains a non-public ' + key + ' value')
            result[key] = environment[key]
    if 'runtime_packages' in environment:
        result['runtime_packages'] = []
        for package in environment['runtime_packages']:
            require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', package['name'])
                    and re.fullmatch(r'[0-9][a-zA-Z0-9.+:~_-]{0,127}', package['version']),
                    'public runtime package facts must contain only names and versions')
            result['runtime_packages'].append({'name': package['name'], 'version': package['version']})
    for key in ('cpu', 'network', 'physical_host'):
        if key in environment:
            result[key] = opaque('host' if key == 'physical_host' else key, environment[key])
    for key in ('vcpus', 'memory_bytes'):
        if key in environment:
            require(type(environment[key]) is int and environment[key] > 0, 'invalid hardware quantity')
            result[key] = environment[key]
    if 'hypervisor' in environment:
        result['hypervisor'] = opaque('hypervisor', environment['hypervisor'])
    if 'other_workloads_idle' in environment:
        result['other_workloads_idle'] = environment['other_workloads_idle'] is True
    if 'generator' in environment:
        generator = environment['generator']
        result['generator'] = {'physical_host': opaque('host', generator.get('physical_host', '')),
                               'calibrated': generator.get('calibrated') is True}
    return result


def sanitize_evidence(private):
    """Copy only the public schema; original commands and raw reports remain private."""
    keys = ('schema_version', 'source_commit', 'frozen_source_commit', 'candidate_sha256', 'manifest_sha256',
            'inventory_sha256', 'policy_sha256', 'created_at')
    result = {key: deepcopy(private[key]) for key in keys}
    producer_keys = (*read(POLICY)['producer'], 'source_commit', 'run_id', 'run_attempt')
    result['producer'] = {key: deepcopy(private['producer'][key]) for key in producer_keys}
    result['results'] = []
    for row in private['results']:
        public = {key: deepcopy(row[key]) for key in ('context', 'gate', 'result', 'bundle_sha256', 'panel_sha256',
                                                     'completed_at', 'configuration_sha256')}
        public['command'] = public_command(row['command'])
        public['environment'] = public_environment(row['environment'])
        public['report'] = {'path': 'reports/' + row['report']['sha256'] + '.json', 'sha256': row['report']['sha256']}
        if 'related_bundle_sha256' in row:
            public['related_bundle_sha256'] = list(row['related_bundle_sha256'])
        result['results'].append(public)
    result['deferred'] = [{'id': row['id'], 'result': row['result'],
                           'reason': 'Historical finding remains deferred; exact-artifact gates are recorded separately.'}
                          for row in private['deferred']]
    return result


def validate_public_evidence(value):
    require(sanitize_evidence(value) == value, 'public evidence contains fields or literals outside its safe schema')


def validate_metadata(directory):
    """Reject unexpected payload fields before publishing the explicit metadata allowlist."""
    candidate, inventory = read(directory / 'candidate.json'), read(directory / 'inventory.json')
    require(set(candidate) == {'schema_version', 'source_commit', 'panel_version', 'generated_at', 'repository',
                               'source_ref', 'run_id', 'run_attempt', 'manifest_sha256', 'inventory_sha256',
                               'policy_sha256', 'note_gates'}, 'unexpected candidate publication field')
    require(set(inventory) == {'schema_version', 'source_commit', 'panel_version', 'combinations', 'artifacts', 'bundles'},
            'unexpected inventory publication field')
    combination_keys = {'bundle_version', 'bundle_sha256', 'descriptor_sha256', 'distro', 'arch', 'deployment',
                        'panel_sha256', 'panel_version', 'panel_min', 'panel_max', 'runtime_sha256', 'runtime_dependencies'}
    for combination in inventory['combinations']:
        require(set(combination) == combination_keys, 'unexpected compatibility publication field')
    base_artifact_keys = {'kind', 'file', 'sha256', 'distro', 'arch', 'panel_version', 'binary_sha256',
                          'build_sha256', 'runtime_sha256'}
    for artifact in inventory['artifacts']:
        expected = base_artifact_keys | ({'package_version'} if artifact.get('kind') == 'package'
                                         else {'source_companion_sha256', 'image_identity'})
        require(artifact.get('kind') in ('package', 'image') and set(artifact) == expected,
                'unexpected panel artifact publication field')
        if artifact['kind'] == 'image':
            identity = artifact['image_identity']
            require(set(identity) == {'os', 'arch', 'chain', 'platform_manifest_digest', 'config_digest', 'rootfs_diff_ids'}
                    and all(set(d) == {'digest', 'media_type', 'size'} for d in identity['chain']),
                    'unexpected image identity publication field')
    for bundle in inventory['bundles']:
        require(set(bundle) == {'version', 'distro', 'arch', 'sha256', 'descriptor_sha256', 'file', 'bytes',
                                'source_commit', 'validation_sha256', 'validator'}
                and set(bundle['validator']) == {'python_sha256', 'shell_sha256', 'canonical_defaults'},
                'unexpected bundle provenance publication field')
    for collection in ('artifacts', 'bundles'):
        for artifact in inventory[collection]:
            name = artifact.get('file', '')
            require(isinstance(name, str) and name.startswith('dist/') and '..' not in Path(name).parts
                    and '.env' not in name and not any(p.startswith('alx-') for p in Path(name).parts),
                    'public artifact identity must use a safe build-output path')
    # These records are generated from verified builders, never arbitrary report payloads.
    encoded = json.dumps({'candidate': candidate, 'inventory': inventory}).lower()
    require(not any('"' + name + '"' in encoded for name in
                    ('password', 'passphrase', 'token', 'authorization', 'entry_path', 'raw_log', 'argv')),
            'private fields are forbidden in public artifact metadata')


def receipt(directory, private_evidence_sha256, bridge):
    policy = read(POLICY)
    require(all(bridge.get(k) == v for k, v in policy['bridge'].items()), 'unapproved source bridge')
    candidate, evidence = read(directory / 'candidate.json'), read(directory / 'evidence.json')
    validate_metadata(directory)
    validate_public_evidence(evidence)
    require(bridge.get('source_commit') == candidate['source_commit']
            and str(bridge.get('run_id', '')).isdigit() and int(bridge['run_id']) > 0
            and str(bridge.get('run_attempt', '')).isdigit() and int(bridge['run_attempt']) > 0,
            'source bridge run identity is required')
    return {'schema_version': 1, 'verified_at': datetime.now(timezone.utc).isoformat(),
            'files': {name: digest(directory / name) for name in TRANSFER_FILES},
            'private_evidence_sha256': private_evidence_sha256, 'source_bridge': bridge,
            'producer': evidence['producer'],
            'verified_reports': sorted({(r['report']['path'], r['report']['sha256']) for r in evidence['results']})}


def verify_receipt(directory, expected_sha256):
    require(CHECKSUM.fullmatch(expected_sha256) and digest(directory / 'producer-receipt.json') == expected_sha256,
            'approved receipt checksum differs')
    value = read(directory / 'producer-receipt.json')
    require(set(value) == {'schema_version', 'verified_at', 'files', 'private_evidence_sha256',
                           'source_bridge', 'producer', 'verified_reports'} and value['schema_version'] == 1,
            'invalid producer receipt schema')
    require(set(value['files']) == set(TRANSFER_FILES)
            and all(digest(directory / name) == checksum for name, checksum in value['files'].items()),
            'receipt file identity mismatch')
    policy, candidate, evidence = read(POLICY), read(directory / 'candidate.json'), read(directory / 'evidence.json')
    require(all(value['source_bridge'].get(k) == v for k, v in policy['bridge'].items())
            and value['source_bridge'].get('source_commit') == candidate['source_commit']
            and COMMIT.fullmatch(value['source_bridge']['source_commit'])
            and CHECKSUM.fullmatch(value['private_evidence_sha256']), 'unapproved source bridge identity')
    require(set(value['source_bridge']) == set(policy['bridge']) | {'source_commit', 'run_id', 'run_attempt'}
            and str(value['source_bridge']['run_id']).isdigit() and int(value['source_bridge']['run_id']) > 0
            and str(value['source_bridge']['run_attempt']).isdigit() and int(value['source_bridge']['run_attempt']) > 0,
            'invalid source bridge attempt')
    require(value['producer'] == evidence['producer'], 'qualification producer identity differs')
    require(value['verified_reports'] == sorted([list(p) for p in
                {(r['report']['path'], r['report']['sha256']) for r in evidence['results']}]),
            'source-verified report set differs')
    validate_metadata(directory)
    validate_public_evidence(evidence)
    return value
