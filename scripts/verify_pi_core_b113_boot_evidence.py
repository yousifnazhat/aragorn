"""Read only. A B113 held owner cannot produce an authorized target transcript."""
import argparse
import json
import os
import re
import stat
import subprocess
from pathlib import Path

from scripts import inspect_pi_core_observable_serial as wire
from scripts import verify_pi_core_owner_watchdog as watchdog
from scripts.build_pi_core_linux import ROOT, BuildError, canonical, require, sha256
from scripts.pi_core_owner_archive import OWNER, read_owner_archive
from scripts.prepare_pi_core_guest_disk import opened
from scripts.verify_pi_core_owner_records import _object, verify_owner_records


PACK = 'packaging/pi-core/'
PATHS = {k: PACK + p for k, p in {
    'media': 'immutable-host-b112/media-output.json', 'recorder': 'immutable-host-b45/serial-recorder.m',
    'request': 'immutable-host-b113/boot-request.json', 'proposal': 'immutable-host-b113/firmware-proposal.json',
    'runner': 'immutable-host-b113/runner-output.json', 'release': 'immutable-host-b113/owner-release.json'}.items()}
EXACT = {'media': 'fac725f23b8a1d694ba89054859710786649693c53d23a9c19a01794938877f7',
         'runner': 'bedfbfb5f8a71dd74c55ce00e5dd1e2a6f09db1a0c00e9b362cae5a552b8dbd0',
         'release': '3c94d1af28930b8d9bdc9f7fc539a03d3d186b40d52e6ce49fb3e6592d71598b',
         'recorder': '210561eb3c0718fe3e7b46db804ce844ab5d4229b6833ad7cb6a54ace7f5533b',
         'request': 'b765a437ea55e54c18e2418c7e084f0bd195361b9fc7537cf755a812087c436a',
         'proposal': 'af7197021a39f2dc7d96ecaa5a47f0c346a0fa6e0d0eb56e413d7b4b3b760d9c'}
HELD = {'schema': 'aragorn/b113-single-use-release/v1', 'approved_attempts': []}
REFUSAL = b'B113 held: no approved boot attempt\n'
MEDIA_KEYS = ('disk_bytes', 'disk_sha256', 'uki_sha256', 'authenticode_sha256', 'esl_sha256')


def _git(*args):
    return subprocess.run(['/usr/bin/git', '--no-replace-objects', '--no-pager',
                           '-c', 'protocol.allow=never', '-c', 'core.hooksPath=/dev/null',
                           '-c', 'gpg.format=ssh', '-c', 'gpg.ssh.program=/usr/bin/ssh-keygen', *args],
                          cwd=ROOT, env={'HOME': '/var/empty', 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
                                        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
                                        'GIT_ALLOW_PROTOCOL': '', 'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'},
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True).stdout


def signed_catalogs(commit, signer):
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit) and isinstance(signer, str)
            and re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', signer), 'need exact independently trusted commit/signer')
    require(_git('log', '-1', '--no-notes', '--no-show-signature', '--format=%H%n%G?%n%GF',
                 commit).decode('ascii').splitlines() == [commit, 'G', signer], 'wrong artifact signature or signer')
    blobs = {}
    for key, path in PATHS.items():
        spec = commit + ':' + path
        require(_git('cat-file', '-t', spec) == b'blob\n' and 0 < int(_git('cat-file', '-s', spec)) <= 65536,
                'wrong artifact object type/size')
        blobs[key] = _git('cat-file', 'blob', spec)
    return joined(blobs)


def joined(blobs):
    require(set(blobs) == set(PATHS) and all(sha256(blobs[k]) == d for k, d in EXACT.items()),
            'wrong B112 media, B113 request/proposal or recorder bytes')
    m, r = _object(blobs['media']), _object(blobs['runner'])
    require(blobs['release'] == canonical(HELD) + b'\n'
            and r.get('release_sha256') == sha256(canonical(HELD)) and r.get('boot_authorized') is False
            and 'approval_commit' in r and r['approval_commit'] is None
            and r.get('schema') == 'aragorn/b113-held-owner/v1' and r.get('identifier') == 'org.aragorn.pi-core.b113.host-owner',
            'not the B113 zero-grant owner')
    media = {k: m[k] for k in MEDIA_KEYS} | {'media_pins_sha256': EXACT['media'], 'request_sha256': EXACT['request'],
            'firmware_proposal_sha256': EXACT['proposal'], 'serial_recorder_sha256': EXACT['recorder']}
    require(canonical({k: r.get(k) for k in media}) == canonical(media), 'runner/recorder/firmware candidate mismatch')
    for name, width in [('runner_sha256', 64), ('cdhash', 40)]:
        value = r.get(name)
        require(isinstance(value, str) and re.fullmatch('[a-f0-9]{%d}' % width, value) and int(value, 16),
                'invalid held runner identity')
    return {'media': media, 'catalog': m, 'runner': r, 'runner_catalog_sha256': sha256(blobs['runner'])}


def compare_serial(raw, ctx, expected_digest):
    """Content-only diagnostic. The retained reporter predates B112 and cannot report its containing UKI."""
    require(type(raw) is bytes and 0 < len(raw) < wire.LIMIT and sha256(raw) == expected_digest,
            'missing, oversized or substituted raw serial')
    m = ctx['catalog']
    # Adapt only the pinned parameters of the unchanged B44 wire parser. Never pretend
    # the original B112 catalog was signed with B44's schema or read B44 checkout pins.
    fields = ('disk_sha256', 'uki_sha256', 'root_sha256', 'manager_sha256', 'sector_size', 'root_size', 'disk_bytes',
              'boot_observed', 'secure_boot_enrollment', 'phase3_exit_eligible')
    contract = {k: m[k] for k in fields} | {'schema': 'aragorn/observable-guest-disk/v1'}
    finding = wire.inspect_serial_with_pins(raw, contract)
    return finding | {'status': 'matching_candidate_record_only', 'signed_media_catalog_sha256': EXACT['media'],
                      'firmware_trust_verified': False, 'boot_verified': False}


def archive_serial(manifest, files, ctx, *, host_loss, authenticate_issue=None):
    """Check original archive streams before parsing. No issued implementation ships in B113.

    A future approved integration must supply its *trusted code* for authenticating
    its signed artifact, signed prebuild seal, single-use release and independently
    nominated pre-attempt facts. Never take this callback, or its result, from an
    evidence file. No supplied facts or boolean can enable this on the B113 artifact.
    """
    uid = manifest['attempt_uuid']
    r = ctx['runner']
    require(host_loss is False and ctx['runner_catalog_sha256'] != EXACT['runner'] and
            r.get('schema') == 'aragorn/b113-single-use-owner/v1' and r.get('boot_authorized') is True and
            r.get('release_sha256') != sha256(canonical(HELD)) and isinstance(r.get('approval_commit'), str) and
            re.fullmatch('[0-9a-f]{40}', r['approval_commit']) and callable(authenticate_issue),
            'held, lost or unauthenticated issue: guest not evaluated')
    facts = authenticate_issue(ctx, uid)
    require(type(facts) is dict and set(facts) == {'attempt_uuid', 'release_sha256', 'host_identity_sha256',
            'fixture_identity', 'disk_identity', 'store_identity', 'store_sha256', 'policy_sha256',
            'not_before_utc', 'expires_utc'} and facts['attempt_uuid'] == uid and
            facts['release_sha256'] == ctx['runner']['release_sha256'] and
            isinstance(facts['host_identity_sha256'], str) and re.fullmatch('[a-f0-9]{64}', facts['host_identity_sha256'])
            and canonical(facts['fixture_identity']) == canonical(manifest['fixture_identity'])
            and manifest['ledger_attempt_identity'] and manifest['attempt_identity'] and OWNER.keys() <= files.keys()
            and files.keys() == manifest['files'].keys() and all(row['source']['mode'] == 0o400 for row in manifest['files'].values()),
            'incomplete or unmatched pre-attempt inputs and archive')
    wrap = _object(files['owner-terminal.json'])
    fixed = {'schema': 'aragorn/b113-owner-terminal/v1', 'release_sha256': facts['release_sha256'],
             'host_identity_sha256': facts['host_identity_sha256'], 'consumed_identity': manifest['attempt_identity'],
             'media': ctx['media']}
    require(set(wrap) == set(fixed) | {'start_check_utc_s', 'start_check_raw_ns', 'terminal'} and
            canonical({k: wrap[k] for k in fixed}) == canonical(fixed), 'owner terminal/profile differs')
    expected = {k: facts[k] for k in ('fixture_identity', 'store_identity', 'disk_identity')} | {
        'attempt_identity': manifest['attempt_identity'], 'runner_sha256': ctx['runner']['runner_sha256'],
        'runner_cdhash': ctx['runner']['cdhash'], 'disk_sha256': ctx['media']['disk_sha256'],
        'store_sha256_before': facts['store_sha256'], 'policy_sha256_before': facts['policy_sha256']}
    streams = {k: files[k] for k in OWNER} | {'owner-terminal.json': canonical(wrap['terminal'])}
    owner = verify_owner_records(uid, streams, expected)
    watch = watchdog.verify_watchdog_records(uid, {k: v for k, v in files.items() if k not in OWNER}, owner)
    utc, raw = wrap['start_check_utc_s'], wrap['start_check_raw_ns']
    low, high = facts['not_before_utc'], facts['expires_utc']
    require(all(type(x) is int for x in (utc, raw, low, high)) and 0 <= low <= utc < high and
            watch['ready_raw_ns'] <= raw <= owner['start_issued_ns'] and
            owner['start_issued_ns'] - raw <= (high - utc - 1) * 10**9, 'unbound issue window or clock')
    return compare_serial(files['serial.raw'], ctx, wrap['terminal']['owner']['capture']['capture_sha256'])


def _held(uid, files):
    st, wt, ref = watchdog.START, watchdog.WATCH, watchdog.REFUSAL
    require(set(files) == {st, wt, ref} and files[ref] == REFUSAL, 'not the exact B113 pre-target refusal')
    common = {'schema': watchdog.SCHEMA, 'clock': watchdog.CLOCK, 'attempt_uuid': uid}
    start, end = watchdog._object(files[st]), watchdog._object(files[wt])
    t = watchdog._time(start, 'reserved_raw_ns')
    a, b = (watchdog._time(end, k) for k in ('start_raw_ns', 'exit_observed_raw_ns'))
    pid, arm = end.get('child_pid'), end.get('owner_arm')
    d = [a + s * 10**9 for s in (180, 195, 210)]
    require(type(pid) is int and 0 < pid < 1 << 31 and t <= a <= b < d[0] and d[-1] < 1 << 64 and
            type(arm) is dict and arm.get('status') in ('not-granted', 'peer-eof'), 'unbounded or armed watchdog')
    expected = dict(common, child_pid=pid, child_reaped=True, child_returncode=78, outcome='child-exited',
                    start_raw_ns=a, exit_observed_raw_ns=b, effective_deadlines_raw_ns=d, run_deadline_raw_ns=d[0],
                    graceful_deadline_raw_ns=d[1], force_deadline_raw_ns=d[2], interrupted=False, interrupt_signal=None,
                    host_kill_requested=False, host_kill_raw_ns=None, graceful=None, force=None, vm_stopped_verified=False,
                    owner_arm=dict(status=arm['status'], ready_raw_ns=None, queued_raw_ns=None))
    require(canonical(expected) == files[wt] and canonical(dict(common, reserved_raw_ns=t,
            disposition='reserved-before-spawn')) == files[st], 'inconsistent held watchdog originals')


def assess(manifest, files, ctx, host_loss):
    uid = manifest['attempt_uuid']
    status = 'indeterminate'
    if files.keys() & (OWNER.keys() | {watchdog.ARM}):
        status = 'transcript-conflicts-with-held-release'
    elif manifest['ledger_attempt_identity'] and manifest['fixture_identity'] is manifest['attempt_identity'] is None:
        try:
            require(manifest['files'].keys() == files.keys() and all(v['source']['mode'] == 0o400 for v in
                    manifest['files'].values()), 'unsealed or incomplete archive')
            _held(uid, files)
            status = 'consistent-held-refusal'
        except BuildError:
            pass
    return {'schema': 'aragorn/b113-held-archive-replay/v1', 'attempt_uuid': uid, 'transcript': status,
            'disposition': 'unresolved-host-loss' if host_loss else status,
            'guest': {'status': 'not-evaluated'}, 'runner_catalog_sha256': ctx['runner_catalog_sha256'],
            'runner_sha256': ctx['runner']['runner_sha256'], 'candidate': ctx['media'],
            'boot_verified': False, 'phase3_exit_eligible': False, 'retry_authorized': False,
            'boot_authorized': False, 'restoration_verified': False, 'cleanup_authorized': False}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('commit', help='independently nominated full signed B113 artifact commit')
    ap.add_argument('signer', help='trusted SSH signing fingerprint')
    ops = ap.add_subparsers(dest='command', required=True)
    rd = ops.add_parser('replay', help='read an original B48 archive; a held owner cannot attest a boot')
    rd.add_argument('archive_root', type=Path)
    rd.add_argument('attempt_uuid')
    rd.add_argument('manifest_sha256')
    rd.add_argument('--host-loss', action='store_true')
    rd.add_argument('--portable', action='store_true')
    sr = ops.add_parser('compare-serial', help='compare nominated sealed bytes only, never attribute them to the held owner')
    sr.add_argument('raw_file', type=Path)
    sr.add_argument('capture_sha256')
    a = ap.parse_args(argv)
    ctx = signed_catalogs(a.commit, a.signer)
    if a.command == 'replay':
        manifest, files = read_owner_archive(a.archive_root, a.attempt_uuid, a.manifest_sha256, portable=a.portable)
        result = assess(manifest, files, ctx, a.host_loss) | {'manifest_sha256': a.manifest_sha256}
        ok = result['disposition'] == 'consistent-held-refusal'
    else:
        with opened(a.raw_file) as f:
            info = os.fstat(f.fileno())
            require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid(), 'not a sealed local capture')
            result = compare_serial(f.read(wire.LIMIT), ctx, a.capture_sha256)
        ok = True
    print(json.dumps(result | {'artifact_commit': a.commit}, sort_keys=True))
    return 0 if ok else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as exc:
        raise SystemExit(f'B113 replay refused; preserve all originals: {exc}')
