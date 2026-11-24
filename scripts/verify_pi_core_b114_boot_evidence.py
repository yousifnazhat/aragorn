"""Read-only, historical B112 issue replay. No slot publication, owner, store or VM invocation."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from scripts import pi_core_b114_release as seal
from scripts import prepare_pi_core_b114_owner as owner
from scripts import verify_pi_core_b113_boot_evidence as predecessor
from scripts.build_pi_core_linux import BuildError, ROOT, canonical, regular_bytes, require, sha256
from scripts.pi_core_owner_archive import OWNER, read_owner_archive
from scripts.prepare_pi_core_host_lifecycle import require_local_custody
from scripts.verify_pi_core_host_binding import identity, retained
from scripts.verify_pi_core_owner_records import _object, verify_owner_records
from scripts.verify_pi_core_owner_watchdog import verify_watchdog_records


ARTIFACT = ROOT / 'packaging/pi-core/immutable-host-b114/runner-output.json'
ID = 'org.aragorn.pi-core.b114.single-use-owner'


def public_issue(approval, artifact, signer):
    """Verify public B112 release lineage before any private path or archive read."""
    pins, seal_sha, sources = seal.approved_source(approval, signer)
    require(artifact != approval, 'artifact and prebuild approval must be distinct')
    seal.verify_commit(artifact, signer)
    seal.require_ancestor(approval, artifact)
    require(sources.keys() == seal.REVIEWED_SOURCES and sha256(sources[seal.SEAL]) == seal_sha and
            all(seal.signed_blob(artifact, path) == raw for path, raw in sources.items()),
            'signed prebuild seal or reviewed source changed before artifact publication')
    # Not an attestation of Python in memory. Start in a trusted checkout; compare the complete
    # reviewed Python sources under it without consulting mutable checkout grants or selecting a release by path.
    require(all(p.resolve(strict=True) == p and regular_bytes(p, 1 << 20) == data for p, data in sources.items()
                if p.suffix == '.py'), 'local verifier/builder differs from approved checkout')
    held = predecessor.joined({k: sources[ROOT / path] for k, path in predecessor.PATHS.items()})
    raw = seal.signed_blob(artifact, ARTIFACT)
    pin = _object(raw)
    require(pin.get('schema') == 'aragorn/b113-single-use-owner/v1' and pin.get('identifier') == ID
            and pin.get('boot_authorized') is True and pin.get('approval_commit') == approval
            and pin.get('build_seal_sha256') == seal_sha and pin.get('release_sha256') == pins['release_sha256']
            and pin['release_sha256'] != held['runner']['release_sha256']
            and canonical({k: pin.get(k) for k in held['media']}) == canonical(held['media']),
            'signed owner not issued for this release, source, media and recorder')
    for k, n in (('runner_sha256', 64), ('cdhash', 40)):
        h = pin.get(k)
        require(type(h) is str and re.fullmatch('[0-9a-f]{%d}' % n, h) and int(h, 16)
                and h != held['runner'][k], 'missing issued executable identity or held owner substituted')
    return pins, seal_sha, sources, dict(held, runner=pin, runner_catalog_sha256=sha256(raw))


def _pre_attempt(source, expected_sha, ctx, entry, approval, artifact):
    require_local_custody(source)
    identity(source.parent, True)
    raw = retained(source, 16384)
    require(sha256(raw) == expected_sha and canonical(_object(raw)) == canonical({
        'schema': 'aragorn/b114-independent-pre-attempt/v1', 'approval_commit': approval,
        'artifact_commit': artifact, 'runner_catalog_sha256': ctx['runner_catalog_sha256'],
        'release_sha256': ctx['runner']['release_sha256'], 'entry': entry}),
        'external pre-attempt digest or independently retained bindings differ')


def _capture(manifest, files, ctx, entry):
    """Separate the B113 host part of archive_serial from interpretation of the guest wire bytes."""
    uid = entry['attempt_uuid']
    require(manifest['attempt_uuid'] == uid and
            canonical(manifest['fixture_identity']) == canonical(entry['fixture_identity'])
            and manifest['ledger_attempt_identity'] and manifest['attempt_identity'] and
            OWNER.keys() <= files.keys() and files.keys() == manifest['files'].keys()
            and all(row['source']['mode'] == 0o400 for row in manifest['files'].values()),
            'missing, cross-attempt or unsealed owner evidence')
    wrap = _object(files['owner-terminal.json'])
    fixed = {'schema': 'aragorn/b113-owner-terminal/v1', 'release_sha256': ctx['runner']['release_sha256'],
             'host_identity_sha256': entry['host_identity_sha256'], 'consumed_identity': manifest['attempt_identity'],
             'media': ctx['media']}
    require(wrap.keys() == fixed.keys() | {'terminal', 'start_check_raw_ns', 'start_check_utc_s'}
            and canonical({k: wrap[k] for k in fixed}) == canonical(fixed), 'unbound owner terminal')
    expected = {k: entry[k] for k in ('fixture_identity', 'disk_identity', 'store_identity', 'disk_sha256')}
    expected.update(attempt_identity=manifest['attempt_identity'], runner_sha256=ctx['runner']['runner_sha256'],
                    runner_cdhash=ctx['runner']['cdhash'], store_sha256_before=entry['store_sha256'],
                    policy_sha256_before=entry['policy_sha256'])
    # The original serial and journal are passed by reference; only the nested JSON terminal is projected.
    streams = {k: files[k] for k in OWNER} | {'owner-terminal.json': canonical(wrap['terminal'])}
    times = verify_owner_records(uid, streams, expected)
    watch = verify_watchdog_records(uid, {k: v for k, v in files.items() if k not in OWNER}, times)
    utc, raw = wrap['start_check_utc_s'], wrap['start_check_raw_ns']
    require(type(utc) is type(raw) is int and entry['not_before_utc'] <= utc < entry['expires_utc']
            and watch['ready_raw_ns'] <= raw <= times['start_issued_ns']
            and times['start_issued_ns'] - raw <= (entry['expires_utc'] - utc - 1) * 10**9,
            'missing or ambiguous pre-start window')
    return files['serial.raw'], wrap['terminal']['owner']['capture']['capture_sha256']


def replay(approval, artifact, signer, private_release, nomination, nomination_sha, archive, uid,
           manifest_sha, *, host_loss, portable=False):
    result = dict(schema='aragorn/b114-issued-archive-replay/v1', attempt_uuid=uid, artifact_commit=artifact,
                  host='indeterminate', guest={'status': 'not-evaluated'}, boot_verified=False,
                  retry_authorized=False, cleanup_authorized=False, boot_authorized=False, phase3_exit_eligible=False,
                  firmware_trust_verified=False, restoration_verified=False)
    if host_loss is not False:
        return result | {'host': 'unresolved-host-loss'}
    pins, digest, sources, ctx = public_issue(approval, artifact, signer)
    # A copied file or a digest inside the owner archive is not an independent nomination.
    roots = (private_release.parent, nomination.parent, archive)
    require(all(not p.is_relative_to(q) for i, p in enumerate(roots)
                for j, q in enumerate(roots) if i != j), 'overlapping release, pre-attempt or archive locations')
    grant = seal.read_private(pins, private_release)
    require(seal.release_digest(grant) == ctx['runner']['release_sha256']
            and len(grant['approved_attempts']) == 1, 'no matching private single-use release')
    entry = grant['approved_attempts'][0]
    require(entry['disk_sha256'] == ctx['media']['disk_sha256'] and entry['attempt_uuid'] == uid,
            'cross-attempt or substituted disk')
    owner.verify_artifact(ctx['runner'], grant, digest, approval, sources)
    _pre_attempt(nomination, nomination_sha, ctx, entry, approval, artifact)
    manifest, files = read_owner_archive(archive, uid, manifest_sha, portable=portable)
    raw, captured_sha = _capture(manifest, files, ctx, entry)
    result.update(host='consistent-issued-transcript', manifest_sha256=manifest_sha,
                  runner_catalog_sha256=ctx['runner_catalog_sha256'], capture_sha256=captured_sha)
    try:
        result['guest'] = predecessor.compare_serial(raw, ctx, captured_sha)
    except BuildError as exc:
        result['guest'] = {'status': 'indeterminate', 'reason': str(exc)}
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    for key in ('approval_commit', 'artifact_commit', 'signer'):
        ap.add_argument(key, help='independently nominated, not inferred from evidence')
    ap.add_argument('private_release', type=Path)
    ap.add_argument('nomination', type=Path, help='separate private pre-attempt record')
    ap.add_argument('nomination_sha256')
    ap.add_argument('archive', type=Path)
    ap.add_argument('attempt_uuid')
    ap.add_argument('manifest_sha256')
    ap.add_argument('--portable', action='store_true',
                    help='allow a byte-preserved archive copy only; private grant, nomination and verified owner still required')
    ap.add_argument('--host-loss', action='store_true')
    a = ap.parse_args(argv)
    result = replay(a.approval_commit, a.artifact_commit, a.signer, a.private_release, a.nomination,
                    a.nomination_sha256, a.archive, a.attempt_uuid, a.manifest_sha256,
                    host_loss=a.host_loss, portable=a.portable)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['host'] == 'consistent-issued-transcript' and result['guest']['status'] == 'matching_candidate_record_only' else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (BuildError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        # File errors and failed subprocesses can include private custody names/argv. Do not export them.
        raise SystemExit('B114 issued replay refused: release, executable, nomination or host evidence unverified; no retry')
