"""Supervise and export one exact B45 no-store preview. No VM start or enrollment path."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid

from scripts import prepare_pi_core_bound_host_runner as build
from scripts import verify_pi_core_host_binding as binding
from scripts.build_pi_core_linux import require, sha256
from scripts.pi_core_host_evidence_export import cleanup_attempt, export_attempt, read_export
from scripts.pi_core_host_watchdog import supervise


def require_local_custody(path):
    # Project/cloud metadata writers can invalidate an inode seal even when content is unchanged.
    home = Path.home()
    forbidden = (build.ROOT, home / "Documents", home / "Desktop", home / "Library/CloudStorage",
                 home / "Library/Mobile Documents")
    require(not any(path.is_relative_to(root) or root.is_relative_to(path) for root in forbidden),
            "use separate operator-owned local evidence storage outside the checkout and managed folders")


def layout(fixture, ledger, exports, uid):
    require(str(uuid.UUID(uid)) == uid and uuid.UUID(uid).int != 0, "invalid attempt UUID")
    roots = (fixture, ledger, exports)
    for root in roots:
        require_local_custody(root)
        binding.identity(root, True)
    require(all(not a.is_relative_to(b) for i, a in enumerate(roots)
                for j, b in enumerate(roots) if i != j), "overlapping custody roots")
    require(not any(os.path.lexists(root / uid) for root in roots), "attempt already reserved")


def preview(fixture, ledger, exports, uid, commit, signer):
    layout(fixture, ledger, exports, uid)
    pin = binding.signed_pin(commit, signer)
    runner = build.WORK / pin["directory"] / "host-runner"
    media_bytes = build.source_bytes(binding.MEDIA)
    require(sha256(media_bytes) == pin["media_pins_sha256"], "changed media catalog")
    disk = build.B41.parent / "build-b44" / json.loads(media_bytes)["directory"] / "aragorn-arm64.raw"
    for root in (fixture, ledger, exports):
        require(not any(root.is_relative_to(p) or p.is_relative_to(root)
                        for p in (runner.parent, disk.parent)), "custody overlaps retained artifacts")
    binding.match_executable(runner, pin)
    run_dir, attempt = ledger / uid, fixture / uid
    run_dir.mkdir(mode=0o700)  # Reserve before any child; never reuse even if no binding is produced.
    out, err = run_dir / "runner.stdout", run_dir / "runner.stderr"
    fixture_q, attempt_q, out_q, err_q, store_q = map(
        lambda p: json.dumps(str(p)), (fixture, attempt, out, err, fixture / "efi-vars.fd"))
    profile = ("(version 1)(allow default)(deny network*)(deny file-write*)"
               f"(allow file-write* (literal {fixture_q}) (subpath {attempt_q}) (literal {out_q}) (literal {err_q}))"
               f"(deny file-read* file-write* (literal {store_q}))")
    with out.open("xb") as stdout, err.open("xb") as stderr:
        for stream in (stdout, stderr):
            os.fchmod(stream.fileno(), 0o600)
        # The pinned preview never consumes VM controls. Exec replaces sandbox-exec in this same child.
        def spawn(_control_fd):
            return subprocess.Popen(["/usr/bin/sandbox-exec", "-p", profile, runner, "preview", disk, fixture, uid],
                                    stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, cwd=fixture,
                                    env={"HOME": str(fixture), "TMPDIR": str(fixture), "PATH": "/usr/bin:/bin"})

        record = run_dir / "watchdog.json"
        watch = supervise(spawn, record=record, attempt_uuid=uid)
        require(watch["child_reaped"] is True, "child retirement unconfirmed; preserve ledger and attempt in place")
        for stream in (stdout, stderr):
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
    require(watch == json.loads(binding.retained(record, 65536), object_pairs_hook=binding.unique),
            "watchdog readback differs; retain attempt")
    matched = None
    if watch["outcome"] == "child-exited" and watch["child_returncode"] == 0:
        raw = binding.retained(out, 65536)
        matched = binding.replay(attempt, disk, sha256(raw), pin)
        capture = json.loads(raw, object_pairs_hook=binding.unique)["capture"]
        require(watch["start_raw_ns"] <= capture["attempt_start_ns"] <= capture["record_end_ns"] <=
                watch["exit_observed_raw_ns"] < watch["run_deadline_raw_ns"], "capture outside owned lifetime")
    require(attempt.is_dir(), "no child attempt to export; retained supervisor journal, stdout and stderr")
    digest = export_attempt(attempt, exports, watch, replay_result=matched)
    verified = read_export(exports, uid, digest)
    require(matched is not None, "child did not complete; failure retained and not cleanup-eligible")
    require(verified["eligible_for_local_evidence_cleanup"] is True, "export not verified for no-boot preview")
    return {"status": "exported_no_boot_preview", "attempt_uuid": uid, "export_sha256": digest,
            "binding_sha256": matched["binding_sha256"], "boot_observed": False, "phase3_exit_eligible": False}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    commands = ap.add_subparsers(required=True, dest="command")
    p = commands.add_parser("preview")
    for name in ("fixture", "ledger", "exports"):
        p.add_argument(name, type=Path)
    for name in ("uuid", "commit", "signer"):
        p.add_argument(name)
    p = commands.add_parser("read-export")
    p.add_argument("exports", type=Path)
    p.add_argument("uuid")
    p.add_argument("digest", help="independently retained manifest SHA-256")
    p = commands.add_parser("cleanup-preview")
    p.add_argument("attempt", type=Path)
    p.add_argument("exports", type=Path)
    p.add_argument("digest", help="explicit custody acknowledgment from the independent reader")
    a = ap.parse_args()
    if a.command == "preview":
        result = preview(a.fixture, a.ledger, a.exports, a.uuid, a.commit, a.signer)
    elif a.command == "read-export":
        result = read_export(a.exports, a.uuid, a.digest)
    else:
        result = cleanup_attempt(a.attempt, a.exports, a.digest)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
