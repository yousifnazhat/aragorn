"""B50: preserve and compare a single-use owner transcript, never execute or authorize one."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

from scripts import pi_core_boot_build_seal as seal
from scripts.build_pi_core_linux import ROOT, BuildError, canonical, require, sha256
from scripts.pi_core_owner_archive import OWNER, export_owner_archive, read_owner_archive
from scripts.pi_core_single_use_release import DISK_SHA256, SCHEMA, release_digest
from scripts.prepare_pi_core_host_lifecycle import require_local_custody
from scripts.prepare_pi_core_single_use_owner import authenticated_pin
from scripts.verify_pi_core_host_binding import identity, retained, signed_pin
from scripts.verify_pi_core_owner_records import _object, verify_owner_records
from scripts import verify_pi_core_owner_watchdog as watchdog


HELD = {"schema": SCHEMA, "approved_attempts": []}
REFUSAL = b"B50 held: no approved boot attempt\n"


def checked_release(pin, release):
    digest = release_digest(release)
    require(type(pin) is dict and pin.get("schema") == "aragorn/b50-single-use-owner/v1" and
            pin.get("identifier") == "org.aragorn.pi-core.b50.host-owner" and pin.get("disk_sha256") == DISK_SHA256 and
            pin.get("boot_authorized") is bool(release["approved_attempts"]) and pin.get("release_sha256") == digest,
            "signed B50 pin and release authority differ")
    for key, width in (("runner_sha256", 64), ("cdhash", 40)):
        value = pin.get(key)
        require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % width, value) and int(value, 16),
                "invalid signed runner or disk digest")
    return digest


def source_seal(approval, commit, signer):
    require(type(approval) is str and re.fullmatch("[0-9a-f]{40}", approval) and approval != commit,
            "expected a distinct prebuild source commit")
    signed_pin(approval, signer)
    result = subprocess.run(["/usr/bin/git", "--no-replace-objects", "merge-base", "--is-ancestor", approval, commit],
                            cwd=ROOT, env={"HOME": str(Path.home()), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    require(result.returncode == 0, "prebuild approval is not an ancestor of the signed artifact")
    return seal._blob(approval, seal.SEAL)


def authenticated_release(commit, signer, release_path):
    pin = authenticated_pin(commit, signer)
    raw = seal._blob(commit, seal.SEAL)
    require(type(pin) is dict and sha256(raw) == pin.get("build_seal_sha256"), "signed artifact and build seal differ")
    if pin.get("boot_authorized") is True:
        fields = seal.approved_digest(raw)
        require(raw == source_seal(pin.get("approval_commit"), commit, signer), "prebuild and artifact seals differ")
        require(release_path is not None, "private single-use release required")
        require_local_custody(release_path)
        identity(release_path.parent, True)
        release = seal.match_private(fields, retained(release_path, 8192))
    else:
        require(_object(raw) == seal.HELD and "approval_commit" in pin and pin["approval_commit"] is None and
                release_path is None, "held build seal cannot accept a private release")
        release = HELD
    checked_release(pin, release)
    return pin, release


def held_watchdog(uid, files):
    """Match the B50 refusal and unarmed watchdog originals, without rewriting predecessor bytes."""
    require(set(files) == {watchdog.START, watchdog.WATCH, watchdog.REFUSAL} and files[watchdog.REFUSAL] == REFUSAL,
            "not the B50 no-grant refusal")
    common = {"schema": watchdog.SCHEMA, "attempt_uuid": uid, "clock": watchdog.CLOCK}
    reservation, row = (watchdog._object(files[k]) for k in (watchdog.START, watchdog.WATCH))
    reserved = watchdog._time(reservation, "reserved_raw_ns")
    start, end = (watchdog._time(row, k) for k in ("start_raw_ns", "exit_observed_raw_ns"))
    deadlines = [start + s * 10**9 for s in (180, 195, 210)]
    pid, arm = row.get("child_pid"), row.get("owner_arm")
    require(type(pid) is int and 0 < pid < 1 << 31 and reserved <= start <= end < deadlines[0] and
            deadlines[-1] < 1 << 64 and type(arm) is dict and arm.get("status") in ("not-granted", "peer-eof"),
            "not a bounded unarmed child retirement")
    expect = dict(common, start_raw_ns=start, exit_observed_raw_ns=end, child_pid=pid, child_reaped=True,
                  child_returncode=78, outcome="child-exited", effective_deadlines_raw_ns=deadlines,
                  run_deadline_raw_ns=deadlines[0], graceful_deadline_raw_ns=deadlines[1],
                  force_deadline_raw_ns=deadlines[2], interrupted=False, interrupt_signal=None,
                  host_kill_requested=False, host_kill_raw_ns=None, graceful=None, force=None,
                  vm_stopped_verified=False, owner_arm=dict(status=arm["status"], ready_raw_ns=None, queued_raw_ns=None))
    require(canonical(row) == canonical(expect) and canonical(reservation) == canonical(dict(common,
            reserved_raw_ns=reserved, disposition="reserved-before-spawn")), "inconsistent B50 held watchdog evidence")
    return {"disposition": "consistent-held-refusal", "child_pid": pid, "start_raw_ns": start, "exit_observed_raw_ns": end}


def assess(manifest, files, *, commit, pin, release, bindings=None, host_loss=False):
    """Inputs: byte-verified B48 archive and independently authenticated pin and private binding record."""
    digest = checked_release(pin, release)
    uid = manifest["attempt_uuid"]
    entries = release["approved_attempts"]
    report = {"schema": "aragorn/b50-owner-replay/v1", "release_commit": commit, "release_sha256": digest,
              "attempt_uuid": uid, "boot_verified": False, "restoration_verified": False, "phase3_exit_eligible": False,
              "retry_authorized": False, "cleanup_authorized": False, "boot_authorized_by_replay": False}
    disposition = "indeterminate"
    try:
        require(manifest["ledger_attempt_identity"] is not None and
                all(row["source"]["mode"] == 0o400 for row in manifest["files"].values()),
                "no sealed ledger or unsealed evidence")
        if not entries:
            if OWNER.keys() & files.keys() or "watchdog.json.owner-arm" in files:
                disposition = "transcript-conflicts-with-held-release"
            else:
                require(bindings is None and manifest["fixture_identity"] is None and
                        manifest["attempt_identity"] is None,
                        "no B50 pre-target refusal")
                report["watchdog"] = held_watchdog(uid, files)
                disposition = "consistent-held-refusal"
        else:
            entry = entries[0]
            require(entry["attempt_uuid"] == uid and entry["disk_sha256"] == pin["disk_sha256"],
                    "wrong release attempt or disk")
            require(canonical(bindings) == canonical({"schema": "aragorn/b50-independent-pre-attempt/v1",
                    "release_commit": commit, "release_sha256": digest, "entry": entry}),
                    "independent pre-attempt bindings absent or differ from release")
            require(canonical(manifest["fixture_identity"]) == canonical(entry["fixture_identity"]) and
                    manifest["attempt_identity"] is not None and OWNER.keys() <= files.keys(),
                    "original fixture or full owner records absent")
            wrapper = _object(files["owner-terminal.json"])
            require(set(wrapper) == {"schema", "release_sha256", "host_identity_sha256", "consumed_identity",
                                     "start_check_utc_s", "start_check_raw_ns", "terminal"} and
                    wrapper["schema"] == "aragorn/b50-owner-terminal/v1" and wrapper["release_sha256"] == digest and
                    wrapper["host_identity_sha256"] == entry["host_identity_sha256"] and
                    canonical(wrapper["consumed_identity"]) == canonical(manifest["attempt_identity"]),
                    "terminal not bound to this release, host and reserved attempt directory")
            expected = {k: entry[k] for k in ("fixture_identity", "disk_identity", "store_identity", "disk_sha256")}
            expected.update(attempt_identity=manifest["attempt_identity"], runner_sha256=pin["runner_sha256"],
                            runner_cdhash=pin["cdhash"], store_sha256_before=entry["store_sha256"],
                            policy_sha256_before=entry["policy_sha256"])
            # Only the nested JSON envelope is projected. The journal and serial are the original archived bytes.
            owner = verify_owner_records(uid, {"serial.raw": files["serial.raw"], "owner-events.jsonl": files["owner-events.jsonl"],
                                               "owner-terminal.json": canonical(wrapper["terminal"])}, expected)
            watch = watchdog.verify_watchdog_records(uid, {k: v for k, v in files.items() if k not in OWNER}, owner)
            utc, raw = wrapper["start_check_utc_s"], wrapper["start_check_raw_ns"]
            require(type(utc) is int and entry["not_before_utc"] <= utc < entry["expires_utc"] and
                    type(raw) is int and watch["ready_raw_ns"] <= raw <= owner["start_issued_ns"],
                    "release window or pre-start RAW ordering mismatch")
            # UTC sample is truncated to seconds. Do not count a boundary we cannot place before expiry.
            require(owner["start_issued_ns"] - raw <= (entry["expires_utc"] - utc - 1) * 1_000_000_000,
                    "start is ambiguous at UTC expiry")
            report["watchdog"] = watch
            disposition = "consistent-single-use-transcript"
    except BuildError as exc:
        report["reason"] = str(exc)
    report.update(transcript=disposition, disposition="unresolved-host-loss" if host_loss else disposition)
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    commands = ap.add_subparsers(dest="operation", required=True)
    ex = commands.add_parser("export", help="seal original available evidence; never run a target or remove sources")
    ex.add_argument("ledger", type=Path)
    ex.add_argument("--fixture", type=Path)
    rd = commands.add_parser("replay", help="verify original or byte-preserved portable archive")
    rd.add_argument("manifest_sha256")
    rd.add_argument("--portable", action="store_true")
    for cmd in (ex, rd):
        cmd.add_argument("destination", type=Path)
        cmd.add_argument("uuid")
        cmd.add_argument("commit", help="full, independently pinned signed commit")
        cmd.add_argument("signer", help="out-of-band trusted Git signer fingerprint")
        cmd.add_argument("--release", type=Path, help="private sealed release; default: held, zero attempts")
        cmd.add_argument("--bindings", nargs=2, metavar=("FILE", "SHA256"), help="separately retained private pre-attempt record")
        cmd.add_argument("--host-loss", action="store_true")
    a = ap.parse_args(argv)
    pin, release = authenticated_release(a.commit, a.signer, a.release)
    if a.operation == "export":
        for path in (a.fixture, a.ledger, a.destination):
            if path is not None:
                require_local_custody(path)
        digest = export_owner_archive(a.fixture, a.ledger, a.destination, a.uuid)
    else:
        digest = a.manifest_sha256
    archive, files = read_owner_archive(a.destination, a.uuid, digest, portable=getattr(a, "portable", False))
    bindings = None
    if a.bindings:
        raw = retained(Path(a.bindings[0]), 8192)
        require(sha256(raw) == a.bindings[1], "independent bindings digest mismatch")
        bindings = _object(raw)
    report = assess(archive, files, commit=a.commit, pin=pin, release=release, bindings=bindings, host_loss=a.host_loss)
    print(json.dumps(report | {"manifest_sha256": digest}, sort_keys=True))
    return 0 if report["disposition"] in ("consistent-held-refusal", "consistent-single-use-transcript") else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BuildError, OSError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit(f"Verification refused; preserve all originals and any partial archive: {exc}")
