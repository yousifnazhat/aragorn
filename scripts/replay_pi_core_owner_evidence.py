"""B48: export and independently replay original B47 evidence. No launch, cleanup or release operation."""
import argparse
import json
from pathlib import Path
import re
import sys

from scripts.build_pi_core_linux import BuildError, canonical, require, sha256
from scripts.pi_core_owner_archive import export_owner_archive, read_owner_archive
from scripts.prepare_pi_core_host_lifecycle import require_local_custody
from scripts.prepare_pi_core_vm_owner import SCHEMA, authenticated_pin
from scripts.verify_pi_core_host_binding import retained, unique
from scripts.verify_pi_core_owner_records import verify_owner_records
from scripts.verify_pi_core_owner_watchdog import verify_watchdog_records


OWNER = {"owner-events.jsonl", "owner-terminal.json", "serial.raw"}
BINDINGS = {"schema", "release_commit", "attempt_uuid", "fixture_identity", "disk_identity", "store_identity",
            "policy_sha256_before", "store_sha256_before"}
HELD_RELEASE = "2c5ffefd4eb65b93c6a818f546e3aa1fbbaa0e1be610e60fc5aef4fca985f87a"


def checked_pin(pin):
    require(pin.get("schema") == SCHEMA and pin.get("boot_authorized") is False and
            pin.get("release_sha256") == HELD_RELEASE and
            all(isinstance(pin.get(k), str) and re.fullmatch(r"[a-f0-9]{64}", pin[k])
                for k in ("runner_sha256", "disk_sha256")) and
            isinstance(pin.get("cdhash"), str) and re.fullmatch(r"[a-f0-9]{40}", pin["cdhash"]),
            "not a recognized B47 zero-boot-authority pin")
    return pin


def load_bindings(path, expected_sha256):
    # Operator/custodian supplies a separately pinned pre-attempt binding document, never producer JSON.
    data = retained(path, 8192)
    require(sha256(data) == expected_sha256, "independent bindings digest mismatch")
    return json.loads(data, object_pairs_hook=unique)


def assess(manifest, files, *, commit, pin, bindings=None, host_loss=False):
    """Assess a byte-verified archive. A result never authorizes action, even when internally consistent."""
    checked_pin(pin)
    uid = manifest["attempt_uuid"]
    report = {"schema":"aragorn/b48-owner-evidence-replay/v1", "attempt_uuid":uid, "release_commit":commit,
              "archive_files":sorted(files), "boot_verified":False, "restoration_verified":False,
              "phase3_exit_eligible":False, "retry_authorized":False, "cleanup_authorized":False,
              "host_loss_reported":host_loss}
    disposition = "indeterminate"
    try:
        require(all(row["source"]["mode"] == 0o400 for row in manifest["files"].values()),
                "unsealed source artifact; preserve as partial")
        names = OWNER.intersection(files)
        ledger = {k:v for k,v in files.items() if k not in OWNER}
        if not names:
            require(bindings is None and manifest["fixture_identity"] is None and manifest["attempt_identity"] is None and
                    manifest["ledger_attempt_identity"] is not None,
                    "no affirmative pre-target refusal with absent target context")
            report["watchdog"] = verify_watchdog_records(uid, ledger)
            disposition = "consistent-held-refusal"
        else:
            require(names == OWNER, "incomplete owner records; no inferred terminal state")
            require(isinstance(bindings, dict) and set(bindings) == BINDINGS and
                    bindings["schema"] == "aragorn/b48-independent-target-bindings/v1" and
                    bindings["attempt_uuid"] == uid and bindings["release_commit"] == commit,
                    "independent bindings missing or for another attempt/release")
            require(canonical(bindings["fixture_identity"]) == canonical(manifest["fixture_identity"]) and
                    manifest["attempt_identity"] is not None and manifest["ledger_attempt_identity"] is not None,
                    "source directories differ from independent fixture")
            expected = {k:bindings[k] for k in BINDINGS - {"attempt_uuid","schema","release_commit"}}
            expected.update(attempt_identity=manifest["attempt_identity"], runner_sha256=pin["runner_sha256"],
                            runner_cdhash=pin["cdhash"], disk_sha256=pin["disk_sha256"])
            observed = verify_owner_records(uid, {k:files[k] for k in OWNER}, expected)
            report["watchdog"] = verify_watchdog_records(uid, ledger, observed)
            report["recorded_timestamps"] = observed
            # A coherent transcript cannot originate in an authorized target run of this held binary.
            disposition = "transcript-conflicts-with-held-release"
    except BuildError as e:
        report["reason"] = str(e)
    report["transcript"] = disposition
    report["disposition"] = "unresolved-host-loss" if host_loss else disposition
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    ex = commands.add_parser("export", help="seal a new local archive without changing the sources")
    ex.add_argument("ledger", type=Path)
    ex.add_argument("--fixture", type=Path, help="exact fixture root; omit only for a known pre-target refusal")
    rd = commands.add_parser("replay", help="reread an archive against an externally retained digest")
    rd.add_argument("manifest_sha256")
    rd.add_argument("--portable", action="store_true", help="verify copied bytes; not original local inode custody")
    for p in (ex, rd):
        p.add_argument("destination", type=Path)
        p.add_argument("uuid")
        p.add_argument("commit", help="operator-pinned full release commit")
        p.add_argument("signer", help="out-of-band trusted Git signer fingerprint")
        p.add_argument("--bindings", nargs=2, metavar=("FILE","SHA256"))
        p.add_argument("--host-loss", action="store_true", help="force unresolved host-loss disposition")
    a = parser.parse_args(argv)
    pin = checked_pin(authenticated_pin(a.commit, a.signer))
    facts = load_bindings(Path(a.bindings[0]), a.bindings[1]) if a.bindings else None
    if a.operation == "export":
        for path in (a.fixture, a.ledger, a.destination):
            if path is not None:
                require_local_custody(path)
        digest = export_owner_archive(a.fixture, a.ledger, a.destination, a.uuid)
    else:
        digest = a.manifest_sha256
    manifest, files = read_owner_archive(a.destination, a.uuid, digest, portable=getattr(a, "portable", False))
    report = assess(manifest, files, commit=a.commit, pin=pin, bindings=facts, host_loss=a.host_loss)
    report.update(manifest_sha256=digest, portable=getattr(a, "portable", False))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["disposition"] == "consistent-held-refusal" else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BuildError, OSError, ValueError) as exc:
        sys.exit(f"Evidence verification refused; preserve all sources and any partial archive: {exc}")
