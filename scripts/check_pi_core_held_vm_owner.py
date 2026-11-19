"""Connect the pinned, zero-boot-authority executable to its watchdog. No target/VM operation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import uuid

from scripts.pi_core_host_owner_supervision import supervise_owner
from scripts.prepare_pi_core_vm_owner import authenticated_pin, verified_binary
from scripts.prepare_pi_core_host_lifecycle import require_local_custody
from scripts.verify_pi_core_host_binding import identity, require


def check_hold(pin, ledger, attempt_uuid):
    require(str(uuid.UUID(attempt_uuid)) == attempt_uuid and uuid.UUID(attempt_uuid).int, "invalid UUID")
    require_local_custody(ledger)
    identity(ledger, True)
    binary = verified_binary(pin)
    run = ledger / attempt_uuid
    run.mkdir(mode=0o700)
    absent = run / "no-target"
    with (run / "refusal.stderr").open("xb") as err:
        # No target media or store is supplied. Deny network and filesystem writes by the child.
        def spawn(stop, arm):
            return subprocess.Popen(["/usr/bin/sandbox-exec", "-p",
                                     "(version 1)(allow default)(deny network*)(deny file-write*)"
                                     "(allow file-write* (literal " + json.dumps(str(run / "refusal.stderr")) + "))",
                                     binary, "own", absent, attempt_uuid, str(stop), str(arm)], pass_fds=(stop, arm),
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, cwd=run,
                                    env={"PATH": "/usr/bin:/bin", "HOME": str(run), "TMPDIR": str(run)})
        row = supervise_owner(spawn, record=run / "watchdog.json", attempt_uuid=attempt_uuid)
        os.fchmod(err.fileno(), 0o400)
        os.fsync(err.fileno())
    require(row["child_returncode"] == 78 and row["child_reaped"] is True and
            row["host_kill_requested"] is False and row["owner_arm"]["queued_raw_ns"] is None and
            not (run / "watchdog.json.owner-arm").exists() and not os.path.lexists(absent) and
            (run / "refusal.stderr").read_bytes() == b"B47 held: no approved boot attempt\n",
            "pinned owner did not demonstrate expected pre-target refusal; retain journal")
    return row


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("commit")
    ap.add_argument("signer")
    ap.add_argument("ledger", type=Path)
    ap.add_argument("uuid")
    a = ap.parse_args()
    check_hold(authenticated_pin(a.commit, a.signer), a.ledger, a.uuid)
    print("Held release refused before target access; no ARM issued.")
