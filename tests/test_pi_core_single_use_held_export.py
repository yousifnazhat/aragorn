"""Run only the new signed empty-list executable, without a target, and preserve its refusal."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

from scripts import prepare_pi_core_single_use_owner as build
from scripts.pi_core_host_owner_supervision import supervise_owner
from scripts.pi_core_owner_archive import export_owner_archive
from scripts.prepare_pi_core_host_lifecycle import require_local_custody


class HeldExport(unittest.TestCase):
    def test_distributed_candidate_refuses_before_target_or_watchdog_grant(self):
        pin = json.loads(build.PIN.read_bytes())
        self.assertIs(pin["boot_authorized"], False)
        runner = build.verified_binary(pin)
        # Unique, retained outside the checkout even on failure. Nothing here is a VM fixture.
        root = Path(tempfile.mkdtemp(prefix="refusal-", dir=build.WORK))
        require_local_custody(root)
        ledger, archive = root / "ledger", root / "archive"
        uid = str(uuid.uuid4())
        run = ledger / uid
        for p in (ledger, archive, run):
            p.mkdir(mode=0o700)
        absent = run / "no-target"
        refusal = run / "refusal.stderr"
        with refusal.open("xb") as err:
            profile = ("(version 1)(allow default)(deny network*)(deny file-write*)"
                       "(allow file-write* (literal " + json.dumps(str(refusal)) + "))")

            def spawn(stop, arm):
                return subprocess.Popen(["/usr/bin/sandbox-exec", "-p", profile, runner, "own",
                                         absent, uid, str(stop), str(arm)], pass_fds=(stop, arm),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                                        cwd=run, env={"PATH":"/usr/bin:/bin","HOME":str(run),"TMPDIR":str(run)})

            row = supervise_owner(spawn, record=run / "watchdog.json", attempt_uuid=uid)
            os.fchmod(err.fileno(), 0o400)
            os.fsync(err.fileno())
        self.assertEqual(refusal.read_bytes(), b"B50 held: no approved boot attempt\n")
        self.assertEqual((row["child_returncode"], row["child_reaped"], row["host_kill_requested"]),
                         (78, True, False))
        self.assertIsNone(row["owner_arm"]["ready_raw_ns"])
        self.assertIsNone(row["owner_arm"]["queued_raw_ns"])
        self.assertEqual({p.name for p in run.iterdir()}, {"watchdog.json.started","watchdog.json","refusal.stderr"})
        digest = export_owner_archive(None, ledger, archive, uid)
        print("B50 retained refusal:", json.dumps({"archive":str(archive), "attempt_uuid":uid,
                                                   "manifest_sha256":digest}), flush=True)
