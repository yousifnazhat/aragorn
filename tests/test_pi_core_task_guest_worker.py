"""Task-worker successor only; no guest, service, socket or benchmark is started."""
from configparser import ConfigParser
import hashlib
from pathlib import Path
import subprocess
import unittest

from scripts import build_pi_core_task_worker as task

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "packaging/pi-core/task-worker-v1"


class FixedTaskGuestWorkerTests(unittest.TestCase):
    def test_gate_derives_only_two_endpoint_changes_and_stricter_parent(self):
        base = (ROOT / "packaging/pi-core/source-gate-view-v3.c").read_bytes()
        candidate = task.task_gate(base)
        self.assertEqual(candidate.count(b"!= 0040710"), 1)
        self.assertNotIn(b"provider.sock", candidate)
        self.assertNotIn(b"request.sock", candidate)
        self.assertEqual(candidate.count(b'endpoint("/run/aragorn-pi-bootstrap/tasks", '), 2)
        self.assertIn(b"close_range(UNSHARE)", candidate)
        self.assertIn(b"--disallow-code-generation-from-strings", candidate)
        with self.assertRaises(ValueError):
            task.task_gate(base.replace(b"call5(129, pid, 19", b"call5(129, pid, 18"))

    def test_unit_limits_worker_to_fixed_chroot_and_two_socket_view(self):
        text = (ASSETS / "aragorn-pi-task-worker.service").read_text("ascii")
        cfg = ConfigParser(strict=False, interpolation=None)
        cfg.read_string(text)
        service = cfg["Service"]
        self.assertNotIn("Install", cfg)
        self.assertEqual(service["RootDirectory"], "/var/lib/aragorn/pi-os")
        self.assertEqual(service["ExecStart"].split(), ["/opt/aragorn/pi-runtime/observer/source-gate",
            "/opt/aragorn/pi-runtime/node/bin/node", "--disallow-code-generation-from-strings",
            "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"])
        self.assertEqual(service["Restart"], "no")
        self.assertEqual(service["PrivateNetwork"], "yes")
        self.assertEqual(service["NoNewPrivileges"], "yes")
        self.assertEqual(service["RestrictAddressFamilies"], "AF_UNIX")
        self.assertEqual(service["DynamicUser"], "yes")
        binds = [line for line in text.splitlines() if line.startswith("Bind")]
        self.assertEqual(binds, ["BindLogSockets=no",
            "BindReadOnlyPaths=/var/lib/aragorn/pi-task-runtime:/opt/aragorn/pi-runtime",
            "BindReadOnlyPaths=/run/aragorn-pi-task-view:/run/aragorn-pi-bootstrap"])

    def test_emit_and_read_back_single_file_worker_and_arm64_gate_without_target_execution(self):
        retained = Path(subprocess.check_output(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                            cwd=ROOT, text=True, timeout=5).strip()).parent
        destination = ROOT / ".aragorn/pi-task-worker-v1"
        receipt = task.build(ROOT, retained, destination)
        self.assertIs(receipt["target_executed"], False)
        self.assertEqual(receipt["external_modules"], ["node:events", "node:fs", "node:net"])
        for name in ("entrypoint.js", "source-gate"):
            raw = (destination / name).read_bytes()
            self.assertEqual(receipt["outputs"][name], {"bytes":len(raw), "sha256":hashlib.sha256(raw).hexdigest()})
        with self.assertRaises((ValueError, FileExistsError)):
            task.build(ROOT, retained, destination)
