"""Approval CLI routing: exercise the Mac shell, not Docker or a real worker."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
RUN = REPO / "scripts/local_quickstart_colima.sh"
PIN = "sha256:" + "a" * 64
DOCKER = """
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
while args[0] in ("--config", "--host"):
    args = args[2:]
if args[0] == "version":
    print("offline")
elif args[0] == "image":
    print("sha256:" + "1" * 64)
elif args[0] == "run":
    Path(os.environ["RECORD"]).write_text(json.dumps(args))
    if "--inventory" in args:
        print('{"tree_digest":"review-only"}')
    elif "--emit-result" in args:
        print('{"total":3}', end="")
elif args[0] != "ps":
    sys.exit(77)
"""


class ApprovalCLI(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(td.cleanup)
        self.root = Path(td.name).resolve()
        sockdir = self.root / ".colima/default"
        sockdir.mkdir(parents=True)
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(sockdir / "docker.sock"))
        for name, source in (("docker", "#!" + sys.executable + "\n" + DOCKER),
                             ("uname", "#!/bin/sh\necho Darwin\n")):
            path = self.root / name
            path.write_text(source)
            path.chmod(0o700)
        self.cap = self.root / "input with spaces"
        self.cap.mkdir()
        (self.cap / "worker.py").write_text("pass\n")
        self.out = self.root / "output directory"
        self.out.mkdir()
        self.record = self.root / "argv"

    def launch(self, *args):
        env = dict(os.environ, HOME=str(self.root), TMPDIR=str(self.root),
                   PATH=f"{self.root}:{os.environ['PATH']}", RECORD=str(self.record))
        return subprocess.run([RUN, *args], cwd=self.root, env=env, capture_output=True, timeout=10)

    def check_guest(self, expected_args):
        argv = json.loads(self.record.read_text())
        mounts = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--mount"]
        self.assertCountEqual(mounts, [
            f"type=bind,source={self.cap},target=/root/aragorn-capability,readonly",
            f"type=bind,source={REPO}/src,target=/opt/aragorn/src,readonly",
            *(f"type=bind,source={REPO}/examples/local-quickstart/{name},"
              f"target=/opt/aragorn/example/{name},readonly"
              for name in ("coordinator.py", "local_approval.py")),
        ])
        self.assertEqual(argv[argv.index("/opt/aragorn/example/coordinator.py") + 1:], expected_args)
        self.assertNotIn(str(self.out), " ".join(argv))

    def test_inventory_routes_to_review_only_and_has_machine_readable_stdout(self):
        r = self.launch("--inventory", self.cap.name)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), {"tree_digest": "review-only"})
        self.check_guest(["--inventory"])

    def test_explicit_prior_digest_passed_with_relative_paths_even_in_export_mode(self):
        r = self.launch("--output", "output directory/new.json", "--approve-tree", PIN,
                        "--capability", self.cap.name)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_guest(["--approve-tree", PIN, "--emit-result"])
        self.assertEqual((self.out / "new.json").read_bytes(), b'{"total":3}')

    def test_invalid_authority_or_unsafe_mount_never_dispatched(self):
        alias = self.root / "alias"
        alias.symlink_to(self.cap)
        for args in (
            ("--capability", self.cap.name), ("--approve-tree", PIN),
            ("--capability", self.cap.name, "--approve-tree", "bad"),
            ("--inventory", self.cap.name, "--output", "x"),
            ("--inventory", self.cap.name, "--approve-tree", PIN),
            ("--inventory", self.cap.name, "--inventory", self.cap.name),
            ("--inventory", "/"), ("--inventory", "alias/"),
            ("--output", "alias/export.json", "--capability", self.cap.name, "--approve-tree", PIN),
        ):
            with self.subTest(args=args):
                self.assertNotEqual(self.launch(*args).returncode, 0)
                self.assertFalse(self.record.exists(), "refused input reached Docker run")
