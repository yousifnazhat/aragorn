"""Host export contract. A fake Docker client never connects to a daemon."""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest


LAUNCHER = Path(__file__).resolve().parents[1] / "scripts/local_quickstart_colima.sh"
SHIM = """#!/bin/bash
set -eu
while [[ "$1" == --host || "$1" == --config ]]; do shift 2; done
case "$1" in
  version) echo 'test';;
  image) printf 'sha256:%064d\\n' 1;;
  run)
    # An output filename or its parent must never be passed into the container.
    for arg in "$@"; do
      [[ "$arg" != *"$DEST_PARENT"* ]] || exit 70
    done
    if [[ "$*" == *" --emit-result" ]]; then
      printf '%s' "$PAYLOAD"
    else
      echo 'human-readable walkthrough'
    fi;;
  ps)
    if [[ "$SCENARIO" == success && ( -e "$DEST" || -L "$DEST" ) ]]; then exit 71; fi
    if [[ "$SCENARIO" == race ]]; then printf 'other writer' >"$DEST"; fi
    touch "$HOME/cleanup-observed"
    [[ "$SCENARIO" != unconfirmed ]];;
  *) exit 72;;
esac
"""


class TestLocalQuickstartOutput(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        folder = self.home / ".colima/default"
        folder.mkdir(parents=True)
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(folder / "docker.sock"))
        self.out = self.home / "chosen destination" / "result.json"
        self.out.parent.mkdir()
        for name, source in (("docker", SHIM), ("uname", "#!/bin/sh\necho Darwin\n")):
            path = self.home / name
            path.write_text(source)
            path.chmod(0o700)

    def launch(self, scenario="success", payload='{"total":3}'):
        env = dict(os.environ, HOME=str(self.home), TMPDIR=str(self.home),
                   PATH=f"{self.home}:{os.environ['PATH']}", DEST=str(self.out),
                   DEST_PARENT=str(self.out.parent), PAYLOAD=payload, SCENARIO=scenario)
        return subprocess.run([LAUNCHER, "--output", self.out], env=env, capture_output=True,
                              timeout=10)

    def test_exports_verified_bytes_only_after_cleanup(self):
        result = self.launch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / "cleanup-observed").is_file())
        self.assertTrue(self.out.is_file(), "verified result was not exported")
        self.assertEqual(self.out.read_bytes(), b'{"total":3}')

    def test_indeterminate_cleanup_never_exports(self):
        result = self.launch("unconfirmed")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.home / "cleanup-observed").is_file())
        self.assertFalse(os.path.lexists(self.out))

    def test_unexpected_payload_never_exports(self):
        self.assertNotEqual(self.launch(payload='{"total":4}').returncode, 0)
        self.assertFalse(os.path.lexists(self.out))

    def test_existing_file_or_dangling_symlink_never_overwritten(self):
        self.out.write_bytes(b"keep")
        self.assertNotEqual(self.launch("collision").returncode, 0)
        self.assertEqual(self.out.read_bytes(), b"keep")
        self.out.unlink()
        self.out.symlink_to("missing")
        self.assertNotEqual(self.launch("collision").returncode, 0)
        self.assertEqual(os.readlink(self.out), "missing")
        self.assertFalse((self.out.parent / "missing").exists())

    def test_concurrent_destination_creation_is_not_overwritten(self):
        self.assertNotEqual(self.launch("race").returncode, 0)
        self.assertEqual(self.out.read_bytes(), b"other writer")
