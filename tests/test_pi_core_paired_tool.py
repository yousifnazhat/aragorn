"""Run the real Pi tool executor over two in-memory frame channels; no sockets or model."""
import hashlib
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts import build_pi_core_linux as build

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "packaging/pi-core"


class PairedToolTests(TestCase):
    def test_exact_single_hop_with_pinned_pi_no_provider_or_reconnect(self):
        pins = json.loads((PACKAGE / "offline-toolchain-v1.json").read_bytes())
        node = Path(pins["node"]["executable"])
        common = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=ROOT,
                                check=True, capture_output=True, text=True, timeout=5)
        deps = PACKAGE / "node_modules"
        if not deps.is_dir():
            deps = Path(common.stdout.strip()).parent / "packaging/pi-core/node_modules"
        def check_inputs():
            self.assertEqual(hashlib.sha256(node.read_bytes()).hexdigest(), pins["node"]["sha256"])
            self.assertEqual(build.sha256(build.canonical(build.tree_inventory(deps))), pins["dependency_tree_sha256"])
        check_inputs()
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "node_modules").symlink_to(deps, target_is_directory=True)
            (root / "paired-task.mjs").write_bytes((PACKAGE / "paired-task.mjs").read_bytes())
            (root / "check.mjs").write_bytes((ROOT / "tests/fixtures/pi_core_paired_tool_offline.mjs").read_bytes())
            result = subprocess.run([str(node), "--disallow-code-generation-from-strings", "./check.mjs"], cwd=root,
                                    env={"HOME": temp, "TMPDIR": temp, "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                                    timeout=10, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace")[-1536:])
        check_inputs()
