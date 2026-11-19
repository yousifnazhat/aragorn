"""One preparation from the actual pinned Ubuntu packages. Not a toolchain or build."""
import json
from pathlib import Path
import unittest

from scripts import prepare_pi_core_host_tool_targets as tools


class UbuntuHostToolSource(unittest.TestCase):
    def test_prepare_the_three_targets_from_the_authenticated_ubuntu_source(self):
        inputs = Path(__file__).resolve().parents[1] / ".aragorn/host-preflight/build-b38"
        dest = inputs / "client-source"
        receipt = tools.prepare(inputs, dest)
        self.assertEqual(receipt["targets"], ["systemctl", "systemd-run", "busctl"])
        self.assertEqual(receipt["ubuntu_patches"], 19)
        self.assertEqual(receipt["meson_sha256"], "19c3cc650bd3e2d856a172db57a359d04392adbb0e6a53226952998a3d9a5428")
        self.assertFalse(any(receipt[k] for k in ("built", "installed", "phase3_exit_eligible")))
        with (dest / "source-preparation.json").open("x", encoding="ascii") as out:
            json.dump(receipt, out, sort_keys=True)
        print(json.dumps(receipt, sort_keys=True), flush=True)
