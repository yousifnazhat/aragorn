from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_PROBE = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-plugin-enable-probe.mjs"
)
_NODE = shutil.which("node")


def _assert_observation_only(test: unittest.TestCase, value: Any) -> None:
    if isinstance(value, list):
        for item in value:
            _assert_observation_only(test, item)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        test.assertFalse(key.endswith("_eligible"), key)
        if key == "status":
            test.assertNotEqual(item, "PASS")
        _assert_observation_only(test, item)


class ProtectedPluginEnableProbeTests(unittest.TestCase):
    def test_static_route_and_claim_ceiling_are_narrow(self) -> None:
        source = _PROBE.read_text()

        self.assertIn(
            'const PLUGIN_ID = "tts-local-cli";',
            source,
        )
        self.assertIn(
            'const ENABLE_ARGS = Object.freeze(["plugins", "enable", PLUGIN_ID]);',
            source,
        )
        self.assertIn(
            "`/runtime/lib/node_modules/openclaw/dist/extensions/${PLUGIN_ID}`",
            source,
        )
        self.assertIn("const PLUGIN_ENTRY = `${PLUGIN_ROOT}/index.js`;", source)
        self.assertIn(
            'schema: "aragorn/openclaw-protected-plugin-enable-observation/v1"',
            source,
        )
        self.assertIn(
            '"sha256:b9a0942063caa917affc1f7ef309e3abcb39dcf755144506f5b1633a66d24b6e"',
            source,
        )
        self.assertIn("file.digest === EXPECTED_CONFIG_DIGEST", source)
        self.assertIn("canonicalDigest === EXPECTED_CONFIG_DIGEST", source)
        self.assertIn(
            'gatewayBefore.cmdline?.[0] === "openclaw-gateway"',
            source,
        )
        self.assertIn('status: started ? "OBSERVED" : "NOT_TESTED"', source)
        self.assertIn("const started = processStarted(enable);", source)
        self.assertNotIn('OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1"', source)
        self.assertNotIn('status: "PASS"', source)
        self.assertNotIn('status: "FAIL"', source)
        self.assertNotIn("decision:", source)
        self.assertIsNone(re.search(r"\b[a-z_]*eligible\b", source))

    @unittest.skipUnless(_NODE, "Node.js is required for the probe checks")
    def test_syntax_and_self_check_are_canonical_and_non_authoritative(self) -> None:
        checked = subprocess.run(
            [_NODE, "--check", str(_PROBE)],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            text=True,
            timeout=5,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(checked.stderr, "")

        completed = subprocess.run(
            [_NODE, str(_PROBE), "self-check"],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            text=True,
            timeout=5,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["assurance"],
            "RAW_ACTION_OBSERVATION_ONLY_NOT_CONFORMANCE_AUTHORITY",
        )
        self.assertEqual(
            result["schema"],
            "aragorn/openclaw-protected-plugin-enable-self-check/v1",
        )
        self.assertEqual(result["status"], "SELF_CHECK_OK")
        self.assertTrue(all(result["checks"].values()))
        self.assertEqual(
            result["native_action"],
            {
                "argv": [
                    "/usr/local/bin/node",
                    "/runtime/lib/node_modules/openclaw/openclaw.mjs",
                    "plugins",
                    "enable",
                    "tts-local-cli",
                ],
                "target_plugin_id": "tts-local-cli",
            },
        )
        _assert_observation_only(self, result)
        canonical = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(completed.stdout, f"{canonical}\n")


if __name__ == "__main__":
    unittest.main()
