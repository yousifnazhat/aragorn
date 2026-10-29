from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SUITE = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "final-admission-v2-suite.mjs"
)
_NODE = shutil.which("node")
_ROUTES = [
    "ADM-02/update/archive-source-force-replacement",
    "ADM-02/update/clawhub-tracked-replacement",
    "ADM-02/update/config-entry-activation",
    "ADM-02/update/core-updater-plugin-replacement",
    "ADM-02/update/curator-restore-activation",
    "ADM-02/update/plugin-enable-activation",
    "ADM-02/update/plugin-force-reinstall",
    "ADM-02/update/plugin-package-skill-replacement",
    "ADM-02/update/workshop-proposal-apply",
    "ADM-02/reload/chat-session-snapshot-consumer",
    "ADM-02/reload/config-invalidation",
    "ADM-02/reload/cron-rescan",
    "ADM-02/reload/filesystem-watch-invalidation",
    "ADM-02/reload/fresh-session-reset",
    "ADM-02/reload/manual-plugin-invalidation",
    "ADM-02/reload/missing-prompt-blob-rebuild",
    "ADM-02/reload/plugin-skill-dir-activation",
    "ADM-02/reload/remote-eligibility-invalidation",
    "ADM-02/reload/sandbox-per-run-rescan",
    "ADM-02/reload/session-snapshot-consumer",
    "ADM-02/reload/workshop-invalidation",
]


class FinalAdmissionV2SuiteTests(unittest.TestCase):
    def _run(self, *args: str, env: dict[str, str] | None = None) -> dict:
        if _NODE is None:
            self.skipTest("node is not installed")
        result = subprocess.run(
            [_NODE, str(_SUITE), *args],
            capture_output=True,
            check=False,
            env=env,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, "")
        document = json.loads(result.stdout)
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
        self.assertEqual(result.stdout, canonical)
        self.assertEqual(
            document["schema"],
            "aragorn/openclaw-final-admission-v2-suite-error/v1",
        )
        self.assertEqual(document["decision"]["status"], "FAIL_CLOSED")
        self.assertTrue(
            all(
                value is False
                for key, value in document["decision"].items()
                if key.endswith("_eligible")
            )
        )
        return document

    def test_exact_environment_and_route_contract_fail_closed(self) -> None:
        missing = self._run("manifest", env={})
        self.assertEqual(
            missing["fatal_error"]["message"], "ARAGORN environment changed"
        )

        required = {
            "ARAGORN_CONFIG_PATH": "/missing/config",
            "ARAGORN_PROBE_ROOT": "/missing/probes",
            "ARAGORN_PROFILE_PATH": "/missing/profile",
            "ARAGORN_RUN_NONCE": "0" * 64,
            "ARAGORN_RUNTIME_LOCK_PATH": "/missing/lock",
            "ARAGORN_RUNTIME_ROOT": "/missing/runtime",
            "ARAGORN_SKILL_PATH": "/missing/skill",
        }
        extra = self._run("manifest", env={**required, "ARAGORN_EXTRA": "rejected"})
        self.assertEqual(extra["fatal_error"]["message"], "ARAGORN environment changed")

        invalid_mode = self._run("manifest", "extra", env=required)
        self.assertEqual(
            invalid_mode["fatal_error"]["message"],
            "usage: final-admission-v2-suite.mjs manifest|main|adm03",
        )

        routes = re.findall(
            r'"(ADM-02/(?:update|reload)/[a-z0-9-]+)"',
            _SUITE.read_text(encoding="utf8"),
        )
        self.assertEqual(routes, _ROUTES)

    def test_malformed_eligibility_values_are_rejected(self) -> None:
        if _NODE is None:
            self.skipTest("node is not installed")
        script = r"""
const fs = require("node:fs");
const source = fs.readFileSync(process.argv[1], "utf8");
const match = source.match(
  /function rejectEligibility\(value, label = "observation"\) \{[\s\S]*?\n\}\n\nfunction evidenceArtifacts/,
);
if (!match) throw new Error("rejectEligibility source contract not found");
function fail(message) { throw new Error(message); }
eval(match[0].replace(/\n\nfunction evidenceArtifacts$/, ""));
rejectEligibility({ candidate_eligible: false });
for (const value of [true, 0, 1, "", "yes", null]) {
  let rejected = false;
  try { rejectEligibility({ candidate_eligible: value }); } catch { rejected = true; }
  if (!rejected) throw new Error(`eligibility bypass accepted: ${String(value)}`);
}
"""
        result = subprocess.run(
            [_NODE, "-e", script, str(_SUITE)],
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
