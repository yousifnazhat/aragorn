from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_BROKER_COMMIT = "ef3e4865f60e0924ca1cab3cf8683ec678ad2e7f"
_SERVICE_COMMIT = "45257585d8c9dd4c6b92059e049857e2102edf22"
_BROKER = "benchmark/admission/openclaw-v2026.7.1/protected-install-broker.py"
_SERVICE = "packaging/systemd/aragorn-protected-install.service"
_LIVE = (
    _ROOT
    / "benchmark/evidence/"
    "openclaw-v2026.7.1-protected-analyzer-isolation-live-"
    "4525758-2026-07-29.json"
)
_RETENTION = (
    _ROOT
    / "benchmark/receipts/"
    "phase1-protected-analyzer-isolation-live-retention-"
    "4525758-2026-07-29.json"
)


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _commit_bytes(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        check=True,
        cwd=_ROOT,
        stdout=subprocess.PIPE,
    ).stdout


class ProtectedInstallAnalyzerLiveTests(unittest.TestCase):
    def test_unprivileged_analyzer_capture_is_exact_but_not_phase1_exit(self) -> None:
        live_raw = _LIVE.read_bytes()
        retention_raw = _RETENTION.read_bytes()
        live = json.loads(live_raw)
        retention = json.loads(retention_raw)
        self.assertEqual(live_raw, _canonical(live))
        self.assertEqual(retention_raw, _canonical(retention))
        self.assertEqual(retention["evidence"]["file_digest"], _digest(live_raw))
        self.assertEqual(retention["evidence"]["file_bytes"], len(live_raw))

        self.assertEqual(live["slice_status"], "PASS")
        self.assertEqual(live["transaction"]["operation"], "update")
        self.assertEqual(
            live["analyzer"]["execution_identity"],
            {
                "gid": 983,
                "group": "aragorn-analyze",
                "supplementary_groups": [],
                "uid": 983,
                "user": "aragorn-analyze",
            },
        )
        self.assertNotIn(
            "ANALYZER_EXECUTES_AS_ROOT_WITHOUT_OS_SANDBOX_OR_UID_DROP",
            live["limitations"],
        )
        self.assertFalse(live["decision"]["installer_work_eligible"])
        self.assertEqual(retention["result"]["installed_digest_mismatches"], 0)
        self.assertEqual(retention["result"]["active"], live["active"])
        self.assertFalse(retention["phase1_exit_eligible"])
        self.assertTrue(
            all(
                not attempt["retained_as_exit_evidence"]
                for attempt in retention["discarded_attempts"]
            )
        )

        broker = _commit_bytes(_BROKER_COMMIT, _BROKER)
        service = _commit_bytes(_SERVICE_COMMIT, _SERVICE)
        implementation = retention["implementation"]
        self.assertEqual(_digest(broker), implementation["broker_digest"])
        self.assertEqual(_digest(service), implementation["service_file_digest"])
        self.assertIn(b'_PASSWD_PATH = Path("/etc/passwd")', broker)
        self.assertIn(b"if os.geteuid()!=", broker)
        self.assertIn(b"('CapEff','CapPrm','CapAmb')", broker)
        self.assertNotIn(b"\nimport grp\n", broker)
        self.assertNotIn(b"\nimport pwd\n", broker)
        for directive in (
            b"CapabilityBoundingSet=CAP_SETGID CAP_SETUID\n",
            b"AmbientCapabilities=CAP_SETGID CAP_SETUID\n",
            b"PrivateNetwork=yes\n",
            b"RestrictSUIDSGID=yes\n",
            b"SystemCallFilter=~@network-io @mount @reboot @swap @raw-io @clock\n",
        ):
            self.assertIn(directive, service)


if __name__ == "__main__":
    unittest.main()
