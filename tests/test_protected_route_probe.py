from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PROBE = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-route-probe.mjs"
)
_COVERAGE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-update-reload-route-coverage-v3-2026-07-28.json"
)
_CONFIG = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-route-config-v1.json"
)
_WORKSHOP = (
    _ROOT / "benchmark" / "fixtures" / "phase1-protected-workshop" / "PROPOSAL.md"
)
_EVIDENCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-protected-route-actions-v5-2026-07-29.json"
)
_RECEIPT = (
    _ROOT
    / "benchmark"
    / "receipts"
    / "phase1-openclaw-protected-route-actions-v5-2026-07-29.json"
)
_NODE = shutil.which("node")


class ProtectedRouteProbeTests(unittest.TestCase):
    def test_retained_live_evidence_remains_raw_only(self) -> None:
        receipt = json.loads(_RECEIPT.read_bytes())
        evidence_raw = _EVIDENCE.read_bytes()
        evidence = json.loads(evidence_raw)

        self.assertEqual(
            receipt["assurance"],
            "OPERATOR_RETAINED_RAW_OBSERVATIONS_NOT_CONFORMANCE_AUTHORITY",
        )
        self.assertFalse(receipt["phase1_exit_eligible"])
        self.assertFalse(receipt["installer_work_eligible"])
        self.assertEqual(receipt["results"]["pass"], [])
        self.assertEqual(receipt["results"]["fail"], [])
        self.assertEqual(receipt["evidence"]["bytes"], len(evidence_raw))
        self.assertEqual(
            receipt["evidence"]["digest"],
            "sha256:" + hashlib.sha256(evidence_raw).hexdigest(),
        )
        self.assertEqual(
            evidence["assurance"],
            "RAW_ACTION_OBSERVATIONS_ONLY_NOT_CONFORMANCE_AUTHORITY",
        )
        self.assertEqual(
            evidence["implementation_digest"],
            receipt["inputs"]["probe"]["digest"],
        )
        for label, path, digest_field in (
            ("probe", _PROBE, "digest"),
            ("configuration", _CONFIG, "raw_digest"),
            ("workshop_proposal", _WORKSHOP, "digest"),
        ):
            raw = path.read_bytes()
            self.assertEqual(receipt["inputs"][label]["bytes"], len(raw))
            self.assertEqual(
                receipt["inputs"][label][digest_field],
                "sha256:" + hashlib.sha256(raw).hexdigest(),
            )
        self.assertEqual(evidence["run_nonce"], receipt["evidence"]["run_nonce"])
        self.assertTrue(evidence["protected_boundary"]["ready"])
        statuses = {route["id"]: route["status"] for route in evidence["routes"]}
        route_ids = [route["id"] for route in evidence["routes"]]
        self.assertEqual(len(route_ids), len(set(route_ids)))
        self.assertLessEqual(set(statuses.values()), {"OBSERVED", "NOT_TESTED"})
        result_groups = [
            receipt["results"][name]
            for name in ("observed", "not_tested", "pass", "fail")
        ]
        self.assertEqual(
            sum(len(group) for group in result_groups),
            len(set().union(*(set(group) for group in result_groups))),
        )
        self.assertEqual(
            set(route_ids),
            set().union(*(set(group) for group in result_groups)),
        )
        self.assertEqual(
            sorted(
                route_id
                for route_id, status in statuses.items()
                if status == "OBSERVED"
            ),
            sorted(receipt["results"]["observed"]),
        )
        self.assertEqual(
            sorted(
                route_id
                for route_id, status in statuses.items()
                if status == "NOT_TESTED"
            ),
            sorted(receipt["results"]["not_tested"]),
        )
        archive = next(
            action
            for action in evidence["actions"]
            if action["id"] == "archive-source-force-replacement"
        )
        self.assertEqual(archive["status"], "OBSERVED")
        self.assertFalse(archive["observations"]["target_after"]["directory"]["exists"])
        self.assertFalse(archive["observations"]["target_after"]["skill"]["exists"])
        self.assertEqual(
            archive["observations"]["upload_begin"]["response"]["value"]["error"][
                "code"
            ],
            "UNAVAILABLE",
        )
        self.assertIn(
            "EROFS",
            archive["observations"]["source_install"]["command"]["stderr_excerpt"],
        )
        core_update = next(
            action
            for action in evidence["actions"]
            if action["id"] == "core-updater-plugin-replacement"
        )
        self.assertEqual(core_update["status"], "OBSERVED")
        response = core_update["observations"]["update_repair"]["response"]
        self.assertTrue(response["parsed"])
        repair = core_update["observations"]["update_repair"]["command"]
        self.assertEqual(
            repair["argv"][-7:],
            [
                "update",
                "repair",
                "--timeout",
                "10",
                "--yes",
                "--json",
                "--no-restart",
            ],
        )
        self.assertEqual(repair["exit_code"], 0)
        self.assertIsNone(repair["error"])
        self.assertIsNone(repair["signal"])
        self.assertEqual(response["value"]["mode"], "finalize")
        self.assertEqual(response["value"]["status"], "ok")
        self.assertFalse(response["value"]["restart"])
        plugins = response["value"]["postUpdate"]["plugins"]
        self.assertFalse(plugins["changed"])
        self.assertEqual(plugins["npm"]["outcomes"], [])
        inventory_before = core_update["observations"]["inventory_before"]
        inventory_after = core_update["observations"]["inventory_after"]
        self.assertEqual(inventory_before["command"]["exit_code"], 0)
        self.assertEqual(inventory_after["command"]["exit_code"], 0)
        self.assertEqual(
            inventory_before["response"]["value"],
            inventory_after["response"]["value"],
        )
        self.assertEqual(inventory_after["response"]["value"]["plugins"], [])
        self.assertEqual(
            core_update["observations"]["roots_before"],
            core_update["observations"]["roots_after"],
        )
        self.assertEqual(
            core_update["observations"]["configuration_after"],
            evidence["protected_boundary"]["configuration"],
        )

    @unittest.skipUnless(_NODE, "Node.js is required for the route dispatcher check")
    def test_source_is_exactly_bounded_and_selector_only(self) -> None:
        source = _PROBE.read_text(encoding="utf-8")
        coverage = json.loads(_COVERAGE.read_bytes())
        expected = [
            route["id"] for route in coverage["routes"] if route["status"] != "PASS"
        ]
        source_routes = sorted(
            set(re.findall(r'"(ADM-02/(?:update|reload)/[^"]+)"', source))
        )

        self.assertEqual(source_routes, sorted(expected))
        self.assertNotIn('"PASS"', source)
        self.assertNotIn("installer_work_eligible", source)
        self.assertNotIn("benchmark/evidence", source)
        self.assertIn(
            "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
            source,
        )
        for expected in (
            "/profile/config.json",
            "/profile/home/.agents/skills",
            "/profile/state/extensions",
            "/profile/state/plugin-skills",
            "/profile/state/skills",
            "/profile/workspace/.agents/skills",
            "/profile/workspace/skills",
            "/runtime",
            "sha256:6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a",
            "sha256:a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
        ):
            self.assertIn(expected, source)
        self.assertIn(
            "WORKSPACE_SKILLS_EXPLICIT_RO_MOUNT_REQUIRED",
            source,
        )
        self.assertIn('readFileSync("/proc/1/stat"', source)
        self.assertIn("info.pid === 1", source)
        self.assertIn("RUN_NONCE", source)

        config = json.loads(_CONFIG.read_bytes())
        config_canonical = json.dumps(
            config,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self.assertEqual(
            hashlib.sha256(config_canonical).hexdigest(),
            "6226f46581416178666681d870d3ff54c5bccebeebb090cb3c996058db1c8a4a",
        )
        self.assertEqual(
            hashlib.sha256(_WORKSHOP.read_bytes()).hexdigest(),
            "a7cd9e12c3c00b4480c173ab92ffedbbbc31ff06e5c9200da829144c8a8f160a",
        )

        selected = [
            "ADM-02/update/clawhub-tracked-replacement",
            "ADM-02/update/curator-restore-activation",
            "ADM-02/reload/manual-plugin-invalidation",
        ]
        command = [_NODE, str(_PROBE)]
        for route_id in selected:
            command.extend(("--route-id", route_id))
        completed = subprocess.run(
            command,
            capture_output=True,
            check=False,
            cwd=_ROOT,
            text=True,
            timeout=5,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        result = json.loads(completed.stdout)
        self.assertEqual(result["selected_route_ids"], selected)
        self.assertEqual([route["id"] for route in result["routes"]], selected)
        self.assertEqual(
            {route["status"] for route in result["routes"]}, {"NOT_TESTED"}
        )
        self.assertEqual(result["actions"], [])
        self.assertEqual(
            {route["reason_codes"][0] for route in result["routes"]},
            {"REQUIRED_ROUTE_ADAPTER_ABSENT"},
        )
        canonical = json.dumps(
            result,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        self.assertEqual(completed.stdout, f"{canonical}\n")

        protected = subprocess.run(
            [
                _NODE,
                str(_PROBE),
                "--route-id",
                "ADM-02/update/workshop-proposal-apply",
            ],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            text=True,
            timeout=5,
        )
        self.assertEqual(protected.returncode, 0, protected.stderr)
        protected_result = json.loads(protected.stdout)
        self.assertEqual(protected_result["routes"][0]["status"], "NOT_TESTED")
        self.assertEqual(protected_result["actions"][0]["commands"], [])
        self.assertIn(
            "WORKSPACE_SKILLS_EXPLICIT_RO_MOUNT_REQUIRED",
            protected_result["actions"][0]["reason_codes"],
        )

        invalidation = subprocess.run(
            [
                _NODE,
                str(_PROBE),
                "--route-id",
                "ADM-02/reload/workshop-invalidation",
            ],
            capture_output=True,
            check=False,
            cwd=_ROOT,
            text=True,
            timeout=5,
        )
        self.assertEqual(invalidation.returncode, 0, invalidation.stderr)
        invalidation_result = json.loads(invalidation.stdout)
        self.assertEqual(invalidation_result["actions"], [])
        self.assertEqual(
            invalidation_result["routes"][0]["reason_codes"],
            ["WORKSHOP_INVALIDATION_NOT_REACHED_AFTER_PROTECTED_APPLY_DENIAL"],
        )


if __name__ == "__main__":
    unittest.main()
