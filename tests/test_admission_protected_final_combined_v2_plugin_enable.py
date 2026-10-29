from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import admission_protected_final_combined_v2_plugin_enable as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-plugin-"
    "enable-activation-route-coverage-v1-2026-08-27.json"
)


class FinalCombinedV2PluginEnableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = (_ROOT / subject._EVIDENCE["path"]).read_bytes()
        cls.evidence = json.loads(cls.raw)

    def verify(
        self,
        raw: bytes | None = None,
        *,
        identity: dict[str, object] | None = None,
    ) -> dict[str, object]:
        raw = self.raw if raw is None else raw
        identity = subject._EVIDENCE if identity is None else identity
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = CAS(temporary.name)
        store.put_expected(
            BytesIO(raw), expected_digest=identity["digest"], max_bytes=len(raw)
        )
        return subject.verify_openclaw_final_combined_v2_plugin_enable(
            evidence_cas=store
        )

    def coordinated(self, evidence: dict[str, object]) -> None:
        document = evidence["route_observation"]["document"]
        document_raw = canonical_json(document) + b"\n"
        route_raw = {
            "bytes": len(document_raw),
            "canonical_digest": canonical_digest(document),
            "digest": "sha256:" + hashlib.sha256(document_raw).hexdigest(),
        }
        evidence["route_observation"]["raw"] = {
            "base64": base64.b64encode(document_raw).decode(),
            **route_raw,
            "raw_is_canonical_json_lf": True,
        }
        raw = canonical_json(evidence) + b"\n"
        identity = {
            **subject._EVIDENCE,
            "bytes": len(raw),
            "canonical_bytes": len(raw) - 1,
            "canonical_digest": canonical_digest(evidence),
            "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
        }
        route = evidence["route_observation"]
        digests = {
            "composition": canonical_digest(evidence["composition"]),
            "source_artifacts": canonical_digest(evidence["source_artifacts"]),
            "route_observation": canonical_digest(route),
            "execution": canonical_digest(route["execution"]),
            "gateway": canonical_digest(route["gateway_pid_binding"]),
            "stack": canonical_digest(route["stack_before"]),
            "document": canonical_digest(document),
            "action": canonical_digest(document["action"]),
        }
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_ROUTE_RAW", route_raw),
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_verify_retained_evidence", return_value=raw),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(raw, identity=identity)

    def test_exact_route_pass_and_receipt(self) -> None:
        result = self.verify()

        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        self.assertEqual(
            [
                route["id"]
                for route in result["profile"]["routes"]
                if route["status"] == "PASS"
            ],
            [subject._ROUTE],
        )
        self.assertTrue(result["route_semantics"]["transitions_dynamically_exercised"])
        self.assertEqual(result["bindings"]["image"], subject._IMAGE)
        self.assertEqual(
            result["bindings"]["plugin_enable_observation"]["retention"]["commit"],
            subject._RETENTION["commit"],
        )
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.base.base.legacy.parent._ELIGIBILITY_KEYS
            )
        )
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_cas_and_coordinated_semantic_repins_fail_closed(self) -> None:
        with (
            patch.object(subject, "_verify_retained_evidence", return_value=b"{}\n"),
            self.assertRaisesRegex(AdmissionEvidenceError, "signed retention"),
        ):
            self.verify()

        enabled = deepcopy(self.evidence)
        action = enabled["route_observation"]["document"]["action"]
        for location in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            plugin = location["response"]["value"]["plugin"]
            plugin["enabled"] = True
            plugin["explicitlyEnabled"] = True
            plugin["activated"] = True
            plugin["status"] = "loaded"
        self.coordinated(enabled)

        allowed = deepcopy(self.evidence)
        action = allowed["route_observation"]["document"]["action"]
        action["commands"][3]["exit_code"] = 0
        action["observations"]["native_enable"]["command"]["exit_code"] = 0
        self.coordinated(allowed)

        rebound = deepcopy(self.evidence)
        action = rebound["route_observation"]["document"]["action"]
        for location in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            location["canonical_digest"] = "sha256:" + "0" * 64
            location["file"]["digest"] = "sha256:" + "0" * 64
        self.coordinated(rebound)

        eligible = deepcopy(self.evidence)
        eligible["decision"]["edr_eligible"] = 0
        self.coordinated(eligible)

        empty_stack = deepcopy(self.evidence)
        empty_stack["route_observation"]["stack_before"] = {}
        self.coordinated(empty_stack)

        zero_pid = deepcopy(self.evidence)
        action = zero_pid["route_observation"]["document"]["action"]
        action["commands"][3]["pid"] = 0
        action["observations"]["native_enable"]["command"]["pid"] = 0
        self.coordinated(zero_pid)

        false_inspection = deepcopy(self.evidence)
        action = false_inspection["route_observation"]["document"]["action"]
        action["commands"][2]["argv"] = ["/bin/false"]
        action["commands"][2]["pid"] = 0
        action["commands"][4]["argv"] = ["/bin/false"]
        action["commands"][4]["pid"] = 0
        action["prerequisites"]["plugin_before"]["command"] = action["commands"][2]
        action["observations"]["plugin_after"]["command"] = action["commands"][4]
        self.coordinated(false_inspection)

        source_repin = deepcopy(self.evidence)
        source_repin["source_artifacts"]["collector"]["digest"] = (
            "sha256:" + "0" * 64
        )
        source_artifacts = deepcopy(subject._SOURCE_ARTIFACTS)
        source_artifacts["collector"]["digest"] = "sha256:" + "0" * 64
        with patch.object(subject, "_SOURCE_ARTIFACTS", source_artifacts):
            self.coordinated(source_repin)

        public_network = deepcopy(self.evidence)
        public_network["composition"]["action"]["harness"]["document"][
            "host_config"
        ]["network_mode"] = "host"
        self.coordinated(public_network)

        writable_config = deepcopy(self.evidence)
        action = writable_config["route_observation"]["document"]["action"]
        for configuration in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            configuration["mount"]["records"][0]["mount_options"] = ["rw"]
        self.coordinated(writable_config)

        missing_config = deepcopy(self.evidence)
        action = missing_config["route_observation"]["document"]["action"]
        for configuration in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            configuration["file"]["exists"] = False
        self.coordinated(missing_config)

        gateway_pid = deepcopy(self.evidence)
        action = gateway_pid["route_observation"]["document"]["action"]
        action["commands"][3]["pid"] = 2680
        action["observations"]["native_enable"]["command"]["pid"] = 2680
        self.coordinated(gateway_pid)

        reversed_duration = deepcopy(self.evidence)
        action = reversed_duration["route_observation"]["document"]["action"]
        action["commands"][3]["started_at"] = "2026-08-27T21:16:44.500Z"
        action["observations"]["native_enable"]["command"]["started_at"] = (
            "2026-08-27T21:16:44.500Z"
        )
        self.coordinated(reversed_duration)

        harness_owner = deepcopy(self.evidence)
        harness_owner["composition"]["action"]["harness"]["file"]["stat"][
            "uid"
        ] = 992
        self.coordinated(harness_owner)

    def test_duplicate_and_nonfinite_json_fail_closed(self) -> None:
        duplicate = self.raw.replace(
            b'{"authority":', b'{"authority":"duplicate","authority":', 1
        )
        identity = {
            **subject._EVIDENCE,
            "bytes": len(duplicate),
            "canonical_bytes": len(duplicate) - 1,
            "digest": "sha256:" + hashlib.sha256(duplicate).hexdigest(),
        }
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_verify_retained_evidence", return_value=duplicate),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(duplicate, identity=identity)

        nonfinite = self.raw.replace(
            b'"route_fail_count":0', b'"route_fail_count":NaN', 1
        )
        identity = {
            **subject._EVIDENCE,
            "bytes": len(nonfinite),
            "canonical_bytes": len(nonfinite) - 1,
            "digest": "sha256:" + hashlib.sha256(nonfinite).hexdigest(),
        }
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_verify_retained_evidence", return_value=nonfinite),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(nonfinite, identity=identity)


if __name__ == "__main__":
    unittest.main()
