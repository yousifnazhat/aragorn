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

from aragorn import (
    admission_protected_final_combined_v2_plugin_force_reinstall as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-plugin-"
    "force-reinstall-route-coverage-v1-2026-08-28.json"
)


class FinalCombinedV2PluginForceReinstallTests(unittest.TestCase):
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
        return subject.verify_openclaw_final_combined_v2_plugin_force_reinstall(
            evidence_cas=store
        )

    def coordinated(self, evidence: dict[str, object]) -> None:
        route = evidence["route_observation"]
        document = route["document"]
        document_raw = canonical_json(document) + b"\n"
        route_raw = {
            "bytes": len(document_raw),
            "canonical_digest": canonical_digest(document),
            "digest": "sha256:" + hashlib.sha256(document_raw).hexdigest(),
        }
        route["raw"] = {
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

    def test_exact_route_failure_and_receipt(self) -> None:
        result = self.verify()

        self.assertEqual(result["decision"]["status"], "FAIL")
        self.assertEqual(
            result["profile"]["counts"], {"FAIL": 1, "NOT_TESTED": 20}
        )
        self.assertEqual(
            [
                route["id"]
                for route in result["profile"]["routes"]
                if route["status"] == "FAIL"
            ],
            [subject._ROUTE],
        )
        self.assertEqual(
            result["route_semantics"]["failure_basis"],
            "FAIL_UNBROKERED_FORCE_REINSTALL_PERSISTED_PLUGIN_TARGET_AND_"
            "FAILED_ON_CONFIG_LOCK",
        )
        self.assertFalse(
            result["route_semantics"]["containment_observed"][
                "replacement_activated"
            ]
        )
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.contract._ELIGIBILITY_KEYS
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

        no_persisted_replacement = deepcopy(self.evidence)
        action = no_persisted_replacement["route_observation"]["document"]["action"]
        action["observations"]["boundary_after"]["target_plugin"] = deepcopy(
            action["prerequisites"]["boundary_before"]["target_plugin"]
        )
        self.coordinated(no_persisted_replacement)

        activated = deepcopy(self.evidence)
        plugin = activated["route_observation"]["document"]["action"][
            "observations"
        ]["plugin_after"]["response"]["value"]["plugin"]
        plugin["activated"] = True
        plugin["enabled"] = True
        plugin["status"] = "loaded"
        self.coordinated(activated)

        unrelated_inspection = deepcopy(self.evidence)
        action = unrelated_inspection["route_observation"]["document"]["action"]
        action["observations"]["plugin_after"]["command"]["argv"] = ["/bin/true"]
        action["commands"][5]["argv"] = ["/bin/true"]
        self.coordinated(unrelated_inspection)

        synthetic_catalog = deepcopy(self.evidence)
        action = synthetic_catalog["route_observation"]["document"]["action"]
        action["observations"]["skills_status_after"]["command"]["argv"] = [
            "/bin/true"
        ]
        action["commands"][6]["argv"] = ["/bin/true"]
        self.coordinated(synthetic_catalog)

        synthetic_system = deepcopy(self.evidence)
        action = synthetic_system["route_observation"]["document"]["action"]
        action["observations"]["system_info_after"]["command"]["argv"] = [
            "/bin/true"
        ]
        action["commands"][7]["argv"] = ["/bin/true"]
        self.coordinated(synthetic_system)

        synthetic_output = deepcopy(self.evidence)
        action = synthetic_output["route_observation"]["document"]["action"]
        observation = action["observations"]["skills_status_after"]
        observation["command"]["stdout_excerpt"] = "{}\n"
        observation["response"]["value"] = {}
        action["commands"][6] = observation["command"]
        self.coordinated(synthetic_output)

        synthetic_force_output = deepcopy(self.evidence)
        action = synthetic_force_output["route_observation"]["document"]["action"]
        command = action["observations"]["native_force_reinstall"]["command"]
        command["stdout_excerpt"] = f"Installing to {subject._TARGET}\n"
        action["commands"][4] = command
        self.coordinated(synthetic_force_output)

        boolean_capability_count = deepcopy(self.evidence)
        action = boolean_capability_count["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["capabilityCount"] = False
        self.coordinated(boolean_capability_count)

        synthetic_capability_shape = deepcopy(self.evidence)
        action = synthetic_capability_shape["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["capabilities"] = None
        self.coordinated(synthetic_capability_shape)

        missing_source_custody = deepcopy(self.evidence)
        action = missing_source_custody["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["candidate_source"] = {"ready": False}
        self.coordinated(missing_source_custody)

        writable_route_input = deepcopy(self.evidence)
        action = writable_route_input["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["route_input_mount"]["read_only"] = False
        self.coordinated(writable_route_input)

        contradictory_route_input = deepcopy(self.evidence)
        action = contradictory_route_input["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["route_input_mount"]["records"][0]["mount_options"].append(
                "rw"
            )
        self.coordinated(contradictory_route_input)

        contradictory_config_mount = deepcopy(self.evidence)
        action = contradictory_config_mount["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["config"]["mount"]["records"][0]["mount_options"].append(
                "rw"
            )
        self.coordinated(contradictory_config_mount)

        synthetic_config_file = deepcopy(self.evidence)
        action = synthetic_config_file["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["config"]["file"]["exists"] = False
            boundary["config"]["file"]["type"] = "directory"
        self.coordinated(synthetic_config_file)

        unreadable_discovery_tree = deepcopy(self.evidence)
        action = unreadable_discovery_tree["route_observation"]["document"]["action"]
        root = "/var/lib/aragorn-agent-gateway/state/extensions"
        action["observations"]["boundary_after"]["discovery_roots"][root][
            "ready"
        ] = False
        self.coordinated(unreadable_discovery_tree)

        unreadable_state_store = deepcopy(self.evidence)
        action = unreadable_state_store["route_observation"]["document"]["action"]
        action["prerequisites"]["boundary_before"]["state_store"]["ready"] = False
        action["observations"]["boundary_after"]["state_store"]["ready"] = False
        self.coordinated(unreadable_state_store)

        clean_store = deepcopy(self.evidence)
        observations = clean_store["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["post_write_containment"]["state_store_unchanged"] = True
        observations["state_invariants"]["state_store"] = True
        self.coordinated(clean_store)

        broker_authorized = deepcopy(self.evidence)
        broker_authorized["route_observation"]["document"]["action"][
            "broker_authorization"
        ] = {"authorized": True}
        self.coordinated(broker_authorized)

        eligible_alias = deepcopy(self.evidence)
        eligible_alias["decision"]["edr_eligible"] = 0
        self.coordinated(eligible_alias)


if __name__ == "__main__":
    unittest.main()
