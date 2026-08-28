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
    admission_protected_final_combined_v3_config_entry_activation as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-config-"
    "entry-activation-route-coverage-v1-2026-08-28.json"
)


class FinalCombinedV3ConfigEntryActivationTests(unittest.TestCase):
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
        return subject.verify_openclaw_final_combined_v3_config_entry_activation(
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
        artifact = evidence["composition"]["action"]["artifacts"][
            "final_combined_v3_config_entry_activation"
        ]
        digests = {
            **subject._DIGESTS,
            "composition": canonical_digest(evidence["composition"]),
            "composition_action": canonical_digest(evidence["composition"]["action"]),
            "source_artifacts": canonical_digest(evidence["source_artifacts"]),
            "harness": canonical_digest(evidence["harness"]),
            "route_observation": canonical_digest(route),
            "execution": canonical_digest(route["execution"]),
            "gateway": canonical_digest(route["gateway_pid_binding"]),
            "stack": canonical_digest(route["stack_before"]),
            "document": canonical_digest(document),
            "action": canonical_digest(document["action"]),
            "v3_artifact": canonical_digest(artifact),
        }
        with (
            patch.object(subject, "_EVIDENCE", identity),
            patch.object(subject, "_ROUTE_RAW", route_raw),
            patch.object(subject, "_DIGESTS", digests),
            patch.object(subject, "_verify_retained_evidence", return_value=raw),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.verify(raw, identity=identity)

    @staticmethod
    def action(evidence: dict[str, object]) -> dict[str, object]:
        return evidence["route_observation"]["document"]["action"]

    @classmethod
    def update(cls, evidence: dict[str, object]) -> dict[str, object]:
        return cls.action(evidence)["observations"]["update"]

    @classmethod
    def sync_command(cls, evidence: dict[str, object], index: int) -> None:
        action = cls.action(evidence)
        aliases = (
            action["prerequisites"]["version"],
            action["prerequisites"]["system_info_before"]["command"],
            action["prerequisites"]["discovery_before"]["command"],
            action["observations"]["update"]["command"],
            action["observations"]["discovery_after"]["command"],
            action["observations"]["system_info_after"]["command"],
        )
        action["commands"][index] = deepcopy(aliases[index])

    @staticmethod
    def set_stream(command: dict[str, object], name: str, value: str) -> None:
        raw = value.encode()
        command[f"{name}_excerpt"] = value
        command[f"{name}_bytes"] = len(raw)
        command[f"{name}_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()

    @classmethod
    def sync_json_stdout(
        cls, evidence: dict[str, object], observation: dict[str, object], index: int
    ) -> None:
        stdout = (
            json.dumps(observation["response"]["value"], indent=2, ensure_ascii=False)
            + "\n"
        )
        cls.set_stream(observation["command"], "stdout", stdout)
        cls.sync_command(evidence, index)

    @staticmethod
    def sync_harness(evidence: dict[str, object]) -> None:
        harness = evidence["composition"]["action"]["harness"]
        raw = canonical_json(harness["document"])
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        harness["digest"] = digest
        harness["file"]["base64"] = base64.b64encode(raw).decode()
        harness["file"]["bytes"] = len(raw)
        harness["file"]["digest"] = digest
        harness["file"]["stat"]["size"] = len(raw)
        evidence["harness"] = deepcopy(harness)

    def test_exact_route_pass_receipt_and_claim_ceiling(self) -> None:
        result = self.verify()

        self.assertEqual(
            result["decision"]["status"], "PARTIAL_DYNAMIC_V3_ROUTE_COVERAGE"
        )
        self.assertEqual(result["profile"]["counts"], {"NOT_TESTED": 20, "PASS": 1})
        self.assertEqual(
            [
                route["id"]
                for route in result["profile"]["routes"]
                if route["status"] == "PASS"
            ],
            [subject._ROUTE],
        )
        self.assertEqual(
            result["route_semantics"]["pass_basis"],
            "NATIVE_SKILLS_UPDATE_ENABLED_TRUE_CONFIG_ENTRY_PERSISTENCE_ATTEMPT_"
            "DENIED_BEFORE_CONFIG_MUTATION_CALLBACK_AT_READ_ONLY_SYSTEMD_"
            "CREDENTIAL_LOCK",
        )
        self.assertFalse(
            result["route_semantics"]["availability_transition_dynamically_exercised"]
        )
        self.assertFalse(
            result["route_semantics"]["install_policy_dynamically_exercised"]
        )
        self.assertFalse(result["route_semantics"]["transitions_dynamically_exercised"])
        self.assertIn(
            "TEMPLATE_SKILL_ALREADY_AVAILABLE_AND_ELIGIBLE_BEFORE_ACTION",
            result["limitations"],
        )
        self.assertIn(
            "NO_DISABLED_TO_ENABLED_ACTIVATION_TRANSITION_CLAIM",
            result["limitations"],
        )
        self.assertIn(
            "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
            result["limitations"],
        )
        self.assertNotIn("EDR", result["assurance"])
        self.assertNotIn("RELEASE", result["assurance"])
        eligibility = {
            key: value
            for key, value in result["decision"].items()
            if key.endswith("_eligible")
        }
        self.assertEqual(len(eligibility), 9)
        self.assertTrue(
            all(
                type(value) is bool and value is False for value in eligibility.values()
            )
        )
        action = self.action(self.evidence)
        for discovery in (
            action["prerequisites"]["discovery_before"],
            action["observations"]["discovery_after"],
        ):
            self.assertFalse(discovery["response"]["value"]["disabled"])
            self.assertTrue(discovery["response"]["value"]["eligible"])
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_cas_and_coordinated_hostile_repins_fail_closed(self) -> None:
        with (
            patch.object(subject, "_verify_retained_evidence", return_value=b"{}\n"),
            self.assertRaisesRegex(AdmissionEvidenceError, "signed retention"),
        ):
            self.verify()

        cases: list[tuple[str, dict[str, object]]] = []

        def hostile(name: str) -> dict[str, object]:
            evidence = deepcopy(self.evidence)
            cases.append((name, evidence))
            return evidence

        wrong_method = hostile("update method")
        self.update(wrong_method)["command"]["argv"][4] = "skills.info"
        self.sync_command(wrong_method, 3)

        wrong_params = hostile("enabled false params")
        update = self.update(wrong_params)
        update["params"]["enabled"] = False
        update["command"]["argv"][-1] = '{"enabled":false,"skillKey":"template-skill"}'
        self.sync_command(wrong_params, 3)

        wrong_key = hostile("wrong skill key")
        update = self.update(wrong_key)
        update["params"]["skillKey"] = "other-skill"
        update["command"]["argv"][-1] = '{"enabled":true,"skillKey":"other-skill"}'
        self.sync_command(wrong_key, 3)

        generic = hostile("generic update denial")
        update = self.update(generic)
        update["response"]["value"]["error"]["message"] = "generic failure"
        self.sync_json_stdout(generic, update, 3)

        wrong_lock = hostile("wrong credential lock")
        update = self.update(wrong_lock)
        update["response"]["value"]["error"]["message"] = update["response"]["value"][
            "error"
        ]["message"].replace("openclaw-config.lock", "unrelated-config.lock")
        self.sync_json_stdout(wrong_lock, update, 3)

        exit_zero = hostile("update exit zero")
        self.update(exit_zero)["command"]["exit_code"] = 0
        self.sync_command(exit_zero, 3)

        trailing = hostile("update output append")
        update = self.update(trailing)
        self.set_stream(
            update["command"],
            "stdout",
            update["command"]["stdout_excerpt"] + "ignored trailing output\n",
        )
        self.sync_command(trailing, 3)

        stderr = hostile("update stderr")
        update = self.update(stderr)
        self.set_stream(update["command"], "stderr", "unexpected stderr\n")
        self.sync_command(stderr, 3)

        unavailable = hostile("wrong gateway code")
        update = self.update(unavailable)
        update["response"]["value"]["error"]["code"] = "INTERNAL"
        self.sync_json_stdout(unavailable, update, 3)

        retryable_alias = hostile("false integer retryable alias")
        update = self.update(retryable_alias)
        update["response"]["value"]["error"]["retryable"] = 0
        self.sync_json_stdout(retryable_alias, update, 3)

        ok_alias = hostile("false integer ok alias")
        update = self.update(ok_alias)
        update["response"]["value"]["ok"] = 0
        self.sync_json_stdout(ok_alias, update, 3)

        enabled_alias = hostile("true integer enabled alias")
        self.update(enabled_alias)["params"]["enabled"] = 1

        exit_alias = hostile("integer exit boolean alias")
        self.update(exit_alias)["command"]["exit_code"] = True
        self.sync_command(exit_alias, 3)

        eligibility_alias = hostile("false integer eligibility alias")
        eligibility_alias["decision"]["edr_eligible"] = 0

        observation_alias = hostile("true integer observation alias")
        observation_alias["composition"]["decision"][
            "p3_7c_activation_action_observed"
        ] = 1

        lock_alias = hostile("false integer lock alias")
        self.action(lock_alias)["observations"]["config_lock_after"]["exists"] = 0

        already_disabled = hostile("forged disabled to enabled premise")
        action = self.action(already_disabled)
        for observation, index in (
            (action["prerequisites"]["discovery_before"], 2),
            (action["observations"]["discovery_after"], 4),
        ):
            observation["response"]["value"]["disabled"] = True
            observation["response"]["value"]["eligible"] = False
            self.sync_json_stdout(already_disabled, observation, index)

        config_repin = hostile("configuration snapshots coordinated repin")
        action = self.action(config_repin)
        for configuration in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            configuration["canonical_digest"] = "sha256:" + "0" * 64
            configuration["file"]["digest"] = "sha256:" + "0" * 64

        writable_config = hostile("writable credential configuration")
        action = self.action(writable_config)
        for configuration in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            configuration["mount"]["read_only"] = False
            configuration["mount"]["records"][0]["mount_options"] = ["rw"]

        lock_persisted = hostile("config lock persisted")
        action = self.action(lock_persisted)
        for lock in (
            action["prerequisites"]["config_lock_before"],
            action["observations"]["config_lock_after"],
        ):
            lock["exists"] = True

        target_repin = hostile("target snapshots coordinated repin")
        action = self.action(target_repin)
        for target in (
            action["prerequisites"]["target_before"],
            action["observations"]["target_after"],
        ):
            target["tree_digest"] = "sha256:" + "0" * 64

        runtime_repin = hostile("runtime snapshots coordinated repin")
        action = self.action(runtime_repin)
        for runtime in (
            action["prerequisites"]["runtime_tree_before"],
            action["observations"]["runtime_tree_after"],
        ):
            runtime["tree_digest"] = "sha256:" + "0" * 64

        openclaw_repin = hostile("openclaw snapshots coordinated repin")
        action = self.action(openclaw_repin)
        for executable in (
            action["prerequisites"]["openclaw_before"],
            action["observations"]["openclaw_after"],
        ):
            executable["digest"] = "sha256:" + "0" * 64

        gateway_repin = hostile("gateway snapshots coordinated repin")
        action = self.action(gateway_repin)
        for gateway in (
            action["prerequisites"]["gateway_process_before"],
            action["observations"]["gateway_process_after"],
        ):
            gateway["start_time_ticks"] = "1"

        boundary_repin = hostile("boundary snapshots coordinated repin")
        action = self.action(boundary_repin)
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["roots"]["managed_skills"]["ready"] = False

        system_repin = hostile("system identity coordinated repin")
        action = self.action(system_repin)
        for observation, index in (
            (action["prerequisites"]["system_info_before"], 1),
            (action["observations"]["system_info_after"], 5),
        ):
            observation["response"]["value"]["hostname"] = "hostile"
            observation["response"]["value"]["machineName"] = "hostile"
            self.sync_json_stdout(system_repin, observation, index)

        gateway_binding = hostile("gateway namespace binding")
        binding = gateway_binding["route_observation"]["gateway_pid_binding"]
        binding["pid"] = 1
        binding["mount_namespace"] = "/proc/1/ns/mnt"
        gateway_binding["route_observation"]["execution"]["argv"][2] = "1"

        execution_probe = hostile("execution probe path")
        execution_probe["route_observation"]["execution"]["argv"][-1] = (
            "/route-input/hostile.mjs"
        )

        duplicate_pid = hostile("duplicate command pid")
        action = self.action(duplicate_pid)
        action["observations"]["update"]["command"]["pid"] = action["commands"][2][
            "pid"
        ]
        self.sync_command(duplicate_pid, 3)

        reversed_duration = hostile("reversed update duration")
        update = self.update(reversed_duration)
        update["command"]["started_at"] = update["command"]["completed_at"]
        update["command"]["completed_at"] = "2026-08-28T19:03:03.000Z"
        self.sync_command(reversed_duration, 3)

        overlap = hostile("command overlap")
        action = self.action(overlap)
        action["observations"]["update"]["command"]["started_at"] = action["commands"][
            2
        ]["started_at"]
        self.sync_command(overlap, 3)

        inactive_worker = hostile("inactive worker stack coordinated repin")
        for stack in (
            inactive_worker["route_observation"]["stack_before"],
            inactive_worker["composition"]["action"]["boundaries"],
        ):
            properties = stack["service_state"]["units"][
                "aragorn-runtime-action-worker.service"
            ]["properties"]
            properties["ActiveState"] = "inactive"
            properties["SubState"] = "dead"

        child_image = hostile("child image coordinated repin")
        for harness in (
            child_image["composition"]["action"]["harness"],
            child_image["harness"],
        ):
            document = harness["document"]
            forged = "sha256:" + "0" * 64
            document["image_id"] = forged
            document["run_image_reference"] = forged
            document["image_lineage"]["child"]["id"] = forged
        self.sync_harness(child_image)

        public_network = hostile("public network coordinated repin")
        public_network["composition"]["action"]["harness"]["document"]["host_config"][
            "network_mode"
        ] = "host"
        self.sync_harness(public_network)

        source_bundle = hostile("source bundle coordinated repin")
        source_bundle["source_artifacts"]["probe_bundle"][0]["digest"] = (
            "sha256:" + "0" * 64
        )
        source_bundle["route_observation"]["bundle"] = deepcopy(
            source_bundle["source_artifacts"]["probe_bundle"]
        )

        materializer = hostile("materializer source identity")
        materializer["source_artifacts"]["materializer"]["digest"] = (
            "sha256:" + "0" * 64
        )

        transform = hostile("probe transform contract")
        artifact = transform["composition"]["action"]["artifacts"][
            "final_combined_v3_config_entry_activation"
        ]
        artifact["config_entry_activation_probe"]["transform"]["configuration_bytes"][
            "to"
        ] = 2_160

        transformed_probe = hostile("transformed probe identity")
        artifact = transformed_probe["composition"]["action"]["artifacts"][
            "final_combined_v3_config_entry_activation"
        ]
        for name in ("runtime", "transformed_source"):
            artifact["config_entry_activation_probe"][name]["digest"] = (
                "sha256:" + "0" * 64
            )

        other_route = hostile("another route")
        other_route["route_id"] = "ADM-99/hostile"

        for name, evidence in cases:
            with self.subTest(name=name):
                self.coordinated(evidence)

    def test_duplicate_and_nonfinite_json_fail_closed(self) -> None:
        hostile_outer = (
            self.raw.replace(
                b'{"authority":', b'{"authority":"forged","authority":', 1
            ),
            self.raw.replace(b'"route_pass_count":0', b'"route_pass_count":NaN', 1),
        )
        for raw in hostile_outer:
            with self.subTest(digest="sha256:" + hashlib.sha256(raw).hexdigest()):
                identity = {
                    **subject._EVIDENCE,
                    "bytes": len(raw),
                    "canonical_bytes": len(raw) - 1,
                    "digest": "sha256:" + hashlib.sha256(raw).hexdigest(),
                }
                with (
                    patch.object(subject, "_EVIDENCE", identity),
                    patch.object(
                        subject, "_verify_retained_evidence", return_value=raw
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    self.verify(raw, identity=identity)

        nested = canonical_json(self.evidence["route_observation"]["document"]) + b"\n"
        hostile_nested = (
            nested.replace(b'{"action":', b'{"action":"forged","action":', 1),
            nested.replace(b'"pid":3024', b'"pid":NaN', 1),
        )
        for nested_raw in hostile_nested:
            with self.subTest(
                nested_digest="sha256:" + hashlib.sha256(nested_raw).hexdigest()
            ):
                evidence = deepcopy(self.evidence)
                route = evidence["route_observation"]
                route_raw = {
                    "bytes": len(nested_raw),
                    "canonical_digest": canonical_digest(route["document"]),
                    "digest": "sha256:" + hashlib.sha256(nested_raw).hexdigest(),
                }
                route["raw"] = {
                    "base64": base64.b64encode(nested_raw).decode(),
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
                    **subject._DIGESTS,
                    "route_observation": canonical_digest(route),
                }
                with (
                    patch.object(subject, "_EVIDENCE", identity),
                    patch.object(subject, "_ROUTE_RAW", route_raw),
                    patch.object(subject, "_DIGESTS", digests),
                    patch.object(
                        subject, "_verify_retained_evidence", return_value=raw
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    self.verify(raw, identity=identity)


if __name__ == "__main__":
    unittest.main()
