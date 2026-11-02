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

from aragorn import admission_protected_final_combined_v3_plugin_enable as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-plugin-"
    "enable-activation-route-coverage-v1-2026-08-28.json"
)


class FinalCombinedV3PluginEnableTests(unittest.TestCase):
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
        return subject.verify_openclaw_final_combined_v3_plugin_enable(
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
            "final_combined_v3_plugin_enable"
        ]
        digests = {
            **subject._DIGESTS,
            "composition": canonical_digest(evidence["composition"]),
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
    def native(cls, evidence: dict[str, object]) -> dict[str, object]:
        return cls.action(evidence)["observations"]["native_enable"]["command"]

    @classmethod
    def sync_native(cls, evidence: dict[str, object]) -> None:
        action = cls.action(evidence)
        action["commands"][3] = deepcopy(cls.native(evidence))

    @staticmethod
    def set_stream(command: dict[str, object], name: str, value: str) -> None:
        raw = value.encode()
        command[f"{name}_excerpt"] = value
        command[f"{name}_bytes"] = len(raw)
        command[f"{name}_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()

    def test_exact_route_pass_and_receipt(self) -> None:
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
        basis = result["route_semantics"]["pass_basis"]
        self.assertIn("PLUGIN_ENABLE", basis)
        self.assertIn("PRE_EFFECT", basis)
        self.assertIn("READ_ONLY_SYSTEMD_CREDENTIAL_LOCK", basis)
        self.assertNotIn("INSTALL_POLICY_BLOCK", basis)
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

        appended = hostile("exact denial output append")
        command = self.native(appended)
        self.set_stream(
            command, "stderr", command["stderr_excerpt"] + "ignored trailing output\n"
        )
        self.sync_native(appended)

        generic = hostile("generic exit one")
        command = self.native(generic)
        self.set_stream(command, "stderr", "config update failed\n")
        self.sync_native(generic)

        wrong_lock = hostile("wrong lock path")
        command = self.native(wrong_lock)
        self.set_stream(
            command,
            "stderr",
            command["stderr_excerpt"].replace(
                "openclaw-config.lock", "unrelated-config.lock"
            ),
        )
        self.sync_native(wrong_lock)

        exit_zero = hostile("native enable exit zero")
        self.native(exit_zero)["exit_code"] = 0
        self.sync_native(exit_zero)

        stdout = hostile("native enable stdout")
        self.set_stream(self.native(stdout), "stdout", "Enabled plugin.\n")
        self.sync_native(stdout)

        not_started = hostile("native enable not started")
        native = self.action(not_started)["observations"]["native_enable"]
        native["process_started"] = False
        native["command"]["pid"] = 0
        self.sync_native(not_started)

        activated = hostile("plugin activated")
        action = self.action(activated)
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            plugin = observation["response"]["value"]["plugin"]
            plugin["activated"] = True
            plugin["enabled"] = True
            plugin["explicitlyEnabled"] = True
            plugin["status"] = "loaded"

        imported = hostile("plugin imported")
        action = self.action(imported)
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["plugin"]["imported"] = True

        allowlisted = hostile("target allowlisted")
        action = self.action(allowlisted)
        for configuration in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            policy = configuration["plugin_policy"]
            policy["allow"].append("tts-local-cli")
            policy["target_allowlisted"] = True

        failed_inspection = hostile("unparsed plugin inspection")
        action = self.action(failed_inspection)
        plugin_after = action["observations"]["plugin_after"]
        plugin_after["response"]["parsed"] = False
        action["commands"][4] = deepcopy(plugin_after["command"])

        truncated_inspection = hostile("truncated plugin inspection")
        action = self.action(truncated_inspection)
        plugin_before = action["prerequisites"]["plugin_before"]
        self.set_stream(
            plugin_before["command"],
            "stdout",
            plugin_before["command"]["stdout_excerpt"][:100],
        )
        action["commands"][2] = deepcopy(plugin_before["command"])

        numeric_alias = hostile("boolean capability count")
        action = self.action(numeric_alias)
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["capabilityCount"] = False

        config_repin = hostile("configuration digest repin")
        action = self.action(config_repin)
        for configuration in (
            action["prerequisites"]["config_before"],
            action["observations"]["config_after"],
            action["prerequisites"]["boundary_before"]["configuration"],
            action["observations"]["boundary_after"]["configuration"],
        ):
            configuration["canonical_digest"] = "sha256:" + "0" * 64
            configuration["file"]["digest"] = "sha256:" + "0" * 64

        writable_config = hostile("writable configuration")
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
        self.action(lock_persisted)["observations"]["config_lock_after"] = {
            "exists": True,
            "path": (
                "/run/credentials/aragorn-agent-gateway.service/openclaw-config.lock"
            ),
        }

        config_custody = hostile("config source custody")
        artifact = config_custody["composition"]["action"]["artifacts"][
            "final_combined_v3_plugin_enable"
        ]
        artifact["config"]["file"]["source"]["stat"]["uid"] = 992

        policy = hostile("install policy disabled")
        artifact = policy["composition"]["action"]["artifacts"][
            "final_combined_v3_plugin_enable"
        ]
        artifact["config"]["document"]["security"]["installPolicy"]["enabled"] = False

        printf_custody = hostile("printf custody")
        artifact = printf_custody["composition"]["action"]["artifacts"][
            "final_combined_v3_plugin_enable"
        ]
        artifact["policy_command"]["stat"]["mode"] = "0777"

        runtime_changed = hostile("runtime tree changed")
        self.action(runtime_changed)["observations"]["runtime_tree_after"][
            "tree_digest"
        ] = "sha256:" + "0" * 64

        plugin_tree_changed = hostile("plugin tree changed")
        self.action(plugin_tree_changed)["observations"]["plugin_tree_after"][
            "tree_digest"
        ] = "sha256:" + "0" * 64

        gateway_changed = hostile("gateway process changed")
        self.action(gateway_changed)["observations"]["gateway_process_after"][
            "start_time_ticks"
        ] = "1"

        gateway_binding = hostile("gateway namespace binding")
        binding = gateway_binding["route_observation"]["gateway_pid_binding"]
        binding["pid"] = 1
        binding["mount_namespace"] = "/proc/1/ns/mnt"

        gateway_info = hostile("gateway system info pid")
        action = self.action(gateway_info)
        for observation in (
            action["prerequisites"]["system_info_before"],
            action["observations"]["system_info_after"],
        ):
            observation["response"]["value"]["pid"] = 1

        inactive_worker = hostile("inactive worker service state")
        for stack in (
            inactive_worker["route_observation"]["stack_before"],
            inactive_worker["composition"]["action"]["boundaries"],
        ):
            properties = stack["service_state"]["units"][
                "aragorn-runtime-action-worker.service"
            ]["properties"]
            properties["ActiveState"] = "inactive"
            properties["SubState"] = "dead"

        reversed_duration = hostile("native command reversed duration")
        command = self.native(reversed_duration)
        command["started_at"] = command["completed_at"]
        command["completed_at"] = "2026-08-28T18:09:27.000Z"
        self.sync_native(reversed_duration)

        reordered = hostile("command reorder")
        commands = self.action(reordered)["commands"]
        commands[0], commands[1] = commands[1], commands[0]

        harness_divergence = hostile("harness copies diverge")
        harness_divergence["harness"]["document"]["host_config"]["network_mode"] = (
            "host"
        )

        public_network = hostile("public network")
        for harness in (
            public_network["harness"],
            public_network["composition"]["action"]["harness"],
        ):
            harness["document"]["host_config"]["network_mode"] = "host"

        source_bundle = hostile("source bundle coordinated repin")
        source_bundle["source_artifacts"]["probe_bundle"][0]["digest"] = (
            "sha256:" + "0" * 64
        )
        source_bundle["route_observation"]["bundle"] = deepcopy(
            source_bundle["source_artifacts"]["probe_bundle"]
        )

        other_route = hostile("another route")
        other_route["route_id"] = "ADM-99/hostile"

        eligibility_alias = hostile("false integer eligibility alias")
        eligibility_alias["decision"]["edr_eligible"] = 0

        observed_alias = hostile("true integer observation alias")
        observed_alias["composition"]["decision"][
            "p3_7c_activation_action_observed"
        ] = 1

        secret_alias = hostile("false integer secret alias")
        secret_alias["composition"]["action"]["secret_checks"][
            "provider_and_gateway_token_values_retained"
        ] = 0

        lock_alias = hostile("false integer lock alias")
        self.action(lock_alias)["observations"]["config_lock_after"]["exists"] = 0

        for name, evidence in cases:
            with self.subTest(name=name):
                self.coordinated(evidence)

        source_repin = deepcopy(self.evidence)
        source_repin["source_artifacts"]["collector"]["digest"] = "sha256:" + "0" * 64
        source_artifacts = deepcopy(subject._SOURCE_ARTIFACTS)
        source_artifacts["collector"]["digest"] = "sha256:" + "0" * 64
        with patch.object(subject, "_SOURCE_ARTIFACTS", source_artifacts):
            self.coordinated(source_repin)

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
