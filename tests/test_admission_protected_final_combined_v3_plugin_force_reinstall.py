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
    admission_protected_final_combined_v3_plugin_force_reinstall as subject,
)
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v3-plugin-"
    "force-reinstall-route-coverage-v1-2026-08-28.json"
)


class FinalCombinedV3PluginForceReinstallTests(unittest.TestCase):
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
        return subject.verify_openclaw_final_combined_v3_plugin_force_reinstall(
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
            "final_combined_v3_plugin_force_reinstall"
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
        self.assertEqual(
            result["route_semantics"]["pass_basis"],
            "PASS_EXACT_NATIVE_INSTALL_POLICY_BLOCK_OBSERVED_FOR_SAME_ID_"
            "LOCAL_DIRECTORY_FORCE_REINSTALL_WITH_EXACT_EQUAL_PROTECTED_"
            "ARTIFACT_BEFORE_AFTER_SNAPSHOTS_AND_DISCLOSED_SQLITE_WAL_SHM_DELTA",
        )
        self.assertTrue(
            all(
                value is True
                for value in result["route_semantics"][
                    "protected_artifact_snapshot_equality"
                ].values()
            )
        )
        self.assertEqual(
            result["route_semantics"]["sqlite_snapshot_observation"],
            {
                "main_file_equal": True,
                "shm_changed": True,
                "wal_byte_delta": 32_960,
                "wal_changed": True,
            },
        )
        self.assertTrue(
            all(
                result["decision"][key] is False
                for key in subject.contract._ELIGIBILITY_KEYS
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

        def force_command(evidence: dict[str, object]) -> dict[str, object]:
            action = evidence["route_observation"]["document"]["action"]
            return action["observations"]["native_force_reinstall"]["command"]

        def sync_force_command(evidence: dict[str, object]) -> None:
            action = evidence["route_observation"]["document"]["action"]
            action["commands"][4] = deepcopy(
                action["observations"]["native_force_reinstall"]["command"]
            )

        def set_stdout(command: dict[str, object], stdout: str) -> None:
            command["stdout_excerpt"] = stdout
            command["stdout_bytes"] = len(stdout.encode())
            command["stdout_digest"] = (
                "sha256:" + hashlib.sha256(stdout.encode()).hexdigest()
            )

        appended = hostile("exact output append")
        command = force_command(appended)
        command["stdout_excerpt"] += "ignored trailing output\n"
        command["stdout_bytes"] = len(command["stdout_excerpt"].encode())
        command["stdout_digest"] = (
            "sha256:" + hashlib.sha256(command["stdout_excerpt"].encode()).hexdigest()
        )
        sync_force_command(appended)

        generic = hostile("generic exit one")
        command = force_command(generic)
        command["stdout_excerpt"] = ""
        command["stdout_bytes"] = 0
        command["stdout_digest"] = "sha256:" + hashlib.sha256(b"").hexdigest()
        command["stderr_excerpt"] = "install failed\n"
        command["stderr_bytes"] = len(command["stderr_excerpt"].encode())
        command["stderr_digest"] = (
            "sha256:" + hashlib.sha256(command["stderr_excerpt"].encode()).hexdigest()
        )
        sync_force_command(generic)

        no_force = hostile("force flag removed")
        action = no_force["route_observation"]["document"]["action"]
        force = action["observations"]["native_force_reinstall"]
        force["command"]["argv"].remove("--force")
        force["effective_update_basis"]["force_requested"] = False
        sync_force_command(no_force)

        raw_flag = hostile("raw policy flag promoted")
        raw_flag["route_observation"]["document"]["action"]["observations"][
            "native_force_reinstall"
        ]["explicit_policy_block_observed"] = True

        runtime_binding = hostile("runtime source commit")
        runtime_binding["route_observation"]["document"]["runtime_binding"][
            "commit"
        ] = "0" * 40

        broker = hostile("unknown broker authorization")
        broker["route_observation"]["document"]["action"]["broker_authorization"] = {
            "authorized": True
        }

        persisted = hostile("candidate persisted")
        action = persisted["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["target_plugin"]["candidate"]["ready"] = True

        non_writable = hostile("target non writable")
        action = non_writable["route_observation"]["document"]["action"]
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["target_plugin"]["parent_writable"] = False
            boundary["target_plugin"]["target_writable"] = False

        activated = hostile("plugin activated")
        action = activated["route_observation"]["document"]["action"]
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
        action = imported["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["plugin"]["imported"] = True

        capability_alias = hostile("boolean capability count")
        action = capability_alias["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["capabilityCount"] = False

        failed_inspection = hostile("failed unparsed plugin inspection")
        action = failed_inspection["route_observation"]["document"]["action"]
        plugin_after = action["observations"]["plugin_after"]
        plugin_after["command"]["exit_code"] = 1
        plugin_after["response"]["parsed"] = False
        action["commands"][5] = deepcopy(plugin_after["command"])

        injected_install = hostile("plugin top level install")
        action = injected_install["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["plugin_before"],
            action["observations"]["plugin_after"],
        ):
            observation["response"]["value"]["install"] = {"command": "hostile"}

        empty_plugin = hostile("empty plugin excerpt")
        action = empty_plugin["route_observation"]["document"]["action"]
        plugin_after = action["observations"]["plugin_after"]
        set_stdout(plugin_after["command"], "")
        action["commands"][5] = deepcopy(plugin_after["command"])

        truncated_plugin = hostile("truncated plugin excerpt")
        action = truncated_plugin["route_observation"]["document"]["action"]
        plugin_before = action["prerequisites"]["plugin_before"]
        set_stdout(
            plugin_before["command"],
            plugin_before["command"]["stdout_excerpt"][:100],
        )
        action["commands"][3] = deepcopy(plugin_before["command"])

        policy = hostile("install policy disabled")
        artifact = policy["composition"]["action"]["artifacts"][
            "final_combined_v3_plugin_force_reinstall"
        ]
        artifact["config"]["document"]["security"]["installPolicy"]["enabled"] = False

        config_custody = hostile("config custody")
        artifact = config_custody["composition"]["action"]["artifacts"][
            "final_combined_v3_plugin_force_reinstall"
        ]
        artifact["config"]["file"]["source"]["stat"]["uid"] = 992

        printf_custody = hostile("printf custody")
        artifact = printf_custody["composition"]["action"]["artifacts"][
            "final_combined_v3_plugin_force_reinstall"
        ]
        artifact["policy_command"]["stat"]["mode"] = "0777"

        discovery = hostile("discovery tree")
        action = discovery["route_observation"]["document"]["action"]
        root = "/var/lib/aragorn-agent-gateway/state/extensions"
        for boundary in (
            action["prerequisites"]["boundary_before"],
            action["observations"]["boundary_after"],
        ):
            boundary["discovery_roots"][root]["ready"] = False

        skills = hostile("skills catalog")
        action = skills["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["skills_status_before"],
            action["observations"]["skills_status_after"],
        ):
            observation["response"]["value"]["hostile"] = True

        gateway = hostile("gateway pid")
        action = gateway["route_observation"]["document"]["action"]
        for observation in (
            action["prerequisites"]["system_info_before"],
            action["observations"]["system_info_after"],
        ):
            observation["response"]["value"]["pid"] = 1

        string_uptime = hostile("string gateway uptime")
        action = string_uptime["route_observation"]["document"]["action"]
        for observation, index in (
            (action["prerequisites"]["system_info_before"], 1),
            (action["observations"]["system_info_after"], 7),
        ):
            value = observation["response"]["value"]
            value["uptimeMs"] = str(value["uptimeMs"])
            set_stdout(observation["command"], json.dumps(value, indent=2) + "\n")
            action["commands"][index] = deepcopy(observation["command"])

        duplicate_pid = hostile("duplicate gateway pid json key")
        action = duplicate_pid["route_observation"]["document"]["action"]
        for observation, index in (
            (action["prerequisites"]["system_info_before"], 1),
            (action["observations"]["system_info_after"], 7),
        ):
            stdout = observation["command"]["stdout_excerpt"].replace(
                '  "pid": 2768,', '  "pid": -1,\n  "pid": 2768,', 1
            )
            set_stdout(observation["command"], stdout)
            action["commands"][index] = deepcopy(observation["command"])

        gateway_binding = hostile("gateway namespace binding")
        binding = gateway_binding["route_observation"]["gateway_pid_binding"]
        binding["pid"] = 1
        binding["mount_namespace"] = "/proc/1/ns/mnt"

        main_file = hostile("sqlite main file")
        action = main_file["route_observation"]["document"]["action"]
        after_entries = action["observations"]["boundary_after"]["state_store"][
            "entries"
        ]
        after_entries[0]["digest"] = "sha256:" + "0" * 64

        wal = hostile("sqlite wal")
        action = wal["route_observation"]["document"]["action"]
        after_entries = action["observations"]["boundary_after"]["state_store"][
            "entries"
        ]
        after_entries[2]["size"] = 3_073_552

        state_flags = hostile("state equality flags")
        observations = state_flags["route_observation"]["document"]["action"][
            "observations"
        ]
        observations["state_invariants"]["state_store"] = True
        observations["post_write_containment"]["state_store_unchanged"] = True

        reordered = hostile("command reorder")
        commands = reordered["route_observation"]["document"]["action"]["commands"]
        commands[0], commands[1] = commands[1], commands[0]

        failed_version = hostile("failed version command")
        action = failed_version["route_observation"]["document"]["action"]
        action["prerequisites"]["version"]["exit_code"] = 1
        action["commands"][0] = deepcopy(action["prerequisites"]["version"])

        negative_support_pid = hostile("negative support command pid")
        action = negative_support_pid["route_observation"]["document"]["action"]
        action["prerequisites"]["version"]["pid"] = -1
        action["commands"][0] = deepcopy(action["prerequisites"]["version"])

        wrong_version = hostile("wrong version output")
        action = wrong_version["route_observation"]["document"]["action"]
        version = action["prerequisites"]["version"]
        version["stdout_excerpt"] = "OpenClaw 2026.7.2 (0000000)\n"
        version["stdout_bytes"] = len(version["stdout_excerpt"].encode())
        version["stdout_digest"] = (
            "sha256:" + hashlib.sha256(version["stdout_excerpt"].encode()).hexdigest()
        )
        action["commands"][0] = deepcopy(version)

        overlap = hostile("command overlap")
        action = overlap["route_observation"]["document"]["action"]
        command = action["observations"]["native_force_reinstall"]["command"]
        command["started_at"] = action["commands"][3]["started_at"]
        sync_force_command(overlap)

        harness = hostile("harness copies diverge")
        harness["harness"]["document"]["host_config"]["network_mode"] = "host"

        source_bundle = hostile("source bundle")
        source_bundle["source_artifacts"]["probe_bundle"][0]["digest"] = (
            "sha256:" + "0" * 64
        )
        source_bundle["route_observation"]["bundle"] = deepcopy(
            source_bundle["source_artifacts"]["probe_bundle"]
        )

        other_route = hostile("another route")
        other_route["route_id"] = "ADM-99/hostile"

        edr_alias = hostile("false integer eligibility alias")
        edr_alias["decision"]["edr_eligible"] = 0

        for name, evidence in cases:
            with self.subTest(name=name):
                self.coordinated(evidence)


if __name__ == "__main__":
    unittest.main()
