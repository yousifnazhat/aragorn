from __future__ import annotations

import copy
import hashlib
import json
import unittest
from base64 import b64encode
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from aragorn import runtime_action_worker_openclaw_systemd_evidence as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = (
    _ROOT
    / "benchmark/evidence/runtime-action-worker-openclaw-systemd-composition-p3-7b-2026-08-09.json"
)
_PARENT = (
    _ROOT
    / "benchmark/evidence/runtime-producer-lineage-openclaw-systemd-composition-p3-6b-2026-08-07.json"
)
_RECEIPT = (
    _ROOT
    / "benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-qualification-v1-2026-08-09.json"
)


def _load(path: Path) -> dict:
    return json.loads(path.read_bytes())


class RuntimeActionWorkerOpenClawSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = _load(_EVIDENCE)
        cls.parent = _load(_PARENT)

    def test_exact_v6_qualifies_without_broad_authority(self) -> None:
        subject.verify_runtime_action_worker_openclaw_systemd_evidence(
            self.evidence,
            self.parent,
            expected_digest=subject._EVIDENCE_DIGEST,
        )
        qualification = subject.runtime_action_worker_openclaw_systemd_qualification(
            self.evidence,
            self.parent,
            expected_digest=subject._EVIDENCE_DIGEST,
            implementation_digest=self._implementation_digest(),
        )
        self.assertEqual(qualification["decision"], subject._QUALIFICATION_DECISION)
        self.assertEqual(qualification["decision"]["status"], "P3_7B_BOUNDED_PASS")
        self.assertTrue(
            qualification["decision"]["qualified_pair_retained_evidence_eligible"]
        )
        for field in (
            "aggregate_gate_eligible",
            "run_01_eligible",
            "run_02_eligible",
            "phase3_exit_eligible",
            "edr_claim_eligible",
            "installer_authority_eligible",
            "public_release_eligible",
        ):
            self.assertIs(qualification["decision"][field], False)

    def test_retained_qualification_is_exact_canonical_output(self) -> None:
        qualification = subject.runtime_action_worker_openclaw_systemd_qualification(
            self.evidence,
            self.parent,
            expected_digest=subject._EVIDENCE_DIGEST,
            implementation_digest=self._implementation_digest(),
        )
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(qualification) + b"\n")

    def test_explicit_source_and_verifier_pins_are_required(self) -> None:
        with self.assertRaises(AdmissionEvidenceError):
            subject.verify_runtime_action_worker_openclaw_systemd_evidence(
                self.evidence, self.parent, expected_digest=None
            )
        with self.assertRaises(AdmissionEvidenceError):
            subject.runtime_action_worker_openclaw_systemd_qualification(
                self.evidence,
                self.parent,
                expected_digest=subject._EVIDENCE_DIGEST,
                implementation_digest=None,
            )
        with self.assertRaises(AdmissionEvidenceError):
            subject.runtime_action_worker_openclaw_systemd_qualification(
                self.evidence,
                self.parent,
                expected_digest=subject._EVIDENCE_DIGEST,
                implementation_digest="sha256:" + "0" * 64,
            )

    def test_hostile_grant_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        wrapper = hostile["inputs"]["grant"]
        wrapper["document"]["runtime_profile_digest"] = "sha256:" + "a" * 64
        wrapper["digest"] = canonical_digest(wrapper["document"])
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_root_grant_sensor_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        wrapper = hostile["inputs"]["grant"]
        wrapper["document"]["sensor_digest"] = "sha256:" + "a" * 64
        wrapper["digest"] = canonical_digest(wrapper["document"])
        self._assert_semantic_repin_fails(
            hostile, expected_message="grant binding changed"
        )

    def test_hostile_action_path_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["action"]["path_digest"] = "sha256:" + "a" * 64
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_driver_authority_leak_repins_still_fail(self) -> None:
        lease = self.evidence["cases"]["coherent"]["effects"]["after"]["grant_state"][
            "document"
        ]["claim"]["lease"]
        for key, value in (
            ("leak", lease["lease_nonce"]),
            ("grant_digest", "innocuous"),
        ):
            with self.subTest(key=key):
                hostile = copy.deepcopy(self.evidence)
                hostile["cases"]["coherent"]["driver"]["output"][key] = value
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_mount_inventory_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        del hostile["boundaries"]["mounts"]["worker_root"]
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_mount_root_repins_still_fail(self) -> None:
        mutations = (
            ("gateway_runtime", "/docker/volumes/evil-runtime/_data"),
            ("gateway_worker_socket", "/evil-worker-socket"),
        )
        for mount_name, new_root in mutations:
            with self.subTest(mount_name=mount_name):
                hostile = copy.deepcopy(self.evidence)
                mount = hostile["boundaries"]["mounts"][mount_name]
                old_root = mount["root"]
                mount["root"] = new_root
                mount["raw"] = mount["raw"].replace(old_root, mount["root"])
                mount["raw_digest"] = (
                    "sha256:" + hashlib.sha256(mount["raw"].encode()).hexdigest()
                )
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_harness_container_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        harness = hostile["harness"]
        harness["document"]["container_id"] = "a" * 64
        harness["digest"] = canonical_digest(harness["document"])
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_harness_image_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        harness = hostile["harness"]
        image_id = "sha256:" + "a" * 64
        harness["document"]["image_id"] = image_id
        harness["document"]["run_image_reference"] = image_id
        harness["document"]["image_lineage"]["child"]["id"] = image_id
        harness["digest"] = canonical_digest(harness["document"])
        self._assert_semantic_repin_fails(hostile)

        hostile = copy.deepcopy(self.evidence)
        harness = hostile["harness"]
        lineage = harness["document"]["image_lineage"]
        parent_count = len(lineage["parent"]["layers"])
        layer = "sha256:" + "b" * 64
        lineage["added_layers"][0] = layer
        lineage["child"]["layers"][parent_count] = layer
        harness["digest"] = canonical_digest(harness["document"])
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_executable_provenance_repin_still_fails(self) -> None:
        mutations = (
            ("path", "/tmp/evil-python"),
            ("digest", "sha256:" + "a" * 64),
            ("bytes", 67_609),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                executable = hostile["profiles"]["executables"]["worker_python"]
                executable[field] = value
                if field == "bytes":
                    executable["stat"]["size"] = value
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_driver_command_repins_still_fail(self) -> None:
        mutations = (
            ("system_info", "exit_code", 1),
            ("send", "error", "COMMAND_ERROR"),
            ("wait", "signal", "SIGKILL"),
            ("history", "stdout_bytes", 0),
        )
        for command_name, field, value in mutations:
            with self.subTest(command_name=command_name, field=field):
                hostile = copy.deepcopy(self.evidence)
                output = hostile["cases"]["coherent"]["driver"]["output"]
                command = (
                    output["gateway"]["system_info"]["command"]
                    if command_name == "system_info"
                    else output["turn"][command_name]["command"]
                )
                command[field] = value
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_driver_shape_repins_still_fail(self) -> None:
        for container in ("driver", "output", "proof"):
            with self.subTest(container=container):
                hostile = copy.deepcopy(self.evidence)
                driver = hostile["cases"]["coherent"]["driver"]
                target = {
                    "driver": driver,
                    "output": driver["output"],
                    "proof": driver["output"]["scenario"]["proof"],
                }[container]
                target["effect_authority"] = True
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_driver_time_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        output = hostile["cases"]["coherent"]["driver"]["output"]
        output["provider"]["records"][0]["received_at"] = "2099-01-01T00:00:00.000Z"
        output["provider"]["records"][1]["received_at"] = "2099-01-01T00:00:01.000Z"
        self._assert_semantic_repin_fails(hostile)

        hostile = copy.deepcopy(self.evidence)
        hostile["cases"]["coherent"]["driver"]["output"]["timing"]["elapsed_ms"] = 0
        hostile["cases"]["coherent"]["driver"]["elapsed_ns"] = 1
        self._assert_semantic_repin_fails(hostile)

        hostile = copy.deepcopy(self.evidence)
        driver = hostile["cases"]["coherent"]["driver"]
        driver["exit_code"] = False
        driver["output"]["provider"]["error_count"] = False
        driver["output"]["provider"]["records"][0]["sequence"] = True
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_driver_authority_clock_split_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)

        def shift(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"completed_at", "received_at", "started_at"}:
                        parsed = datetime.fromisoformat(child.replace("Z", "+00:00"))
                        value[key] = (
                            (parsed - timedelta(seconds=1_000_000))
                            .isoformat(timespec="milliseconds")
                            .replace("+00:00", "Z")
                        )
                    else:
                        shift(child)
            elif isinstance(value, list):
                for child in value:
                    shift(child)

        shift(hostile["cases"]["coherent"]["driver"])
        self._assert_semantic_repin_fails(
            hostile, expected_message="driver root grant window changed: coherent"
        )

    def test_hostile_source_recorded_time_repins_still_fail(self) -> None:
        for recorded_at in (
            "2000-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
        ):
            with self.subTest(recorded_at=recorded_at):
                hostile = copy.deepcopy(self.evidence)
                hostile["recorded_at"] = recorded_at
                self._assert_semantic_repin_fails(
                    hostile, expected_message="source recorded time changed"
                )

    def test_hostile_control_swap_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        sets = hostile["inputs"]["control_sets"]
        sets["worker"], sets["stale_refresh"] = sets["stale_refresh"], sets["worker"]
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_negative_effect_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        effects = hostile["cases"]["worker_binding_mismatch"]["effects"]
        effects["before"]["target_exists"] = True
        effects["after"]["target_exists"] = True
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_request_digest_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        case = hostile["cases"]["coherent"]
        observed = case["driver"]["output"]["scenario"]["proof"]["observed"]
        observed["request_digest"] = "sha256:" + "a" * 64
        identifiers = case["driver"]["output"]["turn"]["identifiers"]
        identifiers["request_digest"] = observed["request_digest"]
        records = case["driver"]["output"]["provider"]["records"]
        records[1]["tool_result_summary_digest"] = canonical_digest(observed)
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_service_pid_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        service = "aragorn-runtime-action-worker.service"
        hostile["boundaries"]["processes"][service]["pid"] = 99_999
        hostile["boundaries"]["units"][service]["MainPID"] = "99999"
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_namespace_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        for index, process in enumerate(
            hostile["boundaries"]["processes"].values(), start=1
        ):
            process["network_namespace"] = f"evil-network-{index}"
            if index != 2:
                process["mount_namespace"] = f"evil-mount-{index}"
        self._assert_semantic_repin_fails(hostile)

        hostile = copy.deepcopy(self.evidence)
        worker = hostile["boundaries"]["processes"][
            "aragorn-runtime-action-worker.service"
        ]
        worker["no_new_privileges"] = True
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_process_start_ticks_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        for name, process in hostile["boundaries"]["processes"].items():
            if name != "aragorn-runtime-action-worker.service":
                process["start_time_ticks"] += "__HOSTILE"
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_principal_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["identities"]["worker"]["uid"] = 998
        hostile["boundaries"]["sockets"]["worker"]["uid"] = 998
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_stale_record_substitution_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["stale_active_record"] = copy.deepcopy(
            hostile["inputs"]["active_record"]
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_active_record_file_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        digest = "sha256:" + "b" * 64
        hostile["inputs"]["active_record"]["file"]["digest"] = digest
        hostile["inputs"]["producer"]["record"]["file"]["digest"] = digest
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_active_record_contract_repins_still_fail(self) -> None:
        mutations = (
            ("record", "schema", "evil/active-runtime/v9"),
            ("record", "authority", "EVIL_INSTALLER_AUTHORITY"),
            ("transaction", "authority", "EVIL_INSTALL_AUTHORITY"),
        )
        for target, field, value in mutations:
            with self.subTest(target=target, field=field):
                hostile = copy.deepcopy(self.evidence)
                records = (
                    hostile["inputs"]["producer"]["record"],
                    hostile["inputs"]["active_record"],
                    hostile["inputs"]["stale_active_record"],
                )
                if target == "record":
                    for record in records:
                        record["document"][field] = value
                else:
                    hostile["inputs"]["producer"]["transaction"][field] = value
                    for record in records:
                        record["document"]["transaction"][field] = value
                for record in records:
                    self._rebind_active_record(record)
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_producer_transaction_provenance_repins_still_fail(self) -> None:
        mutations = (
            ("context_digest", "sha256:" + "a" * 64),
            ("root_device", 999),
            ("root_inode", 999),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                transactions = [hostile["inputs"]["producer"]["transaction"]]
                records = (
                    hostile["inputs"]["producer"]["record"],
                    hostile["inputs"]["active_record"],
                    hostile["inputs"]["stale_active_record"],
                )
                transactions.extend(
                    record["document"]["transaction"] for record in records
                )
                for transaction in transactions:
                    if field in {"root_device", "root_inode"}:
                        transaction["destination"][field] = value
                    else:
                        transaction[field] = value
                for record in records:
                    self._rebind_active_record(record)
                self._assert_semantic_repin_fails(
                    hostile, expected_message="producer transaction contract changed"
                )

    def test_hostile_skill_path_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["producer"]["skill"]["path"] = "/tmp/evil/SKILL.md"
        self._assert_semantic_repin_fails(
            hostile, expected_message="producer skill provenance changed"
        )

        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["producer"]["projected_skill"]["path"] = (
            "/tmp/projected/SKILL.md"
        )
        self._assert_semantic_repin_fails(
            hostile, expected_message="producer skill provenance changed"
        )

    def test_hostile_protected_file_metadata_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        for record in (
            hostile["inputs"]["active_record"]["file"],
            hostile["inputs"]["producer"]["record"]["file"],
        ):
            record["stat"].update(
                {
                    "device": "hostile",
                    "gid": 992,
                    "inode": "hostile",
                    "mode": "0777",
                    "nlink": 2,
                    "type": "symlink",
                    "uid": 992,
                }
            )
        self._assert_semantic_repin_fails(hostile)

        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["producer"]["projected_skill"]["stat"]["mode"] = "0777"
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_receipt_file_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["cases"]["coherent"]["receipt_file"]["digest"] = "sha256:" + "c" * 64
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_negative_trace_pid_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["cases"]["legacy_openclaw_profile"]["traces"]["broker"][
            "service_pid"
        ] = 99_999
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_endpoint_pid_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        service = "aragorn-runtime-action-worker.service"
        endpoint = hostile["cases"]["worker_endpoint_unavailable"]
        endpoint["service_pids"]["before"][service] = 9_999
        endpoint["service_pids"]["after"][service] = 9_999
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_unauthorized_client_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["cases"]["unauthorized_worker_peer"]["client"]["client"]["pid"] = 99_999
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_unauthorized_outcome_repins_still_fail(self) -> None:
        for field, value in (
            ("errno", 105),
            ("error", "HOSTILE"),
            ("request_digest", "sha256:" + "a" * 64),
        ):
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                hostile["cases"]["unauthorized_worker_peer"]["client"][field] = value
                self._assert_semantic_repin_fails(
                    hostile, expected_message="unauthorized peer result changed"
                )

    def test_hostile_unauthorized_bool_identity_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        case = hostile["cases"]["unauthorized_worker_peer"]
        case["client"]["client"]["uid"] = False
        case["traces"]["worker"]["channels"][0]["peer"]["uid"] = False
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_gateway_config_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["gateway_config"]["plugins"]["enabled"] = False
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_unhealthy_control_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        controls = hostile["inputs"]["control_sets"]["legacy"]
        controls["health"]["status"] = "unhealthy"
        digest = canonical_digest(controls["health"])
        effects = hostile["cases"]["legacy_openclaw_profile"]["effects"]
        effects["before"]["controls"]["health.json"] = digest
        effects["after"]["controls"]["health.json"] = digest
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_control_attribution_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        controls = hostile["inputs"]["control_sets"]["worker"]
        controls["observation"]["active"]["run_id"] = "diverged-run"
        digest = canonical_digest(controls["observation"])
        effects = hostile["cases"]["worker_binding_mismatch"]["effects"]
        effects["before"]["controls"]["observation.json"] = digest
        effects["after"]["controls"]["observation.json"] = digest
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_control_observation_contract_repins_still_fail(self) -> None:
        for field, value in (
            ("schema", "evil/observation/v9"),
            ("authority", "EVIL_EFFECT_AUTHORITY"),
            ("sequence", True),
        ):
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                observation = hostile["inputs"]["control_sets"]["legacy"]["observation"]
                observation[field] = value
                digest = canonical_digest(observation)
                effects = hostile["cases"]["legacy_openclaw_profile"]["effects"]
                for position in ("before", "after"):
                    effects[position]["controls"]["observation.json"] = digest
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_coherent_dirty_start_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["cases"]["coherent"]["effects"]["before"]["target_exists"] = True
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_coherent_post_control_inventory_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["cases"]["coherent"]["effects"]["after"]["controls"][
            "override-authority.json"
        ] = "sha256:" + "a" * 64
        self._assert_semantic_repin_fails(
            hostile, expected_message="coherent post-control inventory changed"
        )

    def test_hostile_worker_mismatch_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["worker_binding_mismatch"]["active_skill_digest"] = (
            "sha256:" + "d" * 64
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_provider_contract_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        records = hostile["cases"]["coherent"]["driver"]["output"]["provider"][
            "records"
        ]
        records[0]["authorization_valid"] = False
        records[1]["tool_contract_valid"] = False
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_check_inventory_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        checks = hostile["cases"]["coherent"]["checks"]
        checks["renamed_clean_before"] = checks.pop("clean_before")
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_case_shape_repins_still_fail(self) -> None:
        for name in subject._CASES:
            with self.subTest(name=name):
                hostile = copy.deepcopy(self.evidence)
                hostile["cases"][name]["release_authority"] = True
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_authority_wrapper_repins_still_fail(self) -> None:
        paths = {
            "broker-state": ("cases", "coherent", "broker_state"),
            "effects": ("cases", "coherent", "effects"),
            "grant": ("inputs", "grant"),
            "harness": ("harness",),
            "installed": ("artifacts", "installed", 0),
            "peer-chain": ("peer_chain",),
            "plugin": ("artifacts", "plugin"),
            "process": (
                "boundaries",
                "processes",
                "aragorn-runtime-action-worker.service",
            ),
            "producer": ("inputs", "producer"),
            "producer-record": ("inputs", "producer", "record"),
            "profile": ("profiles", "worker"),
            "receipt": ("cases", "coherent", "receipt"),
            "snapshot": ("cases", "coherent", "effects", "before"),
            "socket": ("boundaries", "sockets", "worker"),
            "trace": ("cases", "legacy_openclaw_profile", "traces", "worker"),
            "unit": (
                "boundaries",
                "units",
                "aragorn-runtime-action-worker.service",
            ),
        }
        for name, path in paths.items():
            with self.subTest(name=name):
                hostile = copy.deepcopy(self.evidence)
                target = hostile
                for component in path:
                    target = target[component]
                target["release_authority"] = True
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_raw_mount_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        mount = hostile["boundaries"]["mounts"]["worker_root"]
        mount["raw"] = mount["raw"].replace(" / / ro,", " / / rw,", 1)
        mount["raw_digest"] = (
            "sha256:" + hashlib.sha256(mount["raw"].encode()).hexdigest()
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_active_record_path_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["active_record"]["file"]["path"] = "/tmp/active.json"
        hostile["inputs"]["producer"]["record"]["file"]["path"] = "/tmp/active.json"
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_worker_attribution_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        service = "aragorn-runtime-action-worker.service"
        hostile["boundaries"]["processes"][service]["start_time_ticks"] = "999"
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_loaded_unit_contract_repins_still_fail(self) -> None:
        mutations = (
            ("aragorn-runtime-action-worker.service", "ProtectSystem", "off"),
            ("aragorn-runtime-action-worker.service", "LoadCredential", ""),
            ("aragorn-runtime-action-worker.service", "ReadOnlyPaths", ""),
            ("aragorn-runtime-action-worker.service", "PrivateNetwork", "no"),
            (
                "aragorn-agent-gateway.service",
                "FragmentDigest",
                "sha256:" + "f" * 64,
            ),
            (
                "aragorn-runtime-lineage-capability-action-broker.service",
                "FragmentDigest",
                "sha256:" + "f" * 64,
            ),
        )
        for service, field, value in mutations:
            with self.subTest(service=service, field=field):
                hostile = copy.deepcopy(self.evidence)
                hostile["boundaries"]["units"][service][field] = value
                self._assert_semantic_repin_fails(hostile)
        hostile = copy.deepcopy(self.evidence)
        sensor = "aragorn-runtime-lineage-capability-observation-publisher.service"
        hostile["boundaries"]["processes"][sensor]["cmdline"] = ["evil"]
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_exec_start_metadata_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        unit = hostile["boundaries"]["units"]["aragorn-agent-gateway.service"]
        unit["ExecStart"] = unit["ExecStart"].replace(
            "ignore_errors=no", "ignore_errors=yes"
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_socket_contract_repins_still_fail(self) -> None:
        mutations = (
            ("sensor", "mode", "0777"),
            ("broker", "gid", 0),
            ("worker_directory", "uid", 0),
            ("worker", "device", True),
            ("sensor", "inode", -1),
            ("broker", "size", "evil"),
            ("worker_directory", "nlink", 999),
        )
        for socket_name, field, value in mutations:
            with self.subTest(socket_name=socket_name, field=field):
                hostile = copy.deepcopy(self.evidence)
                hostile["boundaries"]["sockets"][socket_name][field] = value
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_endpoint_identity_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        identities = hostile["cases"]["worker_endpoint_unavailable"][
            "endpoint_identity"
        ]
        for identity in identities.values():
            identity.update({"device": 12_345, "inode": 67_890})
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_endpoint_service_inventory_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        service_pids = hostile["cases"]["worker_endpoint_unavailable"]["service_pids"]
        service_pids["before"]["evil.service"] = 99_999
        service_pids["after"]["evil.service"] = 99_999
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_installed_artifact_repins_still_fail(self) -> None:
        for field, value in (("mode", "0777"), ("type", "directory")):
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                installed = next(
                    item["installed"]
                    for item in hostile["artifacts"]["installed"]
                    if item["installed"]["path"]
                    == "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py"
                )
                installed["stat"][field] = value
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_file_stat_bool_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        collector = hostile["artifacts"]["collector"]["probe"]
        collector["stat"]["uid"] = False
        collector["stat"]["gid"] = False
        collector["stat"]["nlink"] = True
        self._assert_semantic_repin_fails(
            hostile, expected_message="retained file record changed"
        )

    def test_hostile_installed_closure_repins_still_fail(self) -> None:
        mutations = (
            (
                "/usr/lib/systemd/system/aragorn-agent-gateway.service",
                "aragorn-agent-gateway.service",
            ),
            (
                "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py",
                None,
            ),
        )
        for target_path, service in mutations:
            with self.subTest(target_path=target_path):
                hostile = copy.deepcopy(self.evidence)
                item = next(
                    item
                    for item in hostile["artifacts"]["installed"]
                    if item["installed"]["path"] == target_path
                )
                digest = "sha256:" + "a" * 64
                item["source"]["digest"] = digest
                item["installed"]["digest"] = digest
                if service is not None:
                    hostile["boundaries"]["units"][service]["FragmentDigest"] = digest
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_harness_containment_repins_still_fail(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        harness = hostile["harness"]
        harness["document"]["host_config"]["binds"].append("/etc:/host-etc:rw")
        harness["digest"] = canonical_digest(harness["document"])
        self._assert_semantic_repin_fails(hostile)

        hostile = copy.deepcopy(self.evidence)
        harness = hostile["harness"]
        harness["document"]["host_config"]["runtime"] = "hostile-runtime"
        harness["document"]["openclaw_runtime_volume_identity"]["driver"] = (
            "hostile-driver"
        )
        harness["digest"] = canonical_digest(harness["document"])
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_forbidden_read_inventory_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        reads = hostile["boundaries"]["forbidden_reads"]["gateway"]
        result = reads.pop("/etc/aragorn/agent-gateway/environment")
        reads["/tmp/not-protected"] = result
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_failed_connect_retry_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["coherent"]["traces"]["gateway"]
        trace["raw"] += (
            "884   connect(36, {sa_family=AF_UNIX, "
            'sun_path="/run/aragorn-runtime-action-worker/worker.sock"}, 110) = '
            "-1 ECONNREFUSED (Connection refused)\n"
        )
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_unfinished_connect_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["coherent"]["traces"]["worker"]
        trace["raw"] += (
            "882   connect(7, {sa_family=AF_UNIX, "
            'sun_path="/run/aragorn-runtime-observation/sensor.sock"}, 47 '
            "<unfinished ...>\n"
        )
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        self._assert_semantic_repin_fails(
            hostile, expected_message="unsupported Unix-only connect record"
        )

    def test_hostile_resumed_connect_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["coherent"]["traces"]["worker"]
        trace["raw"] += "882   <... connect resumed>) = 0\n"
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        hostile["peer_chain"]["observed"]["worker"] = copy.deepcopy(trace)
        self._assert_semantic_repin_fails(
            hostile, expected_message="unsupported resumed socket syscall"
        )

    def test_hostile_unknown_unix_service_connect_repin_still_fails(self) -> None:
        for result in ("0", "00", "0.0"):
            with self.subTest(result=result):
                hostile = copy.deepcopy(self.evidence)
                trace = hostile["cases"]["coherent"]["traces"]["worker"]
                trace["raw"] += f"882   connect(99, NULL, 0) = {result}\n"
                trace["raw_bytes"] = len(trace["raw"].encode())
                trace["raw_digest"] = (
                    "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
                )
                hostile["peer_chain"]["observed"]["worker"] = copy.deepcopy(trace)
                self._assert_semantic_repin_fails(
                    hostile, expected_message="unsupported Unix-only connect record"
                )

    def test_hostile_resumed_peer_lookup_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["coherent"]["traces"]["worker"]
        trace["raw"] += (
            "882   <... getsockopt resumed>{pid=999, uid=0, gid=0}, [12]) = 0\n"
        )
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        hostile["peer_chain"]["observed"]["worker"] = copy.deepcopy(trace)
        self._assert_semantic_repin_fails(
            hostile, expected_message="unsupported resumed socket syscall"
        )

    def test_hostile_unpaired_accept_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["coherent"]["traces"]["worker"]
        trace["raw"] += (
            "882   accept4(4, {sa_family=AF_UNIX}, [110 => 2], SOCK_CLOEXEC) = 99\n"
        )
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        self._assert_semantic_repin_fails(
            hostile, expected_message="unpaired Unix accept attempt"
        )

    def test_hostile_null_address_listener_accept_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["coherent"]["traces"]["worker"]
        trace["raw"] += "882   accept4(4, NULL, NULL, SOCK_CLOEXEC) = 99\n"
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        hostile["peer_chain"]["observed"]["worker"] = copy.deepcopy(trace)
        self._assert_semantic_repin_fails(
            hostile, expected_message="unpaired Unix listener accept"
        )

    def test_hostile_listener_accept_variants_repins_still_fail(self) -> None:
        variants = (
            (
                "882   accept4(04, NULL, NULL, SOCK_CLOEXEC) = 99\n",
                "unpaired Unix listener accept",
            ),
            (
                "882   accept(4, NULL, NULL) = 99\n",
                "unpaired Unix listener accept",
            ),
            (
                "882   accept4(99, NULL, NULL, SOCK_CLOEXEC) = 100\n",
                "unpaired Unix listener accept",
            ),
            (
                "882   accept4(4, NULL, NULL, SOCK_CLOEXEC) = 99 <0.000013>\n",
                "unsupported accept success record",
            ),
            (
                (
                    "882   accept4(4, NULL, NULL, SOCK_CLOEXEC <unfinished ...>\n"
                    "882   <... accept4 resumed>) = 99\n"
                ),
                "unsupported resumed socket syscall",
            ),
            (
                (
                    "882   accept4(4, NULL, NULL, SOCK_CLOEXEC <unfinished ...>\n"
                    "882   <... accept4 resumed>) = 99 <0.000013>\n"
                ),
                "unsupported resumed socket syscall",
            ),
        )
        for appended, expected_message in variants:
            with self.subTest(appended=appended):
                hostile = copy.deepcopy(self.evidence)
                trace = hostile["cases"]["coherent"]["traces"]["worker"]
                trace["raw"] += appended
                trace["raw_bytes"] = len(trace["raw"].encode())
                trace["raw_digest"] = (
                    "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
                )
                hostile["peer_chain"]["observed"]["worker"] = copy.deepcopy(trace)
                self._assert_semantic_repin_fails(
                    hostile, expected_message=expected_message
                )

    def test_hostile_negative_connect_attempt_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        trace = hostile["cases"]["legacy_openclaw_profile"]["traces"]["sensor"]
        trace["raw"] += (
            "201   connect(8, {sa_family=AF_UNIX, "
            'sun_path="/var/lib/aragorn-runtime-action/control/broker.sock"}, 54) '
            "= -1 ECONNREFUSED (Connection refused)\n"
        )
        trace["raw_bytes"] = len(trace["raw"].encode())
        trace["raw_digest"] = (
            "sha256:" + hashlib.sha256(trace["raw"].encode()).hexdigest()
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_plugin_subset_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        plugin = hostile["artifacts"]["plugin"]
        digest = "sha256:" + "a" * 64
        plugin["files"][0]["source"]["digest"] = digest
        plugin["files"][0]["installed"]["digest"] = digest
        plugin["digest"] = canonical_digest(
            [
                {
                    "digest": item["installed"]["digest"],
                    "executable": bool(
                        int(item["installed"]["stat"]["mode"], 8) & 0o111
                    ),
                    "kind": "file",
                    "links": item["installed"]["stat"]["nlink"],
                    "path": Path(item["installed"]["path"]).name,
                    "size": item["installed"]["bytes"],
                }
                for item in plugin["files"]
            ]
        )
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_grant_lease_time_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        grant = hostile["inputs"]["grant"]
        old_grant_digest = grant["digest"]
        grant["document"]["issued_at_unix"] = 1_786_279_160
        grant["document"]["expires_at_unix"] = 1_786_279_200
        grant["digest"] = canonical_digest(grant["document"])
        new_grant_digest = grant["digest"]

        def replace_grant_digest(value: object) -> None:
            if isinstance(value, dict):
                for key, child in value.items():
                    if child == old_grant_digest:
                        value[key] = new_grant_digest
                    else:
                        replace_grant_digest(child)
            elif isinstance(value, list):
                for child in value:
                    replace_grant_digest(child)

        for name, case in hostile["cases"].items():
            if name == "legacy_openclaw_profile":
                continue
            for position in ("before", "after"):
                snapshot = case["effects"][position]
                wrapper = snapshot["grant_state"]
                replace_grant_digest(wrapper["document"])
                if name == "coherent" and position == "after":
                    claim = wrapper["document"]["claim"]
                    lease_digest = canonical_digest(claim["lease"])
                    claim["lease_digest"] = lease_digest
                    claim["profile_claim"]["lease_digest"] = lease_digest
                    wrapper["document"]["result"]["lease_digest"] = lease_digest
                    wrapper["document"]["result"]["profile_result"]["lease_digest"] = (
                        lease_digest
                    )
                wrapper["digest"] = canonical_digest(wrapper["document"])
                snapshot["controls"]["capability-grant-state.json"] = wrapper["digest"]
        self._assert_semantic_repin_fails(
            hostile, expected_message="driver root grant window changed: coherent"
        )

    def test_hostile_lease_policy_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        snapshot = hostile["cases"]["coherent"]["effects"]["after"]
        wrapper = snapshot["grant_state"]
        claim = wrapper["document"]["claim"]
        claim["lease"]["policy_digest"] = "sha256:" + "a" * 64
        lease_digest = canonical_digest(claim["lease"])
        claim["lease_digest"] = lease_digest
        claim["profile_claim"]["lease_digest"] = lease_digest
        wrapper["document"]["result"]["lease_digest"] = lease_digest
        wrapper["document"]["result"]["profile_result"]["lease_digest"] = lease_digest
        wrapper["digest"] = canonical_digest(wrapper["document"])
        snapshot["controls"]["capability-grant-state.json"] = wrapper["digest"]
        self._assert_semantic_repin_fails(
            hostile, expected_message="grant and lease authority binding changed"
        )

    def test_hostile_worker_request_lifetime_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        lease = hostile["cases"]["coherent"]["effects"]["after"]["grant_state"][
            "document"
        ]["claim"]["lease"]
        lease["issued_at_unix"] -= 1
        self._rederive_coherent_authority_digests(hostile)
        self._assert_semantic_repin_fails(
            hostile, expected_message="worker request lifetime changed"
        )

    def test_hostile_legacy_grant_window_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        grant = hostile["inputs"]["legacy_grant"]
        grant["document"]["issued_at_unix"] = 100
        grant["document"]["expires_at_unix"] = 200
        grant["digest"] = canonical_digest(grant["document"])
        effects = hostile["cases"]["legacy_openclaw_profile"]["effects"]
        for position in ("before", "after"):
            snapshot = effects[position]
            state = snapshot["grant_state"]
            state["document"]["grant_digest"] = grant["digest"]
            state["digest"] = canonical_digest(state["document"])
            snapshot["controls"]["capability-grant-state.json"] = state["digest"]
        self._assert_semantic_repin_fails(
            hostile, expected_message="legacy grant control window changed"
        )

    def test_hostile_legacy_driver_grant_clock_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        delta = 1_000_000
        grant = hostile["inputs"]["legacy_grant"]
        grant["document"]["issued_at_unix"] -= delta
        grant["document"]["expires_at_unix"] -= delta
        grant["digest"] = canonical_digest(grant["document"])
        controls = hostile["inputs"]["control_sets"]["legacy"]
        for document in (
            controls["health"],
            controls["observation"],
            controls["revocations"],
        ):
            for field in ("observed_at_unix", "expires_at_unix"):
                document[field] -= delta
        effects = hostile["cases"]["legacy_openclaw_profile"]["effects"]
        for position in ("before", "after"):
            snapshot = effects[position]
            state = snapshot["grant_state"]
            state["document"]["grant_digest"] = grant["digest"]
            state["digest"] = canonical_digest(state["document"])
            snapshot["controls"].update(
                {
                    "capability-grant-state.json": state["digest"],
                    "health.json": canonical_digest(controls["health"]),
                    "observation.json": canonical_digest(controls["observation"]),
                    "revocations.json": canonical_digest(controls["revocations"]),
                }
            )
        self._assert_semantic_repin_fails(
            hostile,
            expected_message="driver root grant window changed: legacy_openclaw_profile",
        )

    def test_hostile_decision_scalar_repin_still_fails(self) -> None:
        for field, value in (
            ("policy_version", 2),
            ("revocation_generation", 999),
            ("evaluated_at_unix", 100),
        ):
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                decision = hostile["cases"]["coherent"]["receipt"]["document"][
                    "broker_result"
                ]["decision"]
                decision[field] = value
                self._rebind_coherent_receipt(hostile)
                self._assert_semantic_repin_fails(
                    hostile,
                    expected_message="coherent decision scalar binding changed",
                )

        hostile = copy.deepcopy(self.evidence)
        decision = hostile["cases"]["coherent"]["receipt"]["document"]["broker_result"][
            "decision"
        ]
        decision["override_authority"] = True
        self._rebind_coherent_receipt(hostile)
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_worker_binding_bool_repin_still_fails(self) -> None:
        hostile = copy.deepcopy(self.evidence)
        hostile["inputs"]["worker_binding"]["policy_version"] = True
        hostile["inputs"]["worker_binding_mismatch"]["policy_version"] = True
        self._assert_semantic_repin_fails(hostile)

    def test_hostile_runtime_attribution_repins_still_fail(self) -> None:
        mutations = (
            ("schema", "evil/attribution/v9"),
            ("authority", "EVIL_AUTHORITY"),
            ("mount_namespace", {"device": 5, "inode": 4_026_532_911}),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                hostile = copy.deepcopy(self.evidence)
                case = hostile["cases"]["coherent"]
                claim = case["effects"]["after"]["grant_state"]["document"]["claim"]
                pending = claim["profile_claim"]["profile_pending"]
                pending["runtime_attribution"][field] = value
                attribution_digest = canonical_digest(pending["runtime_attribution"])
                pending["runtime_attribution_digest"] = attribution_digest
                receipt = case["receipt"]["document"]
                receipt["runtime_attribution"][field] = value
                receipt["runtime_attribution_digest"] = attribution_digest
                self._rederive_coherent_authority_digests(hostile)
                self._assert_semantic_repin_fails(hostile)

    def test_hostile_inner_broker_digest_repins_still_fail(self) -> None:
        case = self.evidence["cases"]["coherent"]
        claim = case["effects"]["after"]["grant_state"]["document"]["claim"]
        mutations = (
            (
                "request",
                claim["lease"]["request_digest"],
                "inner broker request binding changed",
            ),
            (
                "envelope",
                claim["profile_claim"]["envelope_digest"],
                "inner broker envelope binding changed",
            ),
            (
                "submission",
                claim["lease"]["submission_digest"],
                "profiled submission binding changed",
            ),
        )
        for name, old_digest, expected_message in mutations:
            with self.subTest(name=name):
                hostile = copy.deepcopy(self.evidence)
                self._replace_value(
                    hostile["cases"]["coherent"],
                    old_digest,
                    "sha256:" + "a" * 64,
                )
                self._rebind_coherent_authority_chain(hostile)
                self._assert_semantic_repin_fails(
                    hostile, expected_message=expected_message
                )

    @staticmethod
    def _rebind_coherent_receipt(hostile: dict) -> None:
        case = hostile["cases"]["coherent"]
        receipt = case["receipt"]
        broker_result = receipt["document"]["broker_result"]
        receipt["document"]["broker_result_digest"] = canonical_digest(broker_result)
        receipt["digest"] = canonical_digest(receipt["document"])
        case["receipt_file"]["digest"] = receipt["digest"]
        case["receipt_file"]["bytes"] = len(canonical_json(receipt["document"]))
        case["receipt_file"]["stat"]["size"] = case["receipt_file"]["bytes"]
        result = case["effects"]["after"]["grant_state"]["document"]["result"]
        result["profile_result"]["broker_result_digest"] = receipt["document"][
            "broker_result_digest"
        ]
        result["profile_result"]["profile_receipt_digest"] = receipt["digest"]
        state = case["effects"]["after"]["grant_state"]
        state["digest"] = canonical_digest(state["document"])
        case["effects"]["after"]["controls"]["capability-grant-state.json"] = state[
            "digest"
        ]

    @classmethod
    def _rebind_coherent_authority_chain(cls, hostile: dict) -> None:
        case = hostile["cases"]["coherent"]
        state = case["effects"]["after"]["grant_state"]
        claim = state["document"]["claim"]
        result = state["document"]["result"]
        lease_digest = canonical_digest(claim["lease"])
        claim["lease_digest"] = lease_digest
        claim["profile_claim"]["lease_digest"] = lease_digest
        result["lease_digest"] = lease_digest
        result["profile_result"]["lease_digest"] = lease_digest
        cls._rebind_coherent_receipt(hostile)
        broker_state = case["broker_state"]
        broker_state["digest"] = canonical_digest(broker_state["document"])
        case["effects"]["after"]["controls"]["state.json"] = broker_state["digest"]

    @classmethod
    def _rederive_coherent_authority_digests(cls, hostile: dict) -> None:
        case = hostile["cases"]["coherent"]
        claim = case["effects"]["after"]["grant_state"]["document"]["claim"]
        lease = claim["lease"]
        correlation = case["correlation"]
        request = {
            "active_skill_digest": lease["active_skill_digest"],
            "authority": "RUNTIME_ACTION_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
            "expires_at_unix": lease["expires_at_unix"],
            "issued_at_unix": lease["issued_at_unix"],
            "operation_digest": lease["operation_digest"],
            "path_digest": lease["path_digest"],
            "payload_digest": lease["payload_digest"],
            "policy_digest": lease["policy_digest"],
            "policy_version": lease["policy_version"],
            "run_id": correlation["run_id"],
            "runtime_digest": lease["runtime_digest"],
            "schema": "aragorn/runtime-action-request/v1",
            "session_id": correlation["session_id"],
            "tool_call_id": correlation["tool_call_id"],
        }
        cls._replace_value(case, lease["request_digest"], canonical_digest(request))
        scenario = case["driver"]["input"]["scenario"]
        envelope = {
            "effect": {
                "operation": "create",
                "payload_base64": b64encode(scenario["content"].encode()).decode(
                    "ascii"
                ),
                "schema": "aragorn/runtime-create-file/v1",
                "target_name": scenario["target_name"],
            },
            "request": request,
            "schema": "aragorn/runtime-action-broker-request/v1",
        }
        profile_claim = claim["profile_claim"]
        cls._replace_value(
            case, profile_claim["envelope_digest"], canonical_digest(envelope)
        )
        attribution = profile_claim["profile_pending"]["runtime_attribution"]
        submission = {
            "authority": "OUT_OF_PROCESS_MEASUREMENT_ONLY_NOT_EFFECT_AUTHORITY",
            "envelope": envelope,
            "envelope_digest": canonical_digest(envelope),
            "measured_action": correlation,
            "request_digest": canonical_digest(request),
            "runtime_attribution": attribution,
            "runtime_peer": {key: attribution[key] for key in ("pid", "uid", "gid")},
            "schema": "aragorn/runtime-observed-create-submission/v2",
            "sensor_digest": lease["sensor_digest"],
        }
        cls._replace_value(
            case, lease["submission_digest"], canonical_digest(submission)
        )
        cls._rebind_coherent_authority_chain(hostile)

    @classmethod
    def _replace_value(cls, value: object, old: object, new: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if child == old:
                    value[key] = new
                else:
                    cls._replace_value(child, old, new)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                if child == old:
                    value[index] = new
                else:
                    cls._replace_value(child, old, new)

    def _assert_semantic_repin_fails(
        self, hostile: dict, *, expected_message: str | None = None
    ) -> None:
        encoded = canonical_json(hostile)
        digest = canonical_digest(hostile)
        raw_digest = "sha256:" + hashlib.sha256(encoded + b"\n").hexdigest()
        with (
            mock.patch.object(subject, "_EVIDENCE_DIGEST", digest),
            mock.patch.object(subject, "_EVIDENCE_RAW_DIGEST", raw_digest),
            mock.patch.object(subject, "_EVIDENCE_BYTES", len(encoded) + 1),
            self.assertRaises(AdmissionEvidenceError) as raised,
        ):
            subject.verify_runtime_action_worker_openclaw_systemd_evidence(
                hostile, self.parent, expected_digest=digest
            )
        if expected_message is not None:
            self.assertEqual(str(raised.exception), expected_message)

    @staticmethod
    def _rebind_active_record(record: dict) -> None:
        encoded = canonical_json(record["document"])
        record["digest"] = canonical_digest(record["document"])
        record["file"]["digest"] = record["digest"]
        record["file"]["bytes"] = len(encoded)
        record["file"]["stat"]["size"] = len(encoded)
        if "raw_digest" in record:
            record["raw_digest"] = record["digest"]

    @staticmethod
    def _implementation_digest() -> str:
        return (
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
