from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_action_worker_activation_expiry_systemd_evidence as subject

_ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict:
    return json.loads((_ROOT / path).read_bytes())


class RuntimeActionWorkerActivationExpirySystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = _load(
            "benchmark/evidence/runtime-action-worker-activation-expiry-systemd-"
            "composition-p3-7c-2026-08-09.json"
        )
        cls.parent = _load(
            "benchmark/evidence/runtime-action-worker-openclaw-systemd-composition-"
            "p3-7b-2026-08-09.json"
        )
        cls.parent_parent = _load(
            "benchmark/evidence/runtime-producer-lineage-openclaw-systemd-"
            "composition-p3-6b-2026-08-07.json"
        )
        cls.parent_receipt = _load(
            "benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-"
            "qualification-v1-2026-08-09.json"
        )

    def test_exact_observation_qualifies_without_broad_authority(self) -> None:
        qualification = (
            subject.runtime_action_worker_activation_expiry_systemd_qualification(
                self.evidence,
                self.parent,
                self.parent_parent,
                self.parent_receipt,
                expected_digest=subject._EVIDENCE_DIGEST,
                implementation_digest=self._implementation_digest(),
            )
        )
        self.assertEqual(qualification["decision"], subject._QUALIFICATION_DECISION)
        self.assertEqual(qualification["decision"]["status"], "P3_7C_BOUNDED_PASS")
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
        self.assertEqual(
            qualification["cases"]["coherent_consumed"],
            {
                "driver_status": "COMPLETED",
                "effect_status": "CREATED",
                "grant_state": "CONSUMED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
        )

    def test_verifier_requires_exact_source_and_implementation_pins(self) -> None:
        with self.assertRaises(subject.AdmissionEvidenceError):
            subject.verify_runtime_action_worker_activation_expiry_systemd_evidence(
                self.evidence,
                self.parent,
                self.parent_parent,
                self.parent_receipt,
                expected_digest=None,
            )
        with self.assertRaises(subject.AdmissionEvidenceError):
            subject.runtime_action_worker_activation_expiry_systemd_qualification(
                self.evidence,
                self.parent,
                self.parent_parent,
                self.parent_receipt,
                expected_digest=subject._EVIDENCE_DIGEST,
                implementation_digest=None,
            )

    def test_parent_receipt_repin_is_rejected(self) -> None:
        receipt = copy.deepcopy(self.parent_receipt)
        receipt["decision"]["status"] = "P3_7C_BOUNDED_PASS"
        with self.assertRaises(subject.AdmissionEvidenceError):
            subject.verify_runtime_action_worker_activation_expiry_systemd_evidence(
                self.evidence,
                self.parent,
                self.parent_parent,
                receipt,
                expected_digest=subject._EVIDENCE_DIGEST,
            )

    def test_installed_source_target_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            pair = document["artifacts"]["installed"][0]
            pair["source"]["digest"] = pair["installed"]["digest"] = (
                "sha256:" + "a" * 64
            )

        self._assert_mutation_rejected(mutate)

    def test_distinct_artifacts_cannot_share_a_single_link_inode(self) -> None:
        def mutate(document: dict) -> None:
            installed = document["artifacts"]["installed"]
            source = installed[0]["source"]["stat"]
            target = installed[1]["source"]["stat"]
            target["device"], target["inode"] = source["device"], source["inode"]

        self._assert_mutation_rejected(mutate)

    def test_worker_installer_custody_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            document["artifacts"]["worker_installer"]["stat"].update(
                {"nlink": 2, "uid": 1000}
            )

        self._assert_mutation_rejected(mutate)

    def test_boolean_file_owner_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["artifacts"]["installed"][0]["source"][
                "stat"
            ].__setitem__("uid", False)
        )

    def test_boolean_boundary_metadata_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            boundaries = document["boundaries"]
            boundaries["processes"]["aragorn-agent-gateway.service"][
                "no_new_privileges"
            ] = True
            boundaries["sockets"]["/run/aragorn-runtime-action-worker/worker.sock"][
                "metadata"
            ]["nlink"] = True

        self._assert_mutation_rejected(mutate)

    def test_expiry_unit_and_process_provenance_repins_are_rejected(self) -> None:
        mutations = (
            ("unit", "FragmentDigest", "sha256:" + "a" * 64),
            ("unit", "NoNewPrivileges", "no"),
            ("unit", "Result", "failed"),
            ("unit", "MainPID", 216),
            ("process", "cmdline", ["/tmp/evil"]),
            ("process", "start_time_ticks", "1"),
        )
        for record, field, replacement in mutations:
            with self.subTest(record=record, field=field):
                self._assert_mutation_rejected(
                    lambda document, record=record, field=field, replacement=replacement: (
                        document["cases"]["expired_fail_stop"]["expiry"][
                            record
                        ].__setitem__(field, replacement)
                    )
                )

    def test_expiry_route_must_be_clean_before_activation(self) -> None:
        def mutate(document: dict) -> None:
            expired = document["cases"]["expired_fail_stop"]
            service = "aragorn-runtime-lineage-capability-observation-publisher.service"
            for route in (
                expired["expiry"]["after_route"],
                expired["activation"]["route"]["before"],
            ):
                self._rebind_service_property(
                    route["units"][service], "ActiveState", "active"
                )

        self._assert_mutation_rejected(mutate)

    def test_capture_commands_require_root_caller(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["expired_fail_stop"]["expiry"][
                "broker_start"
            ].__setitem__("caller", {"gid": 1000, "uid": 1000})
        )

    def test_state_changing_command_output_repins_are_rejected(self) -> None:
        def dirty_broker_start(document: dict) -> None:
            command = document["cases"]["expired_fail_stop"]["expiry"]["broker_start"]
            self._rebind_raw(command["stderr"], b"Failed to start\n")

        def dirty_failed_activation(document: dict) -> None:
            command = document["cases"]["expired_fail_stop"]["activation"]["command"]
            raw = base64.b64decode(command["stderr"]["base64"], validate=True)
            self._rebind_raw(command["stderr"], b"segmentation fault\n" + raw)

        def dirty_successful_activation(document: dict) -> None:
            rotation = document["cases"]["terminal_archive_rotation"]
            command = rotation["activation_command"]
            raw = base64.b64decode(command["stderr"]["base64"], validate=True)
            self._rebind_raw(command["stderr"], raw + b"segmentation fault\n")
            document["cases"]["full_activation"]["activation_command"] = copy.deepcopy(
                command
            )

        for name, mutate in (
            ("broker_start", dirty_broker_start),
            ("failed_activation", dirty_failed_activation),
            ("successful_activation", dirty_successful_activation),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_harness_host_bind_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            harness = document["harness"]
            harness["document"]["host_config"]["binds"].append("/etc:/host-etc:rw")
            self._rebind_document_snapshot(harness)

        self._assert_mutation_rejected(mutate)

    def test_persistent_files_cannot_reuse_live_object_inodes(self) -> None:
        def harness_socket(document: dict) -> None:
            socket = document["cases"]["full_activation"]["stack"]["sockets"][
                "/run/aragorn-runtime-action-worker/worker.sock"
            ]["metadata"]
            document["harness"]["file"]["stat"].update(
                {"device": socket["device"], "inode": socket["inode"]}
            )

        def installer_state(document: dict) -> None:
            state = document["cases"]["terminal_archive_rotation"]["after"][
                "current_state_file"
            ]["stat"]
            document["artifacts"]["worker_installer"]["stat"].update(
                {"device": state["device"], "inode": state["inode"]}
            )

        for name, mutate in (
            ("harness_socket", harness_socket),
            ("installer_state", installer_state),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_expired_activation_success_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["expired_fail_stop"]["activation"][
                "command"
            ].__setitem__("exit_code", 0)
        )

    def test_expired_state_inode_rewrite_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["expired_fail_stop"]["activation"][
                "state"
            ]["after_file"]["stat"].__setitem__("inode", 999_999)
        )

    def test_expired_state_file_custody_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            expiry = document["cases"]["expired_fail_stop"]["expiry"]
            for record in (
                expiry["available_state"]["file"],
                expiry["available_state_file"],
            ):
                record["path"] = "/tmp/forged-grant-state.json"
                record["stat"].update(
                    {"gid": 1000, "mode": "0666", "nlink": 2, "uid": 1000}
                )

        self._assert_mutation_rejected(mutate)

    def test_expiry_state_file_times_stay_in_phase(self) -> None:
        def mutate(document: dict) -> None:
            expiry = document["cases"]["expired_fail_stop"]["expiry"]
            for record in (
                expiry["available_state"]["file"],
                expiry["available_state_file"],
            ):
                record["stat"]["mtime_ns"] = 1
                record["stat"]["ctime_ns"] = 1

        self._assert_mutation_rejected(mutate)

    def test_available_state_and_live_broker_socket_cannot_share_inode(self) -> None:
        def mutate(document: dict) -> None:
            expiry = document["cases"]["expired_fail_stop"]["expiry"]
            socket = expiry["socket"]["metadata"]
            for record in (
                expiry["available_state"]["file"],
                expiry["available_state_file"],
            ):
                record["stat"].update(
                    {"device": socket["device"], "inode": socket["inode"]}
                )

        self._assert_mutation_rejected(mutate)

    def test_fail_stop_orphan_process_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["expired_fail_stop"]["activation"][
                "route"
            ]["after"]["units"]["aragorn-agent-gateway.service"][
                "cgroup_members"
            ].append("99999")
        )

    def test_service_snapshot_command_is_exact_and_unambiguous(self) -> None:
        def entry(document: dict) -> dict:
            return document["cases"]["expired_fail_stop"]["expiry"]["after_route"][
                "units"
            ]["aragorn-agent-gateway.service"]

        def extend_argv(document: dict) -> None:
            entry(document)["command"]["argv"].append("--host=evil")

        def dirty_stderr(document: dict) -> None:
            self._rebind_raw(
                entry(document)["command"]["stderr"],
                b"Failed to connect to bus\n",
            )

        def duplicate_result(document: dict) -> None:
            stdout = entry(document)["command"]["stdout"]
            raw = base64.b64decode(stdout["base64"], validate=True)
            self._rebind_raw(stdout, b"Result=failed\n" + raw)

        for name, mutate in (
            ("argv", extend_argv),
            ("stderr", dirty_stderr),
            ("duplicate_result", duplicate_result),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_archive_path_repin_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["terminal_archive_rotation"]["after"][
                "archive"
            ]["file"].__setitem__(
                "path", "/var/lib/aragorn-runtime-action/control/evil.json"
            )
        )

    def test_archive_time_is_bound_to_rotation_window(self) -> None:
        def mutate(document: dict) -> None:
            after = document["cases"]["terminal_archive_rotation"]["after"]
            coherent = document["cases"]["coherent_consumed"]["expired_archive_after"]
            for record in (
                after["archive"]["file"],
                after["archive_file"],
                coherent["file"],
            ):
                record["stat"]["mtime_ns"] = 1
                record["stat"]["ctime_ns"] = 1

        self._assert_mutation_rejected(mutate)

    def test_archive_and_current_state_cannot_share_inode(self) -> None:
        def mutate(document: dict) -> None:
            after = document["cases"]["terminal_archive_rotation"]["after"]
            current = after["current_state_file"]["stat"]
            for record in (after["archive"]["file"], after["archive_file"]):
                record["stat"]["device"] = current["device"]
                record["stat"]["inode"] = current["inode"]

        self._assert_mutation_rejected(mutate)

    def test_rotation_state_and_socket_cannot_share_inode(self) -> None:
        def mutate(document: dict) -> None:
            after = document["cases"]["terminal_archive_rotation"]["after"]
            socket = after["route"]["sockets"][
                "/var/lib/aragorn-runtime-action/control/broker.sock"
            ]["metadata"]
            for record in (after["current_state"]["file"], after["current_state_file"]):
                record["stat"]["device"] = socket["device"]
                record["stat"]["inode"] = socket["inode"]

        self._assert_mutation_rejected(mutate)

    def test_rotation_state_and_grant_source_path_repins_are_rejected(self) -> None:
        def mutate_state(document: dict) -> None:
            after = document["cases"]["terminal_archive_rotation"]["after"]
            after["current_state"]["file"]["path"] = "/tmp/forged-current-state.json"
            after["current_state_file"]["path"] = "/tmp/forged-current-state.json"

        def mutate_grant(document: dict) -> None:
            rotation = document["cases"]["terminal_archive_rotation"]
            records = (
                rotation["grant_replacement"]["file"],
                rotation["grant_replacement"]["grant"]["file"],
                rotation["before"]["grant_source"]["file"],
                rotation["after"]["grant_source"]["file"],
            )
            for record in records:
                record["path"] = "/tmp/forged-grant.json"

        for name, mutate in (("state", mutate_state), ("grant", mutate_grant)):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_gateway_boot_authority_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            document["cases"]["full_activation"]["stack"]["enablement"][
                "aragorn-agent-gateway.service"
            ] = "enabled"
            document["boundaries"]["enablement"]["aragorn-agent-gateway.service"] = (
                "enabled"
            )

        self._assert_mutation_rejected(mutate)

    def test_gateway_worker_connect_retry_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            trace = document["cases"]["coherent_consumed"]["traces"]["gateway"]
            trace["raw"] += (
                f"{trace['service_pid']}  connect(36, "
                '{sa_family=AF_UNIX, sun_path="/run/aragorn-runtime-action-worker/worker.sock"}, '
                "110) = -1 ECONNREFUSED (Connection refused)\n"
            )
            trace["raw_bytes"] = len(trace["raw"].encode())
            trace["raw_digest"] = subject._raw_digest(trace["raw"].encode())

        self._assert_mutation_rejected(mutate)

    def test_gateway_direct_broker_connect_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            trace = document["cases"]["coherent_consumed"]["traces"]["gateway"]
            trace["raw"] += (
                f"{trace['service_pid']}  connect(37, "
                '{sa_family=AF_UNIX, sun_path="/var/lib/aragorn-runtime-action/control/broker.sock"}, '
                "110) = 0\n"
            )
            trace["raw_bytes"] = len(trace["raw"].encode())
            trace["raw_digest"] = subject._raw_digest(trace["raw"].encode())

        self._assert_mutation_rejected(mutate)

    def test_coherent_effect_digest_repin_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["coherent_consumed"][
                "target"
            ].__setitem__("digest", "sha256:" + "a" * 64)
        )

    def test_coherent_broker_state_custody_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            file = document["cases"]["coherent_consumed"]["broker_state"]["file"]
            file["path"] = "/tmp/forged-state.json"
            file["stat"].update({"gid": 1000, "mode": "0666", "nlink": 2, "uid": 1000})

        self._assert_mutation_rejected(mutate)

    def test_coherent_action_file_times_stay_in_driver_window(self) -> None:
        def mutate(document: dict) -> None:
            file = document["cases"]["coherent_consumed"]["broker_state"]["file"]
            file["stat"]["mtime_ns"] = 1_786_300_729_000_000_000
            file["stat"]["ctime_ns"] = 1_786_300_729_000_000_010

        self._assert_mutation_rejected(mutate)

    def test_coherent_control_files_cannot_share_single_link_inode(self) -> None:
        for source_name in ("receipt", "grant_state"):
            with self.subTest(source=source_name):

                def mutate(document: dict, source_name: str = source_name) -> None:
                    coherent = document["cases"]["coherent_consumed"]
                    source = coherent[source_name]["file"]["stat"]
                    coherent["broker_state"]["file"]["stat"].update(
                        {"device": source["device"], "inode": source["inode"]}
                    )

                self._assert_mutation_rejected(mutate)

    def test_coherent_service_inventory_extension_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["coherent_consumed"]["service_pids"][
                "after"
            ].__setitem__("evil.service", 99999)
        )

    def test_coherent_socket_owner_or_cgroup_extension_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            coherent = document["cases"]["coherent_consumed"]
            coherent["service_state_after"]["sockets"][
                "/run/aragorn-runtime-action-worker/worker.sock"
            ]["metadata"]["uid"] = 0
            coherent["service_state_after"]["units"][
                "aragorn-runtime-action-worker.service"
            ]["cgroup_members"].append("99999")

        self._assert_mutation_rejected(mutate)

    def test_coherent_service_enablement_repin_is_rejected(self) -> None:
        for field, replacement in (
            ("UnitFileState", "enabled"),
            ("SubState", "dead"),
            ("ExecMainCode", "9"),
            ("ControlGroup", "/system.slice/evil.service"),
        ):
            with self.subTest(field=field):

                def mutate(
                    document: dict, field: str = field, replacement: str = replacement
                ) -> None:
                    worker = document["cases"]["coherent_consumed"][
                        "service_state_after"
                    ]["units"]["aragorn-runtime-action-worker.service"]
                    self._rebind_service_property(worker, field, replacement)

                self._assert_mutation_rejected(mutate)

    def test_activation_service_snapshot_repins_are_rejected(self) -> None:
        service = "aragorn-runtime-action-worker.service"

        def records(document: dict) -> tuple[dict, ...]:
            return (
                document["cases"]["full_activation"]["stack"]["service_state"]["units"][
                    service
                ],
                document["cases"]["terminal_archive_rotation"]["after"]["route"][
                    "units"
                ][service],
                document["boundaries"]["service_state"]["units"][service],
            )

        for field, replacement in (
            ("UnitFileState", "enabled"),
            ("ControlGroup", "/system.slice/evil.service"),
            ("ExecMainCode", "9"),
            ("ExecMainStartTimestampMonotonic", "evil"),
        ):
            with self.subTest(field=field):

                def mutate(
                    document: dict, field: str = field, replacement: str = replacement
                ) -> None:
                    for record in records(document):
                        self._rebind_service_property(record, field, replacement)

                self._assert_mutation_rejected(mutate)

    def test_active_service_invocations_must_be_distinct(self) -> None:
        def mutate(document: dict) -> None:
            shared = "a" * 32
            snapshots = (
                document["cases"]["full_activation"]["stack"]["service_state"],
                document["cases"]["terminal_archive_rotation"]["after"]["route"],
                document["boundaries"]["service_state"],
                document["cases"]["coherent_consumed"]["service_state_after"],
            )
            for snapshot in snapshots:
                for entry in snapshot["units"].values():
                    self._rebind_service_property(entry, "InvocationID", shared)

        self._assert_mutation_rejected(mutate)

    def test_failed_invocations_cannot_be_reused_by_active_services(self) -> None:
        def mutate(document: dict) -> None:
            failed = document["cases"]["expired_fail_stop"]["activation"]["route"][
                "invocations"
            ]["aragorn-runtime-lineage-capability-action-broker.service"][
                "invocation_id"
            ]
            service = "aragorn-agent-gateway.service"
            for snapshot in (
                document["cases"]["full_activation"]["stack"]["service_state"],
                document["cases"]["terminal_archive_rotation"]["after"]["route"],
                document["boundaries"]["service_state"],
                document["cases"]["coherent_consumed"]["service_state_after"],
            ):
                self._rebind_service_property(
                    snapshot["units"][service], "InvocationID", failed
                )

        self._assert_mutation_rejected(mutate)

    def test_service_timestamps_are_phase_bound(self) -> None:
        service = "aragorn-runtime-action-worker.service"

        def active_aliases(document: dict) -> tuple[dict, ...]:
            return (
                document["cases"]["full_activation"]["stack"]["service_state"]["units"][
                    service
                ],
                document["cases"]["terminal_archive_rotation"]["after"]["route"][
                    "units"
                ][service],
                document["boundaries"]["service_state"]["units"][service],
            )

        def boot_time(document: dict) -> None:
            for entry in active_aliases(document):
                self._rebind_service_property(
                    entry, "ExecMainStartTimestampMonotonic", "1"
                )
                self._rebind_service_property(
                    entry, "ActiveEnterTimestampMonotonic", "1"
                )

        def reversed_time(document: dict) -> None:
            for entry in active_aliases(document):
                self._rebind_service_property(
                    entry, "ExecMainStartTimestampMonotonic", "999999999999"
                )
                self._rebind_service_property(
                    entry, "ActiveEnterTimestampMonotonic", "1"
                )

        def coherent_drift(document: dict) -> None:
            entry = document["cases"]["coherent_consumed"]["service_state_after"][
                "units"
            ][service]
            self._rebind_service_property(entry, "ExecMainStartTimestampMonotonic", "1")

        def broker_exit_before_start(document: dict) -> None:
            entry = document["cases"]["coherent_consumed"]["service_state_after"][
                "units"
            ]["aragorn-runtime-lineage-capability-action-broker.service"]
            self._rebind_service_property(entry, "ExecMainExitTimestampMonotonic", "1")

        def broker_exit_after_snapshot(document: dict) -> None:
            entry = document["cases"]["coherent_consumed"]["service_state_after"][
                "units"
            ]["aragorn-runtime-lineage-capability-action-broker.service"]
            self._rebind_service_property(
                entry, "ExecMainExitTimestampMonotonic", "999999999999"
            )
            self._rebind_service_property(
                entry, "InactiveEnterTimestampMonotonic", "999999999999"
            )

        def broker_exit_before_driver(document: dict) -> None:
            entry = document["cases"]["coherent_consumed"]["service_state_after"][
                "units"
            ]["aragorn-runtime-lineage-capability-action-broker.service"]
            self._rebind_service_property(
                entry, "ExecMainExitTimestampMonotonic", "297778100000"
            )
            self._rebind_service_property(
                entry, "InactiveEnterTimestampMonotonic", "297778100001"
            )

        def broker_exit_before_provider(document: dict) -> None:
            entry = document["cases"]["coherent_consumed"]["service_state_after"][
                "units"
            ]["aragorn-runtime-lineage-capability-action-broker.service"]
            self._rebind_service_property(
                entry, "ExecMainExitTimestampMonotonic", "297778394999"
            )
            self._rebind_service_property(
                entry, "InactiveEnterTimestampMonotonic", "297778395000"
            )

        def broker_exit_before_effect_files(document: dict) -> None:
            entry = document["cases"]["coherent_consumed"]["service_state_after"][
                "units"
            ]["aragorn-runtime-lineage-capability-action-broker.service"]
            self._rebind_service_property(
                entry, "ExecMainExitTimestampMonotonic", "297783091001"
            )
            self._rebind_service_property(
                entry, "InactiveEnterTimestampMonotonic", "297783091002"
            )

        def active_service_claims_future_inactive_time(document: dict) -> None:
            for entry in active_aliases(document):
                self._rebind_service_property(
                    entry, "InactiveEnterTimestampMonotonic", "999999999999"
                )

        for name, mutate in (
            ("boot_time", boot_time),
            ("reversed", reversed_time),
            ("coherent_drift", coherent_drift),
            ("broker_exit", broker_exit_before_start),
            ("broker_future_exit", broker_exit_after_snapshot),
            ("broker_pre_driver_exit", broker_exit_before_driver),
            ("broker_pre_provider_exit", broker_exit_before_provider),
            ("broker_pre_effect_exit", broker_exit_before_effect_files),
            ("active_future_inactive", active_service_claims_future_inactive_time),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_active_sockets_cannot_share_single_link_inode(self) -> None:
        worker_path = "/run/aragorn-runtime-action-worker/worker.sock"
        sensor_path = "/run/aragorn-runtime-observation/sensor.sock"

        def mutate(document: dict) -> None:
            snapshots = (
                document["cases"]["full_activation"]["stack"]["sockets"],
                document["cases"]["full_activation"]["stack"]["service_state"][
                    "sockets"
                ],
                document["cases"]["terminal_archive_rotation"]["after"]["route"][
                    "sockets"
                ],
                document["boundaries"]["sockets"],
                document["boundaries"]["service_state"]["sockets"],
                document["cases"]["coherent_consumed"]["service_state_after"][
                    "sockets"
                ],
            )
            for sockets in snapshots:
                source = sockets[sensor_path]["metadata"]
                target = sockets[worker_path]["metadata"]
                target["device"], target["inode"] = (
                    source["device"],
                    source["inode"],
                )

        self._assert_mutation_rejected(mutate)

    def test_coherent_broker_dirty_shutdown_journal_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            journal = document["cases"]["coherent_consumed"]["broker_journal_after"]
            self._rebind_raw(
                journal["stdout"],
                b"[297785.900000] broker: segmentation fault; dirty shutdown\n",
            )

        self._assert_mutation_rejected(mutate)

    def test_failed_activation_dirty_shutdown_journal_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            journal = document["cases"]["expired_fail_stop"]["activation"]["journals"][
                "aragorn-runtime-lineage-capability-action-broker.service"
            ]
            self._rebind_raw(journal["stdout"], b"segmentation fault; dirty shutdown\n")

        self._assert_mutation_rejected(mutate)

    def test_failed_activation_unsuccessful_invocation_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            activation = document["cases"]["expired_fail_stop"]["activation"]
            service = "aragorn-runtime-lineage-capability-action-broker.service"
            invocation = activation["route"]["invocations"][service]["invocation_id"]
            for samples in (
                activation["route"]["monitor"],
                activation["route"]["invocations"][service]["samples"],
            ):
                for sample in samples:
                    if sample["units"][service]["InvocationID"] == invocation:
                        sample["units"][service]["Result"] = "failed"

        self._assert_mutation_rejected(mutate)

    def test_monitored_invocation_types_and_identity_are_exact(self) -> None:
        service = "aragorn-runtime-lineage-capability-action-broker.service"

        def samples(activation: dict) -> tuple[list, list]:
            return (
                activation["route"]["monitor"],
                activation["route"]["invocations"][service]["samples"],
            )

        def mutate_type(document: dict) -> None:
            activation = document["cases"]["expired_fail_stop"]["activation"]
            invocation = activation["route"]["invocations"][service]["invocation_id"]
            for retained in samples(activation):
                for sample in retained:
                    unit = sample["units"][service]
                    if unit["InvocationID"] == invocation:
                        unit["ExecMainStartTimestampMonotonic"] = int(
                            unit["ExecMainStartTimestampMonotonic"]
                        )

        def mutate_identity(document: dict) -> None:
            activation = document["cases"]["expired_fail_stop"]["activation"]
            retained = activation["route"]["invocations"][service]
            original = retained["invocation_id"]
            retained["invocation_id"] = "evil"
            for collection in samples(activation):
                for sample in collection:
                    if sample["units"][service]["InvocationID"] == original:
                        sample["units"][service]["InvocationID"] = "evil"
            activation["journals"][service]["argv"][-1] = "_SYSTEMD_INVOCATION_ID=evil"

        for name, mutate in (("type", mutate_type), ("identity", mutate_identity)):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_monitored_unit_invocations_must_be_distinct(self) -> None:
        def mutate(document: dict) -> None:
            activation = document["cases"]["expired_fail_stop"]["activation"]
            broker = "aragorn-runtime-lineage-capability-action-broker.service"
            sensor = "aragorn-runtime-lineage-capability-observation-publisher.service"
            source = activation["route"]["invocations"][broker]["invocation_id"]
            original = activation["route"]["invocations"][sensor]["invocation_id"]
            activation["route"]["invocations"][sensor]["invocation_id"] = source
            for samples in (
                activation["route"]["monitor"],
                activation["route"]["invocations"][sensor]["samples"],
            ):
                for sample in samples:
                    if sample["units"][sensor]["InvocationID"] == original:
                        sample["units"][sensor]["InvocationID"] = source
            activation["journals"][sensor]["argv"][-1] = (
                f"_SYSTEMD_INVOCATION_ID={source}"
            )

        self._assert_mutation_rejected(mutate)

    def test_monitor_observations_follow_command_and_service_start(self) -> None:
        def mutate(document: dict) -> None:
            activation = document["cases"]["expired_fail_stop"]["activation"]
            service = "aragorn-runtime-lineage-capability-action-broker.service"
            retained = activation["route"]["invocations"][service]["samples"]
            original = retained[0]["observed_monotonic_ns"]
            retained[0]["observed_monotonic_ns"] = 1
            for sample in activation["route"]["monitor"]:
                if sample["observed_monotonic_ns"] == original:
                    sample["observed_monotonic_ns"] = 1
                    break

        self._assert_mutation_rejected(mutate)

    def test_monitored_invocation_pid_cannot_drift(self) -> None:
        def mutate(document: dict) -> None:
            activation = document["cases"]["expired_fail_stop"]["activation"]
            service = "aragorn-runtime-lineage-capability-action-broker.service"
            retained = activation["route"]["invocations"][service]["samples"]
            original_time = retained[0]["observed_monotonic_ns"]
            retained[0]["units"][service]["MainPID"] = "99999"
            for sample in activation["route"]["monitor"]:
                if sample["observed_monotonic_ns"] == original_time:
                    sample["units"][service]["MainPID"] = "99999"
                    break

        self._assert_mutation_rejected(mutate)

    def test_process_start_ticks_bind_to_systemd_start(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["full_activation"]["stack"]["processes"][
                "aragorn-runtime-action-worker.service"
            ].__setitem__("start_time_ticks", "1")
        )

    def test_command_wall_and_monotonic_clocks_stay_bound(self) -> None:
        def mutate(document: dict) -> None:
            command = document["cases"]["full_activation"]["stack"]["service_state"][
                "units"
            ]["aragorn-runtime-action-worker.service"]["command"]
            command["started_at"] = "1970-01-01T00:00:00Z"
            command["completed_at"] = "1970-01-01T00:00:01Z"

        self._assert_mutation_rejected(mutate)

    def test_boolean_aliases_do_not_satisfy_retained_claims(self) -> None:
        def mutate(document: dict) -> None:
            document["decision"]["public_release_eligible"] = 0
            activation = document["cases"]["expired_fail_stop"]["activation"]
            activation["effects"]["before"]["target_exists"] = 0
            activation["effects"]["after"]["target_exists"] = 0

        self._assert_mutation_rejected(mutate)

    def test_invalid_clock_records_are_rejected(self) -> None:
        def mutate(document: dict) -> None:
            clock = document["cases"]["expired_fail_stop"]["expiry"]["started_clock"]
            clock["recorded_at"] = "1970-01-01T00:00:00Z"
            self._rebind_raw(clock["clocksource"], b"hostile_clock\n")

        self._assert_mutation_rejected(mutate)

    def test_retained_token_assignment_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            stdout = document["cases"]["coherent_consumed"]["broker_journal_after"][
                "stdout"
            ]
            self._rebind_raw(stdout, b"OPENCLAW_GATEWAY_TOKEN=" + b"a" * 64 + b"\n")

        self._assert_mutation_rejected(mutate)

    def test_driver_authority_injection_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["cases"]["coherent_consumed"][
                "driver"
            ].__setitem__("release_authority", True)
        )

    def test_source_ceiling_elevation_is_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["decision"].__setitem__(
                "public_release_eligible", True
            )
        )

    def _assert_mutation_rejected(self, mutate) -> None:
        document = copy.deepcopy(self.evidence)
        mutate(document)
        encoded = subject.canonical_json(document)
        digest = subject.canonical_digest(document)
        with (
            patch.object(subject, "_EVIDENCE_DIGEST", digest),
            patch.object(
                subject, "_EVIDENCE_RAW_DIGEST", subject._raw_digest(encoded + b"\n")
            ),
            patch.object(subject, "_EVIDENCE_BYTES", len(encoded) + 1),
            self.assertRaises(subject.AdmissionEvidenceError),
        ):
            subject.verify_runtime_action_worker_activation_expiry_systemd_evidence(
                document,
                self.parent,
                self.parent_parent,
                self.parent_receipt,
                expected_digest=digest,
            )

    @staticmethod
    def _rebind_document_snapshot(value: dict) -> None:
        raw = subject.canonical_json(value["document"])
        digest = subject._raw_digest(raw)
        value["digest"] = value["file"]["digest"] = digest
        value["file"]["base64"] = base64.b64encode(raw).decode("ascii")
        value["file"]["bytes"] = value["file"]["stat"]["size"] = len(raw)

    @staticmethod
    def _rebind_raw(value: dict, raw: bytes) -> None:
        value["base64"] = base64.b64encode(raw).decode("ascii")
        value["bytes"] = len(raw)
        value["digest"] = subject._raw_digest(raw)

    @classmethod
    def _rebind_service_property(
        cls, entry: dict, field: str, replacement: str
    ) -> None:
        original = entry["properties"][field]
        entry["properties"][field] = replacement
        stdout = entry["command"]["stdout"]
        raw = base64.b64decode(stdout["base64"], validate=True)
        old = f"{field}={original}\n".encode()
        new = f"{field}={replacement}\n".encode()
        if raw.count(old) != 1:
            raise AssertionError(f"unexpected service property encoding: {field}")
        cls._rebind_raw(stdout, raw.replace(old, new))

    @staticmethod
    def _implementation_digest() -> str:
        return (
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest()
        )


if __name__ == "__main__":
    unittest.main()
