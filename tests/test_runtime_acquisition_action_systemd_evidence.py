from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_acquisition_action_systemd_evidence as subject

_ROOT = Path(__file__).resolve().parents[1]


def _load(path: str) -> dict:
    return json.loads((_ROOT / path).read_bytes())


class _SplitViewMapping(dict):
    def __init__(self, first: dict, later: dict) -> None:
        super().__init__(first)
        self._first = first
        self._later = later
        self.items_calls = 0

    def items(self):
        self.items_calls += 1
        source = self._first if self.items_calls == 1 else self._later
        return source.items()


class RuntimeAcquisitionActionSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = _load(subject._RETAINED_PATH)
        cls.p37c_observation = _load(subject.p37c._RETAINED_PATH)
        cls.p37b_observation = _load(
            "benchmark/evidence/runtime-action-worker-openclaw-systemd-"
            "composition-p3-7b-2026-08-09.json"
        )
        cls.p36b_observation = _load(
            "benchmark/evidence/runtime-producer-lineage-openclaw-systemd-"
            "composition-p3-6b-2026-08-07.json"
        )
        cls.p37b_receipt = _load(
            "benchmark/receipts/phase3-runtime-action-worker-openclaw-systemd-"
            "qualification-v1-2026-08-09.json"
        )
        cls.p37c_receipt = _load(subject._P37C_RECEIPT_PATH)

    def test_exact_observation_qualifies_without_broad_authority(self) -> None:
        qualification = self._qualify()
        self.assertEqual(qualification["decision"], subject._QUALIFICATION_DECISION)
        self.assertEqual(qualification["decision"]["status"], "P3_8B_BOUNDED_PASS")
        self.assertEqual(
            qualification["cases"]["coherent_action"],
            {
                "driver_status": "COMPLETED",
                "effect_status": "CREATED",
                "grant_state": "CONSUMED",
                "status": "PASS",
                "verdict": "ALLOW",
            },
        )
        for field in (
            "aggregate_gate_eligible",
            "same_phase1_release_identity",
            "semantic_skill_causation_established",
            "run_01_eligible",
            "run_02_eligible",
            "phase3_exit_eligible",
            "edr_claim_eligible",
            "installer_authority_eligible",
            "public_release_eligible",
        ):
            self.assertIs(qualification["decision"][field], False)

    def test_qualification_is_deterministic_canonical_json(self) -> None:
        first = self._qualify()
        second = self._qualify()
        self.assertEqual(first, second)
        self.assertEqual(json.loads(subject.canonical_json(first)), first)

    def test_retained_qualification_is_canonical_and_exact(self) -> None:
        path = _ROOT / (
            "benchmark/receipts/phase3-runtime-acquisition-action-systemd-"
            "qualification-v1-2026-08-11.json"
        )
        retained = json.loads(path.read_bytes())
        self.assertEqual(retained, self._qualify())
        self.assertEqual(path.read_bytes(), subject.canonical_json(retained) + b"\n")

    def test_qualification_snapshots_caller_mapping_once(self) -> None:
        forged = copy.deepcopy(self.evidence)
        forged["acquisition"]["protected"]["transaction"]["tree_digest"] = (
            "sha256:" + "a" * 64
        )
        document = _SplitViewMapping(self.evidence, forged)
        self.assertIsInstance(document, Mapping)

        qualification = self._qualify(document=document)

        self.assertEqual(document.items_calls, 1)
        self.assertEqual(
            qualification["bindings"]["acquisition"]["tree_digest"],
            self.evidence["acquisition"]["protected"]["transaction"]["tree_digest"],
        )

    def test_source_and_implementation_pins_are_required(self) -> None:
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(expected_digest=None)
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(implementation_digest=None)

    def test_parent_qualification_repin_is_rejected(self) -> None:
        receipt = copy.deepcopy(self.p37c_receipt)
        receipt["decision"]["run_01_eligible"] = True
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(p37c_receipt=receipt)

    def test_container_cgroup_must_bind_the_outer_container(self) -> None:
        def mutate(document: dict) -> None:
            record = document["harness"]["container_cgroup"]
            self._rebind_bounded_file(
                record,
                b"0::/docker/" + b"a" * 64 + b"/init.scope\n",
                virtual=True,
            )

        self._assert_mutation_rejected(mutate)

    def test_gateway_preimage_adapter_and_postimage_are_independently_pinned(
        self,
    ) -> None:
        for name in ("preimage", "adapter", "installed"):
            with self.subTest(name=name):
                self._assert_mutation_rejected(
                    lambda document, name=name: document["artifacts"][
                        "gateway_adaptation"
                    ][name].__setitem__("digest", "sha256:" + "a" * 64)
                )

    def test_source_install_pair_cannot_be_coordinately_repinned(self) -> None:
        def mutate(document: dict) -> None:
            pair = document["artifacts"]["installed"][0]
            pair["source"]["digest"] = pair["installed"]["digest"] = (
                "sha256:" + "a" * 64
            )

        self._assert_mutation_rejected(mutate)

    def test_artifact_inode_alias_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            pair = document["artifacts"]["installed"][0]
            pair["installed"]["stat"]["device"] = pair["source"]["stat"]["device"]
            pair["installed"]["stat"]["inode"] = pair["source"]["stat"]["inode"]

        self._assert_mutation_rejected(mutate)

    def test_release_package_tree_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            release = document["artifacts"]["release_identity"]
            release["document"]["package"]["tree_digest"] = "sha256:" + "a" * 64
            self._rebind_document_snapshot(release)

        self._assert_mutation_rejected(mutate)

    def test_coordinator_state_result_split_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            state = document["acquisition"]["coordinator"]["state"]
            state["document"]["expected_active"]["context_id"] = "sha256:" + "a" * 64
            self._rebind_document_snapshot(state)

        self._assert_mutation_rejected(mutate)

    def test_cas_must_remain_unchanged_through_runtime(self) -> None:
        def mutate(document: dict) -> None:
            after = document["acquisition"]["quarantine"]["cas_after_runtime"]
            after["root"]["mtime_ns"] += 1

        self._assert_mutation_rejected(mutate)

    def test_cas_closure_custody_and_timing_are_exact(self) -> None:
        def change_blob(field: str, value: int):
            def mutate(document: dict) -> None:
                quarantine = document["acquisition"]["quarantine"]
                for name in ("cas_before_runtime", "cas_after_runtime"):
                    quarantine[name]["blobs"][0]["file"][field] = value

            return mutate

        def add_closure_entry(document: dict) -> None:
            quarantine = document["acquisition"]["quarantine"]
            for name in ("cas_before_runtime", "cas_after_runtime"):
                snapshot = quarantine[name]
                snapshot["closure"]["sha256:" + "a" * 64] = 1
                snapshot["closure_digest"] = subject.canonical_digest(
                    [
                        {"bytes": size, "digest": digest}
                        for digest, size in sorted(snapshot["closure"].items())
                    ]
                )

        mutations = (
            change_blob("device", 999),
            change_blob("ctime_ns", 1),
            add_closure_entry,
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self._assert_mutation_rejected(mutate)

    def test_source_skill_raw_must_equal_installed_skill(self) -> None:
        def mutate(document: dict) -> None:
            source = document["acquisition"]["quarantine"]["source_skill"]
            self._rebind_raw(source, b"X" * source["bytes"])

        self._assert_mutation_rejected(mutate)

    def test_action_must_reuse_the_exact_live_transaction(self) -> None:
        def mutate(document: dict) -> None:
            document["action"]["inputs"]["producer"]["transaction"]["context_id"] = (
                "sha256:" + "a" * 64
            )

        self._assert_mutation_rejected(mutate)

    def test_runtime_network_inventory_cannot_regain_eth0(self) -> None:
        def mutate(document: dict) -> None:
            network = document["acquisition"]["network"]
            network["after_runtime"]["interfaces"].insert(
                0, copy.deepcopy(network["before_acquisition"]["interfaces"][0])
            )

        self._assert_mutation_rejected(mutate)

    def test_disconnect_marker_must_precede_runtime_clocks(self) -> None:
        def mutate(document: dict) -> None:
            marker = document["acquisition"]["network"]["disconnected_marker"]
            marker["file"]["stat"]["ctime_ns"] = 9_999_999_999_999_999_999

        self._assert_mutation_rejected(mutate)

    def test_coherent_verdict_repin_is_rejected(self) -> None:
        def mutate(document: dict) -> None:
            receipt = document["action"]["cases"]["coherent_consumed"]["receipt"]
            receipt["document"]["broker_result"]["verdict"] = "BLOCK"
            self._rebind_document_snapshot(receipt)

        self._assert_mutation_rejected(mutate)

    def test_runtime_attribution_must_use_the_outer_container_cgroup(self) -> None:
        def mutate(document: dict) -> None:
            receipt = document["action"]["cases"]["coherent_consumed"]["receipt"]
            receipt["document"]["runtime_attribution"]["cgroup"] = (
                "/docker/" + "a" * 64 + "/system.slice/"
                "aragorn-runtime-action-worker.service"
            )
            self._rebind_document_snapshot(receipt)

        self._assert_mutation_rejected(mutate)

    def test_consumed_grant_cannot_be_reopened(self) -> None:
        def mutate(document: dict) -> None:
            state = document["action"]["cases"]["coherent_consumed"]["grant_state"]
            state["document"]["status"] = "AVAILABLE"
            self._rebind_document_snapshot(state)

        self._assert_mutation_rejected(mutate)

    def test_effect_target_bytes_cannot_be_rebound(self) -> None:
        def mutate(document: dict) -> None:
            target = document["action"]["cases"]["coherent_consumed"]["target"]
            self._rebind_bounded_file(target, b"X" * target["bytes"])

        self._assert_mutation_rejected(mutate)

    def test_source_claim_ceiling_cannot_be_elevated(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["decision"].__setitem__(
                "public_release_eligible", True
            )
        )

    def test_nested_runtime_cases_are_exactly_bound(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["action"]["cases"]["expired_fail_stop"]["expiry"][
                "process"
            ]["uids"].__setitem__(0, 0)
        )

    def test_coordinator_and_cas_semantics_are_required(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["acquisition"]["coordinator"][
                "path_unit_start"
            ].__setitem__("exit_code", 1)
        )

        def omit_skill(document: dict) -> None:
            quarantine = document["acquisition"]["quarantine"]
            skill_digest = quarantine["source_skill"]["digest"]
            for name in ("cas_before_runtime", "cas_after_runtime"):
                snapshot = quarantine[name]
                snapshot["closure"].pop(skill_digest)
                snapshot["blobs"] = [
                    item for item in snapshot["blobs"] if item["digest"] != skill_digest
                ]
                snapshot["closure_digest"] = subject.canonical_digest(
                    [
                        {"bytes": size, "digest": digest}
                        for digest, size in sorted(snapshot["closure"].items())
                    ]
                )

        self._assert_mutation_rejected(omit_skill)

    def test_protected_custody_receipt_and_journal_are_required(self) -> None:
        mutations = (
            lambda document: document["acquisition"]["protected"]["record"]["file"][
                "stat"
            ].__setitem__("mode", "0666"),
            lambda document: document["acquisition"]["protected"][
                "active_link"
            ].__setitem__("path", "/tmp/forged-active"),
            lambda document: document["acquisition"]["protected"][
                "service_receipt"
            ].__setitem__("slice_status", "FAIL"),
            lambda document: document["acquisition"]["protected"][
                "service_journal_identity"
            ].__setitem__("invocation_id", "a" * 32),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self._assert_mutation_rejected(mutate)

    def test_network_cutover_records_are_semantically_bound(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["acquisition"]["network"]["after_disconnect"][
                "interfaces"
            ][0].__setitem__("ifindex", "1")
        )

        def public_resolver(document: dict) -> None:
            record = document["acquisition"]["network"]["after_runtime"]["resolv_conf"]
            self._rebind_bounded_file(record, b"nameserver 8.8.8.8\n")

        self._assert_mutation_rejected(public_resolver)

        def mismatched_endpoint(document: dict) -> None:
            harness = document["harness"]["document"]
            raw = base64.b64decode(harness["capture_network_inspect"]["base64"])
            inspected = json.loads(raw)
            inspected[0]["Containers"][harness["container_id"]]["EndpointID"] = "a" * 64
            self._rebind_raw(
                harness["capture_network_inspect"],
                subject.canonical_json(inspected),
            )

        self._assert_mutation_rejected(mismatched_endpoint)

    def test_socket_ownership_and_exact_boolean_types_are_required(self) -> None:
        def wrong_socket_owner(document: dict) -> None:
            socket = document["action"]["cases"]["full_activation"]["stack"]["sockets"][
                "/run/aragorn-runtime-action-worker/worker.sock"
            ]
            socket["metadata"]["uid"] = 0

        self._assert_mutation_rejected(wrong_socket_owner)
        self._assert_mutation_rejected(
            lambda document: document["harness"]["document"]["host_config"].__setitem__(
                "readonly_rootfs", 0
            )
        )

    def test_boolean_file_owner_and_float_are_rejected(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["artifacts"]["collector"]["probe"][
                "stat"
            ].__setitem__("uid", False)
        )
        document = copy.deepcopy(self.evidence)
        document["acquisition"]["coordinator"]["command"]["elapsed_ns"] = 1.0
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(document=document, expected_digest=subject._EVIDENCE_DIGEST)

    def _qualify(self, **overrides: object) -> dict:
        arguments = self._arguments()
        arguments["implementation_digest"] = self._implementation_digest()
        arguments.update(overrides)
        return subject.runtime_acquisition_action_systemd_qualification(**arguments)

    def _verify(self, **overrides: object) -> None:
        arguments = self._arguments()
        arguments.update(overrides)
        subject.verify_runtime_acquisition_action_systemd_evidence(**arguments)

    def _arguments(self) -> dict:
        return {
            "document": self.evidence,
            "p37c_observation": self.p37c_observation,
            "p37b_observation": self.p37b_observation,
            "p36b_observation": self.p36b_observation,
            "p37b_receipt": self.p37b_receipt,
            "p37c_receipt": self.p37c_receipt,
            "expected_digest": subject._EVIDENCE_DIGEST,
        }

    def _assert_mutation_rejected(self, mutate) -> None:
        document = copy.deepcopy(self.evidence)
        mutate(document)
        encoded = subject.canonical_json(document)
        with (
            patch.object(
                subject, "_EVIDENCE_DIGEST", subject.canonical_digest(document)
            ),
            patch.object(
                subject, "_EVIDENCE_RAW_DIGEST", subject._raw_digest(encoded + b"\n")
            ),
            patch.object(subject, "_EVIDENCE_BYTES", len(encoded) + 1),
            patch.object(
                subject, "_ACTION_DIGEST", subject.canonical_digest(document["action"])
            ),
            patch.object(
                subject,
                "_HARNESS_DIGEST",
                subject.canonical_digest(document["harness"]["document"]),
            ),
            patch.object(
                subject,
                "_IMAGE_LINEAGE_DIGEST",
                subject.canonical_digest(
                    document["harness"]["document"]["image_lineage"]
                ),
            ),
            patch.object(
                subject,
                "_COLLECTOR_DIGEST",
                subject.canonical_digest(document["artifacts"]["collector"]),
            ),
            patch.object(
                subject,
                "_ADAPTATION_DIGEST",
                subject.canonical_digest(document["artifacts"]["gateway_adaptation"]),
            ),
            self.assertRaises(subject.AdmissionEvidenceError),
        ):
            self._verify(
                document=document, expected_digest=subject.canonical_digest(document)
            )

    @staticmethod
    def _implementation_digest() -> str:
        return (
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest()
        )

    @staticmethod
    def _rebind_raw(value: dict, raw: bytes) -> None:
        value["base64"] = base64.b64encode(raw).decode("ascii")
        value["bytes"] = len(raw)
        value["digest"] = subject._raw_digest(raw)

    @classmethod
    def _rebind_bounded_file(
        cls, value: dict, raw: bytes, *, virtual: bool = False
    ) -> None:
        cls._rebind_raw(value, raw)
        value["stat"]["size"] = 0 if virtual else len(raw)

    @classmethod
    def _rebind_document_snapshot(cls, value: dict) -> None:
        raw = subject.canonical_json(value["document"])
        value["digest"] = value["file"]["digest"] = subject._raw_digest(raw)
        value["file"]["base64"] = base64.b64encode(raw).decode("ascii")
        value["file"]["bytes"] = value["file"]["stat"]["size"] = len(raw)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
