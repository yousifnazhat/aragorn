from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_acquisition_action_nested_systemd_evidence as subject

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
        return (self._first if self.items_calls == 1 else self._later).items()


class RuntimeAcquisitionActionNestedSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = _load(subject._RETAINED_PATH)
        cls.p38c_observation = _load(subject.p38c._RETAINED_PATH)
        cls.p38b_observation = _load(subject.p38c.p38b._RETAINED_PATH)
        cls.p37c_observation = _load(subject.p38c.p38b.p37c._RETAINED_PATH)
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
        cls.p37c_receipt = _load(subject.p38c.p38b._P37C_RECEIPT_PATH)
        cls.p38b_receipt = _load(subject.p38c._P38B_RECEIPT_PATH)
        cls.p38c_receipt = _load(subject._P38C_RECEIPT_PATH)

    def test_exact_observation_qualifies_without_broad_authority(self) -> None:
        qualification = self._qualify()
        self.assertEqual(qualification["decision"], subject._QUALIFICATION_DECISION)
        self.assertEqual(
            qualification["decision"]["status"],
            "P3_8D_BOUNDED_DEPTH_ONE_TWO_FILE_PASS",
        )
        self.assertEqual(
            qualification["bindings"]["depth_one_two_file_tree"],
            {
                "directories": list(subject._DIRECTORIES),
                "entries": subject._TREE_ENTRIES,
                "projected_tree_digest": subject._TREE_DIGEST,
                "protected_tree_digest": subject._TREE_DIGEST,
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
        self.assertEqual(first, self._qualify())
        self.assertEqual(json.loads(subject.canonical_json(first)), first)

    def test_qualification_snapshots_all_ten_caller_mappings_once(self) -> None:
        arguments = self._arguments()
        split = {
            name: _SplitViewMapping(value, {})
            for name, value in arguments.items()
            if name != "expected_digest"
        }
        arguments.update(split)
        arguments["implementation_digest"] = self._implementation_digest()

        qualification = subject.runtime_acquisition_action_nested_systemd_qualification(
            **arguments
        )

        self.assertEqual(
            qualification["decision"]["status"],
            "P3_8D_BOUNDED_DEPTH_ONE_TWO_FILE_PASS",
        )
        self.assertEqual(len(split), 10)
        self.assertTrue(all(value.items_calls == 1 for value in split.values()))

    def test_source_implementation_and_parent_pins_are_required(self) -> None:
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(expected_digest=None)
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(implementation_digest=None)
        receipt = copy.deepcopy(self.p38c_receipt)
        receipt["decision"]["parent_p3_8b_unchanged"] = False
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(p38c_receipt=receipt)

    def test_record_closure_and_fixed_envelopes_are_required(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["artifacts"]["collector"]["probe"][
                "stat"
            ].__setitem__("uid", False)
        )
        document = copy.deepcopy(self.evidence)
        document["acquisition"]["coordinator"]["command"]["elapsed_ns"] = 1.0
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(document=document, expected_digest=subject._EVIDENCE_DIGEST)

    def test_hostile_nested_source_custody_and_action_mutations_fail_closed(
        self,
    ) -> None:
        def directory_mode(document: dict) -> None:
            trees = self._all_trees(document)
            for tree in trees:
                tree["directories"]["references"]["mode"] = "0777"

        def directory_aliases_root(document: dict) -> None:
            for tree in self._all_trees(document):
                directory = tree["directories"]["references"]
                directory["device"] = tree["root"]["device"]
                directory["inode"] = tree["root"]["inode"]

        def nested_file_path(document: dict) -> None:
            document["acquisition"]["protected"]["tree"]["files"][
                "references/voice-profile-schema.md"
            ]["path"] = "/tmp/voice-profile-schema.md"

        def source_file_substitution(document: dict) -> None:
            source = document["acquisition"]["quarantine"]["source_files"]
            source["references/voice-profile-schema.md"] = copy.deepcopy(
                source["SKILL.md"]
            )

        def cas_blob_alias(document: dict) -> None:
            for name in ("cas_before_runtime", "cas_after_runtime"):
                blobs = document["acquisition"]["quarantine"][name]["blobs"]
                blobs[1]["file"]["device"] = blobs[0]["file"]["device"]
                blobs[1]["file"]["inode"] = blobs[0]["file"]["inode"]

        def projection_aliases_protected(document: dict) -> None:
            protected = document["acquisition"]["protected"]["tree"]["files"][
                "SKILL.md"
            ]["stat"]
            projected = document["action"]["inputs"]["producer"]["projected_tree"]
            projected["files"]["SKILL.md"]["stat"].update(
                {"device": protected["device"], "inode": protected["inode"]}
            )

        def action_drops_directory(document: dict) -> None:
            document["action"]["inputs"]["producer"]["directories"] = []

        def binding_drops_directory(document: dict) -> None:
            document["bindings"]["directories"] = []

        def p38c_overlay_path(document: dict) -> None:
            document["artifacts"]["p3_8c_overlay"]["installed"][2]["source"]["path"] = (
                "/src/forged-lineage.py"
            )

        def p38d_overlay_split(document: dict) -> None:
            document["artifacts"]["p3_8d_overlay"]["installed"][0]["installed"][
                "digest"
            ] = "sha256:" + "a" * 64

        def harness_parent(document: dict) -> None:
            document["harness"]["document"]["parent_image_id"] = "sha256:" + "a" * 64

        def coordinator_source(document: dict) -> None:
            document["acquisition"]["coordinator"]["command"]["argv"][-1] = (
                "skills/forged"
            )

        def artifact_graph_incomplete(document: dict) -> None:
            closure = document["acquisition"]["protected"]["service_receipt"]["source"][
                "closure"
            ]
            closure["status"] = "incomplete"

        def coherent_case(document: dict) -> None:
            document["action"]["cases"]["coherent_consumed"]["status"] = "FAILED"

        def regain_eth0(document: dict) -> None:
            network = document["acquisition"]["network"]
            network["after_runtime"]["interfaces"].insert(
                0, copy.deepcopy(network["before_acquisition"]["interfaces"][0])
            )

        for name, mutate in (
            ("directory_mode", directory_mode),
            ("directory_aliases_root", directory_aliases_root),
            ("nested_file_path", nested_file_path),
            ("source_file_substitution", source_file_substitution),
            ("cas_blob_alias", cas_blob_alias),
            ("projection_aliases_protected", projection_aliases_protected),
            ("action_drops_directory", action_drops_directory),
            ("binding_drops_directory", binding_drops_directory),
            ("p38c_overlay_path", p38c_overlay_path),
            ("p38d_overlay_split", p38d_overlay_split),
            ("harness_parent", harness_parent),
            ("coordinator_source", coordinator_source),
            ("artifact_graph_incomplete", artifact_graph_incomplete),
            ("coherent_case", coherent_case),
            ("regain_eth0", regain_eth0),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_source_and_qualification_claim_ceilings_cannot_be_elevated(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["decision"].__setitem__(
                "public_release_eligible", True
            )
        )
        qualification = self._qualify()
        for field in (
            "aggregate_gate_eligible",
            "edr_claim_eligible",
            "installer_authority_eligible",
            "phase3_exit_eligible",
            "public_release_eligible",
            "run_01_eligible",
            "run_02_eligible",
            "same_phase1_release_identity",
            "semantic_skill_causation_established",
        ):
            self.assertIs(qualification["decision"][field], False)

    def test_coordinated_repins_cannot_escape_exact_shapes_devices_or_time(
        self,
    ) -> None:
        def decision_boolean_alias(document: dict) -> None:
            self._service_receipt(document)["decision"]["installer_work_eligible"] = 0

        def decision_verdict(document: dict) -> None:
            self._service_receipt(document)["decision"]["verdict"] = "BLOCK"

        def service_top_extra(document: dict) -> None:
            self._service_receipt(document)["unexpected"] = True

        def source_extra(document: dict) -> None:
            self._service_receipt(document)["source"]["unexpected"] = True

        def recursive_extra(document: dict) -> None:
            extra = {"unexpected": "sha256:" + "a" * 64}
            self._service_receipt(document)["source"]["recursive"].update(extra)
            state = document["acquisition"]["coordinator"]["state"]["document"]
            state["expected_active"]["recursive"].update(extra)

        def active_link_device(document: dict) -> None:
            document["acquisition"]["protected"]["active_link"]["device"] += 1

        def claim_device(document: dict) -> None:
            document["acquisition"]["protected"]["claim"]["file"]["stat"]["device"] += 1

        def active_record_device(document: dict) -> None:
            acquisition_record = document["acquisition"]["protected"]["record"]
            action_record = document["action"]["inputs"]["producer"]["record"]
            acquisition_record["file"]["stat"]["device"] += 1
            action_record["file"]["stat"]["device"] += 1

        def version_tree_device(document: dict) -> None:
            protected = document["acquisition"]["protected"]
            forged = protected["version"]["device"] + 1
            protected["version"]["device"] = forged
            protected["skill"]["stat"]["device"] = forged
            document["action"]["inputs"]["producer"]["skill"]["stat"]["device"] = forged
            for tree in self._protected_trees(document):
                tree["root"]["device"] = forged
                for directory in tree["directories"].values():
                    directory["device"] = forged
                for record in tree["files"].values():
                    record["stat"]["device"] = forged

        def directory_future(document: dict) -> None:
            for tree in self._protected_trees(document):
                tree["directories"]["references"]["ctime_ns"] = (
                    tree["root"]["ctime_ns"] + 1
                )

        def cas_blob_future(document: dict) -> None:
            quarantine = document["acquisition"]["quarantine"]
            for name in ("cas_before_runtime", "cas_after_runtime"):
                snapshot = quarantine[name]
                blob = snapshot["blobs"][0]["file"]
                blob["mtime_ns"] = snapshot["root"]["ctime_ns"] + 1
                blob["ctime_ns"] = snapshot["root"]["ctime_ns"] + 2

        def credential_future(document: dict) -> None:
            credential = self._service_receipt(document)["request_authority"][
                "credential"
            ]
            completed = subject._iso_ns(
                document["acquisition"]["timing"]["completed_at"]
            )
            credential["mtime_ns"] = credential["ctime_ns"] = completed + 1

        def action_state_future(document: dict) -> None:
            recorded = subject._iso_ns(document["action"]["recorded_at"])
            state = document["action"]["cases"]["coherent_consumed"]["broker_state"][
                "file"
            ]["stat"]
            state["mtime_ns"] = state["ctime_ns"] = recorded + 1

        def journal_since_epoch(document: dict) -> None:
            journal = document["acquisition"]["journals"][
                "aragorn-protected-install-coordinator.service"
            ]
            journal["command"]["argv"][7] = "@0.000000"

        def cas_root_device_repin(document: dict) -> None:
            quarantine = document["acquisition"]["quarantine"]
            for name in ("cas_before_runtime", "cas_after_runtime"):
                snapshot = quarantine[name]
                snapshot["root"]["device"] = 999_999
                for blob in snapshot["blobs"]:
                    blob["file"]["device"] = 999_999

        def service_context_operation(document: dict) -> None:
            self._service_receipt(document)["context"]["operation"] = "delete"

        def service_context_extra(document: dict) -> None:
            self._service_receipt(document)["context"][
                "installer_authority_eligible"
            ] = True

        def service_claim_now_negative(document: dict) -> None:
            self._service_receipt(document)["claim"]["fresh"]["claim_now_unix"] = -1

        def service_claim_owner_boolean(document: dict) -> None:
            claim = self._service_receipt(document)["claim"]
            claim["initial_revocation_snapshot"]["owner_uid"] = False
            claim["fresh"]["revocation_snapshot"]["owner_uid"] = False

        def fresh_grant_extra(document: dict) -> None:
            document["action"]["inputs"]["fresh_grant"][
                "installer_authority_eligible"
            ] = True

        def active_record_authority(document: dict) -> None:
            document["acquisition"]["protected"]["record"]["document"]["authority"] = (
                "INSTALLER_AUTHORITY"
            )

        def active_record_document_extra(document: dict) -> None:
            document["acquisition"]["protected"]["record"]["document"]["unexpected"] = (
                True
            )

        def active_record_wrapper_extra(document: dict) -> None:
            document["acquisition"]["protected"]["record"]["unexpected"] = True

        def install_claim_wrapper_extra(document: dict) -> None:
            document["acquisition"]["protected"]["claim"]["unexpected"] = True

        def short_grant_wrapper_extra(document: dict) -> None:
            document["action"]["inputs"]["short_grant"]["unexpected"] = True

        def coordinator_result_extra_authority(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"][
                "installer_authority_eligible"
            ] = True

        def coordinator_result_operation(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"]["operation"] = "delete"

        def coordinator_result_quarantine_authority(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"]["quarantine_authority"] = (
                "ADMISSION_AUTHORITY"
            )

        def coordinator_state_extra_authority(document: dict) -> None:
            document["acquisition"]["coordinator"]["state"]["document"][
                "installer_authority_eligible"
            ] = True

        def expected_active_extra_authority(document: dict) -> None:
            document["acquisition"]["coordinator"]["state"]["document"][
                "expected_active"
            ]["installer_authority_eligible"] = True

        def quarantine_receipt_extra_authority(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"][
                "installer_authority_eligible"
            ] = True

        def quarantine_receipt_authority(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"]["authority"] = (
                "ADMISSION_AUTHORITY"
            )

        def quarantine_receipt_schema(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"]["schema"] = (
                "aragorn/github-quarantine-receipt/v2"
            )

        def quarantine_source_assurance(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"]["source_assurance"] = (
                "UNVERIFIED"
            )

        def quarantine_request_digest(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"]["request_digest"] = (
                "sha256:" + "0" * 64
            )

        def service_request_digest_coordinated(document: dict) -> None:
            forged = "sha256:" + "0" * 64
            acquisition = document["acquisition"]
            acquisition["coordinator"]["result"]["service_request_digest"] = forged
            acquisition["coordinator"]["state"]["document"][
                "service_request_digest"
            ] = forged
            self._service_receipt(document)["request_authority"]["request_digest"] = (
                forged
            )

        def coordinator_result_extra_named_authority(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"]["authority"] = (
                "INSTALLER_AUTHORITY"
            )

        def coordinator_result_operation_boolean(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"]["operation"] = False

        def coordinator_result_quarantine_boolean(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"]["quarantine_authority"] = (
                False
            )

        def service_request_digest_split(document: dict) -> None:
            document["acquisition"]["coordinator"]["result"][
                "service_request_digest"
            ] = "sha256:" + "0" * 64

        def quarantine_gateway_extra_authority(document: dict) -> None:
            receipt = document["acquisition"]["quarantine"]["receipt"]
            receipt["gateway"]["installer_authority_eligible"] = True
            self._service_receipt(document)["source"]["gateway"][
                "installer_authority_eligible"
            ] = True

        def quarantine_containment_unconfined(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"]["containment_profile"] = (
                "unconfined"
            )
            self._service_receipt(document)["source"]["containment_profile"] = (
                "unconfined"
            )

        def gateway_profile_digest_coordinated(document: dict) -> None:
            forged = "sha256:" + "0" * 64
            acquisition = document["acquisition"]
            acquisition["coordinator"]["result"]["gateway_profile_digest"] = forged
            acquisition["coordinator"]["state"]["document"]["expected_active"][
                "gateway_profile_digest"
            ] = forged
            acquisition["quarantine"]["receipt"]["gateway_profile_digest"] = forged
            self._service_receipt(document)["source"]["gateway_profile_digest"] = forged

        def gateway_python_digest_coordinated(document: dict) -> None:
            forged = "sha256:" + "0" * 64
            document["acquisition"]["quarantine"]["receipt"]["gateway"][
                "python_executable_digest"
            ] = forged
            self._service_receipt(document)["source"]["gateway"][
                "python_executable_digest"
            ] = forged

        def quarantine_handoff_digest(document: dict) -> None:
            document["acquisition"]["quarantine"]["receipt"][
                "handoff_manifest_digest"
            ] = "sha256:" + "0" * 64

        for name, mutate in (
            ("decision_boolean_alias", decision_boolean_alias),
            ("decision_verdict", decision_verdict),
            ("service_top_extra", service_top_extra),
            ("source_extra", source_extra),
            ("recursive_extra", recursive_extra),
            ("active_link_device", active_link_device),
            ("claim_device", claim_device),
            ("active_record_device", active_record_device),
            ("version_tree_device", version_tree_device),
            ("directory_future", directory_future),
            ("cas_blob_future", cas_blob_future),
            ("credential_future", credential_future),
            ("action_state_future", action_state_future),
            ("journal_since_epoch", journal_since_epoch),
            ("cas_root_device_repin", cas_root_device_repin),
            ("service_context_operation", service_context_operation),
            ("service_context_extra", service_context_extra),
            ("service_claim_now_negative", service_claim_now_negative),
            ("service_claim_owner_boolean", service_claim_owner_boolean),
            ("fresh_grant_extra", fresh_grant_extra),
            ("active_record_authority", active_record_authority),
            ("active_record_document_extra", active_record_document_extra),
            ("active_record_wrapper_extra", active_record_wrapper_extra),
            ("install_claim_wrapper_extra", install_claim_wrapper_extra),
            ("short_grant_wrapper_extra", short_grant_wrapper_extra),
            ("coordinator_result_extra_authority", coordinator_result_extra_authority),
            ("coordinator_result_operation", coordinator_result_operation),
            (
                "coordinator_result_quarantine_authority",
                coordinator_result_quarantine_authority,
            ),
            ("coordinator_state_extra_authority", coordinator_state_extra_authority),
            ("expected_active_extra_authority", expected_active_extra_authority),
            (
                "quarantine_receipt_extra_authority",
                quarantine_receipt_extra_authority,
            ),
            ("quarantine_receipt_authority", quarantine_receipt_authority),
            ("quarantine_receipt_schema", quarantine_receipt_schema),
            ("quarantine_source_assurance", quarantine_source_assurance),
            ("quarantine_request_digest", quarantine_request_digest),
            ("service_request_digest_coordinated", service_request_digest_coordinated),
            (
                "coordinator_result_extra_named_authority",
                coordinator_result_extra_named_authority,
            ),
            (
                "coordinator_result_operation_boolean",
                coordinator_result_operation_boolean,
            ),
            (
                "coordinator_result_quarantine_boolean",
                coordinator_result_quarantine_boolean,
            ),
            ("service_request_digest_split", service_request_digest_split),
            (
                "quarantine_gateway_extra_authority",
                quarantine_gateway_extra_authority,
            ),
            ("quarantine_containment_unconfined", quarantine_containment_unconfined),
            (
                "gateway_profile_digest_coordinated",
                gateway_profile_digest_coordinated,
            ),
            (
                "gateway_python_digest_coordinated",
                gateway_python_digest_coordinated,
            ),
            ("quarantine_handoff_digest", quarantine_handoff_digest),
        ):
            with self.subTest(name=name):
                self._assert_coordinated_mutation_rejected(mutate)

    def _qualify(self, **overrides: object) -> dict:
        arguments = self._arguments()
        arguments["implementation_digest"] = self._implementation_digest()
        arguments.update(overrides)
        return subject.runtime_acquisition_action_nested_systemd_qualification(
            **arguments
        )

    def _verify(self, **overrides: object) -> None:
        arguments = self._arguments()
        arguments.update(overrides)
        subject.verify_runtime_acquisition_action_nested_systemd_evidence(**arguments)

    def _arguments(self) -> dict:
        return {
            "document": self.evidence,
            "p38c_observation": self.p38c_observation,
            "p38b_observation": self.p38b_observation,
            "p37c_observation": self.p37c_observation,
            "p37b_observation": self.p37b_observation,
            "p36b_observation": self.p36b_observation,
            "p37b_receipt": self.p37b_receipt,
            "p37c_receipt": self.p37c_receipt,
            "p38b_receipt": self.p38b_receipt,
            "p38c_receipt": self.p38c_receipt,
            "expected_digest": subject._EVIDENCE_DIGEST,
        }

    def _assert_mutation_rejected(self, mutate) -> None:
        document = copy.deepcopy(self.evidence)
        mutate(document)
        encoded = subject.canonical_json(document)
        section_digests = {
            name: subject.canonical_digest(document[name])
            for name in subject._SECTION_DIGESTS
        }
        case_digests = {
            name: subject.canonical_digest(case)
            for name, case in document["action"]["cases"].items()
        }
        with (
            patch.object(
                subject, "_EVIDENCE_DIGEST", subject.canonical_digest(document)
            ),
            patch.object(
                subject, "_EVIDENCE_RAW_DIGEST", subject._raw_digest(encoded + b"\n")
            ),
            patch.object(subject, "_EVIDENCE_BYTES", len(encoded) + 1),
            patch.object(subject, "_SECTION_DIGESTS", section_digests),
            patch.object(
                subject,
                "_ACQUISITION_ENVELOPE_DIGEST",
                section_digests["acquisition"],
            ),
            patch.object(subject, "_ACTION_ENVELOPE_DIGEST", section_digests["action"]),
            patch.object(
                subject,
                "_SERVICE_RECEIPT_DIGEST",
                subject.canonical_digest(
                    document["acquisition"]["protected"]["service_receipt"]
                ),
            ),
            patch.object(subject, "_ACTION_CASE_DIGESTS", case_digests),
            self.assertRaises(subject.AdmissionEvidenceError),
        ):
            self._verify(
                document=document,
                expected_digest=subject.canonical_digest(document),
            )

    def _assert_coordinated_mutation_rejected(self, mutate) -> None:
        document = copy.deepcopy(self.evidence)
        mutate(document)
        self._repin_quarantine_receipt_chain(document)
        self._repin_coordinator_result(document)
        self._repin_active_record(document)
        self._repin_state_snapshot(document)
        self._repin_service_journal(document)
        encoded = subject.canonical_json(document)
        section_digests = {
            name: subject.canonical_digest(document[name])
            for name in subject._SECTION_DIGESTS
        }
        case_digests = {
            name: subject.canonical_digest(case)
            for name, case in document["action"]["cases"].items()
        }
        state = document["acquisition"]["coordinator"]["state"]["document"]
        result = document["acquisition"]["coordinator"]["result"]
        quarantine_receipt = document["acquisition"]["quarantine"]["receipt"]
        receipt = self._service_receipt(document)
        with (
            patch.object(
                subject, "_EVIDENCE_DIGEST", subject.canonical_digest(document)
            ),
            patch.object(
                subject, "_EVIDENCE_RAW_DIGEST", subject._raw_digest(encoded + b"\n")
            ),
            patch.object(subject, "_EVIDENCE_BYTES", len(encoded) + 1),
            patch.object(subject, "_SECTION_DIGESTS", section_digests),
            patch.object(
                subject,
                "_ACQUISITION_ENVELOPE_DIGEST",
                section_digests["acquisition"],
            ),
            patch.object(subject, "_ACTION_ENVELOPE_DIGEST", section_digests["action"]),
            patch.object(subject, "_ACTION_CASE_DIGESTS", case_digests),
            patch.object(
                subject, "_COORDINATOR_STATE_DIGEST", subject.canonical_digest(state)
            ),
            patch.object(
                subject,
                "_COORDINATOR_RESULT_DIGEST",
                subject.canonical_digest(result),
            ),
            patch.object(
                subject,
                "_QUARANTINE_RECEIPT_DIGEST",
                subject.canonical_digest(quarantine_receipt),
            ),
            patch.object(
                subject, "_SERVICE_RECEIPT_DIGEST", subject.canonical_digest(receipt)
            ),
            self.assertRaises(subject.AdmissionEvidenceError),
        ):
            self._verify(
                document=document,
                expected_digest=subject.canonical_digest(document),
            )

    @staticmethod
    def _service_receipt(document: dict) -> dict:
        return document["acquisition"]["protected"]["service_receipt"]

    @staticmethod
    def _repin_state_snapshot(document: dict) -> None:
        snapshot = document["acquisition"]["coordinator"]["state"]
        raw = subject.canonical_json(snapshot["document"])
        digest = subject._raw_digest(raw)
        snapshot["digest"] = digest
        snapshot["file"].update(
            {
                "base64": base64.b64encode(raw).decode("ascii"),
                "bytes": len(raw),
                "digest": digest,
            }
        )
        snapshot["file"]["stat"]["size"] = len(raw)

    @staticmethod
    def _repin_active_record(document: dict) -> None:
        record = document["acquisition"]["protected"]["record"]
        raw = subject.canonical_json(record["document"])
        digest = subject.canonical_digest(record["document"])
        record["digest"] = record["raw_digest"] = digest
        record["file"]["digest"] = digest
        record["file"]["bytes"] = len(raw)
        record["file"]["stat"]["size"] = len(raw)
        document["action"]["inputs"]["producer"]["record"] = copy.deepcopy(record)

    @classmethod
    def _repin_quarantine_receipt_chain(cls, document: dict) -> None:
        acquisition = document["acquisition"]
        receipt = acquisition["quarantine"]["receipt"]
        digest = subject.canonical_digest(receipt)
        acquisition["quarantine"]["receipt_digest"] = digest
        acquisition["coordinator"]["result"]["quarantine_receipt_digest"] = digest
        acquisition["coordinator"]["state"]["document"]["expected_active"][
            "quarantine_receipt_digest"
        ] = digest
        cls._service_receipt(document)["source"]["quarantine_receipt_digest"] = digest

    @staticmethod
    def _repin_coordinator_result(document: dict) -> None:
        coordinator = document["acquisition"]["coordinator"]
        raw = subject.canonical_json(coordinator["result"]) + b"\n"
        coordinator["command"]["stdout"].update(
            {
                "base64": base64.b64encode(raw).decode("ascii"),
                "bytes": len(raw),
                "digest": subject._raw_digest(raw),
            }
        )

    @classmethod
    def _repin_service_journal(cls, document: dict) -> None:
        protected = document["acquisition"]["protected"]
        receipt = protected["service_receipt"]
        raw = subject.canonical_json(receipt)
        identity = protected["service_journal_identity"]
        identity["message_bytes"] = len(raw)
        identity["message_digest"] = subject.canonical_digest(receipt)
        journal = document["acquisition"]["journals"][
            "aragorn-protected-install.service"
        ]
        stdout = journal["command"]["stdout"]
        entries = [
            json.loads(line) for line in base64.b64decode(stdout["base64"]).splitlines()
        ]
        matching = 0
        for entry in entries:
            if entry.get("_SYSTEMD_INVOCATION_ID") == identity["invocation_id"]:
                entry["MESSAGE"] = raw.decode("ascii")
                matching += 1
        if matching != 1:
            raise AssertionError("expected one service journal receipt")
        journal_raw = b"".join(
            json.dumps(
                entry,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
            for entry in entries
        )
        stdout.update(
            {
                "base64": base64.b64encode(journal_raw).decode("ascii"),
                "bytes": len(journal_raw),
                "digest": subject._raw_digest(journal_raw),
            }
        )

    @staticmethod
    def _all_trees(document: dict) -> list[dict]:
        return [
            document["acquisition"]["protected"]["tree"],
            document["action"]["inputs"]["producer"]["protected_tree"],
            document["action"]["inputs"]["producer"]["projected_tree"],
            document["bindings"]["protected_tree"]["before_action"],
            document["bindings"]["protected_tree"]["after_action"],
            document["bindings"]["projected_tree"]["before_action"],
            document["bindings"]["projected_tree"]["after_action"],
        ]

    @staticmethod
    def _protected_trees(document: dict) -> list[dict]:
        return [
            document["acquisition"]["protected"]["tree"],
            document["action"]["inputs"]["producer"]["protected_tree"],
            document["bindings"]["protected_tree"]["before_action"],
            document["bindings"]["protected_tree"]["after_action"],
        ]

    @staticmethod
    def _implementation_digest() -> str:
        return (
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest()
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
