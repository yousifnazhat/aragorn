from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from collections.abc import Mapping
from pathlib import Path
from unittest.mock import patch

from aragorn import runtime_acquisition_action_multifile_systemd_evidence as subject

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


class RuntimeAcquisitionActionMultifileSystemdEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = _load(subject._RETAINED_PATH)
        cls.p38b_observation = _load(subject.p38b._RETAINED_PATH)
        cls.p37c_observation = _load(subject.p38b.p37c._RETAINED_PATH)
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
        cls.p37c_receipt = _load(subject.p38b._P37C_RECEIPT_PATH)
        cls.p38b_receipt = _load(subject._P38B_RECEIPT_PATH)

    def test_exact_observation_qualifies_without_broad_authority(self) -> None:
        qualification = self._qualify()
        self.assertEqual(qualification["decision"], subject._QUALIFICATION_DECISION)
        self.assertEqual(
            qualification["decision"]["status"],
            "P3_8C_BOUNDED_TWO_FILE_PASS",
        )
        self.assertEqual(
            qualification["bindings"]["two_file_tree"]["entries"],
            subject._TREE_ENTRIES,
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
            subject._TREE_DIGEST,
        )

    def test_source_implementation_and_parent_pins_are_required(self) -> None:
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(expected_digest=None)
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._qualify(implementation_digest=None)
        receipt = copy.deepcopy(self.p38b_receipt)
        receipt["decision"]["run_01_eligible"] = True
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(p38b_receipt=receipt)

    def test_record_closure_and_exact_boolean_types_are_required(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["artifacts"]["collector"]["probe"][
                "stat"
            ].__setitem__("uid", False)
        )
        document = copy.deepcopy(self.evidence)
        document["acquisition"]["coordinator"]["command"]["elapsed_ns"] = 1.0
        with self.assertRaises(subject.AdmissionEvidenceError):
            self._verify(document=document, expected_digest=subject._EVIDENCE_DIGEST)

    def test_parent_artifacts_and_overlay_are_independently_bound(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["artifacts"]["parent_collector"][
                "probe"
            ].__setitem__("digest", "sha256:" + "a" * 64)
        )

        def split_overlay_pair(document: dict) -> None:
            document["artifacts"]["p3_8c_overlay"]["installed"][0]["installed"][
                "digest"
            ] = "sha256:" + "a" * 64

        self._assert_mutation_rejected(split_overlay_pair)

    def test_harness_must_extend_the_exact_p38b_image(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["harness"]["document"].__setitem__(
                "parent_image_id", "sha256:" + "a" * 64
            )
        )
        self._assert_mutation_rejected(
            lambda document: document["harness"]["document"]["host_config"].__setitem__(
                "privileged", 1
            )
        )

    def test_cas_is_exact_and_unchanged_through_runtime(self) -> None:
        def mutate(document: dict) -> None:
            after = document["acquisition"]["quarantine"]["cas_after_runtime"]
            after["root"]["mtime_ns"] += 1

        self._assert_mutation_rejected(mutate)

        def omit_companion(document: dict) -> None:
            before = document["acquisition"]["quarantine"]["cas_before_runtime"]
            digest = subject._TREE_ENTRIES[1]["digest"]
            before["closure"].pop(digest)
            before["blobs"] = [
                item for item in before["blobs"] if item["digest"] != digest
            ]

        self._assert_mutation_rejected(omit_companion)

    def test_two_source_files_must_match_the_protected_tree(self) -> None:
        def mutate(document: dict) -> None:
            source = document["acquisition"]["quarantine"]["source_files"]
            source["code-reviewer.md"] = copy.deepcopy(source["SKILL.md"])

        self._assert_mutation_rejected(mutate)

    def test_projection_and_protected_tree_must_remain_stable(self) -> None:
        def mutate(document: dict) -> None:
            projected = document["bindings"]["projected_tree"]
            projected["after_action"]["root"]["mtime_ns"] += 1

        self._assert_mutation_rejected(mutate)

        def replace_protected_with_projected(document: dict) -> None:
            document["action"]["inputs"]["producer"]["protected_tree"] = copy.deepcopy(
                document["action"]["inputs"]["producer"]["projected_tree"]
            )

        self._assert_mutation_rejected(replace_protected_with_projected)

    def test_action_must_reuse_the_exact_live_transaction(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["action"]["inputs"]["producer"][
                "transaction"
            ].__setitem__("context_id", "sha256:" + "a" * 64)
        )

    def test_coherent_action_and_consumed_grant_are_required(self) -> None:
        def mutate(document: dict) -> None:
            state = document["action"]["cases"]["coherent_consumed"]["grant_state"]
            state["document"]["status"] = "AVAILABLE"

        self._assert_mutation_rejected(mutate)

    def test_source_claim_ceiling_cannot_be_elevated(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["decision"].__setitem__(
                "public_release_eligible", True
            )
        )

    def test_coordinated_section_repins_cannot_bypass_critical_joins(self) -> None:
        def coordinator_argv(document: dict) -> None:
            document["acquisition"]["coordinator"]["command"]["argv"][0] = "/tmp/python"

        def coordinator_authority(document: dict) -> None:
            coordinator = document["acquisition"]["coordinator"]
            coordinator["result"]["installer_work_eligible"] = True
            raw = subject.canonical_json(coordinator["result"]) + b"\n"
            coordinator["command"]["stdout"].update(
                {
                    "base64": base64.b64encode(raw).decode("ascii"),
                    "bytes": len(raw),
                    "digest": subject._raw_digest(raw),
                }
            )

        def protected_skill_path(document: dict) -> None:
            skill = document["acquisition"]["protected"]["skill"]
            skill["path"] = skill["stat"]["path"] = "/tmp/SKILL.md"

        def binding_skill_digest(document: dict) -> None:
            document["bindings"]["skill_digest"] = "sha256:" + "a" * 64

        def gateway_config(document: dict) -> None:
            document["action"]["inputs"]["gateway_config"]["unexpected"] = True

        def worker_binding(document: dict) -> None:
            inputs = document["action"]["inputs"]
            inputs["worker_binding"]["policy_version"] = 2
            raw = subject.canonical_json(inputs["worker_binding"])
            inputs["worker_binding_file"]["digest"] = subject._raw_digest(raw)
            inputs["worker_binding_file"]["bytes"] = len(raw)
            inputs["worker_binding_file"]["stat"]["size"] = len(raw)

        def nested_artifact_path(document: dict) -> None:
            document["action"]["artifacts"]["installed"][0]["source"]["path"] = (
                "/src/forged.py"
            )

        for name, mutate in (
            ("coordinator_argv", coordinator_argv),
            ("coordinator_authority", coordinator_authority),
            ("protected_skill_path", protected_skill_path),
            ("binding_skill_digest", binding_skill_digest),
            ("gateway_config", gateway_config),
            ("worker_binding", worker_binding),
            ("nested_artifact_path", nested_artifact_path),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_fixed_envelope_pins_survive_section_map_repins(self) -> None:
        for name, mutate in (
            (
                "acquisition",
                lambda document: document["acquisition"].__setitem__(
                    "unexpected", True
                ),
            ),
            (
                "action",
                lambda document: document["action"].__setitem__("unexpected", True),
            ),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_binding_tree_type_aliases_cannot_be_section_repinned(self) -> None:
        self._assert_mutation_rejected(
            lambda document: document["bindings"]["tree_entry"].__setitem__(
                "executable", 0
            )
        )

        for tree_name in ("protected_tree", "projected_tree"):
            for phase in ("before_action", "after_action"):
                with self.subTest(tree=tree_name, phase=phase, field="executable"):
                    self._assert_mutation_rejected(
                        lambda document, tree_name=tree_name, phase=phase: document[
                            "bindings"
                        ][tree_name][phase]["entries"][0].__setitem__("executable", 0)
                    )
                for field in ("uid", "gid"):
                    with self.subTest(tree=tree_name, phase=phase, field=field):
                        self._assert_mutation_rejected(
                            lambda document, tree_name=tree_name, phase=phase, field=field: (
                                document["bindings"][tree_name][phase][
                                    "root"
                                ].__setitem__(field, False)
                            )
                        )

    def test_coordinated_custody_repins_cannot_bypass_root_invariants(self) -> None:
        def active_link_target(document: dict) -> None:
            link = document["acquisition"]["protected"]["active_link"]
            link["target"] += "-forged"
            link["size"] = len(link["target"].encode())

        def active_record_mode(document: dict) -> None:
            document["acquisition"]["protected"]["record"]["file"]["stat"]["mode"] = (
                "0644"
            )
            document["action"]["inputs"]["producer"]["record"]["file"]["stat"][
                "mode"
            ] = "0644"

        def claim_mode(document: dict) -> None:
            document["acquisition"]["protected"]["claim"]["file"]["stat"]["mode"] = (
                "0444"
            )

        def version_path(document: dict) -> None:
            document["acquisition"]["protected"]["version"]["path"] = (
                "/tmp/forged-version"
            )

        def projected_inode_alias(document: dict) -> None:
            trees = [
                document["action"]["inputs"]["producer"]["projected_tree"],
                document["bindings"]["projected_tree"]["before_action"],
                document["bindings"]["projected_tree"]["after_action"],
            ]
            for tree in trees:
                first = tree["files"]["SKILL.md"]["stat"]
                second = tree["files"]["code-reviewer.md"]["stat"]
                second["device"], second["inode"] = first["device"], first["inode"]

        def cas_inode_alias(document: dict) -> None:
            for name in ("cas_before_runtime", "cas_after_runtime"):
                blobs = document["acquisition"]["quarantine"][name]["blobs"]
                blobs[1]["file"]["device"] = blobs[0]["file"]["device"]
                blobs[1]["file"]["inode"] = blobs[0]["file"]["inode"]

        def cas_root_nlink(document: dict) -> None:
            for name in ("cas_before_runtime", "cas_after_runtime"):
                document["acquisition"]["quarantine"][name]["root"]["nlink"] = 1

        def environment_boolean(document: dict) -> None:
            document["action"]["inputs"]["gateway_environment_bytes_retained"] = 0

        for name, mutate in (
            ("active_link_target", active_link_target),
            ("active_record_mode", active_record_mode),
            ("claim_mode", claim_mode),
            ("version_path", version_path),
            ("projected_inode_alias", projected_inode_alias),
            ("cas_inode_alias", cas_inode_alias),
            ("cas_root_nlink", cas_root_nlink),
            ("environment_boolean", environment_boolean),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_root_owned_acquisition_records_cannot_be_repinned(self) -> None:
        def path_start_failure(document: dict) -> None:
            document["acquisition"]["coordinator"]["path_unit_start"]["exit_code"] = 1

        def coordinator_state_mode(document: dict) -> None:
            document["acquisition"]["coordinator"]["state"]["file"]["stat"]["mode"] = (
                "0666"
            )

        def record_owner(document: dict) -> None:
            document["acquisition"]["protected"]["record"]["file"]["stat"]["uid"] = 1000
            document["action"]["inputs"]["producer"]["record"]["file"]["stat"][
                "uid"
            ] = 1000

        def claim_owner(document: dict) -> None:
            document["acquisition"]["protected"]["claim"]["file"]["stat"]["uid"] = 1000

        def active_link_owner(document: dict) -> None:
            document["acquisition"]["protected"]["active_link"]["uid"] = 1000

        for name, mutate in (
            ("path_start_failure", path_start_failure),
            ("coordinator_state_mode", coordinator_state_mode),
            ("record_owner", record_owner),
            ("claim_owner", claim_owner),
            ("active_link_owner", active_link_owner),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_phase_local_identities_and_action_inputs_cannot_be_repinned(
        self,
    ) -> None:
        def projected_aliases_protected(document: dict) -> None:
            protected = document["acquisition"]["protected"]["tree"]["files"][
                "SKILL.md"
            ]["stat"]
            trees = [
                document["action"]["inputs"]["producer"]["projected_tree"],
                document["bindings"]["projected_tree"]["before_action"],
                document["bindings"]["projected_tree"]["after_action"],
            ]
            for tree in trees:
                stat = tree["files"]["SKILL.md"]["stat"]
                stat["device"], stat["inode"] = protected["device"], protected["inode"]
            projected = document["action"]["inputs"]["producer"]["projected_skill"][
                "stat"
            ]
            projected["device"], projected["inode"] = (
                protected["device"],
                protected["inode"],
            )

        def protected_skill_aliases_cas(document: dict) -> None:
            blob = document["acquisition"]["quarantine"]["cas_before_runtime"]["blobs"][
                0
            ]["file"]
            trees = [
                document["acquisition"]["protected"]["tree"],
                document["action"]["inputs"]["producer"]["protected_tree"],
                document["bindings"]["protected_tree"]["before_action"],
                document["bindings"]["protected_tree"]["after_action"],
            ]
            for tree in trees:
                stat = tree["files"]["SKILL.md"]["stat"]
                stat["device"], stat["inode"] = blob["device"], blob["inode"]
            for skill in (
                document["acquisition"]["protected"]["skill"],
                document["action"]["inputs"]["producer"]["skill"],
            ):
                skill["stat"]["device"], skill["stat"]["inode"] = (
                    blob["device"],
                    blob["inode"],
                )

        def claim_aliases_cas(document: dict) -> None:
            blob = document["acquisition"]["quarantine"]["cas_before_runtime"]["blobs"][
                0
            ]["file"]
            stat = document["acquisition"]["protected"]["claim"]["file"]["stat"]
            stat["device"], stat["inode"] = blob["device"], blob["inode"]

        def extra_action_input(document: dict) -> None:
            document["action"]["inputs"]["unexpected"] = True

        def worker_binding_link(document: dict) -> None:
            document["action"]["inputs"]["worker_binding_file"]["stat"]["nlink"] = 2

        for name, mutate in (
            ("projected_aliases_protected", projected_aliases_protected),
            ("protected_skill_aliases_cas", protected_skill_aliases_cas),
            ("claim_aliases_cas", claim_aliases_cas),
            ("extra_action_input", extra_action_input),
            ("worker_binding_link", worker_binding_link),
        ):
            with self.subTest(name=name):
                self._assert_mutation_rejected(mutate)

    def test_network_cutover_cannot_regain_eth0_or_reorder_markers(self) -> None:
        def regain_eth0(document: dict) -> None:
            network = document["acquisition"]["network"]
            network["after_runtime"]["interfaces"].insert(
                0, copy.deepcopy(network["before_acquisition"]["interfaces"][0])
            )

        self._assert_mutation_rejected(regain_eth0)

        def late_marker(document: dict) -> None:
            marker = document["acquisition"]["network"]["disconnected_marker"]
            marker["file"]["stat"]["ctime_ns"] = 9_999_999_999_999_999_999

        self._assert_mutation_rejected(late_marker)

    def _qualify(self, **overrides: object) -> dict:
        arguments = self._arguments()
        arguments["implementation_digest"] = self._implementation_digest()
        arguments.update(overrides)
        return subject.runtime_acquisition_action_multifile_systemd_qualification(
            **arguments
        )

    def _verify(self, **overrides: object) -> None:
        arguments = self._arguments()
        arguments.update(overrides)
        subject.verify_runtime_acquisition_action_multifile_systemd_evidence(
            **arguments
        )

    def _arguments(self) -> dict:
        return {
            "document": self.evidence,
            "p38b_observation": self.p38b_observation,
            "p37c_observation": self.p37c_observation,
            "p37b_observation": self.p37b_observation,
            "p36b_observation": self.p36b_observation,
            "p37b_receipt": self.p37b_receipt,
            "p37c_receipt": self.p37c_receipt,
            "p38b_receipt": self.p38b_receipt,
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
        with (
            patch.object(
                subject, "_EVIDENCE_DIGEST", subject.canonical_digest(document)
            ),
            patch.object(
                subject, "_EVIDENCE_RAW_DIGEST", subject._raw_digest(encoded + b"\n")
            ),
            patch.object(subject, "_EVIDENCE_BYTES", len(encoded) + 1),
            patch.object(subject, "_SECTION_DIGESTS", section_digests),
            self.assertRaises(subject.AdmissionEvidenceError),
        ):
            self._verify(
                document=document,
                expected_digest=subject.canonical_digest(document),
            )

    @staticmethod
    def _implementation_digest() -> str:
        return (
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest()
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
