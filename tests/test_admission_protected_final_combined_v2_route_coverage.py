from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import ExitStack
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from aragorn import admission_protected_final_combined_v2_route_coverage as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_ROOT = Path(__file__).resolve().parents[1]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-protected-final-combined-v2-route-"
    "coverage-v1-2026-08-22.json"
)
_CHILD_RECEIPTS = {
    "config_entry_activation": (
        "phase3-openclaw-protected-final-combined-v2-config-entry-activation-"
        "route-coverage-v1-2026-08-22.json"
    ),
    "catalog_fixed_fresh_session_reset": (
        "phase3-openclaw-protected-final-combined-v2-catalog-fixed-fresh-"
        "session-reset-route-coverage-v1-2026-08-22.json"
    ),
    "catalog_fixed_cron_rescan": (
        "phase3-openclaw-protected-final-combined-v2-cron-rescan-catalog-fixed-"
        "route-coverage-v1-2026-08-22.json"
    ),
    "catalog_fixed_prompt_rebuild": (
        "phase3-openclaw-protected-final-combined-v2-prompt-rebuild-catalog-"
        "fixed-route-coverage-v1-2026-08-22.json"
    ),
    "catalog_fixed_session_snapshot_consumer": (
        "phase3-openclaw-protected-final-combined-v2-session-snapshot-consumer-"
        "catalog-fixed-route-coverage-v1-2026-08-22.json"
    ),
    "catalog_fixed_chat_session_snapshot_consumer": (
        "phase3-openclaw-protected-final-combined-v2-chat-session-snapshot-consumer-"
        "catalog-fixed-route-coverage-v1-2026-08-22.json"
    ),
    "archive_post_write_activation_prevention": (
        "phase3-openclaw-protected-final-combined-v2-archive-source-force-"
        "replacement-route-coverage-v1-2026-08-22.json"
    ),
    "curator_restore_activation": (
        "phase3-openclaw-protected-final-combined-v2-curator-restore-route-"
        "coverage-v1-2026-08-26.json"
    ),
    "workshop_proposal_apply": (
        "phase3-openclaw-protected-final-combined-v2-workshop-proposal-apply-"
        "route-coverage-v1-2026-08-26.json"
    ),
    "workshop_invalidation": (
        "phase3-openclaw-protected-final-combined-v2-workshop-invalidation-"
        "route-coverage-v1-2026-08-26.json"
    ),
    "plugin_enable_activation": (
        "phase3-openclaw-protected-final-combined-v2-plugin-enable-activation-"
        "route-coverage-v1-2026-08-27.json"
    ),
    "plugin_force_reinstall_failure": (
        "phase3-openclaw-protected-final-combined-v2-plugin-force-reinstall-"
        "route-coverage-v1-2026-08-28.json"
    ),
}


class FinalCombinedV2RouteCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        receipts = _ROOT / "benchmark/receipts"
        cls.child_results = {
            name: json.loads((receipts / path).read_bytes())
            for name, path in _CHILD_RECEIPTS.items()
        }

    def compose(self) -> dict[str, object]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = CAS(temporary.name)
        retained: set[str] = set()
        for child in subject._CHILDREN:
            module = child["module"]
            evidence = (
                module._EVIDENCE
                if hasattr(module, "_EVIDENCE")
                else module.parent._EVIDENCE
            )
            raw = (_ROOT / evidence["path"]).read_bytes()
            if evidence["digest"] in retained:
                continue
            store.put_expected(
                BytesIO(raw),
                expected_digest=evidence["digest"],
                max_bytes=len(raw),
            )
            retained.add(evidence["digest"])
        return subject.compose_openclaw_final_combined_v2_route_coverage(
            evidence_cas=store
        )

    def repin_result(self, name: str, result: dict[str, object]) -> tuple[dict, ...]:
        return self.repin_results({name: result})

    def repin_results(self, results: dict[str, dict[str, object]]) -> tuple[dict, ...]:
        return tuple(
            {
                **child,
                "result_digest": canonical_digest(results[child["name"]]),
            }
            if child["name"] in results
            else child
            for child in subject._CHILDREN
        )

    def test_exact_eleven_passes_one_failure_from_ten_captures(self) -> None:
        result = self.compose()

        self.assertEqual(
            result["profile"]["counts"],
            {"FAIL": 1, "NOT_TESTED": 9, "PASS": 11},
        )
        self.assertEqual(len(result["profile"]["routes"]), 21)
        self.assertEqual(
            {
                route["id"]
                for route in result["profile"]["routes"]
                if route["status"] == "PASS"
            },
            subject._EXPECTED_PASS_ROUTES,
        )
        self.assertEqual(
            {
                route["id"]
                for route in result["profile"]["routes"]
                if route["status"] == "FAIL"
            },
            subject._EXPECTED_FAIL_ROUTES,
        )
        self.assertEqual(result["decision"]["status"], "FAIL")
        self.assertTrue(
            all(result["decision"][key] is False for key in subject._ELIGIBILITY_KEYS)
        )
        self.assertFalse(result["capture_model"]["aggregate_execution_observed"])
        self.assertEqual(result["capture_model"]["qualification_count"], 12)
        self.assertEqual(result["capture_model"]["distinct_capture_count"], 10)
        captures = {
            child["route"]: child["capture"]["digest"]
            for child in result["bindings"]["child_qualifications"]
        }
        self.assertEqual(len(set(captures.values())), 10)
        self.assertEqual(
            captures,
            {child["route"]: child["capture_digest"] for child in subject._CHILDREN},
        )
        self.assertEqual(
            captures[subject.session._ROUTE], captures[subject.chat._ROUTE]
        )
        self.assertEqual(
            captures[subject.workshop._ROUTE],
            captures[subject.workshop_reload._ROUTE],
        )
        self.assertEqual(
            result["capture_model"]["shared_capture_groups"],
            [
                {
                    "capture_digest": subject.session._EVIDENCE["digest"],
                    "routes": [subject.session._ROUTE, subject.chat._ROUTE],
                },
                {
                    "capture_digest": subject.workshop._EVIDENCE["digest"],
                    "routes": [
                        subject.workshop._ROUTE,
                        subject.workshop_reload._ROUTE,
                    ],
                },
            ],
        )
        self.assertEqual(
            result["bindings"]["verifier_source_path"], subject._VERIFIER_PATH
        )
        self.assertEqual(
            result["bindings"]["verifier_implementation_digest"],
            "sha256:" + hashlib.sha256(Path(subject.__file__).read_bytes()).hexdigest(),
        )
        self.assertIn(
            "ARCHIVE_DIRECTORY_INSTALL_LEFT_EXCLUDED_WORKSPACE_SKILL_RESIDUE",
            result["limitations"],
        )
        self.assertIn(
            "ARCHIVE_POST_WRITE_CATALOG_REJECTION_MAY_DENY_SKILL_DISCOVERY_AVAILABILITY",
            result["limitations"],
        )
        for limitation in (
            "EXACT_EPHEMERAL_ARCHIVED_LIFECYCLE_FIXTURE_NOT_NATIVE_CURATOR_SWEEP",
            "EXACT_SELECTED_LIFECYCLE_ROW_ONLY_NOT_FULL_DATABASE_STATE",
            "SKILLS_STATUS_ARCHIVED_DIAGNOSTIC_NOT_ACTIVE_CONSUMER_PROOF",
        ):
            self.assertIn(limitation, result["limitations"])
        for limitation in (
            "PLUGIN_ENABLE_DENIED_PRE_EFFECT_AT_READ_ONLY_SYSTEMD_CREDENTIAL_LOCK",
            "PLUGIN_ENABLE_TARGET_REMAINED_DISABLED_NOT_ALLOWLISTED_AND_UNACTIVATED",
        ):
            self.assertIn(limitation, result["limitations"])
        for limitation in (
            "KNOWN_EXACT_ROUTE_FAILURE_PREVENTS_AGGREGATE_AUTHORITY",
            "PLUGIN_FORCE_REINSTALL_UNBROKERED_REPLACEMENT_PERSISTED_IN_CANONICAL_PLUGIN_DISCOVERY_TARGET_AND_COMMAND_FAILED_ON_CONFIG_LOCK",
            "PLUGIN_FORCE_REINSTALL_REPLACEMENT_REMAINED_DISABLED_NOT_ALLOWLISTED_UNACTIVATED_AND_UNIMPORTED",
            "PLUGIN_FORCE_REINSTALL_TARGET_BYTES_AND_EMPTY_INSTALL_BACKUP_DIRECTORY_PERSIST",
            "PLUGIN_FORCE_REINSTALL_SQLITE_WAL_AND_SHM_CHANGED_NO_TABLE_LEVEL_DIFF",
        ):
            self.assertIn(limitation, result["limitations"])
        for limitation in (
            "WORKSHOP_RESIDUE_PERSISTS_THROUGH_FINAL_OBSERVATION",
            "WORKSHOP_POST_APPLY_AND_FINAL_SKILLS_STATUS_DENIED_BY_EXTERNAL_AUTHORITY",
            "NO_POST_APPLY_WORKSHOP_CATALOG_AVAILABILITY_CLAIM",
            "WORKSHOP_INVALIDATION_REUSES_SHARED_PROPOSAL_APPLY_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "RAW_WORKSHOP_CAPTURE_ROUTE_ID_REMAINS_WORKSHOP_PROPOSAL_APPLY",
            "WORKSHOP_NEXT_SAME_SESSION_TURN_FAILED_NO_PROVIDER_SUCCESS_REPLY_OR_DELIVERY_CLAIM",
            "WORKSHOP_APPLIED_TARGET_BYTES_NOT_RETAINED_METADATA_DIGEST_ONLY",
            "WORKSHOP_RESIDUE_NOT_CLEANED_UP_NO_CLEANUP_ROLLBACK_OR_QUARANTINE_CLAIM",
        ):
            self.assertIn(limitation, result["limitations"])
        for limitation in (
            "CHAT_ROUTE_REUSES_SHARED_SESSION_CAPTURE_NOT_INDEPENDENT_EXECUTION",
            "RAW_CAPTURE_ROUTE_ID_REMAINS_SESSION_SNAPSHOT_CONSUMER",
            "BLACK_BOX_NATIVE_CHAT_PERSISTENCE_WITHOUT_DIRECT_SESSION_UPDATE_TRACE",
            "ONE_TAMPER_RECOVERY_TRIGGER_NOT_GENERAL_CHAT_ROUTE_COVERAGE",
            "MODEL_TURNS_FAILED_NO_PROVIDER_BODY_SUCCESSFUL_REPLY_OR_DELIVERY_CLAIM",
            "SESSION_SNAPSHOT_COMPILED_CLOSURE_ACQUISITION_PRE_ROUTE_ONLY",
            "NO_POST_ROUTE_SESSION_CLOSURE_PROVENANCE_OR_CONTINUOUS_IMMUTABILITY_CLAIM",
            "SESSION_SNAPSHOT_DETERMINISTIC_COMPILED_REPLAY_NOT_NATIVE_AGENT_EXECUTION",
            "SESSION_SNAPSHOT_NATIVE_PROVIDER_REQUEST_BODY_AND_SYSTEM_PROMPT_REPORT_NOT_OBSERVED",
            "SESSION_SNAPSHOT_FOURTEEN_SELECTED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "SESSION_SNAPSHOT_COMPILED_CLOSURE_REUSED_FROM_PRIOR_DIFFERENT_IMAGE_CAPTURE",
            "SESSION_SNAPSHOT_ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
        ):
            self.assertIn(limitation, result["limitations"])
        self.assertEqual(_RECEIPT.read_bytes(), canonical_json(result) + b"\n")
        self.assertEqual(json.loads(_RECEIPT.read_bytes()), result)

    def test_coordinated_binding_and_eligibility_repins_fail_closed(self) -> None:
        name = "catalog_fixed_fresh_session_reset"

        mismatch = deepcopy(self.child_results[name])
        mismatch["bindings"]["configuration"]["digest"] = "sha256:" + "0" * 64
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, mismatch)),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=mismatch,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        eligible = deepcopy(self.child_results[name])
        eligible["decision"]["edr_eligible"] = 0
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, eligible)),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=eligible,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        bool_count = deepcopy(self.child_results[name])
        bool_count["profile"]["counts"]["PASS"] = True
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, bool_count)),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=bool_count,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        name = "catalog_fixed_chat_session_snapshot_consumer"
        mismatch = deepcopy(self.child_results[name])
        mismatch["bindings"]["session_snapshot_observation"]["canonical_digest"] = (
            "sha256:" + "0" * 64
        )
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, mismatch)),
            patch.object(
                subject.chat,
                "verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_"
                "catalog_fixed",
                return_value=mismatch,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "shared capture binding"),
        ):
            self.compose()

        name = "catalog_fixed_fresh_session_reset"
        alias = deepcopy(self.child_results[name])
        alias["bindings"]["fresh_session_reset_observation"]["digest"] = (
            self.child_results["config_entry_activation"]["bindings"][
                "config_activation_observation"
            ]["digest"]
        )
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, alias)),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=alias,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "capture digest"),
        ):
            self.compose()

        name = "catalog_fixed_chat_session_snapshot_consumer"
        contradiction = deepcopy(self.child_results[name])
        contradiction["bindings"]["parent_qualification_canonical_digest"] = (
            "sha256:" + "0" * 64
        )
        contradiction["bindings"]["parent_verifier"]["digest"] = "sha256:" + "1" * 64
        contradiction["bindings"]["shared_capture"] = {
            "capture_relationship": "INDEPENDENT_CAPTURE",
            "source_route": subject.config._ROUTE,
        }
        contradiction["route_semantics"]["shared_capture_independent"] = True
        contradiction["route_semantics"]["source_capture_route"] = subject.config._ROUTE
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, contradiction)),
            patch.object(
                subject.chat,
                "verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_"
                "catalog_fixed",
                return_value=contradiction,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "parent relationship"),
        ):
            self.compose()

        name = "workshop_invalidation"
        mismatch = deepcopy(self.child_results[name])
        mismatch["bindings"]["workshop_proposal_apply_observation"][
            "canonical_digest"
        ] = "sha256:" + "0" * 64
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, mismatch)),
            patch.object(
                subject.workshop_reload,
                "verify_openclaw_final_combined_v2_workshop_invalidation",
                return_value=mismatch,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "shared capture binding"),
        ):
            self.compose()

        contradiction = deepcopy(self.child_results[name])
        contradiction["bindings"]["parent_qualification_canonical_digest"] = (
            "sha256:" + "0" * 64
        )
        contradiction["bindings"]["parent_verifier"]["digest"] = (
            "sha256:" + "1" * 64
        )
        contradiction["bindings"]["shared_capture"] = {
            "capture_relationship": "INDEPENDENT_CAPTURE",
            "source_route": subject.config._ROUTE,
        }
        contradiction["route_semantics"]["shared_capture_independent"] = True
        contradiction["route_semantics"]["source_capture_route"] = (
            subject.config._ROUTE
        )
        with (
            patch.object(
                subject, "_CHILDREN", self.repin_result(name, contradiction)
            ),
            patch.object(
                subject.workshop_reload,
                "verify_openclaw_final_combined_v2_workshop_invalidation",
                return_value=contradiction,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "parent relationship"),
        ):
            self.compose()

        config_name = "config_entry_activation"
        fresh_name = "catalog_fixed_fresh_session_reset"
        swapped = {
            config_name: deepcopy(self.child_results[config_name]),
            fresh_name: deepcopy(self.child_results[fresh_name]),
        }
        config_capture = deepcopy(
            swapped[config_name]["bindings"]["config_activation_observation"]
        )
        fresh_capture = deepcopy(
            swapped[fresh_name]["bindings"]["fresh_session_reset_observation"]
        )
        swapped[config_name]["bindings"]["config_activation_observation"] = (
            fresh_capture
        )
        swapped[fresh_name]["bindings"]["fresh_session_reset_observation"] = (
            config_capture
        )
        with (
            patch.object(subject, "_CHILDREN", self.repin_results(swapped)),
            patch.object(
                subject.config,
                "verify_openclaw_final_combined_v2_config_activation",
                return_value=swapped[config_name],
            ),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=swapped[fresh_name],
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "capture digest"),
        ):
            self.compose()

        session_name = "catalog_fixed_session_snapshot_consumer"
        chat_name = "catalog_fixed_chat_session_snapshot_consumer"
        unsigned_parent = deepcopy(self.child_results[session_name])
        unsigned_parent["limitations"].append("UNSIGNED_PARENT_RESULT_MUTATION")
        repinned_chat = deepcopy(self.child_results[chat_name])
        repinned_chat["bindings"]["parent_qualification_canonical_digest"] = (
            canonical_digest(unsigned_parent)
        )
        unsigned_repin = {
            session_name: unsigned_parent,
            chat_name: repinned_chat,
        }
        with (
            patch.object(subject, "_CHILDREN", self.repin_results(unsigned_repin)),
            patch.object(
                subject.session,
                "verify_openclaw_final_combined_v2_session_snapshot_consumer_"
                "catalog_fixed",
                return_value=unsigned_parent,
            ),
            patch.object(
                subject.chat,
                "verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_"
                "catalog_fixed",
                return_value=repinned_chat,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "parent relationship"),
        ):
            self.compose()

        workshop_name = "workshop_proposal_apply"
        workshop_reload_name = "workshop_invalidation"
        unsigned_parent = deepcopy(self.child_results[workshop_name])
        unsigned_parent["limitations"].append("UNSIGNED_WORKSHOP_PARENT_MUTATION")
        repinned_reload = deepcopy(self.child_results[workshop_reload_name])
        repinned_reload["bindings"]["parent_qualification_canonical_digest"] = (
            canonical_digest(unsigned_parent)
        )
        unsigned_repin = {
            workshop_name: unsigned_parent,
            workshop_reload_name: repinned_reload,
        }
        with (
            patch.object(subject, "_CHILDREN", self.repin_results(unsigned_repin)),
            patch.object(
                subject.workshop,
                "verify_openclaw_final_combined_v2_workshop_proposal_apply",
                return_value=unsigned_parent,
            ),
            patch.object(
                subject.workshop_reload,
                "verify_openclaw_final_combined_v2_workshop_invalidation",
                return_value=repinned_reload,
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "parent relationship"),
        ):
            self.compose()

        rebound = {
            config_name: deepcopy(self.child_results[config_name]),
            session_name: deepcopy(self.child_results[session_name]),
            chat_name: deepcopy(self.child_results[chat_name]),
        }
        config_capture = deepcopy(
            rebound[config_name]["bindings"]["config_activation_observation"]
        )
        session_capture = deepcopy(
            rebound[session_name]["bindings"]["session_snapshot_observation"]
        )
        rebound[config_name]["bindings"]["config_activation_observation"] = (
            session_capture
        )
        rebound[session_name]["bindings"]["session_snapshot_observation"] = (
            config_capture
        )
        rebound[chat_name]["bindings"]["session_snapshot_observation"] = deepcopy(
            config_capture
        )
        rebound[chat_name]["bindings"]["parent_qualification_canonical_digest"] = (
            canonical_digest(rebound[session_name])
        )
        with (
            patch.object(subject, "_CHILDREN", self.repin_results(rebound)),
            patch.object(
                subject.config,
                "verify_openclaw_final_combined_v2_config_activation",
                return_value=rebound[config_name],
            ),
            patch.object(
                subject.session,
                "verify_openclaw_final_combined_v2_session_snapshot_consumer_"
                "catalog_fixed",
                return_value=rebound[session_name],
            ),
            patch.object(
                subject.chat,
                "verify_openclaw_final_combined_v2_chat_session_snapshot_consumer_"
                "catalog_fixed",
                return_value=rebound[chat_name],
            ),
            self.assertRaisesRegex(AdmissionEvidenceError, "capture digest"),
        ):
            self.compose()

        empty_shared = deepcopy(self.child_results)
        children = []
        for child in subject._CHILDREN:
            result = empty_shared[child["name"]]
            for key in subject._SHARED_BINDINGS:
                result["bindings"][key] = {}
            children.append({**child, "result_digest": canonical_digest(result)})
        with ExitStack() as stack:
            stack.enter_context(patch.object(subject, "_CHILDREN", tuple(children)))
            for child in subject._CHILDREN:
                stack.enter_context(
                    patch.object(
                        child["module"],
                        child["verifier"],
                        return_value=empty_shared[child["name"]],
                    )
                )
            with self.assertRaises(AdmissionEvidenceError):
                self.compose()

    def test_failure_child_cannot_be_promoted_or_omitted(self) -> None:
        name = "plugin_force_reinstall_failure"

        promoted = deepcopy(self.child_results[name])
        promoted["profile"]["counts"] = {"PASS": 1, "NOT_TESTED": 20}
        for route in promoted["profile"]["routes"]:
            if route["id"] == subject.plugin_force._ROUTE:
                route["status"] = "PASS"
        promoted["decision"]["status"] = "PARTIAL_DYNAMIC_V2_ROUTE_COVERAGE"
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, promoted)),
            patch.object(
                subject.plugin_force,
                "verify_openclaw_final_combined_v2_plugin_force_reinstall",
                return_value=promoted,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        bool_count = deepcopy(self.child_results[name])
        bool_count["profile"]["counts"]["FAIL"] = True
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, bool_count)),
            patch.object(
                subject.plugin_force,
                "verify_openclaw_final_combined_v2_plugin_force_reinstall",
                return_value=bool_count,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        omitted = deepcopy(self.child_results[name])
        omitted["route_semantics"]["dynamically_exercised_routes"] = []
        with (
            patch.object(subject, "_CHILDREN", self.repin_result(name, omitted)),
            patch.object(
                subject.plugin_force,
                "verify_openclaw_final_combined_v2_plugin_force_reinstall",
                return_value=omitted,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

    def test_duplicate_substitution_and_verifier_drift_fail_closed(self) -> None:
        name = "catalog_fixed_fresh_session_reset"
        config_result = self.child_results["config_entry_activation"]

        with (
            patch.object(
                subject,
                "_CHILDREN",
                self.repin_result(name, config_result),
            ),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=config_result,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        duplicate_result = deepcopy(config_result)
        children = tuple(
            {
                **child,
                "route": subject.config._ROUTE,
                "result_digest": canonical_digest(duplicate_result),
            }
            if child["name"] == name
            else child
            for child in subject._CHILDREN
        )
        with (
            patch.object(subject, "_CHILDREN", children),
            patch.object(
                subject.fresh,
                "verify_openclaw_final_combined_v2_catalog_fixed_fresh_session_reset",
                return_value=duplicate_result,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            self.compose()

        drifted = tuple(
            {**child, "verifier_digest": "sha256:" + "1" * 64}
            if child["name"] == name
            else child
            for child in subject._CHILDREN
        )
        with (
            patch.object(subject, "_CHILDREN", drifted),
            self.assertRaisesRegex(AdmissionEvidenceError, "implementation drifted"),
        ):
            self.compose()

    def test_child_inventory_order_and_identity_fail_closed(self) -> None:
        renamed = tuple(
            {**child, "name": "renamed_child"} if index == 1 else child
            for index, child in enumerate(subject._CHILDREN)
        )
        retargeted_capture = tuple(
            {**child, "capture_binding": "configuration"} if index == 0 else child
            for index, child in enumerate(subject._CHILDREN)
        )
        repinned_capture = tuple(
            {**child, "capture_digest": "sha256:" + "0" * 64} if index == 0 else child
            for index, child in enumerate(subject._CHILDREN)
        )
        for children in (
            tuple(reversed(subject._CHILDREN)),
            renamed,
            retargeted_capture,
            repinned_capture,
            subject._CHILDREN + (subject._CHILDREN[0],),
        ):
            with (
                patch.object(subject, "_CHILDREN", children),
                self.assertRaisesRegex(
                    AdmissionEvidenceError, "ordered V2 child inventory"
                ),
            ):
                self.compose()


if __name__ == "__main__":
    unittest.main()
