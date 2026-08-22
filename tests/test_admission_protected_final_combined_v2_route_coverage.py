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
    "archive_post_write_activation_prevention": (
        "phase3-openclaw-protected-final-combined-v2-archive-source-force-"
        "replacement-route-coverage-v1-2026-08-22.json"
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
        for child in subject._CHILDREN:
            raw = (_ROOT / child["module"]._EVIDENCE["path"]).read_bytes()
            store.put_expected(
                BytesIO(raw),
                expected_digest=child["module"]._EVIDENCE["digest"],
                max_bytes=len(raw),
            )
        return subject.compose_openclaw_final_combined_v2_route_coverage(
            evidence_cas=store
        )

    def repin_result(self, name: str, result: dict[str, object]) -> tuple[dict, ...]:
        return tuple(
            {
                **child,
                "result_digest": canonical_digest(result),
            }
            if child["name"] == name
            else child
            for child in subject._CHILDREN
        )

    def test_exact_five_route_receipt_with_all_broad_eligibility_false(self) -> None:
        result = self.compose()

        self.assertEqual(result["profile"]["counts"], {"PASS": 5, "NOT_TESTED": 16})
        self.assertEqual(len(result["profile"]["routes"]), 21)
        self.assertEqual(
            {
                route["id"]
                for route in result["profile"]["routes"]
                if route["status"] == "PASS"
            },
            subject._EXPECTED_PASS_ROUTES,
        )
        self.assertTrue(
            all(result["decision"][key] is False for key in subject._ELIGIBILITY_KEYS)
        )
        self.assertFalse(result["capture_model"]["aggregate_execution_observed"])
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
        for children in (
            tuple(reversed(subject._CHILDREN)),
            renamed,
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
