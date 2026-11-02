from __future__ import annotations

import base64
import hashlib
import json
import unittest
from collections.abc import Callable
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from aragorn import admission_openclaw_final_v2_aggregate_fresh_session as subject
from aragorn.admission_evidence import AdmissionEvidenceError
from aragorn.cas import CAS

_ROOT = Path(__file__).resolve().parents[1]
_EVIDENCE = _ROOT / subject._EVIDENCE["path"]
_RECEIPT = _ROOT / (
    "benchmark/receipts/phase3-openclaw-final-admission-v2-aggregate-fresh-"
    "session-route-qualification-v1-2026-08-27.json"
)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _store(raw: bytes) -> tuple[TemporaryDirectory[str], CAS]:
    temporary = TemporaryDirectory()
    store = CAS(temporary.name)
    store.put_expected(BytesIO(raw), expected_digest=_digest(raw), max_bytes=len(raw))
    return temporary, store


def _outer_identity(raw: bytes) -> dict[str, object]:
    document = json.loads(raw)
    canonical = subject._canonical(document)
    return {
        **subject._EVIDENCE,
        "bytes": len(raw),
        "canonical_bytes": len(canonical),
        "canonical_digest": _digest(canonical),
        "digest": _digest(raw),
    }


def _static_identity(value: Any) -> dict[str, object]:
    canonical = subject._canonical(value)
    return {"bytes": len(canonical), "digest": _digest(canonical)}


def _repin_route(
    changed: dict[str, Any], route: dict[str, Any]
) -> tuple[bytes, dict[str, object], dict[str, object]]:
    bound = changed["main"]["evidence"][0]
    route_raw = subject._canonical(route) + b"\n"
    bound["observation"]["route_capture"] = {
        "base64": base64.b64encode(route_raw).decode(),
        "bytes": len(route_raw),
        "digest": _digest(route_raw),
    }
    bound_document = {
        "bindings": changed["bindings"],
        "mode": "main",
        "observation": bound["observation"],
        "probe_digest": bound["probe_digest"],
        "probe_module": bound["probe_module"],
        "run_nonce": changed["run_nonce"],
        "schema": bound["schema"],
    }
    bound["digest"] = _digest(subject._canonical(bound_document) + b"\n")
    artifact = {
        "digest": bound["digest"],
        "path": bound["path"],
        "schema": bound["schema"],
    }
    route_row = next(
        item for item in changed["main"]["routes"] if item["id"] == subject._ROUTE
    )
    route_row["evidence_refs"] = [bound["digest"]]
    main_input = subject._main_input(
        nonce=changed["run_nonce"], bindings=changed["bindings"], artifact=artifact
    )
    changed["main"]["input"]["digest"] = _digest(
        subject._canonical(main_input) + b"\n"
    )
    changed["execution"]["route_slice"]["artifact"] = artifact
    changed_raw = subject._canonical(changed) + b"\n"
    return (
        changed_raw,
        _outer_identity(changed_raw),
        {
            "bytes": len(route_raw),
            "canonical_bytes": len(route_raw) - 1,
            "canonical_digest": _digest(route_raw[:-1]),
            "digest": _digest(route_raw),
        },
    )


def _repin_action(
    outer: dict[str, Any], mutate: Callable[[dict[str, Any]], None]
) -> tuple[bytes, dict[str, object], dict[str, object], dict[str, object]]:
    changed = deepcopy(outer)
    bound = changed["main"]["evidence"][0]
    route_raw = base64.b64decode(
        bound["observation"]["route_capture"]["base64"], validate=True
    )
    route = json.loads(route_raw)
    action = route["route_observation"]["document"]
    mutate(action)
    action_raw = (
        json.dumps(action, ensure_ascii=False, allow_nan=False, indent=2).encode()
        + b"\n"
    )
    action_canonical = subject._canonical(action)
    route["route_observation"]["raw"] = {
        "base64": base64.b64encode(action_raw).decode(),
        "bytes": len(action_raw),
        "canonical_digest": _digest(action_canonical),
        "digest": _digest(action_raw),
        "raw_is_canonical_json_lf": False,
    }
    changed_raw, evidence_identity, route_identity = _repin_route(changed, route)
    return (
        changed_raw,
        evidence_identity,
        route_identity,
        {
            "bytes": len(action_raw),
            "canonical_bytes": len(action_canonical),
            "canonical_digest": _digest(action_canonical),
            "digest": _digest(action_raw),
        },
    )


class AggregateFreshSessionQualificationTests(unittest.TestCase):
    def test_one_route_pass_with_every_broader_claim_false(self) -> None:
        raw = _EVIDENCE.read_bytes()
        temporary, store = _store(raw)
        self.addCleanup(temporary.cleanup)
        result = subject.verify_openclaw_final_v2_aggregate_fresh_session(
            evidence_cas=store
        )
        self.assertEqual(result["profile"]["counts"], {"PASS": 1, "NOT_TESTED": 20})
        statuses = {
            route["id"]: route["status"] for route in result["profile"]["routes"]
        }
        self.assertEqual(statuses[subject._ROUTE], "PASS")
        self.assertEqual(list(statuses.values()).count("PASS"), 1)
        self.assertTrue(result["decision"]["aggregate_execution_observed"])
        self.assertFalse(result["decision"]["aggregate_semantic_admission_verified"])
        self.assertTrue(
            all(result["decision"][key] is False for key in subject._FALSE_FLAGS)
        )
        self.assertTrue(
            all(
                value is False
                for group in result["formal_claims"].values()
                for value in group.values()
            )
        )
        retained = json.loads(raw)
        self.assertFalse(retained["decision"]["semantic_pass_verified"])
        self.assertFalse(retained["decision"]["aggregate_admission_eligible"])
        receipt = _RECEIPT.read_bytes()
        self.assertEqual(receipt, subject._canonical(result) + b"\n")
        self.assertEqual(json.loads(receipt), result)

    def test_hostile_coordinated_repin_still_checks_reset_semantics(self) -> None:
        raw = _EVIDENCE.read_bytes()
        changed_raw, evidence, route, action = _repin_action(
            json.loads(raw),
            lambda document: document["actions"][0]["observations"].__setitem__(
                "reset_snapshot_cleared", False
            ),
        )
        temporary, store = _store(changed_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_CAPTURE", route),
            patch.object(subject, "_ACTION_RAW", action),
            patch.object(subject, "_verify_retained_evidence", return_value=changed_raw),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_v2_aggregate_fresh_session(
                evidence_cas=store
            )

    def test_hostile_coordinated_outer_decision_scalar_repins_fail_closed(
        self,
    ) -> None:
        raw = _EVIDENCE.read_bytes()
        for label, key, value in (
            ("false-as-zero", "edr_eligible", 0),
            ("one-as-true", "route_observed_count", True),
        ):
            with self.subTest(label=label):
                changed = deepcopy(json.loads(raw))
                changed["decision"][key] = value
                changed_raw = subject._canonical(changed) + b"\n"
                temporary, store = _store(changed_raw)
                self.addCleanup(temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", _outer_identity(changed_raw)),
                    patch.dict(
                        subject._STATIC_OBJECTS,
                        {"decision": _static_identity(changed["decision"])},
                    ),
                    patch.object(
                        subject, "_verify_retained_evidence", return_value=changed_raw
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_v2_aggregate_fresh_session(
                        evidence_cas=store
                    )

    def test_hostile_coordinated_collector_digest_repin_fails_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        changed = deepcopy(json.loads(raw))
        bound = changed["main"]["evidence"][0]
        route = json.loads(
            base64.b64decode(
                bound["observation"]["route_capture"]["base64"], validate=True
            )
        )
        route["source_artifacts"]["collector"]["digest"] = "sha256:" + "0" * 64
        changed_raw, evidence, route_identity = _repin_route(changed, route)
        temporary, store = _store(changed_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_CAPTURE", route_identity),
            patch.object(subject, "_verify_retained_evidence", return_value=changed_raw),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_v2_aggregate_fresh_session(
                evidence_cas=store
            )

    def test_hostile_coordinated_route_exit_type_repins_fail_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        for label, value in (("bool", False), ("float", 0.0)):
            with self.subTest(label=label):
                changed = deepcopy(json.loads(raw))
                bound = changed["main"]["evidence"][0]
                route = json.loads(
                    base64.b64decode(
                        bound["observation"]["route_capture"]["base64"],
                        validate=True,
                    )
                )
                route["route_observation"]["execution"]["exit_code"] = value
                changed_raw, evidence, route_identity = _repin_route(changed, route)
                temporary, store = _store(changed_raw)
                self.addCleanup(temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", evidence),
                    patch.object(subject, "_ROUTE_CAPTURE", route_identity),
                    patch.object(
                        subject,
                        "_verify_retained_evidence",
                        return_value=changed_raw,
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_v2_aggregate_fresh_session(
                        evidence_cas=store
                    )

    def test_hostile_nested_numeric_aliases_fail_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        for label, mutate in (
            (
                "eligibility",
                lambda changed, route: changed["main"]["evidence"][0][
                    "observation"
                ]["decision"].__setitem__("edr_eligible", 0),
            ),
            (
                "semantic-pass",
                lambda changed, route: changed["main"]["evidence"][0][
                    "observation"
                ]["decision"].__setitem__("semantic_pass_verified", 0),
            ),
            (
                "no-new-privileges",
                lambda changed, route: route["route_observation"]["stack_before"][
                    "processes"
                ]["aragorn-agent-gateway.service"].__setitem__(
                    "no_new_privileges", True
                ),
            ),
        ):
            with self.subTest(label=label):
                changed = deepcopy(json.loads(raw))
                bound = changed["main"]["evidence"][0]
                route = json.loads(
                    base64.b64decode(
                        bound["observation"]["route_capture"]["base64"],
                        validate=True,
                    )
                )
                mutate(changed, route)
                changed_raw, evidence, route_identity = _repin_route(changed, route)
                temporary, store = _store(changed_raw)
                self.addCleanup(temporary.cleanup)
                with (
                    patch.object(subject, "_EVIDENCE", evidence),
                    patch.object(subject, "_ROUTE_CAPTURE", route_identity),
                    patch.object(
                        subject,
                        "_verify_retained_evidence",
                        return_value=changed_raw,
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_v2_aggregate_fresh_session(
                        evidence_cas=store
                    )

    def test_hostile_harness_boolean_alias_fails_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        changed = deepcopy(json.loads(raw))
        harness = changed["harness"]
        harness["document"]["container"]["host_profile"]["privileged"] = 1
        harness_raw = subject._canonical(harness["document"])
        harness["digest"] = _digest(harness_raw)
        harness["file"]["base64"] = base64.b64encode(harness_raw).decode()
        harness["file"]["bytes"] = len(harness_raw)
        harness["file"]["digest"] = _digest(harness_raw)
        harness["file"]["stat"]["size"] = len(harness_raw)
        changed_raw = subject._canonical(changed) + b"\n"
        temporary, store = _store(changed_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", _outer_identity(changed_raw)),
            patch.dict(
                subject._STATIC_OBJECTS,
                {"harness": _static_identity(harness)},
            ),
            patch.object(
                subject,
                "_verify_retained_evidence",
                return_value=changed_raw,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_v2_aggregate_fresh_session(
                evidence_cas=store
            )

    def test_hostile_route_execution_window_repin_fails_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        changed = deepcopy(json.loads(raw))
        bound = changed["main"]["evidence"][0]
        route = json.loads(
            base64.b64decode(
                bound["observation"]["route_capture"]["base64"], validate=True
            )
        )
        route["route_observation"]["execution"]["started_at"] = (
            "2026-08-27T21:18:07.500Z"
        )
        changed_raw, evidence, route_identity = _repin_route(changed, route)
        temporary, store = _store(changed_raw)
        self.addCleanup(temporary.cleanup)
        with (
            patch.object(subject, "_EVIDENCE", evidence),
            patch.object(subject, "_ROUTE_CAPTURE", route_identity),
            patch.object(
                subject,
                "_verify_retained_evidence",
                return_value=changed_raw,
            ),
            self.assertRaises(AdmissionEvidenceError),
        ):
            subject.verify_openclaw_final_v2_aggregate_fresh_session(
                evidence_cas=store
            )

    def test_duplicate_and_nonfinite_json_fail_closed(self) -> None:
        raw = _EVIDENCE.read_bytes()
        hostile = {
            "duplicate": raw.replace(b'{"adm03":', b'{"adm03":{},"adm03":', 1),
            "nonfinite": raw.replace(
                b'"adm03_not_tested_count":2',
                b'"adm03_not_tested_count":NaN',
                1,
            ),
        }
        for label, changed_raw in hostile.items():
            with self.subTest(label=label):
                temporary, store = _store(changed_raw)
                self.addCleanup(temporary.cleanup)
                identity = {
                    **subject._EVIDENCE,
                    "bytes": len(changed_raw),
                    "digest": _digest(changed_raw),
                }
                with (
                    patch.object(subject, "_EVIDENCE", identity),
                    patch.object(
                        subject,
                        "_verify_retained_evidence",
                        return_value=changed_raw,
                    ),
                    self.assertRaises(AdmissionEvidenceError),
                ):
                    subject.verify_openclaw_final_v2_aggregate_fresh_session(
                        evidence_cas=store
                    )


if __name__ == "__main__":
    unittest.main()
