"""Inert exact-prepared execution tests, never runtime or acceptance evidence."""

from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import hashlib
from io import BytesIO
import itertools
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

from aragorn import phase3_measurement_collector as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_phase3_measurement_collector as inert


_ADAPTER = None
_FAULT = None
_EXECUTIONS = []


def execute_prepared_fixture(request, mark):
    """Source-pinned test double with an observable once-only entry point."""
    _EXECUTIONS.append(deepcopy(request))
    if _FAULT == "exception":
        raise RuntimeError("inert executor failed after its entry point")
    if _FAULT == "interrupt":
        raise KeyboardInterrupt("inert interruption after executor entry")
    raw = _ADAPTER.execute(request, mark)
    if _FAULT == "remove-commitment":
        pin = request["collection_digest"]
        (_ADAPTER.STORE.root / "blobs" / "sha256" / pin[7:9] / pin[9:]).unlink()
    return raw


class PreparedMeasurementExecutionTests(unittest.TestCase):
    def setUp(self):
        # Compose only the old data constructor, never discover its test methods.
        self.fixture = inert.Phase3MeasurementCollectorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        global _ADAPTER, _FAULT, _EXECUTIONS
        _ADAPTER, _FAULT, _EXECUTIONS = self.fixture.adapter, None, []
        self.cas = self.fixture.cas
        self.pins = {
            **self.fixture.pins,
            "execute": "sha256:"
            + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
        self.callbacks = {
            "execute": execute_prepared_fixture,
            "verify": inert.verify_test_receipt,
            "identity_reader": self.fixture.adapter.identity_reader,
            "source_pins": self.pins,
        }
        with patch.object(subject, "_boottime_ns", side_effect=[100, 200]):
            self.prepared = subject.prepare_phase3_measurement_collection(
                self.fixture.schedule,
                deployment=self.fixture.deployment,
                evidence_cas=self.cas,
                **self.callbacks,
            )
        self.raw = canonical_json(self.prepared)
        self.pin = self.cas.put(BytesIO(self.raw), max_bytes=len(self.raw))
        self.request = {
            "kind": "attempt",
            "attempt_id": "attempt-001",
            "family": "EXFILTRATION",
            "negative_control": False,
            "collection_digest": self.prepared["commitment_digest"],
            "deployment_digest": canonical_digest(self.fixture.deployment),
        }

    @property
    def claim(self):
        return (
            self.cas.root
            / subject._PREPARED_CLAIMS
            / (self.prepared["commitment_digest"][7:] + ".json")
        )

    def arguments(self, **updates):
        return {
            "expected_preparation_digest": self.pin,
            "scheduled_request": deepcopy(self.request),
            "evidence_cas": self.cas,
            **self.callbacks,
            **updates,
        }

    def execute(self, *, raw=None, **updates):
        with (
            patch.object(
                subject, "_boottime_ns", side_effect=itertools.count(300, 100)
            ),
            patch.object(
                subject,
                "prepare_phase3_measurement_collection",
                side_effect=AssertionError(
                    "prepared execution regenerated its commitment"
                ),
            ),
            patch.object(
                subject,
                "collect_phase3_measurements",
                side_effect=AssertionError("single attempt launched a full campaign"),
            ),
        ):
            return subject.collect_prepared_phase3_attempt(
                self.raw if raw is None else raw, **self.arguments(**updates)
            )

    def callback_calls(self, operation, on_call=None):
        codes = {
            function.__code__: name
            for name, function in self.callbacks.items()
            if name in {"execute", "verify", "identity_reader"}
        }
        calls = []

        def profile(frame, event, _argument):
            if event == "call" and frame.f_code in codes:
                calls.append(codes[frame.f_code])
                if on_call is not None:
                    on_call(codes[frame.f_code])

        previous = sys.getprofile()
        sys.setprofile(profile)
        try:
            operation()
        finally:
            sys.setprofile(previous)
        return calls

    def test_one_attributed_attempt_preserves_original_commitment_and_false_ceilings(
        self,
    ):
        results = []
        claim_observations = []

        def claimed_before_callback(name):
            raw = self.claim.read_bytes()
            claim_observations.append((name, raw))
            self.assertEqual(
                json.loads(raw)["commitment_digest"], self.prepared["commitment_digest"]
            )
            self.assertEqual(stat.S_IMODE(self.claim.stat().st_mode), 0o400)

        calls = self.callback_calls(
            lambda: results.append(self.execute()), claimed_before_callback
        )
        result = results[0]
        self.assertEqual(calls.count("execute"), 1)
        self.assertEqual(calls.count("verify"), 1)
        self.assertGreater(calls.count("identity_reader"), 0)
        self.assertEqual(len({raw for _, raw in claim_observations}), 1)
        self.assertEqual(_EXECUTIONS, [self.request])
        self.assertEqual(self.fixture.adapter.CALLS, [self.request])
        self.assertEqual(
            result["schema"], "aragorn/phase3-prepared-attempt-collection/v1"
        )
        self.assertEqual(result["preparation_digest"], self.pin)
        self.assertEqual(
            result["commitment_digest"], self.prepared["commitment_digest"]
        )
        self.assertEqual(result["commitment_readback_boottime_ns"], 200)
        self.assertEqual(result["request"], self.request)
        self.assertEqual(result["request_digest"], canonical_digest(self.request))
        self.assertEqual(
            tuple(result["boundaries"]), ("REQUEST_ACCEPTED", "DECISION_FINALIZED")
        )
        self.assertGreater(result["boundaries"]["REQUEST_ACCEPTED"], 200)
        self.assertGreater(
            result["boundaries"]["DECISION_FINALIZED"],
            result["boundaries"]["REQUEST_ACCEPTED"],
        )
        self.assertEqual(
            result["semantics"],
            {"attributed": True, "blocked_pre_effect": True, "residue_detected": False},
        )
        self.assertEqual(
            result["decision"],
            dict.fromkeys(
                (
                    "phase3_exit_eligible",
                    "run_eligible",
                    "quantitative_metrics_eligible",
                    "generic_collector_semantics_eligible",
                ),
                False,
            ),
        )
        receipt = json.loads(self.cas.read(result["receipt_digest"]))
        verified = json.loads(self.cas.read(result["verified_observation_digest"]))
        self.assertEqual(receipt["boundaries"], result["boundaries"])
        self.assertEqual(verified["semantics"], result["semantics"])
        self.assertEqual(self.cas.read(self.pin), self.raw)
        self.assertEqual(
            self.cas.read(result["commitment_digest"]),
            canonical_json(self.prepared["commitment"]),
        )
        retained = dict(result)
        retained.pop("collection_digest")
        self.assertEqual(
            self.cas.read(result["collection_digest"]), canonical_json(retained)
        )
        claim_raw = self.claim.read_bytes()
        self.assertEqual(
            "sha256:" + hashlib.sha256(claim_raw).hexdigest(), result["claim_digest"]
        )
        self.assertEqual(self.claim.stat().st_nlink, 1)
        self.assertEqual(stat.S_IMODE(self.claim.stat().st_mode) & 0o222, 0)
        self.assertEqual(stat.S_IMODE(self.claim.parent.stat().st_mode), 0o700)
        self.assertTrue(any("BOOT" in item for item in result["limitations"]))

    def test_successful_commitment_cannot_be_replayed_or_rebound_to_another_attempt(
        self,
    ):
        self.execute()
        retained = self.claim.read_bytes()
        for request in (self.request, {**self.request, "attempt_id": "attempt-002"}):

            def refuse():
                with self.assertRaises(subject.Phase3MeasurementCollectionError):
                    self.execute(scheduled_request=request)

            with self.subTest(attempt=request["attempt_id"]):
                self.assertEqual(self.callback_calls(refuse), [])
                self.assertEqual(self.claim.read_bytes(), retained)
                self.assertEqual(_EXECUTIONS, [self.request])

    def test_failed_or_interrupted_effect_keeps_claim_and_never_invokes_callback_again(
        self,
    ):
        global _FAULT
        # Independent inert commitments keep failure and interruption assertions
        # separate without clearing or reusing any claim.
        for mode, error in (
            ("exception", subject.Phase3MeasurementCollectionError),
            ("interrupt", KeyboardInterrupt),
        ):
            if mode == "interrupt":
                self.fixture.adapter.CALLS.clear()
                with patch.object(subject, "_boottime_ns", side_effect=[100, 200]):
                    self.prepared = subject.prepare_phase3_measurement_collection(
                        self.fixture.schedule,
                        deployment=self.fixture.deployment,
                        evidence_cas=self.cas,
                        **self.callbacks,
                    )
                self.raw = canonical_json(self.prepared)
                self.pin = self.cas.put(BytesIO(self.raw), max_bytes=len(self.raw))
                self.request["collection_digest"] = self.prepared["commitment_digest"]
            _FAULT = mode
            with self.subTest(mode=mode), self.assertRaises(error):
                self.execute()
            self.assertTrue(self.claim.is_file())
            retained = self.claim.read_bytes()
            entries = len(_EXECUTIONS)
            _FAULT = None

            def refuse():
                with self.assertRaises(subject.Phase3MeasurementCollectionError):
                    self.execute()

            self.assertEqual(self.callback_calls(refuse), [])
            self.assertEqual(len(_EXECUTIONS), entries)
            self.assertEqual(self.claim.read_bytes(), retained)

    def test_task_negative_control_and_changed_request_are_refused_before_callbacks(
        self,
    ):
        for changed in (
            {**self.request, "kind": "task"},
            {**self.request, "attempt_id": "attempt-000", "negative_control": True},
            {**self.request, "attempt_id": "uncommitted"},
            {**self.request, "family": "DESTRUCTIVE"},
            {**self.request, "negative_control": 0},
            {**self.request, "collection_digest": "sha256:" + "0" * 64},
            {**self.request, "deployment_digest": "sha256:" + "0" * 64},
            {**self.request, "command": "unapproved"},
        ):

            def refuse():
                with self.assertRaises(subject.Phase3MeasurementCollectionError):
                    self.execute(scheduled_request=changed)

            with self.subTest(request=changed):
                self.assertEqual(self.callback_calls(refuse), [])
                self.assertFalse(self.claim.exists())
        self.assertEqual(_EXECUTIONS, [])

    def test_preparation_pin_canonicality_claims_and_source_expectations_are_required(
        self,
    ):
        for updates in (
            {"raw": self.raw + b"\n"},
            {"expected_preparation_digest": "sha256:" + "0" * 64},
            {"source_pins": {**self.pins, "execute": "sha256:" + "0" * 64}},
            {"evidence_cas": CAS(self.cas.root, read_only=True)},
        ):

            def refuse():
                with self.assertRaises(subject.Phase3MeasurementCollectionError):
                    self.execute(**updates)

            with self.subTest(fields=list(updates)):
                self.assertEqual(self.callback_calls(refuse), [])
                self.assertFalse(self.claim.exists())
        for field, value in (
            ("schema", "other"),
            ("authority", "QUALIFIED"),
            ("decision", {**self.prepared["decision"], "measurement_collected": True}),
            ("commitment_readback_boottime_ns", 99),
        ):
            changed = {**self.prepared, field: value}
            raw = canonical_json(changed)
            pin = self.cas.put(BytesIO(raw), max_bytes=len(raw))

            def refuse():
                with self.assertRaises(subject.Phase3MeasurementCollectionError):
                    self.execute(raw=raw, expected_preparation_digest=pin)

            with self.subTest(field=field):
                self.assertEqual(self.callback_calls(refuse), [])
                self.assertFalse(self.claim.exists())
        self.assertEqual(_EXECUTIONS, [])

    def test_incomplete_or_substituted_existing_claim_is_not_repaired(self):
        self.claim.parent.mkdir(mode=0o700)
        self.claim.write_bytes(b"inert partial claim")
        self.claim.chmod(0o400)
        before = self.claim.stat(), self.claim.read_bytes()

        def refuse():
            with self.assertRaises(subject.Phase3MeasurementCollectionError):
                self.execute()

        self.assertEqual(self.callback_calls(refuse), [])
        after = self.claim.stat(), self.claim.read_bytes()
        self.assertEqual((after[0].st_ino, after[1]), (before[0].st_ino, before[1]))
        self.assertEqual(_EXECUTIONS, [])

    def test_out_of_order_boundary_keeps_once_only_claim(self):
        # Exercise the strict callback-boundary check without a campaign.
        self.fixture.adapter.FAULT = "boundary"
        with self.assertRaises(subject.Phase3MeasurementCollectionError):
            self.execute()
        self.assertEqual(_EXECUTIONS, [self.request])
        self.assertTrue(self.claim.is_file())
        self.fixture.adapter.FAULT = None
        with self.assertRaises(subject.Phase3MeasurementCollectionError):
            self.execute()
        self.assertEqual(_EXECUTIONS, [self.request])

    def test_identity_callback_custody_loss_prevents_executor_entry(self):
        removed = []

        def remove_report(name):
            if name == "identity_reader" and not removed:
                path = self.cas.root / "blobs" / "sha256" / self.pin[7:9] / self.pin[9:]
                path.unlink()
                removed.append(self.pin)

        def refuse():
            with self.assertRaises(subject.Phase3MeasurementCollectionError):
                self.execute()

        self.assertEqual(
            self.callback_calls(refuse, remove_report), ["identity_reader"]
        )
        self.assertEqual(removed, [self.pin])
        self.assertEqual(_EXECUTIONS, [])
        self.assertTrue(self.claim.is_file())

    def test_unsafe_claim_directory_is_not_followed_or_repaired(self):
        outside = self.cas.root.parent / "inert-outside"
        outside.mkdir(mode=0o700)
        self.claim.parent.symlink_to(outside, target_is_directory=True)

        def refuse():
            with self.assertRaises(subject.Phase3MeasurementCollectionError):
                self.execute()

        self.assertEqual(self.callback_calls(refuse), [])
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(self.claim.parent.is_symlink())
        self.assertEqual(_EXECUTIONS, [])

    def test_claim_cleanup_attempts_all_descriptors_and_preserves_primary_error(self):
        close = os.close
        for interrupted in (False, True):
            closed = []
            close_error = OSError("inert first descriptor close failure")
            body_error = KeyboardInterrupt("inert primary body interruption")
            commitment_pin = canonical_digest({"inert_cleanup_case": interrupted})
            claim = {
                "schema": "aragorn/phase3-prepared-attempt-claim/v1",
                "preparation_digest": self.pin,
                "commitment_digest": commitment_pin,
                "request_digest": canonical_digest(self.request),
                "claimed_boottime_ns": 300,
                "state": "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
            }

            def fail_first(fd):
                close(fd)
                closed.append(fd)
                if len(closed) == 1:
                    raise close_error

            with (
                self.subTest(interrupted=interrupted),
                self.assertRaises(
                    KeyboardInterrupt if interrupted else OSError
                ) as refusal,
                ExitStack() as patches,
            ):
                with subject._prepared_attempt_claim(self.cas, claim):
                    # Patch only after real descriptors are acquired; close each
                    # for real before the injected error so the test leaks none.
                    patches.enter_context(
                        patch.object(subject.os, "close", side_effect=fail_first)
                    )
                    if interrupted:
                        raise body_error
            self.assertIs(refusal.exception, body_error if interrupted else close_error)
            self.assertEqual(len(closed), 3)
            self.assertEqual(len(set(closed)), 3)
            for fd in closed:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            path = (
                self.cas.root
                / subject._PREPARED_CLAIMS
                / (commitment_pin[7:] + ".json")
            )
            self.assertEqual(path.read_bytes(), canonical_json(claim))

    def test_final_retained_result_loss_prevents_return_and_preserves_claim(self):
        store = subject._store
        removed = []

        def remove_result(cas, raw, limit):
            pin = store(cas, raw, limit)
            if (
                json.loads(raw).get("schema")
                == "aragorn/phase3-prepared-attempt-collection/v1"
            ):
                (cas.root / "blobs" / "sha256" / pin[7:9] / pin[9:]).unlink()
                removed.append(pin)
            return pin

        with (
            patch.object(subject, "_store", side_effect=remove_result),
            self.assertRaises(subject.Phase3MeasurementCollectionError),
        ):
            self.execute()
        self.assertEqual(len(removed), 1)
        self.assertEqual(_EXECUTIONS, [self.request])
        self.assertTrue(self.claim.is_file())
        with self.assertRaises(subject.Phase3MeasurementCollectionError):
            self.execute()
        self.assertEqual(_EXECUTIONS, [self.request])

    def test_later_identity_callback_cannot_mutate_verified_result_alias(self):
        # A profiler retains the actual verifier-owned return object; the next
        # identity callback mutates that alias, not the collector's detached copy.
        aliases = []
        mutations = []

        def profile(frame, event, argument):
            if event == "return" and frame.f_code is inert.verify_test_receipt.__code__:
                aliases.append(argument)
            elif (
                event == "call"
                and frame.f_code is self.fixture.adapter.identity_reader.__code__
                and aliases
                and not mutations
            ):
                aliases[0]["semantics"]["blocked_pre_effect"] = False
                aliases[0]["semantics"]["residue_detected"] = True
                mutations.append(True)

        previous = sys.getprofile()
        sys.setprofile(profile)
        try:
            result = self.execute()
        finally:
            sys.setprofile(previous)
        self.assertEqual(mutations, [True])
        self.assertEqual(len(aliases), 1)
        expected = {
            "attributed": True,
            "blocked_pre_effect": True,
            "residue_detected": False,
        }
        self.assertNotEqual(aliases[0]["semantics"], expected)
        self.assertEqual(result["semantics"], expected)
        retained = json.loads(self.cas.read(result["verified_observation_digest"]))
        self.assertEqual(retained["semantics"], expected)
        self.assertEqual(_EXECUTIONS, [self.request])

    def test_retained_input_loss_after_execution_keeps_claim_without_success(self):
        global _FAULT
        _FAULT = "remove-commitment"
        with self.assertRaises(subject.Phase3MeasurementCollectionError):
            self.execute()
        self.assertEqual(_EXECUTIONS, [self.request])
        self.assertTrue(self.claim.is_file())
        before = self.claim.read_bytes()
        _FAULT = None
        with self.assertRaises(subject.Phase3MeasurementCollectionError):
            self.execute()
        self.assertEqual(_EXECUTIONS, [self.request])
        self.assertEqual(self.claim.read_bytes(), before)

    def test_legacy_collect_still_uses_attempt_and_task_sampler_contract(self):
        # One newly affected compatibility case for the shared sampler. All 300
        # callbacks and clock readings are inert doubles, not acceptance samples.
        with patch.object(
            subject, "_boottime_ns", side_effect=itertools.count(300, 100)
        ):
            result = subject.collect_phase3_measurements(
                self.fixture.schedule,
                deployment=self.fixture.deployment,
                evidence_cas=self.cas,
                **self.callbacks,
            )
        self.assertEqual(len(_EXECUTIONS), 300)
        self.assertEqual(len(result["provenance"]), 300)
        self.assertEqual(sum(row["kind"] == "attempt" for row in _EXECUTIONS), 100)
        self.assertEqual(sum(row["kind"] == "task" for row in _EXECUTIONS), 200)
        evidence = json.loads(self.cas.read(result["evidence_digest"]))
        self.assertEqual(len(evidence["attempts"]), 100)
        self.assertEqual(len(evidence["baseline_samples"]), 100)
        self.assertEqual(len(evidence["instrumented_samples"]), 100)
        self.assertEqual(result["metrics_qualification"]["decision"]["status"], "PASS")
        self.assertFalse(self.claim.exists())
        for row in evidence["attempts"]:
            self.assertGreater(
                row["decision_finalized_boottime_ns"],
                row["request_accepted_boottime_ns"],
            )
        for row in evidence["baseline_samples"] + evidence["instrumented_samples"]:
            self.assertGreater(row["completed_boottime_ns"], row["started_boottime_ns"])


if __name__ == "__main__":
    unittest.main()
