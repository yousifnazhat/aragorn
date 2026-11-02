"""New preparation/custody cases using inert unit doubles, not runtime evidence."""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from aragorn import phase3_measurement_collector as collector
from aragorn.oci_worker_protocol import canonical_json
from tests import test_phase3_measurement_collector as inert_fixture

_STORE = None
_FIRST_RECEIPT = None
_DROP_ON_FINAL = False


def verify_preparation_fixture(raw, request, boundaries):
    """Synthetic verifier fault removes one earlier retained unit-fixture receipt."""
    global _FIRST_RECEIPT
    verified = inert_fixture.verify_test_receipt(raw, request, boundaries)
    if _FIRST_RECEIPT is None:
        _FIRST_RECEIPT = verified["receipt_digest"]
    if (
        _DROP_ON_FINAL
        and request.get("pair_id") == "pair-099"
        and request.get("mode") == "instrumented"
    ):
        digest = _FIRST_RECEIPT
        (_STORE.root / "blobs" / "sha256" / digest[7:9] / digest[9:]).unlink()
    return verified


class Phase3MeasurementPreparationTests(unittest.TestCase):
    def setUp(self):
        # Reuse only existing inert fixture setup; never discover/run its tests.
        self.fixture = inert_fixture.Phase3MeasurementCollectorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        global _STORE, _FIRST_RECEIPT, _DROP_ON_FINAL
        _STORE = self.fixture.cas
        _FIRST_RECEIPT = None
        _DROP_ON_FINAL = False
        self.pins = {
            **self.fixture.pins,
            "verify": "sha256:"
            + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }
        self.kwargs = {
            "deployment": self.fixture.deployment,
            "evidence_cas": self.fixture.cas,
            "execute": self.fixture.adapter.execute,
            "verify": verify_preparation_fixture,
            "identity_reader": self.fixture.adapter.identity_reader,
            "source_pins": self.pins,
        }

    def _callback_calls(self, operation):
        codes = {
            function.__code__: name
            for name, function in self.kwargs.items()
            if name in {"execute", "verify", "identity_reader"}
        }
        calls = []

        def profile(frame, event, _argument):
            if event == "call" and frame.f_code in codes:
                calls.append(codes[frame.f_code])

        previous = sys.getprofile()
        sys.setprofile(profile)
        try:
            return operation(), calls
        finally:
            sys.setprofile(previous)

    def test_preparation_retains_exact_commitment_without_invoking_callbacks(self):
        with patch.object(collector, "_boottime_ns", side_effect=[100, 200]):
            prepared, calls = self._callback_calls(
                lambda: collector.prepare_phase3_measurement_collection(
                    self.fixture.schedule, **self.kwargs
                )
            )
        self.assertEqual(calls, [])
        self.assertEqual(self.fixture.adapter.CALLS, [])
        self.assertEqual(prepared["commitment_readback_boottime_ns"], 200)
        self.assertEqual(prepared["commitment"]["prepared_boottime_ns"], 100)
        self.assertEqual(
            self.fixture.cas.read(prepared["commitment_digest"]),
            canonical_json(prepared["commitment"]),
        )
        self.assertEqual(
            self.fixture.cas.read(prepared["schedule_digest"]),
            canonical_json(self.fixture.schedule),
        )
        self.assertEqual(set(prepared["sources"]), set(self.pins))
        for name, digest in self.pins.items():
            self.assertEqual(prepared["sources"][name]["digest"], digest)
        self.assertTrue(all(value is False for value in prepared["decision"].values()))
        self.assertIn("NOT_EXECUTION_LIVE_IDENTITY", prepared["authority"])
        self.fixture.schedule["attempt_schedule"]["attempt_ids"].clear()
        self.fixture.deployment["bindings"]["policy"] = "sha256:" + "f" * 64
        self.assertEqual(
            len(prepared["schedule"]["attempt_schedule"]["attempt_ids"]), 100
        )
        self.assertNotEqual(
            prepared["deployment"]["bindings"]["policy"], "sha256:" + "f" * 64
        )

    def test_preparation_refuses_non_linux_clock_without_invoking_callbacks(self):
        def refused():
            with self.assertRaisesRegex(
                collector.Phase3MeasurementCollectionError, "CLOCK_BOOTTIME"
            ):
                collector.prepare_phase3_measurement_collection(
                    self.fixture.schedule, **self.kwargs
                )

        with patch.object(collector.sys, "platform", "darwin"):
            _, calls = self._callback_calls(refused)
        self.assertEqual(calls, [])
        self.assertEqual(self.fixture.adapter.CALLS, [])

    def test_collector_refuses_dangling_earlier_sample_before_publication(self):
        global _DROP_ON_FINAL
        _DROP_ON_FINAL = True
        with (
            patch.object(
                collector, "_boottime_ns", side_effect=itertools.count(1, 100)
            ),
            patch.object(collector, "_store", wraps=collector._store) as stored,
            self.assertRaisesRegex(
                collector.Phase3MeasurementCollectionError,
                "sample receipt left custody",
            ),
        ):
            collector.collect_phase3_measurements(self.fixture.schedule, **self.kwargs)
        self.assertEqual(len(self.fixture.adapter.CALLS), 300)
        self.assertIsNotNone(_FIRST_RECEIPT)
        self.assertFalse(
            any(
                json.loads(call.args[1]).get("schema")
                == "aragorn/phase3-measurement-collection/v1"
                for call in stored.call_args_list
            )
        )


if __name__ == "__main__":
    unittest.main()
