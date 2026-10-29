"""Only new prepared-to-native input checks, using inert existing data fixtures."""

from copy import deepcopy
from io import BytesIO
import unittest
from unittest.mock import patch

from aragorn import runtime_native_measurement_inputs as subject
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_runtime_broker_measurement_plan as fixtures


class NativeMeasurementInputTests(unittest.TestCase):
    def fixture(self):
        # Use only the data constructor, not inheritance/discovery of old tests.
        fixture = fixtures.BrokerMeasurementPlanTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        prepared = fixtures.subject.prepare_broker_decision_measurement_binding(
            **fixture.arguments
        )
        return fixture, prepared

    def arguments(self, fixture, prepared):
        return {
            "prepared_raw": canonical_json(prepared),
            "expected_prepared_digest": canonical_digest(prepared),
            "expected_binding_digest": prepared["binding_digest"],
            "expected_broker_source_pins": deepcopy(
                fixture.arguments["expected_broker_source_pins"]
            ),
            "source_cas": CAS(fixture.arguments["target_cas"].root, read_only=True),
        }

    def refuse(self, fixture, prepared, **updates):
        arguments = self.arguments(fixture, prepared)
        arguments.update(updates)
        with self.assertRaises(subject.NativeMeasurementInputError):
            subject.validate_prepared_native_measurement_inputs(**arguments)

    def test_exact_prepared_closure_is_read_only_and_not_live_authority(self):
        fixture, prepared = self.fixture()
        with (
            patch.object(CAS, "put", side_effect=AssertionError("no input write")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("no input write")
            ),
            patch(
                "time.clock_gettime_ns", side_effect=AssertionError("no measurement")
            ),
            patch("time.time", side_effect=AssertionError("no liveness claim")),
        ):
            resolved = subject.validate_prepared_native_measurement_inputs(
                **self.arguments(fixture, prepared)
            )
        self.assertEqual(resolved["binding_raw"], canonical_json(prepared["binding"]))
        self.assertEqual(resolved["prepared_digest"], canonical_digest(prepared))
        self.assertEqual(resolved["binding_digest"], prepared["binding_digest"])
        self.assertEqual(
            resolved["scheduled_request"], fixture.arguments["scheduled_request"]
        )
        self.assertEqual(len(resolved["input_blobs"]), 13)
        self.assertEqual(
            [
                {"digest": pin, "bytes": len(raw)}
                for pin, raw in sorted(resolved["input_blobs"].items())
            ],
            prepared["input_blobs"],
        )
        self.assertNotIn("measurement_collected", resolved)
        self.assertNotIn("deployed", resolved)
        self.assertEqual(resolved["path_descriptor"]["target_name"], "inert.txt")
        self.assertEqual(resolved["grant"]["issued_at_unix"], 1)

    def test_report_pin_binding_pin_source_pin_and_read_only_mode_required(self):
        fixture, prepared = self.fixture()
        self.refuse(fixture, prepared, expected_prepared_digest=fixtures.PIN)
        self.refuse(fixture, prepared, expected_binding_digest=fixtures.PIN)
        self.refuse(fixture, prepared, source_cas=fixture.arguments["target_cas"])
        self.refuse(fixture, prepared, source_cas=None)
        sources = deepcopy(fixture.arguments["expected_broker_source_pins"])
        sources["runtime_action_broker.py"] = "sha256:" + "b" * 64
        self.refuse(fixture, prepared, expected_broker_source_pins=sources)
        self.refuse(fixture, prepared, prepared_raw=canonical_json(prepared) + b"\n")

    def test_rehashed_inventory_changes_do_not_copy_arbitrary_blobs(self):
        fixture, prepared = self.fixture()
        for mutation in (
            "missing",
            "extra",
            "size",
            "float",
            "duplicate",
            "order",
            "field",
        ):
            changed = deepcopy(prepared)
            rows = changed["input_blobs"]
            if mutation == "missing":
                rows.pop()
            elif mutation == "extra":
                rows.append({"digest": fixtures.PIN, "bytes": 1})
            elif mutation == "size":
                rows[0]["bytes"] += 1
            elif mutation == "float":
                rows[0]["bytes"] = float(rows[0]["bytes"])
            elif mutation == "duplicate":
                rows.append(rows[0])
            elif mutation == "order":
                rows.reverse()
            else:
                rows[0]["path"] = "/arbitrary"
            with self.subTest(mutation=mutation):
                self.refuse(fixture, changed)

    def test_rehashed_authority_and_eligibility_changes_refuse(self):
        fixture, prepared = self.fixture()
        for field, value in (
            ("schema", "other"),
            ("authority", "PROVISIONED"),
            ("limitations", []),
            ("binding_digest", fixtures.PIN),
            ("decision", {**prepared["decision"], "deployed": True}),
            ("decision", {**prepared["decision"], "deployed": 0}),
        ):
            with self.subTest(field=field):
                self.refuse(fixture, {**prepared, field: value})

    def test_rehashed_binding_change_requires_retained_binding_and_grant_joins(self):
        fixture, prepared = self.fixture()
        changed = deepcopy(prepared)
        changed["binding"]["runtime_digest"] = "sha256:" + "b" * 64
        changed["binding_digest"] = canonical_digest(changed["binding"])
        target = fixture.arguments["target_cas"]
        target.put(BytesIO(canonical_json(changed["binding"])), max_bytes=4096)
        # The changed binding exists; refusal must precede the later inventory check.
        with patch.object(
            subject,
            "parse_runtime_capability_grant",
            wraps=subject.parse_runtime_capability_grant,
        ) as parse:
            self.refuse(fixture, changed)
        parse.assert_called_once()

    def test_unattributed_schedule_and_shared_callbacks_are_refused(self):
        fixture, prepared = self.fixture()
        negative = {**fixture.arguments["scheduled_request"], "negative_control": True}
        with patch.object(
            subject.retained, "_scheduled_request", return_value=negative
        ):
            self.refuse(fixture, prepared)
        # Rebuild commitment/binding edges, retaining genuine hashes, for a source
        # identity collision which the older low-level schedule reader permits.
        target = fixture.arguments["target_cas"]
        binding = deepcopy(prepared["binding"])
        commitment = subject.retained._parse(
            target.read(binding["collection_commitment_digest"]), subject._LIMIT
        )
        commitment["sources"]["verify"] = deepcopy(commitment["sources"]["execute"])
        binding["collection_commitment_digest"] = target.put(
            BytesIO(canonical_json(commitment)), max_bytes=subject._LIMIT
        )
        scheduled = {
            **fixture.arguments["scheduled_request"],
            "collection_digest": binding["collection_commitment_digest"],
        }
        binding["scheduled_measurement_request_digest"] = canonical_digest(scheduled)
        changed = {
            **prepared,
            "binding": binding,
            "binding_digest": canonical_digest(binding),
        }
        target.put(BytesIO(canonical_json(binding)), max_bytes=4096)
        with self.assertRaisesRegex(subject.NativeMeasurementInputError, "callbacks"):
            subject.validate_prepared_native_measurement_inputs(
                **self.arguments(fixture, changed)
            )

    def test_missing_blob_and_final_readback_loss_refuse(self):
        fixture, prepared = self.fixture()
        arguments = self.arguments(fixture, prepared)
        store = arguments["source_cas"]
        selected = prepared["binding"]["path_digest"]
        original = store.read
        for fail_on in (1, 2):
            calls = {"selected": 0}

            def read(pin, *, max_bytes):
                if pin == selected:
                    calls["selected"] += 1
                    if calls["selected"] == fail_on:
                        raise CASError("inert custody loss")
                return original(pin, max_bytes=max_bytes)

            with (
                self.subTest(fail_on=fail_on),
                patch.object(store, "read", side_effect=read),
                self.assertRaises(subject.NativeMeasurementInputError),
            ):
                subject.validate_prepared_native_measurement_inputs(**arguments)
            self.assertEqual(calls["selected"], fail_on)


if __name__ == "__main__":
    unittest.main()
