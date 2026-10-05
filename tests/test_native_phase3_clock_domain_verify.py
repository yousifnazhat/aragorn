"""Inert clock-domain dictionaries only; no live clock or acceptance samples."""

from copy import deepcopy
import hashlib
import unittest

from aragorn import native_phase3_clock_domain_verify as subject
from aragorn.oci_worker_protocol import canonical_json


BOOT = "00000000-0000-0000-0000-000000000001"
WORKER = {"pid": 200, "start_time_ticks": 1000, "uid": 993, "gid": 993}
BROKER = {"pid": 201, "start_time_ticks": 1001, "uid": 994, "gid": 993}


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _fixture():
    namespace = {"device": 4, "inode": 4026531834}
    before = {
        "schema": "aragorn/native-phase3-clock-domain/v1",
        "authority": "LOCAL_ROOT_PROCESS_TIME_NAMESPACE_READBACK_NOT_REQUEST_EVENTS_OR_ATTESTATION",
        "clock_id": "CLOCK_BOOTTIME",
        "boot_id": BOOT,
        "read_started_boottime_ns": 100,
        "read_finished_boottime_ns": 200,
        "processes": {
            "collector": {
                "pid": 100,
                "start_time_ticks": 900,
                "uid": 0,
                "gid": 0,
                "time_namespace": dict(namespace),
            },
            "worker": {**WORKER, "time_namespace": dict(namespace)},
            "broker": {**BROKER, "time_namespace": dict(namespace)},
        },
        "limitations": [
            "EXTERNAL_ROOT_OBSERVER_NOT_IN_PROCESS_REQUEST_OR_DECISION_TIMESTAMPS",
            "POINT_IN_TIME_READ_BRACKETS_NOT_CONTINUOUS_PROCESS_OR_NAMESPACE_IMMUTABILITY",
            "ACTIVE_TIME_NAMESPACE_IDENTITIES_ONLY_NO_OFFSET_TRANSLATION",
            "LOCAL_ROOT_PROC_READBACK_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
            "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
        ],
        **dict.fromkeys(
            (
                "common_deployment_fully_verified",
                "route_qualified",
                "phase3_eligible",
                "live_deployment_attested",
                "metrics_eligible",
                "application_acknowledged",
            ),
            False,
        ),
    }
    after = deepcopy(before)
    after.update(read_started_boottime_ns=300, read_finished_boottime_ns=400)
    return before, after


class NativeCommonClockDomainVerificationTests(unittest.TestCase):
    def setUp(self):
        self.before, self.after = _fixture()

    def verify(self, before=None, after=None, **changes):
        before_raw = canonical_json(self.before if before is None else before)
        after_raw = canonical_json(self.after if after is None else after)
        arguments = {
            "expected_before_digest": _digest(before_raw),
            "expected_after_digest": _digest(after_raw),
            "expected_worker": dict(WORKER),
            "expected_broker": dict(BROKER),
            **changes,
        }
        return subject.verify_native_common_clock_domain(
            before_raw, after_raw, **arguments
        )

    def test_retained_shared_domain_has_exact_observation_pins_and_false_ceilings(self):
        result = self.verify()
        self.assertEqual(result["status"], "RETAINED_COMMON_CLOCK_DOMAIN_VERIFIED")
        self.assertEqual(result["schema"], subject.SCHEMA)
        self.assertEqual(result["authority"], subject.AUTHORITY)
        self.assertEqual(result["before_digest"], _digest(canonical_json(self.before)))
        self.assertEqual(result["after_digest"], _digest(canonical_json(self.after)))
        self.assertEqual(
            result["clock_domain"],
            {
                "clock_id": "CLOCK_BOOTTIME",
                "boot_id": BOOT,
                "time_namespace": {"device": 4, "inode": 4026531834},
            },
        )
        self.assertEqual(
            result["read_brackets"],
            {
                "before": {"started_boottime_ns": 100, "finished_boottime_ns": 200},
                "after": {"started_boottime_ns": 300, "finished_boottime_ns": 400},
            },
        )
        self.assertEqual(result["processes"], self.before["processes"])
        self.assertTrue(all(result[key] is False for key in subject.FALSE_FLAGS))
        self.assertEqual(result["limitations"], list(subject.LIMITATIONS))
        self.assertNotIn("elapsed_ns", result)
        self.assertNotIn("independent_acquisition_complete", result)
        result["processes"]["worker"]["uid"] = 1
        self.assertEqual(self.before["processes"]["worker"]["uid"], WORKER["uid"])

    def test_zero_device_and_touching_brackets_are_accepted(self):
        for value in (self.before, self.after):
            for process in value["processes"].values():
                process["time_namespace"]["device"] = 0
        self.after["read_started_boottime_ns"] = 200
        self.assertEqual(self.verify()["clock_domain"]["time_namespace"]["device"], 0)

    def test_namespace_mismatch_or_replacement_is_refused(self):
        for side in ("before", "after"):
            for role in ("collector", "worker", "broker"):
                for field in ("device", "inode"):
                    before, after = _fixture()
                    selected = before if side == "before" else after
                    selected["processes"][role]["time_namespace"][field] += 1
                    with (
                        self.subTest(side=side, role=role, field=field),
                        self.assertRaisesRegex(
                            subject.NativeCommonClockDomainVerificationError,
                            "namespaces differ",
                        ),
                    ):
                        self.verify(before, after)
        for process in self.after["processes"].values():
            process["time_namespace"]["inode"] += 1
        with self.assertRaisesRegex(
            subject.NativeCommonClockDomainVerificationError, "namespace changed"
        ):
            self.verify()

    def test_changed_boot_and_collector_epoch_are_refused(self):
        changed = deepcopy(self.after)
        changed["boot_id"] = "00000000-0000-0000-0000-000000000002"
        with self.assertRaisesRegex(
            subject.NativeCommonClockDomainVerificationError, "boot identity changed"
        ):
            self.verify(after=changed)
        for field in ("pid", "start_time_ticks"):
            changed = deepcopy(self.after)
            changed["processes"]["collector"][field] += 1
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    subject.NativeCommonClockDomainVerificationError, "epoch.*changed"
                ),
            ):
                self.verify(after=changed)

    def test_worker_broker_epochs_must_match_caller_and_each_other(self):
        for role in ("worker", "broker"):
            for field in ("pid", "start_time_ticks", "uid", "gid"):
                changed = deepcopy(self.after)
                changed["processes"][role][field] += 1
                with (
                    self.subTest(role=role, field=field),
                    self.assertRaisesRegex(
                        subject.NativeCommonClockDomainVerificationError, "caller epoch"
                    ),
                ):
                    self.verify(after=changed)
        self.before["processes"]["collector"]["pid"] = WORKER["pid"]
        with self.assertRaisesRegex(
            subject.NativeCommonClockDomainVerificationError, "PIDs overlap"
        ):
            self.verify()

    def test_before_after_brackets_are_positive_ordered_and_nonoverlapping(self):
        for start, finish in (
            (100, 100),
            (101, 100),
            (-1, 100),
            (True, 200),
            (0, 2**63),
        ):
            changed = {
                **self.before,
                "read_started_boottime_ns": start,
                "read_finished_boottime_ns": finish,
            }
            with (
                self.subTest(start=start, finish=finish),
                self.assertRaisesRegex(
                    subject.NativeCommonClockDomainVerificationError,
                    "bracket is invalid",
                ),
            ):
                self.verify(before=changed)
        for start, finish in ((199, 300), (0, 50)):
            changed = {
                **self.after,
                "read_started_boottime_ns": start,
                "read_finished_boottime_ns": finish,
            }
            with (
                self.subTest(start=start),
                self.assertRaisesRegex(
                    subject.NativeCommonClockDomainVerificationError,
                    "overlap or are reversed",
                ),
            ):
                self.verify(after=changed)

    def test_booleans_and_invalid_process_namespace_scalars_are_refused(self):
        for role in ("collector", "worker", "broker"):
            for field in ("pid", "start_time_ticks", "uid", "gid"):
                for scalar in (True, -1, 2**63, "1"):
                    changed = deepcopy(self.before)
                    changed["processes"][role][field] = scalar
                    with (
                        self.subTest(role=role, field=field, scalar=scalar),
                        self.assertRaises(
                            subject.NativeCommonClockDomainVerificationError
                        ),
                    ):
                        self.verify(before=changed)
            for field, scalar in (
                ("device", True),
                ("device", -1),
                ("inode", 0),
                ("inode", 2**63),
            ):
                changed = deepcopy(self.before)
                changed["processes"][role]["time_namespace"][field] = scalar
                with (
                    self.subTest(role=role, field=field, scalar=scalar),
                    self.assertRaisesRegex(
                        subject.NativeCommonClockDomainVerificationError,
                        "namespace identity is invalid",
                    ),
                ):
                    self.verify(before=changed)
        for field in ("uid", "gid"):
            changed = deepcopy(self.before)
            changed["processes"]["collector"][field] = 1
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    subject.NativeCommonClockDomainVerificationError,
                    "not recorded as root",
                ),
            ):
                self.verify(before=changed)

    def test_exact_fields_reject_offsets_and_unsupported_namespace_roles(self):
        for field in ("timens_offsets", "time_for_children", "elapsed_ns"):
            changed = deepcopy(self.before)
            changed[field] = {"monotonic": 0, "boottime": 0}
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    subject.NativeCommonClockDomainVerificationError,
                    "observation fields changed",
                ),
            ):
                self.verify(before=changed)
        changed = deepcopy(self.before)
        changed["processes"]["worker"]["time_namespace"]["offset_ns"] = 0
        with self.assertRaisesRegex(
            subject.NativeCommonClockDomainVerificationError, "namespace fields changed"
        ):
            self.verify(before=changed)
        changed = deepcopy(self.before)
        changed["processes"]["sensor"] = deepcopy(changed["processes"]["worker"])
        with self.assertRaisesRegex(
            subject.NativeCommonClockDomainVerificationError,
            "process inventory changed",
        ):
            self.verify(before=changed)
        changed = deepcopy(self.before)
        del changed["processes"]["collector"]
        with self.assertRaisesRegex(
            subject.NativeCommonClockDomainVerificationError,
            "process inventory changed",
        ):
            self.verify(before=changed)

    def test_schema_clock_boot_limitations_and_false_flags_cannot_be_promoted(self):
        for field, value in (
            ("schema", "other"),
            ("authority", "QUALIFIED"),
            ("clock_id", "CLOCK_MONOTONIC"),
            ("boot_id", "unbound"),
            ("limitations", []),
        ):
            changed = {**self.before, field: value}
            with (
                self.subTest(field=field),
                self.assertRaises(subject.NativeCommonClockDomainVerificationError),
            ):
                self.verify(before=changed)
        for field in subject.FALSE_FLAGS:
            for value in (True, 0, None):
                changed = {**self.before, field: value}
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaisesRegex(
                        subject.NativeCommonClockDomainVerificationError,
                        "claim ceiling",
                    ),
                ):
                    self.verify(before=changed)

    def test_expected_epochs_have_no_boolean_zero_or_extra_authority_fields(self):
        for role, original in (("worker", WORKER), ("broker", BROKER)):
            for changed in (
                {**original, "uid": True},
                {**original, "pid": 0},
                {**original, "gid": 0},
                {**original, "time_namespace": {"device": 4, "inode": 1}},
            ):
                with (
                    self.subTest(role=role, changed=changed),
                    self.assertRaisesRegex(
                        subject.NativeCommonClockDomainVerificationError,
                        "expected process",
                    ),
                ):
                    self.verify(**{"expected_" + role: changed})

    def test_raw_pins_canonicality_duplicate_fields_and_numeric_encodings_are_strict(
        self,
    ):
        before_raw, after_raw = canonical_json(self.before), canonical_json(self.after)
        for raw, pin, message in (
            (before_raw, "sha256:" + "0" * 64, "caller pin"),
            (before_raw + b"\n", _digest(before_raw + b"\n"), "not canonical"),
            (b'{"x":1,"x":2}', _digest(b'{"x":1,"x":2}'), "duplicate"),
            (b'{"x":1.0}', _digest(b'{"x":1.0}'), "noninteger"),
            (b'{"x":NaN}', _digest(b'{"x":NaN}'), "noninteger"),
            (b"x" * (subject._MAX_BYTES + 1), "sha256:" + "0" * 64, "oversized"),
            (bytearray(before_raw), _digest(before_raw), "bytes are invalid"),
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(
                    subject.NativeCommonClockDomainVerificationError, message
                ),
            ):
                subject.verify_native_common_clock_domain(
                    raw,
                    after_raw,
                    expected_before_digest=pin,
                    expected_after_digest=_digest(after_raw),
                    expected_worker=WORKER,
                    expected_broker=BROKER,
                )


if __name__ == "__main__":
    unittest.main()
