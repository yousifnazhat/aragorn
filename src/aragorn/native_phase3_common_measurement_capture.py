"""Finite private-input planning and independent retained measurement replay.

Only the single grant is private. No producer, probe, transport, live fixture
observer, clock or write is invoked here. Retained process/namespace evidence
is not fresh attestation; the two existing semantic consumers keep their exact
non-qualification ceilings, including no continuous residue or policy proof.
"""

from __future__ import annotations

import json

from . import native_phase3_common_attempt_capture as public
from . import native_phase3_common_attempt_inputs as inputs
from . import native_phase3_common_process_verifier as processes
from . import native_phase3_blocked_create_verify as blocked
from . import native_phase3_ingress_interval_verify as interval
from . import runtime_broker_decision_measurement_verify as broker
from .runtime_native_measurement_inputs import (
    validate_prepared_native_measurement_inputs,
)
from .cas import CAS
from .oci_worker_protocol import canonical_json

_WORKER = public.base.live._WORKER
_GENESIS = public.base.live._GENESIS
_SINK = "/usr/lib/aragorn/aragorn/native_phase3_denied_create_sink.py"
_EPOCH = ("pid", "start_time_ticks", "uid", "gid")
_LIMIT = 1024 * 1024


class NativeCommonMeasurementCaptureError(ValueError):
    """Fixed secret-safe refusal; no credential content or exception echo."""


def _require(condition, reason):
    if not condition:
        raise NativeCommonMeasurementCaptureError(reason)


def _reader(store):
    _require(type(store) is CAS and store.read_only is True, "read-only CAS required")

    def read(pin, limit=public.MAX_PUBLIC_BLOB):
        pin = public._pin(pin)
        raw = store.read(pin, max_bytes=limit)
        _require(
            type(raw) is bytes and 0 < len(raw) <= limit and public._digest(raw) == pin,
            "retained input changed",
        )
        return raw

    return read


def _separate_stores(public_cas, private_input_cas):
    """Reject aliases and nesting before any private content is read.

    Resolving host CAS roots is custody checking, not a fixture observation.
    The capture owner remains responsible for the private destination lifetime.
    """
    _reader(public_cas)
    _reader(private_input_cas)
    public_root = public_cas.root.resolve(strict=True)
    private_root = private_input_cas.root.resolve(strict=True)
    public_stat, private_stat = public_root.stat(), private_root.stat()
    _require(
        public_root != private_root
        and public_root not in private_root.parents
        and private_root not in public_root.parents
        and (public_stat.st_dev, public_stat.st_ino)
        != (private_stat.st_dev, private_stat.st_ino),
        "disjoint private/public CAS required",
    )


def plan_native_common_measurement_inputs(capture, *, public_cas):
    """Precleanup plan of exact missing bytes, never permission to copy a tree.

    The owning host must separately guard fixture/source/private destination
    custody. No private CAS is read and no missing credential is synthesized.
    Returned grant_bytes is a length, not the grant content.
    """
    try:
        read = _reader(public_cas)
        capture = json.loads(canonical_json(capture))
        guest = capture["guest"]
        _require(
            guest["status"] == "EXPORTED_BOUNDED_ATTEMPT"
            and guest["container_id"] == capture["fixture_container"]
            and guest["input_bundle_digest"] == capture["input_bundle_digest"]
            and guest["public_export_complete"] is True
            and guest["preserve_fixture_for_evidence"] is False
            and guest["refusal"] is None
            and guest["interrupted"] is False,
            "complete original guest required",
        )
        bound = inputs.inspect_common_attempt_inputs(
            read(capture["input_bundle_digest"], inputs.MAX_BUNDLE),
            expected_bundle_digest=capture["input_bundle_digest"],
        )
        exported, roles = public._public(capture, read)
        report = guest["attempt"]
        public._attempt(
            report, bound, capture["fixture_container"], exported, roles, read
        )
        plan = report["plan"]
        prepared_raw = read(plan["measurement_prepared_digest"], 32768)
        prepared = public.base._parse(prepared_raw, 32768)
        binding_raw = canonical_json(prepared["binding"])
        binding = broker._binding(binding_raw, plan["binding_digest"])
        source_pins = json.loads(bound["stage_raw"])["binding_source_pins"]
        _require(
            binding["source_pins"] == source_pins
            and prepared["binding_digest"] == plan["binding_digest"],
            "prepared source binding changed",
        )
        blobs = {}

        def public_read(store, pin, limit=_LIMIT):
            _require(
                store is public_cas and pin in exported, "nonpublic input requested"
            )
            raw = read(pin, limit)
            _require(raw == exported[pin], "exported input changed")
            blobs[pin] = raw
            return raw

        broker._scheduled_request(binding, public_read, public_cas)
        for pin in (
            binding["deployment_identity_digest"],
            plan["binding_digest"],
            binding["path_digest"],
        ):
            public_read(public_cas, pin)
        rows = prepared["input_blobs"]
        _require(
            type(rows) is list and 1 <= len(rows) <= 13,
            "finite prepared inventory required",
        )
        declared = {}
        for row in rows:
            _require(
                type(row) is dict
                and set(row) == {"digest", "bytes"}
                and type(row["bytes"]) is int
                and 0 < row["bytes"] <= _LIMIT,
                "prepared input row changed",
            )
            pin = public._pin(row["digest"])
            _require(pin not in declared, "duplicate prepared input")
            declared[pin] = row["bytes"]
        grant = public._pin(binding["grant_digest"])
        _require(
            set(declared) - set(blobs) == {grant}
            and set(blobs) < set(declared)
            and grant not in exported
            and 0 < declared[grant] <= 65536,
            "exactly one private grant must be missing",
        )
        _require(
            rows
            == [
                {"digest": pin, "bytes": size} for pin, size in sorted(declared.items())
            ]
            and all(declared[pin] == len(raw) for pin, raw in blobs.items()),
            "public prepared sizes/order changed",
        )
        installed_sources = {
            installed: {
                "digest": public._digest(bound["source_raws"][source]),
                "bytes": len(bound["source_raws"][source]),
            }
            for installed, source in sorted(
                (
                    {
                        target: source
                        for source, target in inputs.FIXTURE_HELPERS.items()
                    }
                    | inputs.HELPER_ALIASES
                ).items()
            )
        }
        return {
            "prepared_raw": prepared_raw,
            "prepared_digest": plan["measurement_prepared_digest"],
            "binding_raw": binding_raw,
            "binding_digest": plan["binding_digest"],
            "source_pins": source_pins,
            "input_rows": rows,
            "public_blobs": blobs,
            "grant_digest": grant,
            "grant_bytes": declared[grant],
            "request": public.base._parse(
                read(plan["request_digest"]), public.MAX_PUBLIC_BLOB
            ),
            "sink_source_digest": bound["expected_source_digests"][_SINK],
            "installed_sources": installed_sources,
        }
    except Exception:
        raise NativeCommonMeasurementCaptureError(
            "private input planning refused"
        ) from None


def _role(capture, name, read):
    pins = {
        row["digest"]
        for row in capture["guest"]["attempt"]["public_blob_attempts"]
        if row["role"] == name
    }
    _require(len(pins) == 1, "single retained observation required")
    return read(next(iter(pins)))


def verify_native_common_measurement_records(
    *,
    capture,
    plan,
    public_cas,
    private_input_cas,
    expected_worker,
    expected_broker_process,
    expected_gateway,
    expected_sink_accounts,
):
    """Invoke both real consumers with separate read-only private/public stores."""
    try:
        read = _reader(public_cas)
        _separate_stores(public_cas, private_input_cas)
        report = capture["guest"]["attempt"]
        work = public.base._parse(
            read(report["workload"]["digest"]), public.MAX_PUBLIC_BLOB
        )
        measured = public.base._parse(
            read(report["snapshot"]["digest"]), public.MAX_PUBLIC_BLOB
        )

        def record(row):
            _require(
                type(row) is dict
                and set(row) == {"text", "digest", "bytes"}
                and type(row["bytes"]) is int,
                "measurement record shape changed",
            )
            raw = row["text"].encode("utf-8")
            _require(
                0 < len(raw) == row["bytes"] <= public.MAX_PUBLIC_BLOB
                and read(row["digest"]) == raw,
                "measurement record bytes changed",
            )
            return raw

        records = measured["records"]
        common = {
            name + "_raw": record(records[name])
            for name in ("startup", "ingress", "attempt", "action")
        }
        common.update(
            expected_record_digests={
                name: records[name]["digest"]
                for name in ("startup", "ingress", "attempt", "action")
            },
            completion_raw=record(records["completion"]),
            expected_completion_digest=records["completion"]["digest"],
            expected_binding_raw=plan["binding_raw"],
            expected_binding_digest=plan["binding_digest"],
            expected_worker=expected_worker,
            expected_broker_process=expected_broker_process,
            expected_worker_binding_digest=plan["request"]["expected_file_digests"][
                _WORKER
            ],
            expected_genesis_digest=plan["request"]["expected_file_digests"][_GENESIS],
            input_cas=private_input_cas,
            evidence_cas=public_cas,
        )
        driver = {
            name + "_raw": record(work["records"][name])
            for name in (
                "driver",
                "receipt_before",
                "receipt_after",
                "sink_before",
                "sink_after",
            )
        }
        driver.update(
            {
                "expected_" + name + "_digest": work["records"][name]["digest"]
                for name in (
                    "driver",
                    "receipt_before",
                    "receipt_after",
                    "sink_before",
                    "sink_after",
                )
            }
        )
        before, after = (
            _role(capture, "clock_before", read),
            _role(capture, "clock_after", read),
        )
        result = {
            "blocked_create": blocked.verify_native_blocked_create(
                **common,
                **driver,
                expected_gateway=expected_gateway,
                expected_container_id=plan["request"]["container_id"],
                expected_sink_source_digest=plan["sink_source_digest"],
                expected_sink_accounts=expected_sink_accounts,
            ),
            "ingress_interval": interval.verify_native_ingress_interval(
                **common,
                clock_before_raw=before,
                clock_after_raw=after,
                expected_clock_before_digest=public._digest(before),
                expected_clock_after_digest=public._digest(after),
            ),
        }
        _require(
            canonical_json(result)
            == canonical_json(report["verification"])
            == _role(capture, "independent_verification", read),
            "independent replay differs from guest result",
        )
        return result
    except Exception:
        raise NativeCommonMeasurementCaptureError(
            "independent measurement record replay refused"
        ) from None


def _verify_process_expectations(
    capture,
    plan,
    read,
    *,
    expected_worker,
    expected_broker_process,
    expected_gateway,
    expected_sink_accounts,
):
    identity_before, identity_after, observer_before, observer_after = (
        public.base._parse(_role(capture, role, read), public.MAX_PUBLIC_BLOB)
        for role in (
            "identity_before",
            "identity_after",
            "process_before",
            "process_after",
        )
    )
    result = processes.verify_native_common_process_observations(
        identity_before,
        identity_after,
        observer_before,
        observer_after,
        expected_container_id=plan["request"]["container_id"],
        expected_file_digests=plan["request"]["expected_file_digests"],
    )
    for role, expected in (
        ("worker", expected_worker),
        ("broker", expected_broker_process),
        ("gateway", expected_gateway),
    ):
        observed = observer_before["processes"][role]["process"]
        fields = ("pid", "uid", "gid") if role == "gateway" else _EPOCH
        allowed = set(fields) | (
            {"boot_id", "mount_namespace"} if role == "broker" else set()
        )
        _require(
            type(expected) is dict
            and set(expected) == allowed
            and all(
                type(expected[key]) is int and expected[key] == observed[key]
                for key in fields
            ),
            "caller process differs from retained independent observation",
        )
    _require(
        type(expected_sink_accounts) is dict
        and set(expected_sink_accounts) == {"broker_uid", "broker_gid", "runtime_gid"}
        and all(
            type(value) is int and 0 < value < 2**32
            for value in expected_sink_accounts.values()
        )
        and expected_broker_process["boot_id"] == plan["request"]["boot_id"]
        and expected_broker_process["mount_namespace"]
        == f"mnt:[{identity_before['processes']['broker']['mount_namespace']['inode']}]"
        and expected_sink_accounts["broker_uid"] == expected_broker_process["uid"]
        and expected_sink_accounts["runtime_gid"] == expected_worker["gid"],
        "caller boot/namespace/account joins changed",
    )
    _require(
        canonical_json(result)
        == canonical_json(capture["guest"]["attempt"]["process_verification"]),
        "independent process replay differs from retained result",
    )
    return result


def verify_native_common_measurement_capture(
    capture_raw,
    *,
    expected_capture_digest,
    public_cas,
    private_input_cas,
    expected_worker,
    expected_broker_process,
    expected_gateway,
    expected_sink_accounts,
):
    """Full private-input and two-consumer replay, never full Phase 3 measurement.

    The caller supplies its held process/account expectations explicitly. These
    are also joined to the retained independent process observations, not taken
    from an asserted verifier status or silently derived from sink output.
    """
    try:
        _separate_stores(public_cas, private_input_cas)
        (
            expected_worker,
            expected_broker_process,
            expected_gateway,
            expected_sink_accounts,
        ) = json.loads(
            canonical_json(
                [
                    expected_worker,
                    expected_broker_process,
                    expected_gateway,
                    expected_sink_accounts,
                ]
            )
        )
        public_result = public.verify_native_common_attempt_capture(
            capture_raw,
            expected_capture_digest=expected_capture_digest,
            store=public_cas,
        )
        capture = public.base._parse(capture_raw, public.MAX_CAPTURE, newline=True)
        plan = plan_native_common_measurement_inputs(capture, public_cas=public_cas)
        validated = validate_prepared_native_measurement_inputs(
            prepared_raw=plan["prepared_raw"],
            expected_prepared_digest=plan["prepared_digest"],
            expected_binding_digest=plan["binding_digest"],
            expected_broker_source_pins=plan["source_pins"],
            source_cas=private_input_cas,
        )
        read = _reader(public_cas)
        process_result = _verify_process_expectations(
            capture,
            plan,
            read,
            expected_worker=expected_worker,
            expected_broker_process=expected_broker_process,
            expected_gateway=expected_gateway,
            expected_sink_accounts=expected_sink_accounts,
        )
        result = verify_native_common_measurement_records(
            capture=capture,
            plan=plan,
            public_cas=public_cas,
            private_input_cas=private_input_cas,
            expected_worker=expected_worker,
            expected_broker_process=expected_broker_process,
            expected_gateway=expected_gateway,
            expected_sink_accounts=expected_sink_accounts,
        )
        for pin, raw in validated["input_blobs"].items():
            _require(
                private_input_cas.read(pin, max_bytes=len(raw)) == raw,
                "private final custody changed",
            )
        _require(
            read(expected_capture_digest, public.MAX_CAPTURE) == capture_raw,
            "capture final custody changed",
        )
        return {
            "schema": "aragorn/native-common-measurement-capture-verification/v1",
            "status": "RETAINED_NATIVE_MEASUREMENT_SEMANTICS_REPLAYED",
            "capture_digest": expected_capture_digest,
            "prepared_digest": plan["prepared_digest"],
            "private_input_set_digest": public._digest(
                canonical_json(plan["input_rows"])
            ),
            "public_capture": public_result,
            "process_joins": process_result,
            "measurement": result,
            "prepared_private_input_semantics_replayed": True,
            "bounded_measurement_consumers_replayed": True,
            "private_writer_semantics_replayed": False,
            "independent_full_measurement_replay_complete": False,
            "limitations": [
                "ONE_RETAINED_ATTRIBUTED_CREATE_NOT_FULL_CAMPAIGN_OR_PRIVATE_SEVEN_WRITER_REPLAY",
                "CALLER_HELD_SINK_GROUP_EXPECTATION_NOT_DERIVED_FROM_SINK_REPORT",
                "RETAINED_NAMESPACE_AND_PROCESS_JOINS_NOT_FRESH_OBSERVATIONS",
                "EXISTING_CONSUMER_TIMING_RESIDUE_CAUSALITY_AND_POLICY_CEILINGS_UNCHANGED",
            ],
            **dict.fromkeys(public.FALSE_FLAGS, False),
        }
    except Exception:
        raise NativeCommonMeasurementCaptureError(
            "independent measurement capture replay refused"
        ) from None
