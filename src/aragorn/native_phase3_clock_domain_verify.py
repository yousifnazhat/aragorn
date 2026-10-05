"""Independent, offline joins of caller-pinned active time-namespace readbacks.

This consumes two external observations, not timestamps from request-handling
processes. Neither the observer nor a workload callback is imported. Raw pins
are caller trust anchors; they do not establish independent acquisition, PIDFD
custody, continuous identity, or event semantics.
"""

from __future__ import annotations

import hashlib
import json
import re

from .oci_worker_protocol import canonical_json


SCHEMA = "aragorn/native-phase3-clock-domain-verification/v1"
AUTHORITY = "RETAINED_ACTIVE_TIME_NAMESPACE_JOINS_NOT_EVENT_TIMING_OR_ATTESTATION"
OBSERVATION_SCHEMA = "aragorn/native-phase3-clock-domain/v1"
OBSERVATION_AUTHORITY = (
    "LOCAL_ROOT_PROCESS_TIME_NAMESPACE_READBACK_NOT_REQUEST_EVENTS_OR_ATTESTATION"
)
FALSE_FLAGS = (
    "common_deployment_fully_verified",
    "route_qualified",
    "phase3_eligible",
    "live_deployment_attested",
    "metrics_eligible",
    "application_acknowledged",
)
OBSERVATION_LIMITATIONS = (
    "EXTERNAL_ROOT_OBSERVER_NOT_IN_PROCESS_REQUEST_OR_DECISION_TIMESTAMPS",
    "POINT_IN_TIME_READ_BRACKETS_NOT_CONTINUOUS_PROCESS_OR_NAMESPACE_IMMUTABILITY",
    "ACTIVE_TIME_NAMESPACE_IDENTITIES_ONLY_NO_OFFSET_TRANSLATION",
    "LOCAL_ROOT_PROC_READBACK_NOT_HOSTILE_ROOT_RESISTANT_OR_EXTERNAL_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
LIMITATIONS = (
    "CALLER_RAW_DIGEST_PINS_NOT_INDEPENDENT_ACQUISITION_OR_PIDFD_CUSTODY_PROOF",
    "RETAINED_READ_BRACKETS_NOT_REQUEST_ACCEPTED_OR_DECISION_FINALIZED_EVENTS",
    "NO_ELAPSED_LATENCY_OR_WORKLOAD_SEMANTICS_VERIFIED",
    "POINT_IN_TIME_READS_NOT_CONTINUOUS_PROCESS_OR_NAMESPACE_IMMUTABILITY",
    "ACTIVE_NAMESPACE_EQUALITY_ONLY_NO_OFFSET_TRANSLATION_OR_BOOT_ATTESTATION",
    "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
)
_MAX_BYTES = 16384
_ROLES = {"collector", "worker", "broker"}
_EPOCH_FIELDS = {"pid", "start_time_ticks", "uid", "gid"}
_FIELDS = {
    "schema",
    "authority",
    "clock_id",
    "boot_id",
    "read_started_boottime_ns",
    "read_finished_boottime_ns",
    "processes",
    "limitations",
    *FALSE_FLAGS,
}


class NativeCommonClockDomainVerificationError(ValueError):
    """A bounded, caller-pinned clock-domain record could not be joined."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NativeCommonClockDomainVerificationError(message)


def _exact(value: object, fields: set[str], message: str) -> dict:
    _require(type(value) is dict and set(value) == fields, message)
    return value


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value < 2**63


def _pairs(pairs: list) -> dict:
    value = {}
    for key, item in pairs:
        _require(key not in value, "duplicate observation field")
        value[key] = item
    return value


def _noninteger(_value: str) -> None:
    raise NativeCommonClockDomainVerificationError("noninteger observation number")


def _parse(raw: bytes, pin: str) -> dict:
    _require(
        type(raw) is bytes and 0 < len(raw) <= _MAX_BYTES,
        "observation bytes are invalid or oversized",
    )
    _require(
        type(pin) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is not None
        and "sha256:" + hashlib.sha256(raw).hexdigest() == pin,
        "observation digest differs from caller pin",
    )
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_float=_noninteger,
        parse_constant=_noninteger,
    )
    _require(canonical_json(value) == raw, "observation bytes are not canonical")
    return _exact(value, _FIELDS, "clock observation fields changed")


def _expected(value: dict) -> dict:
    result = _exact(value, _EPOCH_FIELDS, "expected process epoch fields changed")
    _require(
        all(_integer(item, 1) for item in result.values()),
        "expected process epoch scalar is invalid",
    )
    return dict(result)


def _observation(value: dict, worker: dict, broker: dict) -> None:
    _require(
        value["schema"] == OBSERVATION_SCHEMA
        and value["authority"] == OBSERVATION_AUTHORITY
        and value["clock_id"] == "CLOCK_BOOTTIME"
        and value["limitations"] == list(OBSERVATION_LIMITATIONS)
        and all(value[field] is False for field in FALSE_FLAGS),
        "clock observation kind or claim ceiling changed",
    )
    _require(
        type(value["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        )
        is not None,
        "clock observation boot identity is invalid",
    )
    start, finish = (
        value["read_started_boottime_ns"],
        value["read_finished_boottime_ns"],
    )
    _require(
        _integer(start) and _integer(finish) and start < finish,
        "clock observation read bracket is invalid",
    )
    processes = _exact(value["processes"], _ROLES, "clock process inventory changed")
    for role in sorted(_ROLES):
        record = _exact(
            processes[role],
            _EPOCH_FIELDS | {"time_namespace"},
            "clock process record fields changed",
        )
        _require(
            all(_integer(record[key], 1) for key in ("pid", "start_time_ticks"))
            and _integer(record["uid"])
            and _integer(record["gid"]),
            "clock process scalar is invalid",
        )
        if role == "collector":
            _require(
                record["uid"] == record["gid"] == 0,
                "clock observer is not recorded as root",
            )
        else:
            expected = worker if role == "worker" else broker
            _require(
                {key: record[key] for key in _EPOCH_FIELDS} == expected,
                "clock process differs from caller epoch",
            )
        namespace = _exact(
            record["time_namespace"],
            {"device", "inode"},
            "active time namespace fields changed",
        )
        _require(
            _integer(namespace["device"]) and _integer(namespace["inode"], 1),
            "active time namespace identity is invalid",
        )
    _require(
        len({record["pid"] for record in processes.values()}) == len(_ROLES),
        "clock process PIDs overlap",
    )
    namespace = processes["collector"]["time_namespace"]
    _require(
        all(record["time_namespace"] == namespace for record in processes.values()),
        "active time namespaces differ",
    )


def verify_native_common_clock_domain(
    before_raw: bytes,
    after_raw: bytes,
    *,
    expected_before_digest: str,
    expected_after_digest: str,
    expected_worker: dict,
    expected_broker: dict,
) -> dict:
    """Verify retained shared active namespace readbacks, never elapsed latency."""
    try:
        worker, broker = _expected(expected_worker), _expected(expected_broker)
        before = _parse(before_raw, expected_before_digest)
        after = _parse(after_raw, expected_after_digest)
        for value in (before, after):
            _observation(value, worker, broker)
        _require(
            before["boot_id"] == after["boot_id"], "observed boot identity changed"
        )
        _require(
            before["processes"] == after["processes"],
            "observed process epoch or active time namespace changed",
        )
        _require(
            before["read_finished_boottime_ns"] <= after["read_started_boottime_ns"],
            "clock observation brackets overlap or are reversed",
        )
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": "RETAINED_COMMON_CLOCK_DOMAIN_VERIFIED",
            "before_digest": expected_before_digest,
            "after_digest": expected_after_digest,
            "clock_domain": {
                "clock_id": "CLOCK_BOOTTIME",
                "boot_id": before["boot_id"],
                "time_namespace": dict(
                    before["processes"]["collector"]["time_namespace"]
                ),
            },
            "processes": before["processes"],
            "read_brackets": {
                name: {
                    "started_boottime_ns": value["read_started_boottime_ns"],
                    "finished_boottime_ns": value["read_finished_boottime_ns"],
                }
                for name, value in (("before", before), ("after", after))
            },
            "limitations": list(LIMITATIONS),
            **dict.fromkeys(FALSE_FLAGS, False),
        }
    except NativeCommonClockDomainVerificationError:
        raise
    except Exception as exc:
        raise NativeCommonClockDomainVerificationError(
            "retained clock-domain verification refused"
        ) from exc
