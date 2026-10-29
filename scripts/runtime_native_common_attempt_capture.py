"""Fixed one-shot guest attempt and finite public evidence export.

The attempt owns activation and cleanup. This wrapper never resumes it, invokes
setup separately, lists a CAS, or reads a grant. Pre-yield handoff recovery reads
only the permanent original-commitment claim, after its public joins are known.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import re
import stat
import sys

if __package__:
    from scripts import runtime_native_common_attempt as attempt
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_common_attempt as attempt

from aragorn import native_phase3_common_attempt_inputs as contract
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-common-attempt-guest/v1"
AUTHORITY = "OWNED_ONCE_ATTEMPT_PUBLIC_EXPORT_NOT_PHASE3_QUALIFICATION"
BUNDLE_PATH = "/opt/aragorn/native-common-attempt-inputs.json"
MAX_INPUT = 16 * 1024 * 1024
MAX_RESULT = 128 * 1024 * 1024
MAX_PUBLIC_TOTAL = 32 * 1024 * 1024
MAX_PUBLIC_BLOB = 16 * 1024 * 1024
MAX_PUBLIC_BLOBS = 256
_MAX_REPORT = 2 * 1024 * 1024
_IDENTITY = attempt.setup.predecessor.identity
_FALSE = attempt.FALSE_FLAGS
_CONTROLLER_PATHS = {
    "scripts/runtime_native_common_attempt_capture.py": "/opt/aragorn/runtime_native_common_attempt_capture.py",
    "src/aragorn/native_phase3_common_attempt_inputs.py": "/usr/lib/aragorn/aragorn/native_phase3_common_attempt_inputs.py",
}
_PUBLIC_ROLES = frozenset(
    (
        "common_public_input",
        "original_schedule",
        "original_commitment",
        "original_collection_preparation",
        "selected_request",
        "protected_descriptor",
        "measurement_binding",
        "measurement_preparation",
        "common_measured_request",
        "plan_report",
        "handoff",
        "request",
        "provisioning",
        "claim",
        "identity_before",
        "identity_after",
        "process_before",
        "process_after",
        "clock_before",
        "clock_after",
        "workload",
        "measurement_snapshot",
        "broker_blob",
        "independent_verification",
    )
    + tuple(
        "workload_" + name
        for name in (
            "identity_before",
            "identity_after",
            "receipt_before",
            "receipt_after",
            "sink_before",
            "sink_after",
            "driver_input",
            "driver",
        )
    )
    + tuple(
        "measurement_" + name
        for name in (
            "startup",
            "ingress",
            "attempt",
            "action",
            "pending",
            "completion",
        )
    )
)
_LIMITATIONS = [
    "ONE_CONTROLLER_CALL_NO_SETUP_REPLAY_NO_AUTOMATIC_EFFECT_RETRY",
    "EXPLICIT_PUBLIC_ROLES_ONLY_NO_PRIVATE_CAS_ENUMERATION_OR_GRANT_EXPORT",
    "PREYIELD_RECOVERY_IS_EXACT_PERMANENT_CLAIM_NOT_COMPLETION_OR_RESUME_AUTHORITY",
    "PREYIELD_PROVISIONING_PARTIALS_MAY_REMAIN_UNCLASSIFIED_PRESERVE_OWNED_FIXTURE",
    "ROOT_GUEST_READBACK_NOT_HOST_NETWORK_OR_LOADED_CODE_ATTESTATION",
    "BOUNDED_ATTEMPT_EXPORT_NOT_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
]


class NativeCommonAttemptCaptureError(ValueError):
    """Fixed secret-safe refusal, without repairing partial state."""


def _require(condition, reason):
    if not condition:
        raise NativeCommonAttemptCaptureError(reason)


def _pin(value):
    return (
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
    )


def _remember_interrupt(error, interrupts):
    if not isinstance(error, Exception) and not interrupts:
        interrupts.append(error)


def _close_all(descriptors):
    primary, failure = sys.exception(), None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None and primary is None:
        if not isinstance(failure, Exception):
            raise failure
        raise NativeCommonAttemptCaptureError("DESCRIPTOR_CLOSE_REFUSED") from None


def _read_fixed(path, *, mode, limit):
    descriptors = []
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(root)
        return _IDENTITY._read_at(
            root, path, owner=0, owner_gid=0, modes={mode}, limit=limit
        )
    finally:
        _close_all(descriptors)


def _read_bundle(expected):
    raw, metadata = _read_fixed(BUNDLE_PATH, mode=0o444, limit=MAX_INPUT)
    _require(_IDENTITY._digest(raw) == expected, "BUNDLE_PIN_CHANGED")
    return raw, metadata


def _read_controller(source, expected):
    raw, metadata = _read_fixed(
        _CONTROLLER_PATHS[source], mode=0o444, limit=_MAX_REPORT
    )
    _require(raw == expected, "CONTROLLER_SOURCE_CHANGED")
    return metadata


def _directory(descriptor, mode):
    metadata = os.fstat(descriptor)
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and not stat.S_IMODE(metadata.st_mode) & 0o022
        and (mode is None or stat.S_IMODE(metadata.st_mode) == mode),
        "PRIVATE_CAS_DIRECTORY_CUSTODY_REFUSED",
    )
    return _IDENTITY.broker._directory_identity(metadata)


@contextmanager
def _evidence_store(*, blobs=False, claims=False):
    """Hold existing fixed ancestry only; no creation, reset, or enumeration."""
    _require(not (blobs and claims), "FIXED_STORE_SELECTION_REFUSED")
    _require(
        attempt.CAS_ROOT == "/run/aragorn-native-common-attempt",
        "FIXED_CAS_ROOT_CHANGED",
    )
    descriptors, held = [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        root = os.open("/", flags)
        descriptors.append(root)
        held.append((root, ".", root, _directory(root, None), None))
        parent = root
        names = [
            ("run", None),
            ("aragorn-native-common-attempt", 0o700),
            ("evidence", 0o700),
        ]
        if blobs:
            names += [("blobs", 0o700), ("sha256", 0o700)]
        if claims:
            names += [("phase3-prepared-attempt-claims", 0o700)]
        for name, mode in names:
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(name, flags, dir_fd=parent)
            descriptors.append(descriptor)
            identity = _directory(descriptor, mode)
            _require(
                identity == _IDENTITY.broker._directory_identity(before),
                "CAS_DIRECTORY_REPLACED",
            )
            held.append((parent, name, descriptor, identity, mode))
            parent = descriptor

        def guard():
            for ancestor, name, descriptor, identity, mode in held:
                _require(
                    identity
                    == _directory(descriptor, mode)
                    == _IDENTITY.broker._directory_identity(
                        os.stat(name, dir_fd=ancestor, follow_symlinks=False)
                    ),
                    "CAS_DIRECTORY_REPLACED",
                )

        guard()
        try:
            yield parent, guard
        finally:
            # Retain a primary interruption; final custody is checked independently.
            attempt.setup._close_preserving(guard, "EXPORT_FINAL_CAS_CUSTODY_REFUSED")
    finally:
        _close_all(descriptors)


def _candidates(value):
    _require(
        type(value) is list and len(value) <= MAX_PUBLIC_BLOBS,
        "PUBLIC_JOURNAL_BOUND_REFUSED",
    )
    seen = {}
    for row in value:
        _require(
            type(row) is dict
            and set(row) == {"role", "digest", "bytes"}
            and row["role"] in _PUBLIC_ROLES
            and _pin(row["digest"])
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= MAX_PUBLIC_BLOB,
            "PUBLIC_JOURNAL_CLASSIFICATION_REFUSED",
        )
        pin = row["digest"]
        _require(
            pin not in seen or seen[pin]["bytes"] == row["bytes"],
            "PUBLIC_DUPLICATE_PIN_CHANGED",
        )
        seen.setdefault(pin, {"digest": pin, "bytes": row["bytes"]})
    _require(
        sum(row["bytes"] for row in seen.values()) <= MAX_PUBLIC_TOTAL,
        "PUBLIC_TOTAL_BOUND_REFUSED",
    )
    return list(seen.values())


def _read_public_blob(sha_root, candidate):
    descriptors = []
    prefix = candidate["digest"][7:9]
    try:
        before = os.stat(prefix, dir_fd=sha_root, follow_symlinks=False)
        descriptor = os.open(
            prefix,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=sha_root,
        )
        descriptors.append(descriptor)
        identity = _directory(descriptor, 0o700)
        _require(
            identity == _IDENTITY.broker._directory_identity(before),
            "PUBLIC_PREFIX_REPLACED",
        )
        raw, _ = _IDENTITY._read_at(
            descriptor,
            "/" + candidate["digest"][9:],
            owner=0,
            owner_gid=0,
            modes={0o444},
            limit=MAX_PUBLIC_BLOB,
        )
        _require(
            len(raw) == candidate["bytes"]
            and _IDENTITY._digest(raw) == candidate["digest"]
            and identity
            == _directory(descriptor, 0o700)
            == _IDENTITY.broker._directory_identity(
                os.stat(prefix, dir_fd=sha_root, follow_symlinks=False)
            ),
            "PUBLIC_BLOB_OR_PREFIX_CHANGED",
        )
        return raw
    finally:
        _close_all(descriptors)


def _append_public(result, raw):
    pin = _IDENTITY._digest(raw)
    _require(0 < len(raw) <= MAX_PUBLIC_BLOB, "PUBLIC_BLOB_BOUND_REFUSED")
    for row in result["public_blobs"]:
        if row["digest"] == pin:
            _require(
                row["bytes"] == len(raw) and row["text"].encode("utf-8") == raw,
                "DUPLICATE_EXPORT_CHANGED",
            )
            return
    _require(
        len(result["public_blobs"]) < MAX_PUBLIC_BLOBS
        and sum(row["bytes"] for row in result["public_blobs"]) + len(raw)
        <= MAX_PUBLIC_TOTAL,
        "PUBLIC_EXPORT_BOUND_REFUSED",
    )
    row = {"digest": pin, "bytes": len(raw), "text": raw.decode("utf-8")}
    trial = dict(result, public_blobs=[*result["public_blobs"], row])
    _require(
        len(canonical_json(trial)) <= MAX_RESULT - 65536, "PUBLIC_WIRE_BOUND_REFUSED"
    )
    result["public_blobs"].append(row)


def _export_public(result, candidates, interrupts):
    if not candidates:
        return
    attempted = set()
    try:
        with _evidence_store(blobs=True) as (sha_root, guard):
            for row in candidates:
                attempted.add(row["digest"])
                try:
                    guard()
                    raw = _read_public_blob(sha_root, row)
                    guard()
                    _append_public(result, raw)
                except BaseException as error:
                    _remember_interrupt(error, interrupts)
                    result["export_failures"].append(
                        {
                            "digest": row["digest"],
                            "reason": "PUBLIC_BLOB_EXPORT_REFUSED",
                        }
                    )
    except BaseException as error:
        _remember_interrupt(error, interrupts)
        result["export_failures"].extend(
            {"digest": row["digest"], "reason": "PUBLIC_BLOB_EXPORT_REFUSED"}
            for row in candidates
            if row["digest"] not in attempted
        )
        result["postcondition_failures"].append("PUBLIC_CAS_CUSTODY_REFUSED")


def _recovery_bindings(result, container):
    """Classify every prerequisite from already exported, journaled public bytes."""
    report = result["attempt"]
    plan = report["plan"]
    _require(
        type(plan) is dict
        and plan.get("schema") == attempt.planner.SCHEMA
        and plan.get("authority") == attempt.planner.AUTHORITY
        and plan.get("status") == "ORIGINAL_PLAN_PREPARED_NOT_PROVISIONED"
        and plan.get("container_id") == container
        and all(
            plan.get("decision", {}).get(key) is False
            for key in attempt.planner.FALSE_FLAGS
        ),
        "ORIGINAL_PUBLIC_PLAN_REQUIRED",
    )
    exported = {
        row["digest"]: row["text"].encode("utf-8") for row in result["public_blobs"]
    }
    journal = report["public_blob_attempts"]

    def role(pin, name):
        _require(
            _pin(pin)
            and pin in exported
            and any(row["digest"] == pin and row["role"] == name for row in journal),
            "ORIGINAL_PUBLIC_ROLE_JOIN_REFUSED",
        )
        return exported[pin]

    plan_raw = canonical_json(plan)
    _require(
        role(_IDENTITY._digest(plan_raw), "plan_report") == plan_raw,
        "ORIGINAL_PUBLIC_PLAN_CHANGED",
    )
    roles = {
        "common_preparation_digest": "common_public_input",
        "collection_preparation_digest": "original_collection_preparation",
        "commitment_digest": "original_commitment",
        "measurement_prepared_digest": "measurement_preparation",
        "binding_digest": "measurement_binding",
        "request_digest": "common_measured_request",
    }
    documents = {key: json.loads(role(plan[key], name)) for key, name in roles.items()}
    scheduled = canonical_json(plan["scheduled_request"])
    scheduled_pin = _IDENTITY._digest(scheduled)
    _require(
        role(scheduled_pin, "selected_request") == scheduled,
        "ORIGINAL_SELECTED_REQUEST_CHANGED",
    )
    binding, request = documents["binding_digest"], documents["request_digest"]
    _require(
        binding["collection_commitment_digest"] == plan["commitment_digest"]
        and binding["scheduled_measurement_request_digest"] == scheduled_pin
        and binding["attempt_id"] == plan["scheduled_request"]["attempt_id"]
        and request["container_id"] == container
        and request["measurement_binding_digest"] == plan["binding_digest"]
        and documents["measurement_prepared_digest"]["binding"] == binding,
        "ORIGINAL_REQUEST_BINDING_JOIN_REFUSED",
    )
    return {
        "schema": "aragorn/native-common-measurement-claim/v1",
        "collection_preparation_digest": plan["collection_preparation_digest"],
        "common_preparation_digest": plan["common_preparation_digest"],
        "measurement_prepared_digest": plan["measurement_prepared_digest"],
        "commitment_digest": plan["commitment_digest"],
        "request_digest": scheduled_pin,
        "common_request_digest": plan["request_digest"],
        "binding_digest": plan["binding_digest"],
        "container_id": container,
        "state": "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
    }


def _read_claim(expected):
    # The completed claim is 0400; a 0600 partial claim is never read/exported.
    with _evidence_store(claims=True) as (directory, guard):
        guard()
        raw, metadata = _IDENTITY._read_at(
            directory,
            "/" + expected["commitment_digest"][7:] + ".json",
            owner=0,
            owner_gid=0,
            modes={0o400},
            limit=4096,
        )
        claim = json.loads(raw)
        _require(
            type(claim) is dict
            and set(claim) == set(expected) | {"claimed_boottime_ns"}
            and all(claim[key] == value for key, value in expected.items())
            and type(claim["claimed_boottime_ns"]) is int
            and 0 < claim["claimed_boottime_ns"] < 2**63
            and canonical_json(claim) == raw,
            "PERMANENT_CLAIM_CLASSIFICATION_REFUSED",
        )
        guard()
        return raw, metadata


def _recover_claim(result, container, interrupts):
    report = result["attempt"]
    if report is not None and report.get("handoff") is not None:
        # The controller stores session.report before retaining these four
        # roles. A partial retain loop must not authorize fixture destruction.
        try:
            handoff = report["handoff"]
            expected = {
                "handoff": _IDENTITY._digest(canonical_json(handoff)),
                **{
                    role: handoff[role + "_digest"]
                    for role in ("request", "provisioning", "claim")
                },
            }
            exported = {row["digest"] for row in result["public_blobs"]}
            _require(
                all(
                    _pin(pin)
                    and pin in exported
                    and any(
                        row["role"] == role and row["digest"] == pin
                        for row in report["public_blob_attempts"]
                    )
                    for role, pin in expected.items()
                ),
                "HANDOFF_PUBLIC_ROLES_INCOMPLETE",
            )
            result["recovery"]["status"] = "NOT_REQUIRED"
        except BaseException as error:
            _remember_interrupt(error, interrupts)
            result["recovery"]["status"] = "INCOMPLETE"
            result["recovery"]["failures"].append("HANDOFF_PUBLIC_ROLES_INCOMPLETE")
        return
    if (
        report is None
        or (report.get("refusal") or {}).get("phase") != "HELD_PREACTIVATION_HANDOFF"
    ):
        result["recovery"]["status"] = "NOT_REQUIRED"
        return
    result["recovery"]["status"] = "INCOMPLETE"
    try:
        expected = _recovery_bindings(result, container)
        raw, metadata = _read_claim(expected)
        _append_public(result, raw)
        result["recovery"].update(
            status="CLASSIFIED_PERMANENT_CLAIM_EXPORTED",
            claim_metadata=metadata,
            public_blob_attempts=[
                {"role": "claim", "digest": _IDENTITY._digest(raw), "bytes": len(raw)}
            ],
        )
    except BaseException as error:
        _remember_interrupt(error, interrupts)
        result["recovery"]["failures"].append("PERMANENT_CLAIM_RECOVERY_REFUSED")


def _report(value):
    _require(
        type(value) is dict
        and len(canonical_json(value)) <= _MAX_REPORT
        and value.get("schema") == attempt.SCHEMA
        and value.get("authority") == attempt.AUTHORITY
        and value.get("status") in {"REFUSED", "BOUNDED_NATIVE_ATTEMPT_VERIFIED"}
        and all(value.get(key) is False for key in _FALSE),
        "PUBLIC_ATTEMPT_REPORT_REFUSED",
    )
    # Never echo an unknown/private journal role or extra candidate fields.
    _candidates(value.get("public_blob_attempts"))
    return json.loads(canonical_json(value))


def _run(container, expected_bundle_digest):
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": None,
        "input_bundle_digest": None,
        "attempt": None,
        "public_blobs": [],
        "export_failures": [],
        "refusal": None,
        "input_bundle_readback": False,
        "controller_sources": {},
        "controller_sources_after": {},
        "postcondition_failures": [],
        "recovery": {
            "status": "NOT_ATTEMPTED",
            "claim_metadata": None,
            "public_blob_attempts": [],
            "failures": [],
        },
        "public_export_complete": False,
        "preserve_fixture_for_evidence": False,
        "interrupted": False,
        "limitations": list(_LIMITATIONS),
        **dict.fromkeys(_FALSE, False),
    }
    phase, bundle, inspected, called, journal_valid = (
        "ARGUMENTS",
        None,
        None,
        False,
        False,
    )
    candidates, interrupts = [], []
    try:
        _require(
            type(container) is str
            and re.fullmatch(r"[0-9a-f]{64}", container) is not None
            and _pin(expected_bundle_digest),
            "FIXED_CAPTURE_ARGUMENTS_REFUSED",
        )
        result.update(
            container_id=container, input_bundle_digest=expected_bundle_digest
        )
        phase = "ENVIRONMENT"
        attempt.setup.predecessor._environment(container, (0, 0))
        phase = "INPUT_BUNDLE"
        bundle = _read_bundle(expected_bundle_digest)
        inspected = contract.inspect_common_attempt_inputs(
            bundle[0], expected_bundle_digest=expected_bundle_digest
        )
        phase = "CONTROLLER_SOURCES"
        for source in _CONTROLLER_PATHS:
            result["controller_sources"][source] = _read_controller(
                source, inspected["source_raws"][source]
            )
        phase = "ATTEMPT"
        called = True
        try:
            report = attempt.run_native_common_attempt(
                common_arguments={
                    **inspected["common_arguments"],
                    "container_id": container,
                },
                plan_arguments=inspected["plan_arguments"],
                expected_setup_digest=inspected["expected_setup_digest"],
                expected_source_digests=inspected["expected_source_digests"],
            )
        except BaseException as error:
            _remember_interrupt(error, interrupts)
            report = getattr(error, "_native_common_attempt", None)
            result["refusal"] = {
                "phase": phase,
                "reason": "COMMON_ATTEMPT_INTERRUPTED"
                if not isinstance(error, Exception)
                else "COMMON_ATTEMPT_REFUSED",
            }
        result["attempt"] = _report(report)
        candidates = _candidates(result["attempt"]["public_blob_attempts"])
        _require(
            result["attempt"]["public_blob_digests"]
            == sorted(row["digest"] for row in candidates),
            "PUBLIC_JOURNAL_DIGEST_JOIN_REFUSED",
        )
        journal_valid = True
        if (
            report["status"] != "BOUNDED_NATIVE_ATTEMPT_VERIFIED"
            and result["refusal"] is None
        ):
            result["refusal"] = {"phase": "ATTEMPT", "reason": "COMMON_ATTEMPT_REFUSED"}
    except BaseException as error:
        _remember_interrupt(error, interrupts)
        if result["refusal"] is None:
            result["refusal"] = {
                "phase": phase,
                "reason": "COMMON_ATTEMPT_CAPTURE_REFUSED",
            }
    finally:
        if candidates:
            try:
                attempt.setup.predecessor._environment(container, (0, 0))
                _export_public(result, candidates, interrupts)
            except BaseException as error:
                _remember_interrupt(error, interrupts)
                result["export_failures"].extend(
                    {
                        "digest": row["digest"],
                        "reason": "OWNED_EXPORT_ENVIRONMENT_REFUSED",
                    }
                    for row in candidates
                )
        if result["attempt"] is not None and journal_valid:
            try:
                attempt.setup.predecessor._environment(container, (0, 0))
                _recover_claim(result, container, interrupts)
            except BaseException as error:
                _remember_interrupt(error, interrupts)
                result["recovery"]["status"] = "INCOMPLETE"
                result["recovery"]["failures"].append(
                    "OWNED_RECOVERY_ENVIRONMENT_REFUSED"
                )
        if bundle is not None:
            try:
                attempt.setup.predecessor._environment(container, (0, 0))
                _require(
                    _read_bundle(expected_bundle_digest) == bundle,
                    "BUNDLE_CUSTODY_CHANGED",
                )
                result["input_bundle_readback"] = True
            except BaseException as error:
                _remember_interrupt(error, interrupts)
                result["postcondition_failures"].append("BUNDLE_AFTER")
        if inspected is not None:
            for source, label in zip(
                _CONTROLLER_PATHS,
                ("WRAPPER_SOURCE_AFTER", "CONTRACT_SOURCE_AFTER"),
                strict=True,
            ):
                try:
                    attempt.setup.predecessor._environment(container, (0, 0))
                    observed = _read_controller(
                        source, inspected["source_raws"][source]
                    )
                    result["controller_sources_after"][source] = observed
                    _require(
                        observed == result["controller_sources"].get(source),
                        "SOURCE_CUSTODY_CHANGED",
                    )
                except BaseException as error:
                    _remember_interrupt(error, interrupts)
                    result["postcondition_failures"].append(label)
    result["interrupted"] = bool(interrupts)
    result["public_export_complete"] = bool(
        journal_valid
        and not result["export_failures"]
        and not result["postcondition_failures"]
        and result["input_bundle_readback"]
        and result["recovery"]["status"]
        in {"NOT_REQUIRED", "CLASSIFIED_PERMANENT_CLAIM_EXPORTED"}
    )
    # Even a classified permanent claim cannot identify unknown provisioning
    # partials left before the handoff yielded. Keep the exact owned fixture.
    preyield = (
        result["attempt"] is not None
        and result["attempt"].get("handoff") is None
        and (result["attempt"].get("refusal") or {}).get("phase")
        == "HELD_PREACTIVATION_HANDOFF"
    )
    result["preserve_fixture_for_evidence"] = called and (
        not result["public_export_complete"] or preyield
    )
    if result["postcondition_failures"] and result["refusal"] is None:
        result["refusal"] = {
            "phase": "FINAL_READBACKS",
            "reason": "CAPTURE_CUSTODY_READBACK_REFUSED",
        }
    if (
        result["refusal"] is None
        and not interrupts
        and result["public_export_complete"]
        and result["attempt"]["status"] == "BOUNDED_NATIVE_ATTEMPT_VERIFIED"
    ):
        result["status"] = "EXPORTED_BOUNDED_ATTEMPT"
    if interrupts:
        interrupts[0]._native_common_attempt_capture = result
        raise interrupts[0]
    return result


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    interrupted = False
    try:
        result = _run(*arguments) if len(arguments) == 2 else _run(None, None)
    except BaseException as error:
        result = getattr(error, "_native_common_attempt_capture", None)
        if result is None:
            raise
        interrupted = True
    raw = canonical_json(result)
    _require(len(raw) + 1 <= MAX_RESULT, "CAPTURE_OUTPUT_BOUND_REFUSED")
    sys.stdout.buffer.write(raw + b"\n")
    return (
        130
        if interrupted
        else (0 if result["status"] == "EXPORTED_BOUNDED_ATTEMPT" else 126)
    )


if __name__ == "__main__":
    raise SystemExit(main())
