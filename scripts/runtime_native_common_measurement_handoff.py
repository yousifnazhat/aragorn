"""Consume one original native commitment and provision before activation.

Enter this context from the seven-writer preactivation hook using an OUTER
ExitStack which remains open through activation, workload, and cleanup. A local
``with`` inside the hook releases custody too early. This module neither creates
a collection nor invokes the three source-bound functions. In particular it
does not adapt native retained timestamps to the generic collector's mark API.
Private planning inputs (including the grant) must never be blanket-exported.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import sys

if __package__:
    from scripts import runtime_native_blocked_create_workload as workload
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_blocked_create_workload as workload

from aragorn import native_phase3_blocked_create_verify as blockedverify
from aragorn import native_phase3_common_identity as commonidentity
from aragorn import native_phase3_common_preparation as common
from aragorn import phase3_measurement_collector as collector
from aragorn import runtime_native_measurement_provisioning as provisioning
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/native-common-measurement-handoff/v1"
AUTHORITY = "LOCAL_ORIGINAL_COMMITMENT_PROVISIONING_NOT_ACTIVATION_OR_MEASUREMENT"
_CGROUP = Path("/proc/1/cgroup")
_LIMIT = 1024 * 1024
_FALSE = (
    "activation_performed",
    "workload_executed",
    "measurement_collected",
    "resumable",
    "deployment_attested",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "generic_collector_semantics_eligible",
)
LIMITATIONS = (
    "ONE_ATTRIBUTED_ATTEMPT_CONSUMES_ENTIRE_COMMITMENT_NOT_A_100_ATTEMPT_CAMPAIGN",
    "PREACTIVATION_CHECKPOINT_NOT_BODY_COMPLETION_OR_RESUMABLE_AUTHORITY",
    "CALLER_MUST_HOLD_CONTEXT_THROUGH_ACTIVATION_WORKLOAD_AND_CLEANUP",
    "CLAIM_CLOCK_IS_NOT_REQUEST_INGRESS_OR_BROKER_FINAL_TIMESTAMP",
    "V1_PREPARATION_HAS_NO_SAME_BOOT_OR_TIME_NAMESPACE_PROOF",
    "SOURCE_INSPECTION_ONLY_NO_GENERIC_CALLBACK_SIGNATURE_OR_SEMANTIC_COMPATIBILITY",
    "PRIVATE_INPUT_CLOSURE_INCLUDES_GRANT_AND_MUST_NOT_BE_PUBLICLY_EXPORTED",
    "LOCAL_CLAIM_NOT_HOSTILE_OWNER_RESISTANT_OR_CROSS_STORE_REPLAY_PREVENTION",
    "NO_ACTIVATION_SERVICE_CLEANUP_TIMEOUT_RESET_OR_AUTOMATIC_RETRY",
    "RETAINED_INPUT_CUSTODY_NOT_CONTINUOUS_RUNTIME_IDENTITY_OR_EFFECT_PROOF",
)


class NativeCommonMeasurementHandoffError(ValueError):
    """A fixed handoff failed; retain partial state and never retry its claim."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeCommonMeasurementHandoffError(reason)


def _functions() -> dict:
    return {
        "execute": workload.run_native_blocked_create_workload,
        "verify": blockedverify.verify_native_blocked_create,
        "identity_reader": commonidentity.read_native_common_identity,
    }


@contextmanager
def _fixture(expected_container_id: str, expected_boot_id: str):
    _require(
        sys.platform == "linux" and os.geteuid() == os.getegid() == 0,
        "LINUX_ROOT_GUEST_REQUIRED",
    )
    _require(
        type(expected_container_id) is str
        and re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is not None
        and type(expected_boot_id) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected_boot_id
        )
        is not None,
        "INVALID_OWNED_FIXTURE_ARGUMENTS",
    )
    fd = os.open(_CGROUP, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        initial = os.fstat(fd)
        identity = provisioning.broker._file_identity(initial)

        def guard() -> None:
            _require(
                sys.platform == "linux"
                and os.geteuid() == os.getegid() == 0
                and stat.S_ISREG(initial.st_mode)
                and initial.st_uid == 0
                and provisioning.broker._file_identity(os.fstat(fd)) == identity
                and provisioning.broker._file_identity(_CGROUP.lstat()) == identity
                and os.pread(fd, 1025, 0)
                == f"0::/docker/{expected_container_id}/init.scope\n".encode("ascii")
                and provisioning._boot_id() == expected_boot_id,
                "OWNED_FIXTURE_OR_BOOT_CHANGED",
            )

        guard()
        try:
            yield guard
        finally:
            primary = sys.exception()
            try:
                guard()
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("HANDOFF_FINAL_FIXTURE_CHECK_FAILED")
    finally:
        primary = sys.exception()
        try:
            os.close(fd)
        except BaseException:
            if primary is None:
                raise
            primary.add_note("HANDOFF_FIXTURE_CLOSE_FAILED")


class _Session:
    """Only detached public records and a non-resumable held-custody guard."""

    def __init__(self, guard, request_raw, provisioning_raw, report_raw, claim_raw):
        self._guard = guard
        self._request = request_raw
        self._provisioning = provisioning_raw
        self._report = report_raw
        self._claim = claim_raw

    def guard(self) -> None:
        self._guard()

    @property
    def request(self):
        return json.loads(self._request)

    @property
    def request_raw(self):
        return self._request

    @property
    def request_digest(self):
        return canonical_digest(self.request)

    @property
    def provisioning(self):
        return json.loads(self._provisioning)

    @property
    def provisioning_raw(self):
        return self._provisioning

    @property
    def provisioning_digest(self):
        return canonical_digest(self.provisioning)

    @property
    def report(self):
        return json.loads(self._report)

    @property
    def report_raw(self):
        return self._report

    @property
    def report_digest(self):
        return canonical_digest(self.report)

    @property
    def claim_raw(self):
        return self._claim


def _provisioned(value: dict, measured: dict, binding_pin: str) -> bytes:
    # The fixed provisioner owns its OS checks. Bind its returned public report
    # to these inputs; this is not an independent replay of runtime provisioning.
    raw = canonical_json(value)
    _require(0 < len(raw) <= 32768, "PROVISIONING_REPORT_UNBOUNDED")
    detached = json.loads(raw)
    _require(
        type(detached) is dict
        and set(detached)
        == {
            "schema",
            "authority",
            "prepared_digest",
            "binding_digest",
            "credential",
            "input_store",
            "input_blobs",
            "broker_uid",
            "broker_gid",
            "boot_id",
            "stopped_units",
            "payload_digest_expectation",
            "payload_bytes_verified",
            "activation_performed",
            "measurement_collected",
            "run_qualified",
            "quantitative_metrics_eligible",
            "phase3_exit_eligible",
            "limitations",
        }
        and detached["schema"] == "aragorn/native-measurement-provisioning/v1"
        and detached["authority"]
        == "ROOT_PROVISIONED_INPUTS_ONLY_NOT_ACTIVATION_MEASUREMENT_OR_PHASE3"
        and detached["prepared_digest"] == canonical_digest(measured)
        and detached["binding_digest"] == binding_pin
        and detached["boot_id"] == measured["binding"]["boot_id"]
        and canonical_json(detached["input_blobs"])
        == canonical_json(measured["input_blobs"])
        and detached["credential"] == str(provisioning._CREDENTIAL)
        and detached["input_store"] == str(provisioning._STORE)
        and detached["payload_digest_expectation"]
        == measured["binding"]["payload_digest"]
        and all(
            type(detached[name]) is int and 0 < detached[name] < 2**32
            for name in ("broker_uid", "broker_gid")
        )
        and type(detached["stopped_units"]) is dict
        and set(detached["stopped_units"]) == set(provisioning._UNITS)
        and all(
            detached[name] is False
            for name in (
                "payload_bytes_verified",
                "activation_performed",
                "measurement_collected",
                "run_qualified",
                "quantitative_metrics_eligible",
                "phase3_exit_eligible",
            )
        ),
        "PROVISIONING_REPORT_JOIN_FAILED",
    )
    return raw


@contextmanager
def hold_prepared_native_common_measurement(
    *,
    collection_preparation_raw: bytes,
    expected_collection_preparation_digest: str,
    common_preparation_raw: bytes,
    expected_common_preparation_digest: str,
    measurement_prepared_raw: bytes,
    expected_measurement_prepared_digest: str,
    expected_binding_digest: str,
    scheduled_request: dict,
    provisioning_inputs: dict[str, bytes],
    expected_container_id: str,
    expected_boot_id: str,
    protected_descriptor_raw: bytes,
    payload_raw: bytes,
    evidence_cas: CAS,
    source_pins: dict[str, str],
):
    """Permanently consume one original commitment, without invoking callbacks.

    All input blobs and reports must already be in this caller-owned private CAS.
    One attributed attempt consumes the entire commitment, not one campaign slot.
    The same claim namespace as the generic prepared collector prevents a second
    local consumption through either API. A body failure or interruption never
    deletes the claim, published request, partial broker store, or credential.
    """
    try:
        _require(
            type(evidence_cas) is CAS and evidence_cas.read_only is False,
            "PRIVATE_WRITABLE_CAS_REQUIRED",
        )
        _require(
            type(source_pins) is dict and type(provisioning_inputs) is dict,
            "INPUT_INVENTORY_CHANGED",
        )
        pins = dict(source_pins)
        inputs = dict(provisioning_inputs)
        _require(
            all(
                type(path) is str and type(raw) is bytes for path, raw in inputs.items()
            ),
            "WRITER_BYTES_REQUIRED",
        )
        functions = _functions()
        reader = CAS(evidence_cas.root, read_only=True)
        request_arguments = {
            "preparation_raw": common_preparation_raw,
            "expected_preparation_digest": expected_common_preparation_digest,
            "evidence_cas": reader,
            "provisioning_inputs": inputs,
            "measurement_prepared_raw": measurement_prepared_raw,
            "expected_measurement_prepared_digest": expected_measurement_prepared_digest,
            "expected_binding_digest": expected_binding_digest,
            "expected_boot_id": expected_boot_id,
            "protected_descriptor_raw": protected_descriptor_raw,
            "payload_raw": payload_raw,
        }
        with _fixture(expected_container_id, expected_boot_id) as fixture_guard:
            prepared = collector._prepared_context(
                collection_preparation_raw,
                expected_collection_preparation_digest,
                evidence_cas,
                functions,
                pins,
            )
            built = common.prepare_native_common_request(**request_arguments)
            request_raw = built["request_raw"]
            request = built["request"]
            measured = json.loads(measurement_prepared_raw)
            binding = measured["binding"]
            attempts = prepared["schedule"]["attempt_schedule"]
            _require(type(scheduled_request) is dict, "SCHEDULED_REQUEST_REQUIRED")
            selected = scheduled_request.get("attempt_id")
            _require(
                type(selected) is str
                and selected in attempts["attempt_ids"]
                and selected != attempts["unattributed_negative_control_attempt_id"],
                "ONE_ATTRIBUTED_ATTEMPT_REQUIRED",
            )
            original_request = {
                "kind": "attempt",
                "attempt_id": selected,
                "family": attempts["attempt_families"][selected],
                "negative_control": False,
                "collection_digest": prepared["commitment_digest"],
                "deployment_digest": canonical_digest(prepared["deployment"]),
            }
            _require(
                canonical_json(scheduled_request) == canonical_json(original_request)
                and binding["collection_commitment_digest"]
                == prepared["commitment_digest"]
                and binding["measurement_schedule_digest"]
                == prepared["schedule_digest"]
                and binding["scheduled_measurement_request_digest"]
                == canonical_digest(original_request)
                and binding["attempt_id"] == selected
                and request["deployment_digest"]
                == original_request["deployment_digest"]
                and request["container_id"] == expected_container_id,
                "ORIGINAL_COMMITMENT_REQUEST_OR_FIXTURE_JOIN_FAILED",
            )
            closure = dict(built["input_blobs"])
            public = {}

            def source_guard():
                collector._prepared_context(
                    collection_preparation_raw,
                    expected_collection_preparation_digest,
                    evidence_cas,
                    _functions(),
                    pins,
                )

            def request_guard():
                rebuilt = common.prepare_native_common_request(**request_arguments)
                _require(
                    rebuilt["request_raw"] == request_raw, "COMMON_REQUEST_CHANGED"
                )

            def private_guard():
                for pin, raw in closure.items():
                    _require(
                        reader.read(pin, max_bytes=_LIMIT) == raw,
                        "PRIVATE_INPUT_CUSTODY_CHANGED",
                    )

            def public_guard():
                for pin, raw in public.items():
                    _require(
                        reader.read(pin, max_bytes=32768) == raw,
                        "PUBLIC_OUTPUT_CUSTODY_CHANGED",
                    )

            def input_guard():
                fixture_guard()
                source_guard()
                request_guard()
                private_guard()
                public_guard()
                fixture_guard()

            input_guard()
            stamp = collector._boottime_ns()
            _require(
                type(stamp) is int
                and prepared["commitment_readback_boottime_ns"] <= stamp < 2**63,
                "CLAIM_CLOCK_CHRONOLOGY_CHANGED",
            )
            claim = {
                "schema": "aragorn/native-common-measurement-claim/v1",
                "collection_preparation_digest": expected_collection_preparation_digest,
                "common_preparation_digest": expected_common_preparation_digest,
                "measurement_prepared_digest": expected_measurement_prepared_digest,
                "commitment_digest": prepared["commitment_digest"],
                "request_digest": canonical_digest(original_request),
                "common_request_digest": built["request_digest"],
                "binding_digest": expected_binding_digest,
                "container_id": expected_container_id,
                "claimed_boottime_ns": stamp,
                "state": "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
            }
            with collector._prepared_attempt_claim(evidence_cas, claim) as (
                claim_guard,
                claim_raw,
            ):
                active = True

                def guard():
                    _require(active, "HANDOFF_CONTEXT_CLOSED")
                    claim_guard()
                    input_guard()
                    claim_guard()

                def retain(raw):
                    pin = common.old._digest(raw)
                    # Track exact attempted public bytes before the CAS call so
                    # partial publication/readback failures also get a final read.
                    public[pin] = raw
                    _require(
                        collector._store(evidence_cas, raw, 32768) == pin,
                        "PUBLIC_RETENTION_PIN_CHANGED",
                    )
                    return pin

                try:
                    claim_pin = retain(claim_raw)
                    request_pin = retain(request_raw)
                    guard()
                    broker_pins = {
                        name: request["expected_file_digests"][path]
                        for name, path in commonidentity.MEASUREMENT_SOURCES.items()
                    }
                    provisioned = provisioning.provision_runtime_native_measurement(
                        prepared_raw=measurement_prepared_raw,
                        expected_prepared_digest=expected_measurement_prepared_digest,
                        expected_binding_digest=expected_binding_digest,
                        expected_broker_source_pins=broker_pins,
                        source_cas=reader,
                    )
                    provisioning_raw = _provisioned(
                        provisioned, measured, expected_binding_digest
                    )
                    provisioning_pin = retain(provisioning_raw)
                    guard()
                    report = {
                        "schema": SCHEMA,
                        "authority": AUTHORITY,
                        "status": "INPUTS_PROVISIONED_NOT_ACTIVATED",
                        "container_id": expected_container_id,
                        "collection_preparation_digest": expected_collection_preparation_digest,
                        "common_preparation_digest": expected_common_preparation_digest,
                        "measurement_prepared_digest": expected_measurement_prepared_digest,
                        "commitment_digest": prepared["commitment_digest"],
                        "scheduled_request": original_request,
                        "scheduled_request_digest": canonical_digest(original_request),
                        "binding_digest": expected_binding_digest,
                        "request_digest": request_pin,
                        "provisioning_digest": provisioning_pin,
                        "claim_digest": claim_pin,
                        "claimed_boottime_ns": stamp,
                        "decision": dict.fromkeys(_FALSE, False),
                        "limitations": list(LIMITATIONS),
                    }
                    report_raw = canonical_json(report)
                    retain(report_raw)
                    guard()
                    yield _Session(
                        guard, request_raw, provisioning_raw, report_raw, claim_raw
                    )
                finally:
                    primary = sys.exception()
                    first_failure = None
                    try:
                        # These checks deliberately do not short-circuit: claim,
                        # source, private/public inputs, and fixture failures are
                        # independent evidence even if provisioning never yields.
                        for check, label in (
                            (claim_guard, "HANDOFF_FINAL_CLAIM_CHECK_FAILED"),
                            (source_guard, "HANDOFF_FINAL_SOURCE_CHECK_FAILED"),
                            (request_guard, "HANDOFF_FINAL_REQUEST_CHECK_FAILED"),
                            (private_guard, "HANDOFF_FINAL_PRIVATE_INPUT_CHECK_FAILED"),
                            (public_guard, "HANDOFF_FINAL_PUBLIC_OUTPUT_CHECK_FAILED"),
                            (fixture_guard, "HANDOFF_FINAL_FIXTURE_CHECK_FAILED"),
                        ):
                            try:
                                check()
                            except BaseException as error:
                                if first_failure is None:
                                    first_failure = error
                                (
                                    primary if primary is not None else first_failure
                                ).add_note(label)
                        if first_failure is not None and primary is None:
                            raise first_failure
                    finally:
                        active = False
    except NativeCommonMeasurementHandoffError:
        raise
    except Exception as error:
        raise NativeCommonMeasurementHandoffError(
            "NATIVE_HANDOFF_REFUSED_PRESERVE_PARTIAL_STATE"
        ) from error
