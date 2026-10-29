"""Create the original native plan inside the actual seven-writer hook.

The caller supplies the entire real inventory and holds both fresh private CAS
roots through the subsequent handoff and cleanup. No inventory, callback,
timestamp boundary, denial result, activation, or campaign outcome is invented.
Only explicit public roles enter the export journal; private grant bytes do not.
"""

from __future__ import annotations

from contextlib import contextmanager
from io import BytesIO
import json
import os
import re
import stat
import sys

if __package__:
    from scripts import runtime_native_common_measurement_handoff as handoff
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_common_measurement_handoff as handoff

from aragorn import native_phase3_common_preparation as common
from aragorn import phase3_measurement_collector as collector
from aragorn import phase3_quantitative_metrics as metrics
from aragorn import runtime_broker_measurement_plan as broker_plan
from aragorn import runtime_native_measurement_inputs as native_inputs
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-common-attempt-plan/v1"
AUTHORITY = "ORIGINAL_PRIVATE_PLAN_PREPARATION_NOT_ACTIVATION_OR_MEASUREMENT"
MAX_PUBLIC_BLOBS = 48
MAX_BLOB = 1024 * 1024
_ARGUMENTS = {
    "case_id",
    "nonce",
    "container_id",
    "source_record_raw",
    "implementation_source_raws",
    "static_pin_manifest_raw",
    "staged_profile_raw",
    "baseline_capture_raw",
}
FALSE_FLAGS = (
    "activation_performed",
    "measurement_provisioned",
    "workload_executed",
    "measurement_collected",
    "deployment_attested",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "generic_collector_semantics_eligible",
    "resumable",
)
LIMITATIONS = (
    "CALLER_SUPPLIED_INVENTORY_NOT_EXECUTED_OR_QUALIFIED_100_ATTEMPT_CAMPAIGN",
    "ONE_ORIGINAL_COMMITMENT_FOR_ONE_ATTRIBUTED_NATIVE_ATTEMPT",
    "PREPARATION_CLOCK_IS_NOT_REQUEST_INGRESS_OR_BROKER_FINAL_TIMESTAMP",
    "FIXED_FUNCTION_SOURCE_INSPECTION_NOT_GENERIC_CALLBACK_COMPATIBILITY",
    "CALLER_BOOT_AND_PATH_EXPECTATIONS_REQUIRE_ROOT_PROVISIONER_READBACK",
    "PRIVATE_GRANT_AND_UNKNOWN_PARTIAL_INTERNAL_BLOBS_MUST_NOT_BE_EXPORTED",
    "PUBLIC_JOURNAL_IS_AN_EXPLICIT_CANDIDATE_ALLOWLIST_NOT_PUBLICATION_PROOF",
    "CALLER_MUST_HOLD_PRIVATE_CAS_CUSTODY_THROUGH_HANDOFF_AND_CLEANUP",
    "NO_AUTOMATIC_RETRY_RESET_ACTIVATION_OR_OVERALL_SOURCE_ATTESTATION",
)


class NativeCommonAttemptPlanError(ValueError):
    """Retain partial private state and journaled public candidates; do not retry."""


def _require(condition, reason):
    if not condition:
        raise NativeCommonAttemptPlanError(reason)


def _directory(fd):
    value = os.fstat(fd)
    _require(
        stat.S_ISDIR(value.st_mode)
        and value.st_uid == os.geteuid()
        and stat.S_IMODE(value.st_mode) == 0o700,
        "PRIVATE_CAS_DIRECTORY_REQUIRED",
    )
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _names(fd, expected):
    # A fresh directory stream, bounded by the tiny expected structural set.
    duplicate = os.open(
        ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd
    )
    try:
        with os.scandir(duplicate) as entries:
            seen = set()
            for entry in entries:
                _require(
                    entry.name in expected and entry.name not in seen, "CAS_NOT_FRESH"
                )
                seen.add(entry.name)
            _require(seen == expected, "CAS_STRUCTURE_CHANGED")
    finally:
        primary = sys.exception()
        try:
            os.close(duplicate)
        except BaseException:
            if primary is None:
                raise
            primary.add_note("PLAN_DIRECTORY_SCAN_CLOSE_FAILED")


@contextmanager
def _fresh_private_stores(evidence, target):
    _require(
        type(evidence) is CAS
        and type(target) is CAS
        and evidence.read_only is False
        and target.read_only is False,
        "TWO_PRIVATE_WRITABLE_CAS_REQUIRED",
    )
    roots = [store.root.absolute() for store in (evidence, target)]
    _require(
        all(root.resolve(strict=True) == root for root in roots)
        and not roots[0].is_relative_to(roots[1])
        and not roots[1].is_relative_to(roots[0]),
        "CAS_ROOTS_MUST_BE_DISTINCT_AND_DIRECT",
    )
    held, descriptors, root_inodes = [], [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        for root in roots:
            fd = os.open(root, flags)
            descriptors.append(fd)
            identity = _directory(fd)
            root_inodes.append(identity[:2])
            held.append((root, None, fd, identity))
            _names(fd, {"blobs"})
            for name, expected in (("blobs", {"sha256"}), ("sha256", set())):
                parent = fd
                fd = os.open(name, flags, dir_fd=parent)
                descriptors.append(fd)
                held.append((name, parent, fd, _directory(fd)))
                _names(fd, expected)
        _require(root_inodes[0] != root_inodes[1], "CAS_ROOT_INODES_MUST_BE_DISTINCT")

        def guard():
            _require(
                all(root.resolve(strict=True) == root for root in roots),
                "CAS_ROOT_BECAME_INDIRECT",
            )
            for name, parent, fd, identity in held:
                named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _require(
                    _directory(fd)
                    == identity
                    == (
                        named.st_dev,
                        named.st_ino,
                        named.st_mode,
                        named.st_uid,
                        named.st_gid,
                    ),
                    "PRIVATE_CAS_CUSTODY_CHANGED",
                )

        guard()
        try:
            yield guard
        finally:
            primary = sys.exception()
            first = None
            try:
                guard()
            except BaseException as error:
                first = error
                (primary if primary is not None else first).add_note(
                    "PLAN_FINAL_ROOT_CUSTODY_FAILED"
                )
            # Independently examine every held directory on exceptional exits.
            for name, parent, fd, identity in held:
                try:
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    _require(
                        _directory(fd)
                        == identity
                        == (
                            named.st_dev,
                            named.st_ino,
                            named.st_mode,
                            named.st_uid,
                            named.st_gid,
                        ),
                        "PRIVATE_CAS_CUSTODY_CHANGED",
                    )
                except BaseException as error:
                    first = first or error
                    (primary if primary is not None else first).add_note(
                        "PLAN_FINAL_CAS_CUSTODY_FAILED"
                    )
            if first is not None and primary is None:
                raise first
    finally:
        primary, first = sys.exception(), None
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except BaseException as error:
                first = first or error
        if first is not None:
            if primary is None:
                raise first
            primary.add_note("PLAN_CAS_DESCRIPTOR_CLOSE_FAILED")


def prepare_native_common_attempt_plan(
    *,
    common_arguments: dict,
    provisioning_inputs: dict[str, bytes],
    expected_attempt_ids: list[str],
    expected_attempt_families: dict[str, str],
    expected_unattributed_attempt_id: str,
    expected_overhead_pair_bindings: dict[str, dict[str, str]],
    expected_gate_manifest_digest: str,
    expected_campaign_contract_digest: str,
    selected_attempt_id: str,
    expected_boot_id: str,
    protected_descriptor_raw: bytes,
    payload_raw: bytes,
    source_pins: dict[str, str],
    evidence_cas: CAS,
    plan_cas: CAS,
    public_blob_attempts: list,
) -> dict:
    """Create exactly one original commitment, using no caller callbacks.

    Both stores must start empty. The public candidate journal is caller-owned,
    initially empty, bounded, and appended before each explicit public put.
    Collector/planner internal partial blobs are private until their APIs return
    exact bytes and this function classifies those bytes as a known public role.
    Exceptions carry a detached public refusal report and digest candidate list.
    """
    phase, journal, retained, target_retained = "INPUTS", [], {}, {}
    final_checks = []
    result = None

    def report(status, **fields):
        return {
            "schema": SCHEMA,
            "authority": AUTHORITY,
            "status": status,
            "public_blob_attempts": [dict(row) for row in journal],
            "decision": dict.fromkeys(FALSE_FLAGS, False),
            "limitations": list(LIMITATIONS),
            **fields,
        }

    try:
        _require(
            type(public_blob_attempts) is list and not public_blob_attempts,
            "EMPTY_PUBLIC_JOURNAL_REQUIRED",
        )
        _require(
            type(common_arguments) is dict
            and set(common_arguments) == _ARGUMENTS
            and type(provisioning_inputs) is dict
            and type(source_pins) is dict,
            "FIXED_PLAN_ARGUMENT_INVENTORY_REQUIRED",
        )
        arguments = dict(common_arguments)
        arguments["implementation_source_raws"] = dict(
            arguments["implementation_source_raws"]
        )
        inputs, pins = dict(provisioning_inputs), dict(source_pins)
        _require(
            all(
                type(path) is str and type(raw) is bytes for path, raw in inputs.items()
            ),
            "ACTUAL_WRITER_BYTES_REQUIRED",
        )
        _require(
            type(expected_boot_id) is str
            and re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected_boot_id
            )
            is not None,
            "CALLER_BOOT_ID_REQUIRED",
        )
        _require(
            type(protected_descriptor_raw) is bytes
            and 0 < len(protected_descriptor_raw) <= 4096
            and type(payload_raw) is bytes
            and 0 < len(payload_raw) <= 65536,
            "BOUNDED_ACTUAL_ACTION_BYTES_REQUIRED",
        )
        private_pins = {common.old._digest(raw) for raw in inputs.values()}
        with _fresh_private_stores(evidence_cas, plan_cas) as custody:
            reader, target_reader = (
                CAS(evidence_cas.root, read_only=True),
                CAS(plan_cas.root, read_only=True),
            )

            def public_guard():
                _require(
                    canonical_json(public_blob_attempts) == canonical_json(journal),
                    "PUBLIC_JOURNAL_CHANGED",
                )
                for pin, raw in retained.items():
                    _require(
                        reader.read(pin, max_bytes=MAX_BLOB) == raw,
                        "PLAN_SOURCE_CAS_READBACK_CHANGED",
                    )
                for pin, raw in target_retained.items():
                    _require(
                        target_reader.read(pin, max_bytes=MAX_BLOB) == raw,
                        "PLAN_TARGET_CAS_READBACK_CHANGED",
                    )
                custody()

            def put(raw, *, role=None):
                _require(
                    type(raw) is bytes and 0 < len(raw) <= MAX_BLOB,
                    "PLAN_BLOB_BOUND_EXCEEDED",
                )
                pin = common.old._digest(raw)
                custody()
                _require(
                    canonical_json(public_blob_attempts) == canonical_json(journal),
                    "PUBLIC_JOURNAL_CHANGED",
                )
                if role is not None:
                    _require(
                        pin not in private_pins,
                        "PRIVATE_WRITER_CANNOT_ENTER_PUBLIC_JOURNAL",
                    )
                    if not any(row["digest"] == pin for row in journal):
                        _require(
                            len(journal) < MAX_PUBLIC_BLOBS,
                            "PUBLIC_JOURNAL_BOUND_EXCEEDED",
                        )
                        row = {"role": role, "digest": pin, "bytes": len(raw)}
                        journal.append(dict(row))
                        public_blob_attempts.append(dict(row))
                # Retain the attempted bytes in memory before the write/readback,
                # so a partial failure is included in final independent checks.
                retained[pin] = raw
                _require(
                    evidence_cas.put_expected(
                        BytesIO(raw), expected_digest=pin, max_bytes=MAX_BLOB
                    )
                    == pin
                    and reader.read(pin, max_bytes=MAX_BLOB) == raw,
                    "PLAN_RETENTION_FAILED",
                )
                return pin

            try:
                phase = "COMMON_PREPARATION"
                built = common.prepare_native_common_deployment(
                    **arguments, provisioning_inputs=inputs
                )
                phase = "FIXED_ACTION_AND_INVENTORY"
                descriptor = common.old._parse(protected_descriptor_raw, 4096)
                _require(
                    set(descriptor)
                    == {"schema", "root_device", "root_inode", "target_name"}
                    and descriptor["schema"] == "aragorn/runtime-protected-path/v1"
                    and descriptor["target_name"] == "runtime-worker-qualified.txt"
                    and type(descriptor["root_device"]) is int
                    and 0 <= descriptor["root_device"] < 2**63
                    and type(descriptor["root_inode"]) is int
                    and 0 < descriptor["root_inode"] < 2**63
                    and payload_raw == b"Aragorn P3.7b distinct worker create\n",
                    "FIXED_NATIVE_ACTION_CHANGED",
                )
                policy = common.old._parse(inputs[common.old.live._POLICY])
                action = policy["allow"][0]
                _require(
                    action["path_digest"]
                    == common.old._digest(protected_descriptor_raw)
                    and action["payload_digest"] == common.old._digest(payload_raw),
                    "ACTUAL_WRITER_ACTION_DIFFERS",
                )
                schedule = metrics.build_phase3_measurement_schedule(
                    expected_attempt_ids=expected_attempt_ids,
                    expected_attempt_families=expected_attempt_families,
                    expected_unattributed_attempt_id=expected_unattributed_attempt_id,
                    expected_overhead_pair_bindings=expected_overhead_pair_bindings,
                    expected_gate_manifest_digest=expected_gate_manifest_digest,
                    expected_campaign_contract_digest=expected_campaign_contract_digest,
                    expected_runtime_identity_digest=built["preparation"][
                        "deployment_digest"
                    ],
                )
                schedule = json.loads(canonical_json(schedule))
                _require(
                    all(
                        pair["host_profile_digest"]
                        == built["deployment"]["bindings"]["os_profile"]
                        for pair in schedule["overhead_schedule"][
                            "pair_bindings"
                        ].values()
                    ),
                    "CALLER_PAIR_HOST_PROFILE_DIFFERS_FROM_COMMON_DEPLOYMENT",
                )
                _require(
                    type(selected_attempt_id) is str
                    and selected_attempt_id
                    in schedule["attempt_schedule"]["attempt_ids"]
                    and selected_attempt_id
                    != schedule["attempt_schedule"][
                        "unattributed_negative_control_attempt_id"
                    ],
                    "ONE_ATTRIBUTED_SELECTED_ATTEMPT_REQUIRED",
                )
                functions = handoff._functions()
                _require(
                    set(pins) == set(functions), "FIXED_SOURCE_PIN_INVENTORY_REQUIRED"
                )
                sources = {
                    name: collector._source(function, pins[name])
                    for name, function in functions.items()
                }

                def source_replay():
                    current = {
                        name: collector._source(function, pins[name])
                        for name, function in handoff._functions().items()
                    }
                    _require(
                        canonical_json(current) == canonical_json(sources),
                        "FIXED_FUNCTION_SOURCE_CHANGED",
                    )

                final_checks.append(("PLAN_FINAL_FIXED_SOURCE_FAILED", source_replay))
                phase = "COMMON_PUBLIC_RETENTION"
                for raw in built["input_blobs"].values():
                    put(raw, role="common_public_input")
                common._inspect(
                    built["preparation_raw"],
                    built["preparation_digest"],
                    reader,
                    inputs,
                )
                schedule_pin = put(canonical_json(schedule), role="original_schedule")
                phase = "ORIGINAL_COLLECTION_PREPARATION"
                collection = collector.prepare_phase3_measurement_collection(
                    schedule,
                    deployment=built["deployment"],
                    evidence_cas=evidence_cas,
                    **functions,
                    source_pins=pins,
                )
                collection_raw = canonical_json(collection)
                _require(
                    collection["sources"] == sources
                    and collection["schedule_digest"] == schedule_pin,
                    "ORIGINAL_COLLECTION_SOURCE_OR_SCHEDULE_CHANGED",
                )
                put(
                    canonical_json(collection["commitment"]), role="original_commitment"
                )
                collection_pin = put(
                    collection_raw, role="original_collection_preparation"
                )
                collector._prepared_context(
                    collection_raw,
                    collection_pin,
                    evidence_cas,
                    handoff._functions(),
                    pins,
                )
                final_checks.append(
                    (
                        "PLAN_FINAL_ORIGINAL_COLLECTION_FAILED",
                        lambda: collector._prepared_context(
                            collection_raw,
                            collection_pin,
                            evidence_cas,
                            handoff._functions(),
                            pins,
                        ),
                    )
                )
                selected_request = {
                    "kind": "attempt",
                    "attempt_id": selected_attempt_id,
                    "family": schedule["attempt_schedule"]["attempt_families"][
                        selected_attempt_id
                    ],
                    "negative_control": False,
                    "collection_digest": collection["commitment_digest"],
                    "deployment_digest": built["preparation"]["deployment_digest"],
                }
                put(canonical_json(selected_request), role="selected_request")
                path_pin = put(protected_descriptor_raw, role="protected_descriptor")
                phase = "PRIVATE_GRANT_AND_BROKER_PLAN"
                grant_pin = put(inputs[common.old.live._GRANT])
                broker_pins = json.loads(arguments["staged_profile_raw"])[
                    "binding_source_pins"
                ]
                measured = broker_plan.prepare_broker_decision_measurement_binding(
                    source_cas=reader,
                    target_cas=plan_cas,
                    expected_commitment_digest=collection["commitment_digest"],
                    expected_schedule_digest=schedule_pin,
                    expected_deployment_digest=built["preparation"][
                        "deployment_digest"
                    ],
                    expected_grant_digest=grant_pin,
                    expected_path_digest=path_pin,
                    expected_payload_digest=common.old._digest(payload_raw),
                    expected_collector_digest=collection["collector_digest"],
                    expected_collection_source_pins=pins,
                    expected_broker_source_pins=broker_pins,
                    expected_boot_id=expected_boot_id,
                    scheduled_request=selected_request,
                )
                measured_raw = canonical_json(measured)
                measured_pin = common.old._digest(measured_raw)
                bound = native_inputs.validate_prepared_native_measurement_inputs(
                    prepared_raw=measured_raw,
                    expected_prepared_digest=measured_pin,
                    expected_binding_digest=measured["binding_digest"],
                    expected_broker_source_pins=broker_pins,
                    source_cas=target_reader,
                )
                target_retained.update(bound["input_blobs"])
                phase = "EXACT_PLAN_CLOSURE_RETENTION"
                # This is the verified finite closure, not the target CAS inventory.
                for raw in target_retained.values():
                    put(raw)
                binding_raw = canonical_json(measured["binding"])
                put(binding_raw, role="measurement_binding")
                put(measured_raw, role="measurement_preparation")
                phase = "COMMON_MEASURED_REQUEST"
                request_arguments = {
                    "preparation_raw": built["preparation_raw"],
                    "expected_preparation_digest": built["preparation_digest"],
                    "evidence_cas": reader,
                    "provisioning_inputs": inputs,
                    "measurement_prepared_raw": measured_raw,
                    "expected_measurement_prepared_digest": measured_pin,
                    "expected_binding_digest": measured["binding_digest"],
                    "expected_boot_id": expected_boot_id,
                    "protected_descriptor_raw": protected_descriptor_raw,
                    "payload_raw": payload_raw,
                }
                request = common.prepare_native_common_request(**request_arguments)

                def request_replay():
                    _require(
                        common.prepare_native_common_request(**request_arguments)[
                            "request_raw"
                        ]
                        == request["request_raw"],
                        "FINAL_COMMON_REQUEST_CHANGED",
                    )

                final_checks.append(
                    ("PLAN_FINAL_COMMON_REQUEST_FAILED", request_replay)
                )
                put(request["request_raw"], role="common_measured_request")
                phase = "FINAL_REPLAY"
                collector._prepared_context(
                    collection_raw,
                    collection_pin,
                    evidence_cas,
                    handoff._functions(),
                    pins,
                )
                _require(
                    common.prepare_native_common_request(**request_arguments)[
                        "request_raw"
                    ]
                    == request["request_raw"],
                    "FINAL_COMMON_REQUEST_CHANGED",
                )
                public_guard()
                public_report = report(
                    "ORIGINAL_PLAN_PREPARED_NOT_PROVISIONED",
                    container_id=arguments["container_id"],
                    common_preparation_digest=built["preparation_digest"],
                    collection_preparation_digest=collection_pin,
                    commitment_digest=collection["commitment_digest"],
                    measurement_prepared_digest=measured_pin,
                    binding_digest=measured["binding_digest"],
                    request_digest=request["request_digest"],
                    scheduled_request=selected_request,
                    source_records=sources,
                )
                report_raw = canonical_json(public_report)
                _require(len(report_raw) <= 32768, "PUBLIC_PLAN_REPORT_BOUND_EXCEEDED")
                report_pin = put(report_raw, role="plan_report")
                public_guard()
                result = {
                    "common_preparation_raw": built["preparation_raw"],
                    "common_preparation_digest": built["preparation_digest"],
                    "collection_preparation_raw": collection_raw,
                    "collection_preparation_digest": collection_pin,
                    "measurement_prepared_raw": measured_raw,
                    "measurement_prepared_digest": measured_pin,
                    "binding_raw": binding_raw,
                    "binding_digest": measured["binding_digest"],
                    "expected_binding_digest": measured["binding_digest"],
                    "scheduled_request": json.loads(canonical_json(selected_request)),
                    "request_raw": request["request_raw"],
                    "request_digest": request["request_digest"],
                    "public_blob_digests": sorted(row["digest"] for row in journal),
                    "report": json.loads(report_raw),
                    "report_raw": report_raw,
                    "report_digest": report_pin,
                }
            finally:
                primary = sys.exception()
                first = None
                checks = [
                    *final_checks,
                    (
                        "PLAN_FINAL_PUBLIC_JOURNAL_FAILED",
                        lambda: _require(
                            canonical_json(public_blob_attempts)
                            == canonical_json(journal),
                            "PUBLIC_JOURNAL_CHANGED",
                        ),
                    ),
                    ("PLAN_FINAL_CAS_ROOT_FAILED", custody),
                ]
                for store, records, label in (
                    (reader, retained, "PLAN_FINAL_SOURCE_CAS_RECORD_FAILED"),
                    (
                        target_reader,
                        target_retained,
                        "PLAN_FINAL_TARGET_CAS_RECORD_FAILED",
                    ),
                ):
                    for pin, raw in records.items():
                        checks.append(
                            (
                                label,
                                lambda store=store, pin=pin, raw=raw: _require(
                                    store.read(pin, max_bytes=MAX_BLOB) == raw,
                                    "PLAN_FINAL_RETAINED_RECORD_CHANGED",
                                ),
                            )
                        )
                for label, check in checks:
                    try:
                        check()
                    except BaseException as error:
                        first = first or error
                        (primary if primary is not None else first).add_note(label)
                if first is not None and primary is None:
                    raise first
        return result
    except BaseException as error:
        failure = report(
            "REFUSED",
            refusal={"phase": phase, "reason": "ORIGINAL_PLAN_PREPARATION_REFUSED"},
        )
        exposed = (
            error
            if not isinstance(error, Exception)
            else NativeCommonAttemptPlanError(
                "ORIGINAL_PLAN_PREPARATION_REFUSED_PRESERVE_PRIVATE_STATE"
            )
        )
        exposed._native_common_attempt_plan = failure
        exposed._native_common_attempt_public_blob_digests = sorted(
            row["digest"] for row in journal
        )
        if exposed is error:
            raise
        raise exposed from error
