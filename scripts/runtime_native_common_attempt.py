"""One fixed first-activation guest attempt, not host automation or qualification.

The seven actual writers feed the plan before the only activation. Both private
CAS roots and the original-commitment handoff remain held until the four-service
cleanup finishes. Public retention is a finite journal, never CAS enumeration.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import grp
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
from unittest.mock import patch

if __package__:
    from scripts import runtime_native_common_case_setup as setup
    from scripts import runtime_native_common_attempt_plan as planner
    from scripts import runtime_native_common_measurement_handoff as handoff
    from scripts import runtime_native_blocked_create_workload as workload
    from scripts import runtime_native_measurement_evidence_snapshot as snapshot
    from scripts import runtime_phase3_common_process_observer as observer
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_common_case_setup as setup
    import runtime_native_common_attempt_plan as planner
    import runtime_native_common_measurement_handoff as handoff
    import runtime_native_blocked_create_workload as workload
    import runtime_native_measurement_evidence_snapshot as snapshot
    import runtime_phase3_common_process_observer as observer

from aragorn import native_phase3_common_identity as identity
from aragorn import native_phase3_common_process_verifier as process_verify
from aragorn import native_phase3_clock_domain as clock
from aragorn import native_phase3_blocked_create_verify as blocked
from aragorn import native_phase3_ingress_interval_verify as interval
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

SOURCE_PATH = "/opt/aragorn/runtime_native_common_attempt.py"
CAS_ROOT = "/run/aragorn-native-common-attempt"
SCHEMA = "aragorn/native-common-attempt/v1"
AUTHORITY = "OWNED_FIRST_ACTIVATION_BOUNDED_ATTEMPT_NOT_HOST_OR_CAMPAIGN_AUTHORITY"
_PAYLOAD = b"Aragorn P3.7b distinct worker create\n"
_MAX_BLOB = 32 * 1024 * 1024
_MAX_PUBLIC = 128 * 1024 * 1024
_MAX_CANDIDATES = 256
_EPOCH = ("pid", "start_time_ticks", "uid", "gid")
_COMMON_ARGUMENTS = {
    "case_id",
    "nonce",
    "container_id",
    "source_record_raw",
    "implementation_source_raws",
    "static_pin_manifest_raw",
    "staged_profile_raw",
    "baseline_capture_raw",
}
_PLAN_ARGUMENTS = {
    "expected_attempt_ids",
    "expected_attempt_families",
    "expected_unattributed_attempt_id",
    "expected_overhead_pair_bindings",
    "expected_gate_manifest_digest",
    "expected_campaign_contract_digest",
    "selected_attempt_id",
}
SOURCE_PATHS = (
    SOURCE_PATH,
    setup.SETUP_PATH,
    "/opt/aragorn/runtime_native_common_attempt_plan.py",
    "/opt/aragorn/runtime_native_common_measurement_handoff.py",
    workload.SOURCE_PATH,
    workload.REVOCATION_SOURCE_PATH,
    workload.SINK_SOURCE_PATH,
    "/opt/aragorn/runtime_native_measurement_evidence_snapshot.py",
    "/opt/aragorn/runtime_phase3_common_process_observer.py",
    "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py",
    "/usr/lib/aragorn/aragorn/native_phase3_common_process_verifier.py",
    "/usr/lib/aragorn/aragorn/native_phase3_clock_domain.py",
    "/usr/lib/aragorn/aragorn/native_phase3_blocked_create_verify.py",
    "/usr/lib/aragorn/aragorn/native_phase3_ingress_interval_verify.py",
)
FALSE_FLAGS = (
    "deployment_attested",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "generic_collector_semantics_eligible",
    "blocked_pre_effect",
    "causal_attribution",
    "transient_effects_excluded",
    "host_capture_verified",
)
LIMITATIONS = (
    "GUEST_ONLY_HOST_INSTALL_INVENTORY_NETWORK_MODE_AND_EXPORT_REMAIN_SEPARATE",
    "ONE_ATTRIBUTED_ATTEMPT_CONSUMES_ORIGINAL_COMMITMENT_NOT_A_FULL_CAMPAIGN",
    "ADMISSION_CASE_METADATA_NOT_EXECUTED_ADMISSION_LEAF_OR_ROUTE_QUALIFICATION",
    "LOOPBACK_ONLY_GUEST_INVENTORY_NOT_HOST_DOCKER_NETWORK_MODE_ATTESTATION",
    "PUBLIC_ALLOWLIST_ONLY_PRIVATE_PLANNING_CAS_CONTAINS_GRANT_AND_MUST_NOT_BE_EXPORTED",
    "FIXED_INTERNAL_EVENT_COMPOSITION_NOT_GENERIC_COLLECTOR_MARK_TRANSLATION",
    "NO_AUTOMATIC_RETRY_RESET_RESTART_OR_RESUME_AFTER_PARTIAL_FAILURE",
    "LOCAL_SOURCE_AND_PROCESS_READBACKS_NOT_HOSTILE_ROOT_OR_LOADED_PYTHON_ATTESTATION",
)


class NativeCommonAttemptError(ValueError):
    """Fixed secret-safe refusal; partial files are never removed or repaired."""


def _require(value, reason):
    if not value:
        raise NativeCommonAttemptError(reason)


def _source_guard(pins):
    _require(
        type(pins) is dict and set(pins) == set(SOURCE_PATHS),
        "SOURCE_INVENTORY_CHANGED",
    )
    _require(
        os.path.abspath(__file__) == SOURCE_PATH, "INSTALLED_CONTROLLER_PATH_CHANGED"
    )
    records = {}
    for path in SOURCE_PATHS:
        _, metadata = workload._read_fixed(path, 0o444, 2 * 1024 * 1024)
        _require(
            metadata["digest"] == workload._pin(pins[path]),
            "INSTALLED_SOURCE_PIN_CHANGED",
        )
        records[path] = metadata
    # In particular the fixed old bootstrap is checked before package._native.
    records.update(
        workload._sources(
            pins[workload.SOURCE_PATH],
            pins[workload.SINK_SOURCE_PATH],
            pins[workload.REVOCATION_SOURCE_PATH],
        )
    )
    return records


def _network():
    with workload._ancestry("/sys/class/net") as (fd, guard):
        with os.scandir(fd) as entries:
            first = next(entries, None)
            second = next(entries, None)
        _require(
            first is not None and first.name == "lo" and second is None,
            "LOOPBACK_ONLY_GUEST_NETWORK_REQUIRED",
        )
        guard()
        return {
            "path": "/sys/class/net",
            "entries": ["lo"],
            "identity": workload._directory(fd),
        }


def _arguments(common, plan, setup_pin, sources):
    _require(
        type(common) is dict
        and set(common) == _COMMON_ARGUMENTS
        and type(plan) is dict
        and set(plan) == _PLAN_ARGUMENTS,
        "FIXED_ARGUMENT_INVENTORY_CHANGED",
    )
    common = {
        **common,
        "implementation_source_raws": dict(common["implementation_source_raws"]),
    }
    stage = setup._inputs(common, setup_pin)
    _require(
        type(sources) is dict
        and set(sources) == set(SOURCE_PATHS)
        and sources[setup.SETUP_PATH] == setup_pin,
        "SETUP_SOURCE_JOIN_CHANGED",
    )
    for pin in sources.values():
        workload._pin(pin)
    for name, path in setup._IMPLEMENTATION_PATHS.items():
        if path in sources:
            _require(
                workload._digest(common["implementation_source_raws"][name])
                == sources[path],
                "IMPLEMENTATION_SOURCE_JOIN_CHANGED",
            )
    raw = canonical_json(plan)
    _require(0 < len(raw) <= 128 * 1024, "PLAN_ARGUMENT_BOUND_REFUSED")
    plan = json.loads(raw)
    _require(
        type(plan["selected_attempt_id"]) is str
        and 0 < len(plan["selected_attempt_id"]) <= 256,
        "INVALID_SELECTED_ATTEMPT",
    )
    return common, plan, stage


@contextmanager
def _stores():
    descriptors, directories = [], []
    try:
        with workload._ancestry("/run") as (run, ancestry_guard):
            name = Path(CAS_ROOT).name
            workload._absent(run, name)
            os.mkdir(name, 0o700, dir_fd=run)
            os.fsync(run)

            def child(parent, name):
                fd = os.open(name, workload._FLAGS, dir_fd=parent)
                descriptors.append(fd)
                directories.append((parent, name, fd, workload._directory(fd, 0o700)))
                return fd

            root = child(run, name)
            for name in ("evidence", "plan"):
                os.mkdir(name, 0o700, dir_fd=root)
                child(root, name)
            os.fsync(root)

            def guard():
                ancestry_guard()
                for parent, name, fd, expected in directories:
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    _require(
                        workload._directory(fd, 0o700)
                        == expected
                        == [
                            named.st_dev,
                            named.st_ino,
                            named.st_mode,
                            named.st_uid,
                            named.st_gid,
                        ],
                        "PRIVATE_CAS_CUSTODY_CHANGED",
                    )

            guard()
            evidence, plan = CAS(CAS_ROOT + "/evidence"), CAS(CAS_ROOT + "/plan")
            guard()
            try:
                yield evidence, plan, guard
            finally:
                setup._close_preserving(guard, "PRIVATE_CAS_FINAL_CUSTODY_REFUSED")
    finally:
        workload._close_all(descriptors)


@contextmanager
def _protected_descriptor(native):
    """Read and hold the actual fresh root selected by these seven writers."""
    uid, _, runtime_gid, *_ = native.response._identities()
    descriptors = []
    try:
        with workload._ancestry("/var/lib/aragorn-runtime-action") as (
            parent,
            parent_guard,
        ):
            fd = os.open("protected", workload._FLAGS, dir_fd=parent)
            descriptors.append(fd)
            before = os.fstat(fd)
            expected = [
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_uid,
                before.st_gid,
            ]

            def guard():
                parent_guard()
                actual = os.fstat(fd)
                named = os.stat("protected", dir_fd=parent, follow_symlinks=False)
                _require(
                    stat.S_ISDIR(actual.st_mode)
                    and actual.st_uid == uid
                    and actual.st_gid == runtime_gid
                    and stat.S_IMODE(actual.st_mode) == 0o710
                    and expected
                    == [
                        actual.st_dev,
                        actual.st_ino,
                        actual.st_mode,
                        actual.st_uid,
                        actual.st_gid,
                    ]
                    == [
                        named.st_dev,
                        named.st_ino,
                        named.st_mode,
                        named.st_uid,
                        named.st_gid,
                    ],
                    "ACTUAL_PROTECTED_ROOT_CHANGED",
                )

            guard()
            descriptor = {
                "schema": "aragorn/runtime-protected-path/v1",
                "root_device": before.st_dev,
                "root_inode": before.st_ino,
                "target_name": "runtime-worker-qualified.txt",
            }
            try:
                yield canonical_json(descriptor), guard
            finally:
                setup._close_preserving(guard, "PROTECTED_ROOT_FINAL_CUSTODY_REFUSED")
    finally:
        workload._close_all(descriptors)


def _raw(record):
    _require(
        type(record) is dict
        and set(record) == {"text", "bytes", "digest"}
        and type(record["text"]) is str,
        "PUBLIC_RECORD_SHAPE_CHANGED",
    )
    raw = record["text"].encode("ascii")
    _require(
        type(record["bytes"]) is int
        and record["bytes"] == len(raw)
        and 0 < len(raw) <= _MAX_BLOB
        and workload._digest(raw) == record["digest"],
        "PUBLIC_RECORD_PIN_CHANGED",
    )
    return raw


def _retain(writer, reader, guard, journal, role, raw):
    _require(
        type(raw) is bytes
        and 0 < len(raw) <= _MAX_BLOB
        and len(journal) < _MAX_CANDIDATES
        and sum(row["bytes"] for row in journal) + len(raw) <= _MAX_PUBLIC,
        "PUBLIC_RETENTION_BOUND_REFUSED",
    )
    pin = workload._digest(raw)
    journal.append({"role": role, "digest": pin, "bytes": len(raw)})
    _require(
        writer.put_expected(io.BytesIO(raw), expected_digest=pin, max_bytes=_MAX_BLOB)
        == pin
        and reader.read(pin, max_bytes=_MAX_BLOB) == raw,
        "PUBLIC_RETENTION_REFUSED",
    )
    guard()
    return pin


def _expectations(common, observed, boot):
    _require(
        common["boot_id"] == observed["boot_id"] == boot.replace("-", ""),
        "ACTUAL_BOOT_JOIN_CHANGED",
    )
    expected = {
        role: {key: observed["processes"][role]["process"][key] for key in _EPOCH}
        for role in ("worker", "broker", "gateway")
    }
    workload._processes(common, expected)
    path = f"/proc/{expected['broker']['pid']}/ns/mnt"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        metadata = os.fstat(fd)
        namespace = os.readlink(path)
        named = os.stat(path)
        _require(
            {"device": metadata.st_dev, "inode": metadata.st_ino}
            == common["processes"]["broker"]["mount_namespace"]
            and (named.st_dev, named.st_ino) == (metadata.st_dev, metadata.st_ino)
            and namespace == f"mnt:[{metadata.st_ino}]",
            "BROKER_MOUNT_NAMESPACE_CHANGED",
        )
    finally:
        workload._close_all([fd])
    broker = expected["broker"] | {"boot_id": boot, "mount_namespace": namespace}
    accounts = {
        "broker_uid": expected["broker"]["uid"],
        "runtime_gid": expected["worker"]["gid"],
        "broker_gid": grp.getgrnam("aragorn-broker").gr_gid,
    }
    return expected, broker, accounts


def _verify(
    work,
    measured,
    clocks,
    expected,
    broker,
    accounts,
    request,
    binding_raw,
    sources,
    reader,
):
    records = measured["records"]
    common = {
        name + "_raw": _raw(records[name])
        for name in ("startup", "ingress", "attempt", "action")
    }
    common.update(
        expected_record_digests={
            name: records[name]["digest"]
            for name in ("startup", "ingress", "attempt", "action")
        },
        completion_raw=_raw(records["completion"]),
        expected_completion_digest=records["completion"]["digest"],
        expected_binding_raw=binding_raw,
        expected_binding_digest=request["measurement_binding_digest"],
        expected_worker=expected["worker"],
        expected_broker_process=broker,
        expected_worker_binding_digest=request["expected_file_digests"][
            identity.prior._WORKER
        ],
        expected_genesis_digest=request["expected_file_digests"][
            identity.prior._GENESIS
        ],
        input_cas=reader,
        evidence_cas=reader,
    )
    driver = {
        name + "_raw": _raw(work["records"][name])
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
    blocked_result = blocked.verify_native_blocked_create(
        **common,
        **driver,
        expected_gateway={
            key: expected["gateway"][key] for key in ("pid", "uid", "gid")
        },
        expected_container_id=request["container_id"],
        expected_sink_source_digest=sources[workload.SINK_SOURCE_PATH],
        expected_sink_accounts=accounts,
    )
    interval_result = interval.verify_native_ingress_interval(
        **common,
        clock_before_raw=clocks["before"],
        clock_after_raw=clocks["after"],
        expected_clock_before_digest=workload._digest(clocks["before"]),
        expected_clock_after_digest=workload._digest(clocks["after"]),
    )
    return {"blocked_create": blocked_result, "ingress_interval": interval_result}


def run_native_common_attempt(
    *, common_arguments, plan_arguments, expected_setup_digest, expected_source_digests
):
    """Perform only this guest boundary, with fixed operations and no retry."""
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "setup_state": {
            "activation_count": 0,
            "pins_frozen_before_activation": False,
            "provisioning_file_digests": {},
        },
        "callback_count": 0,
        "workload_count": 0,
        "snapshot_count": 0,
        "public_blob_attempts": [],
        "public_blob_digests": [],
        "public_readback_failures": [],
        "sources_before": None,
        "sources_after": None,
        "installed_sources": None,
        "installed_sources_after": None,
        "implementation_sources": None,
        "implementation_sources_after": None,
        "network_before": None,
        "network_after": None,
        "writer_readback": None,
        "writer_readback_after": None,
        "plan": None,
        "handoff": None,
        "workload": None,
        "snapshot": None,
        "verification": None,
        "process_verification": None,
        "fixture_stack_cleanup": None,
        "cleanup_count": 0,
        "refusal": None,
        "postcondition_failures": [],
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    stack, primary, native, writer, reader, guard, session = (
        ExitStack(),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    phase, cleanup_required, captured_inputs = "INPUTS", False, {}
    (
        built,
        descriptor,
        request,
        work,
        measured,
        before,
        observed,
        expected,
        broker,
        accounts,
    ) = (None,) * 10
    clocks = {}
    sources = (
        dict(expected_source_digests) if type(expected_source_digests) is dict else {}
    )

    def failure(label, operation):
        nonlocal primary
        try:
            return operation()
        except BaseException as error:
            result["postcondition_failures"].append(label)
            if primary is None and not isinstance(error, Exception):
                primary = error
            return None

    def retain(role, raw):
        return _retain(writer, reader, guard, result["public_blob_attempts"], role, raw)

    try:
        common, plan, stage = _arguments(
            common_arguments, plan_arguments, expected_setup_digest, sources
        )
        container = common["container_id"]
        phase = "OWNED_SOURCE_GUARDS"
        setup.predecessor._environment(container, (0, 0))
        result["network_before"] = _network()
        result["sources_before"] = _source_guard(sources)
        native = setup.predecessor.package._native()
        native.setup_prior._require_fixture(container)
        stack.enter_context(
            patch.object(
                native, "_STARTUP_CODE", native._STARTUP_CODE | setup._overrides(stage)
            )
        )
        result["installed_sources"] = native._sources(health=True, startup_reserve=True)
        result["implementation_sources"] = setup._implementation_readback(
            common["implementation_source_raws"], expected_setup_digest
        )
        phase = "UNUSED_GUARDS"
        setup.measurement.require_native_measurement_unused()
        setup._ingress_absent()
        with workload._ancestry("/run") as (run, parent_guard):
            workload._absent(run, Path(CAS_ROOT).name)
            workload._absent(run, Path(workload.ATTEMPT_ROOT).name)
            parent_guard()
        cleanup_required = True
        writer, private_plan, guard = stack.enter_context(_stores())
        reader = CAS(writer.root, read_only=True)

        def before_activation(inputs, state):
            nonlocal phase, session, built, descriptor, request
            result["callback_count"] += 1
            _require(
                result["callback_count"] == 1
                and state["activation_count"] == 0
                and state["pins_frozen_before_activation"] is True,
                "FIRST_ACTIVATION_HOOK_NOT_ONCE",
            )
            phase = "ACTUAL_WRITER_READBACK"
            captured_inputs.update(inputs)
            result["writer_readback"] = setup._writer_readback(native, inputs)
            descriptor, descriptor_guard = stack.enter_context(
                _protected_descriptor(native)
            )
            boot = setup.measurement._boot_id()
            source_pins = {
                "execute": sources[workload.SOURCE_PATH],
                "verify": sources[
                    "/usr/lib/aragorn/aragorn/native_phase3_blocked_create_verify.py"
                ],
                "identity_reader": sources[
                    "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py"
                ],
            }
            phase = "ORIGINAL_PLAN"
            built = planner.prepare_native_common_attempt_plan(
                common_arguments=common,
                provisioning_inputs=inputs,
                **plan,
                expected_boot_id=boot,
                protected_descriptor_raw=descriptor,
                payload_raw=_PAYLOAD,
                source_pins=source_pins,
                evidence_cas=writer,
                plan_cas=private_plan,
                public_blob_attempts=result["public_blob_attempts"],
            )
            result["plan"] = built["report"]
            phase = "HELD_PREACTIVATION_HANDOFF"
            session = stack.enter_context(
                handoff.hold_prepared_native_common_measurement(
                    collection_preparation_raw=built["collection_preparation_raw"],
                    expected_collection_preparation_digest=built[
                        "collection_preparation_digest"
                    ],
                    common_preparation_raw=built["common_preparation_raw"],
                    expected_common_preparation_digest=built[
                        "common_preparation_digest"
                    ],
                    measurement_prepared_raw=built["measurement_prepared_raw"],
                    expected_measurement_prepared_digest=built[
                        "measurement_prepared_digest"
                    ],
                    expected_binding_digest=built["expected_binding_digest"],
                    scheduled_request=built["scheduled_request"],
                    provisioning_inputs=inputs,
                    expected_container_id=container,
                    expected_boot_id=boot,
                    protected_descriptor_raw=descriptor,
                    payload_raw=_PAYLOAD,
                    evidence_cas=writer,
                    source_pins=source_pins,
                )
            )
            result["handoff"] = session.report
            for role, raw in (
                ("handoff", session.report_raw),
                ("request", session.request_raw),
                ("provisioning", session.provisioning_raw),
                ("claim", session.claim_raw),
            ):
                retain(role, raw)
            request = session.request
            _require(
                session.request_raw == built["request_raw"], "ORIGINAL_REQUEST_CHANGED"
            )
            result["writer_readback_after"] = setup._writer_readback(native, inputs)
            _require(
                result["writer_readback_after"] == result["writer_readback"],
                "WRITER_CUSTODY_CHANGED",
            )
            descriptor_guard()
            guard()
            session.guard()
            _require(
                _network() == result["network_before"]
                and _source_guard(sources) == result["sources_before"],
                "PREACTIVATION_SOURCE_OR_NETWORK_CHANGED",
            )
            phase = "FIRST_ACTIVATION"

        phase = "SEVEN_WRITER_SETUP"
        setup.predecessor._prepare(
            native, before_activation, state=result["setup_state"]
        )
        _require(
            result["setup_state"]["activation_count"] == result["callback_count"] == 1
            and session is not None,
            "FIRST_ACTIVATION_INCOMPLETE",
        )
        phase = "ACTIVE_IDENTITY"
        pins = request["expected_file_digests"]
        before = identity.read_native_common_identity(
            expected_container_id=container, expected_file_digests=pins
        )
        retain("identity_before", canonical_json(before))
        observed = observer.observe_common_processes(expected_container_id=container)
        retain("process_before", canonical_json(observed))
        with workload._live_processes(identity, before, container) as live_guard:
            expected, broker, accounts = _expectations(
                before, observed, request["boot_id"]
            )
            try:
                phase = "CLOCK_BEFORE"
                clocks["before"] = canonical_json(
                    clock.observe_native_common_clock_domain(
                        expected_worker=expected["worker"],
                        expected_broker=expected["broker"],
                    )
                )
                retain("clock_before", clocks["before"])
                session.guard()
                live_guard()
                phase = "FIXED_WORKLOAD"
                result["workload_count"] = 1
                try:
                    work = workload.run_native_blocked_create_workload(
                        expected_container_id=container,
                        expected_genesis_digest=pins[identity.prior._GENESIS],
                        expected_path_descriptor=json.loads(descriptor),
                        expected_sink_source_digest=sources[workload.SINK_SOURCE_PATH],
                        expected_sink_accounts=accounts,
                        expected_workload_source_digest=sources[workload.SOURCE_PATH],
                        expected_revocation_source_digest=sources[
                            workload.REVOCATION_SOURCE_PATH
                        ],
                        expected_file_digests=pins,
                        expected_processes=expected,
                        nonce=common["nonce"][:32],
                    )
                except BaseException as error:
                    work = getattr(error, "_native_blocked_create_workload", None)
                    raise
            except BaseException as error:
                if primary is None:
                    primary = error
                raise
            finally:

                def after_clock():
                    clocks["after"] = canonical_json(
                        clock.observe_native_common_clock_domain(
                            expected_worker=expected["worker"],
                            expected_broker=expected["broker"],
                        )
                    )
                    retain("clock_after", clocks["after"])

                failure("CLOCK_AFTER_REFUSED", after_clock)
                if work is not None:
                    result["workload"] = {
                        "status": work.get("status"),
                        "digest": failure(
                            "WORKLOAD_RETENTION_REFUSED",
                            lambda: retain("workload", canonical_json(work)),
                        ),
                    }

                    def work_records():
                        rows = work.get("records", {})
                        _require(
                            type(rows) is dict
                            and set(rows)
                            <= {
                                "identity_before",
                                "identity_after",
                                "receipt_before",
                                "receipt_after",
                                "sink_before",
                                "sink_after",
                                "driver_input",
                                "driver",
                            },
                            "WORKLOAD_PUBLIC_RECORD_INVENTORY_CHANGED",
                        )
                        for name, record in rows.items():
                            failure(
                                "WORKLOAD_RECORD_RETENTION_REFUSED",
                                lambda n=name, r=record: retain(
                                    "workload_" + n, _raw(r)
                                ),
                            )

                    failure("WORKLOAD_PUBLIC_INVENTORY_REFUSED", work_records)

                def read_measurement():
                    nonlocal measured
                    worker_request = action_request = None
                    if work is not None and "driver" in work.get("records", {}):
                        try:
                            driver = json.loads(_raw(work["records"]["driver"]))
                            worker_request = workload._pin(
                                driver["worker_request"]["digest"]
                            )
                            action_request = workload._pin(
                                driver["source_result"]["document"]["broker_result"][
                                    "request_digest"
                                ]
                            )
                        except Exception:
                            worker_request = action_request = None
                            result["postcondition_failures"].append(
                                "DRIVER_REQUEST_PINS_UNAVAILABLE"
                            )
                    binding_raw = canonical_json(
                        json.loads(built["measurement_prepared_raw"])["binding"]
                    )
                    result["snapshot_count"] = 1
                    try:
                        measured = snapshot.snapshot_native_measurement_evidence(
                            expected_container_id=container,
                            expected_worker=expected["worker"],
                            expected_broker_process=broker,
                            expected_worker_binding_digest=pins[identity.prior._WORKER],
                            expected_genesis_digest=pins[identity.prior._GENESIS],
                            expected_measurement_binding_raw=binding_raw,
                            expected_measurement_binding_digest=request[
                                "measurement_binding_digest"
                            ],
                            expected_worker_request_digest=worker_request,
                            expected_action_request_digest=action_request,
                            expected_source_digest=sources[
                                "/opt/aragorn/runtime_native_measurement_evidence_snapshot.py"
                            ],
                            expected_worker_helper_digest=pins[
                                "/usr/lib/aragorn/aragorn/runtime_worker_ingress_measurement.py"
                            ],
                        )
                    except BaseException as error:
                        measured = getattr(
                            error, "_native_measurement_evidence_snapshot", None
                        )
                        raise
                    finally:
                        if measured is not None:
                            result["snapshot"] = {
                                "status": measured.get("status"),
                                "digest": failure(
                                    "SNAPSHOT_REPORT_RETENTION_REFUSED",
                                    lambda: retain(
                                        "measurement_snapshot", canonical_json(measured)
                                    ),
                                ),
                            }

                            def measurement_records():
                                rows = measured["records"]
                                _require(
                                    type(rows) is dict
                                    and set(rows)
                                    <= {
                                        "startup",
                                        "ingress",
                                        "attempt",
                                        "action",
                                        "pending",
                                        "completion",
                                    },
                                    "MEASUREMENT_PUBLIC_RECORD_INVENTORY_CHANGED",
                                )
                                for name, record in rows.items():
                                    failure(
                                        "MEASUREMENT_RECORD_RETENTION_REFUSED",
                                        lambda n=name, r=record: retain(
                                            "measurement_" + n, _raw(r)
                                        ),
                                    )

                            failure(
                                "MEASUREMENT_PUBLIC_INVENTORY_REFUSED",
                                measurement_records,
                            )

                            def broker_records():
                                rows, names = (
                                    measured["broker_blobs"],
                                    measured["broker_blob_digests"],
                                )
                                _require(
                                    type(rows) is dict
                                    and type(names) is dict
                                    and set(names)
                                    <= {
                                        "evidence",
                                        "consumed_grant_state",
                                        "profile_receipt",
                                        "broker_result",
                                        "profiled_submission",
                                    }
                                    and set(rows) <= set(names.values())
                                    and len(rows) <= 5,
                                    "BROKER_PUBLIC_RECORD_INVENTORY_CHANGED",
                                )
                                for pin, record in rows.items():
                                    _require(
                                        record["digest"] == pin,
                                        "BROKER_BLOB_KEY_CHANGED",
                                    )
                                    failure(
                                        "BROKER_BLOB_RETENTION_REFUSED",
                                        lambda r=record: retain("broker_blob", _raw(r)),
                                    )

                            failure("BROKER_PUBLIC_INVENTORY_REFUSED", broker_records)

                failure("MEASUREMENT_SNAPSHOT_REFUSED", read_measurement)
                failure("HELD_PROCESS_AFTER_REFUSED", live_guard)
                after_reads = {}

                def after_identity():
                    after_reads["identity"] = identity.read_native_common_identity(
                        expected_container_id=container, expected_file_digests=pins
                    )
                    retain("identity_after", canonical_json(after_reads["identity"]))

                def after_process():
                    after_reads["process"] = observer.observe_common_processes(
                        expected_container_id=container
                    )
                    retain("process_after", canonical_json(after_reads["process"]))

                failure("COMMON_IDENTITY_AFTER_REFUSED", after_identity)
                failure("INDEPENDENT_PROCESS_AFTER_REFUSED", after_process)

                def verify_process():
                    result["process_verification"] = (
                        process_verify.verify_native_common_process_observations(
                            before,
                            after_reads["identity"],
                            observed,
                            after_reads["process"],
                            expected_container_id=container,
                            expected_file_digests=pins,
                        )
                    )

                failure("PROCESS_PAIR_AFTER_REFUSED", verify_process)
        phase = "INDEPENDENT_EVIDENCE_COMPOSITION"
        _require(
            work is not None
            and work["status"] == "OBSERVED"
            and measured is not None
            and measured["status"] == "SNAPSHOTTED"
            and set(clocks) == {"before", "after"},
            "COMPLETE_NATIVE_EVIDENCE_UNAVAILABLE",
        )
        result["verification"] = _verify(
            work,
            measured,
            clocks,
            expected,
            broker,
            accounts,
            request,
            canonical_json(json.loads(built["measurement_prepared_raw"])["binding"]),
            sources,
            reader,
        )
        retain("independent_verification", canonical_json(result["verification"]))
    except BaseException as error:
        if primary is None:
            primary = error
        elif primary is not error:
            result["postcondition_failures"].append("SECONDARY_ATTEMPT_REFUSED")
        if result["plan"] is None:
            result["plan"] = getattr(error, "_native_common_attempt_plan", None)
        result["refusal"] = {"phase": phase, "reason": "FIXED_COMMON_ATTEMPT_REFUSED"}
    finally:
        if native is not None and result["installed_sources"] is not None:

            def installed_after():
                result["installed_sources_after"] = native._sources(
                    health=True, startup_reserve=True
                )
                _require(
                    result["installed_sources_after"] == result["installed_sources"],
                    "INSTALLED_SOURCE_CHANGED",
                )

            failure("INSTALLED_SOURCES_AFTER_REFUSED", installed_after)

            def implementation_after():
                result["implementation_sources_after"] = setup._implementation_readback(
                    common["implementation_source_raws"], expected_setup_digest
                )
                _require(
                    result["implementation_sources_after"]
                    == result["implementation_sources"],
                    "IMPLEMENTATION_SOURCE_CHANGED",
                )

            failure("IMPLEMENTATION_SOURCES_AFTER_REFUSED", implementation_after)
        if result["sources_before"] is not None:

            def sources_after():
                result["sources_after"] = _source_guard(sources)
                _require(
                    result["sources_after"] == result["sources_before"],
                    "FINAL_SOURCES_CHANGED",
                )

            failure("SOURCES_AFTER_REFUSED", sources_after)

            def network_after():
                result["network_after"] = _network()
                _require(
                    result["network_after"] == result["network_before"],
                    "FINAL_NETWORK_CHANGED",
                )

            failure("NETWORK_AFTER_REFUSED", network_after)
        if cleanup_required:

            def cleanup():
                setup.predecessor._environment(common["container_id"], (0, 0))
                native.setup_prior._require_fixture(common["container_id"])
                result["cleanup_count"] += 1
                result["fixture_stack_cleanup"] = setup._cleanup(native)

            failure("OWNED_FOUR_SERVICE_CLEANUP_UNCONFIRMED", cleanup)
        if session is not None:
            failure("HANDOFF_POSTCLEANUP_CUSTODY_REFUSED", session.guard)
        if guard is not None:
            failure("CAS_POSTCLEANUP_CUSTODY_REFUSED", guard)
        if reader is not None:
            # Service cleanup is inside the retained-evidence boundary. Check
            # each public candidate independently while the CAS and handoff are
            # still held; neither a missing blob nor an interrupt skips siblings.
            for row in result["public_blob_attempts"]:
                try:
                    raw = reader.read(row["digest"], max_bytes=_MAX_BLOB)
                    _require(
                        len(raw) == row["bytes"]
                        and workload._digest(raw) == row["digest"],
                        "PUBLIC_FINAL_READBACK_CHANGED",
                    )
                except BaseException as error:
                    result["public_readback_failures"].append(row["digest"])
                    if primary is None and not isinstance(error, Exception):
                        primary = error
            result["public_blob_digests"] = sorted(
                {row["digest"] for row in result["public_blob_attempts"]}
            )
        failure("HELD_CONTEXT_CLOSE_REFUSED", stack.close)
        captured_inputs.clear()
    if (
        primary is None
        and result["verification"] is not None
        and result["fixture_stack_cleanup"] is not None
        and not result["postcondition_failures"]
        and not result["public_readback_failures"]
    ):
        result["status"] = "BOUNDED_NATIVE_ATTEMPT_VERIFIED"
    _require(
        len(canonical_json(result)) <= 2 * 1024 * 1024,
        "PUBLIC_ATTEMPT_REPORT_BOUND_REFUSED",
    )
    if primary is not None and not isinstance(primary, Exception):
        primary._native_common_attempt = result
        raise primary
    return result
