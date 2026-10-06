"""Prepare one owned common74 fixture; deliberately never activate it.

This fixed setup-only checkpoint is not resumable execution authority. It leaves
all new files and partial evidence for the owning host to retain and destroy
with its disposable fixture. No measurement request or callback is invented.
"""

from __future__ import annotations

from contextlib import contextmanager
import io
import os
from pathlib import Path
import re
import sys
from unittest.mock import patch

if __package__:
    from scripts import runtime_native_admission_case as predecessor
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_admission_case as predecessor

from aragorn import native_phase3_common_preparation as preparation
from aragorn import runtime_native_measurement_provisioning as measurement
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-common-case-setup/v1"
AUTHORITY = "OWNED_SEVEN_WRITER_PREPARATION_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY"
CAS_ROOT = "/run/aragorn-native-common-setup"
SETUP_PATH = "/opt/aragorn/runtime_native_common_case_setup.py"
INGRESS_ROOT = Path("/var/lib/aragorn-runtime-worker-measurement")
_LIMIT = 2 * 1024 * 1024
_FALSE = (
    "activation_performed",
    "request_published",
    "measurement_provisioned",
    "measurement_collected",
    "resumable",
    "deployment_attested",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
)
_OVERRIDE_SOURCES = {
    "/usr/lib/aragorn/aragorn/runtime_action_worker.py": (
        "src/aragorn/runtime_action_worker.py",
        "0644",
    ),
    "/usr/lib/systemd/system/aragorn-runtime-action-worker.service": (
        "packaging/systemd/aragorn-runtime-action-worker.service",
        "0644",
    ),
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh": (
        "packaging/activate-runtime-action-worker-host.sh",
        "0755",
    ),
    "/usr/lib/systemd/system/aragorn-agent-gateway.service": (
        "packaging/systemd/aragorn-agent-gateway.service",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/runtime_action_broker.py": (
        "src/aragorn/runtime_action_broker.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/runtime_action_broker_v4.py": (
        "src/aragorn/runtime_action_broker_v4.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/runtime_action_service_v5.py": (
        "src/aragorn/runtime_action_service_v5.py",
        "0644",
    ),
    "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service": (
        "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service",
        "0644",
    ),
    "/usr/libexec/aragorn/activate-runtime-capability-host.sh": (
        "packaging/activate-runtime-capability-host.sh",
        "0755",
    ),
    "/usr/lib/aragorn/aragorn/runtime_broker_decision_measurement.py": (
        "src/aragorn/runtime_broker_decision_measurement.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/phase3_deployment.py": (
        "src/aragorn/phase3_deployment.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/phase3_quantitative_metrics.py": (
        "src/aragorn/phase3_quantitative_metrics.py",
        "0644",
    ),
    "/usr/lib/aragorn/aragorn/runtime_worker_ingress_measurement.py": (
        "src/aragorn/runtime_worker_ingress_measurement.py",
        "0644",
    ),
}
_IMPLEMENTATION_PATHS = {
    name: "/usr/lib/aragorn/" + name.removeprefix("src/")
    if name.startswith("src/")
    else "/opt/aragorn/" + Path(name).name
    for name in preparation.IMPLEMENTATION_SOURCE_PATHS
}


class NativeCommonCaseSetupError(ValueError):
    """A fixed secret-safe setup refusal."""


class _PreparedBeforeActivation(BaseException):
    """Private one-shot control transfer; never handled as native success."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeCommonCaseSetupError(reason)


def _close_preserving(close, reason: str) -> None:
    """Keep an active operation failure and attach only a fixed cleanup label."""
    primary = sys.exception()
    try:
        close()
    except BaseException as error:
        retained = primary if primary is not None else error
        failures = list(getattr(retained, "_common_cleanup_failures", ()))
        failures.append(reason)
        retained._common_cleanup_failures = failures
        if primary is not None:
            raise primary
        raise


def _inputs(arguments: dict, setup_pin: str) -> dict:
    """Validate every caller input possible before any fixture mutation."""
    preparation.old._pin(setup_pin)
    _require(arguments["case_id"] in preparation.CASE_BRANCHES, "UNSUPPORTED_CASE")
    _require(
        all(
            type(arguments[name]) is str
            and re.fullmatch(r"[0-9a-f]{64}", arguments[name])
            for name in ("nonce", "container_id")
        ),
        "INVALID_CASE_IDENTITY",
    )
    for name in (
        "source_record_raw",
        "static_pin_manifest_raw",
        "staged_profile_raw",
        "baseline_capture_raw",
    ):
        raw = arguments[name]
        _require(
            type(raw) is bytes and 0 < len(raw) <= preparation.old._MAX_ARTIFACT,
            "PREPARATION_INPUT_BYTES_INVALID",
        )
    preparation.admission._source(arguments["source_record_raw"])
    baseline, _ = preparation.admission._baseline(arguments["baseline_capture_raw"])
    stage = preparation._stage(arguments["staged_profile_raw"], baseline)
    preparation._static(arguments["static_pin_manifest_raw"], stage, baseline)
    sources = arguments["implementation_source_raws"]
    _require(
        type(sources) is dict and set(sources) == set(_IMPLEMENTATION_PATHS),
        "IMPLEMENTATION_INVENTORY_CHANGED",
    )
    for raw in sources.values():
        _require(
            type(raw) is bytes and 0 < len(raw) <= preparation.old._MAX_ARTIFACT,
            "IMPLEMENTATION_BYTES_INVALID",
        )
        raw.decode("utf-8")
    return stage


def _overrides(stage: dict) -> dict:
    rows = stage["files"]
    _require(
        type(rows) is list
        and len(rows) == 74
        and all(type(row) is dict for row in rows),
        "COMMON74_INVENTORY_REQUIRED",
    )
    files = {row["path"]: row for row in rows}
    _require(len(files) == 74, "DUPLICATE_STAGE_PATH")
    result = {}
    for path, (source, mode) in _OVERRIDE_SOURCES.items():
        row = files[path]
        _require(
            set(row) == {"path", "source_name", "bytes", "digest", "mode"}
            and row["source_name"] == source
            and row["mode"] == mode
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= _LIMIT,
            "COMMON_SOURCE_OVERRIDE_CHANGED",
        )
        result[path] = (
            row["bytes"],
            preparation.old._pin(row["digest"])[7:],
            int(mode, 8),
        )
    return result


def _implementation_readback(sources: dict, setup_pin: str) -> dict:
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = {}
        for source, path in _IMPLEMENTATION_PATHS.items():
            raw, metadata = predecessor.identity._read_at(
                root, path, owner=0, owner_gid=0, modes={0o444}, limit=_LIMIT
            )
            _require(raw == sources[source], "INSTALLED_IMPLEMENTATION_DIFFERS")
            result[path] = metadata
        raw, metadata = predecessor.identity._read_at(
            root, SETUP_PATH, owner=0, owner_gid=0, modes={0o444}, limit=_LIMIT
        )
        _require(preparation.old._digest(raw) == setup_pin, "INSTALLED_SETUP_DIFFERS")
        result[SETUP_PATH] = metadata
        return result
    finally:
        _close_preserving(
            lambda: os.close(root), "IMPLEMENTATION_DESCRIPTOR_CLOSE_REFUSED"
        )


def _ingress_absent() -> dict:
    held = []
    try:
        parent = measurement.custody._root_directory(INGRESS_ROOT.parent, held)
        measurement.custody._absent(parent, INGRESS_ROOT.name)
        measurement.custody._recheck(held)
        return {"path": str(INGRESS_ROOT), "status": "ABSENT", "created": False}
    finally:
        _close_preserving(
            lambda: measurement.custody._close(held), "INGRESS_DESCRIPTOR_CLOSE_REFUSED"
        )


@contextmanager
def _fresh_store():
    with patch.object(predecessor.storage, "CAS_ROOT", CAS_ROOT):
        manager = predecessor.storage._fresh_store()
        opened = manager.__enter__()
        try:
            yield opened
        except BaseException as primary:
            try:
                manager.__exit__(type(primary), primary, primary.__traceback__)
            except BaseException as error:
                if error is not primary:
                    failures = list(getattr(primary, "_common_cleanup_failures", ()))
                    failures.append("CAS_CONTEXT_CLEANUP_REFUSED")
                    primary._common_cleanup_failures = failures
            raise
        else:
            manager.__exit__(None, None, None)


def _writer_readback(native, inputs: dict) -> dict:
    identities = native.response._identities()
    accounts = {"broker": (identities[0], identities[2])}
    root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        result = {}
        for path, expected in inputs.items():
            raw, metadata = predecessor.identity._read_at(
                root,
                path,
                **preparation.common_identity._file_arguments(path, accounts),
            )
            _require(raw == expected, "ACTUAL_WRITER_BYTES_CHANGED")
            result[path] = metadata
        return result
    finally:
        _close_preserving(lambda: os.close(root), "WRITER_DESCRIPTOR_CLOSE_REFUSED")


def _retain_preparation(writer, reader, guard, built: dict, inputs: dict) -> dict:
    pin, raw = built["preparation_digest"], built["preparation_raw"]
    _require(built["input_blobs"].get(pin) == raw, "PREPARATION_CLOSURE_CHANGED")
    # Children first, then the preparation record. Never retain raw writer inputs.
    ordered = [
        (key, value) for key, value in built["input_blobs"].items() if key != pin
    ] + [(pin, raw)]
    for child_pin, child_raw in ordered:
        _require(child_raw not in inputs.values(), "RAW_WRITER_RETENTION_REFUSED")
        _require(
            writer.put_expected(
                io.BytesIO(child_raw), expected_digest=child_pin, max_bytes=_LIMIT
            )
            == child_pin,
            "PREPARATION_PUBLICATION_REFUSED",
        )
        _require(
            reader.read(child_pin, max_bytes=_LIMIT) == child_raw,
            "PREPARATION_READBACK_CHANGED",
        )
        guard()
    # Reconstruct the complete preparation against actual writer bytes, not just
    # its summary or a caller's assertion that the CAS is unchanged.
    replayed = preparation._inspect(raw, pin, reader, inputs)
    _require(replayed["preparation_raw"] == raw, "PREPARATION_REPLAY_CHANGED")
    guard()
    return {
        "preparation": built["preparation"],
        "preparation_digest": pin,
        "retained_blob_digests": sorted(built["input_blobs"]),
        "local_readback": True,
    }


def _cleanup(native) -> dict:
    states = native.prior._stop_fixture()
    _require(
        type(states) is dict and set(states) == set(measurement._UNITS),
        "CLEANUP_UNIT_INVENTORY_CHANGED",
    )
    for unit, state in states.items():
        _require(
            type(state) is dict
            and set(state) == {"Id", "ActiveState", "MainPID", "ControlPID"}
            and state["Id"] == unit
            and state["ActiveState"] == "inactive"
            and state["MainPID"] == state["ControlPID"] == "0",
            "CLEANUP_NOT_CONFIRMED",
        )
    return states


def prepare_common_native_setup(
    *,
    expected_container_id: str,
    expected_setup_digest: str,
    case_id: str,
    nonce: str,
    source_record_raw: bytes,
    implementation_source_raws: dict[str, bytes],
    static_pin_manifest_raw: bytes,
    staged_profile_raw: bytes,
    baseline_capture_raw: bytes,
) -> dict:
    """Capture the seven fixed provisioning documents during setup, then stop.

    Only the fixed owned Linux guest is accepted. The caller must retain the
    returned report before destroying that disposable fixture. This operation
    cannot continue activation and cannot reuse its CAS or partially built state.
    """
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": expected_container_id,
        "setup_source_digest": expected_setup_digest,
        "preparation": None,
        "installed_sources": None,
        "installed_sources_after": None,
        "implementation_sources": None,
        "implementation_sources_after": None,
        "measurement_unused": None,
        "ingress_absent": None,
        "writer_readback": None,
        "writer_readback_after": None,
        "setup_state": {
            "activation_count": 0,
            "pins_frozen_before_activation": False,
            "provisioning_file_digests": {},
        },
        "fixture_stack_cleanup": None,
        "cleanup_failure": None,
        "postcondition_failures": [],
        "refusal": None,
        "limitations": [
            "SETUP_ONLY_CHECKPOINT_NOT_RESUMABLE_AUTHORITY",
            "OWNING_HOST_MUST_RETAIN_EVIDENCE_AND_DESTROY_DISPOSABLE_FIXTURE",
            "NO_MEASUREMENT_BINDING_REQUEST_WORKLOAD_OR_ACTIVATION",
            "LOCAL_SOURCE_AND_WRITER_READBACKS_NOT_LOADED_CODE_OR_SIGNED_HOST_ATTESTATION",
        ],
        **dict.fromkeys(_FALSE, False),
    }
    native = None
    cleanup_required = False
    phase = "ENVIRONMENT"
    try:
        predecessor._environment(expected_container_id, (0, 0))
        _require(
            type(implementation_source_raws) is dict, "IMPLEMENTATION_INVENTORY_CHANGED"
        )
        arguments = {
            "case_id": case_id,
            "nonce": nonce,
            "container_id": expected_container_id,
            "source_record_raw": source_record_raw,
            "implementation_source_raws": dict(implementation_source_raws),
            "static_pin_manifest_raw": static_pin_manifest_raw,
            "staged_profile_raw": staged_profile_raw,
            "baseline_capture_raw": baseline_capture_raw,
        }
        phase = "INPUTS"
        stage = _inputs(arguments, expected_setup_digest)
        overrides = _overrides(stage)
        native = predecessor.package._native()
        native.setup_prior._require_fixture(expected_container_id)
        with patch.object(native, "_STARTUP_CODE", native._STARTUP_CODE | overrides):
            phase = "SOURCES"
            result["installed_sources"] = native._sources(
                health=True, startup_reserve=True
            )
            result["implementation_sources"] = _implementation_readback(
                arguments["implementation_source_raws"], expected_setup_digest
            )
            phase = "UNUSED_GUARDS"
            result["measurement_unused"] = (
                measurement.require_native_measurement_unused()
            )
            result["ingress_absent"] = _ingress_absent()
            cleanup_required = True
            with _fresh_store() as (writer, reader, guard):
                callback_count = 0

                def retain_before_activation(inputs, state):
                    nonlocal phase, callback_count
                    callback_count += 1
                    phase = "WRITER_READBACK"
                    _require(
                        callback_count == 1
                        and state["activation_count"] == 0
                        and state["pins_frozen_before_activation"] is True,
                        "PREPARATION_CALLBACK_NOT_ONCE",
                    )
                    result["writer_readback"] = _writer_readback(native, inputs)
                    phase = "PREPARATION"
                    built = preparation.prepare_native_common_deployment(
                        **arguments, provisioning_inputs=inputs
                    )
                    phase = "RETENTION"
                    result["preparation"] = _retain_preparation(
                        writer, reader, guard, built, inputs
                    )
                    result["writer_readback_after"] = _writer_readback(native, inputs)
                    _require(
                        result["writer_readback_after"] == result["writer_readback"],
                        "WRITER_CUSTODY_CHANGED",
                    )
                    phase = "STOP_BEFORE_ACTIVATION"
                    raise _PreparedBeforeActivation()

                phase = "SEVEN_WRITER_SETUP"
                try:
                    predecessor._prepare(
                        native, retain_before_activation, state=result["setup_state"]
                    )
                    raise NativeCommonCaseSetupError(
                        "NATIVE_PREPARATION_RETURNED_UNEXPECTEDLY"
                    )
                except _PreparedBeforeActivation:
                    _require(
                        callback_count == 1
                        and result["preparation"] is not None
                        and result["setup_state"]["activation_count"] == 0,
                        "NONACTIVATION_CHECKPOINT_INCOMPLETE",
                    )
                    result["status"] = "PREPARED_NOT_ACTIVATED"
                finally:
                    # Independent readbacks still run after partial preparation.
                    for label, operation in (
                        (
                            "INSTALLED_SOURCES_AFTER",
                            lambda: result.update(
                                installed_sources_after=native._sources(
                                    health=True, startup_reserve=True
                                )
                            ),
                        ),
                        (
                            "IMPLEMENTATION_SOURCES_AFTER",
                            lambda: result.update(
                                implementation_sources_after=_implementation_readback(
                                    arguments["implementation_source_raws"],
                                    expected_setup_digest,
                                )
                            ),
                        ),
                        ("INGRESS_ABSENCE_AFTER", _ingress_absent),
                        (
                            "MEASUREMENT_UNUSED_AFTER",
                            measurement.require_native_measurement_unused,
                        ),
                        ("CAS_CUSTODY_AFTER", guard),
                    ):
                        try:
                            operation()
                        except BaseException:
                            result["postcondition_failures"].append(label)
                _require(
                    not result["postcondition_failures"]
                    and result["installed_sources_after"] == result["installed_sources"]
                    and result["implementation_sources_after"]
                    == result["implementation_sources"],
                    "FINAL_SOURCE_OR_CUSTODY_READBACK_REFUSED",
                )
                guard()
    except BaseException as error:
        result["status"] = "REFUSED"
        result["refusal"] = {
            "phase": phase,
            "reason": str(error)
            if type(error) is NativeCommonCaseSetupError
            else "COMMON_SETUP_REFUSED",
            "error_type": type(error).__name__,
        }
        result["postcondition_failures"].extend(
            getattr(error, "_common_cleanup_failures", ())
        )
    finally:
        if cleanup_required:
            try:
                # Check the owned namespace again before any cleanup mutation.
                predecessor._environment(expected_container_id, (0, 0))
                native.setup_prior._require_fixture(expected_container_id)
                result["fixture_stack_cleanup"] = _cleanup(native)
            except BaseException:
                result["status"] = "REFUSED"
                result["cleanup_failure"] = "OWNED_FOUR_SERVICE_CLEANUP_UNCONFIRMED"
    return result
