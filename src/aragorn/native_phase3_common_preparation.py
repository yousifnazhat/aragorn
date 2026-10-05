"""Freeze common identity from supplied writer bytes, then bind one real plan.

The protected inode is chosen by setup, so policy/worker/configuration artifacts
must be derived after the seven writers, not copied from historical observations.
This is a pure byte boundary: it never observes a filesystem, samples a clock,
prepares or rewrites a collection, publishes authority, or activates a service.
The embedding owned-fixture controller must separately establish writer custody,
real collection prerequisites, absent-only provisioning and one-request ordering.
"""

from __future__ import annotations

import re

from . import native_phase3_admission_case as admission
from . import native_phase3_common_identity as common_identity
from .cas import CAS
from .oci_worker_protocol import canonical_json
from .phase3_deployment import build_phase3_deployment_identity
from .runtime_native_measurement_inputs import (
    validate_prepared_native_measurement_inputs,
)

old = admission.old
CASE_BRANCHES = admission.CASE_BRANCHES
STAGED_SCHEMA = "aragorn/runtime-phase3-common-staged-profile/v1"
# Derived from the actual reviewed common stager at ec510d9; inert bytes only.
STAGED_PROFILE_PIN = (
    50029,
    "sha256:4c5e4f131f493d7de2a32cac5764fa7bf4ffb83fe46c4a55d600013a0ab9b65e",
)
STATIC_SCHEMA = "aragorn/native-common-static-pins/v1"
STATIC_PATHS = (*old.live.STATIC_PATHS, *common_identity.MEASUREMENT_SOURCES.values())
IMPLEMENTATION_SOURCE_PATHS = (
    "src/aragorn/native_phase3_common_preparation.py",
    "src/aragorn/native_phase3_common_identity.py",
    "src/aragorn/native_phase3_common_process_verifier.py",
    "src/aragorn/runtime_native_measurement_inputs.py",
    "src/aragorn/runtime_native_measurement_provisioning.py",
    "scripts/runtime_phase3_common_process_observer.py",
    *admission.CASE_SOURCE_PATHS,
)
PREPARATION_SCHEMA = "aragorn/native-common-deployment-preparation/v1"
PREPARATION_AUTHORITY = "CALLER_SUPPLIED_WRITER_BYTES_NOT_DEPLOYMENT_OR_ACTIVATION"
REQUEST_SCHEMA = "aragorn/native-common-measured-case-request/v1"
REQUEST_AUTHORITY = (
    "PURE_COMMON_REQUEST_BYTES_NOT_PUBLICATION_ACTIVATION_OR_MEASUREMENT"
)
_FALSE = (
    "deployment_attested",
    "activation_performed",
    "measurement_collected",
    "admission_qualified",
    "run_qualified",
    "quantitative_metrics_eligible",
    "phase3_exit_eligible",
    "boot_observed",
    "protected_inode_observed",
    "grant_liveness_verified",
    "request_published",
)
_LIMITATIONS = [
    "CALLER_SUPPLIED_WRITER_BYTES_REQUIRE_ACTUAL_PREACTIVATION_CUSTODY",
    "SOURCE_PINS_REQUIRE_SIGNED_HOST_AND_GUEST_INSTALLED_SOURCE_JOINS",
    "HISTORICAL_BINARY_AND_SENSOR_EXPECTATIONS_NOT_LIVE_ATTESTATION",
    "COMMON_HOST_GUEST_REQUEST_AND_OUTER_REPLAY_INTEGRATION_REMAINS_REQUIRED",
    "NO_COLLECTION_CREATION_CALLBACK_EXECUTION_OR_ACCEPTANCE_AUTHORITY",
]


class NativeCommonPreparationError(ValueError):
    """The supplied common inputs do not close over one unchanged deployment."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeCommonPreparationError(reason)


def _stage(raw: bytes, baseline: dict) -> dict:
    _require(
        type(raw) is bytes and (len(raw), old._digest(raw)) == STAGED_PROFILE_PIN,
        "reviewed common stage bytes changed",
    )
    value = old._parse(raw, old._MAX_ARTIFACT)
    _require(
        value["schema"] == STAGED_SCHEMA
        and value["admission_qualified"] is False
        and value["common_deployment_activated"] is False
        and value["phase3_qualification"] is False
        and (
            len(value["files"]),
            len(value["source_inputs"]),
            len(value["new_dependencies"]),
            len(value["directories"]),
        )
        == (73, 93, 29, 16)
        and value["directories"] == baseline["staged_profile"]["directories"]
        and value["required_runtime_not_included"]
        == baseline["staged_profile"]["required_runtime_not_included"],
        "common profile contract changed",
    )
    return value


def _static(raw: bytes, stage: dict, baseline: dict) -> dict:
    value = old._parse(raw)
    _require(
        set(value) == {"schema", "file_digests"} and value["schema"] == STATIC_SCHEMA,
        "common static manifest contract changed",
    )
    pins = old._pins(value["file_digests"], STATIC_PATHS)
    files = {row["path"]: row for row in stage["files"]}
    _require(
        len(files) == 73
        and all(
            pins[path] == files[path]["digest"]
            for path in (
                *old.live._PROFILE_PATHS,
                *common_identity.MEASUREMENT_SOURCES.values(),
            )
        )
        and pins[old.live._WORKER_CODE] == old._WORKER_PIN
        and pins[old.live._ENTRY]
        == stage["required_runtime_not_included"]["entrypoint_digest"]
        and pins[old.live._PYTHON]
        == baseline["observation"]["setup"]["runtime_profile"]["executable_digest"]
        and pins[old.live._NODE] == admission._NODE_PIN,
        "static pins differ from common stage or fixed binary expectations",
    )
    return value


def prepare_native_common_deployment(
    *,
    case_id: str,
    nonce: str,
    container_id: str,
    source_record_raw: bytes,
    implementation_source_raws: dict[str, bytes],
    static_pin_manifest_raw: bytes,
    staged_profile_raw: bytes,
    baseline_capture_raw: bytes,
    provisioning_inputs: dict[str, bytes],
) -> dict:
    """Derive seven artifacts after setup; selection never changes their identity.

    Returned raw blobs need explicit caller retention. The seven provisioning
    documents are not retained here: in particular configuration credentials are
    represented only by a digest, never copied into the public preparation.
    """
    try:
        return _prepare_deployment(
            case_id,
            nonce,
            container_id,
            source_record_raw,
            implementation_source_raws,
            static_pin_manifest_raw,
            staged_profile_raw,
            baseline_capture_raw,
            provisioning_inputs,
        )
    except NativeCommonPreparationError:
        raise
    except Exception as exc:
        raise NativeCommonPreparationError(
            "common deployment preparation refused"
        ) from exc


def _prepare_deployment(
    case_id,
    nonce,
    container,
    source_raw,
    sources,
    static_raw,
    stage_raw,
    baseline_raw,
    inputs,
):
    _require(
        type(case_id) is str and case_id in CASE_BRANCHES, "unsupported common case"
    )
    _require(
        all(
            type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value)
            for value in (nonce, container)
        ),
        "invalid case or owned-fixture identity",
    )
    baseline, original = admission._baseline(baseline_raw)
    stage = _stage(stage_raw, baseline)
    static = _static(static_raw, stage, baseline)
    source = admission._source(source_raw)
    _require(
        type(sources) is dict and set(sources) == set(IMPLEMENTATION_SOURCE_PATHS),
        "common implementation source inventory changed",
    )
    retained = {}

    def retain(raw, limit=old._MAX_ARTIFACT):
        _require(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded common input")
        pin = old._digest(raw)
        _require(pin not in retained or retained[pin] == raw, "common digest collision")
        retained[pin] = raw
        return pin

    source_pin = retain(source_raw)
    source_pins = {}
    for path in IMPLEMENTATION_SOURCE_PATHS:
        sources[path].decode("utf-8")
        source_pins[path] = retain(sources[path])
    adapters = {admission.UPDATE_CASE: original["adapter"]}
    for selected in (admission.DIRECT_WRITE_CASE, *admission.MUTATION_CASE_BRANCHES):
        paths = (
            admission.DIRECT_SOURCE_PATHS
            if selected == admission.DIRECT_WRITE_CASE
            else admission.CASE_SOURCE_PATHS
        )
        adapters[selected] = old._artifact(
            "adapter",
            {
                "route_id": selected,
                "branch": CASE_BRANCHES[selected],
                "probe_sources": {
                    path: {"bytes": len(sources[path]), "digest": source_pins[path]}
                    for path in paths
                },
            },
        )
    _require(
        type(inputs) is dict and set(inputs) == set(old.PROVISIONING_PATHS),
        "common writer inventory changed",
    )
    # Only these three deployment artifacts depend on the fresh writer bytes.
    # The inherited validator then checks their exact document/semantic joins.
    worker = old._parse(inputs[old.live._WORKER], old._MAX_INPUT)
    artifacts = original | {
        "configuration": old._artifact(
            "configuration",
            {
                "configuration_digest": old._digest(inputs[old.live._CONFIG]),
            },
        ),
        "worker": old._artifact(
            "worker",
            {"bytes": old._WORKER_BYTES, "digest": old._WORKER_PIN, "binding": worker},
        ),
        "policy": old._artifact(
            "policy", {"policy_digest": old._digest(inputs[old.live._POLICY])}
        ),
        "adapter": old._artifact(
            "adapter",
            {
                "implementation_source_digests": source_pins,
                "case_adapters": {
                    selected: {
                        "branch": CASE_BRANCHES[selected],
                        "artifact_digest": old._digest(raw),
                    }
                    for selected, raw in adapters.items()
                },
            },
        ),
        "os_profile": old._artifact(
            "os_profile",
            {
                "fixture_image": old.reported._IMAGE,
                "staged_schema": STAGED_SCHEMA,
                "staged_files_digest": old._digest(canonical_json(stage["files"])),
            },
        ),
        "aragorn_version": old._artifact(
            "aragorn_version",
            {
                "source_commit": source["commit"],
                "source_record_digest": source_pin,
            },
        ),
    }
    hashes = old._provisioning(inputs, {"artifacts": artifacts, "static": static})
    observation = old._parse(inputs[old.live._OBSERVATION], old._MAX_INPUT)
    policy = old._parse(inputs[old.live._POLICY], old._MAX_INPUT)
    fixed_policy = baseline["observation"]["setup"]["policy"]
    _require(
        observation["sensor_digest"] == fixed_policy["sensor_digest"]
        and policy["revocation_source_digest"]
        == fixed_policy["revocation_source_digest"],
        "fixed sensor or revocation source identity changed",
    )
    _require(
        observation["runtime_profile"]["cgroup"]
        == f"/docker/{container}/system.slice/aragorn-runtime-action-worker.service",
        "fresh process profile is outside the owned fixture",
    )
    deployment = build_phase3_deployment_identity(
        {name: retain(raw) for name, raw in artifacts.items()}
    )
    for raw in adapters.values():
        retain(raw)
    preparation = {
        "schema": PREPARATION_SCHEMA,
        "authority": PREPARATION_AUTHORITY,
        "case_id": case_id,
        "branch": CASE_BRANCHES[case_id],
        "nonce": nonce,
        "container_id": container,
        "source_commit": source["commit"],
        "source_record_digest": source_pin,
        "implementation_source_digests": source_pins,
        "staged_profile_digest": retain(stage_raw),
        "static_pin_manifest_digest": retain(static_raw),
        "baseline_capture_digest": retain(baseline_raw),
        "case_adapter_digest": old._digest(adapters[case_id]),
        "artifact_digests": dict(deployment["bindings"]),
        "deployment_digest": retain(canonical_json(deployment)),
        "provisioning_file_digests": hashes,
        "decision": dict.fromkeys(_FALSE, False),
        "limitations": list(_LIMITATIONS),
    }
    raw = canonical_json(preparation)
    pin = retain(raw, 16384)
    _require(len(retained) <= 32, "common preparation closure exceeds fixed bound")
    return {
        "preparation": preparation,
        "preparation_raw": raw,
        "preparation_digest": pin,
        "deployment": deployment,
        "artifacts": artifacts,
        "input_blobs": retained,
        "provisioning_file_digests": dict(hashes),
    }


def _inspect(raw, expected, store, inputs):
    _require(
        type(store) is CAS and store.read_only is True, "read-only common CAS required"
    )
    _require(
        type(raw) is bytes and old._digest(raw) == old._pin(expected),
        "common preparation differs from caller pin",
    )
    value = old._parse(raw, 16384)
    retained = {}

    def read(pin):
        result = store.read(old._pin(pin), max_bytes=old._MAX_ARTIFACT)
        _require(
            type(result) is bytes
            and 0 < len(result) <= old._MAX_ARTIFACT
            and old._digest(result) == pin,
            "common retained input changed",
        )
        retained[pin] = result
        return result

    _require(read(expected) == raw, "common preparation not retained")
    pins = old._pins(
        value["implementation_source_digests"], IMPLEMENTATION_SOURCE_PATHS
    )
    rebuilt = prepare_native_common_deployment(
        case_id=value["case_id"],
        nonce=value["nonce"],
        container_id=value["container_id"],
        source_record_raw=read(value["source_record_digest"]),
        implementation_source_raws={path: read(pin) for path, pin in pins.items()},
        static_pin_manifest_raw=read(value["static_pin_manifest_digest"]),
        staged_profile_raw=read(value["staged_profile_digest"]),
        baseline_capture_raw=read(value["baseline_capture_digest"]),
        provisioning_inputs=inputs,
    )
    _require(
        rebuilt["preparation_raw"] == raw,
        "common preparation contract or fresh writers changed",
    )
    for pin, retained_raw in rebuilt["input_blobs"].items():
        _require(read(pin) == retained_raw, "derived common artifact changed")
    _require(retained == rebuilt["input_blobs"], "common closure changed")
    return rebuilt


def prepare_native_common_request(
    *,
    preparation_raw: bytes,
    expected_preparation_digest: str,
    evidence_cas: CAS,
    provisioning_inputs: dict[str, bytes],
    measurement_prepared_raw: bytes,
    expected_measurement_prepared_digest: str,
    expected_binding_digest: str,
    expected_boot_id: str,
    protected_descriptor_raw: bytes,
    payload_raw: bytes,
) -> dict:
    """Join an already real-committed plan; never rewrite it to fit fresh inputs.

    Boot and protected-inode observations remain the caller's responsibility.
    Supplied payload bytes are hashed, not executed or verified at a sink.
    The request is returned, not published; the root provisioner must succeed
    and the caller must retain/read back these bytes before its single activation.
    """
    try:
        return _prepare_request(
            preparation_raw,
            expected_preparation_digest,
            evidence_cas,
            provisioning_inputs,
            measurement_prepared_raw,
            expected_measurement_prepared_digest,
            expected_binding_digest,
            expected_boot_id,
            protected_descriptor_raw,
            payload_raw,
        )
    except NativeCommonPreparationError:
        raise
    except Exception as exc:
        raise NativeCommonPreparationError("common request handoff refused") from exc


def _prepare_request(
    raw,
    expected,
    store,
    inputs,
    measurement_raw,
    measurement_pin,
    binding_pin,
    boot,
    path_raw,
    payload_raw,
):
    prepared = _inspect(raw, expected, store, inputs)
    value = prepared["preparation"]
    stage = old._parse(
        prepared["input_blobs"][value["staged_profile_digest"]], old._MAX_ARTIFACT
    )
    files = {row["path"]: row for row in stage["files"]}
    broker_pins = {
        name: files[path]["digest"]
        for name, path in common_identity.MEASUREMENT_SOURCES.items()
    }
    measured = validate_prepared_native_measurement_inputs(
        prepared_raw=measurement_raw,
        expected_prepared_digest=measurement_pin,
        expected_binding_digest=binding_pin,
        expected_broker_source_pins=broker_pins,
        source_cas=store,
    )
    _require(
        store.read(measurement_pin, max_bytes=32768) == measurement_raw,
        "measurement preparation is not retained",
    )
    binding = measured["binding"]
    policy = old._parse(inputs[old.live._POLICY], old._MAX_INPUT)
    action = policy["allow"][0]
    _require(
        binding["deployment_identity_digest"] == value["deployment_digest"]
        and binding["grant_digest"]
        == prepared["provisioning_file_digests"][old.live._GRANT]
        and measured["input_blobs"][binding["grant_digest"]] == inputs[old.live._GRANT]
        and binding["policy_digest"]
        == prepared["provisioning_file_digests"][old.live._POLICY],
        "measurement plan differs from actual common writer identity",
    )
    _require(
        type(boot) is str
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot)
        and binding["boot_id"] == boot,
        "measurement boot differs from caller observation",
    )
    _require(
        type(path_raw) is bytes
        and 0 < len(path_raw) <= 4096
        and canonical_json(measured["path_descriptor"]) == path_raw
        and old._digest(path_raw) == binding["path_digest"] == action["path_digest"],
        "protected descriptor differs from common policy or measured plan",
    )
    _require(
        type(payload_raw) is bytes
        and 0 < len(payload_raw) <= 65536
        and old._digest(payload_raw)
        == binding["payload_digest"]
        == action["payload_digest"],
        "payload bytes differ from common policy or measured plan",
    )
    _require(
        all(
            binding[key] == action[key]
            for key in ("runtime_digest", "active_skill_digest", "operation_digest")
        ),
        "measured operation differs from common policy action",
    )
    hashes = prepared["provisioning_file_digests"] | {
        common_identity.MEASUREMENT_BINDING: binding_pin
    }
    static = old._parse(prepared["input_blobs"][value["static_pin_manifest_digest"]])
    expected_files = static["file_digests"] | hashes
    _require(
        set(expected_files) == set(common_identity.FILE_PATHS)
        and len(hashes) == 8
        and len(expected_files) == 26,
        "common request file inventory changed",
    )
    retained = dict(prepared["input_blobs"])
    for pin, content in (
        measured["input_blobs"] | {measurement_pin: measurement_raw}
    ).items():
        _require(
            pin not in retained or retained[pin] == content, "request input collision"
        )
        retained[pin] = content
    for pin, content in retained.items():
        _require(
            store.read(pin, max_bytes=old._MAX_ARTIFACT) == content,
            "common request input left custody",
        )
    request = {
        "schema": REQUEST_SCHEMA,
        "authority": REQUEST_AUTHORITY,
        "preparation_digest": expected,
        **{
            key: value[key]
            for key in (
                "case_id",
                "branch",
                "nonce",
                "container_id",
                "deployment_digest",
                "case_adapter_digest",
                "staged_profile_digest",
            )
        },
        "measurement_prepared_digest": measurement_pin,
        "measurement_binding_digest": binding_pin,
        "scheduled_measurement_request_digest": binding[
            "scheduled_measurement_request_digest"
        ],
        "boot_id": boot,
        "path_digest": binding["path_digest"],
        "payload_digest": binding["payload_digest"],
        "provisioning_file_digests": hashes,
        "expected_file_digests": expected_files,
        "decision": {
            **dict.fromkeys(_FALSE, False),
            "supplied_payload_bytes_verified": True,
        },
        "limitations": list(_LIMITATIONS)
        + [
            "BOOT_AND_PROTECTED_DESCRIPTOR_ARE_CALLER_OBSERVATIONS_NOT_READ_HERE",
            "SUPPLIED_PAYLOAD_BYTES_NOT_EXECUTED_WORKLOAD_OR_PROTECTED_SINK_EVIDENCE",
            "PREPARED_MEASUREMENT_PLAN_NOT_VALIDATED_ADMISSION_LEAF_SEMANTICS",
        ],
    }
    request_raw = canonical_json(request)
    _require(len(request_raw) <= 16384, "common request exceeds publication bound")
    return {
        "request": request,
        "request_raw": request_raw,
        "request_digest": old._digest(request_raw),
        "expected_file_digests": dict(expected_files),
        "provisioning_file_digests": dict(hashes),
        "input_blobs": retained,
        "decision": dict(request["decision"]),
    }
