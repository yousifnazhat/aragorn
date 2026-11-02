"""Prepare and replay one fixed native update case, without executing it.

Preparation hashes the trusted provisioning writer's exact inputs. It does not
publish a durable record, activate a service or prove when a caller invoked it.
The guest must commit and read back the returned request before activation.
Replay checks retained joins, not the truth of a retained PASS or time claim.
Configuration bytes and the gateway environment are never returned or retained.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from . import native_phase3_plugin_update_binding as reported
from . import native_phase3_plugin_update_live_binding as live
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json
from .phase3_deployment import (
    BINDING_DIMENSIONS,
    build_phase3_deployment_identity,
    resolve_phase3_deployment_identity,
)

INTENT_SCHEMA = "aragorn/native-plugin-update-case-intent/v1"
REQUEST_SCHEMA = "aragorn/native-plugin-update-case-request/v1"
ROUTE, BRANCH = reported.ROUTE, reported.BRANCH
CONTROLLER_SOURCE_PATHS = (
    "scripts/capture_native_phase3_plugin_update_case.py",
    "scripts/runtime_native_plugin_update_case.py",
    "src/aragorn/native_phase3_plugin_update_case.py",
)
LIVE_SOURCE_PATHS = live.SOURCE_PATHS
PROVISIONING_PATHS = live.DYNAMIC_PATHS
_IDENTITY_SCHEMA = "aragorn/native-phase3-report-identity/v1"
_CONFIG_PIN = "sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c"
_WORKER_PIN = "sha256:df55f788ed29d188c71ca201d5778e7bff734b9a2f09445d8247c4ab6f40cd32"
_WORKER_BYTES = 46629
_BASELINE_BYTES = 422631
_BASELINE_DIGEST = (
    "sha256:42acdf26c128c4d7ecdfd740ac04b17509e9e17e0b799e7d4a870bf5e82a9e12"
)
_BASELINE_SOURCE_COMMIT = "85d59fd39ab8ccc2d74a6ab4ca8de029ed1fdd5d"
_BASELINE_SOURCE_DIGEST = (
    "sha256:1ae8f8739a59318b6b4fcc8b5c58c468aeaad151208c3562a8b6f4ec667b961a"
)
_MAX_INPUT = 2 * 1024 * 1024
_MAX_ARTIFACT = 1024 * 1024
_MAX_DOCUMENT = 16384
_FALSE_FLAGS = (
    "route_qualified",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "common_deployment_fully_verified",
    "live_deployment_attested",
    "metrics_eligible",
    "fresh_campaign_execution",
    "preactivation_commit_verified",
)


class NativePluginUpdateCaseError(ValueError):
    """The fixed case request or its retained evidence cannot be joined."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise NativePluginUpdateCaseError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "invalid content pin",
    )
    return value


def _pairs(items):
    value = dict(items)
    _require(len(value) == len(items), "duplicate JSON key")
    return value


def _parse(raw: bytes, limit: int = _MAX_DOCUMENT) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "unbounded input")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        _require(
            type(value) is dict and canonical_json(value) == raw, "noncanonical object"
        )
        return value
    except NativePluginUpdateCaseError:
        raise
    except (ValueError, TypeError, RecursionError) as exc:
        raise NativePluginUpdateCaseError("invalid canonical JSON input") from exc


def _pins(value: object, paths) -> dict:
    _require(type(value) is dict and set(value) == set(paths), "pin inventory changed")
    return {path: _pin(value[path]) for path in paths}


def _artifact(dimension: str, identity: dict) -> bytes:
    return canonical_json(
        {"schema": _IDENTITY_SCHEMA, "dimension": dimension, "identity": identity}
    )


def _intent(raw: bytes, expected: str) -> dict:
    _require(_digest(raw) == _pin(expected), "intent differs from caller pin")
    value = _parse(raw)
    _require(
        set(value)
        == {
            "schema",
            "case_id",
            "branch",
            "nonce",
            "deployment_digest",
            "case_adapter_digest",
            "source_commit",
            "source_record_digest",
            "static_pin_manifest_digest",
            "controller_source_digests",
            "live_source_digests",
        }
        and value["schema"] == INTENT_SCHEMA
        and value["case_id"] == ROUTE
        and value["branch"] == BRANCH
        and type(value["nonce"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["nonce"]) is not None
        and type(value["source_commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is not None,
        "fixed intent contract changed",
    )
    for name in (
        "deployment_digest",
        "case_adapter_digest",
        "source_record_digest",
        "static_pin_manifest_digest",
    ):
        _pin(value[name])
    _pins(value["controller_source_digests"], CONTROLLER_SOURCE_PATHS)
    _pins(value["live_source_digests"], LIVE_SOURCE_PATHS)
    return value


def build_native_plugin_update_case_intent(
    *,
    nonce: str,
    source_record_raw: bytes,
    controller_source_raws: dict[str, bytes],
    live_source_raws: dict[str, bytes],
    static_pin_manifest_raw: bytes,
    staged_profile: dict,
    baseline_capture_raw: bytes,
) -> dict[str, Any]:
    """Construct fixed caller expectations without files, CAS writes or execution.

    The one pinned historical capture supplies expected runtime, configuration,
    worker, policy, OS-profile and case-adapter bytes. It is not a new run or a
    claim that fresh per-fixture inputs will match: preparation must still check
    their actual writer bytes before activation. Current controller/source bytes
    replace only the common adapter and Aragorn identities. The host separately
    verifies the signed checkout, source record and actual stage; this constructor
    neither verifies a Git signature nor attests a deployment. Python/Node pins
    require the caller's existing independently reviewed pin provenance.
    """
    try:
        _require(
            type(baseline_capture_raw) is bytes
            and len(baseline_capture_raw) == _BASELINE_BYTES
            and _digest(baseline_capture_raw) == _BASELINE_DIGEST,
            "fixed baseline capture changed",
        )
        artifacts = reported.native_plugin_update_identity_artifacts(
            baseline_capture_raw,
            expected_capture_digest=_BASELINE_DIGEST,
            expected_source_digest=_BASELINE_SOURCE_DIGEST,
            expected_source_commit=_BASELINE_SOURCE_COMMIT,
        )
        baseline = reported._parse(baseline_capture_raw, newline=True)
        _require(type(staged_profile) is dict, "stage must be a bounded object")
        stage = _parse(canonical_json(staged_profile), _MAX_ARTIFACT)
        historical_stage = baseline["staged_profile"]
        _require(
            stage["schema"] == historical_stage["schema"]
            and type(stage["files"]) is list
            and len(stage["files"]) == 70
            and canonical_json(stage["files"])
            == canonical_json(historical_stage["files"])
            and stage["required_runtime_not_included"]
            == historical_stage["required_runtime_not_included"],
            "current stage differs from fixed native profile",
        )
        source = _parse(source_record_raw, _MAX_ARTIFACT)
        _require(
            type(source.get("commit")) is str
            and re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None,
            "current source commit is invalid",
        )
        static = _parse(static_pin_manifest_raw)
        _require(
            set(static) == {"schema", "file_digests"}
            and static["schema"]
            == "aragorn/native-plugin-update-identity-static-pins/v1",
            "static manifest contract changed",
        )
        static_pins = _pins(static["file_digests"], live.STATIC_PATHS)
        files = {item["path"]: item for item in stage["files"]}
        _require(
            all(
                static_pins[path] == files[path]["digest"]
                for path in live._PROFILE_PATHS
            )
            and static_pins[live._WORKER_CODE] == _WORKER_PIN
            and static_pins[live._ENTRY]
            == stage["required_runtime_not_included"]["entrypoint_digest"]
            and static_pins[live._PYTHON]
            == baseline["observation"]["setup"]["runtime_profile"]["executable_digest"],
            "static pins differ from fixed code or runtime expectations",
        )
        blobs = {}

        def retain(raw, limit=_MAX_ARTIFACT):
            _require(
                type(raw) is bytes and 0 < len(raw) <= limit, "unbounded public input"
            )
            raw.decode("utf-8")  # The fixed guest bundle transports UTF-8 bytes only.
            pin = _digest(raw)
            _require(
                pin not in blobs or blobs[pin] == raw, "public input digest collision"
            )
            blobs[pin] = raw
            return pin

        source_digest = retain(source_record_raw)
        static_digest = retain(static_pin_manifest_raw, _MAX_DOCUMENT)

        def source_pins(raws, paths):
            _require(
                type(raws) is dict and set(raws) == set(paths),
                "source inventory changed",
            )
            return {path: retain(raws[path]) for path in paths}

        controllers = source_pins(controller_source_raws, CONTROLLER_SOURCE_PATHS)
        live_sources = source_pins(live_source_raws, LIVE_SOURCE_PATHS)
        case_adapter_digest = retain(artifacts["adapter"])
        artifacts["adapter"] = _artifact(
            "adapter",
            {
                "controller_source_digests": controllers,
                "case_adapters": {
                    ROUTE: {
                        "branch": BRANCH,
                        "artifact_digest": case_adapter_digest,
                    }
                },
            },
        )
        artifacts["aragorn_version"] = _artifact(
            "aragorn_version",
            {
                "source_commit": source["commit"],
                "source_record_digest": source_digest,
            },
        )
        deployment = build_phase3_deployment_identity(
            {name: retain(raw) for name, raw in artifacts.items()}
        )
        intent = {
            "schema": INTENT_SCHEMA,
            "case_id": ROUTE,
            "branch": BRANCH,
            "nonce": nonce,
            "deployment_digest": retain(canonical_json(deployment), 4096),
            "case_adapter_digest": case_adapter_digest,
            "source_commit": source["commit"],
            "source_record_digest": source_digest,
            "static_pin_manifest_digest": static_digest,
            "controller_source_digests": controllers,
            "live_source_digests": live_sources,
        }
        intent_raw = canonical_json(intent)
        intent_digest = retain(intent_raw, _MAX_DOCUMENT)
        _intent(intent_raw, intent_digest)
        bundle = canonical_json(
            {
                "schema": "aragorn/native-plugin-update-case-inputs/v1",
                "intent_digest": intent_digest,
                "blobs": {pin: raw.decode("utf-8") for pin, raw in blobs.items()},
            }
        )
        _require(
            len(blobs) <= 32 and len(bundle) <= _MAX_INPUT,
            "case input bundle exceeds bound",
        )
        return {
            "intent_raw": intent_raw,
            "intent_digest": intent_digest,
            "input_blobs": blobs,
        }
    except NativePluginUpdateCaseError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise NativePluginUpdateCaseError(
            "native case intent construction refused"
        ) from exc


def _inputs(raw: bytes, expected: str, store: CAS) -> dict:
    _require(type(store) is CAS and store.read_only is True, "read-only CAS required")
    intent = _intent(raw, expected)
    retained = {}

    def read(pin, limit=_MAX_ARTIFACT):
        value = store.read(_pin(pin), max_bytes=limit)
        _require(type(value) is bytes and 0 < len(value) <= limit, "empty CAS input")
        _require(_digest(value) == pin, "CAS input digest changed")
        retained[pin] = value
        return value

    _require(read(expected, _MAX_DOCUMENT) == raw, "intent is not retained")
    deployment_raw = read(intent["deployment_digest"], 4096)
    deployment = resolve_phase3_deployment_identity(
        deployment_raw, expected_digest=intent["deployment_digest"], evidence_cas=store
    )
    artifacts = {name: read(pin) for name, pin in deployment["bindings"].items()}
    identities = {}
    for name, artifact_raw in artifacts.items():
        document = _parse(artifact_raw, _MAX_ARTIFACT)
        _require(
            set(document) == {"schema", "dimension", "identity"}
            and document["schema"] == _IDENTITY_SCHEMA
            and document["dimension"] == name
            and type(document["identity"]) is dict,
            "deployment artifact envelope changed",
        )
        identities[name] = document["identity"]
    case_adapter = _artifact(
        "adapter",
        {
            "route_id": ROUTE,
            "branch": BRANCH,
            "probe_sources": {
                name: {"bytes": pair[0], "digest": pair[1]}
                for name, pair in reported._SOURCES.items()
            },
        },
    )
    _require(
        read(intent["case_adapter_digest"]) == case_adapter
        and artifacts["adapter"]
        == _artifact(
            "adapter",
            {
                "controller_source_digests": intent["controller_source_digests"],
                "case_adapters": {
                    ROUTE: {
                        "branch": BRANCH,
                        "artifact_digest": intent["case_adapter_digest"],
                    }
                },
            },
        ),
        "common suite and fixed case adapter differ",
    )
    static = _parse(read(intent["static_pin_manifest_digest"], _MAX_DOCUMENT))
    _require(
        set(static) == {"schema", "file_digests"}
        and static["schema"] == "aragorn/native-plugin-update-identity-static-pins/v1",
        "static manifest contract changed",
    )
    _pins(static["file_digests"], live.STATIC_PATHS)
    _require(
        artifacts["runtime_commit_or_image"]
        == _artifact(
            "runtime_commit_or_image",
            {
                "runtime_tree": reported._RUNTIME,
                "fixture_image": reported._IMAGE,
                "runtime_volume": reported._VOLUME,
                "build_record_digest": reported._BUILD,
            },
        )
        and artifacts["configuration"]
        == _artifact("configuration", {"configuration_digest": _CONFIG_PIN})
        and artifacts["aragorn_version"]
        == _artifact(
            "aragorn_version",
            {
                "source_commit": intent["source_commit"],
                "source_record_digest": intent["source_record_digest"],
            },
        ),
        "fixed runtime, configuration or source identity changed",
    )
    source = _parse(read(intent["source_record_digest"]), _MAX_ARTIFACT)
    _require(source["commit"] == intent["source_commit"], "source commit differs")
    worker, profile = identities["worker"], identities["os_profile"]
    _require(
        set(worker) == {"bytes", "digest", "binding"}
        and worker["bytes"] == _WORKER_BYTES
        and worker["digest"] == static["file_digests"][live._WORKER_CODE] == _WORKER_PIN
        and set(profile) == {"fixture_image", "staged_schema", "staged_files_digest"}
        and profile["fixture_image"] == reported._IMAGE
        and profile["staged_schema"]
        == "aragorn/runtime-native-startup-staged-profile/v1",
        "worker or native profile identity changed",
    )
    _pin(profile["staged_files_digest"])
    _require(set(identities["policy"]) == {"policy_digest"}, "policy identity changed")
    _pin(identities["policy"]["policy_digest"])
    for mapping in (intent["controller_source_digests"], intent["live_source_digests"]):
        for pin in mapping.values():
            read(pin)
    return {
        "intent": intent,
        "artifacts": artifacts,
        "identities": identities,
        "static": static,
        "retained": retained,
    }


def _closure(store: CAS, retained: dict[str, bytes]) -> None:
    for pin, raw in retained.items():
        _require(store.read(pin, max_bytes=len(raw)) == raw, "input custody changed")


def validate_native_plugin_update_case_intent(
    intent_raw: bytes,
    *,
    expected_intent_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Resolve the fixed caller-held intent and return its exact input closure.

    The host separately verifies source bytes against its signed checkout and
    the OS-profile digest against the staged 70-file manifest. These read-only
    content joins do not attest either. ``input_blobs`` contains only the pinned
    public input artifacts/source bytes, never fresh provisioning credentials.
    """
    try:
        bound = _inputs(intent_raw, expected_intent_digest, evidence_cas)
        _closure(evidence_cas, bound["retained"])
        return {"intent": bound["intent"], "input_blobs": dict(bound["retained"])}
    except NativePluginUpdateCaseError:
        raise
    except (
        CASError,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OSError,
        OverflowError,
    ) as exc:
        raise NativePluginUpdateCaseError(
            "native case intent inspection refused"
        ) from exc


def _provisioning(inputs: object, bound: dict) -> dict:
    _require(
        type(inputs) is dict and set(inputs) == set(PROVISIONING_PATHS),
        "provisioning input inventory changed",
    )
    documents = {path: _parse(raw, _MAX_INPUT) for path, raw in inputs.items()}
    _require(
        len(inputs[live._GRANT]) <= 64 * 1024 and len(inputs[live._GENESIS]) <= 4096,
        "native grant or genesis exceeds runtime bound",
    )
    hashes = {path: _digest(raw) for path, raw in inputs.items()}
    worker, policy, runtime, observation, grant, genesis = (
        documents[path]
        for path in (
            live._WORKER,
            live._POLICY,
            live._RUNTIME,
            live._OBSERVATION,
            live._GRANT,
            live._GENESIS,
        )
    )
    _require(
        hashes[live._CONFIG] == _CONFIG_PIN
        and bound["artifacts"]["configuration"]
        == _artifact(
            "configuration",
            {
                "configuration_digest": hashes[live._CONFIG],
            },
        )
        and bound["artifacts"]["worker"]
        == _artifact(
            "worker",
            {
                "bytes": _WORKER_BYTES,
                "digest": _WORKER_PIN,
                "binding": worker,
            },
        )
        and bound["artifacts"]["policy"]
        == _artifact(
            "policy",
            {
                "policy_digest": hashes[live._POLICY],
            },
        ),
        "fresh writer inputs differ from common deployment",
    )
    _require(
        set(worker)
        == {
            "schema",
            "runtime_digest",
            "active_skill_digest",
            "policy_digest",
            "policy_version",
        }
        and worker["schema"] == "aragorn/runtime-action-worker-binding/v1"
        and set(runtime) == {"schema", "runtime_digest", "runtime_profile_digest"}
        and runtime["schema"] == "aragorn/runtime-action-runtime-binding/v2"
        and set(observation) == {"schema", "sensor_digest", "runtime_profile"}
        and observation["schema"] == "aragorn/runtime-observation-binding/v2"
        and set(policy)
        == {
            "schema",
            "id",
            "version",
            "default",
            "sensor_digest",
            "revocation_source_digest",
            "allow",
        }
        and policy["schema"] == "aragorn/runtime-action-policy/v1"
        and policy["id"] == "owned-native-receipt-read-create"
        and policy["default"] == "BLOCK"
        and set(grant)
        == {
            "schema",
            "authority",
            "grant_id",
            "issued_at_unix",
            "expires_at_unix",
            "max_actions",
            "runtime_digest",
            "runtime_profile_digest",
            "active_skill_digest",
            "install_context_digest",
            "source_manifest_digest",
            "operation_digest",
            "policy_digest",
            "policy_version",
            "sensor_digest",
        }
        and grant["schema"] == "aragorn/runtime-capability-grant/v1"
        and grant["authority"]
        == "ROOT_RUNTIME_CAPABILITY_GRANT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY"
        and type(grant["max_actions"]) is int
        and grant["max_actions"] == 1
        and set(genesis)
        == {
            "schema",
            "authority",
            "stream_id",
            "runtime_digest",
            "policy_digest",
            "policy_version",
            "worker_uid",
            "worker_gid",
        }
        and genesis["schema"] == "aragorn/native-tool-receipt-genesis/v1"
        and genesis["authority"]
        == "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY"
        and type(genesis["worker_uid"]) is int
        and genesis["worker_uid"] == 997
        and type(genesis["worker_gid"]) is int
        and genesis["worker_gid"] == 997,
        "provisioning document contract changed",
    )
    profile = observation["runtime_profile"]
    _require(
        type(profile) is dict
        and set(profile)
        == {
            "schema",
            "authority",
            "runtime_digest",
            "executable_digest",
            "cgroup",
            "skill_path",
        }
        and profile["schema"] == "aragorn/runtime-single-skill-process-profile/v1"
        and profile["authority"]
        == "ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY"
        and type(profile["cgroup"]) is str
        and re.fullmatch(
            r"/docker/[0-9a-f]{64}/system\.slice/aragorn-runtime-action-worker\.service",
            profile["cgroup"],
        )
        is not None
        and profile["executable_digest"]
        == bound["static"]["file_digests"][live._PYTHON]
        and type(profile["skill_path"]) is str
        and re.fullmatch(
            r"/var/lib/aragorn-protected/skills/\.aragorn-versions/aragorn-admitted/[0-9a-f]{64}-[0-9a-f]{64}/SKILL\.md",
            profile["skill_path"],
        )
        is not None,
        "native process profile binding changed",
    )
    runtime_pin = reported._RUNTIME["tree_digest"]
    _require(
        all(
            item["runtime_digest"] == runtime_pin
            for item in (worker, runtime, profile, grant, genesis)
        )
        and all(
            item["policy_digest"] == hashes[live._POLICY]
            for item in (worker, grant, genesis)
        )
        and type(policy["version"]) is int
        and policy["version"] == 1
        and all(
            type(item["policy_version"]) is int
            and item["policy_version"] == policy["version"]
            for item in (worker, grant, genesis)
        )
        and runtime["runtime_profile_digest"]
        == grant["runtime_profile_digest"]
        == _digest(canonical_json(profile))
        and observation["sensor_digest"]
        == grant["sensor_digest"]
        == policy["sensor_digest"]
        and worker["active_skill_digest"] == grant["active_skill_digest"]
        and type(policy["allow"]) is list
        and len(policy["allow"]) == 1
        and type(policy["allow"][0]) is dict
        and set(policy["allow"][0])
        == {
            "runtime_digest",
            "active_skill_digest",
            "operation_digest",
            "path_digest",
            "payload_digest",
        }
        and policy["allow"][0]["runtime_digest"] == runtime_pin
        and policy["allow"][0]["active_skill_digest"] == worker["active_skill_digest"]
        and policy["allow"][0]["operation_digest"] == grant["operation_digest"],
        "fresh provisioning cross-document joins changed",
    )
    for name in (
        "active_skill_digest",
        "install_context_digest",
        "operation_digest",
        "source_manifest_digest",
    ):
        _pin(grant[name])
    for pin in (
        policy["sensor_digest"],
        policy["revocation_source_digest"],
        policy["allow"][0]["path_digest"],
        policy["allow"][0]["payload_digest"],
    ):
        _pin(pin)
    _pin(genesis["stream_id"])
    _require(
        type(grant["grant_id"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", grant["grant_id"]) is not None
        and profile["skill_path"].endswith(
            "-" + grant["source_manifest_digest"][7:] + "/SKILL.md"
        )
        and all(
            type(grant[name]) is int and 0 < grant[name] < 2**63
            for name in ("issued_at_unix", "expires_at_unix")
        )
        and 0 < grant["expires_at_unix"] - grant["issued_at_unix"] <= 300,
        "grant epoch is invalid",
    )
    return hashes


def _request(intent: dict, intent_digest: str, hashes: dict) -> dict:
    return {
        "schema": REQUEST_SCHEMA,
        "intent_digest": intent_digest,
        **{
            key: intent[key]
            for key in (
                "case_id",
                "branch",
                "nonce",
                "deployment_digest",
                "case_adapter_digest",
                "static_pin_manifest_digest",
            )
        },
        "provisioning_file_digests": _pins(hashes, PROVISIONING_PATHS),
        "prepared_before_activation": True,
    }


def prepare_native_plugin_update_case(
    intent_raw: bytes,
    *,
    expected_intent_digest: str,
    evidence_cas: CAS,
    provisioning_inputs: dict[str, bytes],
) -> dict[str, Any]:
    """Return a nonsecret request, never a durable-precommit or activation claim.

    The trusted guest calls this with the exact bytes intercepted before each
    existing writer call, then durably publishes the request before activation.
    This pure API cannot prove that ordering and performs no filesystem writes.
    """
    try:
        bound = _inputs(intent_raw, expected_intent_digest, evidence_cas)
        hashes = _provisioning(provisioning_inputs, bound)
        request = _request(bound["intent"], expected_intent_digest, hashes)
        raw = canonical_json(request)
        _closure(evidence_cas, bound["retained"])
        return {
            "request_raw": raw,
            "request_digest": _digest(raw),
            "request": request,
            "provisioning_file_digests": dict(hashes),
            "deployment_digest": bound["intent"]["deployment_digest"],
        }
    except NativePluginUpdateCaseError:
        raise
    except (
        CASError,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OSError,
        OverflowError,
    ) as exc:
        raise NativePluginUpdateCaseError("native case preparation refused") from exc


def verify_native_plugin_update_case(
    request_raw: bytes,
    *,
    expected_request_digest: str,
    expected_intent_digest: str,
    expected_collection_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Join one pinned request to independently replayed local capture evidence.

    A request flag is not independent proof of preactivation publication. Source
    pins establish content custody, not executed code or trustworthy semantics.
    The pinned collection selects its nested capture/live pins; it cannot select
    this function, arbitrary callbacks, a different case or a common deployment.
    """
    from . import native_phase3_plugin_update_collection as collection

    try:
        _require(
            type(evidence_cas) is CAS and evidence_cas.read_only is True,
            "read-only CAS required",
        )
        intent_raw = evidence_cas.read(
            _pin(expected_intent_digest), max_bytes=_MAX_DOCUMENT
        )
        bound = _inputs(intent_raw, expected_intent_digest, evidence_cas)
        intent = bound["intent"]
        _require(
            _digest(request_raw) == _pin(expected_request_digest), "request pin changed"
        )
        request = _parse(request_raw)
        _require(
            canonical_json(
                _request(
                    intent, expected_intent_digest, request["provisioning_file_digests"]
                )
            )
            == request_raw
            and evidence_cas.read(expected_request_digest, max_bytes=_MAX_DOCUMENT)
            == request_raw,
            "retained request differs from fixed intent",
        )
        collection_raw = evidence_cas.read(
            _pin(expected_collection_digest), max_bytes=_MAX_DOCUMENT
        )
        manifest = _parse(collection_raw)
        context = manifest["context"]
        _require(
            context["source_record_digest"] == intent["source_record_digest"]
            and context["source_commit"] == intent["source_commit"]
            and context["static_pin_manifest_digest"]
            == intent["static_pin_manifest_digest"]
            and context["live_source_digests"] == intent["live_source_digests"],
            "case collection differs from intent sources",
        )
        replay = collection.replay_native_plugin_update_live_collection(
            expected_collection_digest=expected_collection_digest,
            expected_capture_digest=context["capture_digest"],
            expected_source_digest=intent["source_record_digest"],
            expected_source_commit=intent["source_commit"],
            expected_deployment_digest=context["deployment_identity_digest"],
            expected_live_identity_digest=context["live_identity_digest"],
            expected_static_pin_manifest_digest=intent["static_pin_manifest_digest"],
            expected_live_source_digests=intent["live_source_digests"],
            evidence_cas=evidence_cas,
        )
        validated = replay["collection"]
        _require(
            canonical_json(validated) == collection_raw,
            "collection changed during replay",
        )

        def retain_reference(reference, limit):
            raw = collection._read_reference(evidence_cas, reference, limit)
            pin = reference["digest"]
            _require(
                pin not in bound["retained"] or bound["retained"][pin] == raw,
                "nested evidence differs from retained input",
            )
            bound["retained"][pin] = raw
            return raw

        # Semantic replay has already validated both exact manifest inventories.
        # Carry every child into our final custody pass as well: the nested
        # verifier's earlier readback is not end-of-case retention authority.
        reported_raw = retain_reference(
            validated["reported_collection"], collection._COLLECTION_LIMIT
        )
        reported_manifest = collection._parse(
            reported_raw, collection._COLLECTION_LIMIT
        )
        for name, limit in (
            ("capture", collection._CAPTURE_LIMIT),
            ("source", collection._ARTIFACT_LIMIT),
            ("deployment", collection._DEPLOYMENT_LIMIT),
            ("verification", collection._RESULT_LIMIT),
        ):
            retain_reference(reported_manifest[name], limit)
        for reference in reported_manifest["identity_artifacts"].values():
            retain_reference(reference, collection._ARTIFACT_LIMIT)
        for name, limit in (
            ("live_identity", collection._LIVE_LIMIT),
            ("static_pin_manifest", collection._STATIC_LIMIT),
            ("verification", collection._RESULT_LIMIT),
        ):
            retain_reference(validated[name], limit)
        for reference in validated["live_sources"].values():
            retain_reference(reference, collection._ARTIFACT_LIMIT)
        case_deployment_raw = evidence_cas.read(
            context["deployment_identity_digest"], max_bytes=4096
        )
        case_deployment = resolve_phase3_deployment_identity(
            case_deployment_raw,
            expected_digest=context["deployment_identity_digest"],
            evidence_cas=evidence_cas,
        )
        for dimension in BINDING_DIMENSIONS:
            pin = case_deployment["bindings"][dimension]
            raw = evidence_cas.read(pin, max_bytes=_MAX_ARTIFACT)
            expected = (
                bound["retained"][intent["case_adapter_digest"]]
                if dimension == "adapter"
                else bound["artifacts"][dimension]
            )
            _require(raw == expected, "common and case deployment relation changed")
            bound["retained"][pin] = raw
        live_raw = evidence_cas.read(
            context["live_identity_digest"], max_bytes=_MAX_INPUT
        )
        envelope = _parse(live_raw, _MAX_INPUT)
        _require(
            envelope["provisioning_file_digests"]
            == request["provisioning_file_digests"]
            and all(
                envelope["expected_file_digests"][path] == pin
                for path, pin in request["provisioning_file_digests"].items()
            ),
            "prepared writer inputs differ from live case readback",
        )
        _require(
            canonical_json(replay["collection"]) == collection_raw,
            "collection changed during replay",
        )
        bound["retained"].update(
            {
                expected_request_digest: request_raw,
                expected_collection_digest: collection_raw,
                context["deployment_identity_digest"]: case_deployment_raw,
                context["live_identity_digest"]: live_raw,
            }
        )
        _closure(evidence_cas, bound["retained"])
        return {
            "schema": "aragorn/native-plugin-update-case-verification/v1",
            "status": "BOUNDED_PREPARED_CASE_READBACK_JOINS_VERIFIED",
            "case_id": ROUTE,
            "branch": BRANCH,
            "bindings": {
                "intent_digest": expected_intent_digest,
                "request_digest": expected_request_digest,
                "collection_digest": expected_collection_digest,
                "deployment_digest": intent["deployment_digest"],
                "case_adapter_digest": intent["case_adapter_digest"],
            },
            "limitations": [
                "PURE_REQUEST_PREPARATION_NOT_DURABLE_PREACTIVATION_COMMIT_PROOF",
                "LOCAL_READBACK_JOINS_NOT_EXTERNAL_ATTESTATION_OR_POLICY_SEMANTICS",
                "SINGLE_MARKETPLACE_BRANCH_NOT_COMPLETE_ADMISSION_ROUTE",
                "CONTROLLER_SOURCE_CUSTODY_NOT_PROOF_OF_EXECUTION",
                "NO_ADMISSION_RUN_METRICS_OR_PHASE3_QUALIFICATION",
            ],
            **dict.fromkeys(_FALSE_FLAGS, False),
        }
    except NativePluginUpdateCaseError:
        raise
    except (
        CASError,
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OSError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise NativePluginUpdateCaseError("native case replay refused") from exc
