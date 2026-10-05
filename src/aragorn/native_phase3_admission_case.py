"""Fixed native admission successor expectations and preactivation request joins.

Both case adapters share one deployment identity. Selecting a case changes its
intent/request, never the common adapter inventory. Historical records remain
expectations; actual writer bytes must join before activation. No files, CAS
writes, services, callbacks or live measurements are performed by this module.
"""

from __future__ import annotations

import re
from typing import Any

from . import native_phase3_plugin_update_case as old
from .cas import CAS, CASError
from .oci_worker_protocol import canonical_json
from .phase3_deployment import (
    build_phase3_deployment_identity,
    resolve_phase3_deployment_identity,
)

INTENT_SCHEMA = "aragorn/native-admission-case-intent/v1"
REQUEST_SCHEMA = "aragorn/native-admission-case-request/v1"
DIRECT_WRITE_CASE = "ADM-02/direct-write"
DIRECT_WRITE_BRANCH = "DIRECT_WRITE_SIX_ROOTS_AND_ADMITTED_FILE"
UPDATE_CASE, UPDATE_BRANCH = old.ROUTE, old.BRANCH
CASE_BRANCHES = {
    DIRECT_WRITE_CASE: DIRECT_WRITE_BRANCH,
    UPDATE_CASE: UPDATE_BRANCH,
}
CONTROLLER_SOURCE_PATHS = (
    "scripts/capture_native_phase3_admission_case.py",
    "scripts/runtime_native_admission_case.py",
    "src/aragorn/native_phase3_admission_case.py",
)
LIVE_SOURCE_PATHS = ("src/aragorn/native_phase3_live_identity.py",)
CASE_SOURCE_PATHS = (
    "scripts/runtime_native_admission_direct_write.py",
    "src/aragorn/native_phase3_admission_direct_write.py",
)
PROVISIONING_PATHS = old.PROVISIONING_PATHS
STAGED_SCHEMA = "aragorn/runtime-native-admission-staged-profile/v1"
# Derived once from the actual inert, reviewed admission stager at 7fff0bc.
# These identify the complete report and two exact outputs, not a deployment.
STAGED_PROFILE_PIN = (
    44940,
    "sha256:f57196fb2e6a955ed0485a2d01af6df0448fcae5f74c7fedb66016faf5f28da5",
)
STAGED_REPLACEMENTS = {
    "/usr/lib/systemd/system/aragorn-agent-gateway.service": (
        3870,
        "sha256:660a722ba31decc2f40077e272974b8b571e232f4a77435e9341460e84b2558d",
    ),
    "/usr/libexec/aragorn/activate-runtime-action-worker-host.sh": (
        41965,
        "sha256:578c28cbdbbd236b8930644aba7200514ae2499eee40bb503a00cee1a092e103",
    ),
}
_NODE_PIN = "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"
_MAX_INPUT = old._MAX_INPUT
_MAX_ARTIFACT = old._MAX_ARTIFACT
_MAX_DOCUMENT = old._MAX_DOCUMENT
_FALSE_FLAGS = old._FALSE_FLAGS
_digest, _parse, _pin, _pins, _artifact = (
    old._digest,
    old._parse,
    old._pin,
    old._pins,
    old._artifact,
)
_INTENT_KEYS = {
    "schema",
    "case_id",
    "branch",
    "nonce",
    "deployment_digest",
    "case_adapter_digest",
    "source_commit",
    "source_record_digest",
    "static_pin_manifest_digest",
    "staged_profile_digest",
    "controller_source_digests",
    "live_source_digests",
    "case_source_digests",
}
_SOURCE_INVENTORIES = (
    ("controller_source_digests", CONTROLLER_SOURCE_PATHS),
    ("live_source_digests", LIVE_SOURCE_PATHS),
    ("case_source_digests", CASE_SOURCE_PATHS),
)


class NativeAdmissionCaseError(ValueError):
    """Fixed successor inputs or exact provisioning joins were refused."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise NativeAdmissionCaseError(message)


def _intent(raw: bytes, expected: str) -> dict:
    _require(_digest(raw) == _pin(expected), "intent differs from caller pin")
    value = _parse(raw)
    _require(
        set(value) == _INTENT_KEYS
        and value["schema"] == INTENT_SCHEMA
        and type(value["case_id"]) is str
        and value["case_id"] in CASE_BRANCHES
        and value["branch"] == CASE_BRANCHES[value["case_id"]]
        and type(value["nonce"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", value["nonce"]) is not None
        and type(value["source_commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is not None,
        "fixed admission intent contract changed",
    )
    for name in (
        "deployment_digest",
        "case_adapter_digest",
        "source_record_digest",
        "static_pin_manifest_digest",
        "staged_profile_digest",
    ):
        _pin(value[name])
    for name, paths in _SOURCE_INVENTORIES:
        _pins(value[name], paths)
    return value


def _baseline(raw: bytes) -> tuple[dict, dict[str, bytes]]:
    _require(
        type(raw) is bytes
        and (len(raw), _digest(raw)) == (old._BASELINE_BYTES, old._BASELINE_DIGEST),
        "fixed historical baseline changed",
    )
    artifacts = old.reported.native_plugin_update_identity_artifacts(
        raw,
        expected_capture_digest=old._BASELINE_DIGEST,
        expected_source_digest=old._BASELINE_SOURCE_DIGEST,
        expected_source_commit=old._BASELINE_SOURCE_COMMIT,
    )
    return old.reported._parse(raw, newline=True), artifacts


def _stage(raw: bytes, baseline: dict) -> dict:
    _require(
        (len(raw), _digest(raw)) == STAGED_PROFILE_PIN,
        "reviewed admission stage report changed",
    )
    stage = _parse(raw, _MAX_ARTIFACT)
    predecessor = baseline["staged_profile"]
    _require(
        stage["schema"] == STAGED_SCHEMA
        and stage["admission_qualified"] is False
        and len(stage["files"]) == 70
        and len(stage["source_inputs"]) == 85
        and len(stage["directories"]) == 16
        and stage["directories"] == predecessor["directories"]
        and stage["required_runtime_not_included"]
        == predecessor["required_runtime_not_included"],
        "native successor inventory changed",
    )
    before = {row["path"]: row for row in predecessor["files"]}
    after = {row["path"]: row for row in stage["files"]}
    _require(
        len(before) == len(after) == 70 and set(before) == set(after),
        "native successor destinations changed",
    )
    changed = {path for path in before if before[path] != after[path]}
    _require(
        changed == set(STAGED_REPLACEMENTS),
        "successor must change exactly gateway and activator",
    )
    for path, (size, pin) in STAGED_REPLACEMENTS.items():
        _require(
            after[path] == {**before[path], "bytes": size, "digest": pin},
            "successor replacement bytes or metadata changed",
        )
    return stage


def _static(raw: bytes, stage: dict, baseline: dict) -> dict:
    value = _parse(raw)
    _require(
        set(value) == {"schema", "file_digests"}
        and value["schema"] == "aragorn/native-plugin-update-identity-static-pins/v1",
        "static manifest contract changed",
    )
    pins = _pins(value["file_digests"], old.live.STATIC_PATHS)
    files = {row["path"]: row for row in stage["files"]}
    _require(
        all(pins[path] == files[path]["digest"] for path in old.live._PROFILE_PATHS)
        and pins[old.live._WORKER_CODE] == old._WORKER_PIN
        and pins[old.live._ENTRY]
        == stage["required_runtime_not_included"]["entrypoint_digest"]
        and pins[old.live._PYTHON]
        == baseline["observation"]["setup"]["runtime_profile"]["executable_digest"]
        and pins[old.live._NODE] == _NODE_PIN,
        "static pins differ from exact successor or historical binary expectations",
    )
    return value


def _artifacts(
    baseline_artifacts: dict,
    *,
    stage: dict,
    source: dict,
    source_pin: str,
    controller_pins: dict,
    live_pins: dict,
    case_sources: dict[str, bytes],
) -> tuple[dict, dict]:
    adapters = {
        UPDATE_CASE: baseline_artifacts["adapter"],
        DIRECT_WRITE_CASE: _artifact(
            "adapter",
            {
                "route_id": DIRECT_WRITE_CASE,
                "branch": DIRECT_WRITE_BRANCH,
                "probe_sources": {
                    path: {"bytes": len(raw), "digest": _digest(raw)}
                    for path, raw in case_sources.items()
                },
            },
        ),
    }
    artifacts = dict(baseline_artifacts)
    artifacts["adapter"] = _artifact(
        "adapter",
        {
            "controller_source_digests": controller_pins,
            "live_source_digests": live_pins,
            "case_adapters": {
                case_id: {
                    "branch": CASE_BRANCHES[case_id],
                    "artifact_digest": _digest(raw),
                }
                for case_id, raw in adapters.items()
            },
        },
    )
    artifacts["os_profile"] = _artifact(
        "os_profile",
        {
            "fixture_image": old.reported._IMAGE,
            "staged_schema": STAGED_SCHEMA,
            "staged_files_digest": _digest(canonical_json(stage["files"])),
        },
    )
    artifacts["aragorn_version"] = _artifact(
        "aragorn_version",
        {
            "source_commit": source["commit"],
            "source_record_digest": source_pin,
        },
    )
    return artifacts, adapters


def _source(raw: bytes) -> dict:
    value = _parse(raw, _MAX_ARTIFACT)
    _require(
        type(value.get("commit")) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["commit"]) is not None,
        "current source commit is invalid",
    )
    return value


def build_native_admission_case_intent(
    *,
    case_id: str,
    nonce: str,
    source_record_raw: bytes,
    controller_source_raws: dict[str, bytes],
    live_source_raws: dict[str, bytes],
    case_source_raws: dict[str, bytes],
    static_pin_manifest_raw: bytes,
    staged_profile: dict,
    baseline_capture_raw: bytes,
) -> dict[str, Any]:
    """Build one fixed selection over a two-case common deployment, without writes.

    The caller must first update exactly the gateway static pin from the reviewed
    stager. Historical input bytes are retained as expectations, not fresh evidence.
    The host independently verifies the signed source and actual inert stage.
    """
    try:
        _require(
            type(case_id) is str and case_id in CASE_BRANCHES,
            "unsupported fixed admission case",
        )
        baseline, original = _baseline(baseline_capture_raw)
        stage_raw = canonical_json(staged_profile)
        stage = _stage(stage_raw, baseline)
        _static(static_pin_manifest_raw, stage, baseline)
        source = _source(source_record_raw)
        blobs = {}

        def retain(raw, limit=_MAX_ARTIFACT):
            _require(
                type(raw) is bytes and 0 < len(raw) <= limit, "unbounded public input"
            )
            raw.decode("utf-8")
            pin = _digest(raw)
            _require(pin not in blobs or blobs[pin] == raw, "input digest collision")
            blobs[pin] = raw
            return pin

        def sources(raws, paths):
            _require(
                type(raws) is dict and set(raws) == set(paths),
                "source inventory changed",
            )
            return {path: retain(raws[path]) for path in paths}

        source_pin = retain(source_record_raw)
        controllers = sources(controller_source_raws, CONTROLLER_SOURCE_PATHS)
        live_pins = sources(live_source_raws, LIVE_SOURCE_PATHS)
        case_pins = sources(case_source_raws, CASE_SOURCE_PATHS)
        artifacts, adapters = _artifacts(
            original,
            stage=stage,
            source=source,
            source_pin=source_pin,
            controller_pins=controllers,
            live_pins=live_pins,
            case_sources=case_source_raws,
        )
        deployment = build_phase3_deployment_identity(
            {name: retain(raw) for name, raw in artifacts.items()}
        )
        for raw in adapters.values():
            retain(raw)
        retain(baseline_capture_raw)
        intent = {
            "schema": INTENT_SCHEMA,
            "case_id": case_id,
            "branch": CASE_BRANCHES[case_id],
            "nonce": nonce,
            "deployment_digest": retain(canonical_json(deployment), 4096),
            "case_adapter_digest": _digest(adapters[case_id]),
            "source_commit": source["commit"],
            "source_record_digest": source_pin,
            "static_pin_manifest_digest": retain(
                static_pin_manifest_raw, _MAX_DOCUMENT
            ),
            "staged_profile_digest": retain(stage_raw),
            "controller_source_digests": controllers,
            "live_source_digests": live_pins,
            "case_source_digests": case_pins,
        }
        raw = canonical_json(intent)
        pin = retain(raw, _MAX_DOCUMENT)
        _intent(raw, pin)
        bundle = canonical_json(
            {
                "schema": "aragorn/native-admission-case-inputs/v1",
                "intent_digest": pin,
                "blobs": {key: value.decode("utf-8") for key, value in blobs.items()},
            }
        )
        _require(
            len(blobs) <= 32 and len(bundle) <= _MAX_INPUT,
            "fixed admission bundle exceeds bound",
        )
        return {"intent_raw": raw, "intent_digest": pin, "input_blobs": blobs}
    except NativeAdmissionCaseError:
        raise
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise NativeAdmissionCaseError(
            "native admission intent construction refused"
        ) from exc


def _inputs(raw: bytes, expected: str, store: CAS) -> dict:
    _require(type(store) is CAS and store.read_only is True, "read-only CAS required")
    intent = _intent(raw, expected)
    retained = {}

    def read(pin, limit=_MAX_ARTIFACT):
        value = store.read(_pin(pin), max_bytes=limit)
        _require(
            type(value) is bytes and 0 < len(value) <= limit and _digest(value) == pin,
            "retained input bytes changed",
        )
        retained[pin] = value
        return value

    _require(read(expected, _MAX_DOCUMENT) == raw, "intent is not retained")
    baseline, original = _baseline(read(old._BASELINE_DIGEST))
    stage = _stage(read(intent["staged_profile_digest"]), baseline)
    static = _static(
        read(intent["static_pin_manifest_digest"], _MAX_DOCUMENT), stage, baseline
    )
    source = _source(read(intent["source_record_digest"]))
    _require(source["commit"] == intent["source_commit"], "source commit differs")
    raw_sources = {}
    for name, paths in _SOURCE_INVENTORIES:
        raw_sources[name] = {path: read(intent[name][path]) for path in paths}
        for source_raw in raw_sources[name].values():
            source_raw.decode("utf-8")
    artifacts, adapters = _artifacts(
        original,
        stage=stage,
        source=source,
        source_pin=intent["source_record_digest"],
        controller_pins=intent["controller_source_digests"],
        live_pins=intent["live_source_digests"],
        case_sources=raw_sources["case_source_digests"],
    )
    deployment_raw = read(intent["deployment_digest"], 4096)
    deployment = resolve_phase3_deployment_identity(
        deployment_raw,
        expected_digest=intent["deployment_digest"],
        evidence_cas=store,
    )
    for name, artifact in artifacts.items():
        _require(
            read(deployment["bindings"][name]) == artifact,
            "common deployment artifact changed",
        )
    for artifact in adapters.values():
        _require(read(_digest(artifact)) == artifact, "fixed case adapter changed")
    _require(
        intent["case_adapter_digest"] == _digest(adapters[intent["case_id"]]),
        "selected adapter differs from common inventory",
    )
    return {
        "intent": intent,
        "artifacts": artifacts,
        "static": static,
        "retained": retained,
    }


def validate_native_admission_case_intent(
    intent_raw: bytes,
    *,
    expected_intent_digest: str,
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Read back the complete fixed input closure, never attest its execution."""
    try:
        bound = _inputs(intent_raw, expected_intent_digest, evidence_cas)
        old._closure(evidence_cas, bound["retained"])
        return {"intent": bound["intent"], "input_blobs": dict(bound["retained"])}
    except NativeAdmissionCaseError:
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
        raise NativeAdmissionCaseError(
            "native admission intent inspection refused"
        ) from exc


def prepare_native_admission_case(
    intent_raw: bytes,
    *,
    expected_intent_digest: str,
    evidence_cas: CAS,
    provisioning_inputs: dict[str, bytes],
) -> dict[str, Any]:
    """Join seven exact existing writer inputs; publication/ordering belong to guest."""
    try:
        bound = _inputs(intent_raw, expected_intent_digest, evidence_cas)
        hashes = old._provisioning(provisioning_inputs, bound)
        intent = bound["intent"]
        request = {
            **old._request(intent, expected_intent_digest, hashes),
            "schema": REQUEST_SCHEMA,
            "staged_profile_digest": intent["staged_profile_digest"],
        }
        raw = canonical_json(request)
        old._closure(evidence_cas, bound["retained"])
        return {
            "request": request,
            "request_raw": raw,
            "request_digest": _digest(raw),
            "provisioning_file_digests": dict(hashes),
            "deployment_digest": intent["deployment_digest"],
            **dict.fromkeys(_FALSE_FLAGS, False),
        }
    except NativeAdmissionCaseError:
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
        raise NativeAdmissionCaseError(
            "native admission case preparation refused"
        ) from exc
