"""Prepare or capture one fixed native admission successor case.

Preparation is offline. Capture only uses the already-owned native disposable
fixture primitives; it never starts a VM or activates a service on the host.
All four fixed cases share this deployment. The existing plugin-update adapter and
its exact inert input bundle are reused without changing frozen predecessors.
"""

from __future__ import annotations

import argparse
from io import BytesIO
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from tempfile import TemporaryDirectory

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_native_phase3_plugin_update_case as legacy
from scripts import capture_runtime_native_receipt_systemd_check as native
from scripts import prepare_native_plugin_update_identity_pins as pins
from scripts import runtime_native_admission_case as guest
from scripts import stage_runtime_native_admission_profile as profile
from aragorn import native_phase3_admission_case as case
from aragorn import native_phase3_admission_capture as replay
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

_GUEST = "scripts/runtime_native_admission_case.py"
_FILES = legacy._FILES | {
    _GUEST: "/opt/aragorn/runtime_native_admission_case.py",
    "scripts/runtime_native_admission_direct_write.py": "/opt/aragorn/runtime_native_admission_direct_write.py",
    "src/aragorn/native_phase3_admission_case.py": "/usr/lib/aragorn/aragorn/native_phase3_admission_case.py",
    "src/aragorn/native_phase3_admission_direct_write.py": "/usr/lib/aragorn/aragorn/native_phase3_admission_direct_write.py",
    "scripts/runtime_native_admission_path_mutation.py": "/opt/aragorn/runtime_native_admission_path_mutation.py",
    "src/aragorn/native_phase3_admission_path_mutation.py": "/usr/lib/aragorn/aragorn/native_phase3_admission_path_mutation.py",
}
_FALSE = legacy._FALSE
_DIRECT = "ADM-02/direct-write"
_SCHEMA = "aragorn/native-admission-case-capture/v1"
_AUTHORITY = (
    "OWNED_SUCCESSOR_CASE_CAPTURE_NOT_INDEPENDENT_ROUTE_OR_PHASE3_QUALIFICATION"
)
_LIMIT = 4 * 1024 * 1024
_API = native.acquisition
_UPDATE = legacy.prior.prior

# One fixed public bundle, handed off only after exact owned-fixture checks.
_SEAL = """import hashlib,os,stat,sys
p='/opt/aragorn/native-admission-case-inputs.json'
fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
identity=lambda s:tuple(getattr(s,k) for k in fields)
fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
try:
 before=os.fstat(fd)
 assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==0o444
 assert (before.st_uid,before.st_gid) in ((0,0),(int(sys.argv[2]),int(sys.argv[3])))
 raw=b''
 while len(raw)<=2097152:
  piece=os.read(fd,min(65536,2097153-len(raw)))
  if not piece:break
  raw+=piece
 assert 0<len(raw)<=2097152 and not os.read(fd,1)
 assert 'sha256:'+hashlib.sha256(raw).hexdigest()==sys.argv[1]
 assert identity(before)==identity(os.fstat(fd))==identity(os.stat(p,follow_symlinks=False))
 os.fchown(fd,0,0)
 after=os.fstat(fd)
 assert (after.st_uid,after.st_gid)==(0,0)
 assert identity(after)==identity(os.stat(p,follow_symlinks=False))
finally:os.close(fd)
"""


def _inspect(store: CAS, intent_pin: str) -> dict:
    raw = store.read(case._pin(intent_pin), max_bytes=16384)
    return case.validate_native_admission_case_intent(
        raw, expected_intent_digest=intent_pin, evidence_cas=store
    )


def _current_source() -> dict:
    # Eager imports above make preparation and capture use the same recorder.
    return legacy._current_source()


def _source_guard(inspected: dict) -> dict:
    intent, blobs = inspected["intent"], inspected["input_blobs"]
    source = _current_source()
    case._require(
        source["commit"] == intent["source_commit"]
        and canonical_json(source) == blobs[intent["source_record_digest"]],
        "signed checkout differs from retained successor source",
    )
    for field in (
        "controller_source_digests",
        "live_source_digests",
        "case_source_digests",
    ):
        for path, pin in intent[field].items():
            raw = blobs[pin]
            entry = _API._tree_file(source["commit"], Path(path))
            case._require(
                entry["digest"] == pin and entry["bytes"] == len(raw),
                "successor source differs from signed commit",
            )
            legacy._source_bytes(_ROOT / path, raw)
    return source


def _stage_guard(manifest: dict, inspected: dict) -> None:
    intent, blobs = inspected["intent"], inspected["input_blobs"]
    case._require(
        canonical_json(manifest) == blobs[intent["staged_profile_digest"]]
        and manifest["schema"] == profile._SCHEMA
        and manifest["authority"] == profile._AUTHORITY
        and (
            len(manifest["files"]),
            len(manifest["source_inputs"]),
            len(manifest["new_dependencies"]),
            len(manifest["directories"]),
        )
        == (70, 85, 26, 16),
        "successor staged profile differs from intent",
    )
    destinations = {item["path"] for item in manifest["files"]}
    case._require(
        len(destinations) == 70
        and len(set(_FILES.values())) == len(_FILES)
        and not destinations.intersection(_FILES.values()),
        "successor helper and staged destinations overlap",
    )
    static = case._parse(blobs[intent["static_pin_manifest_digest"]])
    legacy.prior._stage_pins(manifest, static["file_digests"])


def _prepare(store: CAS, selected_case: str, nonce: str) -> dict:
    source = _current_source()
    baseline = pins._read_fixed(_ROOT / pins._CAPTURE, pins._CAPTURE_PIN)
    image = pins._read_fixed(_ROOT / pins._IMAGE_RECORD, pins._IMAGE_PIN)
    static, provenance = pins.prepare_pin_documents(baseline, image)
    paths = (
        *case.CONTROLLER_SOURCE_PATHS,
        *case.LIVE_SOURCE_PATHS,
        *case.CASE_SOURCE_PATHS,
    )
    raws = {}
    for path in paths:
        row = _API._tree_file(source["commit"], Path(path))
        raws[path] = pins._read_fixed(_ROOT / path, (row["bytes"], row["digest"]))
    with TemporaryDirectory(prefix="aragorn-native-admission-prepare-") as temporary:
        staged = profile.stage_runtime_native_admission_profile(
            Path(temporary).resolve() / "stage"
        )
        gateway = "/usr/lib/systemd/system/aragorn-agent-gateway.service"
        # Preserve binary provenance and all other ten static pins.
        original_gateway_pin = static["file_digests"][gateway]
        static["file_digests"][gateway] = next(
            row["digest"] for row in staged["files"] if row["path"] == gateway
        )
        built = case.build_native_admission_case_intent(
            case_id=selected_case,
            nonce=nonce,
            source_record_raw=canonical_json(source),
            controller_source_raws={p: raws[p] for p in case.CONTROLLER_SOURCE_PATHS},
            live_source_raws={p: raws[p] for p in case.LIVE_SOURCE_PATHS},
            case_source_raws={p: raws[p] for p in case.CASE_SOURCE_PATHS},
            static_pin_manifest_raw=canonical_json(static),
            staged_profile=staged,
            baseline_capture_raw=baseline,
        )
        inspected = {
            "intent": case._parse(built["intent_raw"]),
            "input_blobs": built["input_blobs"],
        }
        _stage_guard(staged, inspected)
    _source_guard(inspected)
    intent_pin = built["intent_digest"]
    for pin, raw in built["input_blobs"].items():
        if pin != intent_pin:
            store.put_expected(BytesIO(raw), expected_digest=pin, max_bytes=len(raw))
    store.put_expected(
        BytesIO(built["intent_raw"]), expected_digest=intent_pin, max_bytes=16384
    )
    retained = _inspect(CAS(store.root, read_only=True), intent_pin)
    case._require(
        retained == inspected, "successor input closure changed during publication"
    )
    _source_guard(retained)
    return {
        "schema": "aragorn/native-admission-case-preparation/v1",
        "status": "PREPARED_EXPECTATIONS_ONLY",
        "intent_digest": intent_pin,
        "deployment_digest": retained["intent"]["deployment_digest"],
        "case_id": selected_case,
        "source_commit": source["commit"],
        "input_blobs": {pin: len(raw) for pin, raw in retained["input_blobs"].items()},
        "historical_static_pin_provenance": provenance,
        "successor_static_replacement": {
            "path": gateway,
            "before": original_gateway_pin,
            "after": static["file_digests"][gateway],
        },
        "limitations": [
            "HISTORICAL_EXPECTATIONS_NOT_FRESH_WRITER_OR_LIVE_IDENTITY",
            "SUCCESSOR_PROFILE_IS_INERT_STAGING_ONLY",
            "FOUR_FIXED_CASES_NOT_COMPLETE_ADMISSION_INVENTORY",
        ],
        **dict.fromkeys(_FALSE, False),
    }


def _bundle(inspected: dict, intent_pin: str) -> bytes:
    raw = canonical_json(
        {
            "schema": guest.BUNDLE_SCHEMA,
            "intent_digest": intent_pin,
            "blobs": {
                pin: raw.decode("utf-8")
                for pin, raw in inspected["input_blobs"].items()
            },
        }
    )
    case._require(len(raw) <= 2 * 1024 * 1024, "successor bundle exceeds bound")
    return raw


def _invoke(container: str, inspected: dict, intent_pin: str) -> dict:
    case._require(
        re.fullmatch(r"[0-9a-f]{64}", container) is not None,
        "invalid owned container identity",
    )
    raw = _bundle(inspected, intent_pin)
    pin = case._digest(raw)
    with TemporaryDirectory(prefix="aragorn-native-admission-input-") as temporary:
        path = Path(temporary) / "bundle.json"
        _API._write_output(path, raw)
        path.chmod(0o444)
        native.existing._docker("cp", str(path), container + ":" + guest.BUNDLE_PATH)
        native.existing._docker(
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "-c",
            _SEAL,
            pin,
            str(os.geteuid()),
            str(os.getegid()),
        )
    argv = [
        *_API._DOCKER,
        "exec",
        container,
        "/usr/bin/python3.12",
        "-I",
        "-S",
        "-B",
        _FILES[_GUEST],
        container,
        str(os.geteuid()),
        str(os.getegid()),
        pin,
        intent_pin,
    ]
    completed = subprocess.run(argv, capture_output=True, check=False, timeout=240)
    case._require(
        completed.returncode in (0, 126)
        and not completed.stderr
        and 0 < len(completed.stdout) <= _LIMIT,
        "successor guest returned no bounded envelope",
    )
    value = _API._load_json(completed.stdout, "native admission guest")
    case._require(
        type(value) is dict
        and completed.stdout == canonical_json(value) + b"\n"
        and value["schema"] == guest.SCHEMA
        and value["authority"] == guest.AUTHORITY
        and value["fixture_container"] == container
        and value["intent_digest"] == intent_pin
        and value["input_bundle_digest"] == pin
        and value["case_id"] == inspected["intent"]["case_id"]
        and value["branch"] == inspected["intent"]["branch"]
        and value["status"] == ("OBSERVED" if completed.returncode == 0 else "REFUSED")
        and all(value[key] is False for key in _FALSE),
        "successor guest envelope or proof ceiling changed",
    )
    return value


def _capture(store: CAS, intent_pin: str) -> dict:
    inspected = _inspect(CAS(store.root, read_only=True), intent_pin)
    case._require(
        inspected["intent"]["case_id"] in case.CASE_BRANCHES,
        "unsupported fixed successor case",
    )
    source = _source_guard(inspected)
    build = native._build_binding(source["commit"])
    helpers = {
        path: {
            **_API._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0444",
        }
        for path, target in _FILES.items()
    }
    # Keep the predecessor parent/runtime verification and cleanup primitives.
    parent = native.existing.campaign.current_v3_parent_identity()
    before = native.snapshot.snapshot_parent(parent)
    image = native._inspect("image", native._IMAGE)
    layers = before["image_inspect"]["RootFS"]["Layers"]
    case._require(
        image["Id"] == native._IMAGE
        and image["RootFS"]["Type"] == "layers"
        and image["RootFS"]["Layers"][: len(layers)] == layers
        and len(image["RootFS"]["Layers"]) > len(layers),
        "native image parent changed",
    )
    runtime_before = native._snapshot_runtime()
    owner = secrets.token_hex(32)
    name = "aragorn-native-admission-" + owner[:16]
    result = {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "status": "REFUSED",
        "intent_digest": intent_pin,
        "case_id": inspected["intent"]["case_id"],
        "source": source,
        "build_observation": build,
        "fixture_helpers": helpers,
        "fixture_image": image,
        "parent_identity": parent,
        "parent_before": before,
        "parent_after": None,
        "runtime_before": runtime_before,
        "runtime_after": None,
        "fixture_container": None,
        "container_inspect": None,
        "staged_profile": None,
        "plugin_input_bundle": None,
        "guest": None,
        "cleanup": None,
        "refusal": None,
        "fixture_creation_attempted": False,
        "postcondition_failures": [],
        "independent_capture_replay_complete": False,
        **dict.fromkeys(_FALSE, False),
    }
    phase = "STAGE"
    try:
        with TemporaryDirectory(
            prefix="aragorn-native-admission-capture-"
        ) as temporary:
            output = Path(temporary).resolve() / "stage"
            manifest = profile.stage_runtime_native_admission_profile(output)
            _stage_guard(manifest, inspected)
            result["staged_profile"] = manifest
            original, replacements = profile._verified_payloads()
            profile.base._audit_tree(output, original | replacements)
            payloads = {
                item["path"]: {
                    "installed_path": item["path"],
                    "installed_mode": item["mode"],
                    "bytes": item["bytes"],
                    "digest": item["digest"],
                }
                for item in manifest["files"]
            }
            inputs = None
            if inspected["intent"]["case_id"] == case.UPDATE_CASE:
                phase = "PLUGIN_INPUTS"
                inputs = Path(temporary).resolve() / _UPDATE.guest._STAGED.name
                inputs.mkdir(mode=0o755)
                # macOS can inherit /private/tmp's group instead of the
                # caller's effective group. Establish custody on this newly
                # owned directory before children are materialized; keep the
                # frozen bundle auditor's exact uid/gid requirement unchanged.
                os.chown(inputs, os.geteuid(), os.getegid(), follow_symlinks=False)
                result["plugin_input_bundle"] = _UPDATE.fixture.materialize(
                    inputs / "plugin-package-skill-replacement"
                )
                inputs.chmod(0o555)
                _UPDATE._audit_bundle(inputs, result["plugin_input_bundle"])
            phase = "OWNED_FIXTURE"
            result["fixture_creation_attempted"] = True
            try:
                container = (
                    native.existing._docker(
                        *native._create_arguments(name, owner, source["commit"])
                    )
                    .decode("ascii")
                    .strip()
                )
                case._require(
                    re.fullmatch(r"[0-9a-f]{64}", container) is not None,
                    "created container id changed",
                )
                result["fixture_container"] = container
                fixture = native._inspect("container", container)
                native._verify_fixture(
                    fixture, container, name, owner, source["commit"]
                )
                result["container_inspect"] = fixture
                native.existing._docker("cp", str(output) + "/.", container + ":/")
                profile.base._audit_tree(output, original | replacements)
                for path, target in _FILES.items():
                    native.existing._docker(
                        "cp", str(_ROOT / path), container + ":" + target
                    )
                if inputs is not None:
                    native.existing._docker(
                        "cp", str(inputs), container + ":/opt/aragorn/"
                    )
                    _UPDATE._audit_bundle(inputs, result["plugin_input_bundle"])
                native.existing._docker("start", container)
                native.existing._docker(
                    "exec",
                    container,
                    "/usr/bin/python3.12",
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    native._HEALTH_VERIFY,
                    json.dumps(payloads | helpers),
                    container,
                    json.dumps(manifest["directories"]),
                    json.dumps([os.geteuid(), os.getegid()]),
                )
                phase = "GUEST"
                _source_guard(inspected)
                result["guest"] = _invoke(container, inspected, intent_pin)
            finally:
                try:
                    result["cleanup"] = native.snapshot._cleanup_snapshot(
                        name, owner, native._IMAGE
                    )
                finally:
                    if inputs is not None:
                        try:
                            _UPDATE._audit_bundle(inputs, result["plugin_input_bundle"])
                        except Exception:
                            result["postcondition_failures"].append(
                                "PLUGIN_INPUT_READBACK_REFUSED"
                            )
            phase = "CLEANUP"
            case._require(
                result["cleanup"]["container_name_absent"] is True
                and result["cleanup"]["removed_id_absent"] is True,
                "owned fixture cleanup unconfirmed",
            )
        if result["guest"]["status"] == "OBSERVED":
            result["status"] = "OBSERVED"
    except Exception:
        # Retain every completed observation; never return an exception's input
        # values, and never call this effect again on a consumer/cleanup failure.
        result["refusal"] = {
            "phase": phase,
            "reason": "FIXED_SUCCESSOR_CAPTURE_REFUSED",
        }
    # Exceptions, including a guest timeout, must not skip these read-only
    # postconditions. Each is attempted once and retained independently.
    if result["fixture_creation_attempted"] and (
        type(result["cleanup"]) is not dict
        or result["cleanup"].get("container_name_absent") is not True
        or result["cleanup"].get("removed_id_absent") is not True
    ):
        result["postcondition_failures"].append("OWNED_CLEANUP_UNCONFIRMED")
    try:
        result["runtime_after"] = native._snapshot_runtime()
        case._require(
            runtime_before["volume_inspect"]
            == result["runtime_after"]["volume_inspect"],
            "native runtime changed",
        )
    except Exception:
        result["postcondition_failures"].append("RUNTIME_READBACK_REFUSED")
    try:
        result["parent_after"] = native.snapshot.snapshot_parent(parent)
        case._require(
            native.previous._parent_unchanged(before, result["parent_after"]),
            "pre-existing parent changed",
        )
    except Exception:
        result["postcondition_failures"].append("PARENT_READBACK_REFUSED")
    try:
        _source_guard(inspected)
    except Exception:
        result["postcondition_failures"].append("SOURCE_READBACK_REFUSED")
    try:
        case._require(
            _inspect(CAS(store.root, read_only=True), intent_pin) == inspected,
            "retained input closure changed",
        )
    except Exception:
        result["postcondition_failures"].append("INPUT_CLOSURE_READBACK_REFUSED")
    if result["postcondition_failures"]:
        result["status"] = "REFUSED"
    return result


def _verified_summary(value: object) -> dict:
    case._require(
        type(value) is dict
        and value.get("status") == "BOUNDED_CAPTURE_REPLAY_VERIFIED"
        and value.get("independent_capture_replay_complete") is True
        and all(value.get(key) is False for key in _FALSE),
        "independent capture replay result or proof ceiling changed",
    )
    return value


def _retain(store: CAS, value: dict) -> dict:
    readonly = CAS(store.root, read_only=True)
    inspected = _inspect(readonly, value["intent_digest"])
    prepared = (value.get("guest") or {}).get("prepared_case")
    if prepared is not None:
        request = canonical_json(prepared["request"])
        case._require(
            prepared["request"]["intent_digest"] == value["intent_digest"]
            and prepared["request"]["deployment_digest"]
            == inspected["intent"]["deployment_digest"],
            "retained request differs from intent",
        )
        store.put_expected(
            BytesIO(request),
            expected_digest=prepared["request_digest"],
            max_bytes=16384,
        )
        case._require(
            readonly.read(prepared["request_digest"], max_bytes=16384) == request,
            "retained request changed",
        )
    case._require(
        _inspect(readonly, value["intent_digest"]) == inspected,
        "retained input closure changed before capture publication",
    )
    raw = canonical_json(value) + b"\n"
    pin = store.put(BytesIO(raw), max_bytes=_LIMIT)
    case._require(
        readonly.read(pin, max_bytes=_LIMIT) == raw, "retained capture bytes changed"
    )
    summary = {
        "status": value["status"],
        "capture_digest": pin,
        "intent_digest": value["intent_digest"],
        "independent_capture_replay_complete": False,
        **dict.fromkeys(_FALSE, False),
    }
    if value["status"] == "OBSERVED":
        # The original capture remains immutable and makes no replay claim.
        # A verifier error must never cause another effect or erase that capture.
        try:
            verification = replay.verify_native_admission_capture(
                raw,
                expected_capture_digest=pin,
                expected_intent_digest=value["intent_digest"],
                evidence_cas=readonly,
            )
            _verified_summary(verification)
        except Exception:
            verification = {
                "schema": "aragorn/native-admission-capture-replay-refusal/v1",
                "status": "REFUSED",
                "reason": "INDEPENDENT_CAPTURE_REPLAY_REFUSED",
                "capture_digest": pin,
                "intent_digest": value["intent_digest"],
                "independent_capture_replay_complete": False,
                **dict.fromkeys(_FALSE, False),
            }
            summary["status"] = "REFUSED"
        else:
            summary["independent_capture_replay_complete"] = True
        verification_raw = canonical_json(verification)
        verification_pin = store.put(BytesIO(verification_raw), max_bytes=262144)
        case._require(
            readonly.read(verification_pin, max_bytes=262144) == verification_raw
            and readonly.read(pin, max_bytes=_LIMIT) == raw
            and _inspect(readonly, value["intent_digest"]) == inspected,
            "capture, verification or input closure changed after replay",
        )
        summary["verification_digest"] = verification_pin
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "inspect", "capture", "verify"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--cas", required=True, type=Path)
        if name == "prepare":
            command.add_argument(
                "--case-id", required=True, choices=tuple(case.CASE_BRANCHES)
            )
            command.add_argument("--nonce", required=True)
        else:
            command.add_argument("--expected-intent-digest", required=True)
        if name == "verify":
            command.add_argument("--expected-capture-digest", required=True)
        if name in ("prepare", "capture"):
            command.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        case._require(args.cas.is_absolute(), "CAS must be absolute")
        if args.command == "verify":
            readonly = CAS(args.cas, read_only=True)
            raw = readonly.read(
                case._pin(args.expected_capture_digest), max_bytes=_LIMIT
            )
            value = replay.verify_native_admission_capture(
                raw,
                expected_capture_digest=args.expected_capture_digest,
                expected_intent_digest=args.expected_intent_digest,
                evidence_cas=readonly,
            )
            _verified_summary(value)
        elif args.command == "inspect":
            inspected = _inspect(
                CAS(args.cas, read_only=True), args.expected_intent_digest
            )
            value = {
                "status": "INPUT_CLOSURE_VERIFIED",
                "intent": inspected["intent"],
                "blob_count": len(inspected["input_blobs"]),
                **dict.fromkeys(_FALSE, False),
            }
        else:
            legacy._preparation_destination(args.cas)
            legacy._preparation_destination(args.out)
            with (
                pins._parent(args.cas) as (_, cas_guard),
                pins._parent(args.out) as (parent, guard),
            ):
                pins._absent(parent, args.out.name)
                store = CAS(args.cas)
                value = (
                    _prepare(store, args.case_id, args.nonce)
                    if args.command == "prepare"
                    else _capture(store, args.expected_intent_digest)
                )
                cas_guard()
                guard()
                raw = canonical_json(value) + b"\n"
                pins._write_new(parent, args.out.name, raw)
                pins._read_fixed(args.out, (len(raw), case._digest(raw)))
                if args.command == "capture":
                    value = _retain(store, value)
                value = {
                    "status": value["status"],
                    "path": str(args.out),
                    "digest": case._digest(raw),
                    **{
                        key: value[key]
                        for key in (
                            "intent_digest",
                            "deployment_digest",
                            "capture_digest",
                            "verification_digest",
                            "independent_capture_replay_complete",
                        )
                        if key in value
                    },
                }
        print(json.dumps(value, sort_keys=True))
        return 2 if value["status"] == "REFUSED" else 0
    except Exception:
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "reason": "NATIVE_ADMISSION_PREREQUISITE_OR_EXECUTION_FAILED",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
