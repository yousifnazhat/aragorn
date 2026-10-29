"""Capture one setup-only common74 fixture, never activate its runtime stack.

Preparation and replay are offline. Capture requires an already available owned
VM runtime, never starts that VM, and destroys only its exact disposable fixture.
The frozen admission controller and its report contract remain unchanged.
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

from scripts import capture_native_phase3_admission_case as admission
from scripts import prepare_native_plugin_update_identity_pins as pins
from scripts import runtime_native_common_case_setup as setup
from scripts import runtime_native_common_setup_capture as guest
from scripts import stage_runtime_phase3_ingress_profile as profile
from aragorn import native_phase3_common_preparation as preparation
from aragorn import native_phase3_common_setup_capture as contract
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

native = admission.native
legacy = admission.legacy
_API = native.acquisition
_HOST = "scripts/capture_native_phase3_common_setup.py"
_GUEST = "scripts/runtime_native_common_setup_capture.py"
_SETUP = "scripts/runtime_native_common_case_setup.py"
_CONSUMER = "src/aragorn/native_phase3_common_setup_capture.py"
_STAGER = "scripts/stage_runtime_phase3_ingress_profile.py"
_STAGE_OWNED = {
    "src/aragorn/phase3_deployment.py": "/usr/lib/aragorn/aragorn/phase3_deployment.py",
}
if any(
    admission._FILES.get(source) != target for source, target in _STAGE_OWNED.items()
):
    raise RuntimeError("fixed common stage/helper overlap changed")
_FILES = (
    {name: path for name, path in admission._FILES.items() if name not in _STAGE_OWNED}
    | setup._IMPLEMENTATION_PATHS
    | {
        _SETUP: setup.SETUP_PATH,
        _GUEST: "/opt/aragorn/runtime_native_common_setup_capture.py",
        "src/aragorn/runtime_broker_decision_measurement_verify.py": "/usr/lib/aragorn/aragorn/runtime_broker_decision_measurement_verify.py",
        _CONSUMER: "/usr/lib/aragorn/aragorn/native_phase3_common_setup_capture.py",
    }
)
_SOURCE_PATHS = tuple(sorted(set(_FILES) | {_HOST, _STAGER}))
_SCHEMA = "aragorn/native-common-setup-capture/v1"
_AUTHORITY = "OWNED_COMMON_SETUP_CAPTURE_NOT_ACTIVATION_OR_QUALIFICATION"
_NAME_PREFIX = "aragorn-native-common-setup-"
_BUNDLE_LIMIT = 8 * 1024 * 1024
_GUEST_LIMIT = 48 * 1024 * 1024
_LIMIT = 64 * 1024 * 1024
_FALSE = setup._FALSE


def _require(value: bool, reason: str) -> None:
    if not value:
        raise ValueError(reason)


def _current_source() -> dict:
    return legacy._current_source()


def _inspect(store: CAS, input_pin: str) -> dict:
    raw = store.read(preparation.old._pin(input_pin), max_bytes=_BUNDLE_LIMIT)
    bound = contract.inspect_common_setup_inputs(raw, expected_bundle_digest=input_pin)
    for pin, content in bound["input_blobs"].items():
        _require(
            store.read(pin, max_bytes=_BUNDLE_LIMIT) == content,
            "common input left retained custody",
        )
    _require(
        _FILES == contract.FIXTURE_HELPERS
        and set(_SOURCE_PATHS) == set(contract.SOURCE_PATHS),
        "host copy/source inventory differs from reviewed contract",
    )
    return bound


def _source_guard(bound: dict) -> dict:
    source = _current_source()
    _require(
        canonical_json(source) == bound["source_raw"], "signed source record changed"
    )
    _require(
        set(bound["source_raws"]) == set(_SOURCE_PATHS),
        "signed source inventory changed",
    )
    for path, raw in bound["source_raws"].items():
        row = _API._tree_file(source["commit"], Path(path))
        _require(
            row["digest"] == _API._digest(raw) and row["bytes"] == len(raw),
            "common source differs from signed tree",
        )
        legacy._source_bytes(_ROOT / path, raw)
    return source


def _prepare(store: CAS, case_id: str, nonce: str) -> dict:
    source = _current_source()
    baseline_raw = pins._read_fixed(_ROOT / pins._CAPTURE, pins._CAPTURE_PIN)
    image_raw = pins._read_fixed(_ROOT / pins._IMAGE_RECORD, pins._IMAGE_PIN)
    source_raws = {}
    for path in _SOURCE_PATHS:
        row = _API._tree_file(source["commit"], Path(path))
        source_raws[path] = pins._read_fixed(
            _ROOT / path, (row["bytes"], row["digest"])
        )
    with TemporaryDirectory(prefix="aragorn-common-setup-prepare-") as temporary:
        stage = profile.stage_runtime_phase3_ingress_profile(
            Path(temporary).resolve() / "stage"
        )
        stage_raw = canonical_json(stage)
        _stage_guard(stage, stage_raw)
        static, provenance = _static(stage, baseline_raw, image_raw)
        built = contract.prepare_common_setup_inputs(
            case_id=case_id,
            nonce=nonce,
            source_record_raw=canonical_json(source),
            implementation_source_raws={
                path: source_raws[path]
                for path in preparation.IMPLEMENTATION_SOURCE_PATHS
            },
            static_pin_manifest_raw=canonical_json(static),
            staged_profile_raw=stage_raw,
            baseline_capture_raw=baseline_raw,
            setup_source_raw=source_raws[_SETUP],
            wrapper_source_raw=source_raws[_GUEST],
            host_source_raw=source_raws[_HOST],
            source_raws=source_raws,
        )
    raw, pin = built["bundle_raw"], built["bundle_digest"]
    inspected = contract.inspect_common_setup_inputs(raw, expected_bundle_digest=pin)
    _source_guard(inspected)
    for child_pin, content in built["input_blobs"].items():
        if child_pin != pin:
            store.put_expected(
                BytesIO(content), expected_digest=child_pin, max_bytes=_BUNDLE_LIMIT
            )
            _require(
                store.read(child_pin, max_bytes=_BUNDLE_LIMIT) == content,
                "common input publication changed",
            )
    store.put_expected(BytesIO(raw), expected_digest=pin, max_bytes=_BUNDLE_LIMIT)
    _require(
        _inspect(CAS(store.root, read_only=True), pin) == inspected,
        "common retained preparation differs",
    )
    _source_guard(inspected)
    return {
        "schema": "aragorn/native-common-setup-input-preparation/v1",
        "authority": "SIGNED_SOURCE_AND_STAGED_INPUTS_NOT_EXECUTION_OR_ACTIVATION",
        "status": "PREPARED_EXPECTATIONS_ONLY",
        "input_bundle_digest": pin,
        "source_commit": source["commit"],
        "input_blobs": {key: len(value) for key, value in built["input_blobs"].items()},
        "static_pin_provenance": provenance,
        **dict.fromkeys(_FALSE, False),
    }


def _stage_guard(stage: dict, raw: bytes) -> None:
    _require(
        canonical_json(stage) == raw
        and (len(raw), _API._digest(raw)) == preparation.STAGED_PROFILE_PIN
        and stage["schema"] == preparation.STAGED_SCHEMA
        and tuple(
            len(stage[key])
            for key in ("files", "source_inputs", "new_dependencies", "directories")
        )
        == (74, 96, 30, 16),
        "common74 staged report changed",
    )
    destinations = {row["path"] for row in stage["files"]}
    _require(
        len(destinations) == 74
        and len(set(_FILES.values())) == len(_FILES)
        and not destinations.intersection(_FILES.values()),
        "common helper destinations overlap",
    )
    for source, target in _STAGE_OWNED.items():
        row = next(row for row in stage["files"] if row["path"] == target)
        _require(
            row["source_name"] == source and row["mode"] == "0644",
            "stage-owned former helper changed",
        )


def _static(stage: dict, baseline_raw: bytes, image_raw: bytes) -> tuple[dict, dict]:
    historical, provenance = pins.prepare_pin_documents(baseline_raw, image_raw)
    rows = {row["path"]: row for row in stage["files"]}
    binary_paths = {
        preparation.old.live._ENTRY,
        preparation.old.live._PYTHON,
        preparation.old.live._NODE,
    }
    value = {
        "schema": preparation.STATIC_SCHEMA,
        "file_digests": {
            path: historical["file_digests"][path]
            if path in binary_paths
            else rows[path]["digest"]
            for path in preparation.STATIC_PATHS
        },
    }
    baseline, _ = preparation.admission._baseline(baseline_raw)
    preparation._static(canonical_json(value), stage, baseline)
    return value, provenance


def _seal_program() -> str:
    """Reuse only the exact bounded input handoff, not an old report or route."""
    old = admission.guest.BUNDLE_PATH
    _require(admission._SEAL.count(old) == 1, "input handoff anchor changed")
    _require(
        admission._SEAL.count("2097152") == 2 and admission._SEAL.count("2097153") == 1,
        "input handoff size anchors changed",
    )
    return (
        admission._SEAL.replace(old, guest.BUNDLE_PATH)
        .replace("2097152", str(_BUNDLE_LIMIT))
        .replace("2097153", str(_BUNDLE_LIMIT + 1))
    )


def _guest_output(completed, container: str, input_pin: str) -> dict:
    _require(
        completed.returncode in (0, 126)
        and not completed.stderr
        and 0 < len(completed.stdout) <= _GUEST_LIMIT,
        "common setup guest returned no bounded envelope",
    )
    value = _API._load_json(completed.stdout, "common setup guest")
    _require(
        type(value) is dict and completed.stdout == canonical_json(value) + b"\n",
        "noncanonical common setup guest",
    )
    _require(
        set(value)
        == {
            "schema",
            "authority",
            "status",
            "container_id",
            "input_bundle_digest",
            "setup",
            "public_blobs",
            "export_failures",
            "refusal",
            "input_bundle_readback",
            "controller_sources",
            "controller_sources_after",
            "postcondition_failures",
            "limitations",
            *_FALSE,
        }
        and value["schema"] == guest.SCHEMA
        and value["authority"] == guest.AUTHORITY
        and value["container_id"] == container
        and value["input_bundle_digest"] == input_pin
        and all(value[key] is False for key in _FALSE),
        "common setup guest identity or ceilings changed",
    )
    _require(
        value["status"]
        == ("PREPARED_NOT_ACTIVATED" if completed.returncode == 0 else "REFUSED"),
        "common setup guest return code differs",
    )
    _require(
        completed.returncode != 0
        or (
            value["refusal"] is None
            and value["input_bundle_readback"] is True
            and value["postcondition_failures"] == []
            and value["export_failures"] == []
            and value["controller_sources"] == value["controller_sources_after"]
        ),
        "successful guest has refused postconditions",
    )
    return value


def _invoke(container: str, input_raw: bytes, input_pin: str) -> dict:
    _require(
        re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and 0 < len(input_raw) <= _BUNDLE_LIMIT
        and _API._digest(input_raw) == input_pin,
        "invalid owned common input",
    )
    with TemporaryDirectory(prefix="aragorn-common-setup-input-") as temporary:
        path = Path(temporary).resolve() / "bundle.json"
        _API._write_output(path, input_raw)
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
            _seal_program(),
            input_pin,
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
        input_pin,
    ]
    completed = subprocess.run(argv, capture_output=True, check=False, timeout=240)
    return _guest_output(completed, container, input_pin)


def _retain_guest_exports(store: CAS, result: dict) -> None:
    guest_result = result["guest"]
    rows = guest_result["public_blobs"]
    setup_result = guest_result["setup"]
    journal = [] if setup_result is None else setup_result["public_blob_attempts"]
    _require(
        type(rows) is list
        and len(rows) <= 32
        and type(journal) is list
        and len(journal) <= 32,
        "public export inventory exceeds bound",
    )
    declared = {}
    for row in journal:
        _require(
            type(row) is dict
            and set(row) == {"digest", "bytes"}
            and type(row["bytes"]) is int
            and 0 < row["bytes"] <= 1024 * 1024
            and row["digest"] not in declared,
            "public journal changed",
        )
        declared[preparation.old._pin(row["digest"])] = row["bytes"]
    total = 0
    seen = set()
    for row in rows:
        _require(
            type(row) is dict
            and set(row) == {"digest", "bytes", "text"}
            and type(row["text"]) is str,
            "public export shape changed",
        )
        raw = row["text"].encode("utf-8")
        pin = preparation.old._pin(row["digest"])
        total += len(raw)
        _require(
            pin not in seen
            and type(row["bytes"]) is int
            and 0 < len(raw) == row["bytes"] == declared.get(pin) <= 1024 * 1024
            and total <= _BUNDLE_LIMIT
            and _API._digest(raw) == pin,
            "public export differs from journal or digest",
        )
        seen.add(pin)
        result["guest_publication"]["attempted"].append(pin)
        store.put_expected(BytesIO(raw), expected_digest=pin, max_bytes=1024 * 1024)
        _require(
            store.read(pin, max_bytes=1024 * 1024) == raw,
            "public export readback changed",
        )
        result["guest_publication"]["retained"].append(pin)
    result["guest_publication"]["complete"] = (
        seen == set(declared) and guest_result["export_failures"] == []
    )
    if guest_result["status"] == "PREPARED_NOT_ACTIVATED":
        _require(
            result["guest_publication"]["complete"]
            and type(setup_result) is dict
            and setup_result["status"] == "PREPARED_NOT_ACTIVATED"
            and type(setup_result["preparation"]) is dict
            and type(setup_result["preparation"]["retained_blob_digests"]) is list
            and len(setup_result["preparation"]["retained_blob_digests"])
            == len(declared)
            and set(setup_result["preparation"]["retained_blob_digests"])
            == set(declared),
            "successful setup omitted journaled public evidence",
        )


def _capture(store: CAS, input_pin: str) -> dict:
    bound = _inspect(CAS(store.root, read_only=True), input_pin)
    source = _source_guard(bound)
    build = native._build_binding(source["commit"])
    helpers = {
        path: {
            **_API._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0444",
        }
        for path, target in _FILES.items()
    }
    parent = native.existing.campaign.current_v3_parent_identity()
    before = native.snapshot.snapshot_parent(parent)
    image = native._inspect("image", native._IMAGE)
    layers = before["image_inspect"]["RootFS"]["Layers"]
    _require(
        image["Id"] == native._IMAGE
        and image["RootFS"]["Type"] == "layers"
        and image["RootFS"]["Layers"][: len(layers)] == layers
        and len(image["RootFS"]["Layers"]) > len(layers),
        "common fixture parent changed",
    )
    runtime_before = native._snapshot_runtime()
    owner = secrets.token_hex(32)
    name = _NAME_PREFIX + owner[:16]
    result = {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "status": "REFUSED",
        "input_bundle_digest": input_pin,
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
        "guest": None,
        "guest_publication": {"attempted": [], "retained": [], "complete": False},
        "cleanup": None,
        "cleanup_failure": None,
        "refusal": None,
        "fixture_creation_attempted": False,
        "postcondition_failures": [],
        "independent_capture_replay_complete": False,
        **dict.fromkeys(_FALSE, False),
    }
    phase = "STAGE"
    try:
        with TemporaryDirectory(prefix="aragorn-common-setup-capture-") as temporary:
            output = Path(temporary).resolve() / "stage"
            stage = profile.stage_runtime_phase3_ingress_profile(output)
            _stage_guard(stage, bound["stage_raw"])
            result["staged_profile"] = stage
            original, replacements = profile._verified_payloads()
            profile.base._audit_tree(output, original | replacements)
            payloads = {
                row["path"]: {
                    "installed_path": row["path"],
                    "installed_mode": row["mode"],
                    "bytes": row["bytes"],
                    "digest": row["digest"],
                }
                for row in stage["files"]
            }
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
                _require(
                    re.fullmatch(r"[0-9a-f]{64}", container) is not None,
                    "created common container changed",
                )
                result["fixture_container"] = container
                fixture = native._inspect("container", container)
                native._verify_fixture(
                    fixture, container, name, owner, source["commit"]
                )
                result["container_inspect"] = fixture
                native.existing._docker("cp", str(output) + "/.", container + ":/")
                profile.base._audit_tree(output, original | replacements)
                _source_guard(bound)
                for path, target in _FILES.items():
                    native.existing._docker(
                        "cp", str(_ROOT / path), container + ":" + target
                    )
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
                    json.dumps(stage["directories"]),
                    json.dumps([os.geteuid(), os.getegid()]),
                )
                phase = "GUEST"
                _source_guard(bound)
                result["guest"] = _invoke(container, bound["bundle_raw"], input_pin)
                phase = "PUBLIC_EXPORT_RETENTION"
                _retain_guest_exports(store, result)
            except BaseException:
                result["refusal"] = {
                    "phase": phase,
                    "reason": "COMMON_SETUP_CAPTURE_REFUSED",
                }
            finally:
                try:
                    result["cleanup"] = native.snapshot._cleanup_snapshot(
                        name, owner, native._IMAGE
                    )
                    _require(
                        result["cleanup"]["container_name_absent"] is True
                        and result["cleanup"]["removed_id_absent"] is True,
                        "common fixture cleanup unconfirmed",
                    )
                except BaseException:
                    result["cleanup_failure"] = "OWNED_FIXTURE_CLEANUP_UNCONFIRMED"
            if (
                result["refusal"] is None
                and result["cleanup_failure"] is None
                and result["guest"]["status"] == "PREPARED_NOT_ACTIVATED"
                and result["guest_publication"]["complete"] is True
            ):
                result["status"] = "PREPARED_NOT_ACTIVATED"
    except BaseException:
        if result["refusal"] is None:
            result["refusal"] = {
                "phase": phase,
                "reason": "COMMON_SETUP_CAPTURE_REFUSED",
            }
    # Every read-only postcondition is independent. No failed effect/export is
    # attempted again here or by the final capture publisher.
    if result["fixture_creation_attempted"] and (
        result["cleanup_failure"] is not None
        or type(result["cleanup"]) is not dict
        or result["cleanup"].get("container_name_absent") is not True
        or result["cleanup"].get("removed_id_absent") is not True
    ):
        result["postcondition_failures"].append("OWNED_CLEANUP_UNCONFIRMED")
    try:
        result["runtime_after"] = native._snapshot_runtime()
        _require(
            runtime_before["volume_inspect"]
            == result["runtime_after"]["volume_inspect"],
            "common runtime changed",
        )
    except BaseException:
        result["postcondition_failures"].append("RUNTIME_READBACK_REFUSED")
    try:
        result["parent_after"] = native.snapshot.snapshot_parent(parent)
        _require(
            native.previous._parent_unchanged(before, result["parent_after"]),
            "frozen parent changed",
        )
    except BaseException:
        result["postcondition_failures"].append("PARENT_READBACK_REFUSED")
    try:
        _source_guard(bound)
    except BaseException:
        result["postcondition_failures"].append("SOURCE_READBACK_REFUSED")
    try:
        _require(
            _inspect(CAS(store.root, read_only=True), input_pin) == bound,
            "input closure changed",
        )
    except BaseException:
        result["postcondition_failures"].append("INPUT_CLOSURE_READBACK_REFUSED")
    if result["postcondition_failures"]:
        result["status"] = "REFUSED"
    return result


def _verified_summary(value: dict) -> dict:
    _require(
        type(value) is dict
        and value.get("status") == "BOUNDED_PUBLIC_SETUP_REPLAY_VERIFIED"
        and value.get("independent_capture_replay_complete") is True
        and value.get("private_writer_semantics_replayed") is False
        and all(value.get(key) is False for key in _FALSE),
        "public replay status or proof ceiling changed",
    )
    return value


def _retain(store: CAS, result: dict) -> dict:
    """Publish the original capture once; never retry an earlier child export."""
    raw = canonical_json(result) + b"\n"
    _require(len(raw) <= _LIMIT, "common capture exceeds bound")
    pin = store.put(BytesIO(raw), max_bytes=_LIMIT)
    readonly = CAS(store.root, read_only=True)
    _require(
        readonly.read(pin, max_bytes=_LIMIT) == raw, "common capture readback changed"
    )
    summary = {
        "status": result["status"],
        "capture_digest": pin,
        "input_bundle_digest": result["input_bundle_digest"],
        "independent_capture_replay_complete": False,
        **dict.fromkeys(_FALSE, False),
    }
    if result["status"] == "PREPARED_NOT_ACTIVATED":
        try:
            verification = contract.verify_native_common_setup_capture(
                raw, expected_capture_digest=pin, store=readonly
            )
            _verified_summary(verification)
        except BaseException:
            summary["status"] = "REFUSED"
            verification = {
                "schema": "aragorn/native-common-setup-replay-refusal/v1",
                "status": "REFUSED",
                "reason": "INDEPENDENT_PUBLIC_SETUP_REPLAY_REFUSED",
                "capture_digest": pin,
                "independent_capture_replay_complete": False,
                "private_writer_semantics_replayed": False,
                **dict.fromkeys(_FALSE, False),
            }
        else:
            summary["independent_capture_replay_complete"] = True
        verification_raw = canonical_json(verification)
        verification_pin = store.put(BytesIO(verification_raw), max_bytes=1024 * 1024)
        _require(
            readonly.read(verification_pin, max_bytes=1024 * 1024) == verification_raw
            and readonly.read(pin, max_bytes=_LIMIT) == raw,
            "common replay or original capture changed",
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
                "--case-id", required=True, choices=tuple(preparation.CASE_BRANCHES)
            )
            command.add_argument("--nonce", required=True)
        elif name == "verify":
            command.add_argument("--expected-capture-digest", required=True)
        else:
            command.add_argument("--expected-input-digest", required=True)
        if name in ("prepare", "capture"):
            command.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        _require(args.cas.is_absolute(), "CAS must be absolute")
        if args.command == "verify":
            readonly = CAS(args.cas, read_only=True)
            raw = readonly.read(
                preparation.old._pin(args.expected_capture_digest), max_bytes=_LIMIT
            )
            value = _verified_summary(
                contract.verify_native_common_setup_capture(
                    raw,
                    expected_capture_digest=args.expected_capture_digest,
                    store=readonly,
                )
            )
        elif args.command == "inspect":
            bound = _inspect(CAS(args.cas, read_only=True), args.expected_input_digest)
            value = {
                "status": "INPUT_CLOSURE_VERIFIED",
                "input_bundle_digest": args.expected_input_digest,
                "input_blob_count": len(bound["input_blobs"]),
                **dict.fromkeys(_FALSE, False),
            }
        else:
            legacy._preparation_destination(args.cas)
            legacy._preparation_destination(args.out)
            with (
                pins._parent(args.cas) as (_, cas_guard),
                pins._parent(args.out) as (parent, out_guard),
            ):
                pins._absent(parent, args.out.name)
                store = CAS(args.cas)
                value = (
                    _prepare(store, args.case_id, args.nonce)
                    if args.command == "prepare"
                    else _capture(store, args.expected_input_digest)
                )
                cas_guard()
                out_guard()
                raw = canonical_json(value) + b"\n"
                _require(len(raw) <= _LIMIT, "capture output exceeds bound")
                pins._write_new(parent, args.out.name, raw)
                pins._read_fixed(args.out, (len(raw), _API._digest(raw)))
                if args.command == "capture":
                    value = _retain(store, value)
                value = {
                    "status": value["status"],
                    "path": str(args.out),
                    "digest": _API._digest(raw),
                    **{
                        key: value[key]
                        for key in (
                            "input_bundle_digest",
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
                    "reason": "COMMON_SETUP_PREREQUISITE_OR_CAPTURE_FAILED",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
