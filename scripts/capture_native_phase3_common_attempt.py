"""One owned common74 attempt capture, with public-only export and no retry.

Capture requires an already available VM. Unknown guest outcomes and incomplete
public exports preserve the exact owned fixture for evidence, never erase it.
"""

from __future__ import annotations

import argparse
from io import BytesIO
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_native_phase3_common_setup as base
from scripts import runtime_native_common_attempt_capture as guest
from scripts import materialize_runtime_native_blocked_create_driver as driver
from aragorn import native_phase3_common_attempt_inputs as inputs
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

native, legacy, pins, profile = base.native, base.legacy, base.pins, base.profile
_API = base._API
_FILES = inputs.FIXTURE_HELPERS
_ALIASES = inputs.HELPER_ALIASES
_SOURCE_PATHS = inputs.SOURCE_PATHS
_GUEST = inputs.WRAPPER_SOURCE
_SCHEMA = "aragorn/native-common-attempt-capture/v1"
_AUTHORITY = "OWNED_COMMON_ATTEMPT_CAPTURE_NOT_RUN_OR_PHASE3_QUALIFICATION"
_NAME_PREFIX = "aragorn-native-common-attempt-"
_BUNDLE_LIMIT = inputs.MAX_BUNDLE
_GUEST_LIMIT = guest.MAX_RESULT
_LIMIT = 144 * 1024 * 1024
_DEADLINE = 300
_FALSE = guest._FALSE
_require = base._require
_DRIVER_PATH = "/opt/aragorn/native-blocked-create-driver-v1.mjs"


def _inspect(store: CAS, pin: str) -> dict:
    raw = store.read(base.preparation.old._pin(pin), max_bytes=_BUNDLE_LIMIT)
    bound = inputs.inspect_common_attempt_inputs(raw, expected_bundle_digest=pin)
    for digest, content in bound["input_blobs"].items():
        _require(
            store.read(digest, max_bytes=_BUNDLE_LIMIT) == content,
            "attempt input closure changed",
        )
    return bound


def _source_guard(bound: dict) -> dict:
    source = base._current_source()
    _require(
        canonical_json(source) == bound["source_raw"], "signed source record changed"
    )
    _require(
        set(bound["source_raws"]) == set(_SOURCE_PATHS), "source inventory changed"
    )
    for path, raw in bound["source_raws"].items():
        row = _API._tree_file(source["commit"], Path(path))
        _require(
            row["digest"] == _API._digest(raw) and row["bytes"] == len(raw),
            "attempt source differs from signed tree",
        )
        legacy._source_bytes(_ROOT / path, raw)
    return source


def _prepare(store: CAS, setup_pin: str, plan_arguments: dict) -> dict:
    base_bound = base._inspect(CAS(store.root, read_only=True), setup_pin)
    source = base._source_guard(base_bound)
    sources = {}
    for path in inputs.EXTRA_SOURCE_PATHS:
        row = _API._tree_file(source["commit"], Path(path))
        sources[path] = pins._read_fixed(_ROOT / path, (row["bytes"], row["digest"]))
    built = inputs.prepare_common_attempt_inputs(
        setup_bundle_raw=base_bound["bundle_raw"],
        expected_setup_bundle_digest=setup_pin,
        plan_arguments=plan_arguments,
        source_raws=sources,
    )
    _source_guard(built)
    pin = built["bundle_digest"]
    for child_pin, raw in built["input_blobs"].items():
        if child_pin != pin:
            store.put_expected(
                BytesIO(raw), expected_digest=child_pin, max_bytes=_BUNDLE_LIMIT
            )
            _require(
                store.read(child_pin, max_bytes=_BUNDLE_LIMIT) == raw,
                "attempt preparation child changed",
            )
    store.put_expected(
        BytesIO(built["bundle_raw"]), expected_digest=pin, max_bytes=_BUNDLE_LIMIT
    )
    _require(
        _inspect(CAS(store.root, read_only=True), pin) == built,
        "retained attempt input differs",
    )
    _source_guard(built)
    return {
        "schema": "aragorn/native-common-attempt-input-preparation/v1",
        "authority": "SIGNED_PUBLIC_EXPECTATIONS_NOT_EXECUTION_OR_QUALIFICATION",
        "status": "PREPARED_EXPECTATIONS_ONLY",
        "input_bundle_digest": pin,
        "base_setup_bundle_digest": setup_pin,
        "source_commit": source["commit"],
        "input_blobs": {key: len(raw) for key, raw in built["input_blobs"].items()},
        **dict.fromkeys(inputs.FALSE_FLAGS, False),
    }


def _stage_guard(stage: dict, raw: bytes) -> None:
    base._stage_guard(stage, raw)
    targets = list(_FILES.values()) + list(_ALIASES) + [_DRIVER_PATH]
    _require(
        len(targets) == len(set(targets))
        and not set(targets).intersection(row["path"] for row in stage["files"])
        and all(source in _FILES for source in _ALIASES.values())
        and guest.BUNDLE_PATH == inputs.BUNDLE_PATH
        and guest.BUNDLE_PATH not in targets,
        "attempt helper, alias or stage collision",
    )


def _driver(output: Path) -> tuple[dict, Path, dict]:
    report = driver.materialize_runtime_native_blocked_create_driver(output)
    row = report["files"]
    _require(
        row
        == [
            {
                "name": driver._OUTPUT_NAME,
                "bytes": driver._OUTPUT[0],
                "digest": driver._OUTPUT[1],
                "mode": "0444",
            }
        ],
        "generated blocked driver differs",
    )
    path = output / driver._OUTPUT_NAME
    pins._read_fixed(path, driver._OUTPUT)
    metadata = {
        "installed_path": _DRIVER_PATH,
        "installed_mode": "0444",
        "bytes": driver._OUTPUT[0],
        "digest": driver._OUTPUT[1],
    }
    return report, path, metadata


def _seal_program() -> str:
    old = base.admission
    _require(
        old._SEAL.count(old.guest.BUNDLE_PATH) == 1
        and old._SEAL.count("2097152") == 2
        and old._SEAL.count("2097153") == 1,
        "fixed input seal changed",
    )
    return (
        old._SEAL.replace(old.guest.BUNDLE_PATH, guest.BUNDLE_PATH)
        .replace("2097152", str(_BUNDLE_LIMIT))
        .replace("2097153", str(_BUNDLE_LIMIT + 1))
    )


def _bounded_guest(
    argv: list[str], *, timeout: int = _DEADLINE, maximum: int = _GUEST_LIMIT
):
    """Drain only this one docker-exec client, bounded while running, never retry.

    Terminating the host client does not prove termination of a guest process.
    The caller preserves the owned fixture whenever this operation is uncertain.
    """
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
    )
    output, primary, failures = bytearray(), None, []
    try:
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                _require(remaining > 0, "attempt guest deadline exceeded")
                for key, _ in selector.select(remaining):
                    is_error = key.fileobj is child.stderr
                    chunk = os.read(
                        key.fileobj.fileno(),
                        1 if is_error else min(65536, maximum + 1 - len(output)),
                    )
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    _require(not is_error, "unexpected guest diagnostic output")
                    output.extend(chunk)
                    _require(
                        len(output) <= maximum, "attempt guest output bound exceeded"
                    )
        code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(argv, code, bytes(output), b"")
    except BaseException as error:
        primary = error
        # Never print arbitrary partial output: it is not classified public data.
        error._attempt_output_metadata = {
            "bytes": len(output),
            "digest": _API._digest(bytes(output)),
        }
        raise
    finally:
        terminate = primary is not None
        try:
            terminate = child.poll() is None or terminate
        except BaseException:
            terminate = True
            failures.append("HOST_GUEST_CLIENT_POLL_REFUSED")
        if terminate:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException:
                failures.append("HOST_GUEST_CLIENT_TERMINATION_REFUSED")
        for close in (
            child.stdout.close,
            child.stderr.close,
            lambda: child.wait(timeout=3),
        ):
            try:
                close()
            except BaseException:
                failures.append("HOST_GUEST_CLIENT_CLOSE_OR_REAP_REFUSED")
        if failures:
            if primary is None:
                primary = ValueError("host guest client cleanup refused")
                primary._attempt_output_metadata = {
                    "bytes": len(output),
                    "digest": _API._digest(bytes(output)),
                }
                primary._attempt_client_cleanup = failures
                raise primary
            primary._attempt_client_cleanup = failures


def _guest_output(completed, container: str, pin: str) -> dict:
    _require(
        completed.returncode in (0, 126, 130)
        and not completed.stderr
        and 0 < len(completed.stdout) <= _GUEST_LIMIT,
        "bounded guest envelope required",
    )
    value = _API._load_json(completed.stdout, "common attempt guest")
    fields = {
        "schema",
        "authority",
        "status",
        "container_id",
        "input_bundle_digest",
        "attempt",
        "public_blobs",
        "export_failures",
        "refusal",
        "input_bundle_readback",
        "controller_sources",
        "controller_sources_after",
        "postcondition_failures",
        "recovery",
        "public_export_complete",
        "preserve_fixture_for_evidence",
        "interrupted",
        "limitations",
        *_FALSE,
    }
    _require(
        type(value) is dict
        and set(value) == fields
        and canonical_json(value) + b"\n" == completed.stdout
        and value["schema"] == guest.SCHEMA
        and value["authority"] == guest.AUTHORITY
        and value["container_id"] == container
        and value["input_bundle_digest"] == pin
        and all(value[key] is False for key in _FALSE)
        and value["limitations"] == guest._LIMITATIONS,
        "guest identity, schema or ceilings changed",
    )
    _require(
        all(
            type(value[key]) is bool
            for key in (
                "public_export_complete",
                "preserve_fixture_for_evidence",
                "interrupted",
                "input_bundle_readback",
            )
        )
        and value["status"]
        == ("EXPORTED_BOUNDED_ATTEMPT" if completed.returncode == 0 else "REFUSED")
        and value["interrupted"] is (completed.returncode == 130),
        "guest status differs",
    )
    if completed.returncode == 0:
        _require(
            value["refusal"] is None
            and value["public_export_complete"] is True
            and value["preserve_fixture_for_evidence"] is False
            and value["input_bundle_readback"] is True
            and value["postcondition_failures"] == value["export_failures"] == []
            and value["controller_sources"] == value["controller_sources_after"],
            "successful guest has refused postconditions",
        )
    return value


def _invoke(container: str, raw: bytes, pin: str) -> dict:
    _require(
        re.fullmatch(r"[0-9a-f]{64}", container) is not None
        and 0 < len(raw) <= _BUNDLE_LIMIT
        and _API._digest(raw) == pin,
        "owned attempt input required",
    )
    with TemporaryDirectory(prefix="aragorn-common-attempt-input-") as directory:
        path = Path(directory).resolve() / "bundle.json"
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
            _seal_program(),
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
        pin,
    ]
    return _guest_output(_bounded_guest(argv), container, pin)


def _retain_guest_exports(store: CAS, result: dict, interrupts: list) -> None:
    value = result["guest"]
    attempt = value["attempt"]
    journal = [] if attempt is None else attempt["public_blob_attempts"]
    recovery = value["recovery"]["public_blob_attempts"]
    declared = {
        row["digest"]: row["bytes"] for row in guest._candidates(journal + recovery)
    }
    rows = value["public_blobs"]
    _require(
        type(rows) is list and len(rows) <= guest.MAX_PUBLIC_BLOBS,
        "guest public inventory bound changed",
    )
    seen, total = set(), 0
    for row in rows:
        pin = None
        try:
            _require(
                type(row) is dict
                and set(row) == {"digest", "bytes", "text"}
                and type(row["text"]) is str,
                "public record shape changed",
            )
            pin = base.preparation.old._pin(row["digest"])
            raw = row["text"].encode("utf-8")
            total += len(raw)
            _require(
                pin not in seen
                and type(row["bytes"]) is int
                and 0
                < len(raw)
                == row["bytes"]
                == declared.get(pin)
                <= guest.MAX_PUBLIC_BLOB
                and total <= guest.MAX_PUBLIC_TOTAL
                and _API._digest(raw) == pin,
                "public record differs from journal",
            )
            seen.add(pin)
            result["guest_publication"]["attempted"].append(pin)
            store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=guest.MAX_PUBLIC_BLOB
            )
            _require(
                store.read(pin, max_bytes=guest.MAX_PUBLIC_BLOB) == raw,
                "public child readback changed",
            )
            result["guest_publication"]["retained"].append(pin)
        except BaseException as error:
            if not isinstance(error, Exception) and not interrupts:
                interrupts.append(error)
            result["guest_publication"]["failed"].append(
                {"digest": pin, "reason": "PUBLIC_CHILD_PUBLICATION_REFUSED"}
            )
    publication = result["guest_publication"]
    publication["complete"] = bool(
        seen == set(declared)
        and set(publication["retained"]) == set(declared)
        and not publication["failed"]
        and value["export_failures"] == []
        and value["public_export_complete"] is True
    )


def _suspend_preserved(result: dict, interrupts: list) -> None:
    """Freeze only the exact owned container once, preserving its /run tmpfs.

    A host docker-exec client timeout cannot bound the guest by itself. Never
    stop/remove the container or retry a failed pause, and never unpause here.
    """
    container = result["fixture_container"]
    record = {
        "attempted": False,
        "before": None,
        "after": None,
        "paused": False,
        "failures": [],
    }
    result["preservation_suspension"] = record

    def inspected():
        command = _bounded_guest(
            [*_API._DOCKER, "inspect", "--type", "container", container],
            timeout=10,
            maximum=256 * 1024,
        )
        _require(
            command.returncode == 0 and not command.stderr, "preserved inspect refused"
        )
        values = json.loads(
            command.stdout, object_pairs_hook=_API.shared._no_duplicates
        )
        _require(
            type(values) is list and len(values) == 1 and type(values[0]) is dict,
            "preserved container inventory changed",
        )
        value = values[0]
        native._verify_fixture(
            value,
            container,
            result["fixture_name"],
            result["fixture_owner"],
            result["source"]["commit"],
        )
        return value

    try:
        _require(
            type(container) is str
            and re.fullmatch(r"[0-9a-f]{64}", container) is not None,
            "exact preserved fixture required",
        )
        record["before"] = inspected()
        state = record["before"]["State"]
        _require(
            state["Running"] is True and type(state["Paused"]) is bool,
            "preserved fixture is not running",
        )
        if state["Paused"] is not True:
            record["attempted"] = True
            command = _bounded_guest(
                [*_API._DOCKER, "pause", container], timeout=10, maximum=256
            )
            _require(
                command.returncode == 0
                and not command.stderr
                and command.stdout.decode("ascii").strip() == container,
                "owned fixture pause refused",
            )
    except BaseException as error:
        if not isinstance(error, Exception) and not interrupts:
            interrupts.append(error)
        record["failures"].append("OWNED_FIXTURE_PAUSE_REFUSED")
    finally:
        if (
            type(container) is str
            and re.fullmatch(r"[0-9a-f]{64}", container) is not None
        ):
            try:
                record["after"] = inspected()
                _require(
                    record["after"]["State"]["Running"] is True
                    and record["after"]["State"]["Paused"] is True,
                    "owned fixture suspension unconfirmed",
                )
                record["paused"] = True
            except BaseException as error:
                if not isinstance(error, Exception) and not interrupts:
                    interrupts.append(error)
                record["failures"].append("OWNED_FIXTURE_PAUSE_READBACK_REFUSED")
    if record["failures"] or record["paused"] is not True:
        result["cleanup_failure"] = "OWNED_FIXTURE_PRESERVATION_SUSPENSION_UNCONFIRMED"


def _capture(store: CAS, pin: str) -> dict:
    bound = _inspect(CAS(store.root, read_only=True), pin)
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
    aliases = {
        target: {
            **_API._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0444",
        }
        for target, path in _ALIASES.items()
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
        "fixture parent changed",
    )
    runtime = native._snapshot_runtime()
    owner = secrets.token_hex(32)
    name = _NAME_PREFIX + owner[:16]
    result = {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "status": "REFUSED",
        "input_bundle_digest": pin,
        "source": source,
        "build_observation": build,
        "fixture_helpers": helpers,
        "fixture_aliases": aliases,
        "fixture_image": image,
        "parent_identity": parent,
        "parent_before": before,
        "parent_after": None,
        "runtime_before": runtime,
        "runtime_after": None,
        "fixture_container": None,
        "fixture_name": name,
        "fixture_owner": owner,
        "container_inspect": None,
        "staged_profile": None,
        "generated_driver": None,
        "guest": None,
        "guest_recovery": None,
        "guest_publication": {
            "attempted": [],
            "retained": [],
            "failed": [],
            "complete": False,
        },
        "cleanup": None,
        "cleanup_failure": None,
        "refusal": None,
        "fixture_creation_attempted": False,
        "invocation_started": False,
        "fixture_preserved": False,
        "cleanup_deferred_reason": None,
        "preservation_suspension": None,
        "invocation_failure": None,
        "postcondition_failures": [],
        "independent_capture_replay_complete": False,
        **dict.fromkeys(_FALSE, False),
    }
    phase, interrupts = "STAGE", []

    def refused(error):
        result["status"] = "REFUSED"
        if not isinstance(error, Exception) and not interrupts:
            interrupts.append(error)
        if result["refusal"] is None:
            result["refusal"] = {
                "phase": phase,
                "reason": "COMMON_ATTEMPT_CAPTURE_REFUSED",
            }

    try:
        with TemporaryDirectory(prefix="aragorn-common-attempt-capture-") as directory:
            output = Path(directory).resolve() / "stage"
            stage = profile.stage_runtime_phase3_ingress_profile(output)
            _stage_guard(stage, bound["stage_raw"])
            result["staged_profile"] = stage
            original, replacements = profile._verified_payloads()
            profile.base._audit_tree(output, original | replacements)
            generated, driver_path, driver_metadata = _driver(
                Path(directory).resolve() / "driver"
            )
            result["generated_driver"] = generated
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
                    "owned container changed",
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
                for target, path in _ALIASES.items():
                    native.existing._docker(
                        "cp", str(_ROOT / path), container + ":" + target
                    )
                pins._read_fixed(driver_path, driver._OUTPUT)
                native.existing._docker(
                    "cp", str(driver_path), container + ":" + _DRIVER_PATH
                )
                pins._read_fixed(driver_path, driver._OUTPUT)
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
                    json.dumps(
                        payloads | helpers | aliases | {_DRIVER_PATH: driver_metadata}
                    ),
                    container,
                    json.dumps(stage["directories"]),
                    json.dumps([os.geteuid(), os.getegid()]),
                )
                phase = "GUEST"
                _source_guard(bound)
                result["invocation_started"] = True
                try:
                    result["guest"] = _invoke(container, bound["bundle_raw"], pin)
                except BaseException as error:
                    result["invocation_failure"] = {
                        "reason": "GUEST_OUTCOME_UNCAPTURED",
                        "output": getattr(error, "_attempt_output_metadata", None),
                        "client_cleanup_failures": getattr(
                            error, "_attempt_client_cleanup", []
                        ),
                    }
                    raise
                result["guest_recovery"] = result["guest"]["recovery"]
                phase = "PUBLIC_EXPORT_RETENTION"
                _retain_guest_exports(store, result, interrupts)
                _require(
                    result["guest_publication"]["complete"], "public exports incomplete"
                )
                if result["guest"]["status"] != "EXPORTED_BOUNDED_ATTEMPT":
                    result["refusal"] = {
                        "phase": "GUEST",
                        "reason": "COMMON_ATTEMPT_GUEST_REFUSED",
                    }
            except BaseException as error:
                refused(error)
            finally:
                value = result["guest"]
                preserve = result["invocation_started"] and (
                    value is None
                    or value["preserve_fixture_for_evidence"] is True
                    or not result["guest_publication"]["complete"]
                )
                if preserve:
                    result["fixture_preserved"] = True
                    result["cleanup_deferred_reason"] = (
                        "REQUIRED_PUBLIC_FAILURE_EVIDENCE_INCOMPLETE_NO_RETRY"
                    )
                    _suspend_preserved(result, interrupts)
                else:
                    try:
                        result["cleanup"] = native.snapshot._cleanup_snapshot(
                            name, owner, native._IMAGE
                        )
                        _require(
                            result["cleanup"]["container_name_absent"] is True
                            and result["cleanup"]["removed_id_absent"] is True,
                            "owned cleanup unconfirmed",
                        )
                    except BaseException as error:
                        if not isinstance(error, Exception) and not interrupts:
                            interrupts.append(error)
                        result["cleanup_failure"] = "OWNED_FIXTURE_CLEANUP_UNCONFIRMED"
            if (
                result["refusal"] is None
                and not result["cleanup_failure"]
                and not result["fixture_preserved"]
            ):
                result["status"] = "CAPTURED_BOUNDED_ATTEMPT"
    except BaseException as error:
        refused(error)
    if result["fixture_preserved"]:
        result["postcondition_failures"].append("OWNED_CLEANUP_DEFERRED_FOR_EVIDENCE")
    elif result["fixture_creation_attempted"] and (
        result["cleanup_failure"] or result["cleanup"] is None
    ):
        result["postcondition_failures"].append("OWNED_CLEANUP_UNCONFIRMED")
    for label, observe in (
        ("RUNTIME_READBACK_REFUSED", lambda: _runtime_after(result, runtime)),
        ("PARENT_READBACK_REFUSED", lambda: _parent_after(result, parent, before)),
        ("SOURCE_READBACK_REFUSED", lambda: _source_guard(bound)),
        (
            "INPUT_CLOSURE_READBACK_REFUSED",
            lambda: _require(
                _inspect(CAS(store.root, read_only=True), pin) == bound,
                "input closure changed",
            ),
        ),
    ):
        try:
            observe()
        except BaseException as error:
            if not isinstance(error, Exception) and not interrupts:
                interrupts.append(error)
            result["postcondition_failures"].append(label)
    if result["postcondition_failures"] or interrupts:
        result["status"] = "REFUSED"
    if interrupts:
        interrupts[0]._native_common_attempt_host_capture = result
        raise interrupts[0]
    return result


def _runtime_after(result, before):
    result["runtime_after"] = native._snapshot_runtime()
    _require(
        before["volume_inspect"] == result["runtime_after"]["volume_inspect"],
        "runtime changed",
    )


def _parent_after(result, parent, before):
    result["parent_after"] = native.snapshot.snapshot_parent(parent)
    _require(
        native.previous._parent_unchanged(before, result["parent_after"]),
        "frozen parent changed",
    )


def _verify(raw, pin, store):
    from aragorn.native_phase3_common_attempt_capture import (
        verify_native_common_attempt_capture,
    )

    result = verify_native_common_attempt_capture(
        raw, expected_capture_digest=pin, store=store
    )
    _require(
        type(result) is dict
        and result.get("status") == "BOUNDED_PUBLIC_ATTEMPT_CAPTURE_REPLAY_VERIFIED"
        and result.get("public_capture_joins_verified") is True
        and result.get("private_writer_semantics_replayed") is False
        and result.get("private_measurement_input_semantics_replayed") is False
        and result.get("independent_full_measurement_replay_complete") is False
        and all(result.get(key) is False for key in _FALSE),
        "independent public replay refused",
    )
    return result


def _retain(store, result):
    raw = canonical_json(result) + b"\n"
    _require(len(raw) <= _LIMIT, "host capture bound exceeded")
    pin = store.put(BytesIO(raw), max_bytes=_LIMIT)
    reader = CAS(store.root, read_only=True)
    _require(reader.read(pin, max_bytes=_LIMIT) == raw, "original capture changed")
    summary = {
        "status": result["status"],
        "capture_digest": pin,
        "input_bundle_digest": result["input_bundle_digest"],
        "fixture_preserved": result["fixture_preserved"],
        "fixture_container": result["fixture_container"],
        "public_capture_joins_verified": False,
        "independent_capture_replay_complete": False,
        **dict.fromkeys(_FALSE, False),
    }
    if result["status"] == "CAPTURED_BOUNDED_ATTEMPT":
        try:
            verification = _verify(raw, pin, reader)
            summary["public_capture_joins_verified"] = True
        except Exception:
            summary["status"] = "REFUSED"
            verification = {
                "schema": "aragorn/native-common-attempt-replay-refusal/v1",
                "status": "REFUSED",
                "capture_digest": pin,
                "reason": "INDEPENDENT_PUBLIC_ATTEMPT_REPLAY_REFUSED",
                "public_capture_joins_verified": False,
                "independent_capture_replay_complete": False,
                **dict.fromkeys(_FALSE, False),
            }
        verification_raw = canonical_json(verification)
        verification_pin = store.put(BytesIO(verification_raw), max_bytes=1024 * 1024)
        _require(
            reader.read(verification_pin, max_bytes=1024 * 1024) == verification_raw
            and reader.read(pin, max_bytes=_LIMIT) == raw,
            "replay publication changed",
        )
        summary["verification_digest"] = verification_pin
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "inspect", "capture", "verify"):
        command = commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--cas", required=True, type=Path)
        if name == "prepare":
            command.add_argument("--expected-setup-input-digest", required=True)
            command.add_argument("--plan-arguments", required=True, type=Path)
        elif name == "verify":
            command.add_argument("--expected-capture-digest", required=True)
        else:
            command.add_argument("--expected-input-digest", required=True)
        if name in ("prepare", "capture"):
            command.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        _require(args.cas.is_absolute(), "absolute CAS required")
        if args.command == "verify":
            reader = CAS(args.cas, read_only=True)
            raw = reader.read(
                base.preparation.old._pin(args.expected_capture_digest),
                max_bytes=_LIMIT,
            )
            result = _verify(raw, args.expected_capture_digest, reader)
        elif args.command == "inspect":
            bound = _inspect(CAS(args.cas, read_only=True), args.expected_input_digest)
            result = {
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
                interrupted = None
                if args.command == "prepare":
                    _require(
                        args.plan_arguments.is_absolute(), "absolute plan path required"
                    )
                    with args.plan_arguments.open("rb") as source:
                        raw = source.read(inputs.MAX_PLAN + 1)
                    _require(0 < len(raw) <= inputs.MAX_PLAN, "plan bound exceeded")
                    plan = _API._load_json(raw, "caller plan arguments")
                    result = _prepare(store, args.expected_setup_input_digest, plan)
                else:
                    try:
                        result = _capture(store, args.expected_input_digest)
                    except BaseException as error:
                        result = getattr(
                            error, "_native_common_attempt_host_capture", None
                        )
                        if result is None:
                            raise
                        interrupted = error
                cas_guard()
                out_guard()
                raw = canonical_json(result) + b"\n"
                _require(len(raw) <= _LIMIT, "output bound exceeded")
                pins._write_new(parent, args.out.name, raw)
                pins._read_fixed(args.out, (len(raw), _API._digest(raw)))
                if args.command == "capture":
                    result = _retain(store, result)
                if interrupted is not None:
                    print(json.dumps(result, sort_keys=True))
                    return 130
        print(json.dumps(result, sort_keys=True))
        return 2 if result["status"] == "REFUSED" else 0
    except Exception:
        print(
            json.dumps(
                {
                    "status": "REFUSED",
                    "reason": "COMMON_ATTEMPT_HOST_PREREQUISITE_OR_CAPTURE_FAILED",
                }
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
