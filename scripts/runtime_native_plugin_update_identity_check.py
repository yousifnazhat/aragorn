"""Bracket one existing native update adapter with direct live identity reads.

The inherited owned fixture still provisions, activates, invokes and cleans up
once. Expected dynamic hashes come from its writer inputs before activation,
not from the new reader or filesystem readback. Static hashes are host-held.
No original capture, profile, provisioning implementation or effect is replayed.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

if __package__:
    from scripts import runtime_native_plugin_update_check as update
else:
    sys.path[:0] = ["/usr/lib/aragorn", str(Path(__file__).resolve().parent)]
    import runtime_native_plugin_update_check as update

from aragorn import native_phase3_live_identity as identity
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/runtime-native-plugin-update-identity-observation/v1"
AUTHORITY = (
    "OWNED_UPDATE_ADAPTER_WITH_LOCAL_LIVE_IDENTITY_NOT_ROUTE_OR_RUN_QUALIFICATION"
)
STATIC_SCHEMA = "aragorn/native-plugin-update-identity-static-pins/v1"
STATIC_MANIFEST = Path("/opt/aragorn/native-plugin-update-identity-pins.json")
PROVISIONING_ORIGIN = "EXACT_EXISTING_WRITER_INPUT_BYTES_BEFORE_ACTIVATION"
DYNAMIC_PATHS = (
    identity._CONFIG,
    identity._WORKER,
    identity._RUNTIME,
    identity._OBSERVATION,
    identity._GRANT,
    identity._GENESIS,
    identity._POLICY,
)
STATIC_PATHS = tuple(sorted(set(identity.FILE_PATHS) - set(DYNAMIC_PATHS)))
LIMITATIONS = (
    "BEFORE_AFTER_UPDATE_ADAPTER_NOT_EACH_INTERNAL_COMMAND",
    "WRITER_INPUT_PINS_NOT_INDEPENDENT_HOST_ATTESTATION",
    "LOCAL_NATIVE_IDENTITY_LIMITATIONS_REMAIN",
    "NO_ROUTE_RUN_OR_PHASE3_QUALIFICATION",
)
_FALSE_FLAGS = (
    "route_qualified",
    "phase3_eligible",
    "run_conformance_eligible",
    "production_activation_eligible",
    "common_deployment_fully_verified",
    "live_deployment_attested",
)
_STAMPS = (
    "before_read_started_ns",
    "before_read_finished_ns",
    "invocation_started_ns",
    "invocation_finished_ns",
    "after_read_started_ns",
    "after_read_finished_ns",
)
_UPDATE_PIN = (
    11677,
    "sha256:41d51b170733a0443f601f7d28b5534d2316decaab892ae16ba5ec25c2512ef0",
)


class NativeIdentityGuestError(ValueError):
    """A fixed wrapper invariant failed; never carries credentials or diagnostics."""


def _require(value: bool, message: str) -> None:
    if not value:
        raise NativeIdentityGuestError(message)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "INVALID_CALLER_PIN",
    )
    return value


def _pairs(items):
    result = dict(items)
    _require(len(result) == len(items), "DUPLICATE_MANIFEST_KEY")
    return result


def _parse_static_manifest(raw: bytes, expected_digest: str) -> dict:
    _require(
        type(raw) is bytes
        and 0 < len(raw) <= 16384
        and _digest(raw) == _pin(expected_digest),
        "STATIC_MANIFEST_PIN_MISMATCH",
    )
    value = json.loads(raw, object_pairs_hook=_pairs)
    _require(
        type(value) is dict
        and set(value) == {"schema", "file_digests"}
        and value["schema"] == STATIC_SCHEMA
        and canonical_json(value) == raw
        and type(value["file_digests"]) is dict
        and set(value["file_digests"]) == set(STATIC_PATHS),
        "STATIC_MANIFEST_CONTRACT_CHANGED",
    )
    for digest in value["file_digests"].values():
        _pin(digest)
    return value


def _static_manifest(expected_digest: str) -> dict:
    _require(sys.platform == "linux" and os.geteuid() == 0, "LINUX_ROOT_REQUIRED")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw, _ = identity._read_at(
            fd, str(STATIC_MANIFEST), owner=0, modes={0o444}, limit=16384
        )
    finally:
        os.close(fd)
    return _parse_static_manifest(raw, expected_digest)


def _verify_predecessor() -> None:
    with Path(update.__file__).open("rb") as stream:
        raw = stream.read(_UPDATE_PIN[0] + 1)
    _require((len(raw), _digest(raw)) == _UPDATE_PIN, "UPDATE_PREDECESSOR_CHANGED")


def _refusal_location(error: Exception) -> dict:
    """Only exact installed source locations, including bounded explicit causes.

    Reader errors deliberately hide their messages. Preserve enough fixed code
    locations to diagnose a one-shot refusal without exposing inputs or locals.
    """
    sources = {
        __file__: "scripts/runtime_native_plugin_update_identity_check.py",
        identity.__file__: "src/aragorn/native_phase3_live_identity.py",
    }
    frames, seen = [], set()
    current = error
    for _ in range(4):
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        trace = current.__traceback__
        while trace is not None:
            code = trace.tb_frame.f_code
            source = sources.get(code.co_filename)
            if source is not None and re.fullmatch(
                r"[A-Za-z_][A-Za-z_0-9]{0,127}", code.co_name
            ):
                frames.append(
                    {
                        "source": source,
                        "line": trace.tb_lineno,
                        "function": code.co_name,
                    }
                )
            trace = trace.tb_next
        current = current.__cause__
    return {
        "schema": "aragorn/native-identity-guest-refusal-location/v1",
        "source_frames": frames[-8:],
        "exception_text_retained": False,
        "locals_retained": False,
        "retry_performed": False,
    }


def _p37b():
    # Already imported by the inherited package runner before native._prepare.
    return importlib.import_module("runtime_action_worker_openclaw_systemd_probe")


def _run(
    container: str,
    copied_owner: tuple[int, int],
    expected_static_manifest_digest: str,
    *,
    before_activation=None,
) -> dict:
    """Run once; an optional trusted internal hook may commit frozen writer inputs.

    The hook is not configurable through the CLI. Its detached mapping is cleared
    on return or refusal; without a hook, raw provisioning inputs are not retained.
    """
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "route_id": update._ROUTE,
        "branch": "TRACKED_LOCAL_MARKETPLACE_DIRECTORY_UPDATE",
        "fixture_container": container,
        "static_pin_manifest": None,
        "static_pin_manifest_digest": expected_static_manifest_digest,
        "expected_file_digests": {},
        "provisioning_file_digests": {},
        "provisioning_origin": PROVISIONING_ORIGIN,
        "pins_frozen_before_activation": False,
        "activation_count": 0,
        "invocation_count": 0,
        "before": None,
        "after": None,
        "comparison": None,
        "boundaries_monotonic_ns": dict.fromkeys(_STAMPS),
        "update_observation": None,
        "refusal": None,
        "limitations": list(LIMITATIONS),
        **dict.fromkeys(_FALSE_FLAGS, False),
    }
    phase = "PIN_INPUT"
    original_native, original_invoke = update.prior._native, update._invoke
    loaded = False
    provisioning_inputs = {} if before_activation is not None else None

    def record(path: str, raw: bytes) -> None:
        if path not in DYNAMIC_PATHS:
            return
        _require(not result["pins_frozen_before_activation"], "WRITE_AFTER_PIN_FREEZE")
        _require(
            type(raw) is bytes and 0 < len(raw) <= 2 * 1024 * 1024,
            "UNBOUNDED_WRITER_INPUT",
        )
        _require(
            path not in result["provisioning_file_digests"],
            "DUPLICATE_PROVISIONING_WRITE",
        )
        result["provisioning_file_digests"][path] = _digest(raw)
        if provisioning_inputs is not None:
            provisioning_inputs[path] = raw

    def invoke(p37b, gateway_pid, token):
        nonlocal phase
        _require(
            result["pins_frozen_before_activation"]
            and result["activation_count"] == 1
            and result["invocation_count"] == 0,
            "INVOCATION_ORDER_CHANGED",
        )
        arguments = {
            "expected_container_id": container,
            "expected_file_digests": dict(result["expected_file_digests"]),
        }
        stamps = result["boundaries_monotonic_ns"]
        phase = "BEFORE_READ"
        stamps["before_read_started_ns"] = time.monotonic_ns()
        result["before"] = identity.read_native_live_identity(**arguments)
        stamps["before_read_finished_ns"] = time.monotonic_ns()
        _require(
            result["before"]["processes"]["gateway"]["pid"] == gateway_pid,
            "INVOKED_GATEWAY_DIFFERS_FROM_LIVE_READ",
        )
        phase = "INVOCATION"
        result["invocation_count"] += 1
        stamps["invocation_started_ns"] = time.monotonic_ns()
        try:
            observation = original_invoke(p37b, gateway_pid, token)
        finally:
            stamps["invocation_finished_ns"] = time.monotonic_ns()
        phase = "AFTER_READ"
        stamps["after_read_started_ns"] = time.monotonic_ns()
        result["after"] = identity.read_native_live_identity(**arguments)
        stamps["after_read_finished_ns"] = time.monotonic_ns()
        phase = "COMPARE"
        result["comparison"] = identity.compare_native_live_identity(
            result["before"], result["after"]
        )
        phase = "PREDECESSOR_FINALIZATION"
        return observation

    try:
        _require(
            before_activation is None or callable(before_activation),
            "INVALID_TRUSTED_PREACTIVATION_CALLBACK",
        )
        _require(
            type(container) is str
            and re.fullmatch(r"[0-9a-f]{64}", container) is not None
            and type(copied_owner) is tuple
            and len(copied_owner) == 2
            and all(
                type(item) is int and 0 <= item <= 2**32 - 1 for item in copied_owner
            ),
            "INVALID_OWNED_FIXTURE_ARGUMENTS",
        )
        _verify_predecessor()
        manifest = _static_manifest(expected_static_manifest_digest)
        result["static_pin_manifest"] = manifest
        with ExitStack() as patches:

            def native_factory():
                nonlocal loaded
                _require(not loaded, "MULTIPLE_NATIVE_FIXTURES_FORBIDDEN")
                loaded = True
                native = original_native()
                prepare, activate = native._prepare, native._activate

                def freeze_then_activate(*args, **kwargs):
                    nonlocal phase
                    phase = "ACTIVATION"
                    _require(
                        not result["pins_frozen_before_activation"]
                        and result["activation_count"] == 0
                        and set(result["provisioning_file_digests"])
                        == set(DYNAMIC_PATHS),
                        "PREACTIVATION_PIN_INVENTORY_INCOMPLETE",
                    )
                    expected = {
                        **manifest["file_digests"],
                        **result["provisioning_file_digests"],
                    }
                    _require(
                        set(expected) == set(identity.FILE_PATHS),
                        "FROZEN_PIN_INVENTORY_CHANGED",
                    )
                    result["expected_file_digests"] = expected
                    result["pins_frozen_before_activation"] = True
                    if before_activation is not None:
                        phase = "PRE_ACTIVATION_CALLBACK"
                        detached = dict(provisioning_inputs)
                        try:
                            _require(
                                set(detached) == set(DYNAMIC_PATHS)
                                and {
                                    path: _digest(raw) for path, raw in detached.items()
                                }
                                == result["provisioning_file_digests"],
                                "PREACTIVATION_CALLBACK_INPUTS_CHANGED",
                            )
                            before_activation(detached)
                        finally:
                            detached.clear()
                            provisioning_inputs.clear()
                        phase = "ACTIVATION"
                    result["activation_count"] += 1
                    value = activate(*args, **kwargs)
                    phase = "NATIVE_STARTUP"
                    return value

                def prepare_with_writer_pins():
                    nonlocal phase
                    phase = "PROVISIONING"
                    p37b = _p37b()
                    write_document = p37b._write_document
                    write_control = p37b.capability._write_control
                    create_document = native.provision._create_document

                    def document(path, value, *args, **kwargs):
                        raw = canonical_json(value)
                        record(str(path), raw)
                        outcome = write_document(path, value, *args, **kwargs)
                        _require(
                            canonical_json(value) == raw,
                            "DOCUMENT_WRITER_MUTATED_INPUT",
                        )
                        return outcome

                    def control(path, value, *args, **kwargs):
                        if str(path) == identity._POLICY:
                            raw = canonical_json(value)
                            record(str(path), raw)
                        else:
                            raw = None
                        outcome = write_control(path, value, *args, **kwargs)
                        _require(
                            raw is None or canonical_json(value) == raw,
                            "POLICY_WRITER_MUTATED_INPUT",
                        )
                        return outcome

                    def genesis(parent, name, raw, held):
                        if name == Path(identity._GENESIS).name:
                            record(identity._GENESIS, raw)
                        return create_document(parent, name, raw, held)

                    with (
                        patch.object(p37b, "_write_document", document),
                        patch.object(p37b.capability, "_write_control", control),
                        patch.object(native.provision, "_create_document", genesis),
                    ):
                        return prepare()

                # The inherited seed_then_activate captures this wrapper, so
                # seeding still precedes the freeze and original activation.
                patches.enter_context(
                    patch.object(native, "_activate", freeze_then_activate)
                )
                patches.enter_context(
                    patch.object(native, "_prepare", prepare_with_writer_pins)
                )
                return native

            patches.enter_context(patch.object(update.prior, "_native", native_factory))
            patches.enter_context(patch.object(update, "_invoke", invoke))
            phase = "NATIVE_SETUP"
            result["update_observation"] = update._run(container, copied_owner)
        observation = result["update_observation"]
        _require(
            type(observation) is dict
            and observation.get("schema") == update._SCHEMA
            and observation.get("authority") == update._AUTHORITY
            and observation.get("status") == "OBSERVED"
            and observation.get("route_id") == update._ROUTE
            and observation.get("fixture_container") == container
            and observation.get("branch") == result["branch"]
            and all(observation.get(name) is False for name in _FALSE_FLAGS[:4]),
            "PREDECESSOR_OBSERVATION_CONTRACT_CHANGED",
        )
        _require(
            result["invocation_count"] == result["activation_count"] == 1
            and result["comparison"] is not None
            and result["before"] is not None
            and result["after"] is not None,
            "SINGLE_BRACKET_NOT_COMPLETED",
        )
        stamps = list(result["boundaries_monotonic_ns"].values())
        _require(
            all(type(value) is int and value > 0 for value in stamps)
            and stamps == sorted(stamps),
            "MONOTONIC_BOUNDARY_ORDER_CHANGED",
        )
        result["status"] = "OBSERVED"
    except Exception as exc:  # noqa: BLE001 - fixed diagnostic codes only, never native output
        result["refusal"] = {
            "phase": phase,
            "reason": str(exc)
            if type(exc) is NativeIdentityGuestError
            else "GUEST_EXECUTION_REFUSED",
            "diagnostic": _refusal_location(exc),
        }
    finally:
        if provisioning_inputs is not None:
            provisioning_inputs.clear()
    return result


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if (
        len(args) != 4
        or re.fullmatch(r"[0-9a-f]{64}", args[0]) is None
        or any(re.fullmatch(r"[0-9]{1,10}", value) is None for value in args[1:3])
        or re.fullmatch(r"sha256:[0-9a-f]{64}", args[3]) is None
    ):
        return 64
    value = _run(args[0], tuple(map(int, args[1:3])), args[3])
    sys.stdout.buffer.write(canonical_json(value) + b"\n")
    return 0 if value["status"] == "OBSERVED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
