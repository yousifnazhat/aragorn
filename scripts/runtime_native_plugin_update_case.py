"""Commit one fixed native plugin-update request locally before activation.

The sealed input bundle contains only caller-pinned public artifacts and source
bytes. Fresh provisioning bytes pass through a trusted in-memory hook, never
the output CAS or result. A successful local readback is not a host ACK, remote
attestation, fresh-campaign qualification, or proof of independent semantics.
Partial CAS artifacts remain on refusal for the owned fixture's cleanup.
"""

from __future__ import annotations

import io
import json
import os
import re
import stat
import sys
from contextlib import ExitStack, contextmanager
from pathlib import Path

if __package__:
    from scripts import runtime_native_plugin_update_identity_check as identity_guest
else:
    sys.path[:0] = ["/usr/lib/aragorn", str(Path(__file__).resolve().parent)]
    import runtime_native_plugin_update_identity_check as identity_guest

from aragorn import native_phase3_plugin_update_case as case
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-plugin-update-case-guest/v1"
BUNDLE_SCHEMA = "aragorn/native-plugin-update-case-inputs/v1"
BUNDLE_PATH = "/opt/aragorn/native-plugin-update-case-inputs.json"
CAS_ROOT = "/run/aragorn-native-plugin-update-case"
AUTHORITY = "GUEST_LOCAL_PREACTIVATION_COMMITMENT_NOT_HOST_ACK_OR_QUALIFICATION"
_MAX_INPUT = 2 * 1024 * 1024
_MAX_REQUEST = 16384
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


class NativePluginUpdateCaseGuestError(ValueError):
    """A fixed guest invariant failed; messages never include input values."""


def _require(value: bool, reason: str) -> None:
    if not value:
        raise NativePluginUpdateCaseGuestError(reason)


def _pin(value: object) -> str:
    _require(
        type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None,
        "INVALID_CALLER_PIN",
    )
    return value


def _pairs(items):
    result = dict(items)
    _require(len(result) == len(items), "DUPLICATE_BUNDLE_KEY")
    return result


def _parse_bundle(raw: bytes, expected: str, expected_intent: str) -> dict[str, bytes]:
    _require(
        type(raw) is bytes
        and 0 < len(raw) <= _MAX_INPUT
        and identity_guest._digest(raw) == _pin(expected),
        "BUNDLE_PIN_OR_SIZE_CHANGED",
    )
    _pin(expected_intent)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
        _require(
            type(value) is dict
            and set(value) == {"schema", "intent_digest", "blobs"}
            and value["schema"] == BUNDLE_SCHEMA
            and value["intent_digest"] == expected_intent
            and canonical_json(value) == raw
            and type(value["blobs"]) is dict
            and 1 <= len(value["blobs"]) <= 32,
            "BUNDLE_CONTRACT_CHANGED",
        )
        blobs = {}
        total = 0
        for pin, text in value["blobs"].items():
            _pin(pin)
            _require(type(text) is str, "BUNDLE_BLOB_NOT_UTF8_TEXT")
            blob = text.encode("utf-8")
            total += len(blob)
            _require(
                0 < len(blob)
                and total <= _MAX_INPUT
                and identity_guest._digest(blob) == pin,
                "BUNDLE_BLOB_PIN_OR_SIZE_CHANGED",
            )
            blobs[pin] = blob
        _require(expected_intent in blobs, "BUNDLE_INTENT_MISSING")
        return blobs
    except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
        if type(exc) is NativePluginUpdateCaseGuestError:
            raise
        raise NativePluginUpdateCaseGuestError("BUNDLE_PARSE_REFUSED") from exc


def _environment() -> None:
    _require(
        sys.platform == "linux" and os.geteuid() == os.getegid() == 0,
        "LINUX_ROOT_GUEST_REQUIRED",
    )


def _read_bundle(expected: str, expected_intent: str) -> dict[str, bytes]:
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw, _ = identity_guest.identity._read_at(
            fd, BUNDLE_PATH, owner=0, owner_gid=0, modes={0o444}, limit=_MAX_INPUT
        )
    finally:
        os.close(fd)
    return _parse_bundle(raw, expected, expected_intent)


def _directory(fd: int, mode: int | None = None) -> tuple:
    metadata = os.fstat(fd)
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and not stat.S_IMODE(metadata.st_mode) & 0o022
        and (mode is None or stat.S_IMODE(metadata.st_mode) == mode),
        "GUEST_CAS_DIRECTORY_CUSTODY_CHANGED",
    )
    return identity_guest.identity.broker._directory_identity(metadata)


@contextmanager
def _fresh_store():
    """Create only the fixed absent root; keep its protected ancestry held."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        root = os.open("/", flags)
        stack.callback(os.close, root)
        root_identity = _directory(root)
        run = os.open("run", flags, dir_fd=root)
        stack.callback(os.close, run)
        run_identity = _directory(run)
        name = Path(CAS_ROOT).name
        os.mkdir(name, 0o700, dir_fd=run)  # Existing roots are never reused.
        child = os.open(name, flags, dir_fd=run)
        stack.callback(os.close, child)
        child_identity = _directory(child, 0o700)
        os.fsync(run)

        def guard():
            for parent, component, held, expected, mode in (
                (root, ".", root, root_identity, None),
                (root, "run", run, run_identity, None),
                (run, name, child, child_identity, 0o700),
            ):
                named = os.stat(component, dir_fd=parent, follow_symlinks=False)
                _require(
                    _directory(held, mode)
                    == expected
                    == identity_guest.identity.broker._directory_identity(named),
                    "GUEST_CAS_DIRECTORY_REPLACED",
                )

        guard()
        writer = CAS(CAS_ROOT)
        reader = CAS(CAS_ROOT, read_only=True)
        guard()
        yield writer, reader, guard
        guard()


def _run(
    container: str,
    copied_owner: tuple[int, int],
    expected_static_manifest_digest: str,
    expected_bundle_digest: str,
    expected_intent_digest: str,
) -> dict:
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "case_id": case.ROUTE,
        "branch": case.BRANCH,
        "fixture_container": container,
        "input_bundle_digest": expected_bundle_digest,
        "intent_digest": expected_intent_digest,
        "identity_observation": None,
        "prepared_case": None,
        "refusal": None,
        **dict.fromkeys(_FALSE_FLAGS, False),
    }
    phase = "BUNDLE_INPUT"
    callback_refusal = None
    try:
        _environment()
        _pin(expected_static_manifest_digest)
        blobs = _read_bundle(expected_bundle_digest, expected_intent_digest)
        with _fresh_store() as (writer, reader, guard):
            for pin, raw in blobs.items():
                writer.put_expected(
                    io.BytesIO(raw), expected_digest=pin, max_bytes=_MAX_INPUT
                )
            guard()
            phase = "INPUT_CLOSURE"
            intent_raw = blobs[expected_intent_digest]
            bound = case.validate_native_plugin_update_case_intent(
                intent_raw,
                expected_intent_digest=expected_intent_digest,
                evidence_cas=reader,
            )
            _require(bound["input_blobs"] == blobs, "BUNDLE_INPUT_CLOSURE_CHANGED")
            _require(
                bound["intent"]["static_pin_manifest_digest"]
                == expected_static_manifest_digest,
                "INTENT_STATIC_PIN_CHANGED",
            )
            guard()
            hook_calls = 0

            def commit_before_activation(provisioning_inputs):
                nonlocal hook_calls, phase, callback_refusal
                phase = "PREACTIVATION_ORDER"
                try:
                    hook_calls += 1
                    _require(hook_calls == 1, "DUPLICATE_PREACTIVATION_CALLBACK")
                    phase = "PREACTIVATION_PREPARATION"
                    prepared = case.prepare_native_plugin_update_case(
                        intent_raw,
                        expected_intent_digest=expected_intent_digest,
                        evidence_cas=reader,
                        provisioning_inputs=provisioning_inputs,
                    )
                    request_raw, request_pin = (
                        prepared["request_raw"],
                        prepared["request_digest"],
                    )
                    _require(
                        canonical_json(prepared["request"]) == request_raw,
                        "PREPARED_REQUEST_BYTES_CHANGED",
                    )
                    phase = "PREACTIVATION_PUBLICATION"
                    writer.put_expected(
                        io.BytesIO(request_raw),
                        expected_digest=request_pin,
                        max_bytes=_MAX_REQUEST,
                    )
                    phase = "PREACTIVATION_READBACK"
                    _require(
                        reader.read(request_pin, max_bytes=_MAX_REQUEST) == request_raw,
                        "PREACTIVATION_REQUEST_READBACK_CHANGED",
                    )
                    phase = "PREACTIVATION_CUSTODY"
                    guard()
                    result["prepared_case"] = {
                        "request": prepared["request"],
                        "request_digest": request_pin,
                        "local_pre_activation_readback": True,
                        "authority": AUTHORITY,
                        "host_ack_received": False,
                        **dict.fromkeys(_FALSE_FLAGS, False),
                    }
                except Exception:  # noqa: BLE001 - fixed phase enum, no helper messages
                    callback_refusal = {"phase": phase, "reason": phase + "_REFUSED"}
                    raise
                phase = "IDENTITY_OBSERVATION"

            phase = "IDENTITY_OBSERVATION"
            result["identity_observation"] = identity_guest._run(
                container,
                copied_owner,
                expected_static_manifest_digest,
                before_activation=commit_before_activation,
            )
            _require(
                result["identity_observation"]["status"] == "OBSERVED"
                and hook_calls == 1
                and result["prepared_case"] is not None,
                "CASE_COMMIT_OR_IDENTITY_OBSERVATION_REFUSED",
            )
            phase = "FINAL_READBACK"
            prepared = result["prepared_case"]
            _require(
                reader.read(prepared["request_digest"], max_bytes=_MAX_REQUEST)
                == canonical_json(prepared["request"]),
                "FINAL_REQUEST_READBACK_CHANGED",
            )
            for pin, raw in blobs.items():
                _require(
                    reader.read(pin, max_bytes=_MAX_INPUT) == raw,
                    "FINAL_INPUT_READBACK_CHANGED",
                )
            guard()
        result["status"] = "OBSERVED"
    except Exception as exc:  # noqa: BLE001 - no raw input or exception text in output
        result["refusal"] = callback_refusal or {
            "phase": phase,
            "reason": str(exc)
            if type(exc) is NativePluginUpdateCaseGuestError
            else "CASE_GUEST_REFUSED",
        }
    return result


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if (
        len(args) != 6
        or re.fullmatch(r"[0-9a-f]{64}", args[0]) is None
        or any(re.fullmatch(r"[0-9]{1,10}", item) is None for item in args[1:3])
        or any(re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in args[3:])
    ):
        return 64
    result = _run(args[0], tuple(map(int, args[1:3])), *args[3:])
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0 if result["status"] == "OBSERVED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
