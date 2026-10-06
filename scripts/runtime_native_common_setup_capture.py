"""Fixed owned-guest setup capture and allowlisted public CAS export.

This entrypoint cannot activate or resume the runtime. It never enumerates the
CAS or reads provisioning credentials. Only publication candidates journaled by
the trusted setup operation can be read, and every candidate is read once.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
import re
import stat
import sys

if __package__:
    from scripts import runtime_native_common_case_setup as setup
else:
    sys.path[:0] = ["/usr/lib/aragorn", "/opt/aragorn"]
    import runtime_native_common_case_setup as setup

from aragorn import native_phase3_common_setup_capture as contract
from aragorn.oci_worker_protocol import canonical_json

SCHEMA = "aragorn/native-common-setup-guest/v1"
AUTHORITY = "OWNED_SETUP_ONLY_PUBLIC_EXPORT_NOT_PRIVATE_WRITER_REPLAY"
BUNDLE_PATH = "/opt/aragorn/native-common-setup-inputs.json"
MAX_INPUT = 8 * 1024 * 1024
MAX_RESULT = 48 * 1024 * 1024
MAX_PUBLIC_TOTAL = 8 * 1024 * 1024
MAX_PUBLIC_BLOB = 1024 * 1024
MAX_PUBLIC_BLOBS = 32
_MAX_SETUP = 2 * 1024 * 1024
_FALSE = setup._FALSE
_LIMITATIONS = [
    "SETUP_ONLY_NOT_ACTIVATION_OR_RESUME_AUTHORITY",
    "PUBLIC_JOURNAL_EXPORT_NOT_INDEPENDENT_PRIVATE_WRITER_REPLAY",
    "ROOT_GUEST_READBACK_NOT_HOST_OR_LOADED_CODE_ATTESTATION",
    "NO_CAS_ENUMERATION_OR_UNJOURNALED_BLOB_EXPORT",
]
_IDENTITY = setup.predecessor.identity
_CONTROLLER_PATHS = {
    "scripts/runtime_native_common_setup_capture.py": "/opt/aragorn/runtime_native_common_setup_capture.py",
    "src/aragorn/native_phase3_common_setup_capture.py": "/usr/lib/aragorn/aragorn/native_phase3_common_setup_capture.py",
}


class NativeCommonSetupCaptureError(ValueError):
    """A fixed refusal; no private input or exception text is retained."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise NativeCommonSetupCaptureError(reason)


def _close_all(descriptors: list[int]) -> None:
    primary = sys.exception()
    failure = None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException as error:
            if failure is None:
                failure = error
    if failure is not None and primary is None:
        raise NativeCommonSetupCaptureError("DESCRIPTOR_CLOSE_REFUSED") from None


def _read_bundle(expected: str) -> tuple[bytes, dict]:
    descriptors = []
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(root)
        raw, metadata = _IDENTITY._read_at(
            root, BUNDLE_PATH, owner=0, owner_gid=0, modes={0o444}, limit=MAX_INPUT
        )
        _require(_IDENTITY._digest(raw) == expected, "BUNDLE_PIN_CHANGED")
        return raw, metadata
    finally:
        _close_all(descriptors)


def _directory(descriptor: int, mode: int | None) -> tuple:
    metadata = os.fstat(descriptor)
    _require(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and not stat.S_IMODE(metadata.st_mode) & 0o022
        and (mode is None or stat.S_IMODE(metadata.st_mode) == mode),
        "PUBLIC_CAS_DIRECTORY_CUSTODY_REFUSED",
    )
    return _IDENTITY.broker._directory_identity(metadata)


def _read_controller(source: str, expected: bytes) -> dict:
    descriptors = []
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(root)
        raw, metadata = _IDENTITY._read_at(
            root,
            _CONTROLLER_PATHS[source],
            owner=0,
            owner_gid=0,
            modes={0o444},
            limit=MAX_PUBLIC_BLOB,
        )
        _require(raw == expected, "INSTALLED_CONTROLLER_SOURCE_CHANGED")
        return metadata
    finally:
        _close_all(descriptors)


@contextmanager
def _public_store():
    """Hold the existing fixed CAS ancestry without creating or repairing it."""
    descriptors, held = [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        _require(
            setup.CAS_ROOT == "/run/aragorn-native-common-setup",
            "FIXED_PUBLIC_CAS_ROOT_CHANGED",
        )
        root = os.open("/", flags)
        descriptors.append(root)
        held.append((root, ".", root, _directory(root, None), None))
        parent = root
        for name, mode in (
            ("run", None),
            ("aragorn-native-common-setup", 0o700),
            ("blobs", 0o700),
            ("sha256", 0o700),
        ):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            descriptor = os.open(name, flags, dir_fd=parent)
            descriptors.append(descriptor)
            identity = _directory(descriptor, mode)
            _require(
                identity == _IDENTITY.broker._directory_identity(before),
                "PUBLIC_CAS_DIRECTORY_REPLACED",
            )
            held.append((parent, name, descriptor, identity, mode))
            parent = descriptor

        def guard():
            for ancestor, name, descriptor, identity, mode in held:
                _require(
                    identity
                    == _directory(descriptor, mode)
                    == _IDENTITY.broker._directory_identity(
                        os.stat(name, dir_fd=ancestor, follow_symlinks=False)
                    ),
                    "PUBLIC_CAS_DIRECTORY_REPLACED",
                )

        guard()
        yield parent, guard
        guard()
    finally:
        _close_all(descriptors)


def _candidates(value: object) -> list[dict]:
    _require(
        type(value) is list and len(value) <= MAX_PUBLIC_BLOBS,
        "PUBLIC_JOURNAL_INVENTORY_REFUSED",
    )
    seen = set()
    for candidate in value:
        _require(
            type(candidate) is dict
            and set(candidate) == {"digest", "bytes"}
            and type(candidate["digest"]) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", candidate["digest"]) is not None
            and candidate["digest"] not in seen
            and type(candidate["bytes"]) is int
            and 0 < candidate["bytes"] <= MAX_PUBLIC_BLOB,
            "PUBLIC_JOURNAL_ENTRY_REFUSED",
        )
        seen.add(candidate["digest"])
    return [dict(candidate) for candidate in value]


def _read_public_blob(sha_root: int, candidate: dict) -> bytes:
    """Read exactly one journaled digest through held no-follow descriptors."""
    descriptors = []
    prefix = candidate["digest"][7:9]
    try:
        before = os.stat(prefix, dir_fd=sha_root, follow_symlinks=False)
        descriptor = os.open(
            prefix,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=sha_root,
        )
        descriptors.append(descriptor)
        identity = _directory(descriptor, 0o700)
        _require(
            identity == _IDENTITY.broker._directory_identity(before),
            "PUBLIC_PREFIX_REPLACED",
        )
        raw, _ = _IDENTITY._read_at(
            descriptor,
            "/" + candidate["digest"][9:],
            owner=0,
            owner_gid=0,
            modes={0o444},
            limit=MAX_PUBLIC_BLOB,
        )
        _require(
            len(raw) == candidate["bytes"]
            and _IDENTITY._digest(raw) == candidate["digest"]
            and identity
            == _directory(descriptor, 0o700)
            == _IDENTITY.broker._directory_identity(
                os.stat(prefix, dir_fd=sha_root, follow_symlinks=False)
            ),
            "PUBLIC_BLOB_OR_PREFIX_CHANGED",
        )
        return raw
    finally:
        _close_all(descriptors)


def _export_public(result: dict, candidates: list[dict]) -> None:
    """Retain independent successes even if another candidate was never put."""
    if not candidates:
        return
    attempted = set()
    total = 0
    try:
        with _public_store() as (sha_root, guard):
            for candidate in candidates:
                pin = candidate["digest"]
                attempted.add(pin)
                try:
                    guard()
                    raw = _read_public_blob(sha_root, candidate)
                    guard()
                    _require(
                        total + len(raw) <= MAX_PUBLIC_TOTAL, "EXPORT_TOTAL_REFUSED"
                    )
                    exported = {**candidate, "text": raw.decode("utf-8")}
                    # Reserve room for bounded fixed refusal/cleanup diagnostics.
                    trial = dict(
                        result, public_blobs=[*result["public_blobs"], exported]
                    )
                    _require(
                        len(canonical_json(trial)) <= MAX_RESULT - 65536,
                        "EXPORT_WIRE_BOUND_REFUSED",
                    )
                    result["public_blobs"].append(exported)
                    total += len(raw)
                except BaseException:
                    result["export_failures"].append(
                        {"digest": pin, "reason": "PUBLIC_BLOB_EXPORT_REFUSED"}
                    )
    except BaseException:
        for candidate in candidates:
            if candidate["digest"] not in attempted:
                result["export_failures"].append(
                    {
                        "digest": candidate["digest"],
                        "reason": "PUBLIC_BLOB_EXPORT_REFUSED",
                    }
                )
        # A final ancestry or close failure can occur after every candidate read.
        if result["refusal"] is None:
            result["refusal"] = {
                "phase": "EXPORT",
                "reason": "PUBLIC_CAS_CUSTODY_REFUSED",
            }


def _run(container: str, expected_bundle_digest: str) -> dict:
    result = {
        "schema": SCHEMA,
        "authority": AUTHORITY,
        "status": "REFUSED",
        "container_id": None,
        "input_bundle_digest": None,
        "setup": None,
        "public_blobs": [],
        "export_failures": [],
        "refusal": None,
        "input_bundle_readback": False,
        "controller_sources": {},
        "controller_sources_after": {},
        "postcondition_failures": [],
        "limitations": list(_LIMITATIONS),
        **dict.fromkeys(_FALSE, False),
    }
    phase = "ARGUMENTS"
    bundle = None
    candidates = []
    inspected = None
    try:
        _require(
            type(container) is str
            and re.fullmatch(r"[0-9a-f]{64}", container) is not None
            and type(expected_bundle_digest) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_bundle_digest)
            is not None,
            "FIXED_CAPTURE_ARGUMENTS_REFUSED",
        )
        result["container_id"] = container
        result["input_bundle_digest"] = expected_bundle_digest
        phase = "ENVIRONMENT"
        setup.predecessor._environment(container, (0, 0))
        phase = "INPUT_BUNDLE"
        bundle = _read_bundle(expected_bundle_digest)
        inspected = contract.inspect_common_setup_inputs(
            bundle[0], expected_bundle_digest=expected_bundle_digest
        )
        phase = "CONTROLLER_SOURCES"
        for source in _CONTROLLER_PATHS:
            result["controller_sources"][source] = _read_controller(
                source, inspected["source_raws"][source]
            )
        phase = "SETUP"
        report = setup.prepare_common_native_setup(
            expected_container_id=container, **inspected["setup_arguments"]
        )
        _require(
            type(report) is dict and len(canonical_json(report)) <= _MAX_SETUP,
            "SETUP_REPORT_BOUND_REFUSED",
        )
        result["setup"] = report
        candidates = _candidates(report["public_blob_attempts"])
        _require(
            report.get("schema") == setup.SCHEMA
            and report.get("authority") == setup.AUTHORITY
            and report.get("container_id") == container
            and all(report.get(key) is False for key in _FALSE),
            "SETUP_REPORT_IDENTITY_REFUSED",
        )
        if report["status"] != "PREPARED_NOT_ACTIVATED":
            result["refusal"] = {"phase": "SETUP", "reason": "COMMON_SETUP_REFUSED"}
        else:
            _require(
                bool(candidates)
                and report["preparation"]["retained_blob_digests"]
                == sorted(row["digest"] for row in candidates)
                and report["setup_state"]["activation_count"] == 0,
                "COMPLETE_PUBLIC_JOURNAL_REFUSED",
            )
    except BaseException:
        result["refusal"] = {"phase": phase, "reason": "COMMON_SETUP_CAPTURE_REFUSED"}
    finally:
        if candidates:
            try:
                setup.predecessor._environment(container, (0, 0))
                _export_public(result, candidates)
            except BaseException:
                result["export_failures"].extend(
                    {
                        "digest": row["digest"],
                        "reason": "OWNED_EXPORT_ENVIRONMENT_REFUSED",
                    }
                    for row in candidates
                )
        # These are independent final observations, after export as well as setup.
        if bundle is not None:
            try:
                setup.predecessor._environment(container, (0, 0))
                _require(
                    _read_bundle(expected_bundle_digest) == bundle,
                    "BUNDLE_CUSTODY_CHANGED",
                )
                result["input_bundle_readback"] = True
            except BaseException:
                result["postcondition_failures"].append("BUNDLE_AFTER")
        if inspected is not None:
            for source, label in zip(
                _CONTROLLER_PATHS,
                ("WRAPPER_SOURCE_AFTER", "CONTRACT_SOURCE_AFTER"),
                strict=True,
            ):
                try:
                    setup.predecessor._environment(container, (0, 0))
                    observed = _read_controller(
                        source, inspected["source_raws"][source]
                    )
                    result["controller_sources_after"][source] = observed
                    _require(
                        observed == result["controller_sources"].get(source),
                        "CONTROLLER_SOURCE_CUSTODY_CHANGED",
                    )
                except BaseException:
                    result["postcondition_failures"].append(label)
        if result["postcondition_failures"] and result["refusal"] is None:
            result["refusal"] = {
                "phase": "FINAL_READBACKS",
                "reason": "CAPTURE_CUSTODY_READBACK_REFUSED",
            }
    if (
        result["refusal"] is None
        and not result["export_failures"]
        and result["input_bundle_readback"]
        and result["setup"] is not None
        and result["setup"]["status"] == "PREPARED_NOT_ACTIVATED"
    ):
        result["status"] = "PREPARED_NOT_ACTIVATED"
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    result = _run(*arguments) if len(arguments) == 2 else _run(None, None)
    raw = canonical_json(result)
    _require(len(raw) + 1 <= MAX_RESULT, "CAPTURE_OUTPUT_BOUND_REFUSED")
    sys.stdout.buffer.write(raw + b"\n")
    return 0 if result["status"] == "PREPARED_NOT_ACTIVATED" else 126


if __name__ == "__main__":
    raise SystemExit(main())
