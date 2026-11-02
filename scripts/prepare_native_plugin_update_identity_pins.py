"""Prepare historical caller expectations for the native identity capture.

Repository-local, Python 3.12 standard-library CLI; no auth, network, subprocess,
capture import, or live readback. ``prepare --out ABSENT_ABSOLUTE_MANIFEST
--provenance-out ABSENT_ABSOLUTE_JSON`` emits JSON (0 prepared, 2 refused).
``--help`` is read-only. The manifest is canonical JSON without a newline;
provenance is canonical JSON with one newline. Outputs are never overwritten.
Provenance is written first; an I/O refusal may leave partial output files,
which are not a successful preparation and are never silently repaired.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "src"))

from aragorn import native_phase3_plugin_update_binding as binding

_CAPTURE = "benchmark/evidence/phase3-native-plugin-update-systemd-development-v2-2026-10-01.json"
_IMAGE_RECORD = "benchmark/evidence/runtime-action-worker-final-combined-v3-route-core-updater-plugin-replacement-systemd-p3-final-2026-09-03.json"
_CAPTURE_PIN = (
    422631,
    "sha256:42acdf26c128c4d7ecdfd740ac04b17509e9e17e0b799e7d4a870bf5e82a9e12",
)
_IMAGE_PIN = (
    598667,
    "sha256:4718a3bdaf5c9474e301ff8d825332a804119cc69a17888bc9fdbffba396dabc",
)
_SOURCE_COMMIT = "85d59fd39ab8ccc2d74a6ab4ca8de029ed1fdd5d"
_SOURCE_DIGEST = (
    "sha256:1ae8f8739a59318b6b4fcc8b5c58c468aeaad151208c3562a8b6f4ec667b961a"
)
_IMAGE_SOURCE_COMMIT = "05192ef62e26a067bc8ef72b0c9d3d7d2813b201"
_IMAGE = "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17"
_PYTHON = "sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57"
_NODE = "sha256:3a988781edde7f1c76751f771cf402e0866fb4a81fbcd0852a2ce2f5bd2ccd37"
_ENTRY = "/runtime/lib/node_modules/openclaw/openclaw.mjs"
_ENTRY_PIN = (
    23463,
    "sha256:f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188",
)
_SELECTED = {
    "/usr/lib/aragorn/aragorn/runtime_action_worker.py": (
        "src/aragorn/runtime_action_worker.py",
        46629,
        "0644",
        "sha256:df55f788ed29d188c71ca201d5778e7bff734b9a2f09445d8247c4ab6f40cd32",
    ),
    "/usr/libexec/aragorn/aragorn-runtime-action-service-v5.py": (
        "packaging/libexec/aragorn-runtime-action-service-v5.py",
        349,
        "0755",
        "sha256:9dd8e3836176e3d2a6d2ab8d6a036e078dd868a188f10a74d3808b51290405fc",
    ),
    "/usr/libexec/aragorn/aragorn-runtime-action-worker-service.py": (
        "packaging/libexec/aragorn-runtime-action-worker-service.py",
        338,
        "0755",
        "sha256:5274f51d50293ba7559c6348fe79c5eb43753ecb09024525cfd09c368cc360f8",
    ),
    "/usr/libexec/aragorn/aragorn-runtime-observation-service-v4.py": (
        "packaging/libexec/aragorn-runtime-observation-service-v4.py",
        356,
        "0755",
        "sha256:dba9cf34f9103073f9583f29bf0a83ae7f3162ca511ec2d76ec250ab161167cf",
    ),
    "/usr/lib/systemd/system/aragorn-agent-gateway.service": (
        "packaging/systemd/aragorn-agent-gateway.service",
        3564,
        "0644",
        "sha256:7c9993591363e382ceed407f055a48fe2b5fc539387342487f43ce3575d27317",
    ),
    "/usr/lib/systemd/system/aragorn-runtime-action-worker.service": (
        "packaging/systemd/aragorn-runtime-action-worker.service",
        2946,
        "0644",
        "sha256:4be030dbc98d9564b7c860482e0934c4a62cb6bdd5e0f22dedd7add3fa978bfc",
    ),
    "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-action-broker.service": (
        "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service",
        2725,
        "0644",
        "sha256:e0273dbeb4ed40a203193a52eb6146f81ecbc6abca605fa0bfff69774676b2db",
    ),
    "/usr/lib/systemd/system/aragorn-runtime-lineage-capability-observation-publisher.service": (
        "packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service",
        2777,
        "0644",
        "sha256:f48258b00213c2c1ff4c5c95d0f1c446f78593d1d04780719cba79bf8dd73d8a",
    ),
}
_SCHEMA = "aragorn/native-plugin-update-identity-pin-preparation/v1"
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class PinPreparationError(ValueError):
    """The fixed historical source or exclusive output contract was refused."""


def _require(condition, message):
    if not condition:
        raise PinPreparationError(message)


def _record(raw, pin):
    _require(
        type(raw) is bytes and (len(raw), binding._digest(raw)) == pin,
        "historical record differs from fixed pin",
    )
    return binding._parse(raw, newline=True)


def prepare_pin_documents(capture_raw: bytes, image_raw: bytes) -> tuple[dict, dict]:
    """Validate exactly two historical records; return no live attestation."""
    try:
        capture, image = (
            _record(capture_raw, _CAPTURE_PIN),
            _record(image_raw, _IMAGE_PIN),
        )
        binding.native_plugin_update_identity_artifacts(
            capture_raw,
            expected_capture_digest=_CAPTURE_PIN[1],
            expected_source_digest=_SOURCE_DIGEST,
            expected_source_commit=_SOURCE_COMMIT,
        )
        _require(
            image["schema"]
            == "aragorn/runtime-action-worker-final-combined-v3-core-updater-plugin-replacement-systemd-observation/v1",
            "historical image record kind changed",
        )
        for harness in (
            image["harness"]["document"],
            image["composition"]["action"]["harness"]["document"],
        ):
            _require(
                harness["image_id"] == harness["run_image_reference"] == _IMAGE
                and harness["source_commit"] == _IMAGE_SOURCE_COMMIT,
                "historical exact image or source join changed",
            )
        _require(
            capture["fixture_image"]["Id"] == _IMAGE, "native fixture image changed"
        )
        profile = capture["staged_profile"]
        files = {item["path"]: item for item in profile["files"]}
        selected = []
        for path, (source, size, mode, digest) in _SELECTED.items():
            expected = {
                "path": path,
                "source_name": source,
                "bytes": size,
                "mode": mode,
                "digest": digest,
            }
            _require(files[path] == expected, "selected staged-file identity changed")
            selected.append(expected)
        entry = profile["required_runtime_not_included"]
        _require(
            entry["entrypoint"] == _ENTRY
            and (entry["entrypoint_bytes"], entry["entrypoint_digest"]) == _ENTRY_PIN,
            "historical entrypoint pin changed",
        )
        binaries = image["composition"]["action"]["profiles"]["executables"]
        binary_records = {}
        for name, path, size, digest in (
            ("worker_python", "/usr/local/bin/python3.12", 67608, _PYTHON),
            ("node", "/usr/local/bin/node", 121333752, _NODE),
        ):
            item = binaries[name]
            info = item["stat"]
            _require(
                set(item) == {"path", "bytes", "digest", "stat"}
                and (item["path"], item["bytes"], item["digest"])
                == (path, size, digest)
                and info["type"] == "file"
                and info["mode"] == "0755"
                and (info["uid"], info["gid"], info["nlink"], info["size"])
                == (0, 0, 1, size),
                "historical executable custody or pin changed",
            )
            binary_records[path] = item
        _require(
            capture["observation"]["setup"]["runtime_profile"]["executable_digest"]
            == _PYTHON,
            "native Python profile join changed",
        )
        file_digests = {item["path"]: item["digest"] for item in selected}
        file_digests.update(
            {
                _ENTRY: _ENTRY_PIN[1],
                **{path: item["digest"] for path, item in binary_records.items()},
            }
        )
        manifest = {
            "schema": "aragorn/native-plugin-update-identity-static-pins/v1",
            "file_digests": file_digests,
        }
        provenance = {
            "schema": _SCHEMA,
            "authority": "HISTORICAL_CALLER_EXPECTATIONS_NOT_CURRENT_IMAGE_ATTESTATION",
            "fixture_image": _IMAGE,
            "static_pin_manifest_digest": binding._digest(
                binding.canonical_json(manifest)
            ),
            "records": {
                "native_update": {
                    "path": _CAPTURE,
                    "bytes": _CAPTURE_PIN[0],
                    "digest": _CAPTURE_PIN[1],
                    "source_commit": _SOURCE_COMMIT,
                    "source_record_digest": _SOURCE_DIGEST,
                    "source_json_location": "/source",
                },
                "exact_image": {
                    "path": _IMAGE_RECORD,
                    "bytes": _IMAGE_PIN[0],
                    "digest": _IMAGE_PIN[1],
                    "source_commit": _IMAGE_SOURCE_COMMIT,
                    "source_json_locations": [
                        "/harness/document/source_commit",
                        "/composition/action/harness/document/source_commit",
                    ],
                },
            },
            "selected_profile": {
                "record": "native_update",
                "schema": profile["schema"],
                "json_location": "/staged_profile/files",
                "selected_files": selected,
            },
            "entrypoint": {
                "record": "native_update",
                "json_location": "/staged_profile/required_runtime_not_included",
                "path": _ENTRY,
                "bytes": _ENTRY_PIN[0],
                "digest": _ENTRY_PIN[1],
            },
            "binary_records": binary_records,
            "binary_and_image_record": "exact_image",
            "binary_json_location": "/composition/action/profiles/executables",
            "image_json_locations": [
                "/harness/document/image_id",
                "/composition/action/harness/document/image_id",
            ],
            "native_python_json_location": "/observation/setup/runtime_profile/executable_digest",
            "limitations": [
                "FIXED_HISTORICAL_RECORDS_NOT_CURRENT_IMAGE_OR_HOST_ATTESTATION",
                "NO_FRESH_MEASUREMENT_OR_SOURCE_SIGNATURE_VERIFICATION",
                "SELECTED_EIGHT_STAGED_FILES_NOT_FULL_PROFILE_VERIFICATION",
                "CAPTURE_HOST_MUST_RECHECK_SELECTED_STATIC_PROFILE_BEFORE_ACTIVATION",
                "NO_ROUTE_RUN_OR_PHASE3_QUALIFICATION",
            ],
            "live_deployment_attested": False,
            "current_image_verified": False,
            "source_signature_verified": False,
            "route_qualified": False,
            "phase3_eligible": False,
        }
        return manifest, provenance
    except PinPreparationError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, OverflowError) as exc:
        raise PinPreparationError("historical evidence contract refused") from exc


def _identity(info, *, directory=False):
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    if not directory:
        fields += ("st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return tuple(getattr(info, field) for field in fields)


@contextmanager
def _parent(path):
    _require(
        path.is_absolute() and ".." not in path.parts and path.name != "",
        "output/input path must be direct and absolute",
    )
    held, links = [], []
    try:
        held.append(os.open(path.anchor, _FLAGS | os.O_DIRECTORY))
        for name in path.parts[1:-1]:
            parent = held[-1]
            child = os.open(name, _FLAGS | os.O_DIRECTORY, dir_fd=parent)
            held.append(child)
            links.append(
                (parent, name, child, _identity(os.fstat(child), directory=True))
            )

        def guard():
            for parent, name, child, expected in links:
                _require(
                    expected
                    == _identity(os.fstat(child), directory=True)
                    == _identity(
                        os.stat(name, dir_fd=parent, follow_symlinks=False),
                        directory=True,
                    ),
                    "directory identity changed",
                )

        guard()
        yield held[-1], guard
        guard()
    finally:
        for descriptor in reversed(held):
            os.close(descriptor)


def _read_fixed(path, pin):
    with _parent(path) as (parent, guard):
        descriptor = os.open(path.name, _FLAGS, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            _require(
                stat.S_ISREG(before.st_mode)
                and before.st_nlink == 1
                and before.st_size == pin[0],
                "historical input is not one bounded regular file",
            )
            chunks, remaining = [], pin[0] + 1
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            guard()
            _require(
                _identity(before)
                == _identity(os.fstat(descriptor))
                == _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False))
                and (len(raw), binding._digest(raw)) == pin,
                "historical input changed or differs from pin",
            )
            return raw
        finally:
            os.close(descriptor)


def _absent(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise PinPreparationError("output already exists")


def _write_new(parent, name, raw):
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        remaining = memoryview(raw)
        while remaining:
            count = os.write(descriptor, remaining)
            _require(count > 0, "output write did not progress")
            remaining = remaining[count:]
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        _require(
            stat.S_ISREG(final.st_mode)
            and final.st_nlink == 1
            and final.st_size == len(raw)
            and _identity(final)
            == _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
            "output custody changed",
        )
    finally:
        os.close(descriptor)


class _Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, allow_abbrev=False)

    def error(self, message):
        raise PinPreparationError("invalid command arguments")


def main(argv=None):
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(
        dest="command", required=True, parser_class=_Parser
    )
    prepare = commands.add_parser(
        "prepare",
        help="Write fixed historical expectations and explicit provenance offline",
    )
    prepare.add_argument("--out", required=True)
    prepare.add_argument("--provenance-out", required=True)
    try:
        args = parser.parse_args(argv)
        output, provenance_output = Path(args.out), Path(args.provenance_out)
        _require(output != provenance_output, "output paths must be distinct")
        with (
            _parent(output) as (manifest_parent, manifest_guard),
            _parent(provenance_output) as (provenance_parent, provenance_guard),
        ):
            _require(
                (
                    os.fstat(manifest_parent).st_dev,
                    os.fstat(manifest_parent).st_ino,
                    output.name,
                )
                != (
                    os.fstat(provenance_parent).st_dev,
                    os.fstat(provenance_parent).st_ino,
                    provenance_output.name,
                ),
                "output identities must be distinct",
            )
            _absent(manifest_parent, output.name)
            _absent(provenance_parent, provenance_output.name)
            manifest, provenance = prepare_pin_documents(
                _read_fixed(_ROOT / _CAPTURE, _CAPTURE_PIN),
                _read_fixed(_ROOT / _IMAGE_RECORD, _IMAGE_PIN),
            )
            manifest_raw = binding.canonical_json(manifest)
            provenance_raw = binding.canonical_json(provenance) + b"\n"
            manifest_guard()
            provenance_guard()
            _write_new(provenance_parent, provenance_output.name, provenance_raw)
            _write_new(manifest_parent, output.name, manifest_raw)
            _read_fixed(
                provenance_output,
                (len(provenance_raw), binding._digest(provenance_raw)),
            )
            _read_fixed(output, (len(manifest_raw), binding._digest(manifest_raw)))
        result = {
            "schema": _SCHEMA,
            "status": "PREPARED",
            "manifest": {
                "path": str(output),
                "bytes": len(manifest_raw),
                "digest": binding._digest(manifest_raw),
            },
            "provenance": {
                "path": str(provenance_output),
                "bytes": len(provenance_raw),
                "digest": binding._digest(provenance_raw),
            },
            "live_deployment_attested": False,
            "phase3_eligible": False,
        }
    except (OSError, ValueError) as exc:
        message = (
            str(exc)
            if isinstance(exc, PinPreparationError)
            else "local input/output refused"
        )
        print(
            binding.canonical_json(
                {"schema": _SCHEMA, "status": "REFUSED", "error": message}
            ).decode("utf-8")
        )
        return 2
    print(binding.canonical_json(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
