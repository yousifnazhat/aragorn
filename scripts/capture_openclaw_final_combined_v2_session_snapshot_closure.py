#!/usr/bin/env python3
"""Emit one provenance-bound read-only V2 session-snapshot closure receipt."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_RELATIVE_SCRIPT = Path("scripts") / Path(__file__).name
_BASE = Path("benchmark/admission/openclaw-v2026.7.1")
_MANIFEST_PATH = (
    _BASE
    / "protected-final-combined-v2-session-snapshot-compiled-closure-v1.manifest.json"
)
_ARCHIVE_PATH = (
    _BASE
    / "protected-final-combined-v2-session-snapshot-compiled-closure-v1.tar.gz"
)
_ROUTE_EVIDENCE_PATH = Path("benchmark/evidence") / (
    "runtime-action-worker-final-combined-v2-route-session-snapshot-consumer-"
    "systemd-p3-final-2026-08-22.json"
)
_MANIFEST_IDENTITY = {
    "bytes": 2_948,
    "digest": "sha256:2c869e872b6050c201e407261136d482d1c84f40235b1b9cbf09534a0097a6e9",
}
_ARCHIVE_IDENTITY = {
    "bytes": 338_999,
    "digest": "sha256:f5f93401fe3089a7a74aa790e113be6d9f8ebadcf5f3e3cb521abecf1cb9e588",
}
_ROUTE_EVIDENCE_IDENTITY = {
    "bytes": 600_445,
    "digest": "sha256:58e59c491164b53b3a39b6b07b63dfee77384b0bf0b0642f257a493d86597165",
}
_ROUTE_SOURCE_COMMIT = "c30e43b5ef8a47b6b3865fd2188e4789a6054642"
_ROUTE_RETENTION_COMMIT = "1dca11064d9b4cf25473148b6873202bc2ca5d0a"
_ROUTE_RETENTION_BLOB = "bb2c455b595ad6cd0a114b184418f5f4ec234965"
_ROUTE_IMAGE = "sha256:293a3407dee23bb7e4f8bcd2aa885c78558fb27293ecd8c8bb06429972a89561"
_ACQUISITION_IMAGE_ID = (
    "sha256:d40892e8fca9ce2c5fd3b381c95cb4df8ff1c3f27f101802ac9c936ca2fdd35e"
)
_ACQUISITION_IMAGE = "aragorn-phase3-final-combined-v2-systemd@" + _ACQUISITION_IMAGE_ID
_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_SIGNING_KEY = "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"
_HELPER = "/route-input/session-snapshot-consumer/protected-observation-v1.mjs"
_HELPER_IDENTITY = {
    "bytes": 16_324,
    "digest": "sha256:13baaac69f323603f2029eb1dc675f7438d51e0b9440befe775758a38c09a321",
}
_RUNTIME_TREE = {
    "algorithm": "aragorn/runtime-tree/v1",
    "entry_count": 45_860,
    "file_count": 45_841,
    "symlink_count": 19,
    "total_bytes": 369_443_243,
    "tree_digest": "sha256:5d09f482ad1cb177eae168eaea074f6d2a6ec976d16042a3e1d665cc2371f154",
}
_PATHS = (
    "lib/node_modules/openclaw/dist/agent-command-DTQcyNEV.js",
    "lib/node_modules/openclaw/dist/attempt-execution-D1Tem6Ut.js",
    "lib/node_modules/openclaw/dist/attempt.model-diagnostic-events-C1p7GcKr.js",
    "lib/node_modules/openclaw/dist/embedded-agent-UzpuyD8i.js",
    "lib/node_modules/openclaw/dist/selection-CqQ5E0T1.js",
    "lib/node_modules/openclaw/dist/session-snapshot-C3iM3syv.js",
    "lib/node_modules/openclaw/dist/session-snapshot-CUCETeUr.js",
    "lib/node_modules/openclaw/dist/session-store.runtime-BQlNbwhS.js",
    "lib/node_modules/openclaw/dist/session-store.runtime.js",
    "lib/node_modules/openclaw/dist/skill-prompt-blobs-zJRX9N65.js",
    "lib/node_modules/openclaw/dist/store-Bn4xSDrE.js",
    "lib/node_modules/openclaw/dist/system-prompt-config-C1imAkur.js",
    "lib/node_modules/openclaw/dist/system-prompt-report-jSGxzBCq.js",
    "lib/node_modules/openclaw/dist/workspace-DvqxsRU0.js",
)
_ELIGIBILITY_KEYS = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_COMMAND_OUTPUT = 8 * 1024 * 1024
_MAX_TAR_BYTES = 4 * 1024 * 1024
_GIT_ENV = {**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"}


class CaptureError(RuntimeError):
    """The local acquisition no longer matches its exact signed inputs."""


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CaptureError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                CaptureError(f"non-finite JSON value in {label}: {constant}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CaptureError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CaptureError(f"{label} is not an object")
    return value


def _run(arguments: list[str], *, maximum: int = _MAX_COMMAND_OUTPUT) -> bytes:
    result = subprocess.run(arguments, check=False, capture_output=True)
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        raise CaptureError(f"command output exceeded limit: {arguments[0]}")
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise CaptureError(
            f"command failed ({result.returncode}): {arguments[0]}: {message}"
        )
    return result.stdout


def _git(arguments: list[str], *, maximum: int = _MAX_COMMAND_OUTPUT) -> bytes:
    result = subprocess.run(
        ["git", *arguments], check=False, capture_output=True, env=_GIT_ENV
    )
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        raise CaptureError("Git command output exceeded limit")
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise CaptureError(f"Git command failed ({result.returncode}): {message}")
    return result.stdout


def _file_identity(path: Path) -> dict[str, Any]:
    raw = (_ROOT / path).read_bytes()
    return {"bytes": len(raw), "digest": _digest(raw), "path": path.as_posix()}


def _verify_identity(raw: bytes, expected: dict[str, Any], label: str) -> None:
    if len(raw) != expected["bytes"] or _digest(raw) != expected["digest"]:
        raise CaptureError(f"{label} identity changed")


def _verify_bundle() -> tuple[dict[str, Any], bytes, dict[str, bytes]]:
    manifest_raw = (_ROOT / _MANIFEST_PATH).read_bytes()
    archive_raw = (_ROOT / _ARCHIVE_PATH).read_bytes()
    _verify_identity(manifest_raw, _MANIFEST_IDENTITY, "closure manifest")
    _verify_identity(archive_raw, _ARCHIVE_IDENTITY, "closure archive")
    manifest = _load_json(manifest_raw, "closure manifest")
    if (
        _canonical(manifest) + b"\n" != manifest_raw
        or set(manifest) != {"entries", "runtime_root", "runtime_tree", "schema"}
        or manifest["runtime_root"] != "/runtime"
        or manifest["runtime_tree"] != _RUNTIME_TREE
        or manifest["schema"]
        != "aragorn/openclaw-protected-final-combined-v2-session-snapshot-compiled-closure-manifest/v1"
        or not isinstance(manifest["entries"], list)
        or len(manifest["entries"]) != len(_PATHS)
    ):
        raise CaptureError("closure manifest contract changed")
    for item, path in zip(manifest["entries"], _PATHS):
        if (
            not isinstance(item, dict)
            or set(item) != {"bytes", "path", "sha256", "type"}
            or type(item["bytes"]) is not int
            or item["bytes"] <= 0
            or item["path"] != path
            or item["type"] != "regular"
            or not isinstance(item["sha256"], str)
            or _DIGEST.fullmatch(item["sha256"]) is None
        ):
            raise CaptureError(f"closure manifest entry changed: {path}")

    if archive_raw[:10] != bytes.fromhex("1f8b08000000000002ff"):
        raise CaptureError("closure gzip header changed")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(archive_raw), mode="rb") as compressed:
            tar_raw = compressed.read(_MAX_TAR_BYTES + 1)
            if len(tar_raw) > _MAX_TAR_BYTES or compressed.read(1):
                raise CaptureError("closure archive exceeds limit")
        with tarfile.open(fileobj=io.BytesIO(tar_raw), mode="r:") as bundle:
            members = bundle.getmembers()
            names = ["manifest.json", *_PATHS]
            if [member.name for member in members] != names:
                raise CaptureError("closure archive inventory changed")
            files: dict[str, bytes] = {}
            for member in members:
                if (
                    not member.isfile()
                    or member.mode != 0o444
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != 0
                    or member.pax_headers
                ):
                    raise CaptureError(f"closure metadata changed: {member.name}")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise CaptureError(f"closure member unreadable: {member.name}")
                raw = stream.read(member.size + 1)
                if len(raw) != member.size or stream.read(1):
                    raise CaptureError(f"closure member truncated: {member.name}")
                files[member.name] = raw
    except CaptureError:
        raise
    except (EOFError, OSError, tarfile.TarError) as exc:
        raise CaptureError(f"invalid closure archive: {exc}") from exc
    if files.pop("manifest.json") != manifest_raw:
        raise CaptureError("closure internal manifest changed")
    for item in manifest["entries"]:
        raw = files[item["path"]]
        if len(raw) != item["bytes"] or _digest(raw) != item["sha256"]:
            raise CaptureError(f"closure member identity changed: {item['path']}")
    return manifest, archive_raw, files


def _verify_signature(commit: str) -> None:
    result = subprocess.run(
        ["git", "verify-commit", "--raw", commit],
        check=False,
        capture_output=True,
        env=_GIT_ENV,
    )
    if (
        result.returncode != 0
        or result.stdout
        or _SIGNING_KEY.encode() not in result.stderr
        or b'Good "git" signature for yousif.snazhat@gmail.com' not in result.stderr
    ):
        raise CaptureError(f"commit signature changed: {commit}")


def _tree_file(commit: str, path: Path) -> dict[str, Any]:
    entry = _git(["ls-tree", "-z", "--full-name", commit, "--", path.as_posix()])
    if not entry.endswith(b"\0") or entry.count(b"\0") != 1:
        raise CaptureError(f"signed tree entry changed: {path}")
    metadata, returned = entry[:-1].split(b"\t", 1)
    mode, kind, blob = metadata.decode("ascii").split(" ")
    expected_mode = "100755" if path == _RELATIVE_SCRIPT else "100644"
    if (
        mode != expected_mode
        or kind != "blob"
        or returned.decode() != path.as_posix()
    ):
        raise CaptureError(f"signed tree file changed: {path}")
    raw = _git(["cat-file", "blob", blob], maximum=4 * 1024 * 1024)
    if raw != (_ROOT / path).read_bytes():
        raise CaptureError(f"working file differs from signed tree: {path}")
    return {**_file_identity(path), "blob": blob, "mode": mode}


def _source_identity() -> dict[str, Any]:
    if (
        Path(_git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve()
        != _ROOT
        or _git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
        or _git(["status", "--porcelain=v1", "--untracked-files=all"])
    ):
        raise CaptureError("acquisition requires the exact clean repository")
    commit = _git(["rev-parse", "HEAD"]).decode().strip()
    parent = _git(["rev-parse", "HEAD^"]).decode().strip()
    tree = _git(["rev-parse", "HEAD^{tree}"]).decode().strip()
    for signed in (commit, _ROUTE_SOURCE_COMMIT, _ROUTE_RETENTION_COMMIT):
        _verify_signature(signed)
    route_entry = _tree_file(_ROUTE_RETENTION_COMMIT, _ROUTE_EVIDENCE_PATH)
    if route_entry["blob"] != _ROUTE_RETENTION_BLOB:
        raise CaptureError("route retention blob changed")
    return {
        "commit": commit,
        "parent": parent,
        "tree": tree,
        "signature": {
            "key": _SIGNING_KEY,
            "signer": "yousif.snazhat@gmail.com",
            "status": "GOOD_LOCAL_VERIFICATION",
        },
        "files": {
            "acquisition": _tree_file(commit, _RELATIVE_SCRIPT),
            "archive": _tree_file(commit, _ARCHIVE_PATH),
            "manifest": _tree_file(commit, _MANIFEST_PATH),
            "route_evidence": route_entry,
        },
    }


def _route_evidence() -> tuple[dict[str, Any], dict[str, Any]]:
    raw = (_ROOT / _ROUTE_EVIDENCE_PATH).read_bytes()
    _verify_identity(raw, _ROUTE_EVIDENCE_IDENTITY, "route evidence")
    evidence = _load_json(raw, "route evidence")
    action = evidence["route_observation"]["document"]["action"]
    harness = evidence["composition"]["action"]["harness"]["document"]
    runtime_tree = action["prerequisites"]["runtime_tree_before"]
    if (
        evidence["route_id"] != "ADM-02/reload/session-snapshot-consumer"
        or evidence["decision"]["route_observation_status"] != "OBSERVED"
        or harness["source_commit"] != _ROUTE_SOURCE_COMMIT
        or harness["image_id"] != _ROUTE_IMAGE
        or evidence["composition"]["bindings"]["runtime_volume"] != _VOLUME
        or runtime_tree != _RUNTIME_TREE
        or action["observations"]["runtime_tree_after"] != _RUNTIME_TREE
    ):
        raise CaptureError("route evidence runtime binding changed")
    observed = action["observations"]["compiled_route_replay"]["module_files"]
    if not isinstance(observed, dict) or len(observed) != 11:
        raise CaptureError("route evidence compiled module inventory changed")
    return evidence, observed


def _docker_base() -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-v",
        f"{_VOLUME}:/runtime:ro",
    ]


def _live_acquisition(
    manifest: dict[str, Any], files: dict[str, bytes], observed: dict[str, Any]
) -> dict[str, Any]:
    image_raw = _run(["docker", "image", "inspect", _ACQUISITION_IMAGE])
    try:
        parsed_image = json.loads(image_raw, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as exc:
        raise CaptureError(f"invalid acquisition image inspect: {exc}") from exc
    if (
        not isinstance(parsed_image, list)
        or len(parsed_image) != 1
        or not isinstance(parsed_image[0], dict)
        or parsed_image[0].get("Id") != _ACQUISITION_IMAGE_ID
        or parsed_image[0].get("RepoDigests") != [_ACQUISITION_IMAGE]
    ):
        raise CaptureError("acquisition image identity changed")
    volume_raw = _run(["docker", "volume", "inspect", _VOLUME])
    try:
        parsed_volume = json.loads(volume_raw, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as exc:
        raise CaptureError(f"invalid runtime volume inspect: {exc}") from exc
    if not isinstance(parsed_volume, list) or len(parsed_volume) != 1:
        raise CaptureError("runtime volume inspect shape changed")
    volume = parsed_volume[0]
    selected_volume = {
        key: volume.get(key)
        for key in ("CreatedAt", "Driver", "Labels", "Name", "Options", "Scope")
    }
    expected_volume = {
        "CreatedAt": "2026-08-13T11:52:43-04:00",
        "Driver": "local",
        "Labels": {
            "io.aragorn.phase": "phase3-final",
            "io.aragorn.role": "installed-runtime",
            "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
            "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
        },
        "Name": _VOLUME,
        "Options": None,
        "Scope": "local",
    }
    if selected_volume != expected_volume:
        raise CaptureError("runtime volume identity changed")
    volume_users_command = [
        "docker",
        "ps",
        "--filter",
        f"volume={_VOLUME}",
        "--format",
        "{{.ID}}",
    ]
    if _run(volume_users_command).strip():
        raise CaptureError("runtime volume is mounted by another running container")

    tree_command = [
        *_docker_base(),
        "--entrypoint",
        "/usr/local/bin/node",
        _ACQUISITION_IMAGE,
        "--input-type=module",
        "-e",
        (
            f'import {{ runtimeTree }} from "file://{_HELPER}"; '
            'console.log(JSON.stringify(runtimeTree("/runtime")))'
        ),
    ]
    tree_before = _load_json(_run(tree_command).strip(), "live runtime tree before")
    if tree_before != _RUNTIME_TREE:
        raise CaptureError("live runtime tree changed")

    absolute_paths = [f"/runtime/{path}" for path in _PATHS]
    stat_command = [
        *_docker_base(),
        "--entrypoint",
        "/usr/bin/stat",
        _ACQUISITION_IMAGE,
        "--printf=%n\t%F\t%u\t%g\t%a\t%h\t%s\t%i\t%d\n",
        *absolute_paths,
    ]
    stat_raw = _run(stat_command)
    rows = stat_raw.decode("utf-8").splitlines()
    if len(rows) != len(_PATHS):
        raise CaptureError("live compiled module stat inventory changed")
    live_records = []
    by_manifest = {item["path"]: item for item in manifest["entries"]}
    observed_by_path = {
        item["path"].removeprefix("/runtime/"): item for item in observed.values()
    }
    devices: set[int] = set()
    inodes: set[int] = set()
    for row, relative in zip(rows, _PATHS):
        fields = row.split("\t")
        if len(fields) != 9:
            raise CaptureError(f"invalid live compiled module stat: {relative}")
        path, kind = fields[:2]
        try:
            uid, gid, mode, links, size, inode, device = map(int, fields[2:])
        except ValueError as exc:
            raise CaptureError(f"invalid live compiled module integer: {relative}") from exc
        item = by_manifest[relative]
        if (
            path != f"/runtime/{relative}"
            or kind != "regular file"
            or (uid, gid, mode, links, size) != (0, 0, 644, 1, item["bytes"])
            or inode <= 0
            or device <= 0
        ):
            raise CaptureError(f"live compiled module custody changed: {relative}")
        devices.add(device)
        if inode in inodes:
            raise CaptureError("live compiled modules share an inode")
        inodes.add(inode)
        record = {
            "device": device,
            "digest": item["sha256"],
            "gid": gid,
            "inode": inode,
            "mode": "0644",
            "nlink": links,
            "path": path,
            "size": size,
            "type": "file",
            "uid": uid,
            "observed_in_original_route": relative in observed_by_path,
        }
        if relative in observed_by_path:
            original = observed_by_path[relative]
            compared = {
                key: record[key]
                for key in (
                    "device",
                    "digest",
                    "gid",
                    "inode",
                    "nlink",
                    "path",
                    "size",
                    "type",
                    "uid",
                )
            }
            if compared != {key: original[key] for key in compared} or original["mode"] != "644":
                raise CaptureError(f"live module differs from route capture: {relative}")
        live_records.append(record)
    if len(devices) != 1 or len(observed_by_path) != 11:
        raise CaptureError("live compiled module volume binding changed")

    bytes_command = [
        *_docker_base(),
        "--entrypoint",
        "/bin/tar",
        _ACQUISITION_IMAGE,
        "-C",
        "/runtime",
        "-cf",
        "-",
        *_PATHS,
    ]
    source_tar = _run(bytes_command, maximum=_MAX_TAR_BYTES)
    try:
        with tarfile.open(fileobj=io.BytesIO(source_tar), mode="r:") as source:
            members = source.getmembers()
            if [member.name for member in members] != list(_PATHS):
                raise CaptureError("live compiled module byte inventory changed")
            for member in members:
                stream = source.extractfile(member)
                if stream is None or stream.read(member.size + 1) != files[member.name]:
                    raise CaptureError(f"live compiled module bytes changed: {member.name}")
    except CaptureError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise CaptureError(f"invalid live compiled module stream: {exc}") from exc

    helper_stat_command = [
        *_docker_base(),
        "--entrypoint",
        "/usr/bin/stat",
        _ACQUISITION_IMAGE,
        "--printf=%u:%g:%a:%h:%s",
        _HELPER,
    ]
    helper_digest_command = [
        *_docker_base(),
        "--entrypoint",
        "/usr/bin/sha256sum",
        _ACQUISITION_IMAGE,
        _HELPER,
    ]
    helper_stat_raw = _run(helper_stat_command)
    helper_digest_raw = _run(helper_digest_command)
    helper_digest = "sha256:" + helper_digest_raw.decode().split()[0]
    if (
        helper_stat_raw != b"0:0:444:1:16324"
        or helper_digest != _HELPER_IDENTITY["digest"]
    ):
        raise CaptureError("runtime tree helper identity changed")
    tree_after = _load_json(_run(tree_command).strip(), "live runtime tree after")
    if tree_after != tree_before or _run(volume_users_command).strip():
        raise CaptureError("runtime volume changed during acquisition")
    return {
        "acquisition_image": {
            "id": _ACQUISITION_IMAGE_ID,
            "reference": _ACQUISITION_IMAGE,
            "inspect_canonical_digest": _digest(_canonical(parsed_image[0])),
        },
        "runtime_volume": {
            "created_at": selected_volume["CreatedAt"],
            "driver": selected_volume["Driver"],
            "labels": selected_volume["Labels"],
            "name": selected_volume["Name"],
            "options": selected_volume["Options"],
            "scope": selected_volume["Scope"],
            "inspect_canonical_digest": _digest(_canonical(volume)),
            "runtime_tree_after": tree_after,
            "runtime_tree_before": tree_before,
        },
        "runtime_tree_helper": {
            **_HELPER_IDENTITY,
            "path": _HELPER,
            "stat": "0:0:0444:1:16324",
        },
        "module_files": live_records,
        "commands": {
            "module_bytes": bytes_command,
            "module_stats": stat_command,
            "runtime_tree_after": tree_command,
            "runtime_tree_before": tree_command,
            "runtime_tree_helper_digest": helper_digest_command,
            "runtime_tree_helper_stat": helper_stat_command,
            "volume_users_after": volume_users_command,
            "volume_users_before": volume_users_command,
        },
        "running_volume_users_after": [],
        "running_volume_users_before": [],
    }


def _receipt() -> dict[str, Any]:
    manifest, _, files = _verify_bundle()
    source = _source_identity()
    evidence, observed = _route_evidence()
    live = _live_acquisition(manifest, files, observed)
    return {
        "schema": (
            "aragorn/openclaw-protected-final-combined-v2-session-snapshot-"
            "compiled-closure-acquisition/v1"
        ),
        "authority": (
            "SIGNED_SOURCE_BOUND_READ_ONLY_LOCAL_VOLUME_ACQUISITION_"
            "NOT_ROUTE_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"
        ),
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": source,
        "original_route": {
            "capture_image_id": _ROUTE_IMAGE,
            "evidence": _file_identity(_ROUTE_EVIDENCE_PATH),
            "recorded_at": evidence["recorded_at"],
            "retention_commit": _ROUTE_RETENTION_COMMIT,
            "route_id": evidence["route_id"],
            "source_commit": _ROUTE_SOURCE_COMMIT,
        },
        "containment": {
            "capabilities_dropped": ["ALL"],
            "network_mode": "none",
            "no_new_privileges": True,
            "read_only_root_filesystem": True,
            "runtime_mount": {"destination": "/runtime", "mode": "ro", "source": _VOLUME},
        },
        "acquisition": live,
        "outputs": {
            "archive": {**_ARCHIVE_IDENTITY, "path": _ARCHIVE_PATH.as_posix()},
            "manifest": {**_MANIFEST_IDENTITY, "path": _MANIFEST_PATH.as_posix()},
            "archive_member_count": len(files) + 1,
            "archive_member_payload_bytes": sum(len(raw) for raw in files.values())
            + len((_ROOT / _MANIFEST_PATH).read_bytes()),
            "selected_module_payloads_match_live_volume": True,
        },
        "decision": {
            "status": "COMPILED_CLOSURE_ACQUIRED_ROUTE_REMAINS_NOT_TESTED",
            **{key: False for key in _ELIGIBILITY_KEYS},
        },
        "limitations": [
            "POST_ROUTE_READ_ONLY_ACQUISITION_BOUND_BY_IDENTICAL_FULL_RUNTIME_TREE",
            "ACQUISITION_IMAGE_DIFFERS_FROM_ORIGINAL_ROUTE_CAPTURE_IMAGE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "FOURTEEN_SELECTED_COMPILED_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "ORIGINAL_PROVIDER_REQUEST_AND_SESSION_STORE_RAW_BYTES_NOT_RETAINED",
            "NO_ROUTE_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--self-check"]:
        _verify_bundle()
        return 0
    if arguments:
        print(f"usage: {Path(__file__).name} [--self-check]", file=sys.stderr)
        return 64
    try:
        sys.stdout.buffer.write(_canonical(_receipt()) + b"\n")
    except (CaptureError, OSError, TypeError, ValueError) as exc:
        print(f"closure acquisition failed closed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
