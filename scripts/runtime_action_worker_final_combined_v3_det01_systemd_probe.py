#!/usr/bin/env python3
"""Capture one fresh, bounded DET-01 V3 replay observation."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class Det01CaptureError(RuntimeError):
    """The fresh DET-01 capture left its bounded contract."""


_PYTHON = Path("/usr/local/bin/python3.12")
_HARNESS = Path("/run/aragorn-harness.json")
_OUTPUT = Path(
    "/evidence/runtime-action-worker-final-combined-v3-det01-systemd.json"
)
_CAMPAIGN_ROOT = Path("/campaign")
_CASE_ROOT = _CAMPAIGN_ROOT / "cases" / "00-det-01"
_MATERIALIZER = Path("/src/scripts/materialize_openclaw_final_v3_det01.py")
_RUNNER = "run_admission_authority_replay.py"
_VECTOR = "deterministic-authority-vectors-v1.json"
_CASE_ID = "DET-01"
_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-det01-"
    "systemd-observation/v1"
)
_HARNESS_SCHEMA = (
    "aragorn/runtime-action-worker-final-combined-v3-det01-systemd-harness/v1"
)
_AUTHORITY = (
    "BOUND_FINAL_COMBINED_V3_RAW_DET01_OBSERVATION_ONLY_"
    "NOT_PASS_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"
)
_PARENT_IMAGE = (
    "sha256:e0fa63e8c57a865b8209f47c21e7ba327f6c3300156c3366e6b4e4253b55521f"
)
_RUNTIME_VOLUME = "aragorn-openclaw-2026-7-1-phase3-final-7fa98d8-v1"
_RUNTIME_COMMIT = "7fa98d8e21b6d5937f25a7f19445ff683bb980bf"
_RUNTIME_TREE = "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44"
_BUNDLE = {
    "run_admission_authority_replay.py": (
        7_211,
        "sha256:e01776fd6fd66589f40bdd86dec80aa0451854e6e752740fe9e121b2e76ecb70",
        "probe",
    ),
    "deterministic-authority-vectors-v1.json": (
        11_875,
        "sha256:1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161",
        "vector",
    ),
    "aragorn/__init__.py": (
        78,
        "sha256:4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01",
        "probe-dependency",
    ),
    "aragorn/admission_decision.py": (
        16_879,
        "sha256:6ff41b17d151b89043757c5d0537e1540bd0c964618a6ea4b77f8b8195ce79ca",
        "probe-dependency",
    ),
    "aragorn/analyze.py": (
        29_366,
        "sha256:43796b5fdbca1fd0968ca87c5e8f640e3517867d6eed229c40980451471255a6",
        "probe-dependency",
    ),
    "aragorn/oci_worker_protocol.py": (
        22_775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
        "probe-dependency",
    ),
    "aragorn/policy.py": (
        5_174,
        "sha256:246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b",
        "probe-dependency",
    ),
}
_REPLAY_CONFIGURATION = {
    "case_ids": ["allow", "deny", "error", "review"],
    "input_limit_bytes": 65_536,
    "module": "aragorn.admission_decision",
    "output_limit_bytes": 4_096,
    "seeds": ["1", "2", "3"],
    "timeout_seconds": 5,
    "vector_set_digest": _BUNDLE[_VECTOR][1],
}
_REPLAY_IMPLEMENTATION = {
    "admission_decision_digest": _BUNDLE["aragorn/admission_decision.py"][1],
    "analyze_digest": _BUNDLE["aragorn/analyze.py"][1],
    "oci_worker_protocol_digest": _BUNDLE["aragorn/oci_worker_protocol.py"][1],
    "policy_digest": _BUNDLE["aragorn/policy.py"][1],
    "replay_runner_digest": _BUNDLE[_RUNNER][1],
}
_REPLAY_ADAPTER = {
    "configuration": _REPLAY_CONFIGURATION,
    "configuration_digest": (
        "sha256:2b6a971130a616139ce35824351755129b79707f35e41d89df77707d776acc77"
    ),
    "implementation": _REPLAY_IMPLEMENTATION,
    "implementation_digest": (
        "sha256:ee164cdbf731b59ccae4bebe9b496269714d1be404c76f82b4038fb7d0000ad8"
    ),
}
_REPLAY_LIMITATIONS = [
    "DECISION_ONLY_NOT_INSTALLER_AUTHORITY",
    "LOCAL_PROCESS_SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
    "SOURCE_ANALYZER_RESULTS_ARE_FIXED_RETAINED_VECTORS",
]
_REPLAY_RESULTS = (
    (
        "allow",
        "sha256:7357033ae5de0dddcddde295db6a0eb3495c60b86dff720edf8e4c88e2ee4168",
        "sha256:2a634f0fb371a96c570484a22408309efbb0432379c927926a42350444d141f8",
    ),
    (
        "deny",
        "sha256:f271745c0fc9896f0cea5bd260d0e0ce066c6854a7848f8a5c6bcc1872c9aef7",
        "sha256:21db334be8dbff781cdb8880b6413847398de3da9e1c9fd7324bb71619e62a8a",
    ),
    (
        "error",
        "sha256:9ebfae80f77a092c869fb14585e0705cefca0bb5e639997177f9ef3775ba6304",
        "sha256:c4c6f9501628fc4f4c34ae575c3ddccaa87910ea08ccfa4dc196ad0f58632ce6",
    ),
    (
        "review",
        "sha256:b6b9b867d20505a0e52d0eccd94d98f409fa64e01238dbf8fa8cbc1f5e6983ba",
        "sha256:ff0e0371dc24740faefb75960d08df1a7bec33984522c7bc4b49093867f2ede4",
    ),
)
_EMPTY_DIGEST = (
    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
_SOURCE_PINS = {
    "/src/scripts/materialize_openclaw_final_v3_det01.py": (
        6_960,
        "sha256:42af9e1c895a2e63de4c5803b5fb0dfc9aedcef2b164e4d8bd53b4cbf1660081",
        "0555",
    ),
    "/src/scripts/run_admission_authority_replay.py": (
        7_330,
        "sha256:43be1290771abc4c6664faa262a0c366e8078a3f8aa5143d05b747e01030b966",
        "0444",
    ),
    "/src/benchmark/admission/openclaw-v2026.7.1/"
    "deterministic-authority-vectors-v1.json": (
        11_875,
        "sha256:1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161",
        "0444",
    ),
    "/src/src/aragorn/__init__.py": (
        78,
        "sha256:4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01",
        "0444",
    ),
    "/src/src/aragorn/admission_decision.py": (
        16_879,
        "sha256:6ff41b17d151b89043757c5d0537e1540bd0c964618a6ea4b77f8b8195ce79ca",
        "0444",
    ),
    "/src/src/aragorn/analyze.py": (
        29_366,
        "sha256:43796b5fdbca1fd0968ca87c5e8f640e3517867d6eed229c40980451471255a6",
        "0444",
    ),
    "/src/src/aragorn/oci_worker_protocol.py": (
        22_775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
        "0444",
    ),
    "/src/src/aragorn/policy.py": (
        5_174,
        "sha256:246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b",
        "0444",
    ),
}
_ELIGIBILITY_KEYS = (
    "admission_profile_eligible",
    "aggregate_admission_eligible",
    "det_01_eligible",
    "edr_eligible",
    "installer_work_eligible",
    "phase3_exit_eligible",
    "release_eligible",
    "run_01_eligible",
    "run_02_eligible",
    "run_eligible",
)
_LIMITATIONS = [
    "OBSERVED_IS_NOT_PASS",
    "DET01_FORMAL_QUALIFICATION_NOT_COMPOSED",
    "ONE_FRESH_LOCAL_PRIVILEGED_DOCKER_SYSTEMD_SUBFIXTURE_ONLY",
    "FRESHNESS_AND_DESTRUCTION_ARE_BOUND_TO_THIS_CAPTURE_WRAPPER_ONLY",
    "DECISION_ONLY_NOT_RUNTIME_ACTIVATION_OR_INSTALLER_AUTHORITY",
    "SOURCE_ANALYZER_RESULTS_ARE_FIXED_RETAINED_VECTORS",
    "PRIVATE_PATCHED_BUILD_NOT_OFFICIAL_OPENCLAW_RELEASE",
    "PUBLIC_NETWORK_DENIED",
    "NO_ADMISSION_AGGREGATE_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]
_STAGE = "BOOTSTRAP"


def _set_stage(value: str) -> None:
    global _STAGE
    _STAGE = value


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise Det01CaptureError(message)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _canonical(document: Any) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _expect(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise Det01CaptureError(f"non-finite JSON number: {value}")


def _load_canonical(raw: bytes, *, trailing_lf: bool, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Det01CaptureError(f"{label} is not strict JSON") from exc
    expected = _canonical(document) + (b"\n" if trailing_lf else b"")
    _expect(type(document) is dict and raw == expected, f"{label} is not canonical")
    return document


def _metadata(path: Path) -> dict[str, Any]:
    value = path.stat(follow_symlinks=False)
    kind = (
        "file"
        if stat.S_ISREG(value.st_mode)
        else "directory"
        if stat.S_ISDIR(value.st_mode)
        else "symlink"
        if stat.S_ISLNK(value.st_mode)
        else "other"
    )
    return {
        "device": value.st_dev,
        "gid": value.st_gid,
        "inode": value.st_ino,
        "mode": f"{stat.S_IMODE(value.st_mode):04o}",
        "nlink": value.st_nlink,
        "size": value.st_size,
        "type": kind,
        "uid": value.st_uid,
    }


def _file(path: Path) -> dict[str, Any]:
    _expect(path.is_file() and not path.is_symlink(), f"source file changed: {path}")
    before = path.stat(follow_symlinks=False)
    raw = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    _expect(
        (before.st_dev, before.st_ino, before.st_size)
        == (after.st_dev, after.st_ino, len(raw)),
        f"source file changed while reading: {path}",
    )
    return {
        "bytes": len(raw),
        "digest": _digest(raw),
        "path": str(path),
        "stat": _metadata(path),
    }


def _raw(raw: bytes) -> dict[str, Any]:
    return {
        "base64": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "digest": _digest(raw),
    }


def _decode_raw_record(
    record: dict[str, Any], *, label: str, maximum: int
) -> bytes:
    _expect(
        type(record) is dict
        and set(record) == {"base64", "bytes", "digest"}
        and type(record.get("base64")) is str
        and type(record.get("bytes")) is int
        and 0 <= record["bytes"] <= maximum
        and type(record.get("digest")) is str,
        f"{label} record changed",
    )
    try:
        raw = base64.b64decode(record["base64"], validate=True)
    except (ValueError, TypeError) as exc:
        raise Det01CaptureError(f"{label} base64 changed") from exc
    _expect(
        len(raw) == record["bytes"] and _digest(raw) == record["digest"],
        f"{label} bytes changed",
    )
    return raw


def _harness(path: Path = _HARNESS) -> dict[str, Any]:
    raw = path.read_bytes()
    document = _load_canonical(raw, trailing_lf=False, label="DET-01 harness")
    lineage = document.get("image_lineage")
    subfixture = document.get("subfixture_volume_identity")
    subfixture_mount = document.get("subfixture_mount")
    runtime = document.get("openclaw_runtime_volume_identity")
    runtime_mount = document.get("openclaw_runtime_mount")
    commit = document.get("source_commit")
    verification = document.get("source_commit_verification")
    match = (
        re.fullmatch(
            r"aragorn-phase3-final-combined-v3-det01-subfixture-([1-9][0-9]*)",
            subfixture.get("name", ""),
        )
        if type(subfixture) is dict
        else None
    )
    owner = f"{commit}:{match.group(1)}" if match else None
    expected_fields = {
        "capture_disposition",
        "container_id",
        "host_config",
        "image_id",
        "image_lineage",
        "image_reference",
        "openclaw_runtime_mount",
        "openclaw_runtime_volume",
        "openclaw_runtime_volume_identity",
        "parent_image_id",
        "platform",
        "profile_label",
        "run_image_reference",
        "schema",
        "source_commit",
        "source_commit_verification",
        "subfixture_mount",
        "subfixture_volume_identity",
    }
    _expect(
        set(document) == expected_fields
        and document.get("schema") == _HARNESS_SCHEMA
        and document.get("capture_disposition")
        == "EXPLICIT_OUTPUT_ONLY_NOT_RETAINED_EVIDENCE"
        and type(commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", commit) is not None
        and type(document.get("container_id")) is str
        and re.fullmatch(r"[0-9a-f]{64}", document["container_id"]) is not None
        and type(document.get("image_id")) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", document["image_id"])
        is not None
        and document.get("parent_image_id") == _PARENT_IMAGE
        and document.get("image_reference")
        == "aragorn-phase3-final-combined-v3-det01-systemd"
        and document.get("run_image_reference") == document.get("image_id")
        and document.get("platform") == "linux"
        and document.get("profile_label") == "phase3-final-combined-v3-det01"
        and document.get("openclaw_runtime_volume") == _RUNTIME_VOLUME
        and type(lineage) is dict
        and set(lineage) == {"added_layers", "child", "parent"}
        and set(lineage.get("parent", {})) == {"id", "layers", "rootfs_type"}
        and set(lineage.get("child", {})) == {"id", "layers", "rootfs_type"}
        and lineage["parent"]["rootfs_type"] == "layers"
        and lineage["child"]["rootfs_type"] == "layers"
        and type(lineage["parent"]["layers"]) is list
        and type(lineage["child"]["layers"]) is list
        and len(lineage["child"]["layers"]) > len(lineage["parent"]["layers"])
        and lineage.get("parent", {}).get("id") == _PARENT_IMAGE
        and lineage.get("child", {}).get("id") == document.get("image_id")
        and lineage.get("child", {}).get("layers", [])[: len(lineage["parent"]["layers"])]
        == lineage["parent"]["layers"]
        and lineage.get("added_layers")
        == lineage.get("child", {}).get("layers", [])[len(lineage["parent"]["layers"]) :]
        and match is not None
        and subfixture
        == {
            "driver": "local",
            "labels": {
                "dev.aragorn.capture-owner": owner,
                "dev.aragorn.role": "final-combined-v3-det01-subfixture",
                "dev.aragorn.source-commit": commit,
            },
            "name": subfixture["name"],
            "options": None,
            "scope": "local",
        }
        and subfixture_mount
        == {
            "destination": "/campaign",
            "driver": "local",
            "mode": "rw",
            "rw": True,
            "source": subfixture["name"],
            "type": "volume",
        }
        and runtime
        == {
            "driver": "local",
            "labels": {
                "io.aragorn.phase": "phase3-final",
                "io.aragorn.role": "installed-runtime",
                "io.aragorn.source-commit": _RUNTIME_COMMIT,
                "io.aragorn.source-tree": _RUNTIME_TREE,
            },
            "name": _RUNTIME_VOLUME,
            "options": None,
            "scope": "local",
        }
        and runtime_mount
        == {
            "destination": "/runtime",
            "driver": "local",
            "mode": "ro",
            "rw": False,
            "source": _RUNTIME_VOLUME,
            "type": "volume",
        },
        "outer DET-01 harness identity changed",
    )
    _expect(
        type(verification) is dict
        and set(verification)
        == {"command", "commit_object", "exit_code", "stderr", "stdout"}
        and verification["command"] == ["git", "verify-commit", "--raw", commit]
        and verification["exit_code"] == 0,
        "DET-01 signed source verification changed",
    )
    commit_raw = _decode_raw_record(
        verification["commit_object"], label="DET-01 commit object", maximum=1_048_576
    )
    verification_stdout = _decode_raw_record(
        verification["stdout"], label="DET-01 verify stdout", maximum=1_048_576
    )
    verification_stderr = _decode_raw_record(
        verification["stderr"], label="DET-01 verify stderr", maximum=1_048_576
    )
    _expect(
        hashlib.sha1(
            f"commit {len(commit_raw)}\0".encode("ascii") + commit_raw
        ).hexdigest()
        == commit
        and commit_raw.startswith(b"tree ")
        and b"\ngpgsig " in commit_raw
        and len(verification_stdout) + len(verification_stderr) > 0,
        "DET-01 signed source identity changed",
    )
    expected_binds = sorted(
        [
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            f"{_RUNTIME_VOLUME}:/runtime:ro",
            f"{subfixture['name']}:/campaign:rw",
        ]
    )
    _expect(
        document.get("host_config")
        == {
            "binds": expected_binds,
            "cgroupns_mode": "host",
            "ipc_mode": "private",
            "network_mode": "none",
            "privileged": True,
            "readonly_rootfs": False,
            "runtime": "runc",
            "security_opt": ["label=disable"],
            "tmpfs": {
                "/run": "rw,nosuid,nodev,noexec,mode=755",
                "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
            },
            "userns_mode": "",
        },
        "outer DET-01 host profile changed",
    )
    return {"digest": _digest(raw), "document": document}


def _source_artifacts() -> dict[str, Any]:
    dynamic = {
        "capture_recipe": Path(
            "/src/scripts/"
            "capture_runtime_action_worker_final_combined_v3_det01_systemd.sh"
        ),
        "collector": Path(__file__).resolve(),
        "dockerfile": Path(
            "/src/benchmark/runtime-action-worker-final-combined-v3-"
            "det01-systemd/Dockerfile"
        ),
    }
    result = {name: _file(path) for name, path in dynamic.items()}
    for record in result.values():
        expected_mode = "0444" if record["path"].endswith("Dockerfile") else "0555"
        _expect(
            record["stat"]
            == {
                **record["stat"],
                "gid": 0,
                "mode": expected_mode,
                "nlink": 1,
                "type": "file",
                "uid": 0,
            },
            "DET-01 capture source custody changed",
        )
    pinned = []
    for name, (size, digest, mode) in _SOURCE_PINS.items():
        record = _file(Path(name))
        _expect(
            record["bytes"] == size
            and record["digest"] == digest
            and record["stat"]
            == {
                **record["stat"],
                "gid": 0,
                "mode": mode,
                "nlink": 1,
                "type": "file",
                "uid": 0,
            },
            f"DET-01 pinned source changed: {name}",
        )
        pinned.append(record)
    result["pinned_sources"] = pinned
    return result


def _volume_snapshot(
    root: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> dict[str, Any]:
    _expect(root.is_dir() and not root.is_symlink(), "DET-01 volume root changed")
    result = {
        "entries": sorted(str(path.relative_to(root)) for path in root.rglob("*")),
        "root": _metadata(root),
    }
    _expect(
        result["root"]
        == {
            **result["root"],
            "gid": expected_gid,
            "mode": "0755",
            "type": "directory",
            "uid": expected_uid,
        },
        "DET-01 volume root custody changed",
    )
    return result


def _bundle(
    root: Path, *, expected_uid: int = 0, expected_gid: int = 0
) -> list[dict[str, Any]]:
    _expect(root.is_dir() and not root.is_symlink(), "DET-01 bundle root changed")
    entries = {str(path.relative_to(root)) for path in root.rglob("*")}
    _expect(entries == {"aragorn", *_BUNDLE}, "DET-01 bundle inventory changed")
    _expect(
        stat.S_IMODE(root.stat(follow_symlinks=False).st_mode) == 0o555
        and stat.S_IMODE(
            (root / "aragorn").stat(follow_symlinks=False).st_mode
        )
        == 0o555,
        "DET-01 bundle directory custody changed",
    )
    records = []
    for name, (size, digest, role) in _BUNDLE.items():
        record = _file(root / name)
        _expect(
            record["bytes"] == size
            and record["digest"] == digest
            and record["stat"]
            == {
                **record["stat"],
                "gid": expected_gid,
                "mode": "0444",
                "nlink": 1,
                "type": "file",
                "uid": expected_uid,
            },
            f"DET-01 bundle file changed: {name}",
        )
        records.append(
            {
                "bytes": size,
                "digest": digest,
                "mode": "0444",
                "name": name,
                "role": role,
            }
        )
    return records


def _command(
    argv: list[str], *, cwd: Path, timeout: int, environment: dict[str, str]
) -> tuple[dict[str, Any], bytes]:
    started_at = _iso_now()
    result = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    completed_at = _iso_now()
    _expect(type(result.returncode) is int, "DET-01 process status changed")
    return (
        {
            "argv": argv,
            "completed_at": completed_at,
            "cwd": str(cwd),
            "environment": environment,
            "exit_code": result.returncode,
            "started_at": started_at,
            "stderr": _raw(result.stderr),
            "stdout": _raw(result.stdout),
        },
        result.stdout,
    )


def _execution_profile(python: Path, root: Path) -> dict[str, Any]:
    return {
        "argv": [str(python), "-m", "aragorn.admission_decision"],
        "cwd": str(root.resolve()),
        "executable_digest": _digest(python.read_bytes()),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "system": platform.platform(),
    }


def _expected_replays() -> list[dict[str, Any]]:
    return [
        {
            "case_id": case_id,
            "replays": [
                {
                    "exit_code": 0,
                    "seed": seed,
                    "stdin_digest": stdin_digest,
                    "stderr_digest": _EMPTY_DIGEST,
                    "stdout_digest": stdout_digest,
                }
                for seed in ("1", "2", "3")
            ],
        }
        for case_id, stdin_digest, stdout_digest in _REPLAY_RESULTS
    ]


def _verify_replay_shape(
    raw: bytes, *, python: Path = _PYTHON, root: Path = _CASE_ROOT
) -> dict[str, Any]:
    _expect(len(raw) <= 1_048_576, "DET-01 replay output exceeded bound")
    document = _load_canonical(raw, trailing_lf=True, label="DET-01 replay")
    recorded_at = document.get("recorded_at")
    cases = document.get("cases")
    _expect(
        set(document)
        == {
            "adapter",
            "assurance",
            "cases",
            "environment",
            "limitations",
            "recorded_at",
            "schema",
            "vector_set_digest",
        }
        and document.get("schema")
        == "aragorn/admission-authority-replay-evidence/v1"
        and document.get("assurance")
        == "SELF_REPORTED_LOCAL_PROCESS_NOT_INDEPENDENTLY_ATTESTED"
        and document.get("vector_set_digest") == _BUNDLE[_VECTOR][1]
        and type(recorded_at) is str
        and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
            recorded_at,
        )
        is not None,
        "DET-01 replay identity changed",
    )
    try:
        datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Det01CaptureError("DET-01 replay timestamp changed") from exc
    _expect(document.get("adapter") == _REPLAY_ADAPTER, "DET-01 replay adapter changed")
    profile = _execution_profile(python, root)
    _expect(
        document.get("environment")
        == {"profile": profile, "profile_digest": _digest(_canonical(profile))},
        "DET-01 replay environment changed",
    )
    _expect(
        document.get("limitations") == _REPLAY_LIMITATIONS,
        "DET-01 replay limitations changed",
    )
    _expect(
        type(cases) is list
        and all(
            type(case) is dict
            and type(case.get("replays")) is list
            and all(
                type(item) is dict and type(item.get("exit_code")) is int
                for item in case["replays"]
            )
            for case in cases
        )
        and cases == _expected_replays(),
        "DET-01 replay determinism changed",
    )
    return document


def _destroy_cases(cases: Path) -> None:
    if cases.exists() or cases.is_symlink():
        _expect(cases.is_dir() and not cases.is_symlink(), "DET-01 cases root changed")
        for path in sorted(cases.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            if path.is_dir() and not path.is_symlink():
                path.chmod(0o755)
        cases.chmod(0o755)
        shutil.rmtree(cases)


def _run_subfixture(
    campaign_root: Path = _CAMPAIGN_ROOT,
    materializer: Path = _MATERIALIZER,
    python: Path = _PYTHON,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> dict[str, Any]:
    before = _volume_snapshot(
        campaign_root, expected_uid=expected_uid, expected_gid=expected_gid
    )
    _expect(before["entries"] == [], "DET-01 subfixture volume was not empty")
    cases = campaign_root / "cases"
    case_root = cases / "00-det-01"
    _expect(not cases.exists() and not case_root.exists(), "DET-01 path was reused")
    cases.mkdir(mode=0o755)
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
    }
    try:
        _set_stage("MATERIALIZE_FRESH_SUBFIXTURE")
        materializer_record, manifest_raw = _command(
            [str(python), str(materializer), str(case_root)],
            cwd=Path("/src") if str(materializer).startswith("/src/") else materializer.parents[1],
            timeout=30,
            environment=environment,
        )
        _expect(
            materializer_record["exit_code"] == 0
            and materializer_record["stderr"]["bytes"] == 0,
            "DET-01 materializer did not exit cleanly",
        )
        manifest = _load_canonical(
            manifest_raw, trailing_lf=True, label="DET-01 materializer manifest"
        )
        bundle = _bundle(
            case_root, expected_uid=expected_uid, expected_gid=expected_gid
        )
        _expect(
            manifest
            == {
                "schema": (
                    "aragorn/openclaw-final-admission-v3-"
                    "materialized-probe-bundle/v1"
                ),
                "authority": (
                    "PINNED_V3_PROBE_BUNDLE_ONLY_NOT_EXECUTION_OR_"
                    "QUALIFICATION_AUTHORITY"
                ),
                "case_id": _CASE_ID,
                "files": [
                    {"bytes": item["bytes"], "digest": item["digest"], "name": item["name"]}
                    for item in bundle
                ],
            },
            "DET-01 materializer manifest changed",
        )
        vector_raw = (case_root / _VECTOR).read_bytes()
        _expect(
            len(vector_raw) == _BUNDLE[_VECTOR][0]
            and _digest(vector_raw) == _BUNDLE[_VECTOR][1],
            "DET-01 vector bytes changed",
        )
        _set_stage("EXECUTE_DETERMINISTIC_REPLAY")
        replay_record, replay_raw = _command(
            [str(python), str(case_root / _RUNNER)],
            cwd=case_root,
            timeout=30,
            environment=environment,
        )
        _expect(
            replay_record["exit_code"] == 0
            and replay_record["stderr"]["bytes"] == 0,
            "DET-01 replay did not exit cleanly",
        )
        replay = _verify_replay_shape(replay_raw, python=python, root=case_root)
        during = _volume_snapshot(
            campaign_root, expected_uid=expected_uid, expected_gid=expected_gid
        )
        _expect(
            during["entries"]
            == sorted(
                [
                    "cases",
                    "cases/00-det-01",
                    "cases/00-det-01/aragorn",
                    *[f"cases/00-det-01/{name}" for name in _BUNDLE],
                ]
            ),
            "DET-01 subfixture volume inventory changed",
        )
        result = {
            "bundle": bundle,
            "lifecycle": {
                "before_materialization": before,
                "during_execution": during,
                "root": str(case_root),
            },
            "materializer": {
                "command": materializer_record,
                "manifest": manifest,
            },
            "replay": {
                "command": replay_record,
                "document": replay,
            },
            "vector_set": _raw(vector_raw),
        }
    finally:
        _set_stage("DESTROY_SUBFIXTURE")
        _destroy_cases(cases)
    after = _volume_snapshot(
        campaign_root, expected_uid=expected_uid, expected_gid=expected_gid
    )
    _expect(after["entries"] == [], "DET-01 subfixture destruction failed")
    result["lifecycle"]["after_destruction"] = after
    result["lifecycle"]["destroyed_before_capture_return"] = True
    result["lifecycle"]["fresh_path_observed"] = True
    return result


def _decision(status: str) -> dict[str, Any]:
    _expect(status in {"NOT_TESTED", "OBSERVED"}, "DET-01 status changed")
    return {
        "status": (
            "FINAL_COMBINED_V3_DET01_OBSERVED_PROFILE_NOT_TESTED"
            if status == "OBSERVED"
            else "FINAL_COMBINED_V3_DET01_NOT_TESTED_PROFILE_NOT_TESTED"
        ),
        "det01_observation_status": status,
        "det01_fail_count": 0,
        "det01_not_tested_count": 1,
        "det01_pass_count": 0,
        **{key: False for key in _ELIGIBILITY_KEYS},
    }


def _collect() -> dict[str, Any]:
    _set_stage("VERIFY_OUTER_HARNESS")
    harness = _harness()
    _set_stage("VERIFY_CAPTURE_SOURCES")
    artifacts = _source_artifacts()
    _set_stage("RUN_FRESH_SUBFIXTURE")
    subfixture = _run_subfixture()
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "case_id": _CASE_ID,
        "recorded_at": _iso_now(),
        "harness": harness,
        "source_artifacts": artifacts,
        "subfixture": subfixture,
        "decision": _decision("OBSERVED"),
        "limitations": list(_LIMITATIONS),
    }


def _failure(exc: Exception) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "case_id": _CASE_ID,
        "recorded_at": _iso_now(),
        "decision": _decision("NOT_TESTED"),
        "failure": {
            "code": "LIVE_CAPTURE_FAILED_CLOSED",
            "message": str(exc)[:4_096],
            "stage": _STAGE,
            "type": type(exc).__name__,
        },
        "limitations": ["NO_DET01_OR_ADMISSION_AUTHORITY_FROM_FAILED_CAPTURE"],
    }


def _publish(path: Path, document: dict[str, Any]) -> None:
    raw = _canonical(document) + b"\n"
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        written = 0
        while written < len(raw):
            count = os.write(descriptor, raw[written:])
            _expect(count > 0, "DET-01 observation write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        print(
            "usage: runtime_action_worker_final_combined_v3_"
            "det01_systemd_probe.py",
            file=sys.stderr,
        )
        return 64
    try:
        result = _collect()
        status = 0
    except Exception as exc:  # noqa: BLE001 - failed captures self-describe
        result = _failure(exc)
        status = 2
    _publish(_OUTPUT, result)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
