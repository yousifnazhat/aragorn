"""Verify only the executable DET-01 V3 bundle and replay semantics."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from . import admission_evidence as retained
from .oci_worker_protocol import canonical_digest, canonical_json


class Det01ObservationError(ValueError):
    """The bounded DET-01 bundle or semantic observation changed."""


_CASE_ID = "DET-01"
_SCHEMA = "aragorn/openclaw-final-admission-v3-det01-semantic-observation/v1"
_AUTHORITY = (
    "DET01_BUNDLE_AND_REPLAY_SEMANTICS_ONLY_NO_FRESH_CAPTURE_OR_QUALIFICATION_AUTHORITY"
)
_MAX_OBSERVATION_BYTES = 1_048_576
_FILES = {
    "run_admission_authority_replay.py": (
        7_211,
        "sha256:e01776fd6fd66589f40bdd86dec80aa0451854e6e752740fe9e121b2e76ecb70",
    ),
    "deterministic-authority-vectors-v1.json": (
        11_875,
        "sha256:1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161",
    ),
    "aragorn/__init__.py": (
        78,
        "sha256:4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01",
    ),
    "aragorn/admission_decision.py": (
        16_879,
        "sha256:6ff41b17d151b89043757c5d0537e1540bd0c964618a6ea4b77f8b8195ce79ca",
    ),
    "aragorn/analyze.py": (
        29_366,
        "sha256:43796b5fdbca1fd0968ca87c5e8f640e3517867d6eed229c40980451471255a6",
    ),
    "aragorn/oci_worker_protocol.py": (
        22_775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
    ),
    "aragorn/policy.py": (
        5_174,
        "sha256:246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b",
    ),
}
_IMPLEMENTATION = {
    "admission_decision_digest": _FILES["aragorn/admission_decision.py"][1],
    "analyze_digest": _FILES["aragorn/analyze.py"][1],
    "oci_worker_protocol_digest": _FILES["aragorn/oci_worker_protocol.py"][1],
    "policy_digest": _FILES["aragorn/policy.py"][1],
    "replay_runner_digest": _FILES["run_admission_authority_replay.py"][1],
}
_FALSE_DECISION = {
    "admission_profile_eligible": False,
    "aggregate_admission_eligible": False,
    "det_01_eligible": False,
    "edr_eligible": False,
    "installer_work_eligible": False,
    "phase3_exit_eligible": False,
    "release_eligible": False,
    "run_01_eligible": False,
    "run_02_eligible": False,
    "run_eligible": False,
    "status": "SEMANTIC_OBSERVATION_VERIFIED_NOT_QUALIFIED",
}
_LIMITATIONS = [
    "NO_FRESH_V3_ISOLATED_SUBFIXTURE_CAPTURE_BOUND",
    "EXECUTION_ENVIRONMENT_SELF_REPORTED_NOT_INDEPENDENTLY_VERIFIED",
    "DECISION_ONLY_NOT_RUNTIME_ADMISSION_OR_INSTALLER_AUTHORITY",
    "NO_ADMISSION_INSTALLER_RUN_PHASE3_EDR_OR_RELEASE_AUTHORITY",
]


def verify_openclaw_final_v3_det01_observation(
    observation_raw: bytes, *, bundle_root: Path
) -> dict[str, Any]:
    """Verify bundle bytes and replay semantics without promoting DET-01."""

    try:
        files = _verify_bundle(bundle_root)
        observation = _load_canonical(observation_raw, "DET-01 observation")
        vector_raw = (
            bundle_root / "deterministic-authority-vectors-v1.json"
        ).read_bytes()
        vectors = _load_canonical(vector_raw, "DET-01 vectors")
        _verify_observation_identity(observation)
        _verify_replay_semantics(vectors, observation)
    except Det01ObservationError:
        raise
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise Det01ObservationError(f"invalid DET-01 observation: {exc}") from exc

    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "bindings": {
            "bundle_files": files,
            "bundle_files_canonical_digest": canonical_digest(files),
            "environment_profile_digest": observation["environment"]["profile_digest"],
            "environment_qualification": (
                "UNQUALIFIED_SELF_REPORTED_BOUNDED_SHAPE_ONLY"
            ),
            "observation": {
                "bytes": len(observation_raw),
                "digest": _digest(observation_raw),
            },
            "vector_set_digest": _FILES["deterministic-authority-vectors-v1.json"][1],
        },
        "case_id": _CASE_ID,
        "decision": dict(_FALSE_DECISION),
        "limitations": list(_LIMITATIONS),
        "recorded_at": observation["recorded_at"],
    }


def _verify_observation_identity(observation: dict[str, Any]) -> None:
    recorded_at = observation.get("recorded_at")
    if (
        observation.get("schema") != "aragorn/admission-authority-replay-evidence/v1"
        or type(recorded_at) is not str
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
            recorded_at,
        )
        is None
    ):
        raise Det01ObservationError("DET-01 observation identity changed")
    try:
        datetime.fromisoformat(recorded_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Det01ObservationError("DET-01 recorded_at is invalid") from exc

    environment = observation.get("environment")
    profile = environment.get("profile") if type(environment) is dict else None
    if (
        type(environment) is not dict
        or set(environment) != {"profile", "profile_digest"}
        or type(profile) is not dict
        or set(profile)
        != {
            "argv",
            "cwd",
            "executable_digest",
            "python_implementation",
            "python_version",
            "system",
        }
        or environment["profile_digest"] != canonical_digest(profile)
    ):
        raise Det01ObservationError("DET-01 environment profile shape changed")
    argv = profile["argv"]
    if (
        type(argv) is not list
        or len(argv) != 3
        or type(argv[0]) is not str
        or not argv[0].startswith("/")
        or len(argv[0]) > 4_096
        or argv[1:] != ["-m", "aragorn.admission_decision"]
        or type(profile["cwd"]) is not str
        or not profile["cwd"].startswith("/")
        or len(profile["cwd"]) > 4_096
        or type(profile["executable_digest"]) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", profile["executable_digest"]) is None
        or type(profile["python_implementation"]) is not str
        or not 1 <= len(profile["python_implementation"]) <= 64
        or type(profile["python_version"]) is not str
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", profile["python_version"]) is None
        or type(profile["system"]) is not str
        or not 1 <= len(profile["system"]) <= 1_024
        or any(
            "\x00" in value or "\n" in value
            for value in (
                argv[0],
                profile["cwd"],
                profile["python_implementation"],
                profile["system"],
            )
        )
    ):
        raise Det01ObservationError("DET-01 environment profile changed")


def _verify_replay_semantics(
    vectors: dict[str, Any], observation: dict[str, Any]
) -> None:
    adapter = observation.get("adapter")
    if (
        type(adapter) is not dict
        or adapter.get("implementation") != _IMPLEMENTATION
        or adapter.get("implementation_digest") != canonical_digest(_IMPLEMENTATION)
    ):
        raise Det01ObservationError("DET-01 implementation binding changed")
    cases = observation.get("cases")
    if type(cases) is not list or any(
        type(replay.get("exit_code")) is not int
        for case in cases
        if type(case) is dict
        for replay in case.get("replays", [])
        if type(replay) is dict
    ):
        raise Det01ObservationError("DET-01 process exit-code type changed")

    # The retained verifier pins the historical implementation identity. The
    # current bundle identity is checked above; normalize only that identity so
    # the unchanged vector, process-I/O, decision, policy, and runtime checks can
    # be reused without repinning unrelated retained qualification chains.
    normalized = deepcopy(observation)
    historical = retained._DETERMINISTIC_IMPLEMENTATION
    normalized["adapter"]["implementation"] = dict(historical)
    normalized["adapter"]["implementation_digest"] = canonical_digest(historical)
    retained._verify_deterministic_replay(
        _compatibility_receipt(vectors, normalized),
        vectors,
        normalized,
    )


def _compatibility_receipt(
    vectors: dict[str, Any], replay: dict[str, Any]
) -> dict[str, Any]:
    requests = [item["request"] for item in vectors["vectors"]]
    runtime = requests[0]["target_runtime"]["runtime"]
    implementation = retained._DETERMINISTIC_IMPLEMENTATION
    environment = replay["environment"]
    return {
        "recorded_at": replay["recorded_at"],
        "bindings": {
            "runtime": {
                key: runtime[key]
                for key in (
                    "commit",
                    "name",
                    "repository_url",
                    "source_tree_digest",
                    "version",
                )
            },
            "adapter": {
                "name": "openclaw-contained-deterministic-authority-replay",
                "implementation_digest": canonical_digest(implementation),
                "configuration_digest": replay["adapter"]["configuration_digest"],
            },
            "environment": {
                "worker_digest": environment["profile"]["executable_digest"],
                "os_profile_digest": environment["profile_digest"],
            },
            "aragorn": {
                "implementation_digest": canonical_digest(
                    {
                        key: implementation[key]
                        for key in (
                            "admission_decision_digest",
                            "analyze_digest",
                            "oci_worker_protocol_digest",
                            "policy_digest",
                        )
                    }
                ),
                "policy_digest": canonical_digest(
                    [request["policy"] for request in requests]
                ),
            },
        },
    }


def _verify_bundle(root: Path) -> list[dict[str, Any]]:
    if not isinstance(root, Path) or root.is_symlink() or not root.is_dir():
        raise Det01ObservationError("DET-01 bundle root must be one directory")
    expected_entries = {"aragorn", *_FILES}
    observed_entries = {str(path.relative_to(root)) for path in root.rglob("*")}
    if observed_entries != expected_entries:
        raise Det01ObservationError("DET-01 bundle inventory changed")
    if stat.S_IMODE(root.stat(follow_symlinks=False).st_mode) != 0o555:
        raise Det01ObservationError("DET-01 bundle root mode changed")
    package = root / "aragorn"
    if (
        package.is_symlink()
        or not package.is_dir()
        or stat.S_IMODE(package.stat(follow_symlinks=False).st_mode) != 0o555
    ):
        raise Det01ObservationError("DET-01 package directory changed")

    files = []
    for name, (expected_bytes, expected_digest) in _FILES.items():
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise Det01ObservationError(f"DET-01 bundle file changed: {name}")
        metadata = path.stat(follow_symlinks=False)
        raw = path.read_bytes()
        if (
            stat.S_IMODE(metadata.st_mode) != 0o444
            or metadata.st_nlink != 1
            or len(raw) != expected_bytes
            or _digest(raw) != expected_digest
        ):
            raise Det01ObservationError(f"DET-01 bundle identity changed: {name}")
        files.append(
            {
                "bytes": expected_bytes,
                "digest": expected_digest,
                "mode": "444",
                "name": name,
            }
        )
    return files


def _load_canonical(raw: bytes, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_OBSERVATION_BYTES:
        raise Det01ObservationError(f"{label} size changed")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
        encoded = canonical_json(document)
    except Det01ObservationError:
        raise
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Det01ObservationError(f"{label} is not strict JSON") from exc
    if type(document) is not dict or raw != encoded + b"\n":
        raise Det01ObservationError(f"{label} is not canonical JSON plus LF")
    return document


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Det01ObservationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise Det01ObservationError(f"non-finite JSON number: {value}")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()
