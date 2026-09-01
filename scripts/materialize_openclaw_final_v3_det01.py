#!/usr/bin/env python3
"""Materialize the exact standalone DET-01 V3 replay bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


class Det01MaterializationError(ValueError):
    """The pinned DET-01 source or materialized bundle changed."""


_ROOT = Path(__file__).resolve().parents[1]
_CASE_ID = "DET-01"
_SCHEMA = "aragorn/openclaw-final-admission-v3-materialized-probe-bundle/v1"
_AUTHORITY = "PINNED_V3_PROBE_BUNDLE_ONLY_NOT_EXECUTION_OR_QUALIFICATION_AUTHORITY"
_RUNNER_REPLACEMENTS = (
    (
        (
            b"ROOT = Path(__file__).resolve().parents[1]\n"
            b'sys.path.insert(0, str(ROOT / "src"))'
        ),
        b"ROOT = Path(__file__).resolve().parent\nsys.path.insert(0, str(ROOT))",
    ),
    (
        (
            b"VECTOR_PATH = (\n"
            b"    ROOT\n"
            b'    / "benchmark"\n'
            b'    / "admission"\n'
            b'    / "openclaw-v2026.7.1"\n'
            b'    / "deterministic-authority-vectors-v1.json"\n'
            b")"
        ),
        b'VECTOR_PATH = ROOT / "deterministic-authority-vectors-v1.json"',
    ),
    (
        (
            b'"admission_decision_digest": "src/aragorn/admission_decision.py",\n'
            b'    "analyze_digest": "src/aragorn/analyze.py",\n'
            b'    "oci_worker_protocol_digest": "src/aragorn/oci_worker_protocol.py",\n'
            b'    "policy_digest": "src/aragorn/policy.py",\n'
            b'    "replay_runner_digest": "scripts/run_admission_authority_replay.py",'
        ),
        (
            b'"admission_decision_digest": "aragorn/admission_decision.py",\n'
            b'    "analyze_digest": "aragorn/analyze.py",\n'
            b'    "oci_worker_protocol_digest": "aragorn/oci_worker_protocol.py",\n'
            b'    "policy_digest": "aragorn/policy.py",\n'
            b'    "replay_runner_digest": "run_admission_authority_replay.py",'
        ),
    ),
    (b'"PYTHONPATH": str(ROOT / "src"),', b'"PYTHONPATH": str(ROOT),'),
)
_SOURCES = {
    "run_admission_authority_replay.py": (
        "scripts/run_admission_authority_replay.py",
        7_330,
        "sha256:43be1290771abc4c6664faa262a0c366e8078a3f8aa5143d05b747e01030b966",
        7_211,
        "sha256:e01776fd6fd66589f40bdd86dec80aa0451854e6e752740fe9e121b2e76ecb70",
    ),
    "deterministic-authority-vectors-v1.json": (
        (
            "benchmark/admission/openclaw-v2026.7.1/"
            "deterministic-authority-vectors-v1.json"
        ),
        11_875,
        "sha256:1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161",
        11_875,
        "sha256:1b611972663a9de166bc4de16e15bf4a05841a3dc895cc920e71094b55a16161",
    ),
    "aragorn/__init__.py": (
        "src/aragorn/__init__.py",
        78,
        "sha256:4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01",
        78,
        "sha256:4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01",
    ),
    "aragorn/admission_decision.py": (
        "src/aragorn/admission_decision.py",
        16_879,
        "sha256:6ff41b17d151b89043757c5d0537e1540bd0c964618a6ea4b77f8b8195ce79ca",
        16_879,
        "sha256:6ff41b17d151b89043757c5d0537e1540bd0c964618a6ea4b77f8b8195ce79ca",
    ),
    "aragorn/analyze.py": (
        "src/aragorn/analyze.py",
        29_366,
        "sha256:43796b5fdbca1fd0968ca87c5e8f640e3517867d6eed229c40980451471255a6",
        29_366,
        "sha256:43796b5fdbca1fd0968ca87c5e8f640e3517867d6eed229c40980451471255a6",
    ),
    "aragorn/oci_worker_protocol.py": (
        "src/aragorn/oci_worker_protocol.py",
        22_775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
        22_775,
        "sha256:0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b",
    ),
    "aragorn/policy.py": (
        "src/aragorn/policy.py",
        5_174,
        "sha256:246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b",
        5_174,
        "sha256:246a0f93c1c0e2ca803c8d1bda4e50a0bc4d3ab5855242532308396d6ad82d9b",
    ),
}


def materialize_openclaw_final_v3_det01(output: Path) -> dict[str, Any]:
    """Write the exact read-only DET-01 bundle into a new directory."""

    if not isinstance(output, Path) or output.exists() or output.is_symlink():
        raise Det01MaterializationError("output must be a new Path")

    materialized = []
    for name, (
        source,
        source_bytes,
        source_digest,
        expected_bytes,
        expected_digest,
    ) in _SOURCES.items():
        raw = (_ROOT / source).read_bytes()
        if len(raw) != source_bytes or _digest(raw) != source_digest:
            raise Det01MaterializationError(f"DET-01 source bytes changed for {name}")
        if name == "run_admission_authority_replay.py":
            for old, new in _RUNNER_REPLACEMENTS:
                if raw.count(old) != 1:
                    raise Det01MaterializationError(
                        "DET-01 runner replacement shape changed"
                    )
                raw = raw.replace(old, new)
        if len(raw) != expected_bytes or _digest(raw) != expected_digest:
            raise Det01MaterializationError(
                f"DET-01 materialized bytes changed for {name}"
            )
        materialized.append((name, raw, expected_digest))

    output.mkdir(mode=0o755)
    package = output / "aragorn"
    package.mkdir(mode=0o755)
    files = []
    for name, raw, digest in materialized:
        path = output / name
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o444,
        )
        try:
            written = 0
            while written < len(raw):
                count = os.write(descriptor, raw[written:])
                if count <= 0:
                    raise Det01MaterializationError(
                        "DET-01 bundle write made no progress"
                    )
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o444, follow_symlinks=False)
        files.append({"bytes": len(raw), "digest": digest, "name": name})
    os.chmod(package, 0o555, follow_symlinks=False)
    os.chmod(output, 0o555, follow_symlinks=False)
    return {
        "schema": _SCHEMA,
        "authority": _AUTHORITY,
        "case_id": _CASE_ID,
        "files": files,
    }


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = materialize_openclaw_final_v3_det01(args.output)
    print(json.dumps(manifest, allow_nan=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
