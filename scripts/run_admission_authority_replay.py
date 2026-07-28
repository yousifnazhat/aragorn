"""Retain a bounded clean-process replay of Aragorn's decision authority."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aragorn.admission_decision import (
    AdmissionDecisionError,
    evaluate_admission,
)
from aragorn.oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
)

VECTOR_PATH = (
    ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "deterministic-authority-vectors-v1.json"
)
SEEDS = ("1", "2", "3")
CASE_IDS = ("allow", "deny", "error", "review")
TIMEOUT_SECONDS = 5
INPUT_LIMIT_BYTES = 64 * 1024
OUTPUT_LIMIT_BYTES = 4 * 1024
IMPLEMENTATION_PATHS = {
    "admission_decision_digest": "src/aragorn/admission_decision.py",
    "analyze_digest": "src/aragorn/analyze.py",
    "oci_worker_protocol_digest": "src/aragorn/oci_worker_protocol.py",
    "policy_digest": "src/aragorn/policy.py",
    "replay_runner_digest": "scripts/run_admission_authority_replay.py",
}


class ReplayError(ValueError):
    """The deterministic authority replay did not close."""


def _sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _implementation() -> dict[str, str]:
    return {
        name: _sha256((ROOT / path).read_bytes())
        for name, path in IMPLEMENTATION_PATHS.items()
    }


def _load_vectors() -> tuple[dict[str, Any], bytes]:
    raw = VECTOR_PATH.read_bytes()
    if len(raw) > INPUT_LIMIT_BYTES:
        raise ReplayError("authority vector set exceeds 64 KiB")
    document = json.loads(raw)
    if raw != canonical_json(document) + b"\n":
        raise ReplayError("authority vector set is not canonical JSON plus LF")
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "vectors"}
        or document["schema"] != "aragorn/admission-authority-vector-set/v1"
        or not isinstance(document["vectors"], list)
        or len(document["vectors"]) != len(CASE_IDS)
    ):
        raise ReplayError("authority vector set shape changed")
    case_ids = []
    for vector in document["vectors"]:
        if not isinstance(vector, dict) or set(vector) != {"expected", "request"}:
            raise ReplayError("authority vector shape changed")
        request = vector["request"]
        expected = vector["expected"]
        if (
            not isinstance(request, dict)
            or not isinstance(expected, dict)
            or set(expected) != {"reason_codes", "verdict"}
        ):
            raise ReplayError("authority vector expectation changed")
        decision = evaluate_admission(request)
        if {
            "reason_codes": decision["reason_codes"],
            "verdict": decision["verdict"],
        } != expected:
            raise ReplayError("authority vector expectation is false")
        case_ids.append(request["case_id"])
    if case_ids != list(CASE_IDS):
        raise ReplayError("authority vectors are incomplete or unordered")
    return document, raw


def _run(request: dict[str, Any], seed: str) -> dict[str, Any]:
    raw = canonical_json(request) + b"\n"
    if len(raw) > INPUT_LIMIT_BYTES:
        raise ReplayError("authority request exceeds 64 KiB")
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": seed,
        "PYTHONPATH": str(ROOT / "src"),
        "TZ": "UTC",
    }
    result = subprocess.run(
        [sys.executable, "-m", "aragorn.admission_decision"],
        input=raw,
        capture_output=True,
        cwd=ROOT,
        env=environment,
        check=False,
        timeout=TIMEOUT_SECONDS,
    )
    if (
        result.returncode != 0
        or result.stderr
        or len(result.stdout) > OUTPUT_LIMIT_BYTES
        or len(result.stderr) > OUTPUT_LIMIT_BYTES
    ):
        raise ReplayError(f"authority replay failed for seed {seed}")
    decision = json.loads(result.stdout)
    if (
        result.stdout != canonical_json(decision) + b"\n"
        or decision != evaluate_admission(request)
    ):
        raise ReplayError(f"authority replay diverged for seed {seed}")
    return {
        "exit_code": result.returncode,
        "seed": seed,
        "stdin_digest": _sha256(raw),
        "stderr_digest": _sha256(result.stderr),
        "stdout_digest": _sha256(result.stdout),
    }


def build_evidence() -> dict[str, Any]:
    vector_set, vector_raw = _load_vectors()
    implementation = _implementation()
    configuration = {
        "case_ids": list(CASE_IDS),
        "input_limit_bytes": INPUT_LIMIT_BYTES,
        "module": "aragorn.admission_decision",
        "output_limit_bytes": OUTPUT_LIMIT_BYTES,
        "seeds": list(SEEDS),
        "timeout_seconds": TIMEOUT_SECONDS,
        "vector_set_digest": _sha256(vector_raw),
    }
    execution_profile = {
        "argv": [sys.executable, "-m", "aragorn.admission_decision"],
        "cwd": str(ROOT),
        "executable_digest": _sha256(Path(sys.executable).read_bytes()),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "system": platform.platform(),
    }
    cases = []
    for vector in vector_set["vectors"]:
        request = vector["request"]
        replays = [_run(request, seed) for seed in SEEDS]
        cases.append(
            {
                "case_id": request["case_id"],
                "replays": replays,
            }
        )
    if _implementation() != implementation:
        raise ReplayError("authority implementation changed during replay")
    return {
        "adapter": {
            "configuration": configuration,
            "configuration_digest": canonical_digest(configuration),
            "implementation": implementation,
            "implementation_digest": canonical_digest(implementation),
        },
        "assurance": "SELF_REPORTED_LOCAL_PROCESS_NOT_INDEPENDENTLY_ATTESTED",
        "cases": cases,
        "environment": {
            "profile": execution_profile,
            "profile_digest": canonical_digest(execution_profile),
        },
        "limitations": [
            "DECISION_ONLY_NOT_INSTALLER_AUTHORITY",
            "LOCAL_PROCESS_SELF_REPORTED_NOT_INDEPENDENTLY_ATTESTED",
            "SOURCE_ANALYZER_RESULTS_ARE_FIXED_RETAINED_VECTORS",
        ],
        "recorded_at": datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z"),
        "schema": "aragorn/admission-authority-replay-evidence/v1",
        "vector_set_digest": _sha256(vector_raw),
    }


def main() -> int:
    try:
        evidence = build_evidence()
    except (
        AdmissionDecisionError,
        json.JSONDecodeError,
        OSError,
        ReplayError,
        subprocess.TimeoutExpired,
        UnicodeDecodeError,
        WorkerProtocolError,
    ) as exc:
        print(f"admission authority replay failed: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(evidence) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
