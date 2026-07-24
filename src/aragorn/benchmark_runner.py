"""Evidence-smoke runner for digest-bound inert benchmark suites."""

from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
import math
import os
from pathlib import Path
import sys
from typing import Any, Sequence

from .analyze import AnalyzerResult, run_analyzer
from .benchmark import (
    EVIDENCE_ERROR_CODES,
    BenchmarkError,
    load_suite_for_run,
    normalize_analyzer_result,
)
from .cas import CAS, CASError
from .cli import (
    ConfigurationError,
    _analysis_workspace,
    _canonical_json,
    _load_analyzers,
    _materialized_analyzer,
    _read_json_object_with_bytes,
    _validate_analyzer_locations,
    _within,
)


_MAX_RECORD_BYTES = 8 * 1024 * 1024


class RunnerError(ValueError):
    """The benchmark runner cannot establish a trustworthy execution."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunnerError(message)


def identify_file(
    configuration_path: str | os.PathLike[str],
    *,
    state: str | os.PathLike[str],
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
) -> tuple[dict[str, str], ...]:
    """Return independently derived identities for self-contained adapters."""

    timeout, output_limit = _validate_limits(timeout_seconds, output_limit_bytes)
    state_path = _state_path(state)
    cas = CAS(state_path)
    configuration_file = Path(configuration_path).expanduser()
    document, _raw = _read_json_object_with_bytes(
        configuration_file, forbidden_roots=(state_path,)
    )
    specifications = _validate_analyzer_locations(
        _load_analyzers(document),
        configuration_file.resolve(strict=True),
        state_path,
        cas=cas,
    )
    return tuple(
        _effective_identity(specification, timeout, output_limit)[0]
        for specification in specifications
    )


def run_files(
    suite_path: str | os.PathLike[str],
    configuration_path: str | os.PathLike[str],
    *,
    state: str | os.PathLike[str],
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
) -> tuple[dict[str, Any], ...]:
    """Run the complete suite matrix and retain byte-exact evidence in the CAS."""

    timeout, output_limit = _validate_limits(timeout_seconds, output_limit_bytes)
    suite_file = Path(suite_path).expanduser()
    suite_root = suite_file.parent.resolve(strict=True)
    state_path = _state_path(state)
    if _within(state_path, suite_root) or _within(suite_root, state_path):
        raise RunnerError("benchmark suite and evidence state must not overlap")

    cas = CAS(state_path)
    loaded = load_suite_for_run(
        suite_file, cas, required_purpose="evidence_smoke"
    )
    configuration_file = Path(configuration_path).expanduser()
    configuration, raw_configuration = _read_json_object_with_bytes(
        configuration_file, forbidden_roots=(suite_root, state_path)
    )
    operator_config_digest = _put_bytes(cas, raw_configuration)
    specifications = _validate_analyzer_locations(
        _load_analyzers(configuration), suite_root, state_path, cas=cas
    )

    prepared: dict[tuple[str, str, str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    for specification in specifications:
        system, effective_config = _effective_identity(
            specification, timeout, output_limit
        )
        key = _system_key(system)
        if key in prepared:
            raise RunnerError("duplicate effective benchmark system identity")
        prepared[key] = (specification, effective_config)
    if set(prepared) != set(loaded["systems"]):
        expected = ", ".join(_format_system(key) for key in sorted(loaded["systems"]))
        actual = ", ".join(_format_system(key) for key in sorted(prepared))
        raise RunnerError(
            f"configured system identities do not match suite; expected [{expected}], "
            f"derived [{actual}]"
        )

    manifest_digests = {
        case_id: _put_json(cas, manifest)
        for case_id, manifest in loaded["manifests"].items()
    }
    effective_config_digests = {
        key: _put_json(cas, effective_config)
        for key, (_specification, effective_config) in prepared.items()
    }
    for key, digest in effective_config_digests.items():
        if digest != key[3]:
            raise RunnerError("effective configuration digest changed before execution")

    outcomes: list[dict[str, Any]] = []
    for key in sorted(prepared):
        specification, _effective_config = prepared[key]
        system = loaded["systems"][key]
        for case_id in sorted(loaded["cases"]):
            manifest = loaded["manifests"][case_id]
            for run_id in range(1, loaded["runs_per_case"] + 1):
                with _materialized_analyzer(cas, specification) as command:
                    with _analysis_workspace(cas, manifest) as workspace:
                        result = run_analyzer(
                            command,
                            workspace=workspace,
                            name=system["name"],
                            version=system["version"],
                            config_digest=system["config_digest"],
                            executable_digest=system["implementation_digest"],
                            subject_digest=manifest["tree_digest"],
                            timeout_seconds=timeout,
                            output_limit_bytes=output_limit,
                        )
                outcome = _retain_run(
                    cas,
                    loaded,
                    case_id,
                    run_id,
                    system,
                    result,
                    manifest_digest=manifest_digests[case_id],
                    operator_config_digest=operator_config_digest,
                )
                outcomes.append(outcome)
    return tuple(outcomes)


def _effective_identity(
    specification: dict[str, Any], timeout: float, output_limit: int
) -> tuple[dict[str, str], dict[str, Any]]:
    effective_config = {
        "schema": "aragorn/benchmark-system-config/v1",
        "name": specification["name"],
        "version": specification["version"],
        "executable_digest": specification["executable_digest"],
        "operator_argv0": specification["operator_argv0"],
        "argv_tail": list(specification["argv"][1:]),
        "limits": {
            "timeout_seconds": timeout,
            "output_bytes": output_limit,
        },
        "normalization": "aragorn-observation-severity/v1",
    }
    system = {
        "name": specification["name"],
        "version": specification["version"],
        "implementation_digest": specification["executable_digest"],
        "config_digest": _digest_bytes(_canonical_json(effective_config)),
    }
    return system, effective_config


def _retain_run(
    cas: CAS,
    loaded: dict[str, Any],
    case_id: str,
    run_id: int,
    system: dict[str, str],
    result: AnalyzerResult,
    *,
    manifest_digest: str,
    operator_config_digest: str,
) -> dict[str, Any]:
    if not result.ok and result.error_code not in EVIDENCE_ERROR_CODES:
        raise RunnerError(
            "analyzer failed without independently re-verifiable execution evidence: "
            f"{result.error_code or 'UNKNOWN_ERROR'}"
        )
    stdout_digest = _put_bytes(cas, result.raw_stdout)
    stderr_digest = _put_bytes(cas, result.raw_stderr)
    observation_digests = [
        _put_bytes(cas, observation.document_json.encode("ascii"))
        for observation in result.observations
    ]
    verdict, reason_codes = normalize_analyzer_result(result)
    execution = {
        "status": result.status,
        "error_code": result.error_code,
        "returncode": result.returncode,
    }
    envelope = {
        "schema": "aragorn/benchmark-evidence/v1",
        "suite_digest": loaded["digest"],
        "case_id": case_id,
        "tree_digest": loaded["cases"][case_id]["tree_digest"],
        "run_id": run_id,
        "system": system,
        "manifest_digest": manifest_digest,
        "operator_config_digest": operator_config_digest,
        "effective_config_digest": system["config_digest"],
        "executable_digest": system["implementation_digest"],
        "stdout_digest": stdout_digest,
        "stderr_digest": stderr_digest,
        "observation_digests": observation_digests,
        "execution": execution,
        "normalization": "aragorn-observation-severity/v1",
        "verdict": verdict,
        "reason_codes": list(reason_codes),
    }
    evidence_digest = _put_json(cas, envelope)
    return {
        "schema": "aragorn/benchmark-outcome/v1",
        "suite_digest": loaded["digest"],
        "case_id": case_id,
        "tree_digest": loaded["cases"][case_id]["tree_digest"],
        "run_id": run_id,
        "system": system,
        "evidence_digest": evidence_digest,
        "verdict": verdict,
        "reason_codes": list(reason_codes),
    }


def _validate_limits(timeout_seconds: float, output_limit_bytes: int) -> tuple[float, int]:
    if isinstance(timeout_seconds, bool):
        raise RunnerError("timeout must be finite and greater than zero")
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise RunnerError("timeout must be finite and greater than zero") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise RunnerError("timeout must be finite and greater than zero")
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or not 1 <= output_limit_bytes <= _MAX_RECORD_BYTES
    ):
        raise RunnerError("output limit must be between 1 and 8388608 bytes")
    return timeout, output_limit_bytes


def _state_path(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve(strict=False)


def _put_json(cas: CAS, document: dict[str, Any]) -> str:
    return _put_bytes(cas, _canonical_json(document))


def _put_bytes(cas: CAS, content: bytes) -> str:
    if len(content) > _MAX_RECORD_BYTES:
        raise RunnerError("benchmark evidence record exceeds 8 MiB")
    return cas.put(BytesIO(content), max_bytes=len(content))


def _digest_bytes(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _system_key(system: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        system["name"],
        system["version"],
        system["implementation_digest"],
        system["config_digest"],
    )


def _format_system(key: tuple[str, str, str, str]) -> str:
    return f"{key[0]}@{key[1]}:{key[2]}:{key[3]}"


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python -m aragorn.benchmark_runner",
        description="Run inert benchmark cases through CAS-staged analyzer entrypoints.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("identity")
    identity.add_argument("configuration", type=Path)
    identity.add_argument("--state", type=Path, required=True)
    identity.add_argument("--timeout", type=float, default=120.0)
    identity.add_argument("--output-limit", type=int, default=1024 * 1024)
    identity.set_defaults(action=_identity_command)
    run = commands.add_parser("run")
    run.add_argument("suite", type=Path)
    run.add_argument("configuration", type=Path)
    run.add_argument("--state", type=Path, required=True)
    run.add_argument("--timeout", type=float, default=120.0)
    run.add_argument("--output-limit", type=int, default=1024 * 1024)
    run.set_defaults(action=_run_command)
    return parser


def _identity_command(args: argparse.Namespace) -> int:
    systems = identify_file(
        args.configuration,
        state=args.state,
        timeout_seconds=args.timeout,
        output_limit_bytes=args.output_limit,
    )
    print(
        json.dumps(
            {"schema": "aragorn/benchmark-system-identities/v1", "systems": systems},
            sort_keys=True,
        )
    )
    return 0


def _run_command(args: argparse.Namespace) -> int:
    outcomes = run_files(
        args.suite,
        args.configuration,
        state=args.state,
        timeout_seconds=args.timeout,
        output_limit_bytes=args.output_limit,
    )
    for outcome in outcomes:
        print(json.dumps(outcome, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        return arguments.action(arguments)
    except (
        BenchmarkError,
        CASError,
        ConfigurationError,
        OSError,
        RunnerError,
        RuntimeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": "aragorn/error/v1",
                    "error": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
