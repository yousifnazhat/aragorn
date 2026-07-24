"""Run evidence-smoke suites through the two digest-bound OCI baselines."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from io import BytesIO
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Iterator, Sequence

from .benchmark import (
    BenchmarkError,
    _normalize_pinned_vendor_report,
    _verify_evidence,
    load_suite_for_run,
    normalize_vendor_observations,
)
from .cas import CAS, CASError
from .cli import ConfigurationError, _safe_relative_path, _within
from .oci_runtime import (
    LOCK,
    MAX_RUNTIME_OUTPUT_BYTES,
    DockerExecutable,
    ImageVerification,
    OCIExecutionError,
    OCIExecutionResult,
    VerificationError,
    _build_create_argv,
    _build_effective_config_json,
    _capture_post_runner_identity,
    _capture_pre_runner_identity,
    _RunnerReceiptBuffer,
    _sha256,
    _verify_docker_unchanged,
    load_baseline_lock,
    resolve_docker,
    run_baseline,
    verify_image,
)
from .vendor_reports import VendorReportError


_MAX_DOCKER_BYTES = 128 * 1024 * 1024
_MAX_RECORD_BYTES = 8 * 1024 * 1024
_RETAINABLE_RUNTIME_ERRORS = frozenset({"OUTPUT_LIMIT_EXCEEDED", "TIMEOUT"})


class RunnerError(ValueError):
    """The OCI matrix cannot be executed or evidenced safely."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RunnerError(message)


@dataclass(frozen=True, slots=True)
class _PreparedBaseline:
    baseline: dict[str, Any]
    raw_lock: bytes
    selected_json: bytes
    docker: DockerExecutable
    verification: ImageVerification
    effective_config_json: bytes
    runner_identity_json: bytes
    system: dict[str, str]


def identify(
    *,
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
) -> tuple[dict[str, str], ...]:
    """Verify both local images and return their effective benchmark identities."""

    prepared = _preflight(
        lock_path=lock_path,
        docker_executable=docker_executable,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    )
    return tuple(item.system for item in prepared)


def run_files(
    suite_path: str | os.PathLike[str],
    *,
    state: str | os.PathLike[str],
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
) -> tuple[dict[str, Any], ...]:
    """Run a complete OCI matrix and return only fully verified outcome records."""

    timeout, output_limit = _validate_limits(timeout_seconds, output_limit_bytes)
    suite_file = Path(suite_path).expanduser()
    suite_root = suite_file.parent.resolve(strict=True)
    state_path = Path(state).expanduser().resolve(strict=False)
    if _within(state_path, suite_root) or _within(suite_root, state_path):
        raise RunnerError("benchmark suite and evidence state must not overlap")

    cas = CAS(state_path)
    loaded = load_suite_for_run(
        suite_file,
        cas,
        required_purpose="evidence_smoke",
    )
    prepared = _preflight(
        lock_path=lock_path,
        docker_executable=docker_executable,
        timeout_seconds=timeout,
        output_limit_bytes=output_limit,
    )
    by_key = {_system_key(item.system): item for item in prepared}
    if len(by_key) != len(prepared):
        raise RunnerError("duplicate effective OCI benchmark system identity")
    if set(by_key) != set(loaded["systems"]):
        expected = ", ".join(
            _format_system(key) for key in sorted(loaded["systems"])
        )
        actual = ", ".join(_format_system(key) for key in sorted(by_key))
        raise RunnerError(
            f"OCI identities do not match suite; expected [{expected}], "
            f"derived [{actual}]"
        )

    docker_digest = _retain_docker(cas, prepared[0].docker)
    manifest_digests = {
        case_id: _put_json(cas, manifest)
        for case_id, manifest in loaded["manifests"].items()
    }
    for item in prepared:
        if item.docker != prepared[0].docker:
            raise RunnerError("OCI preflight resolved inconsistent Docker identities")
        if _put_bytes(cas, item.raw_lock) != _sha256(item.raw_lock):
            raise RunnerError("retained baseline lock digest is inconsistent")
        if _put_bytes(cas, item.selected_json) != _sha256(item.selected_json):
            raise RunnerError("retained baseline entry digest is inconsistent")
        if (
            _put_bytes(cas, item.effective_config_json)
            != item.system["config_digest"]
        ):
            raise RunnerError("retained effective OCI configuration changed")
        effective = _load_object(item.effective_config_json, "effective configuration")
        if effective["docker_executable_digest"] != docker_digest:
            raise RunnerError("effective OCI configuration names another Docker binary")

    outcomes: list[dict[str, Any]] = []
    for key in sorted(by_key):
        item = by_key[key]
        system = loaded["systems"][key]
        for case_id in sorted(loaded["cases"]):
            manifest = loaded["manifests"][case_id]
            for run_id in range(1, loaded["runs_per_case"] + 1):
                with _oci_workspace(
                    cas,
                    manifest,
                    parent=state_path.parent,
                    forbidden_roots=(suite_root, state_path),
                ) as workspace:
                    result = run_baseline(
                        item.baseline["name"],
                        workspace=workspace,
                        expected_tree_digest=loaded["cases"][case_id][
                            "tree_digest"
                        ],
                        lock_path=lock_path,
                        docker_executable=item.docker.path,
                        timeout_seconds=timeout,
                        output_limit_bytes=output_limit,
                        expected_effective_config_json=(
                            item.effective_config_json
                        ),
                    )
                    outcome = _retain_run(
                        cas,
                        loaded,
                        case_id,
                        run_id,
                        system,
                        item,
                        result,
                        manifest_digest=manifest_digests[case_id],
                    )
                _verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label=f"{system['name']}:{case_id}:run-{run_id}",
                )
                outcomes.append(outcome)
    _verify_docker_unchanged(prepared[0].docker)
    return tuple(outcomes)


@contextmanager
def _oci_workspace(
    cas: CAS,
    manifest: dict[str, Any],
    *,
    parent: Path,
    forbidden_roots: tuple[Path, ...],
) -> Iterator[Path]:
    """Materialize only CAS subject bytes in a Docker-visible sibling directory."""

    parent_path = parent.resolve(strict=True)
    with tempfile.TemporaryDirectory(
        prefix=".aragorn-oci-workspace-",
        dir=parent_path,
    ) as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        workspace = temporary_root / "workspace"
        if any(
            _within(workspace, forbidden) or _within(forbidden, workspace)
            for forbidden in forbidden_roots
        ):
            raise RunnerError("OCI workspace overlaps suite or evidence state")
        temporary_root.chmod(0o755)
        workspace.mkdir(mode=0o755)
        directories = {workspace}
        files: list[Path] = []
        for entry in manifest["files"]:
            relative = _safe_relative_path(entry["path"])
            destination = workspace.joinpath(*relative.parts)
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            directories.update(
                directory
                for directory in destination.parents
                if directory == workspace or workspace in directory.parents
            )
            cas.materialize(entry["digest"], destination, root=workspace)
            destination.chmod(0o444)
            files.append(destination)
        ordered_directories = sorted(
            directories,
            key=lambda directory: len(directory.parts),
            reverse=True,
        )
        for directory in ordered_directories:
            directory.chmod(0o555)
        try:
            yield workspace
        finally:
            for file in files:
                try:
                    file.chmod(0o600)
                except FileNotFoundError:
                    pass
            for directory in ordered_directories:
                try:
                    directory.chmod(0o700)
                except FileNotFoundError:
                    pass
            temporary_root.chmod(0o700)


def _preflight(
    *,
    lock_path: str | os.PathLike[str],
    docker_executable: str | os.PathLike[str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> tuple[_PreparedBaseline, ...]:
    timeout, output_limit = _validate_limits(timeout_seconds, output_limit_bytes)
    raw_lock, baselines = load_baseline_lock(lock_path)
    docker = resolve_docker(docker_executable)
    prepared: list[_PreparedBaseline] = []
    with tempfile.TemporaryDirectory(prefix="aragorn-oci-preflight-") as temporary:
        control = Path(temporary)
        pre_runner = _RunnerReceiptBuffer()
        post_runner = _RunnerReceiptBuffer()
        (
            discovery_environment,
            environment,
            runner_identity,
        ) = _capture_pre_runner_identity(docker, control, pre_runner)
        identity_workspace = control / "identity-workspace"
        identity_workspace.mkdir(mode=0o700)
        try:
            for baseline in sorted(baselines, key=lambda item: item["name"]):
                verification = verify_image(
                    docker.path, baseline, env=environment
                )
                _create, arguments, effective_environment = _build_create_argv(
                    docker.path,
                    baseline=baseline,
                    verification=verification,
                    workspace=identity_workspace,
                    container_name="aragorn-identity-preflight",
                )
                selected_json = _canonical_json(baseline)
                effective_json = _build_effective_config_json(
                    baseline=baseline,
                    raw_lock=raw_lock,
                    selected_json=selected_json,
                    docker=docker,
                    verification=verification,
                    arguments=arguments,
                    effective_environment=effective_environment,
                    timeout_seconds=timeout,
                    output_limit_bytes=output_limit,
                    runner_identity_json=runner_identity.document_json,
                )
                prepared.append(
                    _PreparedBaseline(
                        baseline=baseline,
                        raw_lock=raw_lock,
                        selected_json=selected_json,
                        docker=docker,
                        verification=verification,
                        effective_config_json=effective_json,
                        runner_identity_json=runner_identity.document_json,
                        system={
                            "name": baseline["name"],
                            "version": baseline["version"],
                            "implementation_digest": baseline["image"][
                                "platform_manifest_digest"
                            ],
                            "config_digest": _sha256(effective_json),
                        },
                    )
                )
        finally:
            _capture_post_runner_identity(
                docker,
                discovery_environment=discovery_environment,
                execution_environment=environment,
                expected=runner_identity,
                evidence=post_runner,
            )
    _verify_docker_unchanged(docker)
    return tuple(prepared)


def _retain_run(
    cas: CAS,
    loaded: dict[str, Any],
    case_id: str,
    run_id: int,
    system: dict[str, str],
    prepared: _PreparedBaseline,
    result: OCIExecutionResult | OCIExecutionError,
    *,
    manifest_digest: str,
) -> dict[str, Any]:
    subject_digest = loaded["cases"][case_id]["tree_digest"]
    evidence = _retain_execution_evidence(
        cas,
        subject_digest=subject_digest,
        prepared=prepared,
        result=result,
    )
    envelope = {
        "schema": "aragorn/benchmark-evidence/v3",
        "suite_digest": loaded["digest"],
        "case_id": case_id,
        "tree_digest": subject_digest,
        "run_id": run_id,
        "system": system,
        "manifest_digest": manifest_digest,
        **evidence,
    }
    evidence_digest = _put_json(cas, envelope)
    return {
        "schema": "aragorn/benchmark-outcome/v1",
        "suite_digest": loaded["digest"],
        "case_id": case_id,
        "tree_digest": subject_digest,
        "run_id": run_id,
        "system": system,
        "evidence_digest": evidence_digest,
        "verdict": evidence["verdict"],
        "reason_codes": evidence["reason_codes"],
    }


def _retain_execution_evidence(
    cas: CAS,
    *,
    subject_digest: str,
    prepared: _PreparedBaseline,
    result: OCIExecutionResult | OCIExecutionError,
) -> dict[str, Any]:
    """Retain one label-free OCI execution closure."""

    _check_execution_identity(prepared, result)
    if isinstance(result, OCIExecutionError):
        if result.error_code not in _RETAINABLE_RUNTIME_ERRORS:
            raise RunnerError(
                f"{prepared.baseline['name']} infrastructure execution failed: "
                f"{result.error_code}: {result.message}"
            )
        observations: tuple[Any, ...] = ()
        status = "error"
        error_code: str | None = result.error_code
    else:
        valid_exit = (
            result.baseline_name == "cisco-skill-scanner"
            and result.returncode == 0
        ) or (
            result.baseline_name == "skillspector"
            and result.returncode in {0, 1}
        )
        observations = ()
        status = "error"
        error_code = "NONZERO_OR_INVALID_VENDOR_EXIT"
        if valid_exit:
            try:
                observations = _normalize_pinned_vendor_report(
                    result.baseline_name,
                    result.raw_stdout,
                    subject_digest=subject_digest,
                    returncode=result.returncode,
                )
            except VendorReportError:
                error_code = "MALFORMED_VENDOR_REPORT"
            else:
                status = "ok"
                error_code = None

    if result.returncode is None or result.container_id is None:
        raise RunnerError("retainable OCI execution lacks a concrete exit identity")
    if status == "ok":
        verdict, reason_codes = normalize_vendor_observations(
            prepared.baseline["name"],
            observations,
        )
    else:
        verdict = "ERROR"
        assert error_code is not None
        reason_codes = (f"ANALYZER_{error_code}",)

    image_config_digest = _put_bytes(cas, result.raw_config_json)
    if image_config_digest != prepared.baseline["image"]["config_digest"]:
        raise RunnerError("retained OCI image config does not match the lock")
    locked_image = prepared.baseline["image"]
    raw_oci_digests = {
        "oci_index_digest": _put_bytes(cas, result.raw_oci_index_json),
        "oci_platform_manifest_digest": _put_bytes(
            cas, result.raw_oci_platform_manifest_json
        ),
        "build_provenance_manifest_digest": _put_bytes(
            cas, result.raw_build_provenance_manifest_json
        ),
    }
    expected_oci_digests = {
        "oci_index_digest": locked_image["index_digest"],
        "oci_platform_manifest_digest": locked_image[
            "platform_manifest_digest"
        ],
        "build_provenance_manifest_digest": locked_image[
            "build_provenance_manifest_digest"
        ],
    }
    if raw_oci_digests != expected_oci_digests:
        raise RunnerError("retained OCI metadata graph does not match the lock")
    if result.verified_subject_digest != subject_digest:
        raise RunnerError("OCI execution did not verify the selected subject")
    observation_digests = [
        _put_bytes(cas, observation.document_json.encode("ascii"))
        for observation in observations
    ]
    runner_receipts = {
        "pre": {
            "context_inspect_digest": _put_bytes(
                cas, result.raw_pre_context_inspect
            ),
            "daemon_version_digest": _put_bytes(
                cas, result.raw_pre_daemon_version
            ),
            "daemon_info_digest": _put_bytes(
                cas, result.raw_pre_daemon_info
            ),
        },
        "post": {
            "context_inspect_digest": _put_bytes(
                cas, result.raw_post_context_inspect
            ),
            "daemon_version_digest": _put_bytes(
                cas, result.raw_post_daemon_version
            ),
            "daemon_info_digest": _put_bytes(
                cas, result.raw_post_daemon_info
            ),
        },
    }
    return {
        "verified_subject_digest": result.verified_subject_digest,
        "baseline_lock_digest": _put_bytes(cas, result.raw_lock),
        "baseline_entry_digest": _put_bytes(
            cas, result.selected_baseline_json
        ),
        "effective_config_digest": _put_bytes(
            cas, result.effective_config_json
        ),
        **raw_oci_digests,
        "index_inspect_digest": _put_bytes(cas, result.raw_index_inspect),
        "platform_inspect_digest": _put_bytes(
            cas, result.raw_platform_inspect
        ),
        "image_config_digest": image_config_digest,
        "runner_receipts": runner_receipts,
        "prestart_container_inspect_digest": _put_bytes(
            cas, result.raw_prestart_container_inspect
        ),
        "postrun_container_inspect_digest": _put_bytes(
            cas, result.raw_postrun_container_inspect
        ),
        "stdout_digest": _put_bytes(cas, result.raw_stdout),
        "stderr_digest": _put_bytes(cas, result.raw_stderr),
        "observation_digests": observation_digests,
        "execution": {
            "status": status,
            "error_code": error_code,
            "returncode": result.returncode,
            "container_id": result.container_id,
        },
        "normalization": _load_object(
            result.effective_config_json, "effective configuration"
        )["normalization"],
        "verdict": verdict,
        "reason_codes": list(reason_codes),
    }


def _check_execution_identity(
    prepared: _PreparedBaseline,
    result: OCIExecutionResult | OCIExecutionError,
) -> None:
    expected = {
        "baseline_name": prepared.baseline["name"],
        "docker_path": os.fspath(prepared.docker.path),
        "docker_digest": prepared.docker.digest,
        "image_reference": prepared.verification.image_reference,
        "raw_lock": prepared.raw_lock,
        "selected_baseline_json": prepared.selected_json,
        "effective_config_json": prepared.effective_config_json,
        "runner_identity_json": prepared.runner_identity_json,
    }
    for field, value in expected.items():
        if getattr(result, field) != value:
            raise RunnerError(f"OCI execution changed preflight identity: {field}")
    if isinstance(result, OCIExecutionResult):
        exact = {
            "version": prepared.baseline["version"],
            "index_digest": prepared.baseline["image"]["index_digest"],
            "platform_manifest_digest": prepared.baseline["image"][
                "platform_manifest_digest"
            ],
            "config_digest": prepared.baseline["image"]["config_digest"],
        }
        for field, value in exact.items():
            if getattr(result, field) != value:
                raise RunnerError(f"OCI execution changed locked identity: {field}")


def _retain_docker(cas: CAS, docker: DockerExecutable) -> str:
    descriptor = -1
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(docker.path, flags)
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MAX_DOCKER_BYTES
            or before.st_mode & 0o111 == 0
            or identity != docker.identity
        ):
            raise RunnerError("Docker executable changed before retention")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as source:
            digest = cas.put(source, max_bytes=_MAX_DOCKER_BYTES)
        after = os.fstat(descriptor)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if after_identity != identity or digest != docker.digest:
            raise RunnerError("Docker executable changed while retained")
        return digest
    except (CASError, RunnerError):
        raise
    except OSError as exc:
        raise RunnerError(f"cannot retain Docker executable: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_limits(
    timeout_seconds: float, output_limit_bytes: int
) -> tuple[float, int]:
    if isinstance(timeout_seconds, bool):
        raise RunnerError("timeout must be finite, greater than zero, and at most 3600")
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "timeout must be finite, greater than zero, and at most 3600"
        ) from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 3600:
        raise RunnerError("timeout must be finite, greater than zero, and at most 3600")
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or not 1 <= output_limit_bytes <= MAX_RUNTIME_OUTPUT_BYTES
    ):
        raise RunnerError("output limit must be between 1 and 8388608 bytes")
    return timeout, output_limit_bytes


def _load_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"invalid {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise RunnerError(f"{label} must be a JSON object")
    return document


def _put_json(cas: CAS, document: dict[str, Any]) -> str:
    return _put_bytes(cas, _canonical_json(document))


def _put_bytes(cas: CAS, content: bytes) -> str:
    if len(content) > _MAX_RECORD_BYTES:
        raise RunnerError("OCI benchmark evidence record exceeds 8 MiB")
    return cas.put(BytesIO(content), max_bytes=len(content))


def _canonical_json(document: Any) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


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
        prog="python -m aragorn.oci_benchmark_runner",
        description="Run digest-bound OCI baselines over an inert evidence suite.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    identity = commands.add_parser("identity")
    _common_arguments(identity)
    identity.set_defaults(action=_identity_command)
    run = commands.add_parser("run")
    run.add_argument("suite", type=Path)
    run.add_argument("--state", type=Path, required=True)
    _common_arguments(run)
    run.set_defaults(action=_run_command)
    return parser


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lock", type=Path, default=LOCK)
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--output-limit", type=int, default=1024 * 1024)


def _identity_command(args: argparse.Namespace) -> int:
    systems = identify(
        lock_path=args.lock,
        docker_executable=args.docker,
        timeout_seconds=args.timeout,
        output_limit_bytes=args.output_limit,
    )
    print(
        json.dumps(
            {
                "schema": "aragorn/benchmark-system-identities/v1",
                "systems": systems,
            },
            sort_keys=True,
        )
    )
    return 0


def _run_command(args: argparse.Namespace) -> int:
    outcomes = run_files(
        args.suite,
        state=args.state,
        lock_path=args.lock,
        docker_executable=args.docker,
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
        VerificationError,
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
