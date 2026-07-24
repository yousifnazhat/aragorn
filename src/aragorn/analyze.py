"""Bounded subprocess execution for administrator-configured analyzers."""

from __future__ import annotations

import json
import math
import os
import re
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


REQUEST_SCHEMA = "aragorn/analyzer-request/v1"
OBSERVATION_SCHEMA = "aragorn/observation/v1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
_MAX_OBSERVATIONS = 10_000
MAX_ANALYZER_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_EVIDENCE_RECORD_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Observation:
    """A validated analyzer observation with its original JSON preserved."""

    schema: str
    subject_digest: str
    reason_code: str
    severity: str
    document_json: str


@dataclass(frozen=True, slots=True)
class AnalyzerResult:
    """Success or an explicit fail-closed analyzer error."""

    name: str
    version: str
    config_digest: str
    status: str
    executable_digest: str | None = None
    observations: tuple[Observation, ...] = ()
    error_code: str | None = None
    error_message: str | None = None
    raw_stdout: bytes = b""
    raw_stderr: bytes = b""
    stderr: str = ""
    returncode: int | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.error_code is None


def run_analyzer(
    argv: Sequence[str],
    *,
    workspace: str | os.PathLike[str],
    name: str,
    version: str,
    config_digest: str,
    executable_digest: str,
    subject_digest: str,
    timeout_seconds: float = 120.0,
    output_limit_bytes: int = 1024 * 1024,
) -> AnalyzerResult:
    """Run one analyzer without a shell and parse its JSONL observations.

    The caller is responsible for any read-only mount or OS sandbox required
    by its threat model. The runner canonicalizes the existing directory and
    exposes no write API itself. Stdout and stderr share one hard byte budget.
    Timeout cleanup covers the analyzer's process group, not descendants that
    deliberately detach into another session.
    """

    identity = (
        str(name),
        str(version),
        str(config_digest),
        str(executable_digest),
    )
    invalid = _validate_configuration(
        argv,
        name=name,
        version=version,
        config_digest=config_digest,
        executable_digest=executable_digest,
        subject_digest=subject_digest,
        timeout_seconds=timeout_seconds,
        output_limit_bytes=output_limit_bytes,
    )
    if invalid is not None:
        return _error(identity, "INVALID_CONFIGURATION", invalid)

    try:
        workspace_path = Path(workspace).resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        return _error(identity, "WORKSPACE_INVALID", f"cannot resolve workspace: {exc}")
    if not workspace_path.is_dir():
        return _error(identity, "WORKSPACE_INVALID", "workspace must be a directory")

    timeout = float(timeout_seconds)
    request = {
        "schema": REQUEST_SCHEMA,
        "workspace": os.fspath(workspace_path),
        "subject_digest": subject_digest,
        "analyzer": {
            "name": name,
            "version": version,
            "config_digest": config_digest,
            "executable_digest": executable_digest,
        },
        "limits": {
            "timeout_seconds": timeout,
            "output_bytes": output_limit_bytes,
        },
    }
    request_bytes = (
        json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        + b"\n"
    )

    try:
        control_directory = tempfile.TemporaryDirectory(prefix="aragorn-control-")
    except OSError as exc:
        return _error(
            identity,
            "CONTROL_DIRECTORY_FAILED",
            f"cannot create analyzer control directory: {exc}",
        )
    control_path = Path(control_directory.name).resolve(strict=True)

    try:
        process = subprocess.Popen(
            tuple(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=control_path,
            env={
                "HOME": os.fspath(control_path),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": _sanitized_path(),
            },
            shell=False,
            start_new_session=(os.name == "posix"),
        )
    except (OSError, ValueError) as exc:
        control_directory.cleanup()
        return _error(identity, "LAUNCH_FAILED", f"cannot start analyzer: {exc}")

    try:
        return _collect_analyzer_process(
            process,
            request_bytes=request_bytes,
            identity=identity,
            subject_digest=subject_digest,
            timeout=timeout,
            output_limit_bytes=output_limit_bytes,
        )
    finally:
        control_directory.cleanup()


def _collect_analyzer_process(
    process: subprocess.Popen[bytes],
    *,
    request_bytes: bytes,
    identity: tuple[str, str, str, str],
    subject_digest: str,
    timeout: float,
    output_limit_bytes: int,
) -> AnalyzerResult:
    """Collect bounded process I/O and terminate the process on any unwind."""

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    output_lock = threading.Lock()
    overflow = threading.Event()
    read_errors: list[str] = []
    write_errors: list[str] = []
    total_bytes = 0
    readers: tuple[threading.Thread, ...] = ()
    writer: threading.Thread | None = None

    def read_stream(label: str, stream: Any) -> None:
        nonlocal total_bytes
        try:
            while chunk := os.read(stream.fileno(), 64 * 1024):
                with output_lock:
                    remaining = output_limit_bytes - total_bytes
                    kept = chunk[: max(0, remaining)]
                    buffers[label].extend(kept)
                    total_bytes += len(kept)
                    exceeded = len(chunk) > len(kept)
                if exceeded:
                    overflow.set()
                    _kill_process_group(process)
                    return
        except OSError as exc:
            with output_lock:
                read_errors.append(f"{label}: {exc}")

    def write_request() -> None:
        try:
            process.stdin.write(request_bytes)
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            write_errors.append(str(exc))
        finally:
            _close_stream(process.stdin)

    try:
        readers = (
            threading.Thread(
                target=read_stream, args=("stdout", process.stdout), daemon=True
            ),
            threading.Thread(
                target=read_stream, args=("stderr", process.stderr), daemon=True
            ),
        )
        for reader in readers:
            reader.start()

        writer = threading.Thread(target=write_request, daemon=True)
        writer.start()

        timed_out = False
        termination_failed = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_process_group(process)
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                termination_failed = True

        writer.join(timeout=1.0)
        if writer.is_alive():
            _kill_process_group(process)
            writer.join(timeout=1.0)
        if writer.is_alive():
            write_errors.append("request writer did not stop after analyzer termination")

        for reader in readers:
            reader.join(timeout=0.25)
        if any(reader.is_alive() for reader in readers):
            _kill_process_group(process)
            for reader in readers:
                reader.join(timeout=1.0)
        if any(reader.is_alive() for reader in readers):
            read_errors.append("output reader did not stop after analyzer termination")

        if termination_failed:
            _abort_process(process, ())

        stdout = bytes(buffers["stdout"])
        stderr_bytes = bytes(buffers["stderr"])
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        returncode = process.returncode

        if termination_failed:
            return _error(
                identity,
                "TERMINATION_FAILED",
                "analyzer did not terminate within one second after SIGKILL",
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )
        if overflow.is_set():
            return _error(
                identity,
                "OUTPUT_LIMIT_EXCEEDED",
                f"analyzer output exceeded {output_limit_bytes} bytes",
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )
        if timed_out:
            return _error(
                identity,
                "TIMEOUT",
                f"analyzer exceeded {timeout:g} seconds",
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )
        if write_errors:
            return _error(
                identity,
                "INPUT_WRITE_FAILED",
                "; ".join(sorted(write_errors)),
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )
        if read_errors:
            return _error(
                identity,
                "OUTPUT_READ_FAILED",
                "; ".join(sorted(read_errors)),
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )
        if returncode != 0:
            return _error(
                identity,
                "NONZERO_EXIT",
                f"analyzer exited with status {returncode}",
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )

        observations, parse_error = _parse_observations(stdout, subject_digest)
        if parse_error is not None:
            code, message = parse_error
            return _error(
                identity,
                code,
                message,
                raw_stdout=stdout,
                raw_stderr=stderr_bytes,
                stderr=stderr,
                returncode=returncode,
            )

        return AnalyzerResult(
            name=identity[0],
            version=identity[1],
            config_digest=identity[2],
            status="ok",
            executable_digest=identity[3],
            observations=observations,
            raw_stdout=stdout,
            raw_stderr=stderr_bytes,
            stderr=stderr,
            returncode=returncode,
        )
    except BaseException:
        _abort_process(process, (*readers, *((writer,) if writer is not None else ())))
        raise
    finally:
        _close_stream(process.stdin)
        _close_stream(process.stdout)
        _close_stream(process.stderr)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        try:
            process_group = os.getpgid(process.pid)
        except (OSError, ProcessLookupError):
            process_group = None
        if process_group == process.pid and process.poll() is None:
            try:
                os.killpg(process_group, signal.SIGKILL)
                return
            except (OSError, ProcessLookupError):
                pass
    try:
        if process.poll() is None:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _abort_process(
    process: subprocess.Popen[bytes], threads: tuple[threading.Thread, ...]
) -> None:
    _kill_process_group(process)
    try:
        process.wait(timeout=1.0)
    except BaseException:
        pass
    _close_stream(process.stdin)
    _close_stream(process.stdout)
    _close_stream(process.stderr)
    for thread in threads:
        try:
            thread.join(timeout=1.0)
        except BaseException:
            pass


def _close_stream(stream: Any) -> None:
    if stream is None:
        return
    try:
        stream.close()
    except (BrokenPipeError, OSError, ValueError):
        pass


def _validate_configuration(
    argv: Sequence[str],
    *,
    name: str,
    version: str,
    config_digest: str,
    executable_digest: str,
    subject_digest: str,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> str | None:
    if isinstance(argv, (str, bytes)) or not argv:
        return "argv must be a non-empty sequence"
    if any(not isinstance(argument, str) or not argument or "\0" in argument for argument in argv):
        return "argv entries must be non-empty strings without NUL bytes"
    if not os.path.isabs(argv[0]):
        return "analyzer executable must be an absolute path"
    if not isinstance(name, str) or not name.strip():
        return "analyzer name must not be empty"
    if len(name) > 256:
        return "analyzer name must not exceed 256 characters"
    if not isinstance(version, str) or not version.strip():
        return "analyzer version must not be empty"
    if len(version) > 256:
        return "analyzer version must not exceed 256 characters"
    if not isinstance(config_digest, str) or _SHA256.fullmatch(config_digest) is None:
        return "config_digest must be a lowercase sha256 digest"
    if (
        not isinstance(executable_digest, str)
        or _SHA256.fullmatch(executable_digest) is None
    ):
        return "executable_digest must be a lowercase sha256 digest"
    if not isinstance(subject_digest, str) or _SHA256.fullmatch(subject_digest) is None:
        return "subject_digest must be a lowercase sha256 digest"
    if isinstance(timeout_seconds, bool):
        return "timeout_seconds must be finite and greater than zero"
    try:
        timeout = float(timeout_seconds)
    except (TypeError, ValueError):
        return "timeout_seconds must be finite and greater than zero"
    if not math.isfinite(timeout) or timeout <= 0:
        return "timeout_seconds must be finite and greater than zero"
    if (
        isinstance(output_limit_bytes, bool)
        or not isinstance(output_limit_bytes, int)
        or not 1 <= output_limit_bytes <= MAX_ANALYZER_OUTPUT_BYTES
    ):
        return (
            "output_limit_bytes must be an integer between 1 and "
            f"{MAX_ANALYZER_OUTPUT_BYTES}"
        )
    return None


def _sanitized_path() -> str:
    return os.pathsep.join(
        entry for entry in os.defpath.split(os.pathsep) if entry and os.path.isabs(entry)
    )


def _parse_observations(
    output: bytes, subject_digest: str
) -> tuple[tuple[Observation, ...], tuple[str, str] | None]:
    observations: list[Observation] = []
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            document = json.loads(
                raw_line.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            return (), ("MALFORMED_OUTPUT", f"invalid JSON on stdout line {line_number}: {exc}")
        if not isinstance(document, dict):
            return (), ("MALFORMED_OUTPUT", f"stdout line {line_number} must be a JSON object")
        if document.get("schema") != OBSERVATION_SCHEMA:
            return (), (
                "MALFORMED_OUTPUT",
                f"stdout line {line_number} has an unsupported observation schema",
            )
        if document.get("subject_digest") != subject_digest:
            return (), (
                "SUBJECT_DIGEST_MISMATCH",
                f"stdout line {line_number} does not match the requested subject digest",
            )
        reason_code = document.get("reason_code")
        severity = document.get("severity")
        if not isinstance(reason_code, str) or re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,127}", reason_code
        ) is None:
            return (), (
                "MALFORMED_OUTPUT",
                f"stdout line {line_number} has a noncanonical reason_code",
            )
        if not isinstance(severity, str) or severity not in _SEVERITIES:
            return (), (
                "MALFORMED_OUTPUT",
                f"stdout line {line_number} has a noncanonical severity",
            )
        try:
            canonical = json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            return (), ("MALFORMED_OUTPUT", f"invalid JSON on stdout line {line_number}: {exc}")
        if len(canonical.encode("ascii")) > _MAX_EVIDENCE_RECORD_BYTES:
            return (), (
                "OBSERVATION_RECORD_LIMIT_EXCEEDED",
                f"canonical observation on stdout line {line_number} exceeds "
                f"{_MAX_EVIDENCE_RECORD_BYTES} bytes",
            )
        observations.append(
            Observation(
                schema=OBSERVATION_SCHEMA,
                subject_digest=subject_digest,
                reason_code=reason_code,
                severity=severity,
                document_json=canonical,
            )
        )
        if len(observations) > _MAX_OBSERVATIONS:
            return (), (
                "OBSERVATION_LIMIT_EXCEEDED",
                f"analyzer emitted more than {_MAX_OBSERVATIONS} observations",
            )

    observations.sort(
        key=lambda observation: (
            observation.reason_code,
            observation.severity,
            observation.document_json,
        )
    )
    return tuple(observations), None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _error(
    identity: tuple[str, str, str, str],
    code: str,
    message: str,
    *,
    raw_stdout: bytes = b"",
    raw_stderr: bytes = b"",
    stderr: str = "",
    returncode: int | None = None,
) -> AnalyzerResult:
    return AnalyzerResult(
        name=identity[0],
        version=identity[1],
        config_digest=identity[2],
        status="error",
        executable_digest=identity[3],
        error_code=code,
        error_message=message,
        raw_stdout=raw_stdout,
        raw_stderr=raw_stderr,
        stderr=stderr,
        returncode=returncode,
    )
