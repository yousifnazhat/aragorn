"""One-shot import, execute, export, and sign supervisor for worker protocol v2."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Sequence

from .benchmark_handoff_v2 import (
    build_worker_output_handoff_manifest,
    export_handoff,
    import_handoff,
)
from .benchmark_protocol_v2 import canonical_result_digest_v2
from .benchmark_worker_measurement import (
    build_worker_measurement,
    sign_worker_measurement,
)
from .cas import CAS, CASError
from .oci_runtime import LOCK
from .oci_worker import WorkerError, _paths_overlap
from .oci_worker_protocol import canonical_json
from .oci_worker_v2 import run as run_worker_v2


_MAX_ENVELOPE_BYTES = 256 * 1024


def supervise(
    *,
    input_bundle: str | os.PathLike[str],
    input_manifest_digest: str,
    request_digest: str,
    expected_challenge: str,
    input_state: str | os.PathLike[str],
    output_state: str | os.PathLike[str],
    output_bundle: str | os.PathLike[str],
    measurement_output: str | os.PathLike[str],
    signing_key: str | os.PathLike[str],
    worker_id: str,
    trust_domain: str,
    key_id: str,
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, str]:
    """Complete one label-blind worker job and publish its signed result."""

    paths = _resolve_boundaries(
        input_bundle=input_bundle,
        input_state=input_state,
        output_state=output_state,
        output_bundle=output_bundle,
        measurement_output=measurement_output,
        signing_key=signing_key,
        lock_path=lock_path,
        workspace_root=workspace_root,
    )
    input_cas = CAS(paths["input_state"])
    import_handoff(
        paths["input_bundle"],
        input_cas,
        expected_manifest_digest=input_manifest_digest,
        expected_kind="worker_input",
        expected_root_digest=request_digest,
        expected_verifier_challenge=expected_challenge,
    )
    result = run_worker_v2(
        request_digest=request_digest,
        expected_challenge=expected_challenge,
        input_state=paths["input_state"],
        output_state=paths["output_state"],
        lock_path=paths["lock_path"],
        docker_executable=docker_executable,
        workspace_root=paths["workspace_root"],
    )
    result_digest = canonical_result_digest_v2(result)
    output_cas = CAS(paths["output_state"], read_only=True)
    manifest = build_worker_output_handoff_manifest(
        output_cas,
        result_digest,
        expected_request_digest=request_digest,
        expected_verifier_challenge=expected_challenge,
    )
    manifest_digest = export_handoff(
        output_cas,
        manifest,
        paths["output_bundle"],
        expected_request_digest=request_digest,
        expected_verifier_challenge=expected_challenge,
    )
    statement = build_worker_measurement(
        trust_domain=trust_domain,
        worker_id=worker_id,
        key_id=key_id,
        job_id=result["job_id"],
        verifier_challenge=expected_challenge,
        request_digest=request_digest,
        result_digest=result_digest,
        handoff_manifest_digest=manifest_digest,
    )
    envelope = sign_worker_measurement(statement, paths["signing_key"])
    _publish_envelope(paths["measurement_output"], envelope)
    return {
        "schema": "aragorn/benchmark-worker-supervisor-result/v1",
        "assurance": "software_key_signature_not_hardware_attested",
        "request_digest": request_digest,
        "result_digest": result_digest,
        "handoff_manifest_digest": manifest_digest,
        "envelope_digest": _bytes_digest(envelope),
    }


def _resolve_boundaries(
    *,
    input_bundle: str | os.PathLike[str],
    input_state: str | os.PathLike[str],
    output_state: str | os.PathLike[str],
    output_bundle: str | os.PathLike[str],
    measurement_output: str | os.PathLike[str],
    signing_key: str | os.PathLike[str],
    lock_path: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str] | None,
) -> dict[str, Path | None]:
    existing = {
        "input_bundle": _existing_path(input_bundle, "input bundle"),
        "signing_key": _existing_path(signing_key, "worker signing key"),
        "lock_path": _existing_path(lock_path, "baseline lock"),
    }
    fresh = {
        "input_state": _fresh_path(input_state, "input state"),
        "output_state": _fresh_path(output_state, "output state"),
        "output_bundle": _fresh_path(output_bundle, "output bundle"),
        "measurement_output": _fresh_path(
            measurement_output,
            "measurement output",
        ),
    }
    workspace = (
        None
        if workspace_root is None
        else _existing_path(workspace_root, "workspace root")
    )
    paths = {**existing, **fresh, "workspace_root": workspace}
    compared = [(label, path) for label, path in paths.items() if path is not None]
    for index, (first_label, first) in enumerate(compared):
        for second_label, second in compared[index + 1 :]:
            if _paths_overlap(first, second):
                raise WorkerError(
                    "worker supervisor security boundaries overlap: "
                    f"{first_label}, {second_label}"
                )
    if not existing["input_bundle"].is_dir():
        raise WorkerError("input bundle must be a real directory")
    if workspace is not None and not workspace.is_dir():
        raise WorkerError("workspace root must be a real directory")
    return paths


def _existing_path(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
        path = supplied.resolve(strict=True)
        metadata = os.lstat(path)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerError(f"invalid {label}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise WorkerError(f"{label} must not be a symlink")
    return path


def _fresh_path(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    try:
        supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
        if not supplied.name or supplied == Path(supplied.anchor):
            raise WorkerError(f"{label} must not be a filesystem root")
        parent = supplied.parent.resolve(strict=True)
        path = parent / supplied.name
        metadata = os.lstat(parent)
    except WorkerError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerError(f"invalid {label}: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise WorkerError(
            f"{label} parent must be a private owned real directory"
        )
    if os.path.lexists(path):
        raise WorkerError(f"{label} must be a fresh path")
    return path


def _publish_envelope(path: Path, envelope: bytes) -> None:
    if not isinstance(envelope, bytes) or len(envelope) > _MAX_ENVELOPE_BYTES:
        raise WorkerError("worker measurement envelope must be bounded bytes")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
            0o400,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(envelope)
            stream.flush()
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except OSError as exc:
        raise WorkerError(
            f"cannot publish worker measurement envelope: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _bytes_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise WorkerError(message)


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python -m aragorn.worker_supervisor_v2",
        description=(
            "Import, execute, export, and sign one protocol-v2 benchmark job."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("run")
    command.add_argument("--input-bundle", type=Path, required=True)
    command.add_argument("--input-manifest-digest", required=True)
    command.add_argument("--request-digest", required=True)
    command.add_argument("--expected-challenge", required=True)
    command.add_argument("--input-state", type=Path, required=True)
    command.add_argument("--output-state", type=Path, required=True)
    command.add_argument("--output-bundle", type=Path, required=True)
    command.add_argument("--measurement-output", type=Path, required=True)
    command.add_argument("--signing-key", type=Path, required=True)
    command.add_argument("--worker-id", required=True)
    command.add_argument("--trust-domain", required=True)
    command.add_argument("--key-id", required=True)
    command.add_argument("--lock", type=Path, default=LOCK)
    command.add_argument("--docker", default="docker")
    command.add_argument("--workspace-root", type=Path)
    command.set_defaults(action=_run_command)
    return parser


def _run_command(args: argparse.Namespace) -> dict[str, str]:
    return supervise(
        input_bundle=args.input_bundle,
        input_manifest_digest=args.input_manifest_digest,
        request_digest=args.request_digest,
        expected_challenge=args.expected_challenge,
        input_state=args.input_state,
        output_state=args.output_state,
        output_bundle=args.output_bundle,
        measurement_output=args.measurement_output,
        signing_key=args.signing_key,
        worker_id=args.worker_id,
        trust_domain=args.trust_domain,
        key_id=args.key_id,
        lock_path=args.lock,
        docker_executable=args.docker,
        workspace_root=args.workspace_root,
    )


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        document = arguments.action(arguments)
        print(canonical_json(document).decode("ascii"))
        return 0
    except (CASError, OSError, RuntimeError, ValueError) as exc:
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
