"""Execute one imported protocol-v2 request without private benchmark labels."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from .benchmark_protocol_v2 import (
    canonical_result_digest_v2,
    validate_portable_policy,
    validate_worker_request_v2,
    validate_worker_result_v2,
    verify_effective_config_binding_v2,
    verify_effective_config_policy_v2,
    verify_request_bindings_v2,
    verify_request_result_binding_v2,
)
from .benchmark_semantic_closure_v2 import (
    SemanticClosureError,
    derive_worker_input_cas_closure,
    verify_worker_output_evidence_cas_v2,
)
from .cas import CAS, CASError
from .oci_benchmark_runner import (
    _oci_workspace,
    _preflight,
    _retain_docker,
    _retain_execution_evidence,
)
from .oci_runtime import (
    LOCK,
    _sha256,
    _verify_docker_unchanged,
    resolve_docker,
    run_baseline,
)
from .oci_worker import (
    WorkerError,
    _copy_exact,
    _enumerate_canonical_cas,
    _load_object,
    _output_transaction,
    _paths_overlap,
    _read_canonical_object,
    _resolve_workspace_root,
)
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_json,
    validate_subject_manifest,
)


_MAX_REQUEST_BYTES = 64 * 1024
_MAX_POLICY_BYTES = 8 * 1024 * 1024
_MAX_SUBJECT_MANIFEST_BYTES = 128 * 1024 * 1024


def run(
    *,
    request_digest: str,
    expected_challenge: str,
    input_state: str | os.PathLike[str],
    output_state: str | os.PathLike[str],
    lock_path: str | os.PathLike[str] = LOCK,
    docker_executable: str | os.PathLike[str] = "docker",
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Execute one exact imported v2 input closure into a fresh output CAS."""

    input_path, output_path, local_lock = _resolve_boundaries(
        input_state,
        output_state,
        lock_path,
    )
    input_cas = CAS(input_path, read_only=True)
    try:
        input_closure = derive_worker_input_cas_closure(
            input_cas,
            request_digest,
            expected_challenge=expected_challenge,
        )
    except (CASError, SemanticClosureError) as exc:
        raise WorkerError(f"worker v2 input closure is invalid: {exc}") from exc
    actual_input = _enumerate_canonical_cas(input_path)
    if actual_input != set(input_closure):
        raise WorkerError("worker v2 input CAS is not the exact request closure")

    request, _raw_request = _read_canonical_object(
        input_cas,
        request_digest,
        max_bytes=_MAX_REQUEST_BYTES,
        label="worker request v2",
        validator=validate_worker_request_v2,
    )
    policy_digest = request["portable_policy_digest"]
    policy, _raw_policy = _read_canonical_object(
        input_cas,
        policy_digest,
        max_bytes=_MAX_POLICY_BYTES,
        label="portable worker policy",
        validator=validate_portable_policy,
    )
    manifest_digest = request["subject"]["manifest_digest"]
    manifest, _raw_manifest = _read_canonical_object(
        input_cas,
        manifest_digest,
        max_bytes=_MAX_SUBJECT_MANIFEST_BYTES,
        label="worker subject manifest",
        validator=validate_subject_manifest,
    )
    try:
        verify_request_bindings_v2(
            request,
            manifest,
            policy,
            expected_challenge=expected_challenge,
        )
    except WorkerProtocolError as exc:
        raise WorkerError(f"worker v2 request bindings are invalid: {exc}") from exc

    docker = resolve_docker(docker_executable)
    if _paths_overlap(docker.path, input_path) or _paths_overlap(
        docker.path,
        output_path,
    ):
        raise WorkerError("Docker executable must be outside worker CAS roots")
    scratch_root = _resolve_workspace_root(
        workspace_root,
        forbidden=(input_path, output_path, local_lock, docker.path),
    )

    with _output_transaction(output_path) as (output_cas, staging_path):
        for digest, size in input_closure.items():
            content = input_cas.read(digest, max_bytes=size)
            if len(content) != size:
                raise WorkerError("worker v2 input blob changed size during copy")
            _copy_exact(output_cas, content, digest, "worker v2 input blob")

        prepared = _select_preflight_v2(
            policy,
            lock_path=local_lock,
            docker_executable=docker.path,
        )
        if prepared.docker != docker:
            raise WorkerError(
                "worker v2 preflight changed the Docker executable identity"
            )
        docker_digest = _retain_docker(output_cas, prepared.docker)
        effective = _load_object(
            prepared.effective_config_json,
            "effective OCI configuration v2",
        )
        try:
            verify_effective_config_policy_v2(
                policy,
                effective,
                expected_config_digest=_sha256(
                    prepared.effective_config_json
                ),
                expected_docker_digest=docker_digest,
            )
        except WorkerProtocolError as exc:
            raise WorkerError(
                f"worker v2 effective policy is invalid before launch: {exc}"
            ) from exc

        with tempfile.TemporaryDirectory(
            prefix=".aragorn-worker-v2-",
            dir=scratch_root,
        ) as temporary:
            opaque_root = Path(temporary).resolve(strict=True)
            with _oci_workspace(
                input_cas,
                manifest,
                parent=opaque_root,
                forbidden_roots=(
                    input_path,
                    staging_path,
                    local_lock,
                ),
            ) as workspace:
                execution = run_baseline(
                    prepared.baseline["name"],
                    workspace=workspace,
                    expected_tree_digest=request["subject"]["tree_digest"],
                    lock_path=local_lock,
                    docker_executable=prepared.docker.path,
                    timeout_seconds=policy["limits"]["timeout_seconds"],
                    output_limit_bytes=policy["limits"]["output_bytes"],
                    expected_effective_config_json=(
                        prepared.effective_config_json
                    ),
                )
                retained = _retain_execution_evidence(
                    output_cas,
                    subject_digest=request["subject"]["tree_digest"],
                    prepared=prepared,
                    result=execution,
                )

        result = {
            "schema": "aragorn/benchmark-worker-result/v2",
            "job_id": request["job_id"],
            "verifier_challenge": request["verifier_challenge"],
            "request_digest": request_digest,
            "portable_policy_digest": policy_digest,
            "subject_manifest_digest": manifest_digest,
            "tree_digest": request["subject"]["tree_digest"],
            "system": dict(request["system"]),
            "docker_executable_digest": docker_digest,
            **retained,
        }
        try:
            validate_worker_result_v2(result)
            verify_request_result_binding_v2(
                request,
                policy,
                result,
                expected_request_digest=request_digest,
                expected_challenge=expected_challenge,
            )
            verify_effective_config_binding_v2(
                policy,
                result,
                effective,
            )
        except WorkerProtocolError as exc:
            raise WorkerError(f"worker v2 result is invalid: {exc}") from exc
        _verify_docker_unchanged(prepared.docker)
        raw_result = canonical_json(result)
        result_digest = canonical_result_digest_v2(result)
        _copy_exact(
            output_cas,
            raw_result,
            result_digest,
            "worker result v2",
        )
        try:
            closure = verify_worker_output_evidence_cas_v2(
                output_cas,
                result_digest,
                expected_request_digest=request_digest,
                expected_challenge=expected_challenge,
            )
        except SemanticClosureError as exc:
            raise WorkerError(
                f"worker v2 retained evidence is invalid: {exc}"
            ) from exc
        actual_output = _enumerate_canonical_cas(output_cas.root)
        if actual_output != set(closure):
            missing = sorted(set(closure) - actual_output)
            extra = sorted(actual_output - set(closure))
            raise WorkerError(
                "worker v2 output CAS is not the exact result closure; "
                f"missing={missing!r}, extra={extra!r}"
            )
    return result


def _select_preflight_v2(
    policy: dict[str, Any],
    *,
    lock_path: Path,
    docker_executable: Path,
) -> Any:
    prepared = _preflight(
        lock_path=lock_path,
        docker_executable=docker_executable,
        timeout_seconds=policy["limits"]["timeout_seconds"],
        output_limit_bytes=policy["limits"]["output_bytes"],
    )
    selected = [
        item
        for item in prepared
        if {
            field: item.system[field]
            for field in ("name", "version", "implementation_digest")
        }
        == policy["system"]
    ]
    if len(selected) != 1:
        raise WorkerError(
            "worker v2 policy does not match one local baseline identity"
        )
    item = selected[0]
    comparisons = {
        "baseline lock": (
            _sha256(item.raw_lock),
            policy["baseline"]["lock_digest"],
        ),
        "baseline entry": (
            _sha256(item.selected_json),
            policy["baseline"]["entry_digest"],
        ),
        "image": (
            {
                field: item.baseline["image"][field]
                for field in (
                    "index_digest",
                    "platform_manifest_digest",
                    "config_digest",
                    "build_provenance_manifest_digest",
                    "os",
                    "architecture",
                    "size_bytes",
                )
            },
            policy["image"],
        ),
    }
    for label, (actual, expected) in comparisons.items():
        if actual != expected:
            raise WorkerError(f"worker v2 policy {label} changed before launch")
    effective = _load_object(
        item.effective_config_json,
        "effective OCI configuration v2",
    )
    try:
        verify_effective_config_policy_v2(
            policy,
            effective,
            expected_config_digest=_sha256(item.effective_config_json),
            expected_docker_digest=item.docker.digest,
        )
    except WorkerProtocolError as exc:
        raise WorkerError(
            f"worker v2 effective policy is invalid before launch: {exc}"
        ) from exc
    return item


def _resolve_boundaries(
    input_state: str | os.PathLike[str],
    output_state: str | os.PathLike[str],
    lock_path: str | os.PathLike[str],
) -> tuple[Path, Path, Path]:
    try:
        input_path = Path(input_state).expanduser().resolve(strict=True)
        output_path = Path(output_state).expanduser().resolve(strict=False)
        local_lock = _trusted_read_only_file(lock_path, "baseline lock")
    except WorkerError:
        raise
    except (OSError, RuntimeError) as exc:
        raise WorkerError(f"cannot resolve worker v2 paths: {exc}") from exc
    if not input_path.is_dir():
        raise WorkerError("worker v2 input state must be a directory")
    if output_path.exists():
        raise WorkerError("worker v2 output state must be a fresh path")
    if _paths_overlap(input_path, output_path):
        raise WorkerError("worker v2 input and output CAS roots overlap")
    if _paths_overlap(local_lock, input_path) or _paths_overlap(
        local_lock,
        output_path,
    ):
        raise WorkerError("baseline lock must be outside worker v2 CAS roots")
    return input_path, output_path, local_lock


def _trusted_read_only_file(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    try:
        supplied = Path(
            os.path.abspath(os.path.expanduser(os.fspath(value)))
        )
        current = Path(supplied.anchor)
        for part in supplied.parts[1:]:
            current /= part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode):
                raise WorkerError(f"{label} path must not contain symlinks")
        path = supplied.resolve(strict=True)
        metadata = os.lstat(path)
    except WorkerError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise WorkerError(f"invalid {label} path: {exc}") from exc
    mode = stat.S_IMODE(metadata.st_mode)
    owner_is_worker = metadata.st_uid == os.geteuid()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or (owner_is_worker and mode & 0o222)
        or (not owner_is_worker and mode & 0o022)
    ):
        raise WorkerError(
            f"{label} must be a root- or worker-owned non-writable regular file"
        )
    return path
