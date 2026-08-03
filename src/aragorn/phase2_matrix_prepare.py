"""Prepare an exact public-source Phase 2 suite and pre-outcome coverage lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from . import gvisor_runtime
from .artifact_closure import canonical_json, load_verified_retained_manifest
from .behavior_capability_diff import CAPABILITY_KINDS
from .benchmark import (
    _read_bounded,
    _validate_phase2_coverage_lock,
    load_suite_for_run,
)
from .cas import CAS, CASError
from .github_gateway import (
    GatewayQuarantineReceipt,
    build_gateway_request,
    quarantine_through_gateway,
)
from .phase0_candidate import candidate_implementation_digest

CATALOG_SCHEMA = "aragorn/phase2-matrix-catalog/v1"
CATALOG_ASSURANCE = "operator_authored_inert_plumbing_not_independent_efficacy"
OPERATOR_INDEX_SCHEMA = "aragorn/phase2-matrix-operator-index/v1"
OPERATOR_INDEX_AUTHORITY = "RELATIVE_PATH_HINTS_ONLY_NOT_EVIDENCE_OR_PHASE2_AUTHORITY"

_COVERAGE_LOCK_SCHEMA = "aragorn/benchmark-phase2-coverage-lock/v1"
_COVERAGE_LOCK_ASSURANCE = (
    "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
)
_VERDICT_PROFILE = "undeclared-observed-review/v1"
_SUITE_ID = "phase2-public-matrix-v1"
_ENTRYPOINT = "run.sh"
_MAX_CATALOG_BYTES = 1024 * 1024
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

Gateway = Callable[..., GatewayQuarantineReceipt]


class Phase2MatrixPrepareError(ValueError):
    """The Phase 2 matrix cannot be prepared without weakening its bindings."""


def prepare_phase2_matrix(
    catalog: object | str | os.PathLike[str],
    work_root: str | os.PathLike[str],
    *,
    worker_uid: int,
    worker_gid: int,
    gateway: Gateway = quarantine_through_gateway,
) -> str:
    """Acquire, materialize, and freeze one exact 20-case Phase 2 matrix."""

    document = _validate_catalog(_load_catalog(catalog))
    final, parent = _fresh_destination(work_root)
    staging = parent / f".{final.name}.prepare-{secrets.token_hex(16)}"
    published = False
    identity: tuple[int, int] | None = None
    parent_descriptor = -1
    try:
        lock_digest = _prepare_staged_matrix(
            document,
            staging,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
            gateway=gateway,
        )
        staging_metadata = os.lstat(staging)
        if (
            not stat.S_ISDIR(staging_metadata.st_mode)
            or stat.S_ISLNK(staging_metadata.st_mode)
            or staging_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(staging_metadata.st_mode) & 0o022
        ):
            raise Phase2MatrixPrepareError("staging work root is not protected")
        identity = (staging_metadata.st_dev, staging_metadata.st_ino)
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        _require_absent(final, "final work root must remain fresh")
        os.rename(
            staging.name,
            final.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        published = True
        final_metadata = os.stat(
            final.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (final_metadata.st_dev, final_metadata.st_ino) != identity:
            raise Phase2MatrixPrepareError("published work root identity changed")
        os.fsync(parent_descriptor)
        return lock_digest
    except BaseException as exc:
        cleanup = final if published else staging
        try:
            _remove_work_tree(
                cleanup, expected_identity=identity if published else None
            )
        except (OSError, RuntimeError, ValueError) as cleanup_exc:
            raise Phase2MatrixPrepareError(
                f"Phase 2 prepare failed and cleanup failed: {cleanup_exc}"
            ) from exc
        raise
    finally:
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def _prepare_staged_matrix(
    document: dict[str, Any],
    work_root: Path,
    *,
    worker_uid: int,
    worker_gid: int,
    gateway: Gateway,
) -> str:
    root, gateway_root, sources_root, suite_root = _create_work_root(
        work_root,
        worker_uid=worker_uid,
        worker_gid=worker_gid,
    )
    candidate = {
        "name": "aragorn",
        "version": document["candidate"]["version"],
        "implementation_digest": candidate_implementation_digest(),
        "config_digest": _digest_bytes(canonical_json(document["candidate"]["config"])),
    }

    acquired: dict[str, dict[str, Any]] = {}
    for case in document["cases"]:
        case_id = case["case_id"]
        skill_path = f"{document['source']['case_root']}/{case_id}"
        request = build_gateway_request(
            document["source"]["owner"],
            document["source"]["repository"],
            document["source"]["commit"],
            skill_path,
        )
        source_state = sources_root / case_id
        receipt = gateway(
            request,
            gateway_root=gateway_root,
            quarantine_state=source_state,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
        )
        acquired[case_id] = _materialize_acquired_case(
            receipt,
            expected_source_state=source_state,
            destination=suite_root / "cases" / case_id,
        )

    suite = _suite_document(document, candidate, acquired)
    suite_path = suite_root / "phase2-suite.json"
    _write_new(suite_path, canonical_json(suite))
    with tempfile.TemporaryDirectory(prefix="aragorn-phase2-suite-") as temporary:
        loaded = load_suite_for_run(
            suite_path,
            CAS(Path(temporary) / "cas"),
            required_purpose="evidence_smoke",
        )
    if loaded["canonical"] != suite:
        raise Phase2MatrixPrepareError("materialized suite did not remain canonical")
    for case_id, source in acquired.items():
        if loaded["manifests"][case_id]["tree_digest"] != source["tree_digest"]:
            raise Phase2MatrixPrepareError(
                f"{case_id}: acquired and materialized trees differ"
            )

    canary_raw, _canary = gvisor_runtime.load_gvisor_detonation_canary_lock()
    coverage_lock = {
        "schema": _COVERAGE_LOCK_SCHEMA,
        "assurance": _COVERAGE_LOCK_ASSURANCE,
        "suite_digest": loaded["digest"],
        "evaluation_split": "held_out",
        "runs_per_case": 5,
        "candidate_system": candidate,
        "verdict_profile": _VERDICT_PROFILE,
        "gvisor": {
            "receipt_schema": gvisor_runtime.ARTIFACT_SCHEMA_V4,
            "normalization_profile": (
                gvisor_runtime.ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE
            ),
            "execution_profile": gvisor_runtime.ARTIFACT_EXECUTION_PROFILE,
            "lock_digest": _digest_bytes(canary_raw),
            "verifier_implementation_digest": (
                _gvisor_artifact_implementation_digest()
            ),
        },
        "cases": [
            {
                "case_id": case_id,
                "class": loaded["cases"][case_id]["class"],
                "family": loaded["cases"][case_id]["family"],
                "lineage": loaded["cases"][case_id]["lineage"],
                "tree_digest": acquired[case_id]["tree_digest"],
                "suite_manifest_digest": _digest_bytes(
                    canonical_json(loaded["manifests"][case_id])
                ),
                "source_manifest_digest": acquired[case_id]["manifest_digest"],
                "quarantine_receipt_digest": acquired[case_id][
                    "quarantine_receipt_digest"
                ],
                "gateway_profile_digest": acquired[case_id]["gateway_profile_digest"],
                "entrypoint_path": _ENTRYPOINT,
                "entrypoint_digest": acquired[case_id]["entrypoint_digest"],
                "declared_capabilities": list(
                    next(
                        case["declared_capabilities"]
                        for case in document["cases"]
                        if case["case_id"] == case_id
                    )
                ),
            }
            for case_id in sorted(acquired)
        ],
    }
    lock_raw = canonical_json(coverage_lock)
    lock_digest = _digest_bytes(lock_raw)
    lock_path = root / "coverage-lock.json"
    _write_new(lock_path, lock_raw)
    _validate_phase2_coverage_lock(
        lock_path,
        expected_digest=lock_digest,
        suite_digest=loaded["digest"],
        runs_per_case=loaded["runs_per_case"],
        cases=loaded["cases"],
        systems=loaded["systems"],
        manifests=loaded["manifests"],
    )

    operator_index = {
        "schema": OPERATOR_INDEX_SCHEMA,
        "authority": OPERATOR_INDEX_AUTHORITY,
        "coverage_lock_digest": lock_digest,
        "suite_path": "suite/phase2-suite.json",
        "coverage_lock_path": "coverage-lock.json",
        "evidence_state_path": "evidence",
        "results_path": "results",
        "cases": [
            {
                "case_id": case_id,
                "source_state_path": f"sources/{case_id}",
            }
            for case_id in sorted(acquired)
        ],
    }
    _write_new(root / "operator-index.json", canonical_json(operator_index))
    return lock_digest


def _load_catalog(value: object | str | os.PathLike[str]) -> dict[str, Any]:
    if isinstance(value, (str, os.PathLike)):
        try:
            raw = _read_bounded(Path(value).expanduser())
        except (OSError, RuntimeError, ValueError) as exc:
            raise Phase2MatrixPrepareError(f"cannot read catalog: {exc}") from exc
        if not 0 < len(raw) <= _MAX_CATALOG_BYTES:
            raise Phase2MatrixPrepareError("catalog must be a bounded regular file")
    else:
        raw = canonical_json(value)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise Phase2MatrixPrepareError(f"invalid catalog JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise Phase2MatrixPrepareError("catalog must be a JSON object")
    return document


def _validate_catalog(document: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        document,
        {"schema", "assurance", "source", "candidate", "cases"},
        "catalog",
    )
    if (
        document["schema"] != CATALOG_SCHEMA
        or document["assurance"] != CATALOG_ASSURANCE
    ):
        raise Phase2MatrixPrepareError("catalog authority is unsupported")

    source = _exact_object(
        document["source"],
        {"owner", "repository", "commit", "case_root"},
        "catalog.source",
    )
    case_root = _relative_path(source["case_root"], "catalog.source.case_root")
    candidate = _exact_object(
        document["candidate"], {"name", "version", "config"}, "catalog.candidate"
    )
    if candidate["name"] != "aragorn":
        raise Phase2MatrixPrepareError("catalog candidate must be Aragorn")
    version = candidate["version"]
    if (
        not isinstance(version, str)
        or not version
        or version != version.strip()
        or "\r" in version
        or "\n" in version
        or len(version) > 256
    ):
        raise Phase2MatrixPrepareError("catalog candidate version is invalid")
    config = _exact_object(
        candidate["config"],
        {
            "evaluation_split",
            "runs_per_case",
            "verdict_profile",
            "gvisor_receipt_schema",
            "normalization_profile",
            "execution_profile",
            "entrypoint_path",
        },
        "catalog.candidate.config",
    )
    expected_config = {
        "evaluation_split": "held_out",
        "runs_per_case": 5,
        "verdict_profile": _VERDICT_PROFILE,
        "gvisor_receipt_schema": gvisor_runtime.ARTIFACT_SCHEMA_V4,
        "normalization_profile": (
            gvisor_runtime.ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE
        ),
        "execution_profile": gvisor_runtime.ARTIFACT_EXECUTION_PROFILE,
        "entrypoint_path": _ENTRYPOINT,
    }
    if config != expected_config:
        raise Phase2MatrixPrepareError("catalog candidate config is unsupported")

    raw_cases = document["cases"]
    if not isinstance(raw_cases, list) or len(raw_cases) != 20:
        raise Phase2MatrixPrepareError("catalog must contain exactly 20 cases")
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_cases):
        case = _exact_object(
            value,
            {"case_id", "class", "family", "lineage", "declared_capabilities"},
            f"catalog.cases[{index}]",
        )
        case_id = _identifier(case["case_id"], f"catalog.cases[{index}].case_id")
        if case_id in seen:
            raise Phase2MatrixPrepareError("catalog repeats a case_id")
        seen.add(case_id)
        case_class = case["class"]
        family = _identifier(case["family"], f"catalog.cases[{index}].family")
        lineage = _identifier(case["lineage"], f"catalog.cases[{index}].lineage")
        if case_class not in {"benign", "adversarial"}:
            raise Phase2MatrixPrepareError("catalog case class is unsupported")
        if (case_class == "benign") != (family == "benign"):
            raise Phase2MatrixPrepareError("catalog case class and family disagree")
        declared = case["declared_capabilities"]
        if (
            not isinstance(declared, list)
            or any(
                not isinstance(capability, str) or capability not in CAPABILITY_KINDS
                for capability in declared
            )
            or declared != sorted(set(declared))
        ):
            raise Phase2MatrixPrepareError(
                "catalog declared capabilities must be canonical categories"
            )
        build_gateway_request(
            source["owner"],
            source["repository"],
            source["commit"],
            f"{case_root}/{case_id}",
        )
        cases.append(
            {
                "case_id": case_id,
                "class": case_class,
                "family": family,
                "lineage": lineage,
                "declared_capabilities": list(declared),
            }
        )
    return {
        "schema": CATALOG_SCHEMA,
        "assurance": CATALOG_ASSURANCE,
        "source": {
            "owner": source["owner"],
            "repository": source["repository"],
            "commit": source["commit"],
            "case_root": case_root,
        },
        "candidate": {
            "name": "aragorn",
            "version": version,
            "config": config,
        },
        "cases": sorted(cases, key=lambda case: case["case_id"]),
    }


def _fresh_destination(value: str | os.PathLike[str]) -> tuple[Path, Path]:
    supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    if not supplied.name or supplied == Path(supplied.anchor):
        raise Phase2MatrixPrepareError("work root must not be a filesystem root")
    parent = _protected_parent(supplied.parent)
    final = parent / supplied.name
    _require_absent(final, "final work root must be fresh")
    return final, parent


def _protected_parent(value: Path) -> Path:
    try:
        parent = value.resolve(strict=True)
        metadata = parent.stat()
    except (OSError, RuntimeError) as exc:
        raise Phase2MatrixPrepareError(
            f"cannot resolve work root parent: {exc}"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise Phase2MatrixPrepareError(
            "work root parent must be protected and owned by the broker"
        )
    return parent


def _require_absent(path: Path, message: str) -> None:
    if os.path.lexists(path):
        raise Phase2MatrixPrepareError(message)


def _remove_work_tree(path: Path, *, expected_identity: tuple[int, int] | None) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (
            expected_identity is not None
            and (metadata.st_dev, metadata.st_ino) != expected_identity
        )
    ):
        raise Phase2MatrixPrepareError("refusing to remove a substituted work tree")
    shutil.rmtree(path)
    descriptor = os.open(
        path.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_work_root(
    value: str | os.PathLike[str], *, worker_uid: int, worker_gid: int
) -> tuple[Path, Path, Path, Path]:
    for label, identity in (("worker_uid", worker_uid), ("worker_gid", worker_gid)):
        if (
            isinstance(identity, bool)
            or not isinstance(identity, int)
            or not 0 < identity < 2**31
        ):
            raise Phase2MatrixPrepareError(
                f"{label} must identify a non-root principal"
            )
    supplied = Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    try:
        parent = _protected_parent(supplied.parent)
        root = parent / supplied.name
        root.mkdir(mode=0o700)
        if root.stat().st_gid != worker_gid:
            os.chown(root, -1, worker_gid)
        os.chmod(root, 0o710)
        gateway_root = root / "gateway"
        sources_root = root / "sources"
        suite_root = root / "suite"
        gateway_root.mkdir(mode=0o700)
        os.chown(gateway_root, worker_uid, worker_gid)
        os.chmod(gateway_root, 0o700)
        sources_root.mkdir(mode=0o700)
        suite_root.mkdir(mode=0o700)
        (suite_root / "cases").mkdir(mode=0o700)
    except Phase2MatrixPrepareError:
        raise
    except FileExistsError as exc:
        raise Phase2MatrixPrepareError("work root must be fresh") from exc
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise Phase2MatrixPrepareError(f"cannot create work root: {exc}") from exc
    return root, gateway_root, sources_root, suite_root


def _materialize_acquired_case(
    receipt: GatewayQuarantineReceipt,
    *,
    expected_source_state: Path,
    destination: Path,
) -> dict[str, Any]:
    if not isinstance(receipt, GatewayQuarantineReceipt):
        raise Phase2MatrixPrepareError("gateway returned an unsupported receipt")
    try:
        actual_state = receipt.quarantine_state.resolve(strict=True)
        expected_state = expected_source_state.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise Phase2MatrixPrepareError(
            f"gateway source state is unavailable: {exc}"
        ) from exc
    if actual_state != expected_state:
        raise Phase2MatrixPrepareError("gateway substituted the quarantine state")
    manifest_digest = _digest(receipt.manifest_digest, "source manifest")
    tree_digest = _digest(receipt.tree_digest, "source tree")
    quarantine_digest = _digest(receipt.quarantine_receipt_digest, "quarantine receipt")
    gateway_digest = _digest(receipt.gateway_profile_digest, "gateway profile")
    source_cas = CAS(expected_state, read_only=True)
    manifest = load_verified_retained_manifest(source_cas, manifest_digest)
    if (
        manifest["tree_digest"] != tree_digest
        or len(manifest["files"]) != receipt.file_count
    ):
        raise Phase2MatrixPrepareError("gateway receipt and source manifest disagree")
    entrypoints = [entry for entry in manifest["files"] if entry["path"] == _ENTRYPOINT]
    if len(entrypoints) != 1:
        raise Phase2MatrixPrepareError("acquired case requires exactly one root run.sh")

    destination.mkdir(mode=0o700)
    for entry in manifest["files"]:
        if entry["executable"]:
            raise Phase2MatrixPrepareError(
                "acquired case contains an executable benchmark fixture"
            )
        relative = _relative_path(entry["path"], "source manifest file path")
        target = destination.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        source_cas.materialize(entry["digest"], target, root=destination)
    return {
        "manifest_digest": manifest_digest,
        "tree_digest": tree_digest,
        "quarantine_receipt_digest": quarantine_digest,
        "gateway_profile_digest": gateway_digest,
        "entrypoint_digest": entrypoints[0]["digest"],
    }


def _suite_document(
    catalog: dict[str, Any],
    candidate: dict[str, str],
    acquired: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-suite/v1",
        "id": _SUITE_ID,
        "purpose": "evidence_smoke",
        "runs_per_case": 5,
        "systems": [candidate],
        "cases": [
            {
                "schema": "aragorn/benchmark-case/v1",
                "id": case["case_id"],
                "class": case["class"],
                "family": case["family"],
                "lineage": case["lineage"],
                "split": "held_out",
                "path": f"cases/{case['case_id']}",
                "tree_digest": acquired[case["case_id"]]["tree_digest"],
                "inert": True,
                "source": {
                    "kind": "synthetic",
                    "reference": (
                        "phase2-github-source:"
                        + acquired[case["case_id"]]["manifest_digest"]
                    ),
                    "license": "UNLICENSED",
                },
            }
            for case in catalog["cases"]
        ],
    }


def _gvisor_artifact_implementation_digest() -> str:
    source_root = Path(gvisor_runtime.__file__).resolve(strict=True).parent
    files: dict[str, str] = {}
    for module in gvisor_runtime._ARTIFACT_IMPLEMENTATION_MODULES:
        path = source_root / module
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise Phase2MatrixPrepareError(
                "gVisor artifact implementation contains a non-regular source"
            )
        files[module] = _digest_bytes(path.read_bytes())
    return _digest_bytes(
        canonical_json(
            {"schema": gvisor_runtime.ARTIFACT_IMPLEMENTATION_SCHEMA, "files": files}
        )
    )


def _write_new(path: Path, content: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o400,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
    except OSError as exc:
        raise Phase2MatrixPrepareError(f"cannot write {path.name}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise Phase2MatrixPrepareError(f"duplicate catalog key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise Phase2MatrixPrepareError(f"non-finite catalog number is unsupported: {value}")


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Phase2MatrixPrepareError(f"{label} must be a JSON object")
    _exact_keys(value, keys, label)
    return value


def _exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise Phase2MatrixPrepareError(f"{label} has missing or unknown fields")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise Phase2MatrixPrepareError(f"{label} is not a canonical identifier")
    return value


def _relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise Phase2MatrixPrepareError(f"{label} must be a relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise Phase2MatrixPrepareError(f"{label} escapes its root")
    return path.as_posix()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise Phase2MatrixPrepareError(f"{label} is not a canonical SHA-256 digest")
    return value


def _digest_bytes(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m aragorn.phase2_matrix_prepare",
        description="Acquire and freeze an inert public-source Phase 2 matrix.",
    )
    parser.add_argument("catalog", type=Path)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--worker-uid", type=int, required=True)
    parser.add_argument("--worker-gid", type=int, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        digest = prepare_phase2_matrix(
            arguments.catalog,
            arguments.work_root,
            worker_uid=arguments.worker_uid,
            worker_gid=arguments.worker_gid,
        )
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
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
