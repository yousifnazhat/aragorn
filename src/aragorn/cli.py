"""Command-line entry point for Aragorn's first admission-control slice."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from io import BytesIO
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
from typing import Any, Iterator, Sequence

from .acquire import InventoryError, ingest_open_directory
from .analyze import MAX_ANALYZER_OUTPUT_BYTES, AnalyzerResult, run_analyzer
from .analyzer_receipt import retain_analyzer_run
from .artifact_closure import (
    MAX_GRAPH_BYTES,
    load_retained_manifest,
    resolve_source_graph,
)
from .cas import CAS, CASError
from .github_acquire import acquire_github_commit
from .github_expand import acquire_github_expansion
from .policy import Policy, evaluate_policy


_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_RECORD_BYTES = MAX_ANALYZER_OUTPUT_BYTES
_MAX_ANALYZERS = 16
_MAX_ANALYZER_EXECUTABLE_BYTES = 128 * 1024 * 1024
_ANALYZER_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_DEFAULT_POLICY_DOCUMENT = {
    "schema": "aragorn/policy/v1",
    "id": "default",
    "version": 1,
    "required_analyzers": ["cisco-skill-scanner", "skillspector"],
    "hard_deny_reason_codes": [
        "ARBITRARY_CODE_EXECUTION",
        "CREDENTIAL_EXFILTRATION",
        "KNOWN_BAD_DIGEST",
        "MALWARE",
    ],
    "review_severities": ["medium", "high", "critical"],
}


class ConfigurationError(ValueError):
    """Operator configuration cannot be interpreted safely."""


class UsageError(ValueError):
    """Command-line syntax is invalid."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        return args.action(args)
    except UsageError as exc:
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
        return 64
    except (CASError, ConfigurationError, InventoryError, OSError, ValueError) as exc:
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


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="aragorn",
        description="Digest-bound admission control for agent capabilities.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser(
        "inventory", help="ingest a bounded local skill tree into the CAS"
    )
    inventory.add_argument("source", type=Path)
    inventory.add_argument("--state", type=Path, default=_default_state())
    inventory.set_defaults(action=_inventory)

    github = commands.add_parser(
        "acquire-github",
        help="evaluation-only acquisition of one public GitHub commit",
    )
    github.add_argument("repository")
    github.add_argument("commit")
    github.add_argument(
        "skill_path",
        help="relative skill directory within the commit, or '.' for repository root",
    )
    github.add_argument("--state", type=Path, default=_default_state())
    github.set_defaults(action=_acquire_github)

    github_expansion = commands.add_parser(
        "expand-github",
        help="evaluation-only expansion of exact same-repository GitHub blob references",
    )
    github_expansion.add_argument("repository")
    github_expansion.add_argument("commit")
    github_expansion.add_argument(
        "skill_path",
        help="relative skill directory within the commit, or '.' for repository root",
    )
    github_expansion.add_argument("--state", type=Path, default=_default_state())
    github_expansion.set_defaults(action=_expand_github)

    resolve = commands.add_parser(
        "resolve-artifacts",
        help="build an evaluation-only literal source-reference graph",
    )
    resolve.add_argument("manifest_digest")
    resolve.add_argument("--state", type=Path, default=_default_state())
    resolve.set_defaults(action=_resolve_artifacts)

    inspect = commands.add_parser(
        "inspect", help="inventory and run Aragorn-protocol analyzer adapters"
    )
    inspect.add_argument("source", type=Path)
    inspect.add_argument("--state", type=Path, default=_default_state())
    inspect.add_argument(
        "--analyzers",
        type=Path,
        help="JSON configuration for administrator-installed analyzer adapters",
    )
    inspect.add_argument("--timeout", type=float, default=120.0)
    inspect.add_argument("--output-limit", type=int, default=1024 * 1024)
    inspect.set_defaults(action=_inspect)
    return parser


def _inventory(args: argparse.Namespace) -> int:
    source_fd, source_path, state_path = _open_source_and_resolve_state(
        args.source, args.state
    )
    try:
        cas = CAS(state_path)
        manifest = ingest_open_directory(source_path, source_fd, cas)
        _assert_source_capability(source_fd, source_path)
    finally:
        os.close(source_fd)
    manifest_digest = _put_json(cas, manifest)
    print(
        json.dumps(
            {
                "schema": "aragorn/inventory-result/v1",
                "manifest_digest": manifest_digest,
                "tree_digest": manifest["tree_digest"],
                "file_count": len(manifest["files"]),
                "closure": manifest["closure"],
            },
            sort_keys=True,
        )
    )
    return 0


def _acquire_github(args: argparse.Namespace) -> int:
    state_path = args.state.expanduser().resolve(strict=False)
    cas = CAS(state_path)
    manifest = acquire_github_commit(
        args.repository,
        args.commit,
        args.skill_path,
        cas,
    )
    manifest_digest = _put_json(cas, manifest)
    print(
        json.dumps(
            {
                "schema": "aragorn/inventory-result/v1",
                "manifest_digest": manifest_digest,
                "tree_digest": manifest["tree_digest"],
                "file_count": len(manifest["files"]),
                "closure": manifest["closure"],
            },
            sort_keys=True,
        )
    )
    return 0


def _expand_github(args: argparse.Namespace) -> int:
    state_path = args.state.expanduser().resolve(strict=False)
    result = acquire_github_expansion(
        args.repository,
        args.commit,
        args.skill_path,
        CAS(state_path),
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["closure"]["status"] == "complete" else 2


def _resolve_artifacts(args: argparse.Namespace) -> int:
    state_path = args.state.expanduser().resolve(strict=False)
    cas = CAS(state_path)
    manifest = load_retained_manifest(cas, args.manifest_digest)
    graph = resolve_source_graph(
        manifest,
        cas,
        root_manifest_digest=args.manifest_digest,
    )
    graph_digest = _put_json(
        cas,
        graph,
        max_bytes=MAX_GRAPH_BYTES,
        record_name="source-reference graph",
    )
    print(
        json.dumps(
            {
                "schema": "aragorn/resolve-artifacts-result/v1",
                "assurance": graph["assurance"],
                "root_manifest_digest": args.manifest_digest,
                "graph_digest": graph_digest,
                "closure": graph["closure"],
            },
            sort_keys=True,
        )
    )
    return 0 if graph["closure"]["status"] == "complete" else 2


def _inspect(args: argparse.Namespace) -> int:
    if (
        isinstance(args.output_limit, bool)
        or not isinstance(args.output_limit, int)
        or not 1 <= args.output_limit <= _MAX_RECORD_BYTES
    ):
        raise ConfigurationError(
            f"output limit must be between 1 and {_MAX_RECORD_BYTES} bytes"
        )
    source_fd, source_path, state_path = _open_source_and_resolve_state(
        args.source, args.state
    )
    cas = CAS(state_path)
    try:
        configuration_document = _validate_configuration_location(
            args.analyzers, source_path, state_path
        )
        specifications = _validate_analyzer_locations(
            _load_analyzers(configuration_document),
            source_path,
            state_path,
            cas=cas,
        )
        _assert_source_capability(source_fd, source_path)
        manifest = ingest_open_directory(source_path, source_fd, cas)
        _assert_source_capability(source_fd, source_path)
    finally:
        os.close(source_fd)
    manifest_digest = _put_json(cas, manifest)

    collected_results = []
    for specification in specifications:
        with _materialized_analyzer(cas, specification) as command:
            with _analysis_workspace(cas, manifest) as workspace:
                collected_results.append(
                    run_analyzer(
                        command,
                        workspace=workspace,
                        name=specification["name"],
                        version=specification["version"],
                        config_digest=specification["config_digest"],
                        executable_digest=specification["executable_digest"],
                        subject_digest=manifest["tree_digest"],
                        configuration_bytes=cas.read(
                            specification["config_digest"],
                            max_bytes=_MAX_CONFIG_BYTES,
                        ),
                        timeout_seconds=args.timeout,
                        output_limit_bytes=args.output_limit,
                    )
                )
    results = tuple(collected_results)

    policy = Policy(
        required_analyzers=tuple(_DEFAULT_POLICY_DOCUMENT["required_analyzers"]),
        hard_deny_reason_codes=frozenset(
            _DEFAULT_POLICY_DOCUMENT["hard_deny_reason_codes"]
        ),
        review_severities=frozenset(_DEFAULT_POLICY_DOCUMENT["review_severities"]),
    )
    decision = evaluate_policy(policy, closure=manifest["closure"], results=results)

    analyzer_records = []
    if results:
        from .phase0_candidate import candidate_implementation_digest

        verifier_implementation_digest = candidate_implementation_digest()
    for result in results:
        observation_digests = tuple(
            _put_bytes(cas, observation.document_json.encode("ascii"))
            for observation in result.observations
        )
        analyzer_records.append(
            _result_record(
                result,
                observation_digests,
                run_receipt_digest=retain_analyzer_run(
                    cas,
                    result,
                    verifier_implementation_digest=verifier_implementation_digest,
                ),
                stdout_digest=_put_bytes(cas, result.raw_stdout),
                stderr_digest=_put_bytes(cas, result.raw_stderr),
            )
        )

    receipt = {
        "schema": "aragorn/decision/v2",
        "authority": "EVIDENCE_SUMMARY_ONLY_NOT_INSTALLER_AUTHORITY",
        "verdict": decision.verdict,
        "manifest_digest": manifest_digest,
        "tree_digest": manifest["tree_digest"],
        "artifact_digests": sorted(entry["digest"] for entry in manifest["files"]),
        "policy": {
            "id": _DEFAULT_POLICY_DOCUMENT["id"],
            "version": _DEFAULT_POLICY_DOCUMENT["version"],
            "digest": _digest_json(_DEFAULT_POLICY_DOCUMENT),
        },
        "analyzers": sorted(analyzer_records, key=lambda record: record["name"]),
        "reason_codes": list(decision.reason_codes),
    }
    receipt_digest = _put_json(cas, receipt)
    print(
        json.dumps(
            {
                "schema": "aragorn/inspect-result/v2",
                "decision_digest": receipt_digest,
                "decision": receipt,
            },
            sort_keys=True,
        )
    )
    return {"ALLOW": 0, "REVIEW": 2, "DENY": 3, "ERROR": 4}[decision.verdict]


def _load_analyzers(document: dict[str, Any] | None) -> tuple[dict[str, Any], ...]:
    if document is None:
        return ()
    if document.get("schema") != "aragorn/analyzers/v1":
        raise ConfigurationError("unsupported analyzer configuration schema")
    analyzers = document.get("analyzers")
    if not isinstance(analyzers, list):
        raise ConfigurationError("analyzers must be a JSON array")
    if len(analyzers) > _MAX_ANALYZERS:
        raise ConfigurationError(f"at most {_MAX_ANALYZERS} analyzers are supported")

    specifications = []
    names: set[str] = set()
    for index, analyzer in enumerate(analyzers):
        if not isinstance(analyzer, dict) or set(analyzer) != {
            "name",
            "version",
            "argv",
        }:
            raise ConfigurationError(
                f"analyzers[{index}] must contain only name, version, and argv"
            )
        name = analyzer["name"]
        version = analyzer["version"]
        command = analyzer["argv"]
        if not isinstance(name, str) or _ANALYZER_NAME.fullmatch(name) is None:
            raise ConfigurationError(
                f"analyzers[{index}].name must be a canonical lowercase identifier"
            )
        if name in names:
            raise ConfigurationError(f"duplicate analyzer name: {name}")
        names.add(name)
        if (
            not isinstance(version, str)
            or not version
            or version != version.strip()
            or "\r" in version
            or "\n" in version
            or len(version) > 256
        ):
            raise ConfigurationError(
                f"analyzers[{index}].version must be a canonical string of at most 256 characters"
            )
        if (
            not isinstance(command, list)
            or not command
            or any(
                not isinstance(argument, str) or not argument or "\0" in argument
                for argument in command
            )
        ):
            raise ConfigurationError(
                f"analyzers[{index}].argv must be a non-empty string array"
            )
        executable = command[0]
        if not os.path.isabs(executable):
            raise ConfigurationError(
                f"analyzers[{index}].argv[0] must be an absolute path"
            )
        bound = {"name": name, "version": version, "argv": command}
        specifications.append({**bound, "config_digest": _digest_json(bound)})
    return tuple(
        sorted(specifications, key=lambda specification: specification["name"])
    )


def _validate_configuration_location(
    path: Path | None, source: Path, state: Path
) -> dict[str, Any] | None:
    if path is None:
        return None
    return _read_json_object(path.expanduser(), forbidden_roots=(source, state))


def _validate_analyzer_locations(
    specifications: tuple[dict[str, Any], ...],
    source: Path,
    state: Path,
    *,
    cas: CAS | None = None,
) -> tuple[dict[str, Any], ...]:
    validated = []
    for specification in specifications:
        executable = Path(specification["argv"][0])
        try:
            resolved = executable.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError(
                f"cannot resolve analyzer executable {executable}: {exc}"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
            raise ConfigurationError(
                f"analyzer executable must be an executable regular file: {resolved}"
            )
        if _within(resolved, source) or _within(resolved, state):
            raise ConfigurationError(
                "analyzer executable must be outside the inspected source and Aragorn state"
            )
        for argument in specification["argv"][1:]:
            _, separator, option_value = argument.partition("=")
            candidate_value = option_value if separator else argument
            candidate = Path(candidate_value)
            if (
                candidate.is_absolute()
                or candidate_value.startswith("~")
                or ".." in candidate.parts
            ):
                raise ConfigurationError(
                    "absolute, home-relative, and parent-traversing analyzer "
                    "filesystem path arguments are unsupported; "
                    "use a dedicated installed wrapper executable"
                )
        command = [os.fspath(resolved), *specification["argv"][1:]]
        executable_digest = (
            _ingest_analyzer_executable(cas, resolved)
            if cas is not None
            else _hash_analyzer_executable(resolved)
        )
        bound = {
            "name": specification["name"],
            "version": specification["version"],
            "argv": command,
            "operator_argv0": specification["argv"][0],
            "executable_digest": executable_digest,
        }
        config_digest = (
            _put_json(
                cas,
                bound,
                max_bytes=_MAX_CONFIG_BYTES,
                record_name="analyzer effective configuration",
            )
            if cas is not None
            else _digest_json(bound)
        )
        validated.append({**bound, "config_digest": config_digest})
    return tuple(sorted(validated, key=lambda item: item["name"]))


@contextmanager
def _materialized_analyzer(
    cas: CAS, specification: dict[str, Any]
) -> Iterator[tuple[str, ...]]:
    """Launch the exact executable bytes retained during validation."""

    with tempfile.TemporaryDirectory(prefix="aragorn-analyzer-launch-") as temporary:
        root = Path(temporary)
        executable = root / "analyzer"
        cas.materialize(specification["executable_digest"], executable, root=root)
        executable.chmod(0o500)
        yield (os.fspath(executable), *specification["argv"][1:])


@contextmanager
def _analysis_workspace(cas: CAS, manifest: dict[str, Any]) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="aragorn-analysis-") as temporary:
        root = Path(temporary) / "workspace"
        root.mkdir(mode=0o700)
        directories = {root}
        for entry in manifest["files"]:
            relative = _safe_relative_path(entry["path"])
            destination = root.joinpath(*relative.parts)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directories.update(destination.parents)
            cas.materialize(entry["digest"], destination, root=root)
            if entry.get("executable") is True:
                destination.chmod(0o555)

        confined_directories = sorted(
            (
                directory
                for directory in directories
                if directory == root or root in directory.parents
            ),
            key=lambda directory: len(directory.parts),
            reverse=True,
        )
        for directory in confined_directories:
            directory.chmod(0o500)
        try:
            yield root
        finally:
            for directory in reversed(confined_directories):
                directory.chmod(0o700)


def _safe_relative_path(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ConfigurationError("manifest contains an invalid file path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ConfigurationError("manifest file path escapes the workspace")
    return path


def _result_record(
    result: AnalyzerResult,
    observation_digests: tuple[str, ...],
    *,
    run_receipt_digest: str,
    stdout_digest: str,
    stderr_digest: str,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "name": result.name,
        "version": result.version,
        "config_digest": result.config_digest,
        "executable_digest": result.executable_digest,
        "status": result.status,
        "run_receipt_digest": run_receipt_digest,
        "observation_digests": list(observation_digests),
        "stdout_digest": stdout_digest,
        "stderr_digest": stderr_digest,
    }
    if result.error_code is not None:
        record["error_code"] = result.error_code
    if result.returncode is not None:
        record["returncode"] = result.returncode
    return record


def _read_json_object(
    path: Path, *, forbidden_roots: tuple[Path, ...] = ()
) -> dict[str, Any]:
    document, _raw = _read_json_object_with_bytes(path, forbidden_roots=forbidden_roots)
    return document


def _read_json_object_with_bytes(
    path: Path, *, forbidden_roots: tuple[Path, ...] = ()
) -> tuple[dict[str, Any], bytes]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ConfigurationError(f"cannot open configuration: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigurationError("configuration must be a regular file")
        if metadata.st_size > _MAX_CONFIG_BYTES:
            raise ConfigurationError("configuration exceeds 1 MiB")
        opened_path = _opened_descriptor_path(descriptor, "configuration")
        if any(_within(opened_path, root) for root in forbidden_roots):
            raise ConfigurationError(
                "analyzer configuration must be outside the inspected source and Aragorn state"
            )
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(_MAX_CONFIG_BYTES + 1)
            after = os.fstat(stream.fileno())
            after_path = _opened_descriptor_path(stream.fileno(), "configuration")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        before_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            len(raw) != after.st_size
            or before_identity != after_identity
            or opened_path != after_path
            or any(_within(after_path, root) for root in forbidden_roots)
        ):
            raise ConfigurationError("configuration changed while reading")
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ConfigurationError(f"configuration is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ConfigurationError("configuration must be a JSON object")
    return document, raw


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _opened_descriptor_path(descriptor: int, subject: str) -> Path:
    try:
        if hasattr(fcntl, "F_GETPATH"):
            raw = fcntl.fcntl(descriptor, fcntl.F_GETPATH, b"\0" * 1024)
            value = os.fsdecode(raw.split(b"\0", 1)[0])
        elif Path("/proc/self/fd").is_dir():
            value = os.readlink(f"/proc/self/fd/{descriptor}")
            if value.endswith(" (deleted)"):
                raise ConfigurationError(f"{subject} path changed while open")
        else:
            raise ConfigurationError(
                "opened-descriptor path verification is unsupported on this platform"
            )
    except ConfigurationError:
        raise
    except (OSError, ValueError) as exc:
        raise ConfigurationError(f"cannot verify opened {subject} path: {exc}") from exc
    if not value or not os.path.isabs(value):
        raise ConfigurationError(f"opened {subject} path is not absolute")
    return Path(os.path.normpath(value))


def _open_source_and_resolve_state(source: Path, state: Path) -> tuple[int, Path, Path]:
    """Bind the selected source to one directory capability before resolving it.

    The final path component may be attacker-controlled. Opening the raw path
    with ``O_NOFOLLOW`` first prevents an lstat/resolve/open race from changing
    which directory Aragorn inventories. All later work uses this descriptor.
    """

    expanded_source = source.expanduser()
    source_fd = _open_source_directory(expanded_source)
    try:
        source_path = _opened_descriptor_path(source_fd, "inspected source")
        _assert_source_capability(source_fd, source_path)
        try:
            state_path = state.expanduser().resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError(f"cannot resolve state path: {exc}") from exc
        if state_path == source_path or source_path in state_path.parents:
            raise ConfigurationError(
                "state directory must be outside the inspected source"
            )
        return source_fd, source_path, state_path
    except BaseException:
        os.close(source_fd)
        raise


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _open_source_directory(source: Path) -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ConfigurationError("safe source opening is unsupported on this platform")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ConfigurationError(
            "cannot open inspected source safely (the final source root must "
            f"not be a symlink): {exc}"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise ConfigurationError("inspected source must be a directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _assert_source_capability(descriptor: int, source: Path) -> None:
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise ConfigurationError(f"cannot verify inspected source: {exc}") from exc
    if not stat.S_ISDIR(opened.st_mode):
        raise ConfigurationError("inspected source descriptor is not a directory")
    if _opened_descriptor_path(descriptor, "inspected source") != source:
        raise ConfigurationError("inspected source identity changed during inspection")


def _hash_analyzer_executable(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ConfigurationError(
                f"analyzer executable is not a regular file: {path}"
            )
        if before.st_size > _MAX_ANALYZER_EXECUTABLE_BYTES:
            raise ConfigurationError("analyzer executable exceeds 128 MiB")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > _MAX_ANALYZER_EXECUTABLE_BYTES:
                raise ConfigurationError("analyzer executable exceeds 128 MiB")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if size != after.st_size or identity_before != identity_after:
            raise ConfigurationError("analyzer executable changed while hashing")
        return f"sha256:{digest.hexdigest()}"
    except ConfigurationError:
        raise
    except OSError as exc:
        raise ConfigurationError(
            f"cannot hash analyzer executable {path}: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _ingest_analyzer_executable(cas: CAS, path: Path) -> str:
    """Open one executable capability, retain its bytes, and return its CAS digest."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ConfigurationError(
                f"analyzer executable is not a regular file: {path}"
            )
        if not stat.S_IMODE(before.st_mode) & 0o111:
            raise ConfigurationError(f"analyzer executable is not executable: {path}")
        if before.st_size > _MAX_ANALYZER_EXECUTABLE_BYTES:
            raise ConfigurationError("analyzer executable exceeds 128 MiB")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as stream:
            digest = cas.put(stream, max_bytes=_MAX_ANALYZER_EXECUTABLE_BYTES)
        size = os.lseek(descriptor, 0, os.SEEK_CUR)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if size != after.st_size or identity_before != identity_after:
            raise ConfigurationError("analyzer executable changed while ingesting")
        return digest
    except (CASError, ConfigurationError):
        raise
    except OSError as exc:
        raise ConfigurationError(
            f"cannot ingest analyzer executable {path}: {exc}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _put_json(
    cas: CAS,
    document: dict[str, Any],
    *,
    max_bytes: int = _MAX_RECORD_BYTES,
    record_name: str = "evidence record",
) -> str:
    return _put_bytes(
        cas,
        _canonical_json(document),
        max_bytes=max_bytes,
        record_name=record_name,
    )


def _put_bytes(
    cas: CAS,
    content: bytes,
    *,
    max_bytes: int = _MAX_RECORD_BYTES,
    record_name: str = "evidence record",
) -> str:
    if len(content) > max_bytes:
        raise CASError(f"{record_name} exceeds its byte limit")
    return cas.put(BytesIO(content), max_bytes=len(content))


def _digest_json(document: dict[str, Any]) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(document)).hexdigest()}"


def _canonical_json(document: dict[str, Any]) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _default_state() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    return (
        Path(base).expanduser() / "aragorn"
        if base
        else Path.home() / ".local/state/aragorn"
    )


if __name__ == "__main__":
    raise SystemExit(main())
