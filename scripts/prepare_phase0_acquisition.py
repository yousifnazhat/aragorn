"""Prepare the paired Phase 0 acquisition stratum without running analyzers."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from typing import Any, BinaryIO, Callable, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark import (
    BenchmarkError,
    _canonical_json_bytes,
    _decode_json,
    _digest_json,
    _exact_keys,
    _identifier,
    _load_phase0_expansion,
    _read_bounded,
    _read_phase0_cas_json,
    _relative_path,
    _system_key,
    _validate_phase0_accounting,
    _validate_phase0_expansion_source,
    load_suite_for_run,
)
from aragorn.cas import CAS, CASError
from aragorn.github_expand import (
    GitHubExpansionError,
    TERMINAL_DEPTH_1_MODE,
    acquire_github_expansion,
)
from aragorn.phase0_candidate import (
    CandidateError,
    build_candidate_policy,
    candidate_policy_digest,
    candidate_system_identity,
)
from scripts.phase0_acquisition_gate import (
    EXPANSION_ASSURANCE,
    EXPANSION_PROFILE,
    ORACLE_SCHEMA,
    build_lock,
)

RESULT_SCHEMA = "aragorn/benchmark-phase0-acquisition-preparation-result/v1"
_CASE_COUNT = 448
_CLASS_COUNTS = {"adversarial": 112, "benign": 336}
_MAX_TOKEN_BYTES = 1024
_OWNER = "yousifnazhat"
_REPOSITORY = "aragorn-phase0-acquisition-holdout-v1"
_ROOT_COMMIT = "9fa1a553e7caf1ec8908ac54a277354307e92ac1"
_TARGET_COMMIT = "6b4c13d042c8e0f4ee8e624c609ee02a41733f34"
_ACQUISITION_CORPUS_LOCK_PATH = (
    ROOT / "benchmark" / "phase0-acquisition-corpus.lock.json"
)
_ACQUISITION_CORPUS_LOCK_DIGEST = (
    "sha256:4d47a175ebb6041c40d3f1a3c6c8901fb4336594fcafd9c7ced614c85e04a1df"
)
_CATALOG_CASE_KEYS = {
    "case_id",
    "root_github_url",
    "root_owner",
    "root_repo",
    "root_commit",
    "root_path",
    "expanded_target_url",
    "expanded_target_commit",
    "expanded_target_path",
    "expected_class",
}
_BUDGETS = {
    "api_requests": 20_050,
    "api_bytes": 384 * 1024 * 1024,
    "retained_bytes": 128 * 1024 * 1024,
    "expanded_objects": 256,
    "expansion_depth": 1,
    "references": 10_000,
}


class AcquisitionPreparationError(ValueError):
    """The pre-outcome acquisition stratum could not be prepared safely."""


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _new_private_path(value: str | Path, label: str) -> Path:
    requested = Path(os.path.abspath(os.fspath(Path(value).expanduser())))
    if os.path.lexists(requested):
        raise AcquisitionPreparationError(f"{label} already exists: {requested}")
    try:
        parent = requested.parent.resolve(strict=True)
    except OSError as exc:
        raise AcquisitionPreparationError(
            f"{label} parent is unavailable: {requested.parent}"
        ) from exc
    path = parent / requested.name
    if os.path.lexists(path):
        raise AcquisitionPreparationError(f"{label} already exists: {path}")
    metadata = parent.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and metadata.st_uid != os.geteuid())
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AcquisitionPreparationError(
            f"{label} parent must be operator-owned without group/other access"
        )
    return path


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _catalog_digest_from_lock() -> str:
    raw = _read_bounded(_ACQUISITION_CORPUS_LOCK_PATH)
    if _digest_bytes(raw) != _ACQUISITION_CORPUS_LOCK_DIGEST:
        raise AcquisitionPreparationError(
            "acquisition corpus lock does not match the pinned release"
        )
    lock = _decode_json(raw, "acquisition corpus lock")
    try:
        digest = lock["artifacts"]["evaluator_catalog_plaintext"]["sha256"]
    except (KeyError, TypeError) as exc:
        raise AcquisitionPreparationError(
            "acquisition corpus lock is malformed"
        ) from exc
    if (
        lock.get("schema")
        != "aragorn/benchmark-phase0-acquisition-corpus-lock/v1"
        or lock.get("repository")
        != {
            "owner": _OWNER,
            "name": _REPOSITORY,
            "visibility": "PRIVATE",
        }
        or lock.get("freeze", {}).get("commit_a") != _TARGET_COMMIT
        or lock.get("freeze", {}).get("commit_b") != _ROOT_COMMIT
        or lock.get("aggregate_counts")
        != {
            "adversarial": 112,
            "benign": 336,
            "cases": 448,
            "roots": 448,
            "targets": 448,
        }
        or not isinstance(digest, str)
    ):
        raise AcquisitionPreparationError(
            "acquisition corpus lock is malformed"
        )
    return digest


def _private_catalog(
    path: str | Path, expected_digest: str
) -> tuple[dict[str, Any], str]:
    source = Path(path).expanduser()
    try:
        metadata = os.lstat(source)
    except OSError as exc:
        raise AcquisitionPreparationError(
            f"acquisition catalog is unavailable: {source}"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (os.name == "posix" and metadata.st_uid != os.geteuid())
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AcquisitionPreparationError(
            "acquisition catalog must be an operator-owned private regular file"
        )
    raw = _read_bounded(source)
    digest = _digest_bytes(raw)
    if digest != expected_digest:
        raise AcquisitionPreparationError(
            "acquisition catalog does not match the frozen plaintext digest"
        )
    document = _decode_json(raw, "acquisition catalog")
    return _catalog(document), digest


def _catalog(value: object) -> dict[str, Any]:
    label = "acquisition catalog"
    if not isinstance(value, list) or len(value) != _CASE_COUNT:
        raise AcquisitionPreparationError(
            f"{label} must be a JSON array of exactly {_CASE_COUNT} cases"
        )
    cases: dict[str, dict[str, Any]] = {}
    root_urls: set[str] = set()
    target_urls: set[str] = set()
    for index, raw in enumerate(value):
        case_label = f"{label}[{index}]"
        if not isinstance(raw, dict):
            raise AcquisitionPreparationError(
                f"{case_label} must be a JSON object"
            )
        _exact_keys(raw, _CATALOG_CASE_KEYS, case_label)
        case_id = _identifier(raw["case_id"], f"{case_label}.case_id")
        if case_id in cases:
            raise AcquisitionPreparationError(f"duplicate catalog case: {case_id}")
        case_class = raw["expected_class"]
        if case_class not in {"benign", "adversarial"}:
            raise AcquisitionPreparationError(
                f"{case_label}.expected_class is unsupported"
            )
        root_path = f"roots/{case_id}/SKILL.md"
        target_path = f"targets/{case_id}/SKILL.md"
        if (
            raw["root_owner"] != _OWNER
            or raw["root_repo"] != _REPOSITORY
            or raw["root_commit"] != _ROOT_COMMIT
            or raw["expanded_target_commit"] != _TARGET_COMMIT
            or raw["root_path"] != root_path
            or raw["expanded_target_path"] != target_path
        ):
            raise AcquisitionPreparationError(
                f"{case_label} does not match the frozen repository boundary"
            )
        root_url = _raw_github_url(_ROOT_COMMIT, root_path)
        target_url = _raw_github_url(_TARGET_COMMIT, target_path)
        if (
            raw["root_github_url"] != root_url
            or raw["expanded_target_url"] != target_url
        ):
            raise AcquisitionPreparationError(
                f"{case_label} contains a noncanonical raw GitHub URL"
            )
        if root_url in root_urls or target_url in target_urls:
            raise AcquisitionPreparationError(
                "acquisition catalog root and target URLs must be unique"
            )
        root_urls.add(root_url)
        target_urls.add(target_url)
        source = _catalog_source(
            {
                "owner": _OWNER,
                "repository": _REPOSITORY,
                "commit": _ROOT_COMMIT,
                "skill_path": f"roots/{case_id}",
            },
            f"{case_label}.root",
        )
        cases[case_id] = {
            "case_id": case_id,
            "class": case_class,
            "family": (
                "benign"
                if case_class == "benign"
                else "agent-skill-adversarial"
            ),
            "lineage": case_id,
            "license": "private-evaluation-only",
            "source": source,
            "expected_source": {
                "commit": _ROOT_COMMIT,
                "repository_path": root_path,
            },
            "expected_target": {
                "commit": _TARGET_COMMIT,
                "repository_path": target_path,
            },
        }
    if list(cases) != sorted(cases):
        raise AcquisitionPreparationError(
            "acquisition catalog cases must be sorted by case_id"
        )
    counts = {
        name: sum(case["class"] == name for case in cases.values())
        for name in _CLASS_COUNTS
    }
    if counts != _CLASS_COUNTS:
        raise AcquisitionPreparationError(
            "acquisition catalog must contain 336 benign and 112 adversarial cases"
        )
    return {
        "split": "held_out",
        "runs_per_case": 1,
        "cases": list(cases.values()),
    }


def _raw_github_url(commit: str, path: str) -> str:
    return (
        f"https://raw.githubusercontent.com/{_OWNER}/{_REPOSITORY}/"
        f"{commit}/{path}"
    )


def _catalog_source(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise AcquisitionPreparationError(f"{label} must be a JSON object")
    _exact_keys(value, {"owner", "repository", "commit", "skill_path"}, label)
    normalized = _validate_phase0_expansion_source(
        {
            "host": "github.com",
            "owner": value["owner"],
            "repository": value["repository"],
            "commit": value["commit"],
            "commit_tree": "0" * 40,
            "skill_path": value["skill_path"],
            "api_version": "2026-03-10",
        },
        label,
    )
    return {
        field: normalized[field]
        for field in ("owner", "repository", "commit", "skill_path")
    }


def _candidate_policy(path: str | Path) -> dict[str, Any]:
    document = _decode_json(
        _read_bounded(Path(path).expanduser()), "candidate policy"
    )
    policy = build_candidate_policy(document)
    return {
        "document": policy,
        "digest": candidate_policy_digest(policy),
        "candidate": candidate_system_identity(policy),
        "comparators": list(policy["required_comparators"]),
    }


def _read_bearer_token(stream: BinaryIO) -> str:
    raw = stream.readline(_MAX_TOKEN_BYTES + 2)
    if (
        not raw.endswith(b"\n")
        or len(raw) > _MAX_TOKEN_BYTES + 1
        or stream.read(1)
    ):
        raise AcquisitionPreparationError(
            "GitHub token input must be exactly one bounded line"
        )
    token = raw[:-1]
    if (
        not token
        or b"\r" in token
        or b"\0" in token
        or any(byte < 0x21 or byte > 0x7E for byte in token)
    ):
        raise AcquisitionPreparationError(
            "GitHub token must contain 1-1024 visible ASCII bytes"
        )
    return token.decode("ascii")


def _write_new(path: Path, document: object) -> None:
    raw = _canonical_json_bytes(document)
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _materialize_manifest(
    cas: CAS,
    manifest: dict[str, Any],
    destination: Path,
    *,
    label: str,
) -> None:
    destination.mkdir(mode=0o700)
    for entry in manifest["files"]:
        if entry["executable"]:
            raise AcquisitionPreparationError(
                f"{label} contains an executable benchmark fixture"
            )
        relative = _relative_path(entry["path"], f"{label}.path")
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        cas.materialize(entry["digest"], target, root=destination)


def _suite_document(
    *,
    suite_id: str,
    systems: list[dict[str, str]],
    cases: list[dict[str, Any]],
    arm: str,
) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-suite/v1",
        "id": suite_id,
        "purpose": "evidence_smoke",
        "runs_per_case": 1,
        "systems": sorted(systems, key=_system_key),
        "cases": [
            {
                "schema": "aragorn/benchmark-case/v1",
                "id": case["case_id"],
                "class": case["class"],
                "family": case["family"],
                "lineage": case["lineage"],
                "split": "held_out",
                "path": f"{arm}-cases/{case['case_id']}",
                "tree_digest": case[f"{arm}_tree_digest"],
                "inert": True,
                "source": {
                    "kind": "synthetic",
                    "reference": (
                        "phase0-github-source:"
                        + _digest_json(case["acquired_source"])
                    ),
                    "license": case["license"],
                },
            }
            for case in cases
        ],
    }


def _expected_references(
    record: dict[str, Any],
    case: dict[str, Any],
) -> list[dict[str, Any]]:
    targets = {
        (item["commit"], item["repository_path"]): item["digest"]
        for item in record["objects"]
    }
    expanded = [
        reference
        for reference in record["references"]
        if reference["status"] == "expanded"
    ]
    expected_source = case["expected_source"]
    expected_target = case["expected_target"]
    if (
        len(expanded) != 1
        or expanded[0]["source_commit"] != expected_source["commit"]
        or expanded[0]["source_repository_path"]
        != expected_source["repository_path"]
        or expanded[0]["target_commit"] != expected_target["commit"]
        or expanded[0]["target_repository_path"]
        != expected_target["repository_path"]
    ):
        raise AcquisitionPreparationError(
            f"acquisition case {case['case_id']} does not match its authored "
            "root/target reference"
        )
    reference = expanded[0]
    target_identity = (
        reference["target_commit"],
        reference["target_repository_path"],
    )
    return [
        {
            key: reference[key]
            for key in (
                "source_commit",
                "source_repository_path",
                "source_blob_digest",
                "byte_offset",
                "literal_size",
                "literal_digest",
                "target_commit",
                "target_repository_path",
            )
        }
        | {"target_digest": targets[target_identity]}
    ]


def prepare_files(
    catalog_path: str | Path,
    output_path: str | Path,
    *,
    state_path: str | Path,
    candidate_policy_path: str | Path,
    bearer_token: str | None = None,
    acquire: Callable[..., dict[str, Any]] = acquire_github_expansion,
) -> dict[str, Any]:
    """Acquire and bind both benchmark arms without producing outcomes."""

    repository_root = ROOT.resolve(strict=True)
    catalog_file = Path(catalog_path).expanduser().resolve(strict=True)
    if _overlaps(catalog_file, repository_root):
        raise AcquisitionPreparationError(
            "private acquisition catalog must remain outside the repository"
        )
    corpus_lock_digest = _ACQUISITION_CORPUS_LOCK_DIGEST
    catalog, catalog_digest = _private_catalog(
        catalog_path, _catalog_digest_from_lock()
    )
    policy = _candidate_policy(candidate_policy_path)
    output = _new_private_path(output_path, "acquisition output")
    state = _new_private_path(state_path, "acquisition state")
    if _overlaps(output, state):
        raise AcquisitionPreparationError(
            "acquisition output and state must not overlap"
        )
    if _overlaps(output, repository_root) or _overlaps(state, repository_root):
        raise AcquisitionPreparationError(
            "private acquisition output and state must remain outside the repository"
        )

    os.mkdir(output, mode=0o700)
    completed = False
    state_created = False
    try:
        state_created = True
        cas = CAS(state)
        root_cases = output / "root-cases"
        expanded_cases = output / "expanded-cases"
        root_cases.mkdir(mode=0o700)
        expanded_cases.mkdir(mode=0o700)
        prepared_cases = []
        for case in catalog["cases"]:
            case_id = case["case_id"]
            source = case["source"]
            result = acquire(
                f"https://github.com/{source['owner']}/{source['repository']}",
                source["commit"],
                source["skill_path"],
                cas,
                bearer_token=bearer_token,
                expansion_mode=TERMINAL_DEPTH_1_MODE,
                **{
                    f"max_{name}": limit
                    for name, limit in _BUDGETS.items()
                },
            )
            if not isinstance(result, dict):
                raise AcquisitionPreparationError(
                    f"acquisition case {case_id} returned no result object"
                )
            _exact_keys(
                result,
                {
                    "schema",
                    "expansion_digest",
                    "root_manifest_digest",
                    "root_tree_digest",
                    "comparator_subject_manifest_digest",
                    "comparator_subject_tree_digest",
                    "expanded_object_count",
                    "accounting",
                    "closure",
                },
                f"acquisition case {case_id} result",
            )
            closure = result["closure"]
            expanded_count = result["expanded_object_count"]
            if (
                result["schema"] != "aragorn/github-expansion-result/v1"
                or not isinstance(closure, dict)
                or closure.get("status") != "complete"
                or not result["comparator_subject_manifest_digest"]
                or not result["comparator_subject_tree_digest"]
                or isinstance(expanded_count, bool)
                or not isinstance(expanded_count, int)
                or not 1 <= expanded_count <= 256
            ):
                raise AcquisitionPreparationError(
                    f"acquisition case {case_id} did not reach complete expansion"
                )
            record = _load_phase0_expansion(
                cas,
                result["expansion_digest"],
                expected_tree_digest=result["comparator_subject_tree_digest"],
                label=f"acquisition case {case_id}",
                expected_profile=EXPANSION_PROFILE,
            )
            acquired_source = record["source"]
            if any(
                acquired_source[field] != source[field]
                for field in ("owner", "repository", "commit", "skill_path")
            ):
                raise AcquisitionPreparationError(
                    f"acquisition case {case_id} source identity changed"
                )
            if (
                record["root_manifest_digest"] != result["root_manifest_digest"]
                or record["profile"] != EXPANSION_PROFILE
                or record["assurance"] != EXPANSION_ASSURANCE
                or record["root_tree_digest"] != result["root_tree_digest"]
                or record["comparator_subject_manifest_digest"]
                != result["comparator_subject_manifest_digest"]
                or record["comparator_subject_tree_digest"]
                != result["comparator_subject_tree_digest"]
                or record["accounting"] != result["accounting"]
                or record["closure"] != result["closure"]
                or len(record["objects"]) != expanded_count
            ):
                raise AcquisitionPreparationError(
                    f"acquisition case {case_id} result binding changed"
                )
            if record["root_tree_digest"] == record[
                "comparator_subject_tree_digest"
            ]:
                raise AcquisitionPreparationError(
                    f"acquisition case {case_id} root and expanded trees are identical"
                )
            limits = {
                name: record["accounting"]["budgets"][name]["limit"]
                for name in _BUDGETS
            }
            if limits != _BUDGETS:
                raise AcquisitionPreparationError(
                    f"acquisition case {case_id} resource budgets changed"
                )
            root_manifest = _read_phase0_cas_json(
                cas,
                record["root_manifest_digest"],
                f"acquisition case {case_id} root manifest",
            )
            expanded_manifest = _read_phase0_cas_json(
                cas,
                record["comparator_subject_manifest_digest"],
                f"acquisition case {case_id} comparator subject",
            )
            assert isinstance(root_manifest, dict)
            assert isinstance(expanded_manifest, dict)
            _materialize_manifest(
                cas,
                root_manifest,
                root_cases / case_id,
                label=f"acquisition case {case_id} root manifest",
            )
            _materialize_manifest(
                cas,
                expanded_manifest,
                expanded_cases / case_id,
                label=f"acquisition case {case_id} comparator subject",
            )
            prepared_cases.append(
                {
                    **case,
                    "acquired_source": acquired_source,
                    "root_tree_digest": record["root_tree_digest"],
                    "expanded_tree_digest": record[
                        "comparator_subject_tree_digest"
                    ],
                    "expansion_digest": record["expansion_digest"],
                    "expected_references": _expected_references(record, case),
                }
            )

        for field in ("root_tree_digest", "expanded_tree_digest"):
            if len({case[field] for case in prepared_cases}) != _CASE_COUNT:
                raise AcquisitionPreparationError(
                    f"acquisition {field} values must be unique"
                )

        root_suite = _suite_document(
            suite_id="phase0-acquisition-root-v1",
            systems=policy["comparators"],
            cases=prepared_cases,
            arm="root",
        )
        expanded_suite = _suite_document(
            suite_id="phase0-acquisition-expanded-v1",
            systems=[policy["candidate"], *policy["comparators"]],
            cases=prepared_cases,
            arm="expanded",
        )
        root_suite_path = output / "root-suite.json"
        expanded_suite_path = output / "expanded-suite.json"
        _write_new(root_suite_path, root_suite)
        _write_new(expanded_suite_path, expanded_suite)
        root_loaded = load_suite_for_run(
            root_suite_path, cas, required_purpose="evidence_smoke"
        )
        expanded_loaded = load_suite_for_run(
            expanded_suite_path, cas, required_purpose="evidence_smoke"
        )
        if (
            root_loaded["canonical"] != root_suite
            or expanded_loaded["canonical"] != expanded_suite
        ):
            raise AcquisitionPreparationError(
                "generated acquisition suite changed during canonical validation"
            )

        oracle = {
            "schema": ORACLE_SCHEMA,
            "root_suite_digest": root_loaded["digest"],
            "expanded_suite_digest": expanded_loaded["digest"],
            "split": "held_out",
            "runs_per_case": 1,
            "candidate_system": policy["candidate"],
            "comparators": policy["comparators"],
            "expansion_profile": EXPANSION_PROFILE,
            "expansion_assurance": EXPANSION_ASSURANCE,
            "budgets": dict(_BUDGETS),
            "cases": [
                {
                    "case_id": case["case_id"],
                    "class": case["class"],
                    "family": case["family"],
                    "lineage": case["lineage"],
                    "root_tree_digest": case["root_tree_digest"],
                    "expanded_tree_digest": case["expanded_tree_digest"],
                    "source": case["acquired_source"],
                    "expected_references": case["expected_references"],
                }
                for case in prepared_cases
            ],
        }
        accounting = {
            "schema": "aragorn/benchmark-phase0-accounting/v1",
            "suite_digest": expanded_loaded["digest"],
            "candidate_system": policy["candidate"],
            "expansion_profile": EXPANSION_PROFILE,
            "expansion_assurance": EXPANSION_ASSURANCE,
            "cases": [
                {
                    "case_id": case["case_id"],
                    "expansion_digest": case["expansion_digest"],
                    "expected_references": case["expected_references"],
                }
                for case in prepared_cases
            ],
        }
        build_lock(oracle, root_loaded, expanded_loaded, policy)
        _, _, canonical_accounting = _validate_phase0_accounting(
            accounting,
            suite_digest=expanded_loaded["digest"],
            cases=expanded_loaded["cases"],
            systems=expanded_loaded["systems"],
        )
        if canonical_accounting != accounting:
            raise AcquisitionPreparationError(
                "generated acquisition accounting changed during validation"
            )
        _write_new(output / "acquisition-oracle.json", oracle)
        _write_new(output / "phase0-accounting.json", accounting)
        completed = True
        return {
            "schema": RESULT_SCHEMA,
            "status": "prepared_for_authenticated_execution",
            "corpus_lock_digest": corpus_lock_digest,
            "catalog_digest": catalog_digest,
            "candidate_policy_digest": policy["digest"],
            "root_suite_digest": root_loaded["digest"],
            "expanded_suite_digest": expanded_loaded["digest"],
            "oracle_digest": _digest_json(oracle),
            "accounting_digest": _digest_json(accounting),
            "case_count": _CASE_COUNT,
        }
    finally:
        if not completed:
            shutil.rmtree(output, ignore_errors=True)
            if state_created:
                shutil.rmtree(state, ignore_errors=True)


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise AcquisitionPreparationError(message)


def _parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="python scripts/prepare_phase0_acquisition.py",
        description=(
            "Acquire and bind the paired Phase 0 acquisition stratum without "
            "running analyzers."
        ),
    )
    parser.add_argument("catalog", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--candidate-policy", type=Path, required=True)
    parser.add_argument("--github-token-stdin", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: BinaryIO | None = None,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        token = (
            _read_bearer_token(stdin or sys.stdin.buffer)
            if arguments.github_token_stdin
            else None
        )
        result = prepare_files(
            arguments.catalog,
            arguments.output,
            state_path=arguments.state,
            candidate_policy_path=arguments.candidate_policy,
            bearer_token=token,
        )
    except (
        AcquisitionPreparationError,
        BenchmarkError,
        CandidateError,
        CASError,
        GitHubExpansionError,
        OSError,
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
    sys.stdout.buffer.write(_canonical_json_bytes(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
