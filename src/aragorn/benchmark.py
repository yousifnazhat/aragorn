"""Deterministic evaluation of inert, digest-locked benchmark cases."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import posixpath
import re
import stat
import sys
import tempfile
import unicodedata
from collections.abc import Iterable, Sequence
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .acquire import InventoryError, ingest_open_directory
from .analyze import AnalyzerResult, _parse_observations
from .artifact_closure import ArtifactClosureError, resolve_source_graph
from .benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    validate_worker_request_v2,
    validate_worker_result_v2,
    verify_effective_environment_v2,
)
from .cas import CAS, CASError
from .github_expand import (
    ASSURANCE as GITHUB_EXPANSION_ASSURANCE,
    PROFILE as GITHUB_EXPANSION_PROFILE,
    TERMINAL_DEPTH_1_ASSURANCE,
    TERMINAL_DEPTH_1_PROFILE,
)
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    sanitize_subject_manifest,
    validate_subject_manifest,
    validate_worker_request,
    validate_worker_result,
    verify_request_result_binding,
    verify_request_subject,
)
from .vendor_reports import (
    VendorReportError,
    normalize_cisco_report,
    normalize_nvidia_report,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_VERDICTS = ("ALLOW", "REVIEW", "DENY", "ERROR")
_SPLITS = frozenset({"development", "held_out", "hidden"})
_PURPOSES = frozenset({"contract_smoke", "evidence_smoke"})
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_MAX_INPUT_BYTES = 16 * 1024 * 1024
_MAX_CASES = 10_000
_MAX_SYSTEMS = 32
_MAX_RUNS = 10
_MAX_OUTCOMES = 200_000
_MAX_SUITE_ENTRIES = 100_000
_MAX_FIXTURE_BYTES = 16 * 1024 * 1024
_MAX_SUITE_BYTES = 128 * 1024 * 1024
_TEXT_SUFFIXES = frozenset({".json", ".md", ".txt", ".yaml", ".yml"})
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_RUNNER_RECEIPT_BYTES = 1024 * 1024
_MAX_WORKER_OUTPUT_BLOBS = 25_000
_MAX_WORKER_OUTPUT_TOTAL_BYTES = 512 * 1024 * 1024
_REQUIRED_DOCKER_COMPONENTS = frozenset({"Engine", "containerd", "runc"})
_UNREPORTED_COMPONENT_DETAILS_PREFIX = "unreported-details-sha256:"
_PHASE0_BENIGN_BURDEN_CEILING = Fraction(1, 20)
_PHASE0_MINIMUM_ATTACK_FLAG_DELTA = Fraction(1, 10)
_PHASE0_EXPANSION_CONTRACTS = {
    GITHUB_EXPANSION_PROFILE: (
        GITHUB_EXPANSION_ASSURANCE,
        "phase0_exact_github_blob_expansion",
    ),
    TERMINAL_DEPTH_1_PROFILE: (
        TERMINAL_DEPTH_1_ASSURANCE,
        "phase0_exact_github_blob_expansion_terminal_depth_1",
    ),
}
_PHASE0_CORPUS_LOCK_DIGEST = (
    "sha256:bbd4c584fa06d2ef7ee9d69011bf756432bb0f6f06c16b6f9dfd0cde87267fb8"
)
_PHASE0_CORPUS_LOCKS = {
    _PHASE0_CORPUS_LOCK_DIGEST: (
        "aragorn/benchmark-corpus-provenance-lock/v1",
        "independent-v1.0.0",
        re.compile(r"case-[0-9a-f]{16}\Z"),
    ),
    (
        "sha256:"
        "2390161f836ac42a5b8526d5ec0b11a2dce9a3c693e3d76513f7b4959eb533b9"
    ): (
        "aragorn/benchmark-corpus-provenance-lock/v2",
        "independent-v3.0.0",
        re.compile(r"v3-[0-9a-f]{24}\Z"),
    ),
}
_CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_OCI_BASELINES = {
    "cisco-skill-scanner": {
        "version": "2.0.12",
        "commit": "605afdc5c7ea887c07e2afeb0fadc1452c07bfa7",
        "repository": "https://github.com/cisco-ai-defense/skill-scanner",
        "release": "2.0.12",
        "distribution": {
            "kind": "pypi-wheel",
            "package": "cisco-ai-skill-scanner==2.0.12",
            "sha256": "e49f979e97b7842549b1f531dc5f426c9780d798a0b21f0125044e3b5ae4a1f7",
        },
        "arguments": [
            "scan",
            "{workspace}",
            "--use-behavioral",
            "--policy",
            "strict",
            "--format",
            "json",
            "--compact",
        ],
        "profile_environment": {},
        "disabled_features": [
            "aidefense",
            "llm",
            "meta-analysis",
            "virustotal",
        ],
        "entrypoint": ["/opt/venv/bin/skill-scanner"],
        "image_version": "2.0.12",
        "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
        "completion_reason": "CISCO_SCAN_COMPLETED",
    },
    "skillspector": {
        "version": "2.4.3+git.a54947c",
        "commit": "a54947c307fe19a24a43db55f6148e181a987a67",
        "repository": "https://github.com/NVIDIA/SkillSpector",
        "release": None,
        "distribution": {"kind": "git-source", "package": None, "sha256": None},
        "arguments": [
            "scan",
            "{workspace}",
            "--no-llm",
            "--format",
            "json",
        ],
        "profile_environment": {"SKILLSPECTOR_OSV_TIMEOUT": "0.2"},
        "disabled_features": ["llm"],
        "entrypoint": ["/opt/venv/bin/python", "-P", "-m", "skillspector.cli"],
        "image_version": "2.4.3",
        "normalization": "nvidia-skillspector-2.4.3/v1",
        "completion_reason": "NVIDIA_SCAN_COMPLETED",
    },
}
_OCI_RUNTIME_PROFILE = {
    "engine": "docker",
    "pull": "never",
    "network": "none",
    "read_only_rootfs": True,
    "cap_drop": ["ALL"],
    "no_new_privileges": True,
    "user": "65532:65532",
    "workdir": "/opt/aragorn-control",
    "pids_limit": 256,
    "memory_bytes": 2_147_483_648,
    "memory_swap_bytes": 2_147_483_648,
    "cpus": 2,
    "nofile_soft": 1024,
    "nofile_hard": 1024,
    "tmpfs": {
        "destination": "/tmp",
        "size_bytes": 536_870_912,
        "options": ["rw", "noexec", "nosuid", "nodev", "mode=1777"],
    },
    "workspace": {"destination": "/workspace", "read_only": True},
}
EVIDENCE_ERROR_CODES = frozenset(
    {
        "MALFORMED_OUTPUT",
        "NONZERO_EXIT",
        "OBSERVATION_LIMIT_EXCEEDED",
        "OBSERVATION_RECORD_LIMIT_EXCEEDED",
        "OUTPUT_LIMIT_EXCEEDED",
        "SUBJECT_DIGEST_MISMATCH",
        "TIMEOUT",
    }
)
_PARSE_ERROR_CODES = frozenset(
    {
        "MALFORMED_OUTPUT",
        "OBSERVATION_LIMIT_EXCEEDED",
        "OBSERVATION_RECORD_LIMIT_EXCEEDED",
        "SUBJECT_DIGEST_MISMATCH",
    }
)


class BenchmarkError(ValueError):
    """Benchmark metadata or outcomes are incomplete or unsafe."""


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise BenchmarkError(message)


def normalize_analyzer_result(result: AnalyzerResult) -> tuple[str, tuple[str, ...]]:
    """Map typed analyzer evidence into one deterministic benchmark verdict."""

    if not result.ok:
        code = result.error_code or "UNKNOWN_ERROR"
        reason = f"ANALYZER_{code}"
        if _REASON_CODE.fullmatch(reason) is None:
            reason = "ANALYZER_ERROR"
        return "ERROR", (reason,)
    if not result.observations:
        return "ALLOW", ()
    reasons = tuple(
        sorted({observation.reason_code for observation in result.observations})
    )
    maximum = max(
        _SEVERITY_RANK[observation.severity] for observation in result.observations
    )
    return ("DENY" if maximum >= _SEVERITY_RANK["high"] else "REVIEW"), reasons


def load_suite_for_run(
    suite_path: str | os.PathLike[str],
    cas: CAS,
    *,
    required_purpose: str | None = None,
) -> dict[str, Any]:
    """Validate and CAS-ingest a suite without reopening fixture paths later."""

    suite_file = Path(suite_path)
    suite_root = suite_file.parent.resolve(strict=True)
    suite_root_fd = _open_directory_path(suite_root)
    try:
        document = _decode_json(
            _read_bounded_at(suite_root_fd, suite_file.name, "benchmark suite"),
            "benchmark suite",
        )
        if not isinstance(document, dict):
            raise BenchmarkError("benchmark suite must be a JSON object")
        if required_purpose is not None and document.get("purpose") != required_purpose:
            raise BenchmarkError(
                f"benchmark runner requires an {required_purpose} suite"
            )
        (
            suite_id,
            purpose,
            runs_per_case,
            cases,
            normalized_cases,
            systems,
            manifests,
        ) = _validate_suite(document, suite_root, suite_root_fd, cas=cas)
    finally:
        os.close(suite_root_fd)
    canonical = _canonical_suite_document(
        suite_id, purpose, runs_per_case, normalized_cases, systems
    )
    return {
        "root": suite_root,
        "id": suite_id,
        "purpose": purpose,
        "runs_per_case": runs_per_case,
        "cases": cases,
        "systems": systems,
        "manifests": manifests,
        "canonical": canonical,
        "digest": _digest_json(canonical),
    }


def evaluate_files(
    suite_path: str | os.PathLike[str],
    outcome_path: str | os.PathLike[str],
    *,
    evidence_state: str | os.PathLike[str] | None = None,
    acceptance_ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Verify an inert corpus and return deterministic aggregate metrics."""

    suite_file = Path(suite_path)
    suite_root = suite_file.parent.resolve(strict=True)
    suite_root_fd = _open_directory_path(suite_root)
    try:
        suite = _decode_json(
            _read_bounded_at(suite_root_fd, suite_file.name, "benchmark suite"),
            "benchmark suite",
        )
        if not isinstance(suite, dict):
            raise BenchmarkError("benchmark suite must be a JSON object")
        outcomes = _decode_json_lines(_read_bounded(Path(outcome_path)))
        evidence_cas = _open_evidence_cas(evidence_state, suite_root)
        trusted_ledger = _open_acceptance_ledger(
            acceptance_ledger,
            suite_root,
            evidence_cas,
        )
        return _evaluate(
            suite,
            outcomes,
            suite_root,
            suite_root_fd,
            evidence_cas=evidence_cas,
            acceptance_ledger=trusted_ledger,
        )
    finally:
        os.close(suite_root_fd)


def evaluate(
    suite: dict[str, Any],
    outcomes: Iterable[object],
    suite_root: Path,
    *,
    evidence_state: str | os.PathLike[str] | None = None,
    acceptance_ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Evaluate already-decoded documents after strict contract validation."""

    canonical_root = Path(suite_root).resolve(strict=True)
    suite_root_fd = _open_directory_path(canonical_root)
    try:
        evidence_cas = _open_evidence_cas(evidence_state, canonical_root)
        trusted_ledger = _open_acceptance_ledger(
            acceptance_ledger,
            canonical_root,
            evidence_cas,
        )
        return _evaluate(
            suite,
            tuple(outcomes),
            canonical_root,
            suite_root_fd,
            evidence_cas=evidence_cas,
            acceptance_ledger=trusted_ledger,
        )
    finally:
        os.close(suite_root_fd)


def evaluate_phase0_files(
    suite_path: str | os.PathLike[str],
    outcome_path: str | os.PathLike[str],
    accounting_path: str | os.PathLike[str],
    *,
    evidence_state: str | os.PathLike[str] | None = None,
    acceptance_ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Evaluate the opt-in Phase 0 comparative accounting contract.

    The ordinary benchmark v1 report remains unchanged. This entry point binds
    a separate accounting sidecar to that report and emits a narrowly scoped
    comparative-metrics report.
    """

    suite_file = Path(suite_path)
    suite_root = suite_file.parent.resolve(strict=True)
    suite_root_fd = _open_directory_path(suite_root)
    try:
        suite = _decode_json(
            _read_bounded_at(suite_root_fd, suite_file.name, "benchmark suite"),
            "benchmark suite",
        )
        if not isinstance(suite, dict):
            raise BenchmarkError("benchmark suite must be a JSON object")
        outcomes = _decode_json_lines(_read_bounded(Path(outcome_path)))
        accounting = _decode_json(
            _read_bounded(Path(accounting_path)), "Phase 0 accounting sidecar"
        )
        evidence_cas = _open_evidence_cas(evidence_state, suite_root)
        trusted_ledger = _open_acceptance_ledger(
            acceptance_ledger,
            suite_root,
            evidence_cas,
        )
        return _evaluate(
            suite,
            outcomes,
            suite_root,
            suite_root_fd,
            evidence_cas=evidence_cas,
            acceptance_ledger=trusted_ledger,
            phase0_accounting=accounting,
        )
    finally:
        os.close(suite_root_fd)


def evaluate_phase0(
    suite: dict[str, Any],
    outcomes: Iterable[object],
    accounting: object,
    suite_root: Path,
    *,
    evidence_state: str | os.PathLike[str] | None = None,
    acceptance_ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Evaluate decoded Phase 0 accounting without changing benchmark v1."""

    canonical_root = Path(suite_root).resolve(strict=True)
    suite_root_fd = _open_directory_path(canonical_root)
    try:
        evidence_cas = _open_evidence_cas(evidence_state, canonical_root)
        trusted_ledger = _open_acceptance_ledger(
            acceptance_ledger,
            canonical_root,
            evidence_cas,
        )
        return _evaluate(
            suite,
            tuple(outcomes),
            canonical_root,
            suite_root_fd,
            evidence_cas=evidence_cas,
            acceptance_ledger=trusted_ledger,
            phase0_accounting=accounting,
        )
    finally:
        os.close(suite_root_fd)


def evaluate_phase0_hidden_files(
    suite_path: str | os.PathLike[str],
    outcome_path: str | os.PathLike[str],
    *,
    corpus_lock: str | os.PathLike[str],
    public_manifest: str | os.PathLike[str],
    hidden_suite_lock: str | os.PathLike[str],
    candidate_policy: str | os.PathLike[str],
    label_ledger_digest: str,
    evidence_state: str | os.PathLike[str] | None = None,
    acceptance_ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Evaluate the opt-in hidden efficacy gate without acquisition accounting."""

    suite_file = Path(suite_path)
    suite_root = suite_file.parent.resolve(strict=True)
    suite_root_fd = _open_directory_path(suite_root)
    try:
        suite = _decode_json(
            _read_bounded_at(suite_root_fd, suite_file.name, "benchmark suite"),
            "benchmark suite",
        )
        if not isinstance(suite, dict):
            raise BenchmarkError("benchmark suite must be a JSON object")
        outcomes = _decode_json_lines(_read_bounded(Path(outcome_path)))
        evidence_cas = _open_evidence_cas(evidence_state, suite_root)
        trusted_ledger = _open_acceptance_ledger(
            acceptance_ledger,
            suite_root,
            evidence_cas,
        )
        return _evaluate(
            suite,
            outcomes,
            suite_root,
            suite_root_fd,
            evidence_cas=evidence_cas,
            acceptance_ledger=trusted_ledger,
            phase0_hidden_gate=True,
            phase0_corpus_lock=Path(corpus_lock),
            phase0_public_manifest=Path(public_manifest),
            phase0_hidden_suite_lock=Path(hidden_suite_lock),
            phase0_candidate_policy=Path(candidate_policy),
            phase0_label_ledger_digest=label_ledger_digest,
        )
    finally:
        os.close(suite_root_fd)


def evaluate_phase0_hidden(
    suite: dict[str, Any],
    outcomes: Iterable[object],
    suite_root: Path,
    *,
    corpus_lock: str | os.PathLike[str],
    public_manifest: str | os.PathLike[str],
    hidden_suite_lock: str | os.PathLike[str],
    candidate_policy: str | os.PathLike[str],
    label_ledger_digest: str,
    evidence_state: str | os.PathLike[str] | None = None,
    acceptance_ledger: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Evaluate decoded hidden outcomes without acquisition accounting."""

    canonical_root = Path(suite_root).resolve(strict=True)
    suite_root_fd = _open_directory_path(canonical_root)
    try:
        evidence_cas = _open_evidence_cas(evidence_state, canonical_root)
        trusted_ledger = _open_acceptance_ledger(
            acceptance_ledger,
            canonical_root,
            evidence_cas,
        )
        return _evaluate(
            suite,
            tuple(outcomes),
            canonical_root,
            suite_root_fd,
            evidence_cas=evidence_cas,
            acceptance_ledger=trusted_ledger,
            phase0_hidden_gate=True,
            phase0_corpus_lock=Path(corpus_lock),
            phase0_public_manifest=Path(public_manifest),
            phase0_hidden_suite_lock=Path(hidden_suite_lock),
            phase0_candidate_policy=Path(candidate_policy),
            phase0_label_ledger_digest=label_ledger_digest,
        )
    finally:
        os.close(suite_root_fd)


def _evaluate(
    suite: dict[str, Any],
    outcomes: Iterable[object],
    suite_root: Path,
    suite_root_fd: int,
    *,
    evidence_cas: CAS | None = None,
    acceptance_ledger: Path | None = None,
    phase0_accounting: object | None = None,
    phase0_hidden_gate: bool = False,
    phase0_corpus_lock: Path | None = None,
    phase0_public_manifest: Path | None = None,
    phase0_hidden_suite_lock: Path | None = None,
    phase0_candidate_policy: Path | None = None,
    phase0_label_ledger_digest: str | None = None,
) -> dict[str, Any]:
    if phase0_accounting is not None and phase0_hidden_gate:
        raise BenchmarkError(
            "Phase 0 accounting and hidden efficacy gates are mutually exclusive"
        )
    (
        suite_id,
        purpose,
        runs_per_case,
        cases,
        normalized_cases,
        systems,
        manifests,
    ) = _validate_suite(suite, suite_root, suite_root_fd)
    canonical_suite = _canonical_suite_document(
        suite_id, purpose, runs_per_case, normalized_cases, systems
    )
    suite_digest = _digest_json(canonical_suite)
    hidden_binding = None
    if phase0_hidden_gate:
        if purpose != "evidence_smoke":
            raise BenchmarkError("Phase 0 hidden gate requires evidence_smoke")
        if any(
            path is None
            for path in (
                phase0_corpus_lock,
                phase0_public_manifest,
                phase0_hidden_suite_lock,
                phase0_candidate_policy,
                phase0_label_ledger_digest,
            )
        ):
            raise BenchmarkError(
                "Phase 0 hidden gate requires corpus, public manifest, "
                "candidate policy, and pre-outcome suite locks"
            )
        assert phase0_corpus_lock is not None
        assert phase0_public_manifest is not None
        assert phase0_hidden_suite_lock is not None
        assert phase0_candidate_policy is not None
        assert phase0_label_ledger_digest is not None
        hidden_binding = _validate_phase0_hidden_binding(
            corpus_lock_path=phase0_corpus_lock,
            public_manifest_path=phase0_public_manifest,
            hidden_suite_lock_path=phase0_hidden_suite_lock,
            candidate_policy_path=phase0_candidate_policy,
            label_ledger_digest=phase0_label_ledger_digest,
            suite_digest=suite_digest,
            runs_per_case=runs_per_case,
            cases=cases,
            systems=systems,
            manifests=manifests,
        )
    normalized_outcomes = _validate_outcomes(
        tuple(outcomes),
        cases,
        systems,
        runs_per_case,
        suite_digest,
        purpose=purpose,
        manifests=manifests,
        evidence_cas=evidence_cas,
        acceptance_ledger=acceptance_ledger,
        require_candidate_composition=phase0_hidden_gate,
        expected_candidate_policy_digest=(
            hidden_binding["candidate_policy_digest"]
            if hidden_binding is not None
            else None
        ),
    )
    canonical_outcomes = sorted(
        normalized_outcomes,
        key=lambda item: (
            item["system"]["name"],
            item["system"]["version"],
            item["system"]["implementation_digest"],
            item["system"]["config_digest"],
            item["case_id"],
            item["run_id"],
        ),
    )

    reports = []
    for system_key in sorted(systems):
        system_outcomes = {
            (item["case_id"], item["run_id"]): item
            for item in canonical_outcomes
            if _system_key(item["system"]) == system_key
        }
        split_reports = []
        for split in sorted({case["split"] for case in cases.values()}):
            split_cases = {
                case_id: case
                for case_id, case in cases.items()
                if case["split"] == split
            }
            split_reports.append(
                {
                    "split": split,
                    "summary": _summarize(split_cases, system_outcomes, runs_per_case),
                    "repeatability": _repeatability(
                        split_cases, system_outcomes, runs_per_case
                    ),
                    "families": _family_reports(
                        split_cases, system_outcomes, runs_per_case
                    ),
                }
            )
        reports.append(
            {
                "system": systems[system_key],
                "overall": _summarize(cases, system_outcomes, runs_per_case),
                "repeatability": _repeatability(cases, system_outcomes, runs_per_case),
                "splits": split_reports,
            }
        )

    report = {
        "schema": "aragorn/benchmark-report/v1",
        "suite_id": suite_id,
        "purpose": purpose,
        "runs_per_case": runs_per_case,
        "suite_digest": suite_digest,
        "outcomes_digest": _digest_json(canonical_outcomes),
        "systems": reports,
    }
    if phase0_accounting is None and not phase0_hidden_gate:
        return report
    if phase0_hidden_gate:
        assert hidden_binding is not None
        return _phase0_hidden_gate_report(
            benchmark_report=report,
            systems=systems,
            binding=hidden_binding,
        )
    return _phase0_gate_report(
        phase0_accounting,
        benchmark_report=report,
        cases=cases,
        systems=systems,
        outcomes=canonical_outcomes,
        evidence_cas=evidence_cas,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = ArgumentParser(
        prog="python -m aragorn.benchmark",
        description="Verify an inert Aragorn corpus and aggregate normalized outcomes.",
    )
    parser.add_argument("suite", type=Path)
    parser.add_argument("outcomes", type=Path)
    parser.add_argument(
        "--state",
        type=Path,
        help="read-only evidence CAS required for evidence_smoke suites",
    )
    parser.add_argument(
        "--acceptance-ledger",
        type=Path,
        help="protected worker-acceptance ledger required for candidate evidence",
    )
    parser.add_argument(
        "--phase0-accounting",
        type=Path,
        help="opt-in comparative accounting sidecar for the private Phase 0 gate",
    )
    parser.add_argument(
        "--phase0-hidden-gate",
        action="store_true",
        help="opt-in hidden efficacy gate without acquisition accounting",
    )
    parser.add_argument(
        "--phase0-corpus-lock",
        type=Path,
        help="exact checked corpus provenance lock required by the hidden gate",
    )
    parser.add_argument(
        "--phase0-public-manifest",
        type=Path,
        help="extracted label-free corpus manifest required by the hidden gate",
    )
    parser.add_argument(
        "--phase0-hidden-suite-lock",
        type=Path,
        help="operator-frozen pre-outcome suite binding required by the hidden gate",
    )
    parser.add_argument(
        "--phase0-candidate-policy",
        type=Path,
        help="checked candidate policy required by the hidden gate",
    )
    parser.add_argument(
        "--phase0-label-ledger-digest",
        help="digest derived from the verified evaluator label ledger",
    )
    try:
        arguments = parser.parse_args(argv)
        if arguments.phase0_accounting is not None and arguments.phase0_hidden_gate:
            raise BenchmarkError(
                "--phase0-accounting and --phase0-hidden-gate are mutually exclusive"
            )
        hidden_inputs = (
            arguments.phase0_corpus_lock,
            arguments.phase0_public_manifest,
            arguments.phase0_hidden_suite_lock,
            arguments.phase0_candidate_policy,
            arguments.phase0_label_ledger_digest,
        )
        if arguments.phase0_hidden_gate and any(
            path is None for path in hidden_inputs
        ):
            raise BenchmarkError(
                "--phase0-hidden-gate requires --phase0-corpus-lock, "
                "--phase0-public-manifest, --phase0-hidden-suite-lock, and "
                "--phase0-candidate-policy plus --phase0-label-ledger-digest"
            )
        if not arguments.phase0_hidden_gate and any(
            path is not None for path in hidden_inputs
        ):
            raise BenchmarkError(
                "Phase 0 hidden binding inputs require --phase0-hidden-gate"
            )
        if arguments.phase0_hidden_gate:
            assert arguments.phase0_corpus_lock is not None
            assert arguments.phase0_public_manifest is not None
            assert arguments.phase0_hidden_suite_lock is not None
            assert arguments.phase0_candidate_policy is not None
            assert arguments.phase0_label_ledger_digest is not None
            report = evaluate_phase0_hidden_files(
                arguments.suite,
                arguments.outcomes,
                corpus_lock=arguments.phase0_corpus_lock,
                public_manifest=arguments.phase0_public_manifest,
                hidden_suite_lock=arguments.phase0_hidden_suite_lock,
                candidate_policy=arguments.phase0_candidate_policy,
                label_ledger_digest=arguments.phase0_label_ledger_digest,
                evidence_state=arguments.state,
                acceptance_ledger=arguments.acceptance_ledger,
            )
        elif arguments.phase0_accounting is None:
            report = evaluate_files(
                arguments.suite,
                arguments.outcomes,
                evidence_state=arguments.state,
                acceptance_ledger=arguments.acceptance_ledger,
            )
        else:
            report = evaluate_phase0_files(
                arguments.suite,
                arguments.outcomes,
                arguments.phase0_accounting,
                evidence_state=arguments.state,
                acceptance_ledger=arguments.acceptance_ledger,
            )
    except (
        BenchmarkError,
        CASError,
        InventoryError,
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
    print(json.dumps(report, sort_keys=True))
    if arguments.phase0_accounting is not None or arguments.phase0_hidden_gate:
        return 0 if report["comparison"]["passed"] else 2
    return 0


def _validate_suite(
    document: dict[str, Any],
    suite_root: Path,
    suite_root_fd: int,
    *,
    cas: CAS | None = None,
) -> tuple[
    str,
    str,
    int,
    dict[str, dict[str, Any]],
    list[dict[str, Any]],
    dict[tuple[str, str, str, str], dict[str, str]],
    dict[str, dict[str, Any]],
]:
    if cas is None:
        with tempfile.TemporaryDirectory(prefix="aragorn-benchmark-cas-") as temporary:
            return _validate_suite(
                document,
                suite_root,
                suite_root_fd,
                cas=CAS(Path(temporary) / "cas"),
            )

    _exact_keys(
        document,
        {"schema", "id", "purpose", "runs_per_case", "systems", "cases"},
        "benchmark suite",
    )
    if document["schema"] != "aragorn/benchmark-suite/v1":
        raise BenchmarkError("unsupported benchmark suite schema")
    suite_id = _identifier(document["id"], "suite id")
    purpose = document["purpose"]
    if not isinstance(purpose, str) or purpose not in _PURPOSES:
        raise BenchmarkError("benchmark purpose is unsupported")
    runs_per_case = document["runs_per_case"]
    if (
        isinstance(runs_per_case, bool)
        or not isinstance(runs_per_case, int)
        or not 1 <= runs_per_case <= _MAX_RUNS
    ):
        raise BenchmarkError(
            f"runs_per_case must be an integer between 1 and {_MAX_RUNS}"
        )
    systems = _validate_expected_systems(document["systems"])
    raw_cases = document["cases"]
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= _MAX_CASES:
        raise BenchmarkError(f"cases must contain between 1 and {_MAX_CASES} entries")
    expected_outcomes = len(raw_cases) * len(systems) * runs_per_case
    if expected_outcomes > _MAX_OUTCOMES:
        raise BenchmarkError(
            f"suite requires {expected_outcomes} outcomes; maximum is {_MAX_OUTCOMES}"
        )
    per_case_entry_limit = min(10_000, _MAX_SUITE_ENTRIES // len(raw_cases))
    if per_case_entry_limit < 1:
        raise BenchmarkError("benchmark suite entry budget is too small")

    cases: dict[str, dict[str, Any]] = {}
    digests: set[str] = set()
    lineage_splits: dict[str, str] = {}
    lineage_classes: dict[str, str] = {}
    lineage_families: dict[str, str] = {}
    lineage_sources: dict[str, dict[str, str]] = {}
    fixture_paths: list[PurePosixPath] = []
    manifests: dict[str, dict[str, Any]] = {}
    suite_bytes = 0
    normalized = []
    for index, raw_case in enumerate(raw_cases):
        label = f"cases[{index}]"
        if not isinstance(raw_case, dict):
            raise BenchmarkError(f"{label} must be a JSON object")
        _exact_keys(
            raw_case,
            {
                "schema",
                "id",
                "class",
                "family",
                "lineage",
                "split",
                "path",
                "tree_digest",
                "inert",
                "source",
            },
            label,
        )
        if raw_case["schema"] != "aragorn/benchmark-case/v1":
            raise BenchmarkError(f"{label} has an unsupported schema")
        case_id = _identifier(raw_case["id"], f"{label}.id")
        if case_id in cases:
            raise BenchmarkError(f"duplicate case id: {case_id}")
        case_class = raw_case["class"]
        if not isinstance(case_class, str) or case_class not in {
            "benign",
            "adversarial",
        }:
            raise BenchmarkError(f"{label}.class must be benign or adversarial")
        family = _identifier(raw_case["family"], f"{label}.family")
        if case_class == "benign" and family != "benign":
            raise BenchmarkError(f"{label}: benign cases require family 'benign'")
        if case_class == "adversarial" and family == "benign":
            raise BenchmarkError(f"{label}: adversarial family must not be 'benign'")
        lineage = _identifier(raw_case["lineage"], f"{label}.lineage")
        split = raw_case["split"]
        if not isinstance(split, str) or split not in _SPLITS:
            raise BenchmarkError(f"{label}.split is unsupported")
        previous_split = lineage_splits.setdefault(lineage, split)
        if previous_split != split:
            raise BenchmarkError(f"lineage {lineage!r} crosses benchmark splits")
        previous_class = lineage_classes.setdefault(lineage, case_class)
        if previous_class != case_class:
            raise BenchmarkError(f"lineage {lineage!r} changes benchmark class")
        previous_family = lineage_families.setdefault(lineage, family)
        if previous_family != family:
            raise BenchmarkError(f"lineage {lineage!r} changes attack family")
        if raw_case["inert"] is not True:
            raise BenchmarkError(f"{label} must be explicitly declared inert")
        tree_digest = _digest(raw_case["tree_digest"], f"{label}.tree_digest")
        if tree_digest in digests:
            raise BenchmarkError(f"duplicate fixture tree digest: {tree_digest}")

        relative = _relative_path(raw_case["path"], f"{label}.path")
        if any(_paths_overlap(relative, existing) for existing in fixture_paths):
            raise BenchmarkError(
                f"{label}.path duplicates or overlaps another fixture path"
            )
        fixture = suite_root.joinpath(*relative.parts)
        fixture_fd = -1
        try:
            remaining_bytes = _MAX_SUITE_BYTES - suite_bytes
            if remaining_bytes < 1:
                raise BenchmarkError("benchmark suite fixture budget exhausted")
            fixture_fd = _open_relative_directory(suite_root_fd, relative)
            manifest = ingest_open_directory(
                fixture,
                fixture_fd,
                cas,
                max_files=per_case_entry_limit,
                max_total_bytes=min(_MAX_FIXTURE_BYTES, remaining_bytes),
            )
            manifest = {
                **manifest,
                "source": {
                    "kind": "local",
                    "path": "/aragorn/opaque-benchmark-fixture",
                },
            }
        except (BenchmarkError, CASError, InventoryError, OSError) as exc:
            raise BenchmarkError(f"{case_id}: unsafe fixture: {exc}") from exc
        finally:
            if fixture_fd >= 0:
                os.close(fixture_fd)
        _validate_fixture_content(case_id, manifest, cas)
        if manifest["tree_digest"] != tree_digest:
            raise BenchmarkError(f"{case_id}: fixture tree digest mismatch")
        suite_bytes += sum(int(entry["size"]) for entry in manifest["files"])

        source = _validate_source(raw_case["source"], label)
        previous_source = lineage_sources.setdefault(lineage, source)
        if previous_source != source:
            raise BenchmarkError(f"lineage {lineage!r} changes source provenance")
        normalized_case = {
            "schema": "aragorn/benchmark-case/v1",
            "id": case_id,
            "class": case_class,
            "family": family,
            "lineage": lineage,
            "split": split,
            "path": relative.as_posix(),
            "tree_digest": tree_digest,
            "inert": True,
            "source": source,
        }
        cases[case_id] = normalized_case
        manifests[case_id] = manifest
        normalized.append(normalized_case)
        digests.add(tree_digest)
        fixture_paths.append(relative)

    classes = {case["class"] for case in cases.values()}
    if classes != {"benign", "adversarial"}:
        raise BenchmarkError("suite must contain benign and adversarial cases")
    for split in {case["split"] for case in cases.values()}:
        split_classes = {
            case["class"] for case in cases.values() if case["split"] == split
        }
        if split_classes != {"benign", "adversarial"}:
            raise BenchmarkError(
                f"benchmark split {split!r} must contain both case classes"
            )
    return (
        suite_id,
        purpose,
        runs_per_case,
        cases,
        sorted(normalized, key=lambda item: item["id"]),
        systems,
        manifests,
    )


def _canonical_suite_document(
    suite_id: str,
    purpose: str,
    runs_per_case: int,
    normalized_cases: list[dict[str, Any]],
    systems: dict[tuple[str, str, str, str], dict[str, str]],
) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-suite/v1",
        "id": suite_id,
        "purpose": purpose,
        "runs_per_case": runs_per_case,
        "systems": [systems[key] for key in sorted(systems)],
        "cases": normalized_cases,
    }


def _open_evidence_cas(
    evidence_state: str | os.PathLike[str] | None, suite_root: Path
) -> CAS | None:
    if evidence_state is None:
        return None
    state_path = Path(evidence_state).expanduser().resolve(strict=True)
    if (
        state_path == suite_root
        or state_path in suite_root.parents
        or suite_root in state_path.parents
    ):
        raise BenchmarkError("benchmark suite and evidence state must not overlap")
    return CAS(state_path, read_only=True)


def _open_acceptance_ledger(
    acceptance_ledger: str | os.PathLike[str] | None,
    suite_root: Path,
    evidence_cas: CAS | None,
) -> Path | None:
    if acceptance_ledger is None:
        return None
    ledger = Path(acceptance_ledger).expanduser().resolve(strict=True)
    if not ledger.is_dir():
        raise BenchmarkError("worker acceptance ledger must be a directory")
    boundaries = [suite_root]
    if evidence_cas is not None:
        boundaries.append(evidence_cas.root.resolve(strict=True))
    if any(
        ledger == boundary
        or ledger in boundary.parents
        or boundary in ledger.parents
        for boundary in boundaries
    ):
        raise BenchmarkError(
            "worker acceptance ledger must not overlap suite or evidence state"
        )
    return ledger


def _validate_fixture_content(case_id: str, manifest: dict[str, Any], cas: CAS) -> None:
    root_skill_found = False
    for entry in manifest["files"]:
        path = PurePosixPath(str(entry["path"]))
        if entry["executable"]:
            raise BenchmarkError(f"{case_id}: executable fixture files are unsupported")
        if path.suffix.lower() not in _TEXT_SUFFIXES:
            raise BenchmarkError(
                f"{case_id}: non-text fixture file is unsupported: {path}"
            )
        content = cas.read(str(entry["digest"]))
        if b"\0" in content:
            raise BenchmarkError(f"{case_id}: NUL byte in fixture file: {path}")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BenchmarkError(
                f"{case_id}: fixture is not UTF-8 text: {path}"
            ) from exc
        if path == PurePosixPath("SKILL.md"):
            root_skill_found = True
            if not text.strip():
                raise BenchmarkError(f"{case_id}: root SKILL.md must not be empty")
    if not root_skill_found:
        raise BenchmarkError(f"{case_id}: fixture requires a root SKILL.md")


def _validate_source(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label}.source must be a JSON object")
    _exact_keys(value, {"kind", "reference", "license"}, f"{label}.source")
    if value["kind"] != "synthetic":
        raise BenchmarkError(f"{label}.source.kind must be synthetic in v1")
    return {
        "kind": "synthetic",
        "reference": _canonical_string(
            value["reference"], f"{label}.source.reference", 2048
        ),
        "license": _canonical_string(value["license"], f"{label}.source.license", 128),
    }


def _validate_expected_systems(
    value: object,
) -> dict[tuple[str, str, str, str], dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_SYSTEMS:
        raise BenchmarkError(
            f"systems must contain between 1 and {_MAX_SYSTEMS} entries"
        )
    systems: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for index, raw_system in enumerate(value):
        system = _validate_system(raw_system, f"systems[{index}]")
        key = _system_key(system)
        if key in systems:
            raise BenchmarkError("duplicate expected benchmark system")
        systems[key] = system
    return systems


def _validate_outcomes(
    raw_outcomes: tuple[object, ...],
    cases: dict[str, dict[str, Any]],
    systems: dict[tuple[str, str, str, str], dict[str, str]],
    runs_per_case: int,
    suite_digest: str,
    *,
    purpose: str,
    manifests: dict[str, dict[str, Any]],
    evidence_cas: CAS | None,
    acceptance_ledger: Path | None,
    require_candidate_composition: bool = False,
    expected_candidate_policy_digest: str | None = None,
) -> list[dict[str, Any]]:
    if require_candidate_composition and purpose != "evidence_smoke":
        raise BenchmarkError("Phase 0 hidden gate requires evidence_smoke")
    if purpose == "evidence_smoke" and evidence_cas is None:
        raise BenchmarkError("evidence_smoke requires a retained evidence state")
    if not raw_outcomes:
        raise BenchmarkError("outcome file must not be empty")
    if len(raw_outcomes) > _MAX_OUTCOMES:
        raise BenchmarkError("outcome file contains too many records")

    expected_dispatch_matrix = {
        (system_key, case_id, run_id): {
            "suite_digest": suite_digest,
            "case_id": case_id,
            "run_id": run_id,
            "system": systems[system_key],
            "tree_digest": cases[case_id]["tree_digest"],
            "private_manifest_digest": _digest_json(manifests[case_id]),
        }
        for system_key in systems
        for case_id in cases
        for run_id in range(1, runs_per_case + 1)
    }
    normalized = []
    v4_bindings: list[dict[str, str]] = []
    candidate_bindings: list[dict[str, Any]] = []
    seen: set[tuple[tuple[str, str, str, str], str, int]] = set()
    for index, raw_outcome in enumerate(raw_outcomes):
        label = f"outcomes[{index}]"
        if not isinstance(raw_outcome, dict):
            raise BenchmarkError(f"{label} must be a JSON object")
        _exact_keys(
            raw_outcome,
            {
                "schema",
                "suite_digest",
                "case_id",
                "tree_digest",
                "run_id",
                "system",
                "evidence_digest",
                "verdict",
                "reason_codes",
            },
            label,
        )
        if raw_outcome["schema"] != "aragorn/benchmark-outcome/v1":
            raise BenchmarkError(f"{label} has an unsupported schema")
        if raw_outcome["suite_digest"] != suite_digest:
            raise BenchmarkError(f"{label}.suite_digest does not match the suite")
        case_id = _identifier(raw_outcome["case_id"], f"{label}.case_id")
        if case_id not in cases:
            raise BenchmarkError(f"outcome references unknown case: {case_id}")
        tree_digest = _digest(raw_outcome["tree_digest"], f"{label}.tree_digest")
        if tree_digest != cases[case_id]["tree_digest"]:
            raise BenchmarkError(f"{label}.tree_digest does not match the case")
        run_id = raw_outcome["run_id"]
        if (
            isinstance(run_id, bool)
            or not isinstance(run_id, int)
            or not 1 <= run_id <= runs_per_case
        ):
            raise BenchmarkError(f"{label}.run_id is outside the declared run matrix")
        system = _validate_system(raw_outcome["system"], label)
        system_key = _system_key(system)
        if system_key not in systems:
            raise BenchmarkError(f"{label}.system is not declared by the suite")
        cell = (system_key, case_id, run_id)
        if cell in seen:
            raise BenchmarkError(
                f"duplicate outcome for {system['name']}:{case_id}:run-{run_id}"
            )
        seen.add(cell)
        evidence_digest = _digest(
            raw_outcome["evidence_digest"], f"{label}.evidence_digest"
        )
        verdict = raw_outcome["verdict"]
        if verdict not in _VERDICTS:
            raise BenchmarkError(f"{label}.verdict is unsupported")
        reason_codes = raw_outcome["reason_codes"]
        if not isinstance(reason_codes, list):
            raise BenchmarkError(f"{label}.reason_codes must be an array")
        normalized_reasons = [
            _reason_code(reason, f"{label}.reason_codes") for reason in reason_codes
        ]
        if len(normalized_reasons) != len(set(normalized_reasons)):
            raise BenchmarkError(f"{label}.reason_codes must be unique")
        normalized_reasons.sort()
        if verdict == "ALLOW" and normalized_reasons:
            raise BenchmarkError(f"{label}: ALLOW must not contain reason codes")
        if verdict != "ALLOW" and not normalized_reasons:
            raise BenchmarkError(f"{label}: non-ALLOW requires a reason code")
        normalized_outcome = {
            "schema": "aragorn/benchmark-outcome/v1",
            "suite_digest": suite_digest,
            "case_id": case_id,
            "tree_digest": tree_digest,
            "run_id": run_id,
            "system": system,
            "evidence_digest": evidence_digest,
            "verdict": verdict,
            "reason_codes": normalized_reasons,
        }
        if purpose == "evidence_smoke":
            assert evidence_cas is not None
            evidence_binding = _verify_evidence(
                evidence_cas,
                normalized_outcome,
                expected_manifest=manifests[case_id],
                label=label,
                expected_dispatch_matrix=expected_dispatch_matrix,
                acceptance_ledger=acceptance_ledger,
            )
            if evidence_binding is not None:
                if "evidence_kind" in evidence_binding:
                    candidate_bindings.append(evidence_binding)
                else:
                    v4_bindings.append(evidence_binding)
        normalized.append(normalized_outcome)

    expected_count = len(systems) * len(cases) * runs_per_case
    if len(seen) != expected_count:
        missing = []
        for system_key in sorted(systems):
            for case_id in sorted(cases):
                for run_id in range(1, runs_per_case + 1):
                    if (system_key, case_id, run_id) not in seen:
                        missing.append(
                            f"{systems[system_key]['name']}:{case_id}:run-{run_id}"
                        )
                        if len(missing) == 8:
                            break
                if len(missing) == 8:
                    break
            if len(missing) == 8:
                break
        suffix = " ..." if expected_count - len(seen) > len(missing) else ""
        raise BenchmarkError(
            "outcome matrix is incomplete; missing: " + ", ".join(missing) + suffix
        )
    if v4_bindings and candidate_bindings:
        raise BenchmarkError(
            "evidence v4 cannot be mixed with candidate-composition evidence"
        )
    if require_candidate_composition and len(candidate_bindings) != expected_count:
        raise BenchmarkError(
            "Phase 0 hidden gate requires candidate-composition evidence "
            "for the entire outcome matrix"
        )
    _verify_v4_batch_bindings(
        v4_bindings,
        expected_count=expected_count,
        suite_digest=suite_digest,
    )
    if candidate_bindings and all(
        item["evidence_kind"] == "authenticated_worker"
        and item["dispatch"].get("schema")
        == "aragorn/benchmark-private-dispatch/v1"
        for item in candidate_bindings
    ):
        _verify_authenticated_worker_batch_bindings(
            candidate_bindings,
            expected_count=expected_count,
            suite_digest=suite_digest,
        )
    else:
        _verify_candidate_batch_bindings(
            candidate_bindings,
            expected_count=expected_count,
            suite_digest=suite_digest,
            expected_policy_digest=expected_candidate_policy_digest,
        )
    return normalized


def _verify_v4_batch_bindings(
    bindings: list[dict[str, str]],
    *,
    expected_count: int,
    suite_digest: str,
) -> None:
    if not bindings:
        return
    if len(bindings) != expected_count:
        raise BenchmarkError("evidence v4 cannot be mixed with older evidence versions")
    if len({item["dispatch_digest"] for item in bindings}) != 1:
        raise BenchmarkError("evidence v4 outcomes do not share one dispatch")
    if len({item["ledger_id"] for item in bindings}) != 1:
        raise BenchmarkError("evidence v4 outcomes do not share one nonce binding")
    for field in ("job_id", "nonce", "request_digest", "result_digest"):
        values = [item[field] for item in bindings]
        if len(values) != len(set(values)):
            raise BenchmarkError(f"evidence v4 repeats a worker {field}")
    dispatch_digest = bindings[0]["dispatch_digest"]
    expected_ledger_id = _digest_json(
        {
            "schema": "aragorn/benchmark-worker-nonce-ledger-id/v1",
            "suite_digest": suite_digest,
            "dispatch_digest": dispatch_digest,
            "jobs": sorted(
                (
                    {
                        "job_id": item["job_id"],
                        "nonce": item["nonce"],
                        "request_digest": item["request_digest"],
                        "result_digest": item["result_digest"],
                    }
                    for item in bindings
                ),
                key=lambda item: item["job_id"],
            ),
        }
    )
    if bindings[0]["ledger_id"] != expected_ledger_id:
        raise BenchmarkError("evidence v4 nonce binding digest does not re-derive")


def _verify_authenticated_worker_batch_bindings(
    bindings: list[dict[str, Any]],
    *,
    expected_count: int,
    suite_digest: str,
) -> None:
    if len(bindings) != expected_count:
        raise BenchmarkError(
            "authenticated worker evidence cannot be mixed with older evidence"
        )
    if (
        len({item["dispatch_digest"] for item in bindings}) != 1
        or any(item["dispatch"] != bindings[0]["dispatch"] for item in bindings)
    ):
        raise BenchmarkError(
            "authenticated worker outcomes do not share one dispatch"
        )
    dispatch = bindings[0]["dispatch"]
    if (
        dispatch.get("schema") != "aragorn/benchmark-private-dispatch/v1"
        or {entry["suite_digest"] for entry in dispatch["jobs"]} != {suite_digest}
    ):
        raise BenchmarkError(
            "authenticated worker dispatch does not bind the suite"
        )
    dispatch_jobs = {entry["job_id"]: entry for entry in dispatch["jobs"]}
    bound_jobs = {item["job"]["job_id"]: item["job"] for item in bindings}
    if (
        len(dispatch_jobs) != expected_count
        or len(bound_jobs) != expected_count
        or dispatch_jobs != bound_jobs
        or len({item["evidence_digest"] for item in bindings}) != expected_count
    ):
        raise BenchmarkError(
            "authenticated worker evidence does not close the exact dispatch"
        )


def _verify_candidate_batch_bindings(
    bindings: list[dict[str, Any]],
    *,
    expected_count: int,
    suite_digest: str,
    expected_policy_digest: str | None = None,
) -> None:
    if not bindings:
        return
    from .phase0_candidate import compose_candidate_decision

    if len(bindings) != expected_count:
        raise BenchmarkError(
            "candidate-composition evidence cannot be mixed with older evidence versions"
        )
    if len({item["dispatch_digest"] for item in bindings}) != 1:
        raise BenchmarkError(
            "candidate-composition outcomes do not share one dispatch"
        )
    if len({item["policy_digest"] for item in bindings}) != 1:
        raise BenchmarkError("candidate-composition outcomes do not share one policy")
    if (
        expected_policy_digest is not None
        and bindings[0]["policy_digest"] != expected_policy_digest
    ):
        raise BenchmarkError(
            "candidate-composition evidence does not match the frozen candidate policy"
        )

    candidate_bindings = [
        item for item in bindings if item["evidence_kind"] == "candidate"
    ]
    worker_bindings = [
        item
        for item in bindings
        if item["evidence_kind"] == "authenticated_worker"
    ]
    if len(candidate_bindings) * 3 != expected_count:
        raise BenchmarkError(
            "candidate-composition evidence requires one candidate per matrix cell"
        )
    if len(worker_bindings) != len(candidate_bindings) * 2:
        raise BenchmarkError(
            "candidate-composition evidence requires two comparators per matrix cell"
        )

    policy = candidate_bindings[0]["policy"]
    dispatch = candidate_bindings[0]["dispatch"]
    required_comparators = {
        system["name"]: system for system in policy["required_comparators"]
    }
    expected_candidate = candidate_bindings[0]["candidate_system"]
    if (
        dispatch["suite_digest"] != suite_digest
        or dispatch["candidate_system"] != expected_candidate
        or dispatch["candidate_policy_digest"] != bindings[0]["policy_digest"]
    ):
        raise BenchmarkError(
            "candidate-composition dispatch does not bind the suite and policy"
        )
    if any(
        item["policy_digest"] != dispatch["candidate_policy_digest"]
        for item in bindings
    ):
        raise BenchmarkError("candidate-composition evidence changed policy binding")

    dispatch_jobs = {entry["job_id"]: entry for entry in dispatch["jobs"]}
    bound_jobs = {item["job"]["job_id"]: item["job"] for item in worker_bindings}
    if dispatch_jobs != bound_jobs:
        raise BenchmarkError(
            "authenticated comparator evidence does not close the exact dispatch"
        )

    cells: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in bindings:
        envelope = item["envelope"]
        cells.setdefault(
            (envelope["case_id"], envelope["run_id"]),
            [],
        ).append(item)
    for cell, items in cells.items():
        candidates = [
            item for item in items if item["evidence_kind"] == "candidate"
        ]
        components = [
            item
            for item in items
            if item["evidence_kind"] == "authenticated_worker"
        ]
        if len(candidates) != 1 or len(components) != 2 or len(items) != 3:
            raise BenchmarkError(
                f"candidate-composition cell {cell[0]}:run-{cell[1]} is incomplete"
            )
        candidate = candidates[0]
        component_by_name = {
            item["envelope"]["system"]["name"]: item for item in components
        }
        if (
            set(component_by_name) != set(required_comparators)
            or any(
                component_by_name[name]["envelope"]["system"]
                != required_comparators[name]
                for name in required_comparators
            )
        ):
            raise BenchmarkError(
                f"candidate-composition cell {cell[0]}:run-{cell[1]} "
                "does not contain the frozen comparator pair"
            )
        if candidate["envelope"]["system"] != expected_candidate:
            raise BenchmarkError(
                f"candidate-composition cell {cell[0]}:run-{cell[1]} "
                "changed the Aragorn identity"
            )

        envelope_set = [item["envelope"] for item in items]
        for field in (
            "suite_digest",
            "case_id",
            "tree_digest",
            "run_id",
            "private_manifest_digest",
            "dispatch_digest",
        ):
            if len({item[field] for item in envelope_set}) != 1:
                raise BenchmarkError(
                    f"candidate-composition cell {cell[0]}:run-{cell[1]} "
                    f"does not share one {field}"
                )
        expected_component_digests = sorted(
            item["evidence_digest"] for item in components
        )
        if (
            candidate["envelope"]["component_evidence_digests"]
            != expected_component_digests
        ):
            raise BenchmarkError(
                f"candidate-composition cell {cell[0]}:run-{cell[1]} "
                "does not bind the exact comparator evidence"
            )
        try:
            expected_verdict, expected_reasons = compose_candidate_decision(
                policy,
                candidate["source_graph"],
                (item["envelope"] for item in components),
                first_party_observations=candidate.get(
                    "first_party_observations",
                    (),
                ),
            )
        except ValueError as exc:
            raise BenchmarkError(
                f"candidate-composition decision cannot be derived: {exc}"
            ) from exc
        if (
            candidate["envelope"]["verdict"] != expected_verdict
            or candidate["envelope"]["reason_codes"] != expected_reasons
        ):
            raise BenchmarkError(
                f"candidate-composition cell {cell[0]}:run-{cell[1]} "
                "decision does not re-derive"
            )


def _verify_composed_evidence_common(
    cas: CAS,
    outcome: dict[str, Any],
    *,
    expected_manifest: dict[str, Any],
    label: str,
    envelope: dict[str, Any],
) -> str:
    for field in (
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "system",
        "verdict",
        "reason_codes",
    ):
        if envelope[field] != outcome[field]:
            raise BenchmarkError(f"{label}.evidence.{field} does not match outcome")
    manifest_digest = _digest(
        envelope["private_manifest_digest"],
        f"{label}.evidence.private_manifest_digest",
    )
    if manifest_digest != _digest_json(expected_manifest):
        raise BenchmarkError(
            f"{label}.evidence private manifest does not match the suite case"
        )
    manifest = _read_canonical_document(
        cas,
        manifest_digest,
        f"{label}.evidence.private_manifest",
        max_bytes=_MAX_SUITE_BYTES,
    )
    if manifest != expected_manifest:
        raise BenchmarkError(
            f"{label}.evidence private manifest bytes do not match the suite"
        )
    return manifest_digest


def _load_candidate_dispatch(
    cas: CAS,
    digest: object,
    *,
    suite_digest: str,
    label: str,
) -> tuple[str, dict[str, Any]]:
    dispatch_digest = _digest(digest, f"{label}.dispatch_digest")
    dispatch = _read_canonical_document(
        cas,
        dispatch_digest,
        f"{label}.dispatch",
        max_bytes=_MAX_SUITE_BYTES,
    )
    from .label_blind_prepare import validate_private_dispatch_v2

    try:
        validate_private_dispatch_v2(dispatch)
    except ValueError as exc:
        raise BenchmarkError(f"{label}.dispatch is invalid: {exc}") from exc
    if (
        _digest_json(dispatch) != dispatch_digest
        or dispatch["suite_digest"] != suite_digest
    ):
        raise BenchmarkError(f"{label}.dispatch is not bound to the suite")
    return dispatch_digest, dispatch


def _load_authenticated_worker_dispatch(
    cas: CAS,
    digest: object,
    *,
    suite_digest: str,
    label: str,
) -> tuple[str, dict[str, Any]]:
    dispatch_digest = _digest(digest, f"{label}.dispatch_digest")
    dispatch = _read_canonical_document(
        cas,
        dispatch_digest,
        f"{label}.dispatch",
        max_bytes=_MAX_SUITE_BYTES,
    )
    from .label_blind_prepare import (
        validate_private_dispatch,
        validate_private_dispatch_v2,
    )

    try:
        if dispatch.get("schema") == "aragorn/benchmark-private-dispatch/v1":
            validate_private_dispatch(dispatch)
            suites = {entry["suite_digest"] for entry in dispatch["jobs"]}
            if suites != {suite_digest}:
                raise ValueError("dispatch spans a different suite")
        else:
            validate_private_dispatch_v2(dispatch)
            if dispatch["suite_digest"] != suite_digest:
                raise ValueError("dispatch spans a different suite")
    except (KeyError, ValueError) as exc:
        raise BenchmarkError(f"{label}.dispatch is invalid: {exc}") from exc
    if _digest_json(dispatch) != dispatch_digest:
        raise BenchmarkError(f"{label}.dispatch is not canonical")
    return dispatch_digest, dispatch


def _verify_authenticated_worker_evidence(
    cas: CAS,
    outcome: dict[str, Any],
    *,
    expected_manifest: dict[str, Any],
    label: str,
    envelope: dict[str, Any],
    acceptance_ledger: Path | None,
) -> dict[str, Any]:
    evidence_label = f"{label}.evidence"
    _exact_keys(
        envelope,
        {
            "schema",
            "suite_digest",
            "case_id",
            "tree_digest",
            "run_id",
            "system",
            "verdict",
            "reason_codes",
            "private_manifest_digest",
            "dispatch_digest",
            "acceptance_receipt_digest",
            "issuance_digest",
        },
        evidence_label,
    )
    manifest_digest = _verify_composed_evidence_common(
        cas,
        outcome,
        expected_manifest=expected_manifest,
        label=label,
        envelope=envelope,
    )
    try:
        dispatch_digest, dispatch = _load_candidate_dispatch(
            cas,
            envelope["dispatch_digest"],
            suite_digest=outcome["suite_digest"],
            label=evidence_label,
        )
    except BenchmarkError:
        dispatch_digest, dispatch = _load_authenticated_worker_dispatch(
            cas,
            envelope["dispatch_digest"],
            suite_digest=outcome["suite_digest"],
            label=evidence_label,
        )
    matches = [
        entry
        for entry in dispatch["jobs"]
        if entry["case_id"] == outcome["case_id"]
        and entry["run_id"] == outcome["run_id"]
        and entry["system"] == outcome["system"]
    ]
    if len(matches) != 1:
        raise BenchmarkError(
            f"{evidence_label}.dispatch does not select one exact worker job"
        )
    job = matches[0]
    for field, expected in {
        "suite_digest": outcome["suite_digest"],
        "tree_digest": outcome["tree_digest"],
        "private_manifest_digest": manifest_digest,
    }.items():
        if job[field] != expected:
            raise BenchmarkError(
                f"{evidence_label}.dispatch job {field} does not match outcome"
            )

    request = _read_canonical_document(
        cas,
        job["request_digest"],
        f"{evidence_label}.worker_request",
        max_bytes=64 * 1024,
    )
    try:
        validate_worker_request_v2(request)
        subject = sanitize_subject_manifest(expected_manifest)
    except WorkerProtocolError as exc:
        raise BenchmarkError(
            f"{evidence_label}.worker_request is invalid: {exc}"
        ) from exc
    expected_request_system = {
        field: outcome["system"][field]
        for field in ("name", "version", "implementation_digest")
    }
    if (
        canonical_request_digest_v2(request) != job["request_digest"]
        or request["job_id"] != job["job_id"]
        or request["subject"]
        != {
            "manifest_digest": _digest_json(subject),
            "tree_digest": outcome["tree_digest"],
        }
        or request["portable_policy_digest"] != outcome["system"]["config_digest"]
        or request["system"] != expected_request_system
    ):
        raise BenchmarkError(
            f"{evidence_label}.worker_request does not match private dispatch"
        )

    issuance_digest = _digest(
        envelope["issuance_digest"], f"{evidence_label}.issuance_digest"
    )
    receipt_digest = _digest(
        envelope["acceptance_receipt_digest"],
        f"{evidence_label}.acceptance_receipt_digest",
    )
    issuance = _read_canonical_document(
        cas,
        issuance_digest,
        f"{evidence_label}.issuance",
        max_bytes=256 * 1024,
    )
    receipt = _read_canonical_document(
        cas,
        receipt_digest,
        f"{evidence_label}.acceptance_receipt",
        max_bytes=256 * 1024,
    )
    from .benchmark_authenticated_handoff_v2 import (
        load_verified_worker_output_acceptance,
    )

    if acceptance_ledger is None:
        raise BenchmarkError(
            f"{evidence_label} requires a protected acceptance ledger"
        )
    try:
        accepted = load_verified_worker_output_acceptance(
            cas,
            acceptance_ledger,
            receipt.get("verifier_challenge"),
        )
    except ValueError as exc:
        raise BenchmarkError(
            f"{evidence_label} authenticated acceptance is invalid: {exc}"
        ) from exc
    if accepted != {"issuance": issuance, "receipt": receipt}:
        raise BenchmarkError(
            f"{evidence_label} acceptance is not a member of the protected ledger"
        )
    if (
        receipt["job_id"] != job["job_id"]
        or receipt["request_digest"] != job["request_digest"]
    ):
        raise BenchmarkError(
            f"{evidence_label} authenticated acceptance changed its dispatch job"
        )

    result = _read_canonical_document(
        cas,
        receipt["result_digest"],
        f"{evidence_label}.worker_result",
        max_bytes=_MAX_SUITE_BYTES,
    )
    try:
        validate_worker_result_v2(result)
    except WorkerProtocolError as exc:
        raise BenchmarkError(
            f"{evidence_label}.worker_result is invalid: {exc}"
        ) from exc
    result_bindings = {
        "job_id": job["job_id"],
        "verifier_challenge": request["verifier_challenge"],
        "request_digest": job["request_digest"],
        "portable_policy_digest": outcome["system"]["config_digest"],
        "subject_manifest_digest": request["subject"]["manifest_digest"],
        "tree_digest": outcome["tree_digest"],
        "verified_subject_digest": outcome["tree_digest"],
        "system": expected_request_system,
        "verdict": outcome["verdict"],
        "reason_codes": outcome["reason_codes"],
    }
    for field, expected in result_bindings.items():
        if result[field] != expected:
            raise BenchmarkError(
                f"{evidence_label}.worker_result.{field} does not match outcome"
            )
    binding = {
        "evidence_kind": "authenticated_worker",
        "evidence_digest": outcome["evidence_digest"],
        "envelope": envelope,
        "dispatch_digest": dispatch_digest,
        "dispatch": dispatch,
        "job": job,
    }
    if dispatch["schema"] == "aragorn/benchmark-private-dispatch/v2":
        binding["policy_digest"] = dispatch["candidate_policy_digest"]
    return binding


def _verify_candidate_evidence(
    cas: CAS,
    outcome: dict[str, Any],
    *,
    expected_manifest: dict[str, Any],
    label: str,
    envelope: dict[str, Any],
) -> dict[str, Any]:
    evidence_label = f"{label}.evidence"
    evidence_schema = envelope.get("schema")
    evidence_keys = {
        "schema",
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "system",
        "verdict",
        "reason_codes",
        "private_manifest_digest",
        "source_graph_digest",
        "dispatch_digest",
        "policy_digest",
        "component_evidence_digests",
    }
    if evidence_schema == "aragorn/benchmark-candidate-evidence/v2":
        evidence_keys.add("first_party_observation_digests")
    elif evidence_schema != "aragorn/benchmark-candidate-evidence/v1":
        raise BenchmarkError(f"{evidence_label}.schema is unsupported")
    _exact_keys(
        envelope,
        evidence_keys,
        evidence_label,
    )
    manifest_digest = _verify_composed_evidence_common(
        cas,
        outcome,
        expected_manifest=expected_manifest,
        label=label,
        envelope=envelope,
    )
    dispatch_digest, dispatch = _load_candidate_dispatch(
        cas,
        envelope["dispatch_digest"],
        suite_digest=outcome["suite_digest"],
        label=evidence_label,
    )
    policy_digest = _digest(
        envelope["policy_digest"], f"{evidence_label}.policy_digest"
    )
    if policy_digest != dispatch["candidate_policy_digest"]:
        raise BenchmarkError(f"{evidence_label}.policy_digest changed dispatch policy")
    policy_document = _read_canonical_document(
        cas,
        policy_digest,
        f"{evidence_label}.policy",
        max_bytes=_MAX_INPUT_BYTES,
    )
    from .phase0_candidate import (
        build_candidate_policy,
        candidate_system_identity,
        detect_first_party_observations,
    )

    try:
        policy = build_candidate_policy(policy_document)
        candidate_system = candidate_system_identity(policy)
    except ValueError as exc:
        raise BenchmarkError(f"{evidence_label}.policy is invalid: {exc}") from exc
    expected_evidence_schema = {
        "aragorn/benchmark-candidate-policy/v1": (
            "aragorn/benchmark-candidate-evidence/v1"
        ),
        "aragorn/benchmark-candidate-policy/v2": (
            "aragorn/benchmark-candidate-evidence/v2"
        ),
        "aragorn/benchmark-candidate-policy/v3": (
            "aragorn/benchmark-candidate-evidence/v2"
        ),
    }[policy["schema"]]
    if evidence_schema != expected_evidence_schema:
        raise BenchmarkError(
            f"{evidence_label}.schema does not match candidate policy"
        )
    if _digest_json(policy) != policy_digest:
        raise BenchmarkError(f"{evidence_label}.policy canonical digest changed")
    if (
        candidate_system != outcome["system"]
        or candidate_system != dispatch["candidate_system"]
    ):
        raise BenchmarkError(f"{evidence_label}.system does not match candidate policy")

    source_graph_digest = _digest(
        envelope["source_graph_digest"],
        f"{evidence_label}.source_graph_digest",
    )
    source_graph = _read_canonical_document(
        cas,
        source_graph_digest,
        f"{evidence_label}.source_graph",
        max_bytes=_MAX_SUITE_BYTES,
    )
    try:
        expected_graph = resolve_source_graph(
            expected_manifest,
            cas,
            root_manifest_digest=manifest_digest,
        )
    except (ArtifactClosureError, CASError) as exc:
        raise BenchmarkError(
            f"{evidence_label}.source_graph cannot be re-derived: {exc}"
        ) from exc
    if (
        source_graph != expected_graph
        or _digest_json(expected_graph) != source_graph_digest
    ):
        raise BenchmarkError(f"{evidence_label}.source_graph does not re-derive")

    first_party_observations = ()
    if evidence_schema == "aragorn/benchmark-candidate-evidence/v2":
        try:
            first_party_observations = detect_first_party_observations(
                expected_manifest,
                cas,
            )
        except ValueError as exc:
            raise BenchmarkError(
                f"{evidence_label}.first_party analysis cannot be re-derived: {exc}"
            ) from exc
        expected_observations = {
            _digest_bytes(observation.document_json.encode("ascii")): observation
            for observation in first_party_observations
        }
        expected_observation_digests = sorted(expected_observations)
        raw_observation_digests = envelope["first_party_observation_digests"]
        if not isinstance(raw_observation_digests, list) or len(
            raw_observation_digests
        ) > 4:
            raise BenchmarkError(
                f"{evidence_label}.first_party_observation_digests is invalid"
            )
        observation_digests = [
            _digest(
                value,
                f"{evidence_label}.first_party_observation_digests",
            )
            for value in raw_observation_digests
        ]
        if observation_digests != sorted(set(observation_digests)):
            raise BenchmarkError(
                f"{evidence_label}.first_party_observation_digests is invalid"
            )
        if observation_digests != expected_observation_digests:
            raise BenchmarkError(
                f"{evidence_label}.first_party observations do not re-derive"
            )
        for digest in observation_digests:
            observation = expected_observations[digest]
            if cas.read(digest, max_bytes=_MAX_EVIDENCE_BYTES) != (
                observation.document_json.encode("ascii")
            ):
                raise BenchmarkError(
                    f"{evidence_label}.first_party observation bytes changed"
                )

    raw_component_digests = envelope["component_evidence_digests"]
    if not isinstance(raw_component_digests, list):
        raise BenchmarkError(
            f"{evidence_label}.component_evidence_digests must be an array"
        )
    component_digests = [
        _digest(value, f"{evidence_label}.component_evidence_digests")
        for value in raw_component_digests
    ]
    if len(component_digests) != 2 or component_digests != sorted(
        set(component_digests)
    ):
        raise BenchmarkError(
            f"{evidence_label}.component_evidence_digests must be two sorted digests"
        )
    return {
        "evidence_kind": "candidate",
        "evidence_digest": outcome["evidence_digest"],
        "envelope": envelope,
        "dispatch_digest": dispatch_digest,
        "dispatch": dispatch,
        "policy_digest": policy_digest,
        "policy": policy,
        "candidate_system": candidate_system,
        "source_graph": source_graph,
        "first_party_observations": first_party_observations,
    }


def _verify_evidence(
    cas: CAS,
    outcome: dict[str, Any],
    *,
    expected_manifest: dict[str, Any],
    label: str,
    expected_dispatch_matrix: dict[
        tuple[tuple[str, str, str, str], str, int], dict[str, Any]
    ]
    | None = None,
    acceptance_ledger: Path | None = None,
) -> dict[str, Any] | None:
    envelope = _read_canonical_document(
        cas,
        outcome["evidence_digest"],
        f"{label}.evidence",
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    if envelope.get("schema") == "aragorn/benchmark-evidence/v4":
        return _verify_oci_evidence_v4(
            cas,
            outcome,
            expected_manifest=expected_manifest,
            label=label,
            envelope=envelope,
            expected_dispatch_matrix=expected_dispatch_matrix,
        )
    if (
        envelope.get("schema")
        == "aragorn/benchmark-authenticated-worker-evidence/v1"
    ):
        return _verify_authenticated_worker_evidence(
            cas,
            outcome,
            expected_manifest=expected_manifest,
            label=label,
            envelope=envelope,
            acceptance_ledger=acceptance_ledger,
        )
    if envelope.get("schema") in {
        "aragorn/benchmark-candidate-evidence/v1",
        "aragorn/benchmark-candidate-evidence/v2",
    }:
        return _verify_candidate_evidence(
            cas,
            outcome,
            expected_manifest=expected_manifest,
            label=label,
            envelope=envelope,
        )
    if envelope.get("schema") in {
        "aragorn/benchmark-evidence/v2",
        "aragorn/benchmark-evidence/v3",
    }:
        _verify_oci_evidence_v2(
            cas,
            outcome,
            expected_manifest=expected_manifest,
            label=label,
            envelope=envelope,
        )
        return None
    _exact_keys(
        envelope,
        {
            "schema",
            "suite_digest",
            "case_id",
            "tree_digest",
            "run_id",
            "system",
            "manifest_digest",
            "operator_config_digest",
            "effective_config_digest",
            "executable_digest",
            "stdout_digest",
            "stderr_digest",
            "observation_digests",
            "execution",
            "normalization",
            "verdict",
            "reason_codes",
        },
        f"{label}.evidence",
    )
    if envelope["schema"] != "aragorn/benchmark-evidence/v1":
        raise BenchmarkError(f"{label}.evidence has an unsupported schema")
    for field in (
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "verdict",
        "reason_codes",
    ):
        if envelope[field] != outcome[field]:
            raise BenchmarkError(f"{label}.evidence.{field} does not match outcome")
    evidence_system = _validate_system(envelope["system"], f"{label}.evidence")
    if evidence_system != outcome["system"]:
        raise BenchmarkError(f"{label}.evidence.system does not match outcome")
    if envelope["normalization"] != "aragorn-observation-severity/v1":
        raise BenchmarkError(f"{label}.evidence normalization is unsupported")

    manifest_digest = _digest(
        envelope["manifest_digest"], f"{label}.evidence.manifest_digest"
    )
    if manifest_digest != _digest_json(expected_manifest):
        raise BenchmarkError(f"{label}.evidence manifest does not match the suite case")
    manifest = _read_canonical_document(
        cas,
        manifest_digest,
        f"{label}.evidence.manifest",
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    if manifest != expected_manifest:
        raise BenchmarkError(f"{label}.evidence manifest bytes do not match the suite")

    operator_config_digest = _digest(
        envelope["operator_config_digest"],
        f"{label}.evidence.operator_config_digest",
    )
    operator_config = cas.read(operator_config_digest, max_bytes=_MAX_INPUT_BYTES)
    effective_config_digest = _digest(
        envelope["effective_config_digest"],
        f"{label}.evidence.effective_config_digest",
    )
    executable_digest = _digest(
        envelope["executable_digest"], f"{label}.evidence.executable_digest"
    )
    if effective_config_digest != outcome["system"]["config_digest"]:
        raise BenchmarkError(f"{label}.evidence effective config identity is unbound")
    if executable_digest != outcome["system"]["implementation_digest"]:
        raise BenchmarkError(f"{label}.evidence executable identity is unbound")
    effective_config = _read_canonical_document(
        cas,
        effective_config_digest,
        f"{label}.evidence.effective_config",
        max_bytes=_MAX_INPUT_BYTES,
    )
    _validate_effective_config(effective_config, outcome["system"], label)
    _validate_operator_config(operator_config, effective_config, label)
    cas.verify(executable_digest, max_bytes=_MAX_EXECUTABLE_BYTES)

    stdout_digest = _digest(
        envelope["stdout_digest"], f"{label}.evidence.stdout_digest"
    )
    stderr_digest = _digest(
        envelope["stderr_digest"], f"{label}.evidence.stderr_digest"
    )
    stdout = cas.read(stdout_digest, max_bytes=_MAX_EVIDENCE_BYTES)
    stderr = cas.read(stderr_digest, max_bytes=_MAX_EVIDENCE_BYTES)
    raw_observation_digests = envelope["observation_digests"]
    if (
        not isinstance(raw_observation_digests, list)
        or len(raw_observation_digests) > 10_000
    ):
        raise BenchmarkError(f"{label}.evidence observation list is invalid")
    observation_digests = [
        _digest(value, f"{label}.evidence.observation_digests")
        for value in raw_observation_digests
    ]

    execution = envelope["execution"]
    if not isinstance(execution, dict):
        raise BenchmarkError(f"{label}.evidence.execution must be a JSON object")
    _exact_keys(
        execution,
        {"status", "error_code", "returncode"},
        f"{label}.evidence.execution",
    )
    status = execution["status"]
    error_code = execution["error_code"]
    returncode = execution["returncode"]
    if returncode is not None and (
        isinstance(returncode, bool) or not isinstance(returncode, int)
    ):
        raise BenchmarkError(f"{label}.evidence.execution.returncode is invalid")

    if status == "ok":
        if error_code is not None or returncode != 0:
            raise BenchmarkError(
                f"{label}.evidence successful execution is inconsistent"
            )
        observations, parse_error = _parse_observations(stdout, outcome["tree_digest"])
        if parse_error is not None:
            raise BenchmarkError(
                f"{label}.evidence successful stdout is malformed: {parse_error[0]}"
            )
        expected_observation_bytes = [
            observation.document_json.encode("ascii") for observation in observations
        ]
        expected_observation_digests = [
            _digest_bytes(content) for content in expected_observation_bytes
        ]
        if observation_digests != expected_observation_digests:
            raise BenchmarkError(f"{label}.evidence observations do not match stdout")
        for digest, content in zip(observation_digests, expected_observation_bytes):
            if cas.read(digest, max_bytes=_MAX_EVIDENCE_BYTES) != content:
                raise BenchmarkError(
                    f"{label}.evidence canonical observation bytes do not match"
                )
        reconstructed = AnalyzerResult(
            name=outcome["system"]["name"],
            version=outcome["system"]["version"],
            config_digest=outcome["system"]["config_digest"],
            executable_digest=outcome["system"]["implementation_digest"],
            status="ok",
            observations=observations,
            raw_stdout=stdout,
            returncode=0,
        )
    elif status == "error":
        if (
            not isinstance(error_code, str)
            or _REASON_CODE.fullmatch(error_code) is None
        ):
            raise BenchmarkError(f"{label}.evidence execution error code is invalid")
        if observation_digests:
            raise BenchmarkError(f"{label}.evidence failed execution has observations")
        _validate_error_evidence(
            error_code,
            returncode,
            stdout=stdout,
            stderr=stderr,
            subject_digest=outcome["tree_digest"],
            output_limit=effective_config["limits"]["output_bytes"],
            label=label,
        )
        reconstructed = AnalyzerResult(
            name=outcome["system"]["name"],
            version=outcome["system"]["version"],
            config_digest=outcome["system"]["config_digest"],
            executable_digest=outcome["system"]["implementation_digest"],
            status="error",
            error_code=error_code,
            raw_stdout=stdout,
            returncode=returncode,
        )
    else:
        raise BenchmarkError(f"{label}.evidence execution status is unsupported")

    expected_verdict, expected_reasons = normalize_analyzer_result(reconstructed)
    if outcome["verdict"] != expected_verdict or outcome["reason_codes"] != list(
        expected_reasons
    ):
        raise BenchmarkError(f"{label}.evidence does not derive the declared outcome")


def _verify_oci_evidence_v4(
    cas: CAS,
    outcome: dict[str, Any],
    *,
    expected_manifest: dict[str, Any],
    label: str,
    envelope: dict[str, Any],
    expected_dispatch_matrix: dict[
        tuple[tuple[str, str, str, str], str, int], dict[str, Any]
    ]
    | None,
) -> dict[str, str]:
    """Verify a collected unsigned label-free worker closure and nested OCI v3."""

    evidence_label = f"{label}.evidence"
    _exact_keys(
        envelope,
        {
            "schema",
            "suite_digest",
            "case_id",
            "tree_digest",
            "run_id",
            "system",
            "verdict",
            "reason_codes",
            "nested_evidence_digest",
            "worker",
        },
        evidence_label,
    )
    for field in (
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "system",
        "verdict",
        "reason_codes",
    ):
        if envelope[field] != outcome[field]:
            raise BenchmarkError(f"{evidence_label}.{field} does not match outcome")

    worker = envelope["worker"]
    if not isinstance(worker, dict):
        raise BenchmarkError(f"{evidence_label}.worker must be an object")
    _exact_keys(
        worker,
        {
            "assurance",
            "ledger_id",
            "dispatch_digest",
            "job_id",
            "nonce",
            "request_digest",
            "result_digest",
            "subject_manifest_digest",
            "output_closure_digest",
            "nonce_receipt_digest",
        },
        f"{evidence_label}.worker",
    )
    if worker["assurance"] != "unsigned_label_free_protocol_not_isolated_or_attested":
        raise BenchmarkError(f"{evidence_label}.worker assurance is unsupported")
    for field in (
        "ledger_id",
        "dispatch_digest",
        "request_digest",
        "result_digest",
        "subject_manifest_digest",
        "output_closure_digest",
        "nonce_receipt_digest",
    ):
        _digest(worker[field], f"{evidence_label}.worker.{field}")
    if (
        not isinstance(worker["job_id"], str)
        or re.fullmatch(r"[0-9a-f]{32}", worker["job_id"]) is None
    ):
        raise BenchmarkError(f"{evidence_label}.worker.job_id is invalid")
    if (
        not isinstance(worker["nonce"], str)
        or re.fullmatch(r"[0-9a-f]{64}", worker["nonce"]) is None
    ):
        raise BenchmarkError(f"{evidence_label}.worker.nonce is invalid")

    request = _read_canonical_document(
        cas,
        worker["request_digest"],
        f"{evidence_label}.worker.request",
        max_bytes=64 * 1024,
    )
    result = _read_canonical_document(
        cas,
        worker["result_digest"],
        f"{evidence_label}.worker.result",
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    subject = _read_canonical_document(
        cas,
        worker["subject_manifest_digest"],
        f"{evidence_label}.worker.subject_manifest",
        max_bytes=_MAX_SUITE_BYTES,
    )
    try:
        validate_worker_request(request)
        validate_worker_result(result)
        validate_subject_manifest(subject)
        verify_request_subject(request, subject)
        verify_request_result_binding(request, result)
    except WorkerProtocolError as exc:
        raise BenchmarkError(
            f"{evidence_label}.worker protocol binding is invalid: {exc}"
        ) from exc

    worker_bindings = {
        "job_id": request["job_id"],
        "nonce": request["nonce"],
        "request_digest": _digest_json(request),
        "result_digest": _digest_json(result),
        "subject_manifest_digest": _digest_json(subject),
    }
    for field, expected in worker_bindings.items():
        if worker[field] != expected:
            raise BenchmarkError(
                f"{evidence_label}.worker.{field} is not bound to retained bytes"
            )

    receipt = _read_canonical_document(
        cas,
        worker["nonce_receipt_digest"],
        f"{evidence_label}.worker.nonce_receipt",
        max_bytes=64 * 1024,
    )
    _exact_keys(
        receipt,
        {
            "schema",
            "ledger_id",
            "dispatch_digest",
            "job_id",
            "nonce",
            "request_digest",
            "result_digest",
        },
        f"{evidence_label}.worker.nonce_receipt",
    )
    expected_receipt = {
        "schema": "aragorn/benchmark-worker-nonce-consumption/v1",
        "ledger_id": worker["ledger_id"],
        "dispatch_digest": worker["dispatch_digest"],
        "job_id": worker["job_id"],
        "nonce": worker["nonce"],
        "request_digest": worker["request_digest"],
        "result_digest": worker["result_digest"],
    }
    if receipt != expected_receipt:
        raise BenchmarkError(f"{evidence_label}.worker nonce receipt is unbound")

    dispatch = _read_canonical_document(
        cas,
        worker["dispatch_digest"],
        f"{evidence_label}.worker.dispatch",
        max_bytes=_MAX_SUITE_BYTES,
    )
    dispatch_entry = _verify_worker_dispatch(
        dispatch,
        job_id=worker["job_id"],
        suite_digest=outcome["suite_digest"],
        expected_matrix=expected_dispatch_matrix,
        label=f"{evidence_label}.worker.dispatch",
    )
    expected_dispatch_binding = {
        "request_digest": worker["request_digest"],
        "suite_digest": outcome["suite_digest"],
        "case_id": outcome["case_id"],
        "run_id": outcome["run_id"],
        "system": outcome["system"],
        "tree_digest": outcome["tree_digest"],
        "private_manifest_digest": _digest_json(expected_manifest),
    }
    for field, expected in expected_dispatch_binding.items():
        if dispatch_entry[field] != expected:
            raise BenchmarkError(f"{evidence_label}.worker.dispatch {field} is unbound")

    closure = _read_canonical_document(
        cas,
        worker["output_closure_digest"],
        f"{evidence_label}.worker.output_closure",
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    _verify_worker_output_closure(
        cas,
        closure,
        request=request,
        result=result,
        subject=subject,
        request_digest=worker["request_digest"],
        result_digest=worker["result_digest"],
        label=f"{evidence_label}.worker.output_closure",
    )

    nested_digest = _digest(
        envelope["nested_evidence_digest"],
        f"{evidence_label}.nested_evidence_digest",
    )
    nested = _read_canonical_document(
        cas,
        nested_digest,
        f"{evidence_label}.nested_evidence",
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    expected_nested = {
        "schema": "aragorn/benchmark-evidence/v3",
        "suite_digest": outcome["suite_digest"],
        "case_id": outcome["case_id"],
        "tree_digest": result["tree_digest"],
        "verified_subject_digest": result["verified_subject_digest"],
        "run_id": outcome["run_id"],
        "system": result["system"],
        "manifest_digest": _digest_json(expected_manifest),
        "baseline_lock_digest": result["baseline_lock_digest"],
        "baseline_entry_digest": result["baseline_entry_digest"],
        "effective_config_digest": result["effective_config_digest"],
        "oci_index_digest": result["oci_index_digest"],
        "oci_platform_manifest_digest": result["oci_platform_manifest_digest"],
        "build_provenance_manifest_digest": result["build_provenance_manifest_digest"],
        "index_inspect_digest": result["index_inspect_digest"],
        "platform_inspect_digest": result["platform_inspect_digest"],
        "image_config_digest": result["image_config_digest"],
        "runner_receipts": result["runner_receipts"],
        "prestart_container_inspect_digest": result[
            "prestart_container_inspect_digest"
        ],
        "postrun_container_inspect_digest": result["postrun_container_inspect_digest"],
        "stdout_digest": result["stdout_digest"],
        "stderr_digest": result["stderr_digest"],
        "observation_digests": result["observation_digests"],
        "execution": result["execution"],
        "normalization": result["normalization"],
        "verdict": result["verdict"],
        "reason_codes": result["reason_codes"],
    }
    if nested != expected_nested:
        raise BenchmarkError(
            f"{evidence_label}.nested_evidence is not derived from worker result"
        )
    _verify_oci_evidence_v2(
        cas,
        outcome,
        expected_manifest=expected_manifest,
        label=label,
        envelope=nested,
    )
    return {
        "ledger_id": worker["ledger_id"],
        "dispatch_digest": worker["dispatch_digest"],
        "job_id": worker["job_id"],
        "nonce": worker["nonce"],
        "request_digest": worker["request_digest"],
        "result_digest": worker["result_digest"],
    }


def _verify_worker_dispatch(
    dispatch: dict[str, Any],
    *,
    job_id: str,
    suite_digest: str,
    expected_matrix: dict[tuple[tuple[str, str, str, str], str, int], dict[str, Any]]
    | None,
    label: str,
) -> dict[str, Any]:
    _exact_keys(dispatch, {"schema", "jobs"}, label)
    if dispatch["schema"] != "aragorn/benchmark-private-dispatch/v1":
        raise BenchmarkError(f"{label}.schema is unsupported")
    jobs = dispatch["jobs"]
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= _MAX_OUTCOMES:
        raise BenchmarkError(f"{label}.jobs is not a bounded array")
    job_ids: set[str] = set()
    requests: set[str] = set()
    matrix: set[tuple[tuple[str, str, str, str], str, int]] = set()
    normalized_ids: list[str] = []
    matches: list[dict[str, Any]] = []
    for index, raw_entry in enumerate(jobs):
        entry_label = f"{label}.jobs[{index}]"
        if not isinstance(raw_entry, dict):
            raise BenchmarkError(f"{entry_label} must be an object")
        _exact_keys(
            raw_entry,
            {
                "job_id",
                "request_digest",
                "suite_digest",
                "case_id",
                "run_id",
                "system",
                "tree_digest",
                "private_manifest_digest",
            },
            entry_label,
        )
        entry_job_id = raw_entry["job_id"]
        if (
            not isinstance(entry_job_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", entry_job_id) is None
        ):
            raise BenchmarkError(f"{entry_label}.job_id is invalid")
        request_digest = _digest(
            raw_entry["request_digest"], f"{entry_label}.request_digest"
        )
        entry_suite_digest = _digest(
            raw_entry["suite_digest"], f"{entry_label}.suite_digest"
        )
        if entry_suite_digest != suite_digest:
            raise BenchmarkError(f"{entry_label}.suite_digest is not batch-wide")
        case_id = _identifier(raw_entry["case_id"], f"{entry_label}.case_id")
        run_id = raw_entry["run_id"]
        if (
            isinstance(run_id, bool)
            or not isinstance(run_id, int)
            or not 1 <= run_id <= 10
        ):
            raise BenchmarkError(f"{entry_label}.run_id is outside the bounded range")
        system = _validate_system(raw_entry["system"], entry_label)
        _digest(raw_entry["tree_digest"], f"{entry_label}.tree_digest")
        _digest(
            raw_entry["private_manifest_digest"],
            f"{entry_label}.private_manifest_digest",
        )
        matrix_key = (_system_key(system), case_id, run_id)
        if (
            entry_job_id in job_ids
            or request_digest in requests
            or matrix_key in matrix
        ):
            raise BenchmarkError(f"{label}.jobs contains a duplicate binding")
        job_ids.add(entry_job_id)
        requests.add(request_digest)
        matrix.add(matrix_key)
        if expected_matrix is not None:
            expected = expected_matrix.get(matrix_key)
            if expected is None:
                raise BenchmarkError(f"{entry_label} is outside the suite matrix")
            for field in (
                "suite_digest",
                "case_id",
                "run_id",
                "system",
                "tree_digest",
                "private_manifest_digest",
            ):
                if raw_entry[field] != expected[field]:
                    raise BenchmarkError(
                        f"{entry_label}.{field} does not match the suite matrix"
                    )
        normalized_ids.append(entry_job_id)
        if entry_job_id == job_id:
            matches.append(raw_entry)
    if normalized_ids != sorted(normalized_ids):
        raise BenchmarkError(f"{label}.jobs is not sorted by job_id")
    if expected_matrix is not None and matrix != set(expected_matrix):
        raise BenchmarkError(f"{label}.jobs does not cover the exact suite matrix")
    if len(matches) != 1:
        raise BenchmarkError(f"{label} does not select exactly one worker job")
    return matches[0]


def _verify_worker_output_closure(
    cas: CAS,
    closure: dict[str, Any],
    *,
    request: dict[str, Any],
    result: dict[str, Any],
    subject: dict[str, Any],
    request_digest: str,
    result_digest: str,
    label: str,
) -> None:
    _exact_keys(
        closure,
        {"schema", "job_id", "request_digest", "result_digest", "blobs", "total_bytes"},
        label,
    )
    if closure["schema"] != "aragorn/benchmark-worker-output-closure/v1":
        raise BenchmarkError(f"{label}.schema is unsupported")
    if closure["job_id"] != request["job_id"]:
        raise BenchmarkError(f"{label}.job_id is unbound")
    if closure["request_digest"] != request_digest:
        raise BenchmarkError(f"{label}.request_digest is unbound")
    if closure["result_digest"] != result_digest:
        raise BenchmarkError(f"{label}.result_digest is unbound")
    blobs = closure["blobs"]
    if not isinstance(blobs, list) or not 1 <= len(blobs) <= _MAX_WORKER_OUTPUT_BLOBS:
        raise BenchmarkError(f"{label}.blobs is not a bounded array")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for index, raw_entry in enumerate(blobs):
        entry_label = f"{label}.blobs[{index}]"
        if not isinstance(raw_entry, dict):
            raise BenchmarkError(f"{entry_label} must be an object")
        _exact_keys(raw_entry, {"digest", "size"}, entry_label)
        digest = _digest(raw_entry["digest"], f"{entry_label}.digest")
        size = raw_entry["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 0 <= size <= _MAX_EXECUTABLE_BYTES
        ):
            raise BenchmarkError(f"{entry_label}.size is outside the bounded range")
        if digest in seen:
            raise BenchmarkError(f"{label}.blobs repeats a digest")
        seen.add(digest)
        content = cas.read(digest, max_bytes=size)
        if len(content) != size:
            raise BenchmarkError(f"{entry_label}.size does not match retained bytes")
        total += size
        if total > _MAX_WORKER_OUTPUT_TOTAL_BYTES:
            raise BenchmarkError(f"{label} exceeds the total byte limit")
        normalized.append({"digest": digest, "size": size})
    if normalized != sorted(normalized, key=lambda item: item["digest"]):
        raise BenchmarkError(f"{label}.blobs must be sorted by digest")
    if closure["total_bytes"] != total:
        raise BenchmarkError(f"{label}.total_bytes is inconsistent")

    expected = {
        request_digest,
        result_digest,
        result["subject_manifest_digest"],
        *(entry["digest"] for entry in subject["files"]),
        result["baseline_lock_digest"],
        result["baseline_entry_digest"],
        result["effective_config_digest"],
        result["oci_index_digest"],
        result["oci_platform_manifest_digest"],
        result["build_provenance_manifest_digest"],
        result["index_inspect_digest"],
        result["platform_inspect_digest"],
        result["image_config_digest"],
        result["prestart_container_inspect_digest"],
        result["postrun_container_inspect_digest"],
        result["stdout_digest"],
        result["stderr_digest"],
        *result["observation_digests"],
    }
    for receipt in result["runner_receipts"].values():
        expected.update(receipt.values())
    effective = _read_canonical_document(
        cas,
        result["effective_config_digest"],
        f"{label}.effective_config",
        max_bytes=_MAX_INPUT_BYTES,
    )
    docker_digest = _digest(
        effective.get("docker_executable_digest"),
        f"{label}.effective_config.docker_executable_digest",
    )
    expected.add(docker_digest)
    if seen != expected:
        raise BenchmarkError(f"{label}.blobs is not the exact worker output closure")


def _verify_oci_evidence_v2(
    cas: CAS,
    outcome: dict[str, Any],
    *,
    expected_manifest: dict[str, Any],
    label: str,
    envelope: dict[str, Any],
) -> None:
    evidence_label = f"{label}.evidence"
    evidence_schema = envelope.get("schema")
    evidence_keys = {
        "schema",
        "suite_digest",
        "case_id",
        "tree_digest",
        "verified_subject_digest",
        "run_id",
        "system",
        "manifest_digest",
        "baseline_lock_digest",
        "baseline_entry_digest",
        "effective_config_digest",
        "oci_index_digest",
        "oci_platform_manifest_digest",
        "build_provenance_manifest_digest",
        "index_inspect_digest",
        "platform_inspect_digest",
        "image_config_digest",
        "prestart_container_inspect_digest",
        "postrun_container_inspect_digest",
        "stdout_digest",
        "stderr_digest",
        "observation_digests",
        "execution",
        "normalization",
        "verdict",
        "reason_codes",
    }
    if evidence_schema == "aragorn/benchmark-evidence/v3":
        evidence_keys.add("runner_receipts")
    elif evidence_schema != "aragorn/benchmark-evidence/v2":
        raise BenchmarkError(f"{evidence_label} has an unsupported schema")
    _exact_keys(
        envelope,
        evidence_keys,
        evidence_label,
    )
    for field in (
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "verdict",
        "reason_codes",
    ):
        if envelope[field] != outcome[field]:
            raise BenchmarkError(f"{evidence_label}.{field} does not match outcome")
    evidence_system = _validate_system(envelope["system"], evidence_label)
    if evidence_system != outcome["system"]:
        raise BenchmarkError(f"{evidence_label}.system does not match outcome")
    if (
        _digest(
            envelope["verified_subject_digest"],
            f"{evidence_label}.verified_subject_digest",
        )
        != outcome["tree_digest"]
    ):
        raise BenchmarkError(f"{evidence_label} verified subject is unbound")

    manifest_digest = _digest(
        envelope["manifest_digest"], f"{evidence_label}.manifest_digest"
    )
    if manifest_digest != _digest_json(expected_manifest):
        raise BenchmarkError(f"{evidence_label} manifest does not match the suite case")
    if (
        _read_canonical_document(
            cas,
            manifest_digest,
            f"{evidence_label}.manifest",
            max_bytes=_MAX_EVIDENCE_BYTES,
        )
        != expected_manifest
    ):
        raise BenchmarkError(f"{evidence_label} manifest bytes do not match the suite")

    lock_digest = _digest(
        envelope["baseline_lock_digest"],
        f"{evidence_label}.baseline_lock_digest",
    )
    raw_lock = cas.read(lock_digest, max_bytes=_MAX_INPUT_BYTES)
    lock = _decode_json(raw_lock, f"{evidence_label}.baseline_lock")
    _finite_json(lock, f"{evidence_label}.baseline_lock")
    selected = _select_oci_baseline(lock, outcome["system"], evidence_label)

    entry_digest = _digest(
        envelope["baseline_entry_digest"],
        f"{evidence_label}.baseline_entry_digest",
    )
    if entry_digest != _digest_json(selected):
        raise BenchmarkError(f"{evidence_label} selected baseline digest is unbound")
    retained_entry = _read_canonical_document(
        cas,
        entry_digest,
        f"{evidence_label}.baseline_entry",
        max_bytes=_MAX_INPUT_BYTES,
    )
    if retained_entry != selected:
        raise BenchmarkError(f"{evidence_label} selected baseline bytes do not match")

    effective_digest = _digest(
        envelope["effective_config_digest"],
        f"{evidence_label}.effective_config_digest",
    )
    if effective_digest != outcome["system"]["config_digest"]:
        raise BenchmarkError(f"{evidence_label} effective config identity is unbound")
    effective = _read_canonical_document(
        cas,
        effective_digest,
        f"{evidence_label}.effective_config",
        max_bytes=_MAX_INPUT_BYTES,
    )
    baseline_spec = _validate_oci_effective_config(
        effective,
        selected,
        lock_digest=lock_digest,
        entry_digest=entry_digest,
        system=outcome["system"],
        evidence_schema=evidence_schema,
        label=evidence_label,
    )
    cas.verify(
        effective["docker_executable_digest"],
        max_bytes=_MAX_EXECUTABLE_BYTES,
    )
    if evidence_schema == "aragorn/benchmark-evidence/v3":
        _verify_runner_receipts(
            cas,
            envelope["runner_receipts"],
            expected_identity=effective["runner_identity"],
            label=evidence_label,
        )

    execution = _validate_oci_execution(envelope["execution"], evidence_label)
    image = selected["image"]
    oci_index_digest = _digest(
        envelope["oci_index_digest"],
        f"{evidence_label}.oci_index_digest",
    )
    oci_platform_digest = _digest(
        envelope["oci_platform_manifest_digest"],
        f"{evidence_label}.oci_platform_manifest_digest",
    )
    provenance_digest = _digest(
        envelope["build_provenance_manifest_digest"],
        f"{evidence_label}.build_provenance_manifest_digest",
    )
    if (
        oci_index_digest != image["index_digest"]
        or oci_platform_digest != image["platform_manifest_digest"]
        or provenance_digest != image["build_provenance_manifest_digest"]
    ):
        raise BenchmarkError(f"{evidence_label} OCI metadata identity is unbound")
    raw_oci_index = cas.read(
        oci_index_digest,
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    raw_oci_platform = cas.read(
        oci_platform_digest,
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    raw_provenance = cas.read(
        provenance_digest,
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    raw_index = cas.read(
        _digest(
            envelope["index_inspect_digest"],
            f"{evidence_label}.index_inspect_digest",
        ),
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    raw_platform = cas.read(
        _digest(
            envelope["platform_inspect_digest"],
            f"{evidence_label}.platform_inspect_digest",
        ),
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    image_config_digest = _digest(
        envelope["image_config_digest"],
        f"{evidence_label}.image_config_digest",
    )
    if image_config_digest != selected["image"]["config_digest"]:
        raise BenchmarkError(f"{evidence_label} OCI image config digest is unbound")
    raw_image_config = cas.read(
        image_config_digest,
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    _verify_oci_metadata_graph(
        raw_oci_index,
        raw_oci_platform,
        raw_provenance,
        raw_image_config,
        selected=selected,
        label=evidence_label,
    )
    raw_prestart_container = cas.read(
        _digest(
            envelope["prestart_container_inspect_digest"],
            f"{evidence_label}.prestart_container_inspect_digest",
        ),
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    raw_postrun_container = cas.read(
        _digest(
            envelope["postrun_container_inspect_digest"],
            f"{evidence_label}.postrun_container_inspect_digest",
        ),
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    image_environment = _verify_oci_image_config(
        raw_image_config,
        selected=selected,
        baseline_spec=baseline_spec,
        label=evidence_label,
    )
    inspected_environment = _verify_oci_image_inspects(
        raw_index,
        raw_platform,
        selected=selected,
        effective=effective,
        baseline_spec=baseline_spec,
        label=evidence_label,
    )
    if inspected_environment != image_environment:
        raise BenchmarkError(f"{evidence_label} image config evidence is inconsistent")
    try:
        verify_effective_environment_v2(
            image_environment,
            selected["profile"]["environment"],
            effective["environment"],
        )
    except WorkerProtocolError as exc:
        raise BenchmarkError(
            f"{evidence_label} effective environment is unbound: {exc}"
        ) from exc
    _verify_oci_container_inspect(
        raw_prestart_container,
        selected=selected,
        effective=effective,
        execution=execution,
        phase="prestart",
        label=evidence_label,
    )
    _verify_oci_container_inspect(
        raw_postrun_container,
        selected=selected,
        effective=effective,
        execution=execution,
        phase="postrun",
        label=evidence_label,
    )

    stdout = cas.read(
        _digest(envelope["stdout_digest"], f"{evidence_label}.stdout_digest"),
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    stderr = cas.read(
        _digest(envelope["stderr_digest"], f"{evidence_label}.stderr_digest"),
        max_bytes=_MAX_EVIDENCE_BYTES,
    )
    raw_observation_digests = envelope["observation_digests"]
    if (
        not isinstance(raw_observation_digests, list)
        or len(raw_observation_digests) > 10_000
    ):
        raise BenchmarkError(f"{evidence_label} observation list is invalid")
    observation_digests = [
        _digest(value, f"{evidence_label}.observation_digests")
        for value in raw_observation_digests
    ]

    normalization = envelope["normalization"]
    if normalization != effective["normalization"]:
        raise BenchmarkError(f"{evidence_label} normalization is unbound")
    if execution["status"] == "error":
        if observation_digests:
            raise BenchmarkError(f"{evidence_label} failed execution has observations")
        _verify_oci_execution_error(
            selected["name"],
            execution["error_code"],
            execution["returncode"],
            stdout=stdout,
            stderr=stderr,
            output_limit=effective["limits"]["output_bytes"],
            subject_digest=outcome["tree_digest"],
            label=evidence_label,
        )
        expected_verdict = "ERROR"
        expected_reasons = (f"ANALYZER_{execution['error_code']}",)
    else:
        try:
            observations = _normalize_pinned_vendor_report(
                selected["name"],
                stdout,
                subject_digest=outcome["tree_digest"],
                returncode=execution["returncode"],
            )
        except VendorReportError as exc:
            raise BenchmarkError(
                f"{evidence_label} successful vendor report is malformed"
            ) from exc
        if execution["status"] != "ok" or execution["error_code"] is not None:
            raise BenchmarkError(
                f"{evidence_label} valid vendor report is declared as an error"
            )
        observation_bytes = [
            observation.document_json.encode("ascii") for observation in observations
        ]
        expected_digests = [_digest_bytes(content) for content in observation_bytes]
        if observation_digests != expected_digests:
            raise BenchmarkError(
                f"{evidence_label} observations do not match vendor stdout"
            )
        for digest, content in zip(observation_digests, observation_bytes):
            if cas.read(digest, max_bytes=_MAX_EVIDENCE_BYTES) != content:
                raise BenchmarkError(
                    f"{evidence_label} canonical observation bytes do not match"
                )
        expected_verdict, expected_reasons = normalize_vendor_observations(
            selected["name"],
            observations,
            normalization=normalization,
        )

    if outcome["verdict"] != expected_verdict or outcome["reason_codes"] != list(
        expected_reasons
    ):
        raise BenchmarkError(f"{evidence_label} does not derive the declared outcome")


def _normalize_pinned_vendor_report(
    baseline_name: str,
    raw_report: bytes,
    *,
    subject_digest: str,
    returncode: int,
) -> tuple[Any, ...]:
    if baseline_name == "cisco-skill-scanner":
        return normalize_cisco_report(
            raw_report,
            subject_digest=subject_digest,
            returncode=returncode,
        )
    if baseline_name == "skillspector":
        return normalize_nvidia_report(
            raw_report,
            subject_digest=subject_digest,
            returncode=returncode,
        )
    raise BenchmarkError("OCI evidence names an unsupported baseline")


def normalize_vendor_observations(
    baseline_name: str,
    observations: tuple[Any, ...],
    *,
    normalization: str | None = None,
) -> tuple[str, tuple[str, ...]]:
    """Derive an outcome under an explicitly versioned vendor policy."""

    spec = _OCI_BASELINES[baseline_name]
    legacy_normalization = spec["normalization"]
    actionable_normalization = {
        "cisco-skill-scanner": "cisco-ai-skill-scanner-2.0.12/v2",
        "skillspector": "nvidia-skillspector-2.4.3/v2",
    }[baseline_name]
    selected_normalization = (
        legacy_normalization if normalization is None else normalization
    )
    if selected_normalization not in {
        legacy_normalization,
        actionable_normalization,
    }:
        raise BenchmarkError("vendor outcome normalization is unsupported")
    completion_reason = spec["completion_reason"]
    completion = [
        observation
        for observation in observations
        if observation.reason_code == completion_reason
    ]
    if len(completion) != 1 or completion[0].severity != "info":
        raise BenchmarkError("vendor completion observation is missing or malformed")
    findings = [
        observation
        for observation in observations
        if observation.reason_code != completion_reason
        and (
            selected_normalization == legacy_normalization
            or _SEVERITY_RANK[observation.severity] >= _SEVERITY_RANK["medium"]
        )
    ]
    if not findings:
        return "ALLOW", ()
    reasons = tuple(sorted({observation.reason_code for observation in findings}))
    maximum = max(_SEVERITY_RANK[observation.severity] for observation in findings)
    return ("DENY" if maximum >= _SEVERITY_RANK["high"] else "REVIEW"), reasons


def _verify_oci_execution_error(
    baseline_name: str,
    error_code: str | None,
    returncode: int,
    *,
    stdout: bytes,
    stderr: bytes,
    output_limit: int,
    subject_digest: str,
    label: str,
) -> None:
    if error_code == "OUTPUT_LIMIT_EXCEEDED":
        if len(stdout) + len(stderr) != output_limit:
            raise BenchmarkError(f"{label} output limit is inconsistent")
        return
    if error_code == "TIMEOUT":
        if returncode == 0:
            raise BenchmarkError(f"{label} timeout has a successful container exit")
        return
    valid_exit = (baseline_name == "cisco-skill-scanner" and returncode == 0) or (
        baseline_name == "skillspector" and returncode in {0, 1}
    )
    if error_code == "NONZERO_OR_INVALID_VENDOR_EXIT":
        if valid_exit:
            raise BenchmarkError(f"{label} invalid vendor exit is inconsistent")
    elif error_code == "MALFORMED_VENDOR_REPORT":
        if not valid_exit:
            raise BenchmarkError(f"{label} malformed report has an invalid vendor exit")
    else:
        raise BenchmarkError(f"{label} execution error is not re-verifiable")
    try:
        _normalize_pinned_vendor_report(
            baseline_name,
            stdout,
            subject_digest=subject_digest,
            returncode=returncode,
        )
    except VendorReportError:
        return
    raise BenchmarkError(f"{label} declared execution error has a valid vendor report")


def _select_oci_baseline(
    document: object, system: dict[str, str], label: str
) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise BenchmarkError(f"{label}.baseline_lock must be a JSON object")
    _exact_keys(
        document,
        {"schema", "observed_at", "baselines"},
        f"{label}.baseline_lock",
    )
    if document["schema"] != "aragorn/baseline-lock/v1":
        raise BenchmarkError(f"{label}.baseline_lock schema is unsupported")
    if (
        not isinstance(document["observed_at"], str)
        or _DATE.fullmatch(document["observed_at"]) is None
    ):
        raise BenchmarkError(f"{label}.baseline_lock observed_at is invalid")
    baselines = document["baselines"]
    if not isinstance(baselines, list) or len(baselines) != len(_OCI_BASELINES):
        raise BenchmarkError(
            f"{label}.baseline_lock must contain exactly the pinned baselines"
        )
    selected: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, candidate in enumerate(baselines):
        if not isinstance(candidate, dict):
            raise BenchmarkError(
                f"{label}.baseline_lock.baselines[{index}] must be an object"
            )
        name = _identifier(
            candidate.get("name"),
            f"{label}.baseline_lock.baselines[{index}].name",
        )
        if name in names:
            raise BenchmarkError(f"{label}.baseline_lock has duplicate baseline names")
        names.add(name)
        if name not in _OCI_BASELINES:
            raise BenchmarkError(f"{label}.baseline_lock has an unsupported baseline")
        image = candidate.get("image")
        if not isinstance(image, dict):
            raise BenchmarkError(
                f"{label}.baseline_lock.baselines[{index}].image must be an object"
            )
        _validate_oci_baseline_entry(
            candidate,
            {
                "name": name,
                "version": _OCI_BASELINES[name]["version"],
                "implementation_digest": image.get("platform_manifest_digest"),
            },
            label,
        )
        if name == system["name"]:
            selected.append(candidate)
    if names != set(_OCI_BASELINES):
        raise BenchmarkError(f"{label}.baseline_lock omits a pinned baseline")
    if len(selected) != 1:
        raise BenchmarkError(f"{label}.baseline_lock does not select one system")
    if (
        selected[0]["version"] != system["version"]
        or selected[0]["image"]["platform_manifest_digest"]
        != system["implementation_digest"]
    ):
        raise BenchmarkError(f"{label}.baseline_lock selected system is unbound")
    return selected[0]


def _validate_oci_baseline_entry(
    entry: dict[str, Any], system: dict[str, str], label: str
) -> None:
    entry_label = f"{label}.baseline_entry"
    _exact_keys(
        entry,
        {
            "name",
            "version",
            "repository",
            "commit",
            "release",
            "license",
            "distribution",
            "profile",
            "build",
            "image",
            "runtime_profile",
            "attestation_status",
        },
        entry_label,
    )
    name = _identifier(entry["name"], f"{entry_label}.name")
    if name not in _OCI_BASELINES:
        raise BenchmarkError(f"{entry_label} names an unsupported pinned baseline")
    spec = _OCI_BASELINES[name]
    for field in ("version", "repository", "commit", "release"):
        if entry[field] != spec[field]:
            raise BenchmarkError(f"{entry_label}.{field} is not pinned")
    if entry["license"] != "Apache-2.0":
        raise BenchmarkError(f"{entry_label}.license is unsupported")
    if entry["distribution"] != spec["distribution"]:
        raise BenchmarkError(f"{entry_label}.distribution is not pinned")
    if entry["attestation_status"] != (
        "oci_closure_candidate_runner_attestation_pending"
    ):
        raise BenchmarkError(f"{entry_label}.attestation_status is unsupported")

    profile = entry["profile"]
    expected_profile = {
        "mode": "local-static",
        "network": "deny",
        "arguments": spec["arguments"],
        "environment": spec["profile_environment"],
        "disabled_features": spec["disabled_features"],
    }
    if profile != expected_profile:
        raise BenchmarkError(f"{entry_label}.profile is not the pinned safe profile")

    build = entry["build"]
    if not isinstance(build, dict):
        raise BenchmarkError(f"{entry_label}.build must be an object")
    _exact_keys(
        build,
        {
            "dockerfile_sha256",
            "build_input_sha256",
            "dependency_lock_sha256",
            "frontend_digest",
            "python_image_digest",
            "uv_image_digest",
            "artifacts",
        },
        f"{entry_label}.build",
    )
    for field in (
        "dockerfile_sha256",
        "build_input_sha256",
        "dependency_lock_sha256",
    ):
        _hex_digest(build[field], f"{entry_label}.build.{field}")
    for field in ("frontend_digest", "python_image_digest", "uv_image_digest"):
        _digest(build[field], f"{entry_label}.build.{field}")
    artifacts = build["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 32:
        raise BenchmarkError(f"{entry_label}.build.artifacts is invalid")
    artifact_names: set[str] = set()
    for index, artifact in enumerate(artifacts):
        artifact_label = f"{entry_label}.build.artifacts[{index}]"
        if not isinstance(artifact, dict):
            raise BenchmarkError(f"{artifact_label} must be an object")
        _exact_keys(artifact, {"name", "sha256"}, artifact_label)
        artifact_name = _identifier(artifact["name"], f"{artifact_label}.name")
        if artifact_name in artifact_names:
            raise BenchmarkError(f"{entry_label}.build has duplicate artifacts")
        artifact_names.add(artifact_name)
        _hex_digest(artifact["sha256"], f"{artifact_label}.sha256")

    image = entry["image"]
    if not isinstance(image, dict):
        raise BenchmarkError(f"{entry_label}.image must be an object")
    _exact_keys(
        image,
        {
            "local_tag",
            "index_digest",
            "platform_manifest_digest",
            "config_digest",
            "build_provenance_manifest_digest",
            "os",
            "architecture",
            "size_bytes",
        },
        f"{entry_label}.image",
    )
    _canonical_string(image["local_tag"], f"{entry_label}.image.local_tag", 1024)
    if "@" in image["local_tag"]:
        raise BenchmarkError(f"{entry_label}.image.local_tag is invalid")
    for field in (
        "index_digest",
        "platform_manifest_digest",
        "config_digest",
        "build_provenance_manifest_digest",
    ):
        _digest(image[field], f"{entry_label}.image.{field}")
    if image["os"] != "linux" or image["architecture"] not in {"arm64", "amd64"}:
        raise BenchmarkError(f"{entry_label}.image platform is unsupported")
    _positive_integer(image["size_bytes"], f"{entry_label}.image.size_bytes")

    _validate_oci_runtime_profile(
        entry["runtime_profile"],
        f"{entry_label}.runtime_profile",
    )
    if (
        name != system["name"]
        or entry["version"] != system["version"]
        or image["platform_manifest_digest"] != system["implementation_digest"]
    ):
        raise BenchmarkError(f"{entry_label} does not match the exact system identity")


def _validate_oci_effective_config(
    document: dict[str, Any],
    selected: dict[str, Any],
    *,
    lock_digest: str,
    entry_digest: str,
    system: dict[str, str],
    evidence_schema: str,
    label: str,
) -> dict[str, Any]:
    config_label = f"{label}.effective_config"
    config_keys = {
        "schema",
        "name",
        "version",
        "baseline_lock_digest",
        "baseline_entry_digest",
        "docker_executable_digest",
        "image",
        "entrypoint",
        "arguments",
        "environment",
        "runtime_profile",
        "limits",
        "normalization",
    }
    if evidence_schema == "aragorn/benchmark-evidence/v3":
        expected_schema = "aragorn/benchmark-oci-system-config/v2"
        config_keys.add("runner_identity")
    elif evidence_schema == "aragorn/benchmark-evidence/v2":
        expected_schema = "aragorn/benchmark-oci-system-config/v1"
    else:
        raise BenchmarkError(f"{config_label} evidence schema is unsupported")
    _exact_keys(
        document,
        config_keys,
        config_label,
    )
    if document["schema"] != expected_schema:
        raise BenchmarkError(f"{config_label} schema is unsupported")
    if evidence_schema == "aragorn/benchmark-evidence/v3":
        _validate_normalized_runner_identity(
            document["runner_identity"],
            f"{config_label}.runner_identity",
        )
    spec = _OCI_BASELINES[selected["name"]]
    if (
        document["name"] != selected["name"]
        or document["version"] != selected["version"]
    ):
        raise BenchmarkError(f"{config_label} baseline identity is unbound")
    if (
        document["baseline_lock_digest"] != lock_digest
        or document["baseline_entry_digest"] != entry_digest
    ):
        raise BenchmarkError(f"{config_label} baseline lock identity is unbound")
    _digest(
        document["docker_executable_digest"],
        f"{config_label}.docker_executable_digest",
    )

    image = document["image"]
    if not isinstance(image, dict):
        raise BenchmarkError(f"{config_label}.image must be an object")
    _exact_keys(
        image,
        {
            "reference",
            "index_digest",
            "platform_manifest_digest",
            "config_digest",
            "os",
            "architecture",
            "size_bytes",
        },
        f"{config_label}.image",
    )
    locked_image = selected["image"]
    expected_image = {
        "reference": _oci_digest_reference(
            locked_image["local_tag"], locked_image["index_digest"]
        ),
        "index_digest": locked_image["index_digest"],
        "platform_manifest_digest": locked_image["platform_manifest_digest"],
        "config_digest": locked_image["config_digest"],
        "os": locked_image["os"],
        "architecture": locked_image["architecture"],
        "size_bytes": locked_image["size_bytes"],
    }
    if image != expected_image:
        raise BenchmarkError(f"{config_label}.image is not the selected locked image")
    if image["platform_manifest_digest"] != system["implementation_digest"]:
        raise BenchmarkError(f"{config_label} implementation identity is unbound")

    if document["entrypoint"] != spec["entrypoint"]:
        raise BenchmarkError(f"{config_label}.entrypoint is not pinned")
    expected_arguments = [
        "/workspace" if argument == "{workspace}" else argument
        for argument in spec["arguments"]
    ]
    if document["arguments"] != expected_arguments:
        raise BenchmarkError(f"{config_label}.arguments are not lock-derived")
    _validate_environment(document["environment"], f"{config_label}.environment")
    for key, value in spec["profile_environment"].items():
        if document["environment"].get(key) != value:
            raise BenchmarkError(f"{config_label}.environment omits a profile value")
    if document["runtime_profile"] != selected["runtime_profile"]:
        raise BenchmarkError(f"{config_label}.runtime_profile is not lock-derived")
    _validate_oci_runtime_profile(
        document["runtime_profile"], f"{config_label}.runtime_profile"
    )

    limits = document["limits"]
    if not isinstance(limits, dict):
        raise BenchmarkError(f"{config_label}.limits must be an object")
    _exact_keys(
        limits,
        {"timeout_seconds", "output_bytes"},
        f"{config_label}.limits",
    )
    timeout = limits["timeout_seconds"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 0 < timeout <= 3600
    ):
        raise BenchmarkError(f"{config_label}.limits.timeout_seconds is invalid")
    output_bytes = limits["output_bytes"]
    if (
        isinstance(output_bytes, bool)
        or not isinstance(output_bytes, int)
        or not 1 <= output_bytes <= _MAX_EVIDENCE_BYTES
    ):
        raise BenchmarkError(f"{config_label}.limits.output_bytes is invalid")
    supported_normalizations = {spec["normalization"]}
    if evidence_schema == "aragorn/benchmark-evidence/v3":
        supported_normalizations.add(
            {
                "cisco-skill-scanner": "cisco-ai-skill-scanner-2.0.12/v2",
                "skillspector": "nvidia-skillspector-2.4.3/v2",
            }[selected["name"]]
        )
    if document["normalization"] not in supported_normalizations:
        raise BenchmarkError(f"{config_label}.normalization is not pinned")
    return spec


def _verify_runner_receipts(
    cas: CAS,
    value: object,
    *,
    expected_identity: object,
    label: str,
) -> None:
    receipts_label = f"{label}.runner_receipts"
    if not isinstance(value, dict):
        raise BenchmarkError(f"{receipts_label} must be an object")
    _exact_keys(value, {"pre", "post"}, receipts_label)
    identities: dict[str, dict[str, Any]] = {}
    for phase in ("pre", "post"):
        receipt_label = f"{receipts_label}.{phase}"
        receipt = value[phase]
        if not isinstance(receipt, dict):
            raise BenchmarkError(f"{receipt_label} must be an object")
        _exact_keys(
            receipt,
            {
                "context_inspect_digest",
                "daemon_version_digest",
                "daemon_info_digest",
            },
            receipt_label,
        )
        documents = []
        for field in (
            "context_inspect_digest",
            "daemon_version_digest",
            "daemon_info_digest",
        ):
            raw = cas.read(
                _digest(receipt[field], f"{receipt_label}.{field}"),
                max_bytes=_MAX_RUNNER_RECEIPT_BYTES,
            )
            document = _decode_json(raw, f"{receipt_label}.{field}")
            _finite_json(document, f"{receipt_label}.{field}")
            if not isinstance(document, dict):
                raise BenchmarkError(f"{receipt_label}.{field} must contain an object")
            documents.append(document)
        identities[phase] = _normalize_runner_receipt(
            documents[0],
            documents[1],
            documents[2],
            receipt_label,
        )
    if identities["pre"] != identities["post"]:
        raise BenchmarkError(f"{receipts_label} runner identity changed")
    if identities["pre"] != expected_identity:
        raise BenchmarkError(f"{receipts_label} runner identity is unbound")


def _normalize_runner_receipt(
    context: dict[str, Any],
    version: dict[str, Any],
    info: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    context_label = f"{label}.context"
    _exact_keys(context, {"Name", "DockerEndpoint"}, context_label)
    endpoint = context["DockerEndpoint"]
    if not isinstance(endpoint, dict):
        raise BenchmarkError(f"{context_label}.DockerEndpoint must be an object")
    _exact_keys(
        endpoint,
        {"Host", "SkipTLSVerify", "TLSMaterialCount"},
        f"{context_label}.DockerEndpoint",
    )
    if endpoint["SkipTLSVerify"] is not False:
        raise BenchmarkError(f"{context_label} TLS verification bypass is unsupported")
    tls_material_count = endpoint["TLSMaterialCount"]
    if (
        isinstance(tls_material_count, bool)
        or not isinstance(tls_material_count, int)
        or tls_material_count != 0
    ):
        raise BenchmarkError(f"{context_label} TLS material is unsupported")
    normalized_context = {
        "name": _runner_string(context["Name"], f"{context_label}.Name"),
        "endpoint": _canonical_unix_endpoint(
            endpoint["Host"], f"{context_label}.DockerEndpoint.Host"
        ),
        "skip_tls_verify": False,
        "tls_material_count": 0,
    }

    version_label = f"{label}.version"
    _exact_keys(
        version,
        {
            "PlatformName",
            "Version",
            "APIVersion",
            "MinAPIVersion",
            "GitCommit",
            "GoVersion",
            "Os",
            "Arch",
            "KernelVersion",
            "BuildTime",
            "Components",
        },
        version_label,
    )
    raw_components = version["Components"]
    if not isinstance(raw_components, list) or not 3 <= len(raw_components) <= 32:
        raise BenchmarkError(f"{version_label}.Components is invalid")
    components: list[dict[str, str]] = []
    component_names: set[str] = set()
    component_collision_keys: set[str] = set()
    for index, component in enumerate(raw_components):
        component_label = f"{version_label}.Components[{index}]"
        if not isinstance(component, dict):
            raise BenchmarkError(f"{component_label} must be an object")
        _exact_keys(component, {"Name", "Version", "Details"}, component_label)
        name = _runner_string(component["Name"], f"{component_label}.Name")
        component_version = _runner_string(
            component["Version"], f"{component_label}.Version"
        )
        details = component["Details"]
        if not isinstance(details, dict) or len(details) > 64:
            raise BenchmarkError(f"{component_label}.Details must be a bounded object")
        if "GitCommit" in details:
            git_commit = _runner_string(
                details["GitCommit"],
                f"{component_label}.Details.GitCommit",
            )
        elif name in _REQUIRED_DOCKER_COMPONENTS:
            raise BenchmarkError(
                f"{component_label}.Details.GitCommit must be a non-empty string"
            )
        else:
            git_commit = _unreported_component_details_identity(
                details,
                component_label,
            )
        collision_key = name.casefold()
        if collision_key in component_collision_keys:
            raise BenchmarkError(f"{version_label}.Components contains duplicate names")
        component_names.add(name)
        component_collision_keys.add(collision_key)
        components.append(
            {"name": name, "version": component_version, "git_commit": git_commit}
        )
    if not _REQUIRED_DOCKER_COMPONENTS.issubset(component_names):
        raise BenchmarkError(f"{version_label}.Components omits a required component")
    components.sort(key=lambda component: component["name"])
    normalized_engine = {
        "platform_name": _runner_string(
            version["PlatformName"], f"{version_label}.PlatformName"
        ),
        "version": _runner_string(version["Version"], f"{version_label}.Version"),
        "api_version": _runner_string(
            version["APIVersion"], f"{version_label}.APIVersion"
        ),
        "minimum_api_version": _runner_string(
            version["MinAPIVersion"], f"{version_label}.MinAPIVersion"
        ),
        "git_commit": _runner_string(
            version["GitCommit"], f"{version_label}.GitCommit"
        ),
        "go_version": _runner_string(
            version["GoVersion"], f"{version_label}.GoVersion"
        ),
        "os": _runner_linux(version["Os"], f"{version_label}.Os"),
        "architecture": _normalize_runner_arch(
            version["Arch"], f"{version_label}.Arch"
        ),
        "kernel_version": _runner_string(
            version["KernelVersion"], f"{version_label}.KernelVersion"
        ),
        "build_time": _runner_string(
            version["BuildTime"], f"{version_label}.BuildTime"
        ),
        "components": components,
    }
    engine_component = next(
        component for component in components if component["name"] == "Engine"
    )
    if (
        engine_component["version"] != normalized_engine["version"]
        or engine_component["git_commit"] != normalized_engine["git_commit"]
    ):
        raise BenchmarkError(f"{version_label}.Components Engine is inconsistent")

    info_label = f"{label}.info"
    _exact_keys(
        info,
        {
            "ID",
            "Name",
            "ServerVersion",
            "OperatingSystem",
            "OSType",
            "Architecture",
            "KernelVersion",
            "SecurityOptions",
            "CgroupVersion",
            "DefaultRuntime",
            "Driver",
        },
        info_label,
    )
    raw_security_options = info["SecurityOptions"]
    if not isinstance(raw_security_options, list) or len(raw_security_options) > 64:
        raise BenchmarkError(f"{info_label}.SecurityOptions is invalid")
    security_options = [
        _runner_string(option, f"{info_label}.SecurityOptions")
        for option in raw_security_options
    ]
    if len(security_options) != len(set(security_options)):
        raise BenchmarkError(f"{info_label}.SecurityOptions contains duplicates")
    security_options.sort()
    normalized_worker = {
        "daemon_id": _runner_string(info["ID"], f"{info_label}.ID"),
        "daemon_name": _runner_string(info["Name"], f"{info_label}.Name"),
        "server_version": _runner_string(
            info["ServerVersion"], f"{info_label}.ServerVersion"
        ),
        "operating_system": _runner_string(
            info["OperatingSystem"], f"{info_label}.OperatingSystem"
        ),
        "os": _runner_linux(info["OSType"], f"{info_label}.OSType"),
        "architecture": _normalize_runner_arch(
            info["Architecture"], f"{info_label}.Architecture"
        ),
        "kernel_version": _runner_string(
            info["KernelVersion"], f"{info_label}.KernelVersion"
        ),
        "security_options": security_options,
        "cgroup_version": _runner_string(
            info["CgroupVersion"], f"{info_label}.CgroupVersion"
        ),
        "default_runtime": _runner_string(
            info["DefaultRuntime"], f"{info_label}.DefaultRuntime"
        ),
        "storage_driver": _runner_string(info["Driver"], f"{info_label}.Driver"),
    }
    identity = {
        "assurance": "docker_daemon_self_report_not_attested",
        "context": normalized_context,
        "engine": normalized_engine,
        "worker_claim": normalized_worker,
    }
    _validate_normalized_runner_identity(identity, f"{label}.identity")
    return identity


def _unreported_component_details_identity(
    details: dict[Any, Any],
    label: str,
) -> str:
    if not details:
        raise BenchmarkError(f"{label}.Details has no identity-bearing fields")
    normalized: dict[str, str] = {}
    for raw_key, raw_value in details.items():
        key = _runner_string(raw_key, f"{label}.Details key")
        if key in normalized:
            raise BenchmarkError(f"{label}.Details repeats a key")
        normalized[key] = _runner_string(
            raw_value,
            f"{label}.Details.{key}",
        )
    raw = json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return (
        _UNREPORTED_COMPONENT_DETAILS_PREFIX
        + hashlib.sha256(raw).hexdigest()
    )


def _validate_normalized_runner_identity(value: object, label: str) -> None:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be an object")
    _exact_keys(value, {"assurance", "context", "engine", "worker_claim"}, label)
    if value["assurance"] != "docker_daemon_self_report_not_attested":
        raise BenchmarkError(f"{label}.assurance is unsupported")

    context = value["context"]
    if not isinstance(context, dict):
        raise BenchmarkError(f"{label}.context must be an object")
    _exact_keys(
        context,
        {"name", "endpoint", "skip_tls_verify", "tls_material_count"},
        f"{label}.context",
    )
    _runner_string(context["name"], f"{label}.context.name")
    _canonical_unix_endpoint(context["endpoint"], f"{label}.context.endpoint")
    if context["skip_tls_verify"] is not False:
        raise BenchmarkError(f"{label}.context skips TLS verification")
    if (
        isinstance(context["tls_material_count"], bool)
        or not isinstance(context["tls_material_count"], int)
        or context["tls_material_count"] != 0
    ):
        raise BenchmarkError(f"{label}.context has TLS material")

    engine = value["engine"]
    if not isinstance(engine, dict):
        raise BenchmarkError(f"{label}.engine must be an object")
    _exact_keys(
        engine,
        {
            "platform_name",
            "version",
            "api_version",
            "minimum_api_version",
            "git_commit",
            "go_version",
            "os",
            "architecture",
            "kernel_version",
            "build_time",
            "components",
        },
        f"{label}.engine",
    )
    for field in (
        "platform_name",
        "version",
        "api_version",
        "minimum_api_version",
        "git_commit",
        "go_version",
        "kernel_version",
        "build_time",
    ):
        _runner_string(engine[field], f"{label}.engine.{field}")
    _runner_linux(engine["os"], f"{label}.engine.os")
    if engine["architecture"] not in {"arm64", "amd64"}:
        raise BenchmarkError(f"{label}.engine.architecture is unsupported")
    components = engine["components"]
    if not isinstance(components, list) or not 3 <= len(components) <= 32:
        raise BenchmarkError(f"{label}.engine.components is invalid")
    names: list[str] = []
    collision_keys: set[str] = set()
    for index, component in enumerate(components):
        component_label = f"{label}.engine.components[{index}]"
        if not isinstance(component, dict):
            raise BenchmarkError(f"{component_label} must be an object")
        _exact_keys(component, {"name", "version", "git_commit"}, component_label)
        name = _runner_string(component["name"], f"{component_label}.name")
        collision_key = name.casefold()
        if collision_key in collision_keys:
            raise BenchmarkError(f"{label}.engine.components is not canonical")
        collision_keys.add(collision_key)
        names.append(name)
        _runner_string(component["version"], f"{component_label}.version")
        _runner_string(component["git_commit"], f"{component_label}.git_commit")
    if (
        names != sorted(names)
        or len(names) != len(set(names))
        or not {"Engine", "containerd", "runc"}.issubset(names)
    ):
        raise BenchmarkError(f"{label}.engine.components is not canonical")
    engine_component = next(
        component for component in components if component["name"] == "Engine"
    )
    if (
        engine_component["version"] != engine["version"]
        or engine_component["git_commit"] != engine["git_commit"]
    ):
        raise BenchmarkError(f"{label}.engine Engine component is inconsistent")

    worker = value["worker_claim"]
    if not isinstance(worker, dict):
        raise BenchmarkError(f"{label}.worker_claim must be an object")
    _exact_keys(
        worker,
        {
            "daemon_id",
            "daemon_name",
            "server_version",
            "operating_system",
            "os",
            "architecture",
            "kernel_version",
            "security_options",
            "cgroup_version",
            "default_runtime",
            "storage_driver",
        },
        f"{label}.worker_claim",
    )
    for field in (
        "daemon_id",
        "daemon_name",
        "server_version",
        "operating_system",
        "kernel_version",
        "cgroup_version",
        "default_runtime",
        "storage_driver",
    ):
        _runner_string(worker[field], f"{label}.worker_claim.{field}")
    _runner_linux(worker["os"], f"{label}.worker_claim.os")
    if worker["architecture"] not in {"arm64", "amd64"}:
        raise BenchmarkError(f"{label}.worker_claim.architecture is unsupported")
    security_options = worker["security_options"]
    if not isinstance(security_options, list) or len(security_options) > 64:
        raise BenchmarkError(f"{label}.worker_claim.security_options is invalid")
    for option in security_options:
        _runner_string(option, f"{label}.worker_claim.security_options")
    if security_options != sorted(security_options) or len(security_options) != len(
        set(security_options)
    ):
        raise BenchmarkError(f"{label}.worker_claim.security_options is not canonical")
    if (
        worker["server_version"] != engine["version"]
        or worker["os"] != engine["os"]
        or worker["architecture"] != engine["architecture"]
        or worker["kernel_version"] != engine["kernel_version"]
    ):
        raise BenchmarkError(f"{label} daemon version and info are inconsistent")


def _runner_string(value: object, label: str) -> str:
    result = _canonical_string(value, label, 4096)
    try:
        encoded = result.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BenchmarkError(f"{label} contains invalid Unicode") from exc
    if (
        len(encoded) > 4096
        or result != unicodedata.normalize("NFC", result)
        or any(unicodedata.category(character).startswith("C") for character in result)
    ):
        raise BenchmarkError(f"{label} is not a canonical bounded string")
    return result


def _runner_linux(value: object, label: str) -> str:
    if _runner_string(value, label) != "linux":
        raise BenchmarkError(f"{label} must identify Linux")
    return "linux"


def _normalize_runner_arch(value: object, label: str) -> str:
    architecture = _runner_string(value, label)
    aliases = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }
    try:
        return aliases[architecture]
    except KeyError as exc:
        raise BenchmarkError(f"{label} is unsupported") from exc


def _canonical_unix_endpoint(value: object, label: str) -> str:
    endpoint = _runner_string(value, label)
    if "%" in endpoint or "\\" in endpoint:
        raise BenchmarkError(f"{label} must be a canonical absolute Unix endpoint")
    try:
        parsed = urlsplit(endpoint)
    except ValueError as exc:
        raise BenchmarkError(
            f"{label} must be a canonical absolute Unix endpoint"
        ) from exc
    path = parsed.path
    if (
        parsed.scheme != "unix"
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not path.startswith("/")
        or path == "/"
        or "//" in path
        or posixpath.normpath(path) != path
        or any(part in {".", ".."} for part in path.split("/"))
        or endpoint != f"unix://{path}"
    ):
        raise BenchmarkError(f"{label} must be a canonical absolute Unix endpoint")
    return endpoint


def _validate_oci_runtime_profile(value: object, label: str) -> None:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be an object")
    _exact_keys(
        value,
        {
            "engine",
            "pull",
            "network",
            "read_only_rootfs",
            "cap_drop",
            "no_new_privileges",
            "user",
            "workdir",
            "pids_limit",
            "memory_bytes",
            "memory_swap_bytes",
            "cpus",
            "nofile_soft",
            "nofile_hard",
            "tmpfs",
            "workspace",
        },
        label,
    )
    if value != _OCI_RUNTIME_PROFILE:
        raise BenchmarkError(f"{label} does not match the pinned isolation profile")


def _validate_oci_execution(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label}.execution must be an object")
    _exact_keys(
        value,
        {"status", "error_code", "returncode", "container_id"},
        f"{label}.execution",
    )
    if value["status"] not in {"ok", "error"}:
        raise BenchmarkError(f"{label}.execution.status is unsupported")
    allowed_errors = {
        "MALFORMED_VENDOR_REPORT",
        "NONZERO_OR_INVALID_VENDOR_EXIT",
        "OUTPUT_LIMIT_EXCEEDED",
        "TIMEOUT",
    }
    error_code = value["error_code"]
    if value["status"] == "ok":
        if error_code is not None:
            raise BenchmarkError(f"{label}.execution success has an error code")
    elif error_code not in allowed_errors:
        raise BenchmarkError(f"{label}.execution error code is unsupported")
    if isinstance(value["returncode"], bool) or not isinstance(
        value["returncode"], int
    ):
        raise BenchmarkError(f"{label}.execution.returncode is invalid")
    if (
        not isinstance(value["container_id"], str)
        or _CONTAINER_ID.fullmatch(value["container_id"]) is None
    ):
        raise BenchmarkError(f"{label}.execution.container_id is invalid")
    return value


def _verify_oci_image_inspects(
    raw_index: bytes,
    raw_platform: bytes,
    *,
    selected: dict[str, Any],
    effective: dict[str, Any],
    baseline_spec: dict[str, Any],
    label: str,
) -> dict[str, str]:
    index = _docker_inspect_one(raw_index, f"{label}.index_inspect")
    platform = _docker_inspect_one(raw_platform, f"{label}.platform_inspect")
    image = selected["image"]
    image_reference = effective["image"]["reference"]
    index_config = _verify_oci_image_inspect(
        index,
        expected_id=image["index_digest"],
        expected_media_type="application/vnd.oci.image.index.v1+json",
        image_reference=image_reference,
        selected=selected,
        baseline_spec=baseline_spec,
        label=f"{label}.index_inspect",
    )
    platform_config = _verify_oci_image_inspect(
        platform,
        expected_id=image["platform_manifest_digest"],
        expected_media_type="application/vnd.oci.image.manifest.v1+json",
        image_reference=image_reference,
        selected=selected,
        baseline_spec=baseline_spec,
        label=f"{label}.platform_inspect",
    )
    if index_config != platform_config:
        raise BenchmarkError(f"{label} index and platform image configs differ")
    environment = _docker_environment(
        platform_config.get("Env"),
        f"{label}.platform_inspect.Config.Env",
    )
    return environment


def _verify_oci_metadata_graph(
    raw_index: bytes,
    raw_platform: bytes,
    raw_provenance: bytes,
    raw_config: bytes,
    *,
    selected: dict[str, Any],
    label: str,
) -> None:
    graph_label = f"{label}.oci_metadata"
    image = selected["image"]
    index = _oci_metadata_object(raw_index, f"{graph_label}.index")
    _exact_keys(
        index,
        {"schemaVersion", "mediaType", "manifests"},
        f"{graph_label}.index",
    )
    if (
        index["schemaVersion"] != 2
        or index["mediaType"] != "application/vnd.oci.image.index.v1+json"
    ):
        raise BenchmarkError(f"{graph_label}.index is not an OCI image index")
    manifests = index["manifests"]
    if not isinstance(manifests, list) or len(manifests) != 2:
        raise BenchmarkError(
            f"{graph_label}.index must contain the image and provenance manifests"
        )
    descriptors: dict[str, dict[str, Any]] = {}
    for position, value in enumerate(manifests):
        if not isinstance(value, dict):
            raise BenchmarkError(
                f"{graph_label}.index.manifests[{position}] must be an object"
            )
        manifest_digest = _digest(
            value.get("digest"),
            f"{graph_label}.index.manifests[{position}].digest",
        )
        descriptor = _oci_descriptor(
            value,
            f"{graph_label}.index.manifests[{position}]",
            extra_keys=(
                {"annotations", "platform"}
                if manifest_digest == image["build_provenance_manifest_digest"]
                else {"platform"}
            ),
        )
        digest = descriptor["digest"]
        if digest in descriptors:
            raise BenchmarkError(f"{graph_label}.index repeats a manifest")
        descriptors[digest] = descriptor
    if set(descriptors) != {
        image["platform_manifest_digest"],
        image["build_provenance_manifest_digest"],
    }:
        raise BenchmarkError(f"{graph_label}.index manifest graph is unbound")
    platform_descriptor = descriptors[image["platform_manifest_digest"]]
    provenance_descriptor = descriptors[image["build_provenance_manifest_digest"]]
    if (
        platform_descriptor["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
        or platform_descriptor["size"] != len(raw_platform)
        or platform_descriptor["platform"]
        != {"architecture": image["architecture"], "os": image["os"]}
    ):
        raise BenchmarkError(f"{graph_label}.index platform descriptor is unbound")
    if (
        provenance_descriptor["mediaType"]
        != "application/vnd.oci.image.manifest.v1+json"
        or provenance_descriptor["size"] != len(raw_provenance)
        or provenance_descriptor["platform"]
        != {"architecture": "unknown", "os": "unknown"}
        or provenance_descriptor["annotations"]
        != {
            "vnd.docker.reference.digest": image["platform_manifest_digest"],
            "vnd.docker.reference.type": "attestation-manifest",
        }
    ):
        raise BenchmarkError(f"{graph_label}.index provenance descriptor is unbound")

    platform = _oci_metadata_object(raw_platform, f"{graph_label}.platform_manifest")
    _exact_keys(
        platform,
        {"schemaVersion", "mediaType", "config", "layers"},
        f"{graph_label}.platform_manifest",
    )
    if (
        platform["schemaVersion"] != 2
        or platform["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
    ):
        raise BenchmarkError(
            f"{graph_label}.platform_manifest is not an OCI image manifest"
        )
    config_descriptor = _oci_descriptor(
        platform["config"],
        f"{graph_label}.platform_manifest.config",
    )
    if (
        config_descriptor["mediaType"] != "application/vnd.oci.image.config.v1+json"
        or config_descriptor["digest"] != image["config_digest"]
        or config_descriptor["size"] != len(raw_config)
    ):
        raise BenchmarkError(
            f"{graph_label}.platform_manifest config descriptor is unbound"
        )
    layers = platform["layers"]
    if not isinstance(layers, list) or not 1 <= len(layers) <= 1024:
        raise BenchmarkError(f"{graph_label}.platform_manifest layers are invalid")
    layer_digests: set[str] = set()
    supported_layers = {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
        "application/vnd.oci.image.layer.v1.tar+zstd",
        "application/vnd.oci.image.layer.nondistributable.v1.tar",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
        "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",
    }
    for position, value in enumerate(layers):
        descriptor = _oci_descriptor(
            value,
            f"{graph_label}.platform_manifest.layers[{position}]",
        )
        if (
            descriptor["mediaType"] not in supported_layers
            or descriptor["digest"] in layer_digests
        ):
            raise BenchmarkError(
                f"{graph_label}.platform_manifest has an invalid layer descriptor"
            )
        layer_digests.add(descriptor["digest"])

    provenance = _oci_metadata_object(
        raw_provenance, f"{graph_label}.provenance_manifest"
    )
    _exact_keys(
        provenance,
        {"schemaVersion", "mediaType", "config", "layers"},
        f"{graph_label}.provenance_manifest",
    )
    if (
        provenance["schemaVersion"] != 2
        or provenance["mediaType"] != "application/vnd.oci.image.manifest.v1+json"
    ):
        raise BenchmarkError(
            f"{graph_label}.provenance_manifest is not an OCI image manifest"
        )
    provenance_config = _oci_descriptor(
        provenance["config"],
        f"{graph_label}.provenance_manifest.config",
    )
    if provenance_config["mediaType"] != "application/vnd.oci.image.config.v1+json":
        raise BenchmarkError(f"{graph_label}.provenance_manifest config is unsupported")
    statements = provenance["layers"]
    if not isinstance(statements, list) or len(statements) != 1:
        raise BenchmarkError(
            f"{graph_label}.provenance_manifest must contain one statement"
        )
    statement = _oci_descriptor(
        statements[0],
        f"{graph_label}.provenance_manifest.layers[0]",
        extra_keys={"annotations"},
    )
    if statement["mediaType"] != "application/vnd.in-toto+json" or statement[
        "annotations"
    ] != {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}:
        raise BenchmarkError(
            f"{graph_label}.provenance_manifest statement is unsupported"
        )


def _oci_metadata_object(raw: bytes, label: str) -> dict[str, Any]:
    document = _decode_json(raw, label)
    _finite_json(document, label)
    if not isinstance(document, dict):
        raise BenchmarkError(f"{label} must be an object")
    return document


def _oci_descriptor(
    value: object,
    label: str,
    *,
    extra_keys: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be an object")
    _exact_keys(
        value,
        {"mediaType", "digest", "size"} | (extra_keys or set()),
        label,
    )
    media_type = value["mediaType"]
    if (
        not isinstance(media_type, str)
        or not media_type
        or len(media_type) > 256
        or media_type != media_type.strip()
    ):
        raise BenchmarkError(f"{label}.mediaType is invalid")
    _digest(value["digest"], f"{label}.digest")
    size = value["size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= 2**63 - 1:
        raise BenchmarkError(f"{label}.size is invalid")
    return value


def _verify_oci_image_config(
    raw: bytes,
    *,
    selected: dict[str, Any],
    baseline_spec: dict[str, Any],
    label: str,
) -> dict[str, str]:
    config_label = f"{label}.image_config"
    document = _decode_json(raw, config_label)
    _finite_json(document, config_label)
    if not isinstance(document, dict):
        raise BenchmarkError(f"{config_label} must be an object")
    image = selected["image"]
    if (
        document.get("os") != image["os"]
        or document.get("architecture") != image["architecture"]
    ):
        raise BenchmarkError(f"{config_label} platform is unbound")
    config = document.get("config")
    if not isinstance(config, dict):
        raise BenchmarkError(f"{config_label}.config must be an object")
    expected = {
        "User": selected["runtime_profile"]["user"],
        "WorkingDir": selected["runtime_profile"]["workdir"],
        "Entrypoint": baseline_spec["entrypoint"],
    }
    if any(config.get(key) != value for key, value in expected.items()):
        raise BenchmarkError(f"{config_label}.config is not pinned")
    environment = _docker_environment(
        config.get("Env"),
        f"{config_label}.config.Env",
    )
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        raise BenchmarkError(f"{config_label}.config.Labels must be an object")
    expected_labels = {
        "dev.aragorn.baseline.build-input-sha256": selected["build"][
            "build_input_sha256"
        ],
        "dev.aragorn.baseline.lock-sha256": selected["build"]["dependency_lock_sha256"],
        "dev.aragorn.closure-status": "candidate-not-runner-attested",
        "org.opencontainers.image.revision": selected["commit"],
        "org.opencontainers.image.source": selected["repository"],
        "org.opencontainers.image.version": baseline_spec["image_version"],
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise BenchmarkError(f"{config_label}.config.Labels do not match the lock")
    return environment


def _verify_oci_image_inspect(
    document: dict[str, Any],
    *,
    expected_id: str,
    expected_media_type: str,
    image_reference: str,
    selected: dict[str, Any],
    baseline_spec: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    image = selected["image"]
    if document.get("Id") != expected_id:
        raise BenchmarkError(f"{label}.Id does not match the locked image")
    descriptor = document.get("Descriptor")
    if not isinstance(descriptor, dict):
        raise BenchmarkError(f"{label}.Descriptor must be an object")
    if (
        descriptor.get("digest") != expected_id
        or descriptor.get("mediaType") != expected_media_type
    ):
        raise BenchmarkError(f"{label}.Descriptor does not match the locked image")
    if expected_media_type.endswith("manifest.v1+json") and descriptor.get(
        "platform"
    ) != {"architecture": image["architecture"], "os": image["os"]}:
        raise BenchmarkError(f"{label}.Descriptor platform is unbound")
    if (
        document.get("Os") != image["os"]
        or document.get("Architecture") != image["architecture"]
    ):
        raise BenchmarkError(f"{label} platform does not match the lock")
    if document.get("Size") != image["size_bytes"]:
        raise BenchmarkError(f"{label}.Size does not match the lock")
    if image_reference not in _bounded_string_list(
        document.get("RepoDigests"), f"{label}.RepoDigests", maximum=64
    ):
        raise BenchmarkError(f"{label}.RepoDigests omits the locked digest reference")
    if image["local_tag"] not in _bounded_string_list(
        document.get("RepoTags"), f"{label}.RepoTags", maximum=64
    ):
        raise BenchmarkError(f"{label}.RepoTags omits the locked local tag")

    config = document.get("Config")
    if not isinstance(config, dict):
        raise BenchmarkError(f"{label}.Config must be an object")
    if config.get("User") != selected["runtime_profile"]["user"]:
        raise BenchmarkError(f"{label}.Config.User is not pinned")
    if config.get("WorkingDir") != selected["runtime_profile"]["workdir"]:
        raise BenchmarkError(f"{label}.Config.WorkingDir is not pinned")
    if config.get("Entrypoint") != baseline_spec["entrypoint"]:
        raise BenchmarkError(f"{label}.Config.Entrypoint is not pinned")
    _docker_environment(config.get("Env"), f"{label}.Config.Env")
    labels = config.get("Labels")
    if not isinstance(labels, dict):
        raise BenchmarkError(f"{label}.Config.Labels must be an object")
    expected_labels = {
        "dev.aragorn.baseline.build-input-sha256": selected["build"][
            "build_input_sha256"
        ],
        "dev.aragorn.baseline.lock-sha256": selected["build"]["dependency_lock_sha256"],
        "dev.aragorn.closure-status": "candidate-not-runner-attested",
        "org.opencontainers.image.revision": selected["commit"],
        "org.opencontainers.image.source": selected["repository"],
        "org.opencontainers.image.version": baseline_spec["image_version"],
    }
    if any(labels.get(key) != value for key, value in expected_labels.items()):
        raise BenchmarkError(f"{label}.Config.Labels do not match the lock")
    return config


def _verify_oci_container_inspect(
    raw: bytes,
    *,
    selected: dict[str, Any],
    effective: dict[str, Any],
    execution: dict[str, Any],
    phase: str,
    label: str,
) -> None:
    container_label = f"{label}.{phase}_container_inspect"
    container = _docker_inspect_one(raw, container_label)
    if container.get("Id") != execution["container_id"]:
        raise BenchmarkError(f"{container_label}.Id does not match execution")
    if container.get("Image") != effective["image"]["index_digest"]:
        raise BenchmarkError(f"{container_label}.Image is not the locked index")
    manifest = container.get("ImageManifestDescriptor")
    if not isinstance(manifest, dict):
        raise BenchmarkError(
            f"{container_label}.ImageManifestDescriptor must be an object"
        )
    if (
        manifest.get("digest") != effective["image"]["platform_manifest_digest"]
        or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
        or manifest.get("platform")
        != {
            "architecture": effective["image"]["architecture"],
            "os": effective["image"]["os"],
        }
    ):
        raise BenchmarkError(f"{container_label} platform manifest is unbound")
    entrypoint = effective["entrypoint"]
    expected_process_args = [*entrypoint[1:], *effective["arguments"]]
    if (
        container.get("Path") != entrypoint[0]
        or container.get("Args") != expected_process_args
    ):
        raise BenchmarkError(f"{container_label} process arguments are unbound")

    config = container.get("Config")
    if not isinstance(config, dict):
        raise BenchmarkError(f"{container_label}.Config must be an object")
    expected_config = {
        "Image": effective["image"]["reference"],
        "User": selected["runtime_profile"]["user"],
        "WorkingDir": selected["runtime_profile"]["workdir"],
        "Entrypoint": entrypoint,
        "Cmd": effective["arguments"],
    }
    if any(config.get(key) != value for key, value in expected_config.items()):
        raise BenchmarkError(f"{container_label}.Config is not effective-config bound")
    if (
        _docker_environment(config.get("Env"), f"{container_label}.Config.Env")
        != effective["environment"]
    ):
        raise BenchmarkError(f"{container_label}.Config.Env is unbound")

    runtime = selected["runtime_profile"]
    host = container.get("HostConfig")
    if not isinstance(host, dict):
        raise BenchmarkError(f"{container_label}.HostConfig must be an object")
    expected_host = {
        "NetworkMode": runtime["network"],
        "ReadonlyRootfs": runtime["read_only_rootfs"],
        "CapDrop": runtime["cap_drop"],
        "SecurityOpt": ["no-new-privileges=true"],
        "PidsLimit": runtime["pids_limit"],
        "Memory": runtime["memory_bytes"],
        "MemorySwap": runtime["memory_swap_bytes"],
        "NanoCpus": int(float(runtime["cpus"]) * 1_000_000_000),
        "Privileged": False,
        "PublishAllPorts": False,
    }
    if any(host.get(key) != value for key, value in expected_host.items()):
        raise BenchmarkError(f"{container_label}.HostConfig weakens isolation")
    if host.get("CapAdd") not in (None, [], ()):
        raise BenchmarkError(f"{container_label}.HostConfig adds capabilities")
    if host.get("Devices") not in (None, [], ()):
        raise BenchmarkError(f"{container_label}.HostConfig adds devices")
    if host.get("DeviceRequests") not in (None, [], ()):
        raise BenchmarkError(f"{container_label}.HostConfig requests devices")

    ulimits = host.get("Ulimits")
    expected_ulimit = {
        "Name": "nofile",
        "Soft": runtime["nofile_soft"],
        "Hard": runtime["nofile_hard"],
    }
    if ulimits != [expected_ulimit]:
        raise BenchmarkError(f"{container_label}.HostConfig.Ulimits is unbound")
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict) or set(tmpfs) != {"/tmp"}:
        raise BenchmarkError(f"{container_label}.HostConfig.Tmpfs is invalid")
    expected_tmpfs = {
        *runtime["tmpfs"]["options"],
        f"size={runtime['tmpfs']['size_bytes']}",
    }
    if not isinstance(tmpfs["/tmp"], str) or set(tmpfs["/tmp"].split(",")) != (
        expected_tmpfs
    ):
        raise BenchmarkError(f"{container_label}.HostConfig.Tmpfs is unbound")
    host_mounts = host.get("Mounts")
    if not isinstance(host_mounts, list) or len(host_mounts) != 1:
        raise BenchmarkError(f"{container_label}.HostConfig.Mounts is invalid")
    host_mount = host_mounts[0]
    if (
        not isinstance(host_mount, dict)
        or host_mount.get("Type") != "bind"
        or host_mount.get("Target") != runtime["workspace"]["destination"]
        or host_mount.get("ReadOnly") is not True
    ):
        raise BenchmarkError(
            f"{container_label}.HostConfig.Mounts weakens workspace isolation"
        )
    workspace_source = host_mount.get("Source")
    if (
        not isinstance(workspace_source, str)
        or not Path(workspace_source).is_absolute()
        or "\0" in workspace_source
    ):
        raise BenchmarkError(f"{container_label} workspace source is invalid")

    mounts = container.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 1:
        raise BenchmarkError(f"{container_label}.Mounts is invalid")
    mount = mounts[0]
    if (
        not isinstance(mount, dict)
        or mount.get("Type") != "bind"
        or mount.get("Source") != workspace_source
        or mount.get("Destination") != runtime["workspace"]["destination"]
        or mount.get("RW") is not False
        or mount.get("Mode") not in {"", "ro"}
    ):
        raise BenchmarkError(f"{container_label}.Mounts weakens workspace isolation")
    network_settings = container.get("NetworkSettings")
    if not isinstance(network_settings, dict) or not isinstance(
        network_settings.get("Networks"), dict
    ):
        raise BenchmarkError(f"{container_label}.NetworkSettings is invalid")
    if set(network_settings["Networks"]) not in (set(), {"none"}):
        raise BenchmarkError(f"{container_label} has a network other than none")

    state = container.get("State")
    if not isinstance(state, dict):
        raise BenchmarkError(f"{container_label}.State must be an object")
    expected_status = "created" if phase == "prestart" else "exited"
    expected_exit = 0 if phase == "prestart" else execution["returncode"]
    if (
        state.get("Status") != expected_status
        or state.get("Running") is not False
        or state.get("Dead") is not False
        or state.get("OOMKilled") is not False
        or state.get("ExitCode") != expected_exit
    ):
        raise BenchmarkError(f"{container_label}.State is inconsistent with execution")


def _docker_inspect_one(raw: bytes, label: str) -> dict[str, Any]:
    document = _decode_json(raw, label)
    _finite_json(document, label)
    if (
        not isinstance(document, list)
        or len(document) != 1
        or not isinstance(document[0], dict)
    ):
        raise BenchmarkError(f"{label} must contain exactly one inspect object")
    return document[0]


def _docker_environment(value: object, label: str) -> dict[str, str]:
    values = _bounded_string_list(value, label, maximum=256)
    environment: dict[str, str] = {}
    for item in values:
        name, separator, setting = item.partition("=")
        if (
            not separator
            or _ENVIRONMENT_NAME.fullmatch(name) is None
            or name in environment
        ):
            raise BenchmarkError(f"{label} contains an invalid environment entry")
        environment[name] = setting
    return environment


def _validate_environment(value: object, label: str) -> None:
    if not isinstance(value, dict) or len(value) > 256:
        raise BenchmarkError(f"{label} must be a bounded object")
    for name, setting in value.items():
        if (
            not isinstance(name, str)
            or _ENVIRONMENT_NAME.fullmatch(name) is None
            or not isinstance(setting, str)
            or "\0" in setting
            or len(setting.encode("utf-8")) > 16_384
        ):
            raise BenchmarkError(f"{label} contains an invalid entry")


def _bounded_string_list(value: object, label: str, *, maximum: int) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > maximum
        or any(not isinstance(item, str) for item in value)
    ):
        raise BenchmarkError(f"{label} must be a bounded string array")
    return value


def _oci_digest_reference(local_tag: str, index_digest: str) -> str:
    last_slash = local_tag.rfind("/")
    last_colon = local_tag.rfind(":")
    repository = local_tag[:last_colon] if last_colon > last_slash else local_tag
    if not repository:
        raise BenchmarkError("locked OCI image repository is invalid")
    return f"{repository}@{index_digest}"


def _hex_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_DIGEST.fullmatch(value) is None:
        raise BenchmarkError(f"{label} must be a lowercase SHA-256 hex digest")
    return value


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BenchmarkError(f"{label} must be a positive integer")
    return value


def _finite_json(value: object, label: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise BenchmarkError(f"{label} contains a non-finite number")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BenchmarkError(f"{label} contains invalid Unicode") from exc
    elif isinstance(value, list):
        for item in value:
            _finite_json(item, label)
    elif isinstance(value, dict):
        for item in value.values():
            _finite_json(item, label)


def _validate_error_evidence(
    error_code: str,
    returncode: int | None,
    *,
    stdout: bytes,
    stderr: bytes,
    subject_digest: str,
    output_limit: int,
    label: str,
) -> None:
    if error_code not in EVIDENCE_ERROR_CODES:
        raise BenchmarkError(f"{label}.evidence execution error is not re-verifiable")
    if error_code in _PARSE_ERROR_CODES:
        if returncode != 0:
            raise BenchmarkError(f"{label}.evidence parser error has a nonzero process")
        _observations, parse_error = _parse_observations(stdout, subject_digest)
        if parse_error is None or parse_error[0] != error_code:
            raise BenchmarkError(f"{label}.evidence parser error does not match stdout")
        return
    if error_code == "NONZERO_EXIT":
        if returncode is None or returncode == 0:
            raise BenchmarkError(f"{label}.evidence nonzero exit is inconsistent")
        return
    if error_code == "TIMEOUT":
        if returncode is None or returncode > 0:
            raise BenchmarkError(f"{label}.evidence timeout is inconsistent")
        return
    if error_code == "OUTPUT_LIMIT_EXCEEDED":
        if len(stdout) + len(stderr) != output_limit:
            raise BenchmarkError(f"{label}.evidence output limit is inconsistent")
        return
    raise BenchmarkError(f"{label}.evidence execution error is unsupported")


def _validate_effective_config(
    document: dict[str, Any], system: dict[str, str], label: str
) -> None:
    _exact_keys(
        document,
        {
            "schema",
            "name",
            "version",
            "executable_digest",
            "operator_argv0",
            "argv_tail",
            "limits",
            "normalization",
        },
        f"{label}.evidence.effective_config",
    )
    if document["schema"] != "aragorn/benchmark-system-config/v1":
        raise BenchmarkError(f"{label}.evidence effective config schema is unsupported")
    if document["name"] != system["name"] or document["version"] != system["version"]:
        raise BenchmarkError(f"{label}.evidence effective config system is unbound")
    if document["executable_digest"] != system["implementation_digest"]:
        raise BenchmarkError(f"{label}.evidence effective config executable is unbound")
    operator_argv0 = document["operator_argv0"]
    if (
        not isinstance(operator_argv0, str)
        or not operator_argv0
        or "\0" in operator_argv0
        or not Path(operator_argv0).is_absolute()
    ):
        raise BenchmarkError(
            f"{label}.evidence effective operator executable path is invalid"
        )
    argv_tail = document["argv_tail"]
    if not isinstance(argv_tail, list) or any(
        not isinstance(argument, str) or not argument for argument in argv_tail
    ):
        raise BenchmarkError(f"{label}.evidence effective argv is invalid")
    limits = document["limits"]
    if not isinstance(limits, dict):
        raise BenchmarkError(f"{label}.evidence effective limits are invalid")
    _exact_keys(
        limits,
        {"timeout_seconds", "output_bytes"},
        f"{label}.evidence.effective_config.limits",
    )
    timeout = limits["timeout_seconds"]
    output_bytes = limits["output_bytes"]
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout <= 0
    ):
        raise BenchmarkError(f"{label}.evidence effective timeout is invalid")
    if (
        isinstance(output_bytes, bool)
        or not isinstance(output_bytes, int)
        or not 1 <= output_bytes <= _MAX_EVIDENCE_BYTES
    ):
        raise BenchmarkError(f"{label}.evidence effective output limit is invalid")
    if document["normalization"] != "aragorn-observation-severity/v1":
        raise BenchmarkError(f"{label}.evidence effective normalization is unsupported")


def _validate_operator_config(
    raw: bytes, effective_config: dict[str, Any], label: str
) -> None:
    document = _decode_json(raw, f"{label}.evidence.operator_config")
    if not isinstance(document, dict):
        raise BenchmarkError(f"{label}.evidence operator config must be a JSON object")
    _exact_keys(
        document,
        {"schema", "analyzers"},
        f"{label}.evidence.operator_config",
    )
    if document["schema"] != "aragorn/analyzers/v1":
        raise BenchmarkError(f"{label}.evidence operator config schema is unsupported")
    analyzers = document["analyzers"]
    if not isinstance(analyzers, list) or not 1 <= len(analyzers) <= _MAX_SYSTEMS:
        raise BenchmarkError(f"{label}.evidence operator analyzer list is invalid")
    matches = []
    names: set[str] = set()
    for index, analyzer in enumerate(analyzers):
        item_label = f"{label}.evidence.operator_config.analyzers[{index}]"
        if not isinstance(analyzer, dict):
            raise BenchmarkError(f"{item_label} must be a JSON object")
        _exact_keys(analyzer, {"name", "version", "argv"}, item_label)
        name = _identifier(analyzer["name"], f"{item_label}.name")
        version = _canonical_string(analyzer["version"], f"{item_label}.version", 256)
        if name in names:
            raise BenchmarkError(
                f"{label}.evidence operator config has duplicate names"
            )
        names.add(name)
        argv = analyzer["argv"]
        if (
            not isinstance(argv, list)
            or not argv
            or any(
                not isinstance(argument, str) or not argument or "\0" in argument
                for argument in argv
            )
        ):
            raise BenchmarkError(f"{item_label}.argv is invalid")
        if not Path(argv[0]).is_absolute():
            raise BenchmarkError(f"{item_label}.argv[0] must be absolute")
        for argument in argv[1:]:
            _key, separator, option_value = argument.partition("=")
            candidate_value = option_value if separator else argument
            candidate = Path(candidate_value)
            if (
                candidate.is_absolute()
                or candidate_value.startswith("~")
                or ".." in candidate.parts
            ):
                raise BenchmarkError(f"{item_label}.argv contains a filesystem path")
        if name == effective_config["name"] and version == effective_config["version"]:
            matches.append(argv)
    if (
        len(matches) != 1
        or matches[0][0] != effective_config["operator_argv0"]
        or matches[0][1:] != effective_config["argv_tail"]
    ):
        raise BenchmarkError(
            f"{label}.evidence operator config is not effectively bound"
        )


def _read_canonical_document(
    cas: CAS, digest: str, label: str, *, max_bytes: int
) -> dict[str, Any]:
    raw = cas.read(digest, max_bytes=max_bytes)
    document = _decode_json(raw, label)
    if not isinstance(document, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    if raw != _canonical_json_bytes(document):
        raise BenchmarkError(f"{label} must use canonical JSON bytes")
    return document


def _validate_system(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label}.system must be a JSON object")
    _exact_keys(
        value,
        {"name", "version", "implementation_digest", "config_digest"},
        f"{label}.system",
    )
    return {
        "name": _identifier(value["name"], f"{label}.system.name"),
        "version": _canonical_string(value["version"], f"{label}.system.version", 256),
        "implementation_digest": _digest(
            value["implementation_digest"],
            f"{label}.system.implementation_digest",
        ),
        "config_digest": _digest(
            value["config_digest"], f"{label}.system.config_digest"
        ),
    }


def _phase0_gate_report(
    value: object,
    *,
    benchmark_report: dict[str, Any],
    cases: dict[str, dict[str, Any]],
    systems: dict[tuple[str, str, str, str], dict[str, str]],
    outcomes: list[dict[str, Any]],
    evidence_cas: CAS | None,
) -> dict[str, Any]:
    if evidence_cas is None:
        raise BenchmarkError("Phase 0 accounting requires a retained evidence state")
    candidate, plans, canonical_accounting = _validate_phase0_accounting(
        value,
        suite_digest=benchmark_report["suite_digest"],
        cases=cases,
        systems=systems,
    )
    expansion_profile = canonical_accounting.get(
        "expansion_profile", GITHUB_EXPANSION_PROFILE
    )
    records = {
        case_id: _load_phase0_expansion(
            evidence_cas,
            plan["expansion_digest"],
            expected_tree_digest=cases[case_id]["tree_digest"],
            expected_profile=expansion_profile,
            label=f"Phase 0 accounting case {case_id}",
        )
        for case_id, plan in plans.items()
    }
    candidate_key = _system_key(candidate)
    outcomes_by_cell = {
        (_system_key(item["system"]), item["case_id"], item["run_id"]): item
        for item in outcomes
    }
    case_facts = {
        case_id: _phase0_case_facts(records[case_id], plans[case_id])
        for case_id in sorted(plans)
    }
    for case_id, facts in case_facts.items():
        if not facts["incomplete"]:
            continue
        for run_id in range(1, benchmark_report["runs_per_case"] + 1):
            outcome = outcomes_by_cell[(candidate_key, case_id, run_id)]
            if outcome["verdict"] == "ALLOW":
                raise BenchmarkError(
                    "Aragorn cannot ALLOW a case with incomplete Phase 0 "
                    f"accounting: {case_id}:run-{run_id}"
                )

    held_out_accounting = _phase0_accounting_metrics(
        (records[case_id], case_facts[case_id]) for case_id in sorted(records)
    )
    comparison = _phase0_comparative_gate(
        benchmark_report,
        candidate=candidate,
        held_out_accounting=held_out_accounting,
    )
    return {
        "schema": "aragorn/benchmark-phase0-gate-report/v1",
        "assurance": "comparative_metrics_only",
        "suite_id": benchmark_report["suite_id"],
        "purpose": benchmark_report["purpose"],
        "suite_digest": benchmark_report["suite_digest"],
        "outcomes_digest": benchmark_report["outcomes_digest"],
        "benchmark_report_digest": _digest_json(benchmark_report),
        "accounting_digest": _digest_json(canonical_accounting),
        "evaluation_split": "held_out",
        "accounting": held_out_accounting,
        "comparison": comparison,
    }


def _phase0_hidden_gate_report(
    *,
    benchmark_report: dict[str, Any],
    systems: dict[tuple[str, str, str, str], dict[str, str]],
    binding: dict[str, str],
) -> dict[str, Any]:
    candidates = [system for system in systems.values() if system["name"] == "aragorn"]
    if len(candidates) != 1:
        raise BenchmarkError(
            "Phase 0 suite must declare exactly one Aragorn candidate identity"
        )
    comparison = _phase0_hidden_comparative_gate(
        benchmark_report,
        candidate=candidates[0],
    )
    return {
        "schema": "aragorn/benchmark-phase0-gate-report/v2",
        "assurance": "comparative_metrics_only",
        "suite_id": benchmark_report["suite_id"],
        "purpose": benchmark_report["purpose"],
        "suite_digest": benchmark_report["suite_digest"],
        "outcomes_digest": benchmark_report["outcomes_digest"],
        "benchmark_report_digest": _digest_json(benchmark_report),
        "corpus_lock_digest": binding["corpus_lock_digest"],
        "public_manifest_digest": binding["public_manifest_digest"],
        "hidden_suite_lock_digest": binding["hidden_suite_lock_digest"],
        "candidate_policy_digest": binding["candidate_policy_digest"],
        "label_ledger_digest": binding["label_ledger_digest"],
        "evaluation_split": "hidden",
        "comparison": comparison,
    }


def _validate_phase0_hidden_binding(
    *,
    corpus_lock_path: Path,
    public_manifest_path: Path,
    hidden_suite_lock_path: Path,
    candidate_policy_path: Path,
    label_ledger_digest: str,
    suite_digest: str,
    runs_per_case: int,
    cases: dict[str, dict[str, Any]],
    systems: dict[tuple[str, str, str, str], dict[str, str]],
    manifests: dict[str, dict[str, Any]],
) -> dict[str, str]:
    corpus_lock_raw = _read_bounded(corpus_lock_path)
    corpus_lock_digest = _digest_bytes(corpus_lock_raw)
    corpus_identity = _PHASE0_CORPUS_LOCKS.get(corpus_lock_digest)
    if corpus_identity is None:
        raise BenchmarkError("Phase 0 hidden gate corpus lock identity does not match")
    expected_schema, expected_corpus_id, opaque_case_id = corpus_identity
    corpus_lock = _decode_json(corpus_lock_raw, "Phase 0 corpus lock")
    if not isinstance(corpus_lock, dict):
        raise BenchmarkError("Phase 0 corpus lock must be a JSON object")
    corpus_lock_keys = {
        "schema",
        "corpus_id",
        "assurance",
        "case_count",
        "runs_per_case",
        "worker_archive",
        "public_manifest",
        "evaluator_archive",
        "freeze",
        "signing",
    }
    if expected_schema == "aragorn/benchmark-corpus-provenance-lock/v2":
        corpus_lock_keys.update({"evaluator_encryption", "release_manifest"})
    _exact_keys(
        corpus_lock,
        corpus_lock_keys,
        "Phase 0 corpus lock",
    )
    if (
        corpus_lock["schema"] != expected_schema
        or corpus_lock["corpus_id"] != expected_corpus_id
        or corpus_lock["case_count"] != 448
        or corpus_lock["runs_per_case"] != 1
    ):
        raise BenchmarkError("Phase 0 hidden gate corpus lock is unsupported")
    if expected_schema == "aragorn/benchmark-corpus-provenance-lock/v2" and (
        corpus_lock["evaluator_encryption"]
        != {
            "profile": "openssl-aes-256-cbc-pbkdf2-sha256/v1",
            "iterations": 600000,
        }
    ):
        raise BenchmarkError("Phase 0 hidden gate corpus encryption is unsupported")

    public_manifest_raw = _read_bounded(public_manifest_path)
    public_manifest_digest = _digest_bytes(public_manifest_raw)
    if public_manifest_digest != corpus_lock["public_manifest"].get("sha256"):
        raise BenchmarkError("Phase 0 public manifest digest does not match corpus lock")
    public_manifest = _decode_json(
        public_manifest_raw,
        "Phase 0 public corpus manifest",
    )
    if not isinstance(public_manifest, dict):
        raise BenchmarkError("Phase 0 public corpus manifest must be a JSON object")
    _exact_keys(
        public_manifest,
        {
            "schema_version",
            "corpus_version",
            "hash_algorithm",
            "case_count",
            "entries",
        },
        "Phase 0 public corpus manifest",
    )
    if (
        public_manifest["schema_version"] != "1.0"
        or public_manifest["hash_algorithm"] != "sha256"
        or public_manifest["corpus_version"] != corpus_lock["corpus_id"]
        or public_manifest["case_count"] != corpus_lock["case_count"]
    ):
        raise BenchmarkError("Phase 0 public corpus manifest identity does not match")
    raw_entries = public_manifest["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) != 448:
        raise BenchmarkError("Phase 0 public corpus manifest must contain 448 entries")
    entries: dict[str, dict[str, Any]] = {}
    for index, raw_entry in enumerate(raw_entries):
        label = f"Phase 0 public corpus manifest entries[{index}]"
        if not isinstance(raw_entry, dict):
            raise BenchmarkError(f"{label} must be a JSON object")
        _exact_keys(raw_entry, {"id", "path", "sha256", "size"}, label)
        case_id = raw_entry["id"]
        if (
            not isinstance(case_id, str)
            or opaque_case_id.fullmatch(case_id) is None
        ):
            raise BenchmarkError(f"{label}.id is not an opaque case identifier")
        if case_id in entries:
            raise BenchmarkError("Phase 0 public corpus manifest repeats a case")
        sha256 = raw_entry["sha256"]
        if not isinstance(sha256, str) or _HEX_DIGEST.fullmatch(sha256) is None:
            raise BenchmarkError(f"{label}.sha256 is invalid")
        size = raw_entry["size"]
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= _MAX_FIXTURE_BYTES
        ):
            raise BenchmarkError(f"{label}.size is invalid")
        expected_path = f"cases/{case_id}/SKILL.md"
        if raw_entry["path"] != expected_path:
            raise BenchmarkError(f"{label}.path does not match its case identifier")
        entries[case_id] = {
            "digest": f"sha256:{sha256}",
            "size": size,
        }
    if list(entries) != sorted(entries):
        raise BenchmarkError("Phase 0 public corpus manifest entries must be sorted")

    candidate_policy_raw = _read_bounded(candidate_policy_path)
    candidate_policy = _decode_json(
        candidate_policy_raw,
        "Phase 0 candidate policy",
    )
    try:
        from .phase0_candidate import (
            build_candidate_policy,
            candidate_policy_digest,
            candidate_system_identity,
        )

        canonical_policy = build_candidate_policy(candidate_policy)
        frozen_policy_digest = candidate_policy_digest(canonical_policy)
        expected_systems = sorted(
            [
                candidate_system_identity(canonical_policy),
                *canonical_policy["required_comparators"],
            ],
            key=_system_key,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BenchmarkError(f"invalid Phase 0 candidate policy: {exc}") from exc

    hidden_suite_lock_raw = _read_bounded(hidden_suite_lock_path)
    hidden_suite_lock_digest = _digest_bytes(hidden_suite_lock_raw)
    hidden_suite_lock = _decode_json(
        hidden_suite_lock_raw,
        "Phase 0 hidden suite lock",
    )
    if not isinstance(hidden_suite_lock, dict):
        raise BenchmarkError("Phase 0 hidden suite lock must be a JSON object")
    if hidden_suite_lock_raw != _canonical_json_bytes(hidden_suite_lock):
        raise BenchmarkError("Phase 0 hidden suite lock must use canonical JSON bytes")
    _exact_keys(
        hidden_suite_lock,
        {
            "schema",
            "assurance",
            "corpus_lock_digest",
            "worker_archive_digest",
            "public_manifest_digest",
            "evaluator_archive_digest",
            "label_ledger_digest",
            "candidate_policy_digest",
            "suite_digest",
            "case_count",
            "class_counts",
            "runs_per_case",
            "split",
            "systems",
        },
        "Phase 0 hidden suite lock",
    )
    if (
        hidden_suite_lock["schema"]
        != "aragorn/benchmark-phase0-hidden-suite-lock/v1"
        or hidden_suite_lock["assurance"]
        != "operator_asserted_pre_outcome_binding_not_independent_or_timestamped"
    ):
        raise BenchmarkError("Phase 0 hidden suite lock is unsupported")
    for field in (
        "corpus_lock_digest",
        "worker_archive_digest",
        "public_manifest_digest",
        "evaluator_archive_digest",
        "label_ledger_digest",
        "candidate_policy_digest",
        "suite_digest",
    ):
        _digest(hidden_suite_lock[field], f"Phase 0 hidden suite lock.{field}")
    expected_bindings = {
        "corpus_lock_digest": corpus_lock_digest,
        "worker_archive_digest": corpus_lock["worker_archive"]["sha256"],
        "public_manifest_digest": public_manifest_digest,
        "evaluator_archive_digest": corpus_lock["evaluator_archive"]["sha256"],
        "candidate_policy_digest": frozen_policy_digest,
        "label_ledger_digest": _digest(
            label_ledger_digest,
            "Phase 0 verified label ledger digest",
        ),
        "suite_digest": suite_digest,
    }
    if any(
        hidden_suite_lock[field] != expected
        for field, expected in expected_bindings.items()
    ):
        raise BenchmarkError(
            "Phase 0 hidden suite lock does not bind the frozen inputs"
        )
    if (
        hidden_suite_lock["case_count"] != 448
        or hidden_suite_lock["class_counts"]
        != {"benign": 336, "adversarial": 112}
        or hidden_suite_lock["runs_per_case"] != 1
        or hidden_suite_lock["split"] != "hidden"
    ):
        raise BenchmarkError("Phase 0 hidden suite lock has invalid matrix accounting")
    raw_systems = hidden_suite_lock["systems"]
    if not isinstance(raw_systems, list):
        raise BenchmarkError("Phase 0 hidden suite lock systems must be an array")
    locked_systems = [
        _validate_system(value, f"Phase 0 hidden suite lock systems[{index}]")
        for index, value in enumerate(raw_systems)
    ]
    if locked_systems != expected_systems:
        raise BenchmarkError(
            "Phase 0 hidden suite lock does not bind the frozen system identities"
        )
    declared_systems = [systems[key] for key in sorted(systems)]
    if declared_systems != expected_systems:
        raise BenchmarkError(
            "Phase 0 hidden suite does not declare the frozen system identities"
        )

    if (
        runs_per_case != 1
        or len(cases) != 448
        or set(cases) != set(entries)
        or any(case["split"] != "hidden" for case in cases.values())
    ):
        raise BenchmarkError(
            "Phase 0 hidden suite does not match the frozen public case matrix"
        )
    class_counts = {
        case_class: sum(
            case["class"] == case_class for case in cases.values()
        )
        for case_class in ("benign", "adversarial")
    }
    if class_counts != hidden_suite_lock["class_counts"]:
        raise BenchmarkError("Phase 0 hidden suite class accounting does not match")
    for case_id, entry in entries.items():
        files = manifests[case_id]["files"]
        if (
            len(files) != 1
            or files[0]["path"] != "SKILL.md"
            or files[0]["digest"] != entry["digest"]
            or files[0]["size"] != entry["size"]
            or files[0]["executable"] is not False
        ):
            raise BenchmarkError(
                f"Phase 0 hidden suite case {case_id} does not match public manifest"
            )
    return {
        "corpus_lock_digest": corpus_lock_digest,
        "public_manifest_digest": public_manifest_digest,
        "hidden_suite_lock_digest": hidden_suite_lock_digest,
        "candidate_policy_digest": frozen_policy_digest,
        "label_ledger_digest": label_ledger_digest,
    }


def _validate_phase0_accounting(
    value: object,
    *,
    suite_digest: str,
    cases: dict[str, dict[str, Any]],
    systems: dict[tuple[str, str, str, str], dict[str, str]],
) -> tuple[dict[str, str], dict[str, dict[str, Any]], dict[str, Any]]:
    label = "Phase 0 accounting sidecar"
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    base_fields = {"schema", "suite_digest", "candidate_system", "cases"}
    contract_fields = {"expansion_profile", "expansion_assurance"}
    if frozenset(value) not in {
        frozenset(base_fields),
        frozenset(base_fields | contract_fields),
    }:
        raise BenchmarkError(f"{label} has missing or unknown fields")
    if value["schema"] != "aragorn/benchmark-phase0-accounting/v1":
        raise BenchmarkError("unsupported Phase 0 accounting schema")
    if value["suite_digest"] != suite_digest:
        raise BenchmarkError("Phase 0 accounting suite_digest does not match")
    candidate = _validate_system(value["candidate_system"], label)
    if candidate["name"] != "aragorn":
        raise BenchmarkError("Phase 0 candidate system must be named aragorn")
    if _system_key(candidate) not in systems:
        raise BenchmarkError("Phase 0 candidate system is not declared by the suite")
    aragorn_systems = [
        system for system in systems.values() if system["name"] == "aragorn"
    ]
    if aragorn_systems != [candidate]:
        raise BenchmarkError(
            "Phase 0 suite must declare exactly one Aragorn candidate identity"
        )
    expansion_contract: dict[str, str] = {}
    if contract_fields <= set(value):
        profile = value["expansion_profile"]
        contract = (
            _PHASE0_EXPANSION_CONTRACTS.get(profile)
            if isinstance(profile, str)
            else None
        )
        if contract is None:
            raise BenchmarkError("Phase 0 accounting expansion profile is unsupported")
        assurance, _scope = contract
        if value["expansion_assurance"] != assurance:
            raise BenchmarkError(
                "Phase 0 accounting expansion assurance does not match its profile"
            )
        expansion_contract = {
            "expansion_profile": profile,
            "expansion_assurance": assurance,
        }

    raw_records = value["cases"]
    if not isinstance(raw_records, list):
        raise BenchmarkError("Phase 0 accounting cases must be an array")
    held_out_ids = {
        case_id for case_id, case in cases.items() if case["split"] == "held_out"
    }
    normalized_records: dict[str, dict[str, Any]] = {}
    for index, raw_record in enumerate(raw_records):
        record = _validate_phase0_case_record(raw_record, f"{label}.cases[{index}]")
        case_id = record["case_id"]
        if case_id not in held_out_ids:
            raise BenchmarkError(
                f"Phase 0 accounting references a non-held-out case: {case_id}"
            )
        if case_id in normalized_records:
            raise BenchmarkError(f"duplicate Phase 0 accounting case: {case_id}")
        normalized_records[case_id] = record
    if set(normalized_records) != held_out_ids:
        missing = sorted(held_out_ids - set(normalized_records))
        extra = sorted(set(normalized_records) - held_out_ids)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing[:8]))
        if extra:
            detail.append("unknown " + ", ".join(extra[:8]))
        raise BenchmarkError(
            "Phase 0 accounting case matrix is incomplete: " + "; ".join(detail)
        )
    canonical = {
        "schema": "aragorn/benchmark-phase0-accounting/v1",
        "suite_digest": suite_digest,
        "candidate_system": candidate,
        **expansion_contract,
        "cases": [
            normalized_records[case_id] for case_id in sorted(normalized_records)
        ],
    }
    return candidate, normalized_records, canonical


def _validate_phase0_case_record(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(
        value,
        {
            "case_id",
            "expansion_digest",
            "expected_references",
        },
        label,
    )
    case_id = _identifier(value["case_id"], f"{label}.case_id")
    expected = _validate_phase0_expected_references(
        value["expected_references"], f"{label}.expected_references"
    )
    return {
        "case_id": case_id,
        "expansion_digest": _digest(
            value["expansion_digest"], f"{label}.expansion_digest"
        ),
        "expected_references": expected,
    }


def _phase0_reference_key(
    value: dict[str, Any],
) -> tuple[str, str, str, int, int, str]:
    return (
        value["source_commit"],
        value["source_repository_path"],
        value["source_blob_digest"],
        value["byte_offset"],
        value["literal_size"],
        value["literal_digest"],
    )


def _validate_phase0_reference_identity(
    value: object, label: str, *, expected: set[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(value, expected, label)
    source_commit = value["source_commit"]
    if (
        not isinstance(source_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
    ):
        raise BenchmarkError(f"{label}.source_commit must be a lowercase Git SHA-1")
    source_path = _relative_path(
        value["source_repository_path"], f"{label}.source_repository_path"
    ).as_posix()
    byte_offset = _phase0_count(
        value["byte_offset"], f"{label}.byte_offset", maximum=_MAX_FIXTURE_BYTES
    )
    literal_size = _phase0_count(
        value["literal_size"],
        f"{label}.literal_size",
        minimum=1,
        maximum=_MAX_FIXTURE_BYTES,
    )
    return {
        "source_commit": source_commit,
        "source_repository_path": source_path,
        "source_blob_digest": _digest(
            value["source_blob_digest"], f"{label}.source_blob_digest"
        ),
        "byte_offset": byte_offset,
        "literal_size": literal_size,
        "literal_digest": _digest(value["literal_digest"], f"{label}.literal_digest"),
    }


def _validate_phase0_expected_references(
    value: object, label: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 10_000:
        raise BenchmarkError(f"{label} must be an array with at most 10000 entries")
    normalized = []
    seen: set[tuple[str, str, str, int, int, str]] = set()
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        item = _validate_phase0_reference_identity(
            raw,
            item_label,
            expected={
                "source_repository_path",
                "source_commit",
                "source_blob_digest",
                "byte_offset",
                "literal_size",
                "literal_digest",
                "target_commit",
                "target_repository_path",
                "target_digest",
            },
        )
        assert isinstance(raw, dict)
        target_commit = raw["target_commit"]
        if (
            not isinstance(target_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", target_commit) is None
        ):
            raise BenchmarkError(
                f"{item_label}.target_commit must be a lowercase Git SHA-1"
            )
        item["target_commit"] = target_commit
        item["target_repository_path"] = _relative_path(
            raw["target_repository_path"],
            f"{item_label}.target_repository_path",
        ).as_posix()
        item["target_digest"] = _digest(
            raw["target_digest"], f"{item_label}.target_digest"
        )
        key = _phase0_reference_key(item)
        if key in seen:
            raise BenchmarkError(f"{label} contains a duplicate reference occurrence")
        seen.add(key)
        normalized.append(item)
    return sorted(normalized, key=_phase0_reference_sort_key)


def _phase0_reference_sort_key(value: dict[str, Any]) -> tuple[Any, ...]:
    return (
        value["source_commit"],
        value["source_repository_path"],
        value["source_blob_digest"],
        value["byte_offset"],
        value["literal_size"],
        value["literal_digest"],
    )


def _phase0_count(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise BenchmarkError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _load_phase0_expansion(
    cas: CAS,
    expansion_digest: str,
    *,
    expected_tree_digest: str,
    label: str,
    expected_profile: str = GITHUB_EXPANSION_PROFILE,
) -> dict[str, Any]:
    contract = (
        _PHASE0_EXPANSION_CONTRACTS.get(expected_profile)
        if isinstance(expected_profile, str)
        else None
    )
    if contract is None:
        raise BenchmarkError(f"{label} expected expansion profile is unsupported")
    expected_assurance, expected_scope = contract
    raw = _read_phase0_cas_json(cas, expansion_digest, label)
    if not isinstance(raw, dict):
        raise BenchmarkError(f"{label} expansion must be a JSON object")
    _exact_keys(
        raw,
        {
            "schema",
            "profile",
            "assurance",
            "source",
            "root_manifest_digest",
            "root_tree_digest",
            "comparator_subject_manifest_digest",
            "comparator_subject_tree_digest",
            "references",
            "objects",
            "accounting",
            "closure",
        },
        f"{label} expansion",
    )
    if raw["schema"] != "aragorn/github-expansion/v1":
        raise BenchmarkError(f"{label} has an unsupported expansion schema")
    if raw["profile"] != expected_profile:
        raise BenchmarkError(f"{label} has an unsupported expansion profile")
    if raw["assurance"] != expected_assurance:
        raise BenchmarkError(f"{label} has an unsupported expansion assurance")
    root_manifest_digest = _digest(
        raw["root_manifest_digest"], f"{label}.root_manifest_digest"
    )
    root_tree_digest = _digest(raw["root_tree_digest"], f"{label}.root_tree_digest")
    root_manifest = _read_phase0_cas_json(
        cas, root_manifest_digest, f"{label} root manifest"
    )
    root = _validate_phase0_root_manifest(
        root_manifest,
        cas,
        expected_digest=root_manifest_digest,
        expected_tree_digest=root_tree_digest,
        label=f"{label} root manifest",
    )
    source = _validate_phase0_expansion_source(raw["source"], f"{label}.source")
    if any(
        root["source"][field] != source[field]
        for field in (
            "host",
            "owner",
            "repository",
            "commit",
            "commit_tree",
            "skill_path",
            "api_version",
        )
    ):
        raise BenchmarkError(f"{label} source does not match its root manifest")
    references = _validate_phase0_expansion_references(
        raw["references"], f"{label}.references"
    )
    objects = _validate_phase0_expansion_objects(
        raw["objects"],
        cas,
        f"{label}.objects",
        root_commit=source["commit"],
    )
    closure = _validate_phase0_expansion_closure(
        raw["closure"],
        f"{label}.closure",
        expected_scope=expected_scope,
    )
    accounting = _validate_phase0_expansion_accounting(
        raw["accounting"], references, objects, f"{label}.accounting"
    )
    subject_manifest_digest = raw["comparator_subject_manifest_digest"]
    subject_tree_digest = raw["comparator_subject_tree_digest"]
    if closure["status"] == "complete":
        subject_manifest_digest = _digest(
            subject_manifest_digest, f"{label}.comparator_subject_manifest_digest"
        )
        subject_tree_digest = _digest(
            subject_tree_digest, f"{label}.comparator_subject_tree_digest"
        )
        subject = _read_phase0_cas_json(
            cas, subject_manifest_digest, f"{label} comparator subject"
        )
        subject_files = _validate_phase0_subject_manifest(
            subject,
            cas,
            expected_digest=subject_manifest_digest,
            expected_tree_digest=subject_tree_digest,
            label=f"{label} comparator subject",
        )
        if expected_tree_digest != subject_tree_digest:
            raise BenchmarkError(
                f"{label} expanded comparator tree does not match the benchmark case"
            )
        expected_subject_files = {
            path: {
                "size": item["size"],
                "digest": item["digest"],
                "executable": False,
            }
            for path, item in root["relative_files"].items()
        }
        for item in objects:
            if item["materialized_path"] in expected_subject_files:
                raise BenchmarkError(
                    f"{label} expanded object collides with a root subject path"
                )
            expected_subject_files[item["materialized_path"]] = {
                "size": item["size"],
                "digest": item["digest"],
                "executable": False,
            }
        if subject_files != expected_subject_files:
            raise BenchmarkError(
                f"{label} comparator subject file map does not exactly match "
                "the root and expanded objects"
            )
    else:
        if subject_manifest_digest is not None or subject_tree_digest is not None:
            raise BenchmarkError(
                f"{label} incomplete expansion published a comparator subject"
            )
        if objects:
            raise BenchmarkError(f"{label} incomplete expansion published objects")
        if expected_tree_digest != root_tree_digest:
            raise BenchmarkError(
                f"{label} incomplete expansion root tree does not match the benchmark case"
            )

    target_digests = {
        (source["commit"], path): digest
        for path, digest in root["repository_targets"].items()
    }
    for item in objects:
        target_identity = (item["commit"], item["repository_path"])
        if target_identity in target_digests:
            raise BenchmarkError(
                f"{label} expansion target duplicates an exact commit path"
            )
        target_digests[target_identity] = item["digest"]
    source_content: dict[str, bytes] = {}
    for reference in references:
        source_path = reference["source_repository_path"]
        source_commit = reference["source_commit"]
        source_digest = reference["source_blob_digest"]
        if target_digests.get((source_commit, source_path)) != source_digest:
            raise BenchmarkError(
                f"{label} reference source is not bound to retained bytes"
            )
        if source_digest not in source_content:
            try:
                source_content[source_digest] = cas.read(
                    source_digest,
                    max_bytes=_MAX_FIXTURE_BYTES,
                )
            except CASError as exc:
                raise BenchmarkError(
                    f"{label} reference source bytes are unavailable"
                ) from exc
        start = reference["byte_offset"]
        end = start + reference["literal_size"]
        retained = source_content[source_digest]
        if end > len(retained):
            raise BenchmarkError(
                f"{label} reference literal span exceeds retained source bytes"
            )
        if _digest_bytes(retained[start:end]) != reference["literal_digest"]:
            raise BenchmarkError(
                f"{label} reference literal digest does not match retained source bytes"
            )
        if reference["status"] == "unresolved":
            continue
        target_path = reference["target_repository_path"]
        if (reference["target_commit"], target_path) not in target_digests:
            raise BenchmarkError(f"{label} resolved reference has no retained target")
    if closure["status"] == "complete":
        if not accounting["references"]["scan_complete"]:
            raise BenchmarkError(f"{label} complete expansion has an incomplete scan")
        if not accounting["references"]["occurrences_complete"]:
            raise BenchmarkError(
                f"{label} complete expansion omits reference occurrences"
            )
        if (
            accounting["references"]["unresolved"]
            or accounting["references"]["opaque_carriers"]
        ):
            raise BenchmarkError(
                f"{label} complete expansion contains incomplete reference evidence"
            )
        expanded_by_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for reference in references:
            if reference["status"] == "expanded":
                expanded_by_target.setdefault(
                    (
                        reference["target_commit"],
                        reference["target_repository_path"],
                    ),
                    [],
                ).append(
                    {
                        key: reference[key]
                        for key in (
                            "source_commit",
                            "source_repository_path",
                            "source_blob_digest",
                            "byte_offset",
                            "literal_size",
                            "literal_digest",
                        )
                    }
                )
        object_references = {
            (item["commit"], item["repository_path"]): item["references"]
            for item in objects
        }
        if object_references != {
            target: sorted(items, key=_phase0_reference_sort_key)
            for target, items in expanded_by_target.items()
        }:
            raise BenchmarkError(
                f"{label} expanded object references do not exactly match "
                "top-level expanded occurrences"
            )
        reference_counts = accounting["references"]
        budgets = accounting["budgets"]
        if (
            reference_counts["total_edges"]
            != reference_counts["artifact_references"]
            + reference_counts["non_artifact"]
        ):
            raise BenchmarkError(
                f"{label} complete expansion total edge accounting is inconsistent"
            )
        if budgets["references"]["used"] != reference_counts["total_edges"]:
            raise BenchmarkError(
                f"{label} complete expansion reference budget is inconsistent"
            )
        if budgets["retained_bytes"]["used"] != root["retained_bytes"] + sum(
            item["size"] for item in objects
        ):
            raise BenchmarkError(
                f"{label} complete expansion retained byte accounting is inconsistent"
            )
        if budgets["expanded_objects"]["used"] != len(objects):
            raise BenchmarkError(
                f"{label} complete expansion object accounting is inconsistent"
            )
        if budgets["expansion_depth"]["used"] != max(
            (item["depth"] for item in objects), default=0
        ):
            raise BenchmarkError(
                f"{label} complete expansion depth accounting is inconsistent"
            )
        if reference_counts["deduplicated"] != sum(
            len(item["references"]) - 1 for item in objects
        ):
            raise BenchmarkError(
                f"{label} complete expansion deduplication accounting is inconsistent"
            )
    return {
        "expansion_digest": expansion_digest,
        "profile": expected_profile,
        "assurance": expected_assurance,
        "source": source,
        "root_manifest_digest": root_manifest_digest,
        "root_tree_digest": root_tree_digest,
        "comparator_subject_manifest_digest": subject_manifest_digest,
        "comparator_subject_tree_digest": subject_tree_digest,
        "references": references,
        "objects": objects,
        "accounting": accounting,
        "closure": closure,
        "_target_digests": target_digests,
    }


def _read_phase0_cas_json(cas: CAS, digest: str, label: str) -> object:
    try:
        raw = cas.read(digest, max_bytes=_MAX_INPUT_BYTES)
    except CASError as exc:
        raise BenchmarkError(f"{label} is unavailable or corrupt: {exc}") from exc
    document = _decode_json(raw, label)
    if _canonical_json_bytes(document) != raw:
        raise BenchmarkError(f"{label} must use canonical JSON")
    return document


def _validate_phase0_expansion_source(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(
        value,
        {
            "host",
            "owner",
            "repository",
            "commit",
            "commit_tree",
            "skill_path",
            "api_version",
        },
        label,
    )
    if value["host"] != "github.com" or value["api_version"] != "2026-03-10":
        raise BenchmarkError(f"{label} has unsupported GitHub source metadata")
    commit = value["commit"]
    commit_tree = value["commit_tree"]
    for field, item in (("commit", commit), ("commit_tree", commit_tree)):
        if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{40}", item) is None:
            raise BenchmarkError(f"{label}.{field} must be a lowercase Git SHA-1")
    owner = _canonical_string(value["owner"], f"{label}.owner", 39)
    repository = _canonical_string(value["repository"], f"{label}.repository", 100)
    if (
        re.fullmatch(r"[a-z0-9][a-z0-9-]{0,38}", owner) is None
        or owner.endswith("-")
    ):
        raise BenchmarkError(f"{label}.owner is not canonical")
    if (
        re.fullmatch(r"[a-z0-9_.-]{1,100}", repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
    ):
        raise BenchmarkError(f"{label}.repository is not canonical")
    skill_path = value["skill_path"]
    if skill_path != ".":
        skill_path = _relative_path(skill_path, f"{label}.skill_path").as_posix()
    return {
        "host": "github.com",
        "owner": owner,
        "repository": repository,
        "commit": commit,
        "commit_tree": commit_tree,
        "skill_path": skill_path,
        "api_version": "2026-03-10",
    }


def _validate_phase0_root_manifest(
    value: object,
    cas: CAS,
    *,
    expected_digest: str,
    expected_tree_digest: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(
        value,
        {"schema", "source", "tree_digest", "files", "closure"},
        label,
    )
    if value["schema"] != "aragorn/github-manifest/v1":
        raise BenchmarkError(f"{label} is not a GitHub manifest")
    if canonical_digest(value) != expected_digest:
        raise BenchmarkError(f"{label} digest does not match its expansion")
    tree_digest = _digest(value["tree_digest"], f"{label}.tree_digest")
    if tree_digest != expected_tree_digest:
        raise BenchmarkError(f"{label} tree digest does not match its expansion")
    source = _validate_phase0_root_source(value["source"], f"{label}.source")
    if value["closure"] != {"scope": "source_tree", "status": "complete"}:
        raise BenchmarkError(f"{label}.closure is not a complete source tree")
    files = value["files"]
    if not isinstance(files, list) or not 1 <= len(files) <= 10_000:
        raise BenchmarkError(f"{label}.files must contain 1 to 10000 files")
    skill_path = source["skill_path"]
    targets: dict[str, str] = {}
    relative_files: dict[str, dict[str, Any]] = {}
    folded_paths: set[str] = set()
    tree_files: list[dict[str, Any]] = []
    retained_bytes = 0
    for index, entry in enumerate(files):
        item_label = f"{label}.files[{index}]"
        if not isinstance(entry, dict):
            raise BenchmarkError(f"{item_label} must be an object")
        _exact_keys(
            entry,
            {"path", "size", "digest", "git_blob_sha1", "executable"},
            item_label,
        )
        path = _relative_path(entry["path"], f"{item_label}.path").as_posix()
        if path in relative_files or path.casefold() in folded_paths:
            raise BenchmarkError(f"{label} has a duplicate or colliding file path")
        folded_paths.add(path.casefold())
        digest = _digest(entry["digest"], f"{item_label}.digest")
        size = _phase0_count(
            entry["size"], f"{item_label}.size", maximum=_MAX_FIXTURE_BYTES
        )
        retained_bytes += size
        if retained_bytes > _MAX_SUITE_BYTES:
            raise BenchmarkError(f"{label} exceeds the retained byte limit")
        try:
            content = cas.read(digest, max_bytes=size)
        except CASError as exc:
            raise BenchmarkError(f"{item_label} content is unavailable: {exc}") from exc
        if len(content) != size:
            raise BenchmarkError(f"{item_label} size does not match retained bytes")
        git_blob = entry["git_blob_sha1"]
        if (
            not isinstance(git_blob, str)
            or re.fullmatch(r"[0-9a-f]{40}", git_blob) is None
            or git_blob != _phase0_git_blob_sha1(content)
        ):
            raise BenchmarkError(
                f"{item_label}.git_blob_sha1 does not match retained bytes"
            )
        executable = entry["executable"]
        if not isinstance(executable, bool):
            raise BenchmarkError(f"{item_label}.executable must be boolean")
        normalized = {
            "size": size,
            "digest": digest,
            "executable": executable,
        }
        relative_files[path] = normalized
        tree_files.append({"path": path, **normalized})
        repository_path = path if skill_path == "." else f"{skill_path}/{path}"
        if repository_path in targets:
            raise BenchmarkError(f"{label} has a duplicate repository path")
        targets[repository_path] = digest
    if [item["path"] for item in tree_files] != sorted(relative_files):
        raise BenchmarkError(f"{label}.files must be sorted by path")
    if canonical_digest(tree_files) != expected_tree_digest:
        raise BenchmarkError(f"{label} tree digest is not rederivable from files")
    return {
        "source": source,
        "repository_targets": targets,
        "relative_files": relative_files,
        "retained_bytes": retained_bytes,
    }


def _validate_phase0_root_source(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(
        value,
        {
            "kind",
            "host",
            "owner",
            "repository",
            "commit",
            "repository_hash_algorithm",
            "commit_tree",
            "skill_path",
            "skill_tree",
            "api_version",
        },
        label,
    )
    if (
        value["kind"] != "github_commit"
        or value["host"] != "github.com"
        or value["repository_hash_algorithm"] != "sha1"
        or value["api_version"] != "2026-03-10"
    ):
        raise BenchmarkError(f"{label} has unsupported GitHub source metadata")
    owner = value["owner"]
    if (
        not isinstance(owner, str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,38}", owner) is None
        or owner.endswith("-")
    ):
        raise BenchmarkError(f"{label}.owner is not canonical")
    repository = value["repository"]
    if (
        not isinstance(repository, str)
        or re.fullmatch(r"[a-z0-9_.-]{1,100}", repository) is None
        or repository in {".", ".."}
        or repository.endswith(".git")
    ):
        raise BenchmarkError(f"{label}.repository is not canonical")
    for field in ("commit", "commit_tree", "skill_tree"):
        item = value[field]
        if not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{40}", item) is None:
            raise BenchmarkError(f"{label}.{field} must be a lowercase Git SHA-1")
    skill_path = value["skill_path"]
    if skill_path != ".":
        skill_path = _relative_path(skill_path, f"{label}.skill_path").as_posix()
    if skill_path == "." and value["skill_tree"] != value["commit_tree"]:
        raise BenchmarkError(
            f"{label}.skill_tree must equal commit_tree for a repository-root skill"
        )
    return {
        **value,
        "owner": owner,
        "repository": repository,
        "skill_path": skill_path,
    }


def _validate_phase0_subject_manifest(
    value: object,
    cas: CAS,
    *,
    expected_digest: str,
    expected_tree_digest: str,
    label: str,
) -> dict[str, dict[str, Any]]:
    try:
        validate_subject_manifest(value)
    except WorkerProtocolError as exc:
        raise BenchmarkError(f"{label} is invalid: {exc}") from exc
    assert isinstance(value, dict)
    if canonical_digest(value) != expected_digest:
        raise BenchmarkError(f"{label} digest does not match its expansion")
    if value["tree_digest"] != expected_tree_digest:
        raise BenchmarkError(f"{label} tree digest does not match its expansion")
    files: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(value["files"]):
        try:
            content = cas.read(entry["digest"], max_bytes=entry["size"])
        except CASError as exc:
            raise BenchmarkError(
                f"{label}.files[{index}] content is unavailable: {exc}"
            ) from exc
        if len(content) != entry["size"]:
            raise BenchmarkError(
                f"{label}.files[{index}] size does not match retained bytes"
            )
        files[entry["path"]] = {
            "size": entry["size"],
            "digest": entry["digest"],
            "executable": entry["executable"],
        }
    return files


def _validate_phase0_expansion_references(
    value: object, label: str
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 10_000:
        raise BenchmarkError(f"{label} must contain at most 10000 references")
    normalized = []
    seen: set[tuple[str, str, str, int, int, str]] = set()
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        item = _validate_phase0_reference_identity(
            raw,
            item_label,
            expected={
                "source_repository_path",
                "source_commit",
                "source_blob_digest",
                "byte_offset",
                "literal_size",
                "literal_digest",
                "target_commit",
                "target_repository_path",
                "status",
                "reason_code",
            },
        )
        assert isinstance(raw, dict)
        status = raw["status"]
        if status not in {"root_resolved", "expanded", "unresolved"}:
            raise BenchmarkError(f"{item_label}.status is unsupported")
        target_path = raw["target_repository_path"]
        target_commit = raw["target_commit"]
        reason = raw["reason_code"]
        if status == "unresolved":
            if target_commit is not None and (
                not isinstance(target_commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", target_commit) is None
            ):
                raise BenchmarkError(
                    f"{item_label}.target_commit must be null or a lowercase Git SHA-1"
                )
            if target_path is not None:
                target_path = _relative_path(
                    target_path, f"{item_label}.target_repository_path"
                ).as_posix()
            reason = _reason_code(reason, f"{item_label}.reason_code")
        else:
            if (
                not isinstance(target_commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", target_commit) is None
            ):
                raise BenchmarkError(
                    f"{item_label}.target_commit must be a lowercase Git SHA-1"
                )
            target_path = _relative_path(
                target_path, f"{item_label}.target_repository_path"
            ).as_posix()
            if reason is not None:
                raise BenchmarkError(
                    f"{item_label}: resolved references cannot have a reason code"
                )
        item.update(
            {
                "target_commit": target_commit,
                "target_repository_path": target_path,
                "status": status,
                "reason_code": reason,
            }
        )
        key = _phase0_reference_key(item)
        if key in seen:
            raise BenchmarkError(f"{label} has a duplicate reference occurrence")
        seen.add(key)
        normalized.append(item)
    return sorted(normalized, key=_phase0_reference_sort_key)


def _validate_phase0_expansion_objects(
    value: object,
    cas: CAS,
    label: str,
    *,
    root_commit: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 256:
        raise BenchmarkError(f"{label} must contain at most 256 objects")
    normalized = []
    identities: set[tuple[str, str]] = set()
    materialized_paths: set[str] = set()
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(raw, dict):
            raise BenchmarkError(f"{item_label} must be a JSON object")
        _exact_keys(
            raw,
            {
                "commit",
                "commit_tree",
                "repository_path",
                "materialized_path",
                "depth",
                "size",
                "digest",
                "git_blob_sha1",
                "executable",
                "references",
            },
            item_label,
        )
        repository_path = _relative_path(
            raw["repository_path"], f"{item_label}.repository_path"
        ).as_posix()
        commit = raw["commit"]
        commit_tree = raw["commit_tree"]
        for field, item in (("commit", commit), ("commit_tree", commit_tree)):
            if (
                not isinstance(item, str)
                or re.fullmatch(r"[0-9a-f]{40}", item) is None
            ):
                raise BenchmarkError(
                    f"{item_label}.{field} must be a lowercase Git SHA-1"
                )
        materialized_path = _relative_path(
            raw["materialized_path"], f"{item_label}.materialized_path"
        ).as_posix()
        expected_materialized = "__aragorn_expanded__/" + (
            repository_path
            if commit == root_commit
            else f"{commit}/{repository_path}"
        )
        if materialized_path != expected_materialized:
            raise BenchmarkError(
                f"{item_label}.materialized_path does not match repository_path and commit"
            )
        identity = (commit, repository_path)
        if identity in identities or materialized_path in materialized_paths:
            raise BenchmarkError(f"{label} has duplicate expanded object identities")
        identities.add(identity)
        materialized_paths.add(materialized_path)
        digest = _digest(raw["digest"], f"{item_label}.digest")
        size = _phase0_count(
            raw["size"], f"{item_label}.size", maximum=_MAX_FIXTURE_BYTES
        )
        depth = _phase0_count(raw["depth"], f"{item_label}.depth", minimum=1, maximum=4)
        git_blob = raw["git_blob_sha1"]
        if (
            not isinstance(git_blob, str)
            or re.fullmatch(r"[0-9a-f]{40}", git_blob) is None
        ):
            raise BenchmarkError(f"{item_label}.git_blob_sha1 is invalid")
        if not isinstance(raw["executable"], bool):
            raise BenchmarkError(f"{item_label}.executable must be boolean")
        raw_references = raw["references"]
        if (
            not isinstance(raw_references, list)
            or not 1 <= len(raw_references) <= 10_000
        ):
            raise BenchmarkError(f"{item_label}.references must not be empty")
        references: list[dict[str, Any]] = []
        seen_references: set[tuple[str, str, str, int, int, str]] = set()
        for reference_index, reference in enumerate(raw_references):
            reference_label = f"{item_label}.references[{reference_index}]"
            normalized_reference = _validate_phase0_reference_identity(
                reference,
                reference_label,
                expected={
                    "source_repository_path",
                    "source_commit",
                    "source_blob_digest",
                    "byte_offset",
                    "literal_size",
                    "literal_digest",
                },
            )
            reference_key = _phase0_reference_key(normalized_reference)
            if reference_key in seen_references:
                raise BenchmarkError(
                    f"{item_label}.references contains a duplicate identity"
                )
            seen_references.add(reference_key)
            references.append(normalized_reference)
        if references != sorted(references, key=_phase0_reference_sort_key):
            raise BenchmarkError(f"{item_label}.references must be canonically sorted")
        try:
            content = cas.read(digest, max_bytes=size)
        except CASError as exc:
            raise BenchmarkError(f"{item_label} content is unavailable: {exc}") from exc
        if len(content) != size:
            raise BenchmarkError(f"{item_label} size does not match retained bytes")
        if git_blob != _phase0_git_blob_sha1(content):
            raise BenchmarkError(
                f"{item_label}.git_blob_sha1 does not match retained bytes"
            )
        normalized.append(
            {
                "commit": commit,
                "commit_tree": commit_tree,
                "repository_path": repository_path,
                "materialized_path": materialized_path,
                "depth": depth,
                "size": size,
                "digest": digest,
                "git_blob_sha1": git_blob,
                "executable": raw["executable"],
                "references": references,
            }
        )
    return sorted(normalized, key=lambda item: (item["commit"], item["repository_path"]))


def _phase0_git_blob_sha1(content: bytes) -> str:
    header = b"blob " + str(len(content)).encode("ascii") + b"\0"
    return hashlib.sha1(header + content).hexdigest()


def _validate_phase0_expansion_accounting(
    value: object,
    references: list[dict[str, Any]],
    objects: list[dict[str, Any]],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(value, {"references", "budgets"}, label)
    raw_references = value["references"]
    if not isinstance(raw_references, dict):
        raise BenchmarkError(f"{label}.references must be an object")
    reference_fields = {
        "total_edges",
        "artifact_references",
        "resolved_in_root",
        "expanded",
        "deduplicated",
        "non_artifact",
        "unresolved",
        "opaque_carriers",
    }
    occurrence_fields = {
        "scan_complete",
        "occurrences_complete",
        "occurrences_omitted",
    }
    _exact_keys(
        raw_references,
        reference_fields | occurrence_fields,
        f"{label}.references",
    )
    counters = {
        key: _phase0_count(
            raw_references[key], f"{label}.references.{key}", maximum=1_000_000
        )
        for key in sorted(reference_fields)
    }
    scan_complete = raw_references["scan_complete"]
    if not isinstance(scan_complete, bool):
        raise BenchmarkError(f"{label}.references.scan_complete must be boolean")
    occurrences_complete = raw_references["occurrences_complete"]
    if not isinstance(occurrences_complete, bool):
        raise BenchmarkError(f"{label}.references.occurrences_complete must be boolean")
    raw_occurrences_omitted = raw_references["occurrences_omitted"]
    occurrences_omitted = (
        None
        if raw_occurrences_omitted is None
        else _phase0_count(
            raw_occurrences_omitted,
            f"{label}.references.occurrences_omitted",
            maximum=1_000_000,
        )
    )
    derived = {
        "artifact_references": len(references),
        "resolved_in_root": sum(
            item["status"] == "root_resolved" for item in references
        ),
        "expanded": sum(item["status"] == "expanded" for item in references),
        "unresolved": sum(item["status"] == "unresolved" for item in references),
    }
    if occurrences_complete:
        if not scan_complete:
            raise BenchmarkError(
                f"{label}.references complete occurrences require a complete scan"
            )
        if occurrences_omitted != 0:
            raise BenchmarkError(
                f"{label}.references complete occurrences cannot be omitted"
            )
        for key, expected in derived.items():
            if counters[key] != expected:
                raise BenchmarkError(f"{label}.references.{key} is not rederivable")
    elif scan_complete:
        if occurrences_omitted is None or occurrences_omitted < 1:
            raise BenchmarkError(
                f"{label}.references incomplete occurrences omit no records"
            )
        if counters["artifact_references"] != len(references) + occurrences_omitted:
            raise BenchmarkError(
                f"{label}.references omitted occurrence count is inconsistent"
            )
        if (
            counters["resolved_in_root"] + counters["expanded"] + counters["unresolved"]
            != counters["artifact_references"]
        ):
            raise BenchmarkError(
                f"{label}.references aggregate statuses are inconsistent"
            )
    elif occurrences_omitted is not None:
        raise BenchmarkError(
            f"{label}.references incomplete scan must use an unknown omitted count"
        )
    if (
        counters["resolved_in_root"] + counters["expanded"] + counters["unresolved"]
        != counters["artifact_references"]
    ):
        raise BenchmarkError(f"{label}.references aggregate statuses are inconsistent")
    if counters["expanded"] < len(objects):
        raise BenchmarkError(f"{label}.references.expanded is smaller than objects")
    budgets = value["budgets"]
    budget_names = {
        "api_requests",
        "api_bytes",
        "retained_bytes",
        "expanded_objects",
        "expansion_depth",
        "references",
    }
    if not isinstance(budgets, dict):
        raise BenchmarkError(f"{label}.budgets must be an object")
    _exact_keys(budgets, budget_names, f"{label}.budgets")
    normalized_budgets = {
        key: _validate_phase0_budget(budgets[key], f"{label}.budgets.{key}")
        for key in sorted(budget_names)
    }
    if normalized_budgets["expanded_objects"]["used"] < len(objects):
        raise BenchmarkError(f"{label}.budgets.expanded_objects understates objects")
    return {
        "references": {
            **counters,
            "scan_complete": scan_complete,
            "occurrences_complete": occurrences_complete,
            "occurrences_omitted": occurrences_omitted,
        },
        "budgets": normalized_budgets,
    }


def _validate_phase0_budget(value: object, label: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(value, {"limit", "used"}, label)
    limit = _phase0_count(value["limit"], f"{label}.limit")
    used = _phase0_count(value["used"], f"{label}.used")
    if used > limit:
        raise BenchmarkError(f"{label}.used exceeds its limit")
    return {"limit": limit, "used": used}


def _validate_phase0_expansion_closure(
    value: object,
    label: str,
    *,
    expected_scope: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be a JSON object")
    _exact_keys(value, {"scope", "status", "unresolved"}, label)
    if value["scope"] != expected_scope:
        raise BenchmarkError(f"{label}.scope is unsupported")
    status = value["status"]
    if status not in {"complete", "incomplete"}:
        raise BenchmarkError(f"{label}.status is unsupported")
    unresolved = value["unresolved"]
    if not isinstance(unresolved, list):
        raise BenchmarkError(f"{label}.unresolved must be an array")
    normalized = []
    seen = set()
    for index, raw in enumerate(unresolved):
        item_label = f"{label}.unresolved[{index}]"
        if not isinstance(raw, dict):
            raise BenchmarkError(f"{item_label} must be an object")
        _exact_keys(raw, {"reason_code", "subject"}, item_label)
        item = {
            "reason_code": _reason_code(
                raw["reason_code"], f"{item_label}.reason_code"
            ),
            "subject": _canonical_string(raw["subject"], f"{item_label}.subject", 4096),
        }
        key = (item["reason_code"], item["subject"])
        if key in seen:
            raise BenchmarkError(f"{label}.unresolved contains duplicates")
        seen.add(key)
        normalized.append(item)
    if status == "complete" and normalized:
        raise BenchmarkError(f"{label}: complete closure has unresolved items")
    if status == "incomplete" and not normalized:
        raise BenchmarkError(f"{label}: incomplete closure needs an unresolved item")
    return {
        "scope": expected_scope,
        "status": status,
        "unresolved": sorted(
            normalized, key=lambda item: (item["reason_code"], item["subject"])
        ),
    }


def _phase0_case_facts(record: dict[str, Any], plan: dict[str, Any]) -> dict[str, Any]:
    expected = {
        _phase0_reference_key(item): item for item in plan["expected_references"]
    }
    observed = {_phase0_reference_key(item): item for item in record["references"]}
    captured = 0
    wrong_target = 0
    unresolved_expected = 0
    for key, expectation in expected.items():
        observation = observed.get(key)
        actual_digest = (
            record["_target_digests"].get(
                (
                    observation["target_commit"],
                    observation["target_repository_path"],
                )
            )
            if observation is not None and observation["status"] != "unresolved"
            else None
        )
        if observation is not None and observation["status"] == "unresolved":
            unresolved_expected += 1
        elif observation is not None and (
            observation["target_commit"] == expectation["target_commit"]
            and
            observation["target_repository_path"]
            == expectation["target_repository_path"]
            and actual_digest == expectation["target_digest"]
        ):
            captured += 1
        elif observation is not None:
            wrong_target += 1
    unresolved = record["accounting"]["references"]["unresolved"]
    opaque = record["accounting"]["references"]["opaque_carriers"]
    scan_complete = record["accounting"]["references"]["scan_complete"]
    occurrences_complete = record["accounting"]["references"]["occurrences_complete"]
    missed = len(expected) - captured
    budget_or_deadline_failure = any(
        "BUDGET_EXCEEDED" in item["reason_code"]
        or item["reason_code"] == "ACQUISITION_DEADLINE_EXCEEDED"
        for item in record["closure"]["unresolved"]
    )
    incomplete = bool(
        missed
        or unresolved
        or opaque
        or record["closure"]["status"] != "complete"
        or budget_or_deadline_failure
        or not scan_complete
        or not occurrences_complete
    )
    return {
        "expected": len(expected),
        "captured": captured,
        "missed": missed,
        "wrong_target": wrong_target,
        "unresolved_expected": unresolved_expected,
        "resolved": (
            record["accounting"]["references"]["artifact_references"] - unresolved
        ),
        "unresolved": unresolved,
        "non_artifact": record["accounting"]["references"]["non_artifact"],
        "opaque_carriers": opaque,
        "budget_or_deadline_failure": budget_or_deadline_failure,
        "incomplete": incomplete,
    }


def _phase0_accounting_metrics(
    values: Iterable[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    pairs = tuple(values)
    records = tuple(item[0] for item in pairs)
    facts = tuple(item[1] for item in pairs)
    expected = sum(item["expected"] for item in facts)
    captured = sum(item["captured"] for item in facts)
    unresolved = sum(item["unresolved"] for item in facts)
    artifact_references = sum(
        record["accounting"]["references"]["artifact_references"] for record in records
    )
    successful = sum(record["closure"]["status"] == "complete" for record in records)
    budgets = {}
    for name in (
        "api_requests",
        "api_bytes",
        "retained_bytes",
        "expanded_objects",
        "expansion_depth",
        "references",
    ):
        limit = sum(
            record["accounting"]["budgets"][name]["limit"] for record in records
        )
        used = sum(record["accounting"]["budgets"][name]["used"] for record in records)
        budgets[name] = {
            "limit": limit,
            "used": used,
            "utilization_rate": _phase0_rate(used, limit),
        }
    reason_counts: dict[str, int] = {}
    for record in records:
        for item in record["closure"]["unresolved"]:
            reason = item["reason_code"]
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return {
        "cases": len(records),
        "complete_expansions": successful,
        "incomplete_expansions": len(records) - successful,
        "expansion_success_rate": _phase0_rate(successful, len(records)),
        "incomplete_cases": sum(item["incomplete"] for item in facts),
        "expected_references": expected,
        "captured_references": captured,
        "missed_references": sum(item["missed"] for item in facts),
        "wrong_target_references": sum(item["wrong_target"] for item in facts),
        "unresolved_expected_references": sum(
            item["unresolved_expected"] for item in facts
        ),
        "source_reference_capture_rate": _phase0_rate(captured, expected),
        "profile_artifact_references": artifact_references,
        "unresolved_references": unresolved,
        "non_artifact_references": sum(item["non_artifact"] for item in facts),
        "unresolved_cases": sum(item["unresolved"] > 0 for item in facts),
        "unresolved_reference_rate": _phase0_rate(unresolved, artifact_references),
        "opaque_carriers": sum(item["opaque_carriers"] for item in facts),
        "published_expanded_objects": sum(len(record["objects"]) for record in records),
        "attempted_expanded_objects": budgets["expanded_objects"]["used"],
        "budgets": budgets,
        "reason_counts": [
            {"reason_code": reason, "cases": reason_counts[reason]}
            for reason in sorted(reason_counts)
        ],
    }


def _phase0_rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _phase0_comparative_gate(
    benchmark_report: dict[str, Any],
    *,
    candidate: dict[str, str],
    held_out_accounting: dict[str, Any],
) -> dict[str, Any]:
    (
        candidate_point,
        comparator_points,
        frontier,
        selected,
        held_out_missing,
    ) = _phase0_comparison_points(
        benchmark_report,
        candidate=candidate,
        evaluation_split="held_out",
    )

    reasons = []
    delta: Fraction | None = None
    if held_out_missing or candidate_point is None:
        reasons.append("NO_HELD_OUT_SPLIT")
    else:
        if held_out_accounting["expected_references"] == 0:
            reasons.append("NO_EXPECTED_SOURCE_REFERENCES")
        if held_out_accounting["incomplete_cases"]:
            reasons.append("HELD_OUT_EXPANSION_INCOMPLETE")
        if not candidate_point["burden_compliant"]:
            reasons.append("CANDIDATE_BURDEN_CEILING_EXCEEDED")
        if selected is None:
            reasons.append("NO_BURDEN_COMPLIANT_COMPARATOR")
        else:
            delta = candidate_point["attack"] - selected["attack"]
            if delta < _PHASE0_MINIMUM_ATTACK_FLAG_DELTA:
                reasons.append("ATTACK_FLAG_DELTA_BELOW_10PP")
    return {
        "benign_burden_ceiling": _phase0_fraction_report(_PHASE0_BENIGN_BURDEN_CEILING),
        "minimum_attack_flag_delta": _phase0_fraction_report(
            _PHASE0_MINIMUM_ATTACK_FLAG_DELTA
        ),
        "candidate": (
            _phase0_point_report(candidate_point)
            if candidate_point is not None
            else None
        ),
        "comparators": [
            _phase0_point_report(point)
            for point in sorted(
                comparator_points, key=lambda item: _system_key(item["system"])
            )
        ],
        "pareto_frontier": [
            _phase0_point_report(point)
            for point in sorted(frontier, key=lambda item: _system_key(item["system"]))
        ],
        "selected_comparator": (
            _phase0_point_report(selected) if selected is not None else None
        ),
        "attack_flag_delta": (
            _phase0_fraction_report(delta) if delta is not None else None
        ),
        "evaluable": not any(
            reason
            in {
                "NO_HELD_OUT_SPLIT",
                "NO_EXPECTED_SOURCE_REFERENCES",
                "NO_BURDEN_COMPLIANT_COMPARATOR",
            }
            for reason in reasons
        ),
        "passed": not reasons,
        "reason_codes": sorted(reasons),
    }


def _phase0_hidden_comparative_gate(
    benchmark_report: dict[str, Any],
    *,
    candidate: dict[str, str],
) -> dict[str, Any]:
    (
        candidate_point,
        comparator_points,
        frontier,
        selected,
        hidden_missing,
    ) = _phase0_comparison_points(
        benchmark_report,
        candidate=candidate,
        evaluation_split="hidden",
    )
    reasons = []
    delta: Fraction | None = None
    if hidden_missing or candidate_point is None:
        reasons.append("NO_HIDDEN_SPLIT")
    else:
        if not candidate_point["burden_compliant"]:
            reasons.append("CANDIDATE_BURDEN_CEILING_EXCEEDED")
        if selected is None:
            reasons.append("NO_BURDEN_COMPLIANT_COMPARATOR")
        else:
            delta = candidate_point["attack"] - selected["attack"]
            if delta < _PHASE0_MINIMUM_ATTACK_FLAG_DELTA:
                reasons.append("ATTACK_FLAG_DELTA_BELOW_10PP")
    return {
        "benign_burden_ceiling": _phase0_fraction_report(_PHASE0_BENIGN_BURDEN_CEILING),
        "minimum_attack_flag_delta": _phase0_fraction_report(
            _PHASE0_MINIMUM_ATTACK_FLAG_DELTA
        ),
        "candidate": (
            _phase0_point_report(candidate_point)
            if candidate_point is not None
            else None
        ),
        "comparators": [
            _phase0_point_report(point)
            for point in sorted(
                comparator_points, key=lambda item: _system_key(item["system"])
            )
        ],
        "pareto_frontier": [
            _phase0_point_report(point)
            for point in sorted(frontier, key=lambda item: _system_key(item["system"]))
        ],
        "selected_comparator": (
            _phase0_point_report(selected) if selected is not None else None
        ),
        "attack_flag_delta": (
            _phase0_fraction_report(delta) if delta is not None else None
        ),
        "evaluable": not any(
            reason in {"NO_HIDDEN_SPLIT", "NO_BURDEN_COMPLIANT_COMPARATOR"}
            for reason in reasons
        ),
        "passed": not reasons,
        "reason_codes": sorted(reasons),
    }


def _phase0_comparison_points(
    benchmark_report: dict[str, Any],
    *,
    candidate: dict[str, str],
    evaluation_split: str,
) -> tuple[
    dict[str, Any] | None,
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, Any] | None,
    bool,
]:
    candidate_key = _system_key(candidate)
    points = []
    split_missing = False
    for system_report in benchmark_report["systems"]:
        split = next(
            (
                item
                for item in system_report["splits"]
                if item["split"] == evaluation_split
            ),
            None,
        )
        if split is None:
            split_missing = True
            continue
        summary = split["summary"]
        benign_evaluations = sum(summary["class_verdicts"]["benign"].values())
        adversarial_evaluations = sum(summary["class_verdicts"]["adversarial"].values())
        burden = Fraction(summary["benign_intervened"], benign_evaluations)
        attack = Fraction(summary["adversarial_flagged"], adversarial_evaluations)
        points.append(
            {
                "system": system_report["system"],
                "burden": burden,
                "attack": attack,
                "burden_compliant": burden <= _PHASE0_BENIGN_BURDEN_CEILING,
            }
        )
    candidate_point = next(
        (point for point in points if _system_key(point["system"]) == candidate_key),
        None,
    )
    comparator_points = [
        point for point in points if _system_key(point["system"]) != candidate_key
    ]
    frontier = _phase0_pareto_frontier(comparator_points)
    eligible = [point for point in comparator_points if point["burden_compliant"]]
    selected = None
    if eligible:
        best_attack = max(point["attack"] for point in eligible)
        selected = min(
            (point for point in eligible if point["attack"] == best_attack),
            key=lambda point: _system_key(point["system"]),
        )
    return candidate_point, comparator_points, frontier, selected, split_missing


def _phase0_pareto_frontier(
    points: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        point
        for point in points
        if not any(
            other is not point
            and other["attack"] >= point["attack"]
            and other["burden"] <= point["burden"]
            and (other["attack"] > point["attack"] or other["burden"] < point["burden"])
            for other in points
        )
    ]


def _phase0_point_report(point: dict[str, Any]) -> dict[str, Any]:
    return {
        "system": point["system"],
        "benign_intervention": _phase0_fraction_report(point["burden"]),
        "adversarial_flag": _phase0_fraction_report(point["attack"]),
        "burden_compliant": point["burden_compliant"],
    }


def _phase0_fraction_report(value: Fraction) -> dict[str, Any]:
    return {
        "numerator": value.numerator,
        "denominator": value.denominator,
        "rate": round(float(value), 6),
    }


def _summarize(
    cases: dict[str, dict[str, Any]],
    outcomes: dict[tuple[str, int], dict[str, Any]],
    runs_per_case: int,
) -> dict[str, Any]:
    benign = [case_id for case_id, case in cases.items() if case["class"] == "benign"]
    adversarial = [
        case_id for case_id, case in cases.items() if case["class"] == "adversarial"
    ]
    if not benign or not adversarial:
        raise BenchmarkError("every evaluated split must contain both case classes")
    benign_verdicts = _verdict_counts(benign, outcomes, runs_per_case)
    adversarial_verdicts = _verdict_counts(adversarial, outcomes, runs_per_case)
    verdicts = {
        verdict: benign_verdicts[verdict] + adversarial_verdicts[verdict]
        for verdict in _VERDICTS
    }
    benign_evaluations = len(benign) * runs_per_case
    adversarial_evaluations = len(adversarial) * runs_per_case
    evaluations = benign_evaluations + adversarial_evaluations
    adversarial_flagged = adversarial_verdicts["REVIEW"] + adversarial_verdicts["DENY"]
    all_flagged = (
        adversarial_flagged + benign_verdicts["REVIEW"] + benign_verdicts["DENY"]
    )
    benign_intervened = (
        benign_verdicts["REVIEW"] + benign_verdicts["DENY"] + benign_verdicts["ERROR"]
    )
    return {
        "cases": len(cases),
        "runs_per_case": runs_per_case,
        "evaluations": evaluations,
        "benign_cases": len(benign),
        "adversarial_cases": len(adversarial),
        "verdicts": verdicts,
        "class_verdicts": {
            "benign": benign_verdicts,
            "adversarial": adversarial_verdicts,
        },
        "adversarial_allowed": adversarial_verdicts["ALLOW"],
        "adversarial_flagged": adversarial_flagged,
        "benign_reviewed": benign_verdicts["REVIEW"],
        "benign_denied": benign_verdicts["DENY"],
        "benign_intervened": benign_intervened,
        "adversarial_flag_rate": round(
            adversarial_flagged / adversarial_evaluations, 6
        ),
        "adversarial_allow_rate": round(
            adversarial_verdicts["ALLOW"] / adversarial_evaluations, 6
        ),
        "benign_review_rate": round(benign_verdicts["REVIEW"] / benign_evaluations, 6),
        "benign_deny_rate": round(benign_verdicts["DENY"] / benign_evaluations, 6),
        "benign_intervention_rate": round(benign_intervened / benign_evaluations, 6),
        "benign_error_rate": round(benign_verdicts["ERROR"] / benign_evaluations, 6),
        "adversarial_error_rate": round(
            adversarial_verdicts["ERROR"] / adversarial_evaluations, 6
        ),
        "error_rate": round(verdicts["ERROR"] / evaluations, 6),
        "flag_precision": (
            round(adversarial_flagged / all_flagged, 6) if all_flagged else None
        ),
    }


def _family_reports(
    cases: dict[str, dict[str, Any]],
    outcomes: dict[tuple[str, int], dict[str, Any]],
    runs_per_case: int,
) -> list[dict[str, Any]]:
    reports = []
    families = sorted(
        {case["family"] for case in cases.values() if case["class"] == "adversarial"}
    )
    for family in families:
        case_ids = [
            case_id
            for case_id, case in cases.items()
            if case["class"] == "adversarial" and case["family"] == family
        ]
        verdicts = _verdict_counts(case_ids, outcomes, runs_per_case)
        evaluations = len(case_ids) * runs_per_case
        flagged = verdicts["REVIEW"] + verdicts["DENY"]
        reports.append(
            {
                "family": family,
                "cases": len(case_ids),
                "runs_per_case": runs_per_case,
                "evaluations": evaluations,
                "verdicts": verdicts,
                "allowed": verdicts["ALLOW"],
                "reviewed": verdicts["REVIEW"],
                "denied": verdicts["DENY"],
                "errors": verdicts["ERROR"],
                "flagged": flagged,
                "flag_rate": round(flagged / evaluations, 6),
                "error_rate": round(verdicts["ERROR"] / evaluations, 6),
                "repeatability": _repeatability(
                    {case_id: cases[case_id] for case_id in case_ids},
                    outcomes,
                    runs_per_case,
                ),
            }
        )
    return reports


def _verdict_counts(
    case_ids: Iterable[str],
    outcomes: dict[tuple[str, int], dict[str, Any]],
    runs_per_case: int,
) -> dict[str, int]:
    identifiers = tuple(case_ids)
    return {
        verdict: sum(
            outcomes[(case_id, run_id)]["verdict"] == verdict
            for case_id in identifiers
            for run_id in range(1, runs_per_case + 1)
        )
        for verdict in _VERDICTS
    }


def _repeatability(
    cases: dict[str, dict[str, Any]],
    outcomes: dict[tuple[str, int], dict[str, Any]],
    runs_per_case: int,
) -> dict[str, Any]:
    error_cases = [
        case_id
        for case_id in cases
        if any(
            outcomes[(case_id, run_id)]["verdict"] == "ERROR"
            for run_id in range(1, runs_per_case + 1)
        )
    ]
    evaluable_case_ids = [case_id for case_id in cases if case_id not in error_cases]
    if runs_per_case < 2 or not evaluable_case_ids:
        return {
            "runs_per_case": runs_per_case,
            "evaluable": False,
            "cases": len(cases),
            "evaluable_cases": 0,
            "error_cases": len(error_cases),
            "unanimous_cases": None,
            "unanimous_rate": None,
            "verdict_agreement": None,
        }
    modal_total = 0
    unanimous_cases = 0
    for case_id in evaluable_case_ids:
        counts = {
            verdict: sum(
                outcomes[(case_id, run_id)]["verdict"] == verdict
                for run_id in range(1, runs_per_case + 1)
            )
            for verdict in _VERDICTS
        }
        modal_count = max(counts.values())
        modal_total += modal_count
        unanimous_cases += modal_count == runs_per_case
    return {
        "runs_per_case": runs_per_case,
        "evaluable": True,
        "cases": len(cases),
        "evaluable_cases": len(evaluable_case_ids),
        "error_cases": len(error_cases),
        "unanimous_cases": unanimous_cases,
        "unanimous_rate": round(unanimous_cases / len(evaluable_case_ids), 6),
        "verdict_agreement": round(
            modal_total / (len(evaluable_case_ids) * runs_per_case), 6
        ),
    }


def _read_bounded(path: Path) -> bytes:
    parent = path.parent.resolve(strict=True)
    parent_fd = _open_directory_path(parent)
    try:
        return _read_bounded_at(parent_fd, path.name, str(path))
    finally:
        os.close(parent_fd)


def _read_bounded_at(directory_fd: int, name: str, label: str) -> bytes:
    if not name or Path(name).name != name:
        raise BenchmarkError(f"benchmark input name is invalid: {label}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BenchmarkError(f"benchmark input must be a regular file: {label}")
        if before.st_size > _MAX_INPUT_BYTES:
            raise BenchmarkError(f"benchmark input exceeds 16 MiB: {label}")
        raw = bytearray()
        while chunk := os.read(
            descriptor, min(1024 * 1024, _MAX_INPUT_BYTES + 1 - len(raw))
        ):
            raw.extend(chunk)
            if len(raw) > _MAX_INPUT_BYTES:
                raise BenchmarkError(f"benchmark input exceeds 16 MiB: {label}")
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
        if len(raw) != after.st_size or identity_before != identity_after:
            raise BenchmarkError(f"benchmark input changed while reading: {label}")
        return bytes(raw)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_directory_path(path: Path) -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise BenchmarkError("safe benchmark directory access is unsupported")
    absolute = Path(path)
    if not absolute.is_absolute():
        raise BenchmarkError("benchmark directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    current = os.open(os.path.sep, flags)
    try:
        for component in absolute.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _open_relative_directory(root_fd: int, relative: PurePosixPath) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    current = os.dup(root_fd)
    try:
        for component in relative.parts:
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _decode_json(raw: bytes, label: str) -> object:
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BenchmarkError(f"invalid {label} JSON: {exc}") from exc


def _decode_json_lines(raw: bytes) -> tuple[object, ...]:
    records = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line) > 1024 * 1024:
            raise BenchmarkError(f"outcome line {line_number} exceeds 1 MiB")
        records.append(_decode_json(line, f"outcome line {line_number}"))
    return tuple(records)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise BenchmarkError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> None:
    raise BenchmarkError(f"non-finite JSON number is unsupported: {value}")


def _exact_keys(document: dict[str, Any], expected: set[str], label: str) -> None:
    if set(document) != expected:
        raise BenchmarkError(f"{label} has missing or unknown fields")


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise BenchmarkError(f"{label} must be a canonical lowercase identifier")
    return value


def _canonical_string(value: object, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\r" in value
        or "\n" in value
        or len(value) > maximum
    ):
        raise BenchmarkError(f"{label} must be a canonical non-empty string")
    return value


def _reason_code(value: object, label: str) -> str:
    if not isinstance(value, str) or _REASON_CODE.fullmatch(value) is None:
        raise BenchmarkError(f"{label} must contain canonical reason codes")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise BenchmarkError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _relative_path(value: object, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise BenchmarkError(f"{label} must be a relative POSIX path")
    path = PurePosixPath(value)
    if (
        not path.parts
        or path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise BenchmarkError(f"{label} escapes the suite directory")
    return path


def _paths_overlap(first: PurePosixPath, second: PurePosixPath) -> bool:
    shorter, longer = sorted((first.parts, second.parts), key=len)
    return longer[: len(shorter)] == shorter


def _system_key(system: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        system["name"],
        system["version"],
        system["implementation_digest"],
        system["config_digest"],
    )


def _digest_json(value: object) -> str:
    return _digest_bytes(_canonical_json_bytes(value))


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _digest_bytes(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


if __name__ == "__main__":
    raise SystemExit(main())
