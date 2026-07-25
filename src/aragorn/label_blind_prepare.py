"""Prepare label-blind filesystem jobs without launching a worker."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import stat
import sys
import unicodedata
from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from secrets import token_hex as _token_hex
from typing import Any

from .benchmark import BenchmarkError, load_suite_for_run
from .benchmark_authenticated_handoff_v2 import (
    issue_worker_measurement_challenge,
)
from .benchmark_handoff_v2 import (
    build_worker_input_handoff_manifest,
    export_handoff,
)
from .benchmark_protocol_v2 import (
    build_portable_policy,
    build_worker_request_v2,
    canonical_request_digest_v2,
    portable_policy_digest,
)
from .cas import CAS, CASError
from .oci_runtime import LOCK, VerificationError, load_baseline_lock
from .oci_worker_protocol import (
    WorkerProtocolError,
    build_worker_request,
    canonical_json,
    canonical_request_digest,
    sanitize_subject_manifest,
    subject_manifest_digest,
    validate_subject_manifest,
    validate_worker_request,
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_MAX_JOBS = 200_000
_MAX_IDENTITY_BYTES = 64 * 1024
_TIMEOUT_SECONDS = 120.0
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_JOB_KEYS = {
    "job_id",
    "request_digest",
    "suite_digest",
    "case_id",
    "run_id",
    "system",
    "tree_digest",
    "private_manifest_digest",
}
_SYSTEM_KEYS = {
    "name",
    "version",
    "implementation_digest",
    "config_digest",
}
_WORKLIST_JOB_KEYS = {"job_id", "request_digest"}
_DISPATCH_CASE_KEYS = {
    "case_id",
    "tree_digest",
    "private_manifest_digest",
}


class PrepareError(ValueError):
    """A label-blind filesystem bundle could not be prepared safely."""


def prepare_files_v2(
    suite_path: str | os.PathLike[str],
    *,
    portable_policies: Sequence[object],
    candidate_policy: object | None = None,
    trust_domain: str,
    worker_id: str,
    challenge_ledger: str | os.PathLike[str],
    control_state: str | os.PathLike[str],
    jobs_root: str | os.PathLike[str],
    lock_path: str | os.PathLike[str] = LOCK,
) -> dict[str, Any]:
    """Prepare one cross-owner-capable protocol-v2 benchmark batch."""

    suite_file = _input_file(suite_path, "benchmark suite")
    lock_file = _input_file(lock_path, "baseline lock")
    control_root = _output_path(control_state, "control CAS")
    job_root = _output_path(jobs_root, "jobs root")
    ledger_root = _output_path(challenge_ledger, "challenge ledger")
    _validate_v2_path_separation(
        suite_file=suite_file,
        lock_file=lock_file,
        control_root=control_root,
        jobs_root=job_root,
        ledger_root=ledger_root,
    )
    if candidate_policy is not None:
        if os.path.lexists(control_root):
            raise PrepareError(
                "candidate composition requires a fresh control CAS"
            )
        _require_real_directory(control_root.parent, "control CAS parent")
    for path, label in (
        (job_root, "jobs root"),
        (ledger_root, "challenge ledger"),
    ):
        if os.path.lexists(path):
            raise PrepareError(f"{label} already exists: {path}")
        _require_real_directory(path.parent, f"{label} parent")

    control_cas = CAS(control_root)
    loaded = load_suite_for_run(
        suite_file,
        control_cas,
        required_purpose="evidence_smoke",
    )
    worker_systems = loaded["systems"]
    candidate_system: dict[str, str] | None = None
    candidate_policy_digest: str | None = None
    canonical_candidate_policy: dict[str, Any] | None = None
    if candidate_policy is not None:
        from .phase0_candidate import (
            build_candidate_policy,
            candidate_system_identity,
        )
        from .phase0_candidate import (
            candidate_policy_digest as digest_candidate_policy,
        )

        canonical_candidate_policy = build_candidate_policy(candidate_policy)
        candidate_policy_digest = digest_candidate_policy(
            canonical_candidate_policy
        )
        candidate_system = candidate_system_identity(
            canonical_candidate_policy
        )
        matches = [
            key
            for key, system in loaded["systems"].items()
            if system["name"] == "aragorn"
        ]
        if len(matches) != 1 or loaded["systems"][matches[0]] != candidate_system:
            raise PrepareError(
                "suite Aragorn identity does not match the candidate policy"
            )
        worker_systems = {
            key: system
            for key, system in loaded["systems"].items()
            if system["name"] != "aragorn"
        }
        if sorted(
            worker_systems.values(),
            key=lambda system: system["name"],
        ) != canonical_candidate_policy["required_comparators"]:
            raise PrepareError(
                "suite comparator identities do not match the candidate policy"
            )
    elif any(
        system["name"] == "aragorn" for system in loaded["systems"].values()
    ):
        raise PrepareError("suite Aragorn identity requires a candidate policy")

    raw_lock, baselines = load_baseline_lock(lock_file)
    lock_digest = _put_bytes(control_cas, raw_lock)
    baseline_digests = {
        baseline["name"]: _put_json(control_cas, baseline)
        for baseline in baselines
    }
    policies = _bind_portable_policies(
        worker_systems,
        portable_policies,
        baselines=baselines,
        lock_digest=lock_digest,
        baseline_digests=baseline_digests,
    )
    policy_digests = {
        name: _put_json(control_cas, policy)
        for name, policy in policies.items()
    }
    if canonical_candidate_policy is not None:
        retained_candidate_policy_digest = _put_json(
            control_cas,
            canonical_candidate_policy,
        )
        if retained_candidate_policy_digest != candidate_policy_digest:
            raise PrepareError("candidate policy changed during retention")

    private_manifest_digests = {
        case_id: _put_json(control_cas, manifest)
        for case_id, manifest in loaded["manifests"].items()
    }
    sanitized_manifests = {
        case_id: sanitize_subject_manifest(manifest)
        for case_id, manifest in loaded["manifests"].items()
    }
    for subject in sanitized_manifests.values():
        _copy_subject_closure(control_cas, control_cas, subject)

    identities = {
        "schema": "aragorn/benchmark-system-identities/v1",
        "systems": [
            dict(worker_systems[key])
            for key in sorted(worker_systems)
        ],
    }
    identities_digest = _put_json(control_cas, identities)

    _create_private_directory(job_root, "jobs root")
    completed = False
    ledger_owned = False
    try:
        _create_private_directory(ledger_root, "challenge ledger")
        ledger_owned = True
        entries: list[dict[str, Any]] = []
        job_ids: set[str] = set()
        challenges: set[str] = set()
        for system_key in sorted(worker_systems):
            system = worker_systems[system_key]
            policy = policies[system["name"]]
            if policy_digests[system["name"]] != _put_json(control_cas, policy):
                raise PrepareError("portable policy changed during retention")
            for case_id in sorted(loaded["cases"]):
                manifest = loaded["manifests"][case_id]
                subject = sanitized_manifests[case_id]
                for run_id in range(1, loaded["runs_per_case"] + 1):
                    challenge = _token_hex(32)
                    request = build_worker_request_v2(
                        subject,
                        policy,
                        verifier_challenge=challenge,
                        token_hex=_token_hex,
                    )
                    job_id = request["job_id"]
                    if job_id in job_ids or challenge in challenges:
                        raise PrepareError("duplicate cryptographic job randomness")
                    job_ids.add(job_id)
                    challenges.add(challenge)
                    request_digest = _put_json(control_cas, request)
                    if request_digest != canonical_request_digest_v2(request):
                        raise PrepareError("canonical worker request changed")

                    job_directory = job_root / job_id
                    _create_private_directory(job_directory, "job directory")
                    input_manifest = build_worker_input_handoff_manifest(
                        control_cas,
                        request_digest,
                        expected_verifier_challenge=challenge,
                    )
                    input_manifest_digest = export_handoff(
                        control_cas,
                        input_manifest,
                        job_directory / "input-bundle",
                        expected_verifier_challenge=challenge,
                    )
                    _write_canonical_request(
                        job_directory,
                        canonical_json(request),
                    )
                    _write_read_only_file(
                        job_directory,
                        "input-manifest-digest.txt",
                        input_manifest_digest.encode("ascii") + b"\n",
                        "worker input manifest digest",
                    )
                    issue_worker_measurement_challenge(
                        ledger_root,
                        trust_domain=trust_domain,
                        worker_id=worker_id,
                        job_id=job_id,
                        request_digest=request_digest,
                        verifier_challenge=challenge,
                    )
                    entries.append(
                        {
                            "job_id": job_id,
                            "request_digest": request_digest,
                            "suite_digest": loaded["digest"],
                            "case_id": case_id,
                            "run_id": run_id,
                            "system": dict(system),
                            "tree_digest": manifest["tree_digest"],
                            "private_manifest_digest": private_manifest_digests[
                                case_id
                            ],
                        }
                    )

        expected_jobs = (
            len(worker_systems)
            * len(loaded["cases"])
            * loaded["runs_per_case"]
        )
        if len(entries) != expected_jobs:
            raise PrepareError("prepared job matrix is incomplete")
        if candidate_system is None:
            dispatch = {
                "schema": "aragorn/benchmark-private-dispatch/v1",
                "jobs": sorted(entries, key=lambda entry: entry["job_id"]),
            }
            validate_private_dispatch(dispatch)
        else:
            assert candidate_policy_digest is not None
            dispatch = {
                "schema": "aragorn/benchmark-private-dispatch/v2",
                "suite_digest": loaded["digest"],
                "candidate_system": candidate_system,
                "candidate_policy_digest": candidate_policy_digest,
                "runs_per_case": loaded["runs_per_case"],
                "cases": [
                    {
                        "case_id": case_id,
                        "tree_digest": loaded["cases"][case_id]["tree_digest"],
                        "private_manifest_digest": private_manifest_digests[case_id],
                    }
                    for case_id in sorted(loaded["cases"])
                ],
                "jobs": sorted(entries, key=lambda entry: entry["job_id"]),
            }
            validate_private_dispatch_v2(dispatch)
        dispatch_digest = _put_json(control_cas, dispatch)
        worklist = {
            "schema": "aragorn/benchmark-worker-worklist/v1",
            "jobs": [
                {
                    "job_id": entry["job_id"],
                    "request_digest": entry["request_digest"],
                }
                for entry in dispatch["jobs"]
            ],
        }
        validate_worker_worklist(worklist)
        worklist_raw = canonical_json(worklist)
        worklist_digest = _put_bytes(control_cas, worklist_raw)
        _write_read_only_file(
            job_root,
            "worklist.json",
            worklist_raw,
            "worker worklist",
        )
        completed = True
        result = {
            "schema": (
                "aragorn/benchmark-prepare-result/v1"
                if candidate_system is None
                else "aragorn/benchmark-prepare-result/v2"
            ),
            "suite_digest": loaded["digest"],
            "dispatch_digest": dispatch_digest,
            "worker_identities_digest": identities_digest,
            "worklist_digest": worklist_digest,
            "job_count": len(entries),
        }
        if candidate_policy_digest is not None:
            result["candidate_policy_digest"] = candidate_policy_digest
        return result
    finally:
        if not completed:
            shutil.rmtree(job_root, ignore_errors=True)
            if ledger_owned:
                shutil.rmtree(ledger_root, ignore_errors=True)


def prepare_files(
    suite_path: str | os.PathLike[str],
    *,
    worker_identities: str | os.PathLike[str],
    control_state: str | os.PathLike[str],
    jobs_root: str | os.PathLike[str],
    lock_path: str | os.PathLike[str] = LOCK,
) -> dict[str, Any]:
    """Create one fresh label-free filesystem job for every suite matrix cell."""

    suite_file = _input_file(suite_path, "benchmark suite")
    lock_file = _input_file(lock_path, "baseline lock")
    identities_file = _input_file(worker_identities, "worker identities")
    control_root = _output_path(control_state, "control CAS")
    job_root = _output_path(jobs_root, "jobs root")
    _validate_path_separation(
        suite_file=suite_file,
        lock_file=lock_file,
        identities_file=identities_file,
        control_root=control_root,
        jobs_root=job_root,
    )
    if os.path.lexists(job_root):
        raise PrepareError(f"jobs root already exists: {job_root}")
    _require_real_directory(job_root.parent, "jobs root parent")

    control_cas = CAS(control_root)
    loaded = load_suite_for_run(
        suite_file,
        control_cas,
        required_purpose="evidence_smoke",
    )
    raw_lock, baselines = load_baseline_lock(lock_file)
    identities = _load_worker_identities(identities_file)
    identities_digest = _put_json(control_cas, identities)
    lock_digest = _put_bytes(control_cas, raw_lock)
    baseline_digests = {
        baseline["name"]: _put_json(control_cas, baseline)
        for baseline in baselines
    }
    systems = _bind_locked_systems(
        loaded["systems"],
        baselines,
        identities["systems"],
    )

    suite_digest = _put_json(control_cas, loaded["canonical"])
    if suite_digest != loaded["digest"]:
        raise PrepareError("canonical suite digest changed during retention")
    private_manifest_digests = {
        case_id: _put_json(control_cas, manifest)
        for case_id, manifest in loaded["manifests"].items()
    }
    sanitized_manifests = {
        case_id: sanitize_subject_manifest(manifest)
        for case_id, manifest in loaded["manifests"].items()
    }

    _create_private_directory(job_root, "jobs root")
    completed = False
    try:
        entries: list[dict[str, Any]] = []
        job_ids: set[str] = set()
        nonces: set[str] = set()
        for system in systems:
            baseline_entry_digest = baseline_digests[system["name"]]
            for case_id in sorted(loaded["cases"]):
                manifest = loaded["manifests"][case_id]
                subject = sanitized_manifests[case_id]
                for run_id in range(1, loaded["runs_per_case"] + 1):
                    request = build_worker_request(
                        subject,
                        system,
                        baseline_lock_digest=lock_digest,
                        baseline_entry_digest=baseline_entry_digest,
                        timeout_seconds=_TIMEOUT_SECONDS,
                        output_limit_bytes=_OUTPUT_LIMIT_BYTES,
                        token_hex=_token_hex,
                    )
                    validate_worker_request(request)
                    job_id = request["job_id"]
                    nonce = request["nonce"]
                    if job_id in job_ids or nonce in nonces:
                        raise PrepareError("duplicate cryptographic job randomness")
                    job_ids.add(job_id)
                    nonces.add(nonce)

                    job_directory = job_root / job_id
                    _create_private_directory(job_directory, "job directory")
                    input_cas = CAS(job_directory / "input")
                    _copy_subject_closure(control_cas, input_cas, subject)
                    request_digest = canonical_request_digest(request)
                    _write_canonical_request(
                        job_directory,
                        canonical_json(request),
                    )
                    entries.append(
                        {
                            "job_id": job_id,
                            "request_digest": request_digest,
                            "suite_digest": loaded["digest"],
                            "case_id": case_id,
                            "run_id": run_id,
                            "system": dict(system),
                            "tree_digest": manifest["tree_digest"],
                            "private_manifest_digest": private_manifest_digests[
                                case_id
                            ],
                        }
                    )

        expected_jobs = (
            len(systems) * len(loaded["cases"]) * loaded["runs_per_case"]
        )
        if len(entries) != expected_jobs:
            raise PrepareError("prepared job matrix is incomplete")
        dispatch = {
            "schema": "aragorn/benchmark-private-dispatch/v1",
            "jobs": sorted(entries, key=lambda entry: entry["job_id"]),
        }
        validate_private_dispatch(dispatch)
        dispatch_digest = _put_json(control_cas, dispatch)
        worklist = {
            "schema": "aragorn/benchmark-worker-worklist/v1",
            "jobs": [
                {
                    "job_id": entry["job_id"],
                    "request_digest": entry["request_digest"],
                }
                for entry in dispatch["jobs"]
            ],
        }
        validate_worker_worklist(worklist)
        worklist_raw = canonical_json(worklist)
        worklist_digest = _put_bytes(control_cas, worklist_raw)
        _write_read_only_file(
            job_root,
            "worklist.json",
            worklist_raw,
            "worker worklist",
        )
        completed = True
        return {
            "schema": "aragorn/benchmark-prepare-result/v1",
            "suite_digest": loaded["digest"],
            "dispatch_digest": dispatch_digest,
            "worker_identities_digest": identities_digest,
            "worklist_digest": worklist_digest,
            "job_count": len(entries),
        }
    finally:
        if not completed:
            shutil.rmtree(job_root, ignore_errors=True)


def validate_private_dispatch(document: object) -> None:
    """Validate the private control-plane mapping for one prepared batch."""

    dispatch = _exact_object(
        document,
        {"schema", "jobs"},
        "private dispatch",
    )
    if dispatch["schema"] != "aragorn/benchmark-private-dispatch/v1":
        raise PrepareError("private dispatch schema is unsupported")
    jobs = dispatch["jobs"]
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= _MAX_JOBS:
        raise PrepareError("private dispatch jobs must be a bounded array")

    job_ids: set[str] = set()
    requests: set[str] = set()
    matrix: set[tuple[tuple[str, str, str, str], str, int]] = set()
    suite_digests: set[str] = set()
    normalized_ids: list[str] = []
    for index, raw_entry in enumerate(jobs):
        label = f"private dispatch jobs[{index}]"
        entry = _exact_object(raw_entry, _JOB_KEYS, label)
        job_id = _hex(entry["job_id"], _JOB_ID, f"{label}.job_id")
        request_digest = _digest(
            entry["request_digest"], f"{label}.request_digest"
        )
        suite_digest = _digest(entry["suite_digest"], f"{label}.suite_digest")
        case_id = _identifier(entry["case_id"], f"{label}.case_id")
        run_id = entry["run_id"]
        if (
            isinstance(run_id, bool)
            or not isinstance(run_id, int)
            or not 1 <= run_id <= 10
        ):
            raise PrepareError(f"{label}.run_id is outside the bounded range")
        system = _system(entry["system"], f"{label}.system")
        _digest(entry["tree_digest"], f"{label}.tree_digest")
        _digest(
            entry["private_manifest_digest"],
            f"{label}.private_manifest_digest",
        )

        system_key = (
            system["name"],
            system["version"],
            system["implementation_digest"],
            system["config_digest"],
        )
        matrix_key = (system_key, case_id, run_id)
        if job_id in job_ids:
            raise PrepareError("private dispatch repeats a job_id")
        if request_digest in requests:
            raise PrepareError("private dispatch repeats a request_digest")
        if matrix_key in matrix:
            raise PrepareError("private dispatch repeats a matrix cell")
        job_ids.add(job_id)
        requests.add(request_digest)
        matrix.add(matrix_key)
        suite_digests.add(suite_digest)
        normalized_ids.append(job_id)
    if len(suite_digests) != 1:
        raise PrepareError("private dispatch spans multiple suites")
    if normalized_ids != sorted(normalized_ids):
        raise PrepareError("private dispatch jobs must be sorted by job_id")


def validate_private_dispatch_v2(document: object) -> None:
    """Validate a comparator-only dispatch with one derived Aragorn identity."""

    dispatch = _exact_object(
        document,
        {
            "schema",
            "suite_digest",
            "candidate_system",
            "candidate_policy_digest",
            "runs_per_case",
            "cases",
            "jobs",
        },
        "private dispatch v2",
    )
    if dispatch["schema"] != "aragorn/benchmark-private-dispatch/v2":
        raise PrepareError("private dispatch v2 schema is unsupported")
    suite_digest = _digest(
        dispatch["suite_digest"],
        "private dispatch v2 suite_digest",
    )
    policy_digest = _digest(
        dispatch["candidate_policy_digest"],
        "private dispatch v2 candidate_policy_digest",
    )
    candidate = _system(
        dispatch["candidate_system"],
        "private dispatch v2 candidate_system",
    )
    if candidate["name"] != "aragorn":
        raise PrepareError("private dispatch v2 candidate must be Aragorn")
    if candidate["config_digest"] != policy_digest:
        raise PrepareError(
            "private dispatch v2 candidate config does not match its policy"
        )
    runs_per_case = dispatch["runs_per_case"]
    if (
        isinstance(runs_per_case, bool)
        or not isinstance(runs_per_case, int)
        or not 1 <= runs_per_case <= 10
    ):
        raise PrepareError("private dispatch v2 runs_per_case is invalid")
    raw_cases = dispatch["cases"]
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 10_000:
        raise PrepareError("private dispatch v2 cases must be a bounded array")
    cases: dict[str, dict[str, str]] = {}
    ordered_case_ids: list[str] = []
    for index, raw_case in enumerate(raw_cases):
        label = f"private dispatch v2 cases[{index}]"
        case = _exact_object(raw_case, _DISPATCH_CASE_KEYS, label)
        case_id = _identifier(case["case_id"], f"{label}.case_id")
        if case_id in cases:
            raise PrepareError("private dispatch v2 repeats a case")
        cases[case_id] = {
            "tree_digest": _digest(case["tree_digest"], f"{label}.tree_digest"),
            "private_manifest_digest": _digest(
                case["private_manifest_digest"],
                f"{label}.private_manifest_digest",
            ),
        }
        ordered_case_ids.append(case_id)
    if ordered_case_ids != sorted(ordered_case_ids):
        raise PrepareError("private dispatch v2 cases must be sorted by case_id")
    validate_private_dispatch(
        {
            "schema": "aragorn/benchmark-private-dispatch/v1",
            "jobs": dispatch["jobs"],
        }
    )
    if any(
        entry["suite_digest"] != suite_digest
        for entry in dispatch["jobs"]
    ):
        raise PrepareError("private dispatch v2 job suite digest does not match")
    if any(
        entry["system"]["name"] == "aragorn"
        for entry in dispatch["jobs"]
    ):
        raise PrepareError("private dispatch v2 cannot dispatch Aragorn to a worker")
    systems = {
        (
            entry["system"]["name"],
            entry["system"]["version"],
            entry["system"]["implementation_digest"],
            entry["system"]["config_digest"],
        )
        for entry in dispatch["jobs"]
    }
    if {system[0] for system in systems} != {
        "cisco-skill-scanner",
        "skillspector",
    } or len(systems) != 2:
        raise PrepareError(
            "private dispatch v2 requires the exact two comparator systems"
        )
    actual_matrix = set()
    for entry in dispatch["jobs"]:
        case = cases.get(entry["case_id"])
        if case is None or any(
            entry[field] != case[field]
            for field in ("tree_digest", "private_manifest_digest")
        ):
            raise PrepareError(
                "private dispatch v2 job does not match its declared case"
            )
        actual_matrix.add(
            (
                (
                    entry["system"]["name"],
                    entry["system"]["version"],
                    entry["system"]["implementation_digest"],
                    entry["system"]["config_digest"],
                ),
                entry["case_id"],
                entry["run_id"],
            )
        )
    expected_matrix = {
        (system, case_id, run_id)
        for system in systems
        for case_id in cases
        for run_id in range(1, runs_per_case + 1)
    }
    if actual_matrix != expected_matrix:
        raise PrepareError("private dispatch v2 job matrix is incomplete")


def validate_worker_worklist(document: object) -> None:
    """Validate the label-free scheduling surface emitted beside worker jobs."""

    worklist = _exact_object(document, {"schema", "jobs"}, "worker worklist")
    if worklist["schema"] != "aragorn/benchmark-worker-worklist/v1":
        raise PrepareError("worker worklist schema is unsupported")
    jobs = worklist["jobs"]
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= _MAX_JOBS:
        raise PrepareError("worker worklist jobs must be a bounded array")
    ordered_job_ids: list[str] = []
    job_ids: set[str] = set()
    requests: set[str] = set()
    for index, raw_job in enumerate(jobs):
        label = f"worker worklist jobs[{index}]"
        job = _exact_object(raw_job, _WORKLIST_JOB_KEYS, label)
        job_id = _hex(job["job_id"], _JOB_ID, f"{label}.job_id")
        request_digest = _digest(
            job["request_digest"], f"{label}.request_digest"
        )
        if job_id in job_ids or request_digest in requests:
            raise PrepareError("worker worklist repeats a job binding")
        job_ids.add(job_id)
        ordered_job_ids.append(job_id)
        requests.add(request_digest)
    if ordered_job_ids != sorted(ordered_job_ids):
        raise PrepareError("worker worklist jobs must be sorted by job_id")


def _bind_locked_systems(
    systems: dict[tuple[str, str, str, str], dict[str, str]],
    baselines: tuple[dict[str, Any], ...],
    worker_identities: list[dict[str, str]],
) -> tuple[dict[str, str], ...]:
    locked = {baseline["name"]: baseline for baseline in baselines}
    workers = {identity["name"]: identity for identity in worker_identities}
    selected: dict[str, dict[str, str]] = {}
    for system in systems.values():
        name = system["name"]
        if name in selected:
            raise PrepareError("suite repeats a locked baseline name")
        baseline = locked.get(name)
        if baseline is None:
            raise PrepareError("suite system set does not match the baseline lock")
        expected = (
            baseline["name"],
            baseline["version"],
            baseline["image"]["platform_manifest_digest"],
        )
        actual = (
            system["name"],
            system["version"],
            system["implementation_digest"],
        )
        if actual != expected:
            raise PrepareError(
                f"suite system identity does not match baseline lock: {name}"
            )
        if workers.get(name) != system:
            raise PrepareError(
                f"suite system identity does not match worker identities: {name}"
            )
        selected[name] = dict(system)
    if set(selected) != set(locked) or set(selected) != set(workers):
        raise PrepareError("suite system set does not match the baseline lock")
    return tuple(selected[name] for name in sorted(selected))


def _bind_portable_policies(
    systems: dict[tuple[str, str, str, str], dict[str, str]],
    portable_policies: Sequence[object],
    *,
    baselines: tuple[dict[str, Any], ...],
    lock_digest: str,
    baseline_digests: dict[str, str],
) -> dict[str, dict[str, Any]]:
    if isinstance(portable_policies, (str, bytes)) or not isinstance(
        portable_policies, Sequence
    ):
        raise PrepareError("portable policies must be a bounded sequence")
    if not 1 <= len(portable_policies) <= 32:
        raise PrepareError("portable policies must be a bounded sequence")
    policies: dict[str, dict[str, Any]] = {}
    for raw_policy in portable_policies:
        policy = build_portable_policy(raw_policy)
        name = policy["system"]["name"]
        if name in policies:
            raise PrepareError("portable policies repeat a system")
        policies[name] = policy

    locked = {baseline["name"]: baseline for baseline in baselines}
    selected = {system["name"]: system for system in systems.values()}
    if (
        len(selected) != len(systems)
        or set(selected) != set(locked)
        or set(selected) != set(policies)
    ):
        raise PrepareError(
            "suite, portable policy, and baseline system sets do not match"
        )
    for name, system in selected.items():
        baseline = locked[name]
        policy = policies[name]
        expected_identity = {
            "name": baseline["name"],
            "version": baseline["version"],
            "implementation_digest": baseline["image"][
                "platform_manifest_digest"
            ],
        }
        if policy["system"] != expected_identity or {
            field: system[field]
            for field in ("name", "version", "implementation_digest")
        } != expected_identity:
            raise PrepareError(
                f"portable policy identity does not match suite and lock: {name}"
            )
        if system["config_digest"] != portable_policy_digest(policy):
            raise PrepareError(
                f"suite config identity does not match portable policy: {name}"
            )
        if policy["baseline"] != {
            "lock_digest": lock_digest,
            "entry_digest": baseline_digests[name],
        }:
            raise PrepareError(
                f"portable policy baseline binding does not match lock: {name}"
            )
        expected_image = {
            field: baseline["image"][field]
            for field in (
                "index_digest",
                "platform_manifest_digest",
                "config_digest",
                "build_provenance_manifest_digest",
                "os",
                "architecture",
                "size_bytes",
            )
        }
        if policy["image"] != expected_image:
            raise PrepareError(
                f"portable policy image binding does not match lock: {name}"
            )
        expected_arguments = [
            "/workspace" if value == "{workspace}" else value
            for value in baseline["profile"]["arguments"]
        ]
        if (
            policy["arguments"] != expected_arguments
            or policy["environment"] != baseline["profile"]["environment"]
            or policy["runtime_profile"] != baseline["runtime_profile"]
        ):
            raise PrepareError(
                f"portable policy execution profile does not match lock: {name}"
            )
    return {name: policies[name] for name in sorted(policies)}


def _load_worker_identities(path: Path) -> dict[str, Any]:
    raw = _read_stable_file(
        path,
        max_bytes=_MAX_IDENTITY_BYTES,
        label="worker identities",
    )
    payload = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        document = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
        _finite(document)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise PrepareError(f"invalid worker identities JSON: {exc}") from exc
    identities = _exact_object(
        document,
        {"schema", "systems"},
        "worker identities",
    )
    if identities["schema"] != "aragorn/benchmark-system-identities/v1":
        raise PrepareError("worker identities schema is unsupported")
    systems = identities["systems"]
    if not isinstance(systems, list) or not 1 <= len(systems) <= 32:
        raise PrepareError("worker identities systems must be a bounded array")
    normalized = [
        _system(system, f"worker identities systems[{index}]")
        for index, system in enumerate(systems)
    ]
    names = [system["name"] for system in normalized]
    if len(names) != len(set(names)):
        raise PrepareError("worker identities repeat a system name")
    if names != sorted(names):
        raise PrepareError("worker identities systems must be sorted by name")
    result = {
        "schema": identities["schema"],
        "systems": normalized,
    }
    if canonical_json(result) != payload:
        raise PrepareError("worker identities must be canonical JSON")
    return result


def _copy_subject_closure(
    source: CAS,
    destination: CAS,
    subject: dict[str, Any],
) -> None:
    validate_subject_manifest(subject)
    manifest_digest = _put_json(destination, subject)
    if manifest_digest != subject_manifest_digest(subject):
        raise PrepareError("sanitized subject manifest digest changed")
    retained = {manifest_digest}
    for entry in subject["files"]:
        content = source.read(entry["digest"], max_bytes=entry["size"])
        if len(content) != entry["size"]:
            raise PrepareError(
                f"subject blob size does not match manifest: {entry['path']}"
            )
        digest = _put_bytes(destination, content)
        if digest != entry["digest"]:
            raise PrepareError(
                f"subject blob digest does not match manifest: {entry['path']}"
            )
        retained.add(digest)
    for digest in retained:
        destination.verify(digest)


def _write_canonical_request(job_directory: Path, content: bytes) -> None:
    _write_read_only_file(
        job_directory,
        "request.json",
        content,
        "canonical worker request",
    )


def _write_read_only_file(
    directory: Path,
    filename: str,
    content: bytes,
    label: str,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    directory_descriptor = -1
    try:
        directory_descriptor = os.open(
            directory,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor = os.open(
            filename,
            flags,
            0o400,
            dir_fd=directory_descriptor,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            descriptor = -1
            output.write(content)
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
        os.fsync(directory_descriptor)
    except OSError as exc:
        raise PrepareError(f"cannot write {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_descriptor >= 0:
            os.close(directory_descriptor)


def _put_json(cas: CAS, document: object) -> str:
    return _put_bytes(cas, canonical_json(document))


def _put_bytes(cas: CAS, content: bytes) -> str:
    return cas.put(BytesIO(content), max_bytes=len(content))


def _input_file(value: str | os.PathLike[str], label: str) -> Path:
    supplied = _absolute_path(value)
    _reject_operator_symlinks(supplied)
    try:
        path = supplied.resolve(strict=True)
        metadata = os.lstat(path)
    except OSError as exc:
        raise PrepareError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise PrepareError(f"{label} must be a regular file")
    return path


def _read_stable_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PrepareError(f"{label} must be a regular file")
        if before.st_size > max_bytes:
            raise PrepareError(f"{label} exceeds {max_bytes} bytes")
        with os.fdopen(descriptor, "rb", closefd=True) as source:
            descriptor = -1
            raw = source.read(max_bytes + 1)
            after = os.fstat(source.fileno())
        if len(raw) > max_bytes or len(raw) != before.st_size:
            raise PrepareError(f"{label} changed while it was read")
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise PrepareError(f"{label} changed while it was read")
        return raw
    except PrepareError:
        raise
    except OSError as exc:
        raise PrepareError(f"cannot read {label}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _output_path(value: str | os.PathLike[str], label: str) -> Path:
    supplied = _absolute_path(value)
    _reject_operator_symlinks(supplied)
    try:
        path = supplied.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise PrepareError(f"cannot resolve {label}: {exc}") from exc
    if path == Path(path.anchor):
        raise PrepareError(f"{label} must not be a filesystem root")
    return path


def _absolute_path(value: str | os.PathLike[str]) -> Path:
    try:
        return Path(os.path.abspath(os.path.expanduser(os.fspath(value))))
    except (TypeError, ValueError, OSError) as exc:
        raise PrepareError(f"invalid filesystem path: {exc}") from exc


def _reject_operator_symlinks(path: Path) -> None:
    current = Path(path.anchor)
    try:
        controlled = _writable_by_current_user(os.lstat(current))
    except OSError as exc:
        raise PrepareError(f"cannot inspect filesystem path {current}: {exc}") from exc
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PrepareError(
                f"cannot inspect filesystem path {current}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode) and controlled:
            raise PrepareError(f"filesystem path must not use a symlink: {current}")
        if stat.S_ISDIR(metadata.st_mode) and _writable_by_current_user(metadata):
            controlled = True


def _writable_by_current_user(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid == os.geteuid():
        return bool(mode & stat.S_IWUSR)
    if metadata.st_gid in {os.getegid(), *os.getgroups()}:
        return bool(mode & stat.S_IWGRP)
    return bool(mode & stat.S_IWOTH)


def _require_real_directory(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise PrepareError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise PrepareError(f"{label} must be a directory")


def _create_private_directory(path: Path, label: str) -> None:
    created = False
    try:
        os.mkdir(path, mode=0o700)
        created = True
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fchmod(descriptor, 0o700)
            metadata = os.fstat(descriptor)
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise PrepareError(f"{label} is not private")
        finally:
            os.close(descriptor)
    except FileExistsError as exc:
        raise PrepareError(f"{label} already exists: {path}") from exc
    except OSError as exc:
        if created:
            try:
                os.rmdir(path)
            except OSError:
                pass
        raise PrepareError(f"cannot create {label}: {exc}") from exc
    except PrepareError:
        if created:
            try:
                os.rmdir(path)
            except OSError:
                pass
        raise


def _validate_path_separation(
    *,
    suite_file: Path,
    lock_file: Path,
    identities_file: Path,
    control_root: Path,
    jobs_root: Path,
) -> None:
    if _paths_overlap(control_root, jobs_root):
        raise PrepareError("control CAS and jobs root must not overlap")
    for output_label, output in (
        ("control CAS", control_root),
        ("jobs root", jobs_root),
    ):
        if _paths_overlap(output, suite_file.parent):
            raise PrepareError(f"{output_label} and benchmark suite must not overlap")
        if _paths_overlap(output, lock_file):
            raise PrepareError(f"{output_label} and baseline lock must not overlap")
        if _paths_overlap(output, identities_file):
            raise PrepareError(
                f"{output_label} and worker identities must not overlap"
            )


def _validate_v2_path_separation(
    *,
    suite_file: Path,
    lock_file: Path,
    control_root: Path,
    jobs_root: Path,
    ledger_root: Path,
) -> None:
    outputs = (
        ("control CAS", control_root),
        ("jobs root", jobs_root),
        ("challenge ledger", ledger_root),
    )
    for index, (first_label, first) in enumerate(outputs):
        for second_label, second in outputs[index + 1 :]:
            if _paths_overlap(first, second):
                raise PrepareError(
                    f"{first_label} and {second_label} must not overlap"
                )
    for output_label, output in outputs:
        if _paths_overlap(output, suite_file.parent):
            raise PrepareError(
                f"{output_label} and benchmark suite must not overlap"
            )
        if _paths_overlap(output, lock_file):
            raise PrepareError(
                f"{output_label} and baseline lock must not overlap"
            )


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _exact_object(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PrepareError(f"{label} must be a JSON object")
    if set(value) != expected:
        raise PrepareError(f"{label} has missing or unknown fields")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PrepareError(f"duplicate worker identities JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise PrepareError(f"non-finite worker identities JSON value: {value}")


def _finite(value: object) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise PrepareError("non-finite worker identities JSON number")
    if isinstance(value, list):
        for item in value:
            _finite(item)
    elif isinstance(value, dict):
        for item in value.values():
            _finite(item)


def _system(value: object, label: str) -> dict[str, str]:
    system = _exact_object(value, _SYSTEM_KEYS, label)
    name = _identifier(system["name"], f"{label}.name")
    version = system["version"]
    if (
        not isinstance(version, str)
        or not version
        or version != version.strip()
        or len(version) > 256
        or any(
            unicodedata.category(character).startswith("C")
            for character in version
        )
    ):
        raise PrepareError(f"{label}.version is not canonical")
    return {
        "name": name,
        "version": version,
        "implementation_digest": _digest(
            system["implementation_digest"],
            f"{label}.implementation_digest",
        ),
        "config_digest": _digest(
            system["config_digest"],
            f"{label}.config_digest",
        ),
    }


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise PrepareError(f"{label} is not a canonical identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise PrepareError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PrepareError(f"{label} is not canonical lowercase hex")
    return value


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PrepareError(message)


def main(argv: Sequence[str] | None = None) -> int:
    parser = ArgumentParser(
        prog="python -m aragorn.label_blind_prepare",
        description="Prepare one complete label-blind OCI benchmark batch.",
    )
    parser.add_argument("suite", type=Path)
    parser.add_argument("--worker-identities", type=Path, required=True)
    parser.add_argument("--control-state", type=Path, required=True)
    parser.add_argument("--jobs-root", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=LOCK)
    try:
        arguments = parser.parse_args(argv)
        document = prepare_files(
            arguments.suite,
            worker_identities=arguments.worker_identities,
            control_state=arguments.control_state,
            jobs_root=arguments.jobs_root,
            lock_path=arguments.lock,
        )
    except (
        BenchmarkError,
        CASError,
        OSError,
        PrepareError,
        RuntimeError,
        ValueError,
        VerificationError,
        WorkerProtocolError,
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
    print(canonical_json(document).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
