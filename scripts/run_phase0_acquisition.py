"""Prepare, execute, and replay the authenticated Phase 0 acquisition arms."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark_authenticated_handoff_v2 import (
    load_verified_worker_output_acceptance,
)
from aragorn.benchmark import (
    _load_phase0_expansion,
    _validate_phase0_accounting,
    load_suite_for_run,
)
from aragorn.benchmark_protocol_v2 import build_portable_policy
from aragorn.benchmark_worker_measurement import (
    build_worker_trust_store,
    load_worker_trust_store,
    write_worker_trust_store,
)
from aragorn.cas import CAS, CASError
from aragorn.github_expand import (
    TERMINAL_DEPTH_1_ASSURANCE,
    TERMINAL_DEPTH_1_PROFILE,
)
from aragorn.label_blind_prepare import (
    PrepareError,
    prepare_files_v2,
    validate_private_dispatch,
    validate_private_dispatch_v2,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase0_candidate import (
    CandidateError,
    build_candidate_policy,
    candidate_implementation_digest,
    candidate_policy_digest,
    candidate_system_identity,
    compose_authenticated_comparator_batch,
    compose_candidate_batch,
)
from scripts.phase0_acquisition_gate import EXPANSION_PROFILE, build_lock
from scripts.prepare_hidden_suite import (
    _ALLOWED_SIGNER,
    _committed_bytes,
    _committed_document,
    _git,
    _verified_commit,
)
from scripts.run_hidden_workers import (
    ExecutionError,
    Job,
    _cleanup_ordinal,
    _collect_authenticated,
    _controller_lock,
    _copy_worker_return,
    _create_guest_attempt,
    _directory_names,
    _guest_attempts,
    _host_returns,
    _load_jobs,
    _private_root,
    _resolve_executable,
    _retain_cas_document,
    _retain_exact,
    _run_worker,
    _runner_commit,
    _validate_acceptance_binding,
    _validate_staging_root,
    _vm_preflight,
    _write_outcomes,
)

PLAN_SCHEMA = "aragorn/benchmark-phase0-acquisition-execution-plan/v1"
RECEIPT_SCHEMA = "aragorn/benchmark-phase0-acquisition-worker-run-receipt/v1"
TRUST_DOMAIN = "phase0.acquisition-v1"
WORKER_ID = "isolated-worker-01"
ROOT_JOBS = 896
EXPANDED_JOBS = 896
ROOT_OUTCOMES = 896
EXPANDED_OUTCOMES = 1_344
_MAX_JSON = 128 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_VM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_GUEST_PATH = re.compile(r"/[A-Za-z0-9._/-]{1,4095}\Z")
_ORACLE_LOCK_PATH = Path("benchmark/phase0-acquisition-oracle.lock.json")


class AcquisitionExecutionError(ValueError):
    """The paired authenticated acquisition run could not close safely."""


def _digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _runner_source() -> tuple[str, str]:
    try:
        dirty = _git(["status", "--porcelain=v1", "--untracked-files=all"])
    except (ExecutionError, OSError, RuntimeError, ValueError) as exc:
        raise AcquisitionExecutionError(
            "cannot verify the acquisition execution worktree"
        ) from exc
    if dirty:
        raise AcquisitionExecutionError(
            "working tree must be clean before acquisition execution"
        )
    commit = _runner_commit()
    try:
        with tempfile.TemporaryDirectory(
            prefix="aragorn-acquisition-signer-"
        ) as temporary:
            allowed_signers = Path(temporary) / "allowed_signers"
            allowed_signers.write_bytes(_ALLOWED_SIGNER)
            _verified_commit(commit, allowed_signers)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AcquisitionExecutionError(
            "acquisition execution HEAD is not signed by the pinned signer"
        ) from exc
    raw = Path(__file__).read_bytes()
    try:
        committed = _git(
            ["cat-file", "blob", f"{commit}:scripts/run_phase0_acquisition.py"]
        )
    except (ExecutionError, OSError, RuntimeError, ValueError) as exc:
        raise AcquisitionExecutionError(
            "acquisition runner is not retained by its claimed commit"
        ) from exc
    if committed != raw:
        raise AcquisitionExecutionError(
            "acquisition runner differs from its claimed commit"
        )
    return commit, _digest_bytes(raw)


def _read_canonical(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise AcquisitionExecutionError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = -1
            raw = stream.read(_MAX_JSON + 1)
            after = os.fstat(stream.fileno())
        if (
            len(raw) > _MAX_JSON
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise AcquisitionExecutionError(f"{label} changed while reading")
        document = json.loads(raw)
    except AcquisitionExecutionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcquisitionExecutionError(f"cannot read {label}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        not isinstance(document, dict)
        or canonical_json(document) != raw
    ):
        raise AcquisitionExecutionError(f"{label} must be a bounded canonical object")
    return document, raw


def _load_signed_oracle_lock(
    commit: str,
    rebuilt: dict[str, Any],
) -> dict[str, Any]:
    lock, raw = _read_canonical(
        ROOT / _ORACLE_LOCK_PATH,
        "signed acquisition oracle lock",
    )
    try:
        committed = _committed_bytes(commit, _ORACLE_LOCK_PATH)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AcquisitionExecutionError(
            "acquisition oracle lock is not retained by signed HEAD"
        ) from exc
    if committed != raw or lock != rebuilt:
        raise AcquisitionExecutionError(
            "signed acquisition oracle lock does not match the frozen inputs"
        )
    return lock


def _private_existing(path: Path, label: str) -> Path:
    requested = Path(os.path.abspath(os.fspath(path.expanduser())))
    try:
        metadata = os.lstat(requested)
    except OSError as exc:
        raise AcquisitionExecutionError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AcquisitionExecutionError(
            f"{label} must be an operator-owned private directory"
        )
    return requested.resolve(strict=True)


def _new_private_root(path: Path) -> Path:
    requested = Path(os.path.abspath(os.fspath(path.expanduser())))
    if os.path.lexists(requested):
        raise AcquisitionExecutionError("acquisition run root already exists")
    parent = _private_existing(requested.parent, "acquisition run parent")
    result = parent / requested.name
    os.mkdir(result, mode=0o700)
    return result


def _separate(paths: Sequence[Path]) -> None:
    resolved = [path.resolve(strict=False) for path in paths]
    for index, left in enumerate(resolved):
        for right in resolved[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise AcquisitionExecutionError(
                    "acquisition security boundaries overlap"
                )


def _policy(path: Path, label: str, commit: str) -> dict[str, Any]:
    target = Path(os.path.abspath(os.fspath(path.expanduser())))
    try:
        relative = target.relative_to(ROOT)
        return _committed_document(commit, relative, label)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AcquisitionExecutionError(
            f"{label} must be retained by signed HEAD"
        ) from exc


def _trust_record(path: Path) -> dict[str, Any]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AcquisitionExecutionError(
            "worker trust record must be an operator-owned private file"
        )
    record, _raw = _read_canonical(path, "worker trust record")
    store = build_worker_trust_store(trust_domain=TRUST_DOMAIN, keys=[record])
    key = store["keys"][0]
    if (
        len(store["keys"]) != 1
        or key["worker_id"] != WORKER_ID
        or key["status"] != "active"
        or key["scopes"] != ["aragorn/benchmark-worker-output/v2"]
    ):
        raise AcquisitionExecutionError("worker trust record binding is invalid")
    return record


def _cas_digest_set(cas: CAS) -> list[str]:
    root = cas.root / "blobs" / "sha256"
    digests: list[str] = []
    for prefix in sorted(root.iterdir(), key=lambda item: item.name):
        prefix_metadata = os.lstat(prefix)
        if (
            re.fullmatch(r"[0-9a-f]{2}", prefix.name) is None
            or not stat.S_ISDIR(prefix_metadata.st_mode)
            or stat.S_ISLNK(prefix_metadata.st_mode)
        ):
            raise AcquisitionExecutionError("acquisition CAS layout is unsafe")
        for blob in sorted(prefix.iterdir(), key=lambda item: item.name):
            metadata = os.lstat(blob)
            digest = f"sha256:{prefix.name}{blob.name}"
            if (
                re.fullmatch(r"[0-9a-f]{62}", blob.name) is None
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o222
            ):
                raise AcquisitionExecutionError("acquisition CAS blob is unsafe")
            cas.verify(digest, max_bytes=_MAX_JSON)
            digests.append(digest)
    if not digests:
        raise AcquisitionExecutionError("acquisition CAS is empty")
    return digests


def _copy_cas(source: CAS, destination: CAS) -> str:
    digests = _cas_digest_set(source)
    for digest in digests:
        raw = source.read(digest, max_bytes=_MAX_JSON)
        destination.put_expected(
            BytesIO(raw),
            expected_digest=digest,
            max_bytes=len(raw),
        )
    document = {
        "schema": "aragorn/cas-digest-set/v1",
        "digests": digests,
    }
    raw = canonical_json(document)
    digest = canonical_digest(document)
    destination.put_expected(
        BytesIO(raw),
        expected_digest=digest,
        max_bytes=len(raw),
    )
    return digest


def _validate_plan(plan: object) -> dict[str, Any]:
    if not isinstance(plan, dict) or set(plan) != {
        "schema",
        "source",
        "inputs",
        "worker",
        "arms",
        "acquisition_cas_digest_set",
    }:
        raise AcquisitionExecutionError("acquisition execution plan contract changed")
    if plan["schema"] != PLAN_SCHEMA:
        raise AcquisitionExecutionError("acquisition execution plan schema changed")
    source = plan["source"]
    if not isinstance(source, dict) or set(source) != {
        "runner_commit",
        "runner_digest",
        "candidate_implementation_digest",
        "candidate_policy_digest",
        "portable_policy_digests",
    }:
        raise AcquisitionExecutionError("acquisition plan source binding changed")
    if (
        _GIT_OID.fullmatch(str(source["runner_commit"])) is None
        or any(
            _DIGEST.fullmatch(str(source[field])) is None
            for field in (
                "runner_digest",
                "candidate_implementation_digest",
                "candidate_policy_digest",
            )
        )
        or not isinstance(source["portable_policy_digests"], list)
        or len(source["portable_policy_digests"]) != 2
        or any(
            _DIGEST.fullmatch(str(item)) is None
            for item in source["portable_policy_digests"]
        )
    ):
        raise AcquisitionExecutionError("acquisition plan source digest is invalid")
    inputs = plan["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "oracle_digest",
        "oracle_lock_digest",
        "accounting_digest",
        "root_suite_digest",
        "expanded_suite_digest",
    } or any(_DIGEST.fullmatch(str(value)) is None for value in inputs.values()):
        raise AcquisitionExecutionError("acquisition plan input binding changed")
    worker = plan["worker"]
    if (
        not isinstance(worker, dict)
        or set(worker) != {
            "trust_domain",
            "worker_id",
            "key_id",
            "trust_store_digest",
        }
        or worker["trust_domain"] != TRUST_DOMAIN
        or worker["worker_id"] != WORKER_ID
        or _DIGEST.fullmatch(str(worker["key_id"])) is None
        or _DIGEST.fullmatch(str(worker["trust_store_digest"])) is None
    ):
        raise AcquisitionExecutionError("acquisition plan worker binding changed")
    arms = plan["arms"]
    if not isinstance(arms, dict) or set(arms) != {"root", "expanded"}:
        raise AcquisitionExecutionError("acquisition plan arm binding changed")
    for name, count, schema in (
        ("root", ROOT_JOBS, "aragorn/benchmark-prepare-result/v1"),
        ("expanded", EXPANDED_JOBS, "aragorn/benchmark-prepare-result/v2"),
    ):
        arm = arms[name]
        expected = {
            "schema",
            "suite_digest",
            "dispatch_digest",
            "worker_identities_digest",
            "worklist_digest",
            "job_count",
        }
        if name == "expanded":
            expected.add("candidate_policy_digest")
        if (
            not isinstance(arm, dict)
            or set(arm) != expected
            or arm["schema"] != schema
            or arm["job_count"] != count
            or any(
                _DIGEST.fullmatch(str(arm[field])) is None
                for field in expected - {"schema", "job_count"}
            )
        ):
            raise AcquisitionExecutionError(
                f"acquisition {name} plan binding changed"
            )
    if (
        arms["root"]["suite_digest"] != inputs["root_suite_digest"]
        or arms["expanded"]["suite_digest"] != inputs["expanded_suite_digest"]
        or arms["expanded"]["candidate_policy_digest"]
        != source["candidate_policy_digest"]
        or _DIGEST.fullmatch(str(plan["acquisition_cas_digest_set"])) is None
    ):
        raise AcquisitionExecutionError("acquisition plan cross-binding changed")
    return plan


def prepare(
    *,
    prepared_root: Path,
    acquisition_state: Path,
    run_root: Path,
    candidate_policy_path: Path,
    portable_policy_paths: Sequence[Path],
    worker_trust_record: Path,
) -> dict[str, Any]:
    prepared_root = _private_existing(prepared_root, "prepared acquisition root")
    acquisition_state = _private_existing(acquisition_state, "acquisition CAS")
    _separate((ROOT, prepared_root, acquisition_state, run_root))
    if len(portable_policy_paths) != 2:
        raise AcquisitionExecutionError("exactly two portable policies are required")
    runner_commit, runner_digest = _runner_source()
    candidate_policy = build_candidate_policy(
        _policy(candidate_policy_path, "candidate policy", runner_commit)
    )
    portable_policies = [
        build_portable_policy(
            _policy(path, f"portable policy {index}", runner_commit)
        )
        for index, path in enumerate(portable_policy_paths)
    ]
    record = _trust_record(worker_trust_record)
    run_root = _new_private_root(run_root)
    completed = False
    try:
        verifier = run_root / "verifier"
        verifier.mkdir(mode=0o700)
        trust_store = build_worker_trust_store(
            trust_domain=TRUST_DOMAIN,
            keys=[record],
        )
        trust_store_digest = write_worker_trust_store(
            verifier / "worker-trust-store.json",
            trust_store,
        )
        key_id = trust_store["keys"][0]["key_id"]
        evidence_state = run_root / "evidence-state"
        expanded = prepare_files_v2(
            prepared_root / "expanded-suite.json",
            portable_policies=portable_policies,
            candidate_policy=candidate_policy,
            trust_domain=TRUST_DOMAIN,
            worker_id=WORKER_ID,
            challenge_ledger=run_root / "expanded-ledger",
            control_state=evidence_state,
            jobs_root=run_root / "expanded-jobs",
            lock_path=ROOT / "benchmark" / "baselines.lock.json",
        )
        root = prepare_files_v2(
            prepared_root / "root-suite.json",
            portable_policies=portable_policies,
            trust_domain=TRUST_DOMAIN,
            worker_id=WORKER_ID,
            challenge_ledger=run_root / "root-ledger",
            control_state=evidence_state,
            jobs_root=run_root / "root-jobs",
            lock_path=ROOT / "benchmark" / "baselines.lock.json",
        )
        acquisition_set = _copy_cas(
            CAS(acquisition_state, read_only=True),
            CAS(evidence_state),
        )
        oracle, _oracle_raw = _read_canonical(
            prepared_root / "acquisition-oracle.json",
            "acquisition oracle",
        )
        accounting, _accounting_raw = _read_canonical(
            prepared_root / "phase0-accounting.json",
            "acquisition accounting",
        )
        evidence = CAS(evidence_state)
        root_suite = load_suite_for_run(
            prepared_root / "root-suite.json",
            evidence,
            required_purpose="evidence_smoke",
        )
        expanded_suite = load_suite_for_run(
            prepared_root / "expanded-suite.json",
            evidence,
            required_purpose="evidence_smoke",
        )
        policy_record = {
            "document": candidate_policy,
            "digest": candidate_policy_digest(candidate_policy),
            "candidate": candidate_system_identity(candidate_policy),
            "comparators": list(candidate_policy["required_comparators"]),
        }
        oracle_lock = build_lock(
            oracle,
            root_suite,
            expanded_suite,
            policy_record,
        )
        oracle_lock = _load_signed_oracle_lock(runner_commit, oracle_lock)
        candidate, plans, canonical_accounting = _validate_phase0_accounting(
            accounting,
            suite_digest=expanded_suite["digest"],
            cases=expanded_suite["cases"],
            systems=expanded_suite["systems"],
        )
        oracle_cases = {item["case_id"]: item for item in oracle["cases"]}
        if (
            candidate != policy_record["candidate"]
            or canonical_accounting != accounting
            or set(plans) != set(oracle_cases)
        ):
            raise AcquisitionExecutionError(
                "acquisition accounting does not match the paired inputs"
            )
        source_cas = CAS(acquisition_state, read_only=True)
        for case_id, item in plans.items():
            expected = oracle_cases[case_id]
            expansion = _load_phase0_expansion(
                source_cas,
                item["expansion_digest"],
                expected_tree_digest=expanded_suite["cases"][case_id][
                    "tree_digest"
                ],
                label=f"acquisition case {case_id}",
                expected_profile=EXPANSION_PROFILE,
            )
            if (
                item["expected_references"] != expected["expected_references"]
                or expansion["source"] != expected["source"]
                or expansion["root_tree_digest"] != expected["root_tree_digest"]
                or expansion["comparator_subject_tree_digest"]
                != expected["expanded_tree_digest"]
                or expansion["closure"]["status"] != "complete"
            ):
                raise AcquisitionExecutionError(
                    f"acquisition case {case_id} closure binding changed"
                )
        oracle_digest = _retain_cas_document(
            evidence,
            oracle,
            label="acquisition oracle",
        )
        accounting_digest = _retain_cas_document(
            evidence,
            accounting,
            label="acquisition accounting",
        )
        plan = _validate_plan(
            {
                "schema": PLAN_SCHEMA,
                "source": {
                    "runner_commit": runner_commit,
                    "runner_digest": runner_digest,
                    "candidate_implementation_digest": (
                        candidate_implementation_digest()
                    ),
                    "candidate_policy_digest": candidate_policy_digest(
                        candidate_policy
                    ),
                    "portable_policy_digests": sorted(
                        canonical_digest(policy) for policy in portable_policies
                    ),
                },
                "inputs": {
                    "oracle_digest": oracle_digest,
                    "oracle_lock_digest": canonical_digest(oracle_lock),
                    "accounting_digest": accounting_digest,
                    "root_suite_digest": root["suite_digest"],
                    "expanded_suite_digest": expanded["suite_digest"],
                },
                "worker": {
                    "trust_domain": TRUST_DOMAIN,
                    "worker_id": WORKER_ID,
                    "key_id": key_id,
                    "trust_store_digest": trust_store_digest,
                },
                "arms": {"root": root, "expanded": expanded},
                "acquisition_cas_digest_set": acquisition_set,
            }
        )
        raw = canonical_json(plan)
        _retain_exact(
            run_root / "execution-plan.json",
            raw,
            mode=0o400,
            label="acquisition execution plan",
        )
        completed = True
        return {
            "schema": "aragorn/benchmark-phase0-acquisition-execution-preparation/v1",
            "status": "prepared",
            "plan_digest": canonical_digest(plan),
            "root_job_count": root["job_count"],
            "expanded_job_count": expanded["job_count"],
        }
    finally:
        if not completed:
            shutil.rmtree(run_root, ignore_errors=True)


def _load_execution_plan(run_root: Path) -> tuple[dict[str, Any], bytes]:
    plan, raw = _read_canonical(
        run_root / "execution-plan.json",
        "acquisition execution plan",
    )
    _validate_plan(plan)
    runner_commit, runner_digest = _runner_source()
    if (
        plan["source"]["runner_commit"] != runner_commit
        or plan["source"]["runner_digest"] != runner_digest
        or plan["source"]["candidate_implementation_digest"]
        != candidate_implementation_digest()
    ):
        raise AcquisitionExecutionError("acquisition runner source changed")
    cas = CAS(run_root / "evidence-state", read_only=True)
    try:
        digest_set_raw = cas.read(
            plan["acquisition_cas_digest_set"],
            max_bytes=_MAX_JSON,
        )
        digest_set = json.loads(digest_set_raw)
    except (CASError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AcquisitionExecutionError(
            "acquisition CAS digest set is unavailable"
        ) from exc
    if (
        not isinstance(digest_set, dict)
        or set(digest_set) != {"schema", "digests"}
        or digest_set["schema"] != "aragorn/cas-digest-set/v1"
        or canonical_json(digest_set) != digest_set_raw
        or not isinstance(digest_set["digests"], list)
        or not digest_set["digests"]
        or digest_set["digests"] != sorted(set(digest_set["digests"]))
        or any(_DIGEST.fullmatch(str(item)) is None for item in digest_set["digests"])
    ):
        raise AcquisitionExecutionError("acquisition CAS digest set is invalid")
    for digest in digest_set["digests"]:
        cas.verify(digest, max_bytes=_MAX_JSON)
    for field in ("oracle_digest", "accounting_digest"):
        document_raw = cas.read(plan["inputs"][field], max_bytes=_MAX_JSON)
        try:
            document = json.loads(document_raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcquisitionExecutionError(
                f"acquisition {field} is unavailable"
            ) from exc
        if canonical_json(document) != document_raw:
            raise AcquisitionExecutionError(f"acquisition {field} changed")
    return plan, raw


def _bound_jobs(
    run_root: Path,
    plan: dict[str, Any],
    arm: str,
) -> list[Job]:
    arm_plan = plan["arms"][arm]
    jobs = _load_jobs(
        jobs_root=run_root / f"{arm}-jobs",
        ledger_root=run_root / f"{arm}-ledger",
        expected_job_count=arm_plan["job_count"],
        expected_worklist_digest=arm_plan["worklist_digest"],
        trust_domain=TRUST_DOMAIN,
        worker_id=WORKER_ID,
    )
    cas = CAS(run_root / "evidence-state", read_only=True)
    dispatch = json.loads(
        cas.read(arm_plan["dispatch_digest"], max_bytes=_MAX_JSON)
    )
    if canonical_digest(dispatch) != arm_plan["dispatch_digest"]:
        raise AcquisitionExecutionError(f"{arm} dispatch digest changed")
    try:
        if arm == "root":
            validate_private_dispatch(dispatch)
        else:
            validate_private_dispatch_v2(dispatch)
    except ValueError as exc:
        raise AcquisitionExecutionError(f"{arm} dispatch is invalid") from exc
    expected = {(job.job_id, job.request_digest) for job in jobs}
    actual = {
        (entry["job_id"], entry["request_digest"]) for entry in dispatch["jobs"]
    }
    if expected != actual or len(expected) != arm_plan["job_count"]:
        raise AcquisitionExecutionError(f"{arm} dispatch and worklist differ")
    return jobs


def _execute_arm(
    *,
    arm: str,
    jobs: Sequence[Job],
    run_root: Path,
    plan: dict[str, Any],
    limactl_path: Path,
    vm: str,
    guest_source: str,
    guest_python: str,
    guest_signing_key: str,
    guest_execution_root: str,
    progress_every: int,
) -> list[dict[str, object]]:
    ledger = run_root / f"{arm}-ledger"
    staging = _private_root(run_root / f"{arm}-staging", f"{arm} staging root")
    _validate_staging_root(staging)
    trust_store_path = run_root / "verifier" / "worker-trust-store.json"
    destination = CAS(run_root / "evidence-state")
    receipts = ledger / "receipts"
    accepted: list[dict[str, object]] = []
    limactl: Path | None = None
    for job in jobs:
        supervisor: dict[str, object] | None = None
        receipt_path = receipts / f"{job.challenge}.json"
        if os.path.lexists(receipt_path):
            acceptance = load_verified_worker_output_acceptance(
                destination,
                ledger,
                job.challenge,
            )
            _validate_acceptance_binding(
                acceptance=acceptance,
                job=job,
                trust_store_digest=plan["worker"]["trust_store_digest"],
                key_id=plan["worker"]["key_id"],
                trust_domain=TRUST_DOMAIN,
                worker_id=WORKER_ID,
            )
        else:
            staged, copy_number = _host_returns(staging, job.ordinal)
            if staged is None:
                if limactl is None:
                    limactl = _resolve_executable(limactl_path, "limactl")
                    _vm_preflight(
                        limactl=limactl,
                        vm=vm,
                        guest_source=guest_source,
                        guest_python=guest_python,
                        guest_signing_key=guest_signing_key,
                        guest_execution_root=guest_execution_root,
                        expected_source_digest=plan["source"][
                            "candidate_implementation_digest"
                        ],
                    )
                attempt, attempt_number = _guest_attempts(
                    limactl=limactl,
                    vm=vm,
                    guest_execution_root=guest_execution_root,
                    ordinal=job.ordinal,
                )
                if attempt is None:
                    attempt = (
                        f"job-{job.ordinal:06d}-attempt-{attempt_number:04d}"
                    )
                    _create_guest_attempt(
                        limactl=limactl,
                        vm=vm,
                        guest_execution_root=guest_execution_root,
                        name=attempt,
                        input_bundle=job.input_bundle,
                    )
                    supervisor = _run_worker(
                        limactl=limactl,
                        vm=vm,
                        guest_source=guest_source,
                        guest_python=guest_python,
                        guest_signing_key=guest_signing_key,
                        guest_execution_root=guest_execution_root,
                        attempt_name=attempt,
                        job=job,
                        key_id=plan["worker"]["key_id"],
                        trust_domain=TRUST_DOMAIN,
                    )
                staged = _copy_worker_return(
                    limactl=limactl,
                    vm=vm,
                    guest_execution_root=guest_execution_root,
                    attempt_name=attempt,
                    staging_root=staging,
                    ordinal=job.ordinal,
                    copy_number=copy_number,
                )
            acceptance = _collect_authenticated(
                job=job,
                staged=staged,
                destination=destination,
                trust_store_path=trust_store_path,
                ledger_root=ledger,
                trust_store_digest=plan["worker"]["trust_store_digest"],
                key_id=plan["worker"]["key_id"],
                trust_domain=TRUST_DOMAIN,
                worker_id=WORKER_ID,
                supervisor=supervisor,
            )
            if limactl is not None:
                _cleanup_ordinal(
                    limactl=limactl,
                    vm=vm,
                    guest_execution_root=guest_execution_root,
                    staging_root=staging,
                    ordinal=job.ordinal,
                )
        accepted.append(acceptance)
        if job.ordinal % progress_every == 0 or job.ordinal == len(jobs):
            print(
                json.dumps(
                    {
                        "schema": "aragorn/benchmark-worker-progress/v1",
                        "arm": arm,
                        "accepted": job.ordinal,
                        "total": len(jobs),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
    expected_receipts = {f"{job.challenge}.json" for job in jobs}
    if _directory_names(receipts, f"{arm} acceptance receipts") != expected_receipts:
        raise AcquisitionExecutionError(f"{arm} acceptance matrix is incomplete")
    return accepted


def _arm_sets(
    *,
    arm: str,
    jobs: Sequence[Job],
    run_root: Path,
    plan: dict[str, Any],
) -> tuple[str, str]:
    cas = CAS(run_root / "evidence-state")
    ledger = run_root / f"{arm}-ledger"
    receipts: list[str] = []
    results: list[str] = []
    for job in jobs:
        acceptance = load_verified_worker_output_acceptance(
            cas,
            ledger,
            job.challenge,
        )
        _validate_acceptance_binding(
            acceptance=acceptance,
            job=job,
            trust_store_digest=plan["worker"]["trust_store_digest"],
            key_id=plan["worker"]["key_id"],
            trust_domain=TRUST_DOMAIN,
            worker_id=WORKER_ID,
        )
        receipts.append(canonical_digest(acceptance["receipt"]))
        results.append(acceptance["receipt"]["result_digest"])
    if (
        len(set(receipts)) != len(jobs)
        or len(set(results)) != len(jobs)
        or len(jobs) != plan["arms"][arm]["job_count"]
    ):
        raise AcquisitionExecutionError(f"{arm} authenticated digest set is incomplete")
    return (
        _retain_cas_document(
            cas,
            {
                "schema": "aragorn/benchmark-acceptance-digest-set/v1",
                "digests": sorted(receipts),
            },
            label=f"{arm} acceptance digest set",
        ),
        _retain_cas_document(
            cas,
            {
                "schema": "aragorn/benchmark-result-digest-set/v1",
                "digests": sorted(results),
            },
            label=f"{arm} result digest set",
        ),
    )


def _composition(
    arm: str,
    run_root: Path,
    plan: dict[str, Any],
) -> dict[str, Any]:
    arguments = {
        "dispatch_digest": plan["arms"][arm]["dispatch_digest"],
        "control_state": run_root / "evidence-state",
        "challenge_ledger": run_root / f"{arm}-ledger",
    }
    if arm == "root":
        result = compose_authenticated_comparator_batch(**arguments)
    else:
        cas = CAS(run_root / "evidence-state", read_only=True)
        try:
            raw = cas.read(plan["inputs"]["accounting_digest"], max_bytes=_MAX_JSON)
            accounting = json.loads(raw)
        except (CASError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AcquisitionExecutionError(
                "acquisition source contexts are unavailable"
            ) from exc
        if (
            not isinstance(accounting, dict)
            or canonical_json(accounting) != raw
            or set(accounting)
            != {
                "schema",
                "suite_digest",
                "candidate_system",
                "expansion_profile",
                "expansion_assurance",
                "cases",
            }
            or accounting["schema"]
            != "aragorn/benchmark-phase0-accounting/v1"
            or accounting["suite_digest"] != plan["arms"][arm]["suite_digest"]
            or accounting["expansion_profile"] != TERMINAL_DEPTH_1_PROFILE
            or accounting["expansion_assurance"] != TERMINAL_DEPTH_1_ASSURANCE
            or not isinstance(accounting["cases"], list)
        ):
            raise AcquisitionExecutionError(
                "acquisition source context contract changed"
            )
        source_contexts: dict[str, str] = {}
        for item in accounting["cases"]:
            if (
                not isinstance(item, dict)
                or set(item)
                != {"case_id", "expansion_digest", "expected_references"}
                or not isinstance(item["case_id"], str)
                or _DIGEST.fullmatch(str(item["expansion_digest"])) is None
                or item["case_id"] in source_contexts
            ):
                raise AcquisitionExecutionError(
                    "acquisition source context matrix changed"
                )
            source_contexts[item["case_id"]] = item["expansion_digest"]
        result = compose_candidate_batch(
            **arguments,
            source_contexts=source_contexts,
        )
    expected = ROOT_OUTCOMES if arm == "root" else EXPANDED_OUTCOMES
    if (
        result["suite_digest"] != plan["arms"][arm]["suite_digest"]
        or result["dispatch_digest"] != plan["arms"][arm]["dispatch_digest"]
        or result["outcomes_digest"] != canonical_digest(result["outcomes"])
        or len(result["outcomes"]) != expected
        or len({canonical_digest(item) for item in result["outcomes"]}) != expected
    ):
        raise AcquisitionExecutionError(f"{arm} composition matrix is incomplete")
    return result


def _receipt(
    *,
    plan: dict[str, Any],
    plan_raw: bytes,
    arm_records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "assurance": (
            "authenticated_complete_paired_worker_batches_"
            "not_independent_or_hardware_attested"
        ),
        "source": {
            "runner_commit": plan["source"]["runner_commit"],
            "runner_digest": plan["source"]["runner_digest"],
            "candidate_implementation_digest": plan["source"][
                "candidate_implementation_digest"
            ],
            "plan_digest": canonical_digest(plan),
            "plan_file_digest": _digest_bytes(plan_raw),
        },
        "worker": dict(plan["worker"]),
        "arms": arm_records,
        "totals": {
            "accepted_count": ROOT_JOBS + EXPANDED_JOBS,
            "outcome_count": ROOT_OUTCOMES + EXPANDED_OUTCOMES,
        },
        "limitations": {
            "custody": (
                "software_signatures_operator_uid_trusted_"
                "not_same_uid_or_hardware_attested"
            ),
            "worker_attestation": (
                "software_key_possession_not_vm_or_hardware_attestation"
            ),
        },
    }


def _arm_record(
    *,
    arm: str,
    run_root: Path,
    plan: dict[str, Any],
    jobs: Sequence[Job],
) -> dict[str, Any]:
    acceptance_set, result_set = _arm_sets(
        arm=arm,
        jobs=jobs,
        run_root=run_root,
        plan=plan,
    )
    composition = _composition(arm, run_root, plan)
    outcomes_raw = _write_outcomes(
        run_root / f"{arm}-outcomes.jsonl",
        composition["outcomes"],
    )
    return {
        "suite_digest": plan["arms"][arm]["suite_digest"],
        "dispatch_digest": plan["arms"][arm]["dispatch_digest"],
        "worklist_digest": plan["arms"][arm]["worklist_digest"],
        "accepted_count": len(jobs),
        "acceptance_set_digest": acceptance_set,
        "result_set_digest": result_set,
        "composition_digest": canonical_digest(composition),
        "outcomes_digest": composition["outcomes_digest"],
        "outcomes_file_digest": _digest_bytes(outcomes_raw),
        "outcome_count": len(composition["outcomes"]),
    }


def _replay_receipt(
    receipt: dict[str, Any],
    *,
    run_root: Path,
    plan: dict[str, Any],
    plan_raw: bytes,
    jobs: dict[str, list[Job]],
) -> None:
    expected = _receipt(
        plan=plan,
        plan_raw=plan_raw,
        arm_records={
            arm: _arm_record(
                arm=arm,
                run_root=run_root,
                plan=plan,
                jobs=jobs[arm],
            )
            for arm in ("root", "expanded")
        },
    )
    if receipt != expected:
        raise AcquisitionExecutionError("acquisition run receipt did not replay")


def run(
    *,
    run_root: Path,
    limactl_path: Path,
    vm: str,
    guest_source: str,
    guest_python: str,
    guest_signing_key: str,
    guest_execution_root: str,
    progress_every: int,
) -> dict[str, Any]:
    run_root = _private_existing(run_root, "acquisition run root")
    if (
        _VM_NAME.fullmatch(vm) is None
        or not 1 <= progress_every <= ROOT_JOBS
        or not guest_python.endswith("/venv/bin/python")
    ):
        raise AcquisitionExecutionError("acquisition worker arguments are invalid")
    for value in (
        guest_source,
        guest_python,
        guest_signing_key,
        guest_execution_root,
    ):
        if (
            _GUEST_PATH.fullmatch(value) is None
            or os.path.normpath(value) != value
            or ".." in Path(value).parts
        ):
            raise AcquisitionExecutionError("acquisition guest path is invalid")
    runtime_suffix = "/venv/bin/python"
    guest_boundaries = [
        Path(guest_source),
        Path(guest_python.removesuffix(runtime_suffix)),
        Path(guest_signing_key),
        Path(guest_execution_root),
    ]
    for index, left in enumerate(guest_boundaries):
        for right in guest_boundaries[index + 1 :]:
            if (
                left == right
                or left.is_relative_to(right)
                or right.is_relative_to(left)
            ):
                raise AcquisitionExecutionError(
                    "acquisition guest security boundaries overlap"
                )
    plan, plan_raw = _load_execution_plan(run_root)
    trust_store = load_worker_trust_store(
        run_root / "verifier" / "worker-trust-store.json"
    )
    if (
        canonical_digest(trust_store) != plan["worker"]["trust_store_digest"]
        or trust_store["trust_domain"] != TRUST_DOMAIN
        or len(trust_store["keys"]) != 1
        or trust_store["keys"][0]["key_id"] != plan["worker"]["key_id"]
    ):
        raise AcquisitionExecutionError("acquisition worker trust store changed")
    jobs = {
        arm: _bound_jobs(run_root, plan, arm) for arm in ("root", "expanded")
    }
    lock = _controller_lock(run_root)
    try:
        for arm in ("root", "expanded"):
            _execute_arm(
                arm=arm,
                jobs=jobs[arm],
                run_root=run_root,
                plan=plan,
                limactl_path=limactl_path,
                vm=vm,
                guest_source=guest_source,
                guest_python=guest_python,
                guest_signing_key=guest_signing_key,
                guest_execution_root=f"{guest_execution_root}/{arm}",
                progress_every=progress_every,
            )
        arm_records = {
            arm: _arm_record(
                arm=arm,
                run_root=run_root,
                plan=plan,
                jobs=jobs[arm],
            )
            for arm in ("root", "expanded")
        }
        receipt = _receipt(
            plan=plan,
            plan_raw=plan_raw,
            arm_records=arm_records,
        )
        _replay_receipt(
            receipt,
            run_root=run_root,
            plan=plan,
            plan_raw=plan_raw,
            jobs=jobs,
        )
        raw = canonical_json(receipt)
        _retain_exact(
            run_root / "worker-run-receipt.json",
            raw,
            mode=0o400,
            label="acquisition worker run receipt",
        )
        retained, retained_raw = _read_canonical(
            run_root / "worker-run-receipt.json",
            "acquisition worker run receipt",
        )
        if retained_raw != raw:
            raise AcquisitionExecutionError("acquisition run receipt bytes changed")
        _replay_receipt(
            retained,
            run_root=run_root,
            plan=plan,
            plan_raw=plan_raw,
            jobs=jobs,
        )
        return receipt
    finally:
        os.close(lock)


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise AcquisitionExecutionError(message)


def _parser() -> ArgumentParser:
    parser = ArgumentParser(prog="python scripts/run_phase0_acquisition.py")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_command = commands.add_parser("prepare")
    prepare_command.add_argument("prepared_root", type=Path)
    prepare_command.add_argument("acquisition_state", type=Path)
    prepare_command.add_argument("run_root", type=Path)
    prepare_command.add_argument("--candidate-policy", type=Path, required=True)
    prepare_command.add_argument(
        "--portable-policy",
        type=Path,
        action="append",
        required=True,
    )
    prepare_command.add_argument("--worker-trust-record", type=Path, required=True)
    run_command = commands.add_parser("run")
    run_command.add_argument("run_root", type=Path)
    run_command.add_argument(
        "--limactl",
        type=Path,
        default=Path("/opt/homebrew/bin/limactl"),
    )
    run_command.add_argument("--vm", required=True)
    run_command.add_argument("--guest-source", required=True)
    run_command.add_argument("--guest-python", required=True)
    run_command.add_argument("--guest-signing-key", required=True)
    run_command.add_argument("--guest-execution-root", required=True)
    run_command.add_argument("--progress-every", type=int, default=10)
    return parser


def _error_record(exc: BaseException) -> dict[str, str]:
    return {
        "schema": "aragorn/error/v1",
        "error": (
            "execution_failed"
            if isinstance(exc, (AcquisitionExecutionError, ExecutionError))
            else "validation_failed"
        ),
        "message": "Phase 0 acquisition worker controller failed",
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        if arguments.command == "prepare":
            result = prepare(
                prepared_root=arguments.prepared_root,
                acquisition_state=arguments.acquisition_state,
                run_root=arguments.run_root,
                candidate_policy_path=arguments.candidate_policy,
                portable_policy_paths=arguments.portable_policy,
                worker_trust_record=arguments.worker_trust_record,
            )
        else:
            result = run(
                run_root=arguments.run_root,
                limactl_path=arguments.limactl,
                vm=arguments.vm,
                guest_source=arguments.guest_source,
                guest_python=arguments.guest_python,
                guest_signing_key=arguments.guest_signing_key,
                guest_execution_root=arguments.guest_execution_root,
                progress_every=arguments.progress_every,
            )
    except (
        AcquisitionExecutionError,
        CandidateError,
        CASError,
        ExecutionError,
        OSError,
        PrepareError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        print(json.dumps(_error_record(exc), sort_keys=True), file=sys.stderr)
        return 4
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
