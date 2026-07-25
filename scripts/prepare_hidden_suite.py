"""Provision trust and prepare the frozen Phase 0 hidden comparator batch."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark import (
    _validate_phase0_hidden_binding,
    load_suite_for_run,
)
from aragorn.benchmark_authenticated_handoff_v2 import (
    issue_worker_measurement_challenge,
)
from aragorn.benchmark_handoff_v2 import import_handoff
from aragorn.benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    validate_worker_request_v2,
)
from aragorn.benchmark_semantic_closure_v2 import (
    derive_worker_input_cas_closure,
)
from aragorn.benchmark_worker_measurement import (
    build_worker_trust_store,
    load_worker_trust_store,
    write_worker_trust_store,
)
from aragorn.cas import CAS
from aragorn.label_blind_prepare import (
    prepare_files_v2,
    validate_private_dispatch_v2,
    validate_worker_worklist,
)
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.freeze_hidden_suite import (
    FreezeError,
    _decode_json,
    _lexical_absolute,
    _read,
    _reject_symlink_components,
    _require_private_directory,
    _sha256,
    _write_new,
    validate_freeze_receipt_bindings,
)

_FREEZE_COMMIT = "7ee1bd3422c11b31ddf2d942019d23a5617673f5"
_FREEZE_TREE = "27100abd85554fa409b7e2dd410ffb0656cdcce7"
_SIGNER_PRINCIPAL = "yousif.snazhat@gmail.com"
_SIGNER_FINGERPRINT = "SHA256:HJb87ljuOOkonZk+6GzgpASjhRMkRKBHKO3bzjuIDNk"
_ALLOWED_SIGNER = (
    "yousif.snazhat@gmail.com ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIP+34WpE4lJYYXs96Dbx/j7GMMm0WahOQl267+T2ESDA\n"
).encode("ascii")
_LOCK_PATH = Path("benchmark/phase0-hidden-suite.lock.json")
_FREEZE_RECEIPT_PATH = Path(
    "benchmark/receipts/phase0-hidden-suite-freeze-2026-07-24.json"
)
_PREPARATION_RECEIPT_PATH = Path(
    "benchmark/receipts/phase0-hidden-preparation-2026-07-24.json"
)
_PREPARATION_SCRIPT_PATH = Path("scripts/prepare_hidden_suite.py")
_CORPUS_LOCK_PATH = Path("benchmark/phase0-corpus.lock.json")
_CANDIDATE_POLICY_PATH = Path("benchmark/phase0-candidate-policy.json")
_BASELINE_LOCK_PATH = Path("benchmark/baselines.lock.json")
_PORTABLE_POLICY_PATHS = (
    Path("benchmark/phase0-cisco-portable-policy.json"),
    Path("benchmark/phase0-skillspector-portable-policy.json"),
)
_LOCK_DIGEST = "sha256:7f05171db56b35f8f76053222a6806228711679d4a5562b0b7328417fae549c7"
_FREEZE_RECEIPT_DIGEST = (
    "sha256:98909fff1a9eddd27f2ad02f27e7705078b713d822c8e5eaa9e11db420a46ad2"
)
_SUITE_DIGEST = (
    "sha256:5307d67bef0d074d600b6eae2a7e935f657dccc691927e5b9a2a05b0b4afbc5c"
)
_CANDIDATE_POLICY_DIGEST = (
    "sha256:80b760cd54e0470b11d8c030ca9ce2e438eeb515f5dfe4d29b0d21a7d40f87f0"
)
_STATE_BINDING_DIGEST = (
    "sha256:c8957dc21e2ace612ce9686e526dad17db6974f8970e16978568754118f8d53f"
)
_TRUST_DOMAIN = "phase0.hidden-independent-v1.0.0"
_WORKER_ID = "isolated-worker-01"
_WORKER_SCOPE = "aragorn/benchmark-worker-output/v2"
_RECORDED_ON = "2026-07-24"
_EXPECTED_CASES = 448
_EXPECTED_JOBS = 896
_MAX_JSON = 128 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_JOB_ID = re.compile(r"[0-9a-f]{32}\Z")
_CHALLENGE = re.compile(r"[0-9a-f]{64}\Z")


class PreparationError(ValueError):
    """The frozen hidden batch could not be prepared safely."""


def _exec(
    executable: str,
    arguments: list[str],
    *,
    maximum: int = 8 * 1024 * 1024,
) -> bytes:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        completed = subprocess.run(
            [executable, *arguments],
            cwd=ROOT,
            capture_output=True,
            check=False,
            timeout=60,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreparationError(f"cannot execute {executable}: {exc}") from exc
    if completed.returncode != 0:
        raise PreparationError(f"{Path(executable).name} verification failed")
    if len(completed.stdout) > maximum or len(completed.stderr) > 64 * 1024:
        raise PreparationError(f"{Path(executable).name} output exceeds its bound")
    return completed.stdout


def _git(arguments: list[str], *, maximum: int = 8 * 1024 * 1024) -> bytes:
    return _exec(
        "/usr/bin/git",
        ["--no-replace-objects", "-C", str(ROOT), *arguments],
        maximum=maximum,
    )


def _git_with_signer(arguments: list[str], allowed_signers: Path) -> bytes:
    return _git(
        [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_signers}",
            "-c",
            "gpg.ssh.program=/usr/bin/ssh-keygen",
            *arguments,
        ]
    )


def _verified_commit(commit: str, allowed_signers: Path) -> dict[str, str]:
    if _GIT_OID.fullmatch(commit) is None:
        raise PreparationError("Git commit identity is invalid")
    _git_with_signer(["verify-commit", commit], allowed_signers)
    raw = _git_with_signer(
        [
            "show",
            "-s",
            "--format=%H%x00%T%x00%P%x00%G?%x00%GF%x00%GS%x00%GT",
            commit,
        ],
        allowed_signers,
    ).rstrip(b"\n")
    fields = raw.split(b"\0")
    if len(fields) != 7:
        raise PreparationError("signed Git metadata is malformed")
    try:
        oid, tree, parents, status, fingerprint, principal, trust = (
            field.decode("ascii") for field in fields
        )
    except UnicodeDecodeError as exc:
        raise PreparationError("signed Git metadata is not ASCII") from exc
    if (
        oid != commit
        or _GIT_OID.fullmatch(tree) is None
        or status != "G"
        or fingerprint != _SIGNER_FINGERPRINT
        or principal != _SIGNER_PRINCIPAL
        or trust != "fully"
    ):
        raise PreparationError("Git commit signature does not match the pinned signer")
    return {
        "commit": oid,
        "tree": tree,
        "parents": parents,
        "signature_status": "verified",
        "principal": principal,
        "fingerprint": fingerprint,
    }


def _verified_repository() -> dict[str, dict[str, str]]:
    root = _git(["rev-parse", "--show-toplevel"]).decode("utf-8").strip()
    if Path(root).resolve(strict=True) != ROOT.resolve(strict=True):
        raise PreparationError("Git repository root changed")
    if _git(["rev-parse", "--show-object-format"]).strip() != b"sha1":
        raise PreparationError("Git repository object format is unsupported")
    if _git(["status", "--porcelain=v1", "--untracked-files=all"]):
        raise PreparationError("working tree must be clean before preparation")
    head = _git(["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()
    with tempfile.TemporaryDirectory(prefix="aragorn-preparation-signer-") as temporary:
        allowed_signers = Path(temporary) / "allowed_signers"
        _write_new(allowed_signers, _ALLOWED_SIGNER)
        fingerprint = (
            _exec(
                "/usr/bin/ssh-keygen",
                ["-lf", str(allowed_signers), "-E", "sha256"],
                maximum=16 * 1024,
            )
            .decode("ascii")
            .split()
        )
        if len(fingerprint) < 2 or fingerprint[1] != _SIGNER_FINGERPRINT:
            raise PreparationError("embedded preparation signer changed")
        freeze = _verified_commit(_FREEZE_COMMIT, allowed_signers)
        preparation = _verified_commit(head, allowed_signers)
    if freeze["tree"] != _FREEZE_TREE:
        raise PreparationError("signed freeze tree changed")
    _git(["merge-base", "--is-ancestor", _FREEZE_COMMIT, head])
    return {"freeze": freeze, "preparation": preparation}


def _committed_bytes(
    commit: str,
    path: Path,
    expected_digest: str | None = None,
) -> bytes:
    raw = _git(
        ["cat-file", "blob", f"{commit}:{path.as_posix()}"],
        maximum=_MAX_JSON,
    )
    if expected_digest is not None and _sha256(raw) != expected_digest:
        raise PreparationError(f"committed {path.name} digest changed")
    working = _read(ROOT / path, max_bytes=_MAX_JSON)
    if working != raw:
        raise PreparationError(f"working {path.name} differs from signed bytes")
    return raw


def _committed_document(
    commit: str,
    path: Path,
    label: str,
) -> dict[str, object]:
    return _decode_json(_committed_bytes(commit, path), label)


def _canonical_document(path: Path, label: str) -> dict[str, object]:
    raw = _read(path, max_bytes=_MAX_JSON)
    document = _decode_json(raw, label)
    if canonical_json(document) != raw:
        raise PreparationError(f"{label} must use canonical JSON bytes")
    return document


def _state_paths(run_state_root: Path) -> dict[str, Path]:
    paths = {
        "challenge_ledger": run_state_root / "challenge-ledger",
        "control_state": run_state_root / "control-state",
        "jobs_root": run_state_root / "jobs",
        "outcomes": run_state_root / "outcomes.jsonl",
    }
    if (
        canonical_digest({role: str(path) for role, path in sorted(paths.items())})
        != _STATE_BINDING_DIGEST
    ):
        raise PreparationError("run-state path binding does not match the freeze")
    return paths


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _require_preparation_paths(
    *,
    private_suite_path: Path,
    run_state_root: Path,
    verifier_root: Path,
    worker_trust_record: Path,
    receipt_output: Path,
) -> dict[str, Path]:
    paths = _state_paths(run_state_root)
    checked = [
        private_suite_path,
        run_state_root,
        verifier_root,
        worker_trust_record,
        receipt_output,
        *paths.values(),
    ]
    for index, path in enumerate(checked):
        _reject_symlink_components(path, f"preparation path[{index}]")
    _require_private_directory(run_state_root, "run state root")
    _require_private_directory(private_suite_path.parent, "private suite root")
    _require_private_directory(verifier_root, "verifier trust root")
    _require_private_directory(
        worker_trust_record.parent,
        "worker trust-record parent",
    )
    if any(verifier_root.iterdir()):
        raise PreparationError("verifier trust root must be empty")
    if any(os.path.lexists(path) for path in paths.values()):
        raise PreparationError("all frozen dispatch and outcome paths must be absent")
    if os.path.lexists(receipt_output):
        raise PreparationError("preparation receipt already exists")
    if receipt_output != ROOT / _PREPARATION_RECEIPT_PATH:
        raise PreparationError("preparation receipt path does not match the gate")
    protected = [
        private_suite_path.parent,
        run_state_root,
        verifier_root,
        worker_trust_record,
        receipt_output,
    ]
    if any(
        _paths_overlap(left, right)
        for index, left in enumerate(protected)
        for right in protected[index + 1 :]
    ):
        raise PreparationError(
            "suite, state, trust, and receipt paths must not overlap"
        )
    repository = ROOT.resolve(strict=True)
    if any(
        path == repository or path.is_relative_to(repository)
        for path in (
            private_suite_path,
            run_state_root,
            verifier_root,
            worker_trust_record,
        )
    ):
        raise PreparationError("private preparation state must remain outside the repo")
    return paths


def _load_worker_record(path: Path) -> dict[str, object]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_nlink != 1
    ):
        raise PreparationError("worker trust record must be a protected regular file")
    record = _canonical_document(path, "worker trust record")
    store = build_worker_trust_store(
        trust_domain=_TRUST_DOMAIN,
        keys=[record],
    )
    keys = store["keys"]
    if (
        len(keys) != 1
        or keys[0]["worker_id"] != _WORKER_ID
        or keys[0]["scopes"] != [_WORKER_SCOPE]
        or keys[0]["status"] != "active"
    ):
        raise PreparationError("worker trust record does not match the hidden worker")
    return record


def _preflight_suite(
    private_suite_path: Path,
    lock: dict[str, object],
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="aragorn-hidden-preflight-") as temporary:
        loaded = load_suite_for_run(
            private_suite_path,
            CAS(temporary),
            required_purpose="evidence_smoke",
        )
    _validate_phase0_hidden_binding(
        corpus_lock_path=ROOT / _CORPUS_LOCK_PATH,
        public_manifest_path=private_suite_path.parent / "public-manifest.json",
        hidden_suite_lock_path=ROOT / _LOCK_PATH,
        candidate_policy_path=ROOT / _CANDIDATE_POLICY_PATH,
        label_ledger_digest=lock["label_ledger_digest"],
        suite_digest=loaded["digest"],
        runs_per_case=loaded["runs_per_case"],
        cases=loaded["cases"],
        systems=loaded["systems"],
        manifests=loaded["manifests"],
    )
    if (
        loaded["digest"] != _SUITE_DIGEST
        or len(loaded["cases"]) != _EXPECTED_CASES
        or loaded["runs_per_case"] != 1
    ):
        raise PreparationError("hidden suite matrix changed after its freeze")
    candidates = [
        system for system in loaded["systems"].values() if system["name"] == "aragorn"
    ]
    if len(candidates) != 1:
        raise PreparationError("hidden suite candidate identity is ambiguous")
    return {
        "candidate_system": candidates[0],
        "cases": [
            {
                "case_id": case_id,
                "tree_digest": loaded["cases"][case_id]["tree_digest"],
                "private_manifest_digest": canonical_digest(
                    loaded["manifests"][case_id]
                ),
            }
            for case_id in sorted(loaded["cases"])
        ],
    }


def _decode_canonical(raw: bytes, label: str) -> dict[str, Any]:
    document = _decode_json(raw, label)
    if canonical_json(document) != raw:
        raise PreparationError(f"{label} must use canonical JSON bytes")
    return document


def _read_exact(path: Path, *, maximum: int, label: str) -> bytes:
    raw = _read(path, max_bytes=maximum)
    metadata = os.lstat(path)
    if (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o222
        or metadata.st_nlink != 1
    ):
        raise PreparationError(f"{label} must be an immutable operator-owned file")
    return raw


def _directory_names(path: Path, label: str) -> set[str]:
    try:
        return {entry.name for entry in os.scandir(path)}
    except OSError as exc:
        raise PreparationError(f"cannot enumerate {label}: {exc}") from exc


def _verify_prepared_batch(
    result: dict[str, Any],
    paths: dict[str, Path],
    expected_suite: dict[str, object],
) -> dict[str, object]:
    if (
        result.get("schema") != "aragorn/benchmark-prepare-result/v2"
        or result.get("suite_digest") != _SUITE_DIGEST
        or result.get("candidate_policy_digest") != _CANDIDATE_POLICY_DIGEST
        or result.get("job_count") != _EXPECTED_JOBS
    ):
        raise PreparationError("preparation result does not match the frozen matrix")
    control = CAS(paths["control_state"], read_only=True)
    dispatch_raw = control.read(result["dispatch_digest"], max_bytes=_MAX_JSON)
    dispatch = _decode_canonical(dispatch_raw, "private dispatch")
    validate_private_dispatch_v2(dispatch)
    if (
        canonical_digest(dispatch) != result["dispatch_digest"]
        or dispatch["suite_digest"] != _SUITE_DIGEST
        or dispatch["candidate_policy_digest"] != _CANDIDATE_POLICY_DIGEST
        or dispatch["candidate_system"] != expected_suite["candidate_system"]
        or dispatch["cases"] != expected_suite["cases"]
        or dispatch["runs_per_case"] != 1
        or len(dispatch["cases"]) != _EXPECTED_CASES
        or len(dispatch["jobs"]) != _EXPECTED_JOBS
    ):
        raise PreparationError("private dispatch does not match the frozen matrix")

    jobs_root = paths["jobs_root"]
    worklist_raw = _read_exact(
        jobs_root / "worklist.json",
        maximum=_MAX_JSON,
        label="worker worklist",
    )
    worklist = _decode_canonical(worklist_raw, "worker worklist")
    validate_worker_worklist(worklist)
    expected_worklist = [
        {
            "job_id": job["job_id"],
            "request_digest": job["request_digest"],
        }
        for job in dispatch["jobs"]
    ]
    if (
        worklist["jobs"] != expected_worklist
        or canonical_digest(worklist) != result["worklist_digest"]
        or control.read(result["worklist_digest"], max_bytes=_MAX_JSON) != worklist_raw
        or _directory_names(jobs_root, "jobs root")
        != {"worklist.json", *(job["job_id"] for job in dispatch["jobs"])}
    ):
        raise PreparationError("worker worklist does not close the private dispatch")

    ledger = paths["challenge_ledger"]
    if _directory_names(ledger, "challenge ledger") != {
        ".lock",
        ".staging",
        "issuances",
        "receipts",
    }:
        raise PreparationError("challenge ledger contains unexpected state")
    if _directory_names(ledger / ".staging", "challenge staging"):
        raise PreparationError("challenge ledger has abandoned staging state")
    if _directory_names(ledger / "receipts", "acceptance receipts"):
        raise PreparationError("acceptance receipts exist before worker execution")

    expected_issuances: set[str] = set()
    issuance_bindings: list[dict[str, str]] = []
    seen_challenges: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="aragorn-hidden-receiver-") as temporary:
        receiver = CAS(temporary)
        for job in dispatch["jobs"]:
            job_id = job["job_id"]
            if _JOB_ID.fullmatch(job_id) is None:
                raise PreparationError("prepared job identifier is invalid")
            job_root = jobs_root / job_id
            if _directory_names(job_root, "worker job") != {
                "request.json",
                "input-manifest-digest.txt",
                "input-bundle",
            }:
                raise PreparationError("worker job contains unexpected entries")
            request_raw = _read_exact(
                job_root / "request.json",
                maximum=64 * 1024,
                label="worker request",
            )
            request = _decode_canonical(request_raw, "worker request")
            validate_worker_request_v2(request)
            challenge = request["verifier_challenge"]
            if (
                request["job_id"] != job_id
                or canonical_request_digest_v2(request) != job["request_digest"]
                or request["system"]
                != {
                    field: job["system"][field]
                    for field in ("name", "version", "implementation_digest")
                }
                or request["portable_policy_digest"] != job["system"]["config_digest"]
                or request["subject"]["tree_digest"] != job["tree_digest"]
                or _CHALLENGE.fullmatch(challenge) is None
                or challenge in seen_challenges
            ):
                raise PreparationError("worker request changed its dispatch binding")
            seen_challenges.add(challenge)
            closure = derive_worker_input_cas_closure(
                control,
                job["request_digest"],
                expected_challenge=challenge,
            )
            manifest_digest_raw = _read_exact(
                job_root / "input-manifest-digest.txt",
                maximum=80,
                label="input manifest digest",
            )
            try:
                manifest_digest = manifest_digest_raw.decode("ascii").removesuffix("\n")
            except UnicodeDecodeError as exc:
                raise PreparationError("input manifest digest is not ASCII") from exc
            if (
                manifest_digest_raw != manifest_digest.encode("ascii") + b"\n"
                or _DIGEST.fullmatch(manifest_digest) is None
            ):
                raise PreparationError("input manifest digest file is malformed")
            imported = import_handoff(
                job_root / "input-bundle",
                receiver,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_input",
                expected_root_digest=job["request_digest"],
                expected_verifier_challenge=challenge,
            )
            imported_blobs = {
                item["digest"]: item["size"] for item in imported["blobs"]
            }
            if imported_blobs != closure:
                raise PreparationError("worker input handoff changed semantic closure")
            issuance_bindings.append(
                {
                    "job_id": job_id,
                    "request_digest": job["request_digest"],
                    "verifier_challenge": challenge,
                }
            )
            expected_issuances.add(f"{challenge}.json")

    if (
        len(seen_challenges) != _EXPECTED_JOBS
        or _directory_names(ledger / "issuances", "challenge issuances")
        != expected_issuances
    ):
        raise PreparationError("prepared challenge issuance accounting changed")
    for binding in issuance_bindings:
        issue_worker_measurement_challenge(
            ledger,
            trust_domain=_TRUST_DOMAIN,
            worker_id=_WORKER_ID,
            **binding,
        )
    if os.path.lexists(paths["outcomes"]):
        raise PreparationError("outcomes exist before worker execution")
    systems = sorted(
        {
            (
                job["system"]["name"],
                job["system"]["version"],
                job["system"]["implementation_digest"],
                job["system"]["config_digest"],
            )
            for job in dispatch["jobs"]
        }
    )
    system_documents = [
        {
            "name": name,
            "version": version,
            "implementation_digest": implementation,
            "config_digest": config,
        }
        for name, version, implementation, config in systems
    ]
    identities = {
        "schema": "aragorn/benchmark-system-identities/v1",
        "systems": system_documents,
    }
    if (
        canonical_digest(identities) != result["worker_identities_digest"]
        or _decode_canonical(
            control.read(result["worker_identities_digest"], max_bytes=64 * 1024),
            "worker identities",
        )
        != identities
    ):
        raise PreparationError("worker identity digest changed after preparation")
    return {
        "case_count": len(dispatch["cases"]),
        "comparator_count": len(systems),
        "runs_per_case": dispatch["runs_per_case"],
        "job_count": len(dispatch["jobs"]),
        "worklist_count": len(worklist["jobs"]),
        "issuance_count": len(expected_issuances),
        "acceptance_count": 0,
        "systems": system_documents,
    }


def _receipt(
    *,
    recorded_on: str,
    commits: dict[str, dict[str, str]],
    trust_store_digest: str,
    key_id: str,
    result: dict[str, Any],
    matrix: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": "aragorn/benchmark-phase0-hidden-preparation-receipt/v1",
        "recorded_on": recorded_on,
        "assurance": (
            "operator_asserted_signed_preparation_not_independent_or_hardware_attested"
        ),
        "source": {
            "freeze_commit": commits["freeze"]["commit"],
            "freeze_tree": commits["freeze"]["tree"],
            "freeze_signature_status": commits["freeze"]["signature_status"],
            "preparation_commit": commits["preparation"]["commit"],
            "preparation_tree": commits["preparation"]["tree"],
            "preparation_signature_status": commits["preparation"]["signature_status"],
            "signer_principal": commits["preparation"]["principal"],
            "signer_fingerprint": commits["preparation"]["fingerprint"],
            "hidden_suite_lock_digest": _LOCK_DIGEST,
            "freeze_receipt_digest": _FREEZE_RECEIPT_DIGEST,
        },
        "state": {
            "layout": "phase0-hidden-run-state/v1",
            "binding_digest": _STATE_BINDING_DIGEST,
            "fresh_before_prepare": True,
            "outcomes_absent_after_prepare": True,
            "operator_uid_protected": True,
        },
        "worker": {
            "trust_domain": _TRUST_DOMAIN,
            "worker_id": _WORKER_ID,
            "key_id": key_id,
            "trust_store_digest": trust_store_digest,
            "key_provisioning": (
                "operator_asserted_guest_generated_public_record_not_attested"
            ),
            "trust_store_status": "verifier_owned_protected_file",
        },
        "preparation": result,
        "preparation_result_digest": canonical_digest(result),
        "matrix": matrix,
        "worker_surface": {
            "request_count": _EXPECTED_JOBS,
            "handoff_count": _EXPECTED_JOBS,
            "semantic_validation": "passed",
            "forbidden_evaluator_metadata_absent": True,
        },
        "limitations": {
            "authorship": "technical_codex_authorship_not_independent_human_identity",
            "ordering": "signed_preparation_commit_verified_before_issuance",
            "custody": (
                "software_signatures_operator_uid_trusted_"
                "not_same_uid_or_hardware_attested"
            ),
            "worker_attestation": (
                "software_key_possession_not_vm_or_hardware_attestation"
            ),
        },
    }


def validate_preparation_receipt_bindings(
    receipt: dict[str, object],
    raw: bytes,
    hidden_lock: dict[str, object],
    freeze_receipt: dict[str, object],
    *,
    verified_preparation: dict[str, str] | None = None,
) -> None:
    """Reject a digest-only preparation receipt detached from the frozen gate."""

    try:
        if raw != canonical_json(receipt):
            raise PreparationError("preparation receipt must use canonical JSON bytes")
        if receipt["source"]["freeze_commit"] != _FREEZE_COMMIT:
            raise PreparationError("preparation receipt freeze commit changed")
        if verified_preparation is not None and any(
            receipt["source"][receipt_field] != verified_preparation[verified_field]
            for receipt_field, verified_field in (
                ("preparation_commit", "commit"),
                ("preparation_tree", "tree"),
                ("preparation_signature_status", "signature_status"),
                ("signer_principal", "principal"),
                ("signer_fingerprint", "fingerprint"),
            )
        ):
            raise PreparationError("preparation receipt signed source changed")
        if (
            receipt["source"]["hidden_suite_lock_digest"] != _LOCK_DIGEST
            or receipt["source"]["freeze_receipt_digest"] != _FREEZE_RECEIPT_DIGEST
        ):
            raise PreparationError("preparation receipt source digests changed")
        if (
            receipt["state"]["binding_digest"]
            != freeze_receipt["pre_outcome"]["state_binding_digest"]
            or receipt["preparation"]["suite_digest"] != hidden_lock["suite_digest"]
            or receipt["preparation"]["candidate_policy_digest"]
            != hidden_lock["candidate_policy_digest"]
            or receipt["preparation_result_digest"]
            != canonical_digest(receipt["preparation"])
        ):
            raise PreparationError("preparation receipt frozen binding changed")
        expected_systems = [
            system for system in hidden_lock["systems"] if system["name"] != "aragorn"
        ]
        matrix = receipt["matrix"]
        expected_worker_identities_digest = canonical_digest(
            {
                "schema": "aragorn/benchmark-system-identities/v1",
                "systems": matrix["systems"],
            }
        )
        if (
            matrix["systems"] != expected_systems
            or matrix["case_count"] != hidden_lock["case_count"]
            or matrix["runs_per_case"] != hidden_lock["runs_per_case"]
            or matrix["job_count"] != _EXPECTED_JOBS
            or matrix["worklist_count"] != _EXPECTED_JOBS
            or matrix["issuance_count"] != _EXPECTED_JOBS
            or matrix["acceptance_count"] != 0
            or receipt["preparation"]["job_count"] != _EXPECTED_JOBS
            or receipt["preparation"]["worker_identities_digest"]
            != expected_worker_identities_digest
        ):
            raise PreparationError("preparation receipt matrix accounting changed")
    except (KeyError, TypeError) as exc:
        raise PreparationError("preparation receipt binding is malformed") from exc


def validate_retained_preparation_receipt(
    receipt: dict[str, object],
    raw: bytes,
    hidden_lock: dict[str, object],
    freeze_receipt: dict[str, object],
) -> None:
    """Verify a checked receipt through its signed Git retention boundary."""

    try:
        claimed_commit = receipt["source"]["preparation_commit"]
    except (KeyError, TypeError) as exc:
        raise PreparationError("retained preparation source is malformed") from exc
    if not isinstance(claimed_commit, str):
        raise PreparationError("retained preparation commit is invalid")
    retained = _verified_repository()
    retained_commit = retained["preparation"]["commit"]
    if claimed_commit == retained_commit:
        raise PreparationError(
            "retained receipt must strictly follow the preparation commit"
        )
    if claimed_commit == _FREEZE_COMMIT:
        raise PreparationError("preparation commit must strictly follow the freeze")
    with tempfile.TemporaryDirectory(
        prefix="aragorn-retained-preparation-signer-"
    ) as temporary:
        allowed_signers = Path(temporary) / "allowed_signers"
        _write_new(allowed_signers, _ALLOWED_SIGNER)
        claimed = _verified_commit(claimed_commit, allowed_signers)
    _git(["merge-base", "--is-ancestor", _FREEZE_COMMIT, claimed_commit])
    _git(
        [
            "merge-base",
            "--is-ancestor",
            claimed_commit,
            retained_commit,
        ]
    )
    script_entry = _git(
        [
            "ls-tree",
            "-z",
            "--full-name",
            claimed_commit,
            "--",
            _PREPARATION_SCRIPT_PATH.as_posix(),
        ]
    )
    script_header, separator, script_path = script_entry.partition(b"\t")
    script_fields = script_header.split()
    if (
        separator != b"\t"
        or script_path != os.fsencode(_PREPARATION_SCRIPT_PATH.as_posix()) + b"\0"
        or len(script_fields) != 3
        or script_fields[0] not in (b"100644", b"100755")
        or script_fields[1] != b"blob"
        or re.fullmatch(rb"[0-9a-f]{40}", script_fields[2]) is None
    ):
        raise PreparationError(
            "claimed preparation commit lacks the regular preparation script"
        )
    if _git(
        [
            "ls-tree",
            "-z",
            "--name-only",
            claimed_commit,
            "--",
            _PREPARATION_RECEIPT_PATH.as_posix(),
        ]
    ):
        raise PreparationError("preparation receipt already exists at claimed commit")
    committed = _git(
        [
            "cat-file",
            "blob",
            f"{retained_commit}:{_PREPARATION_RECEIPT_PATH}",
        ],
        maximum=_MAX_JSON,
    )
    if committed != raw:
        raise PreparationError("retained preparation receipt differs from signed Git")
    validate_preparation_receipt_bindings(
        receipt,
        raw,
        hidden_lock,
        freeze_receipt,
        verified_preparation=claimed,
    )


def prepare(
    *,
    private_suite_path: Path,
    run_state_root: Path,
    verifier_root: Path,
    worker_trust_record: Path,
    receipt_output: Path,
    recorded_on: str,
) -> dict[str, object]:
    try:
        parsed_date = date.fromisoformat(recorded_on)
    except ValueError as exc:
        raise PreparationError("recorded_on must be a real YYYY-MM-DD date") from exc
    if parsed_date.isoformat() != recorded_on:
        raise PreparationError("recorded_on must use YYYY-MM-DD")
    if recorded_on != _RECORDED_ON:
        raise PreparationError("recorded_on does not match the preparation gate")
    paths = _require_preparation_paths(
        private_suite_path=private_suite_path,
        run_state_root=run_state_root,
        verifier_root=verifier_root,
        worker_trust_record=worker_trust_record,
        receipt_output=receipt_output,
    )
    commits = _verified_repository()
    lock_raw = _committed_bytes(_FREEZE_COMMIT, _LOCK_PATH, _LOCK_DIGEST)
    freeze_raw = _committed_bytes(
        _FREEZE_COMMIT,
        _FREEZE_RECEIPT_PATH,
        _FREEZE_RECEIPT_DIGEST,
    )
    corpus_raw = _read(ROOT / _CORPUS_LOCK_PATH, max_bytes=_MAX_JSON)
    lock = _decode_json(lock_raw, "hidden suite lock")
    freeze_receipt = _decode_json(freeze_raw, "hidden suite freeze receipt")
    corpus_lock = _decode_json(corpus_raw, "Phase 0 corpus lock")
    validate_freeze_receipt_bindings(
        freeze_receipt,
        freeze_raw,
        lock,
        lock_raw,
        corpus_lock,
        corpus_raw,
    )
    expected_suite = _preflight_suite(private_suite_path, lock)
    worker_record = _load_worker_record(worker_trust_record)

    trust_store = build_worker_trust_store(
        trust_domain=_TRUST_DOMAIN,
        keys=[worker_record],
    )
    trust_store_path = verifier_root / "worker-trust-store.json"
    trust_store_digest = write_worker_trust_store(
        trust_store_path,
        trust_store,
    )
    if load_worker_trust_store(trust_store_path) != trust_store:
        raise PreparationError("published worker trust store changed")

    preparation_commit = commits["preparation"]["commit"]
    portable_policies = [
        _committed_document(
            preparation_commit,
            path,
            f"portable policy {index}",
        )
        for index, path in enumerate(_PORTABLE_POLICY_PATHS)
    ]
    candidate_policy = _committed_document(
        preparation_commit,
        _CANDIDATE_POLICY_PATH,
        "candidate policy",
    )
    result = prepare_files_v2(
        private_suite_path,
        portable_policies=portable_policies,
        candidate_policy=candidate_policy,
        trust_domain=_TRUST_DOMAIN,
        worker_id=_WORKER_ID,
        challenge_ledger=paths["challenge_ledger"],
        control_state=paths["control_state"],
        jobs_root=paths["jobs_root"],
        lock_path=ROOT / _BASELINE_LOCK_PATH,
    )
    matrix = _verify_prepared_batch(result, paths, expected_suite)
    if _git(["rev-parse", "--verify", "HEAD^{commit}"]).decode(
        "ascii"
    ).strip() != commits["preparation"]["commit"] or _git(
        ["status", "--porcelain=v1", "--untracked-files=all"]
    ):
        raise PreparationError("repository changed during hidden preparation")
    receipt = _receipt(
        recorded_on=recorded_on,
        commits=commits,
        trust_store_digest=trust_store_digest,
        key_id=worker_record["key_id"],
        result=result,
        matrix=matrix,
    )
    receipt_raw = canonical_json(receipt)
    validate_preparation_receipt_bindings(
        receipt,
        receipt_raw,
        lock,
        freeze_receipt,
        verified_preparation=commits["preparation"],
    )
    _write_new(receipt_output, receipt_raw, mode=0o644)
    return {
        "schema": "aragorn/benchmark-phase0-hidden-preparation-result/v1",
        "status": "ok",
        "preparation_commit": commits["preparation"]["commit"],
        "suite_digest": result["suite_digest"],
        "dispatch_digest": result["dispatch_digest"],
        "trust_store_digest": trust_store_digest,
        "job_count": result["job_count"],
        "receipt_digest": _sha256(receipt_raw),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-suite", type=Path, required=True)
    parser.add_argument("--run-state-root", type=Path, required=True)
    parser.add_argument("--verifier-root", type=Path, required=True)
    parser.add_argument("--worker-trust-record", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path, required=True)
    parser.add_argument("--recorded-on", required=True)
    arguments = parser.parse_args()
    try:
        result = prepare(
            private_suite_path=_lexical_absolute(arguments.private_suite),
            run_state_root=_lexical_absolute(arguments.run_state_root),
            verifier_root=_lexical_absolute(arguments.verifier_root),
            worker_trust_record=_lexical_absolute(arguments.worker_trust_record),
            receipt_output=_lexical_absolute(arguments.receipt_output),
            recorded_on=arguments.recorded_on,
        )
    except (
        FreezeError,
        KeyError,
        OSError,
        PreparationError,
        RuntimeError,
        TypeError,
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
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
