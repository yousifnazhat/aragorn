"""Evidence-bound, label-free Phase 0 Aragorn candidate composition."""

from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from collections.abc import Iterable
from io import BytesIO
from pathlib import Path
from typing import Any

from .analyze import _parse_observations
from .artifact_closure import (
    ASSURANCE as SOURCE_GRAPH_ASSURANCE,
)
from .artifact_closure import (
    PROFILE as SOURCE_GRAPH_PROFILE,
)
from .artifact_closure import (
    ArtifactClosureError,
    load_retained_manifest,
    resolve_source_graph,
)
from .benchmark_authenticated_handoff_v2 import (
    load_verified_worker_output_acceptance,
)
from .benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    validate_worker_request_v2,
    validate_worker_result_v2,
    verify_request_subject_v2,
)
from .cas import CAS, CASError
from .oci_worker_protocol import (
    WorkerProtocolError,
    canonical_digest,
    canonical_json,
    sanitize_subject_manifest,
)

POLICY_SCHEMA = "aragorn/benchmark-candidate-policy/v1"
POLICY_ASSURANCE = "comparative_candidate_only_not_admission"
POLICY_ALGORITHM = "source-graph-fail-closed-vendor-union/v1"
COMPOSITION_ASSURANCE = (
    "derived_from_authenticated_comparator_evidence_not_hardware_attested"
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
_POLICY_KEYS = {
    "schema",
    "assurance",
    "algorithm",
    "candidate",
    "required_comparators",
}
_PARTIAL_SYSTEM_KEYS = {"name", "version", "implementation_digest"}
_SYSTEM_KEYS = {*_PARTIAL_SYSTEM_KEYS, "config_digest"}
_CANDIDATE_VERSION = "0.1.0-phase0"
_REQUIRED_COMPARATORS = (
    {
        "name": "cisco-skill-scanner",
        "version": "2.0.12",
        "implementation_digest": (
            "sha256:7fadcfbe836eef9490feba0fadd2ada5"
            "64c11eb541077e3efee5f61edbd2e65c"
        ),
        "config_digest": (
            "sha256:1bd32d308ef4341513ce023a026f163e"
            "3476b6dbb8f0fe0692688643ef5b272c"
        ),
    },
    {
        "name": "skillspector",
        "version": "2.4.3+git.a54947c",
        "implementation_digest": (
            "sha256:e731be01105243f94437a4b9bd449bd4"
            "6bbcb5cb306f44b4845121d109a4a95e"
        ),
        "config_digest": (
            "sha256:3ea219f45c1b65bff7b521e76d0b38a"
            "6b3a2aee6d260d04f60613e3ee4a7f7ec"
        ),
    },
)
_NVIDIA_INCOMPLETE = "NVIDIA_ANALYSIS_INCOMPLETE"


class CandidateError(ValueError):
    """Phase 0 candidate evidence could not be derived safely."""


def candidate_implementation_digest() -> str:
    """Identify the exact Aragorn Python source closure used by this checkout."""

    root = Path(__file__).parent
    digest = hashlib.sha256(
        b"aragorn-python-source-and-lock-closure/v1\0"
    )
    count = 0
    try:
        for path in sorted(
            root.rglob("*.py"),
            key=lambda item: item.relative_to(root).as_posix(),
        ):
            if path.is_symlink() or not path.is_file():
                raise CandidateError(
                    "candidate implementation contains a non-regular Python source"
                )
            relative = path.relative_to(root).as_posix().encode("utf-8")
            content = path.read_bytes()
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
            count += 1
        lock_path = root.parents[1] / "requirements-worker.lock"
        if lock_path.is_symlink() or not lock_path.is_file():
            raise CandidateError(
                "candidate implementation dependency lock is unavailable"
            )
        lock = lock_path.read_bytes()
        lock_name = b"requirements-worker.lock"
        digest.update(len(lock_name).to_bytes(4, "big"))
        digest.update(lock_name)
        digest.update(len(lock).to_bytes(8, "big"))
        digest.update(lock)
    except OSError as exc:
        raise CandidateError(f"cannot identify candidate implementation: {exc}") from exc
    if count == 0:
        raise CandidateError("candidate implementation source closure is empty")
    return "sha256:" + digest.hexdigest()


def build_candidate_policy(document: object) -> dict[str, Any]:
    """Validate and return an independent canonical candidate-policy copy."""

    policy = _exact_object(document, _POLICY_KEYS, "candidate policy")
    if policy["schema"] != POLICY_SCHEMA:
        raise CandidateError("candidate policy schema is unsupported")
    if policy["assurance"] != POLICY_ASSURANCE:
        raise CandidateError("candidate policy assurance is unsupported")
    if policy["algorithm"] != POLICY_ALGORITHM:
        raise CandidateError("candidate policy algorithm is unsupported")
    candidate = _partial_system(policy["candidate"], "candidate policy candidate")
    if (
        candidate["name"] != "aragorn"
        or candidate["version"] != _CANDIDATE_VERSION
    ):
        raise CandidateError("candidate policy system identity is unsupported")
    if candidate["implementation_digest"] != candidate_implementation_digest():
        raise CandidateError(
            "candidate policy implementation digest does not match composer bytes"
        )
    raw_comparators = policy["required_comparators"]
    if not isinstance(raw_comparators, list) or len(raw_comparators) != 2:
        raise CandidateError(
            "candidate policy requires exactly two comparator identities"
        )
    comparators = [
        _system(value, f"candidate policy comparator[{index}]")
        for index, value in enumerate(raw_comparators)
    ]
    if comparators != list(_REQUIRED_COMPARATORS):
        raise CandidateError("candidate policy comparator identities are unsupported")
    canonical = {
        "schema": POLICY_SCHEMA,
        "assurance": POLICY_ASSURANCE,
        "algorithm": POLICY_ALGORITHM,
        "candidate": candidate,
        "required_comparators": comparators,
    }
    return json.loads(canonical_json(canonical))


def candidate_policy_digest(document: object) -> str:
    """Return the digest of one validated canonical candidate policy."""

    return canonical_digest(build_candidate_policy(document))


def candidate_system_identity(document: object) -> dict[str, str]:
    """Derive the full benchmark identity from one candidate policy."""

    policy = build_candidate_policy(document)
    return {
        **policy["candidate"],
        "config_digest": canonical_digest(policy),
    }


def compose_candidate_decision(
    policy: object,
    source_graph: object,
    components: Iterable[object],
) -> tuple[str, list[str]]:
    """Apply the frozen label-free vendor-union policy."""

    canonical_policy = build_candidate_policy(policy)
    graph = _source_graph(source_graph)
    normalized = [_component(value) for value in components]
    if len(normalized) != 2:
        raise CandidateError("candidate composition requires two components")
    by_name = {item["system"]["name"]: item for item in normalized}
    required = {
        item["name"]: item
        for item in canonical_policy["required_comparators"]
    }
    if set(by_name) != set(required) or any(
        by_name[name]["system"] != required[name] for name in required
    ):
        raise CandidateError(
            "candidate components do not match the frozen comparator identities"
        )
    for field in (
        "suite_digest",
        "case_id",
        "tree_digest",
        "run_id",
        "private_manifest_digest",
        "dispatch_digest",
    ):
        if len({item[field] for item in normalized}) != 1:
            raise CandidateError(
                f"candidate components do not share one {field}"
            )
    if (
        graph["root_manifest_digest"]
        != normalized[0]["private_manifest_digest"]
        or graph["tree_digest"] != normalized[0]["tree_digest"]
    ):
        raise CandidateError(
            "source-reference graph does not match the candidate components"
        )

    errors: set[str] = set()
    if graph["closure"]["status"] != "complete":
        errors.add("SOURCE_REFERENCE_GRAPH_INCOMPLETE")
    for name, component in by_name.items():
        if component["verdict"] == "ERROR":
            errors.add(f"COMPARATOR_ERROR_{_reason_name(name)}")
    if errors:
        return "ERROR", sorted(errors)

    denied = [
        component
        for component in normalized
        if component["verdict"] == "DENY"
    ]
    if denied:
        reasons = _actionable_reasons(denied)
        return "DENY", reasons or ["COMPARATOR_DENY"]

    review_reasons: set[str] = set()
    cisco = by_name["cisco-skill-scanner"]
    if cisco["verdict"] == "REVIEW":
        review_reasons.update(cisco["reason_codes"])
    nvidia = by_name["skillspector"]
    if nvidia["verdict"] == "REVIEW":
        review_reasons.update(
            reason
            for reason in nvidia["reason_codes"]
            if reason != _NVIDIA_INCOMPLETE
        )
    if review_reasons:
        return "REVIEW", sorted(review_reasons)
    return "ALLOW", []


def compose_candidate_batch(
    *,
    dispatch_digest: str,
    control_state: str | os.PathLike[str],
    challenge_ledger: str | os.PathLike[str],
) -> dict[str, Any]:
    """Compose a complete candidate matrix without reading benchmark labels."""

    dispatch_digest = _digest(dispatch_digest, "dispatch digest")
    control_root = _existing_directory(control_state, "control state")
    ledger_root = _existing_directory(challenge_ledger, "challenge ledger")
    if _paths_overlap(control_root, ledger_root):
        raise CandidateError("control state and challenge ledger must not overlap")
    cas = CAS(control_root)
    dispatch = _read_canonical_document(
        cas,
        dispatch_digest,
        "private dispatch v2",
    )
    from .label_blind_prepare import validate_private_dispatch_v2

    try:
        validate_private_dispatch_v2(dispatch)
    except ValueError as exc:
        raise CandidateError(f"private dispatch v2 is invalid: {exc}") from exc
    if canonical_digest(dispatch) != dispatch_digest:
        raise CandidateError("private dispatch v2 digest is not canonical")

    policy = build_candidate_policy(
        _read_canonical_document(
            cas,
            dispatch["candidate_policy_digest"],
            "candidate policy",
        )
    )
    policy_digest = canonical_digest(policy)
    if policy_digest != dispatch["candidate_policy_digest"]:
        raise CandidateError("candidate policy digest changed")
    candidate_system = candidate_system_identity(policy)
    if candidate_system != dispatch["candidate_system"]:
        raise CandidateError("candidate system does not match its policy")

    required_comparators = {
        item["name"]: item for item in policy["required_comparators"]
    }
    cells: dict[tuple[str, int], list[dict[str, Any]]] = {}
    expected_challenges: dict[str, dict[str, Any]] = {}
    subjects: dict[str, dict[str, Any]] = {}
    for entry in dispatch["jobs"]:
        system = entry["system"]
        if required_comparators.get(system["name"]) != system:
            raise CandidateError(
                "private dispatch system is outside the candidate policy"
            )
        request = _read_canonical_document(
            cas,
            entry["request_digest"],
            "worker request v2",
        )
        try:
            validate_worker_request_v2(request)
            manifest_digest = entry["private_manifest_digest"]
            subject = subjects.get(manifest_digest)
            if subject is None:
                manifest = load_retained_manifest(cas, manifest_digest)
                subject = sanitize_subject_manifest(manifest)
                subjects[manifest_digest] = subject
            verify_request_subject_v2(request, subject)
        except (ArtifactClosureError, CASError, WorkerProtocolError) as exc:
            raise CandidateError(f"worker request v2 is invalid: {exc}") from exc
        if canonical_request_digest_v2(request) != entry["request_digest"]:
            raise CandidateError("worker request v2 digest changed")
        if (
            request["job_id"] != entry["job_id"]
            or request["subject"]["tree_digest"] != entry["tree_digest"]
            or request["portable_policy_digest"] != system["config_digest"]
            or request["system"]
            != {
                field: system[field]
                for field in ("name", "version", "implementation_digest")
            }
        ):
            raise CandidateError("worker request v2 does not match private dispatch")
        challenge = request["verifier_challenge"]
        if challenge in expected_challenges:
            raise CandidateError("private dispatch repeats a verifier challenge")
        expected_challenges[challenge] = {**entry, "request": request}
        cells.setdefault((entry["case_id"], entry["run_id"]), []).append(entry)

    expected_names = set(required_comparators)
    for entries in cells.values():
        if (
            len(entries) != 2
            or {entry["system"]["name"] for entry in entries} != expected_names
            or len({entry["tree_digest"] for entry in entries}) != 1
            or len({entry["private_manifest_digest"] for entry in entries}) != 1
        ):
            raise CandidateError(
                "private dispatch does not contain one exact comparator pair per cell"
            )

    component_outcomes: list[dict[str, Any]] = []
    component_evidence: dict[tuple[str, int], list[tuple[str, dict[str, Any]]]] = {}
    for challenge in sorted(expected_challenges):
        entry = expected_challenges[challenge]
        accepted = load_verified_worker_output_acceptance(
            cas,
            ledger_root,
            challenge,
        )
        issuance_digest = _put_json(cas, accepted["issuance"])
        receipt_digest = _put_json(cas, accepted["receipt"])
        receipt = accepted["receipt"]
        if (
            receipt["job_id"] != entry["job_id"]
            or receipt["request_digest"] != entry["request_digest"]
        ):
            raise CandidateError(
                "authenticated worker acceptance does not match private dispatch"
            )
        result = _read_canonical_document(
            cas,
            receipt["result_digest"],
            "worker result v2",
        )
        try:
            validate_worker_result_v2(result)
        except ValueError as exc:
            raise CandidateError(f"worker result v2 is invalid: {exc}") from exc
        system = entry["system"]
        if (
            result["job_id"] != entry["job_id"]
            or result["request_digest"] != entry["request_digest"]
            or result["tree_digest"] != entry["tree_digest"]
            or result["portable_policy_digest"] != system["config_digest"]
            or result["system"]
            != {
                field: system[field]
                for field in ("name", "version", "implementation_digest")
            }
        ):
            raise CandidateError(
                "authenticated worker result does not match private dispatch"
            )
        _validate_result_observations(cas, result)
        evidence = {
            "schema": "aragorn/benchmark-authenticated-worker-evidence/v1",
            "suite_digest": dispatch["suite_digest"],
            "case_id": entry["case_id"],
            "tree_digest": entry["tree_digest"],
            "run_id": entry["run_id"],
            "system": dict(system),
            "verdict": result["verdict"],
            "reason_codes": list(result["reason_codes"]),
            "private_manifest_digest": entry["private_manifest_digest"],
            "dispatch_digest": dispatch_digest,
            "acceptance_receipt_digest": receipt_digest,
            "issuance_digest": issuance_digest,
        }
        evidence_digest = _put_json(cas, evidence)
        outcome = _outcome(evidence, evidence_digest)
        component_outcomes.append(outcome)
        component_evidence.setdefault(
            (entry["case_id"], entry["run_id"]),
            [],
        ).append((evidence_digest, evidence))

    graph_digests: dict[str, str] = {}
    candidate_outcomes: list[dict[str, Any]] = []
    for cell in sorted(cells):
        entries = cells[cell]
        manifest_digest = entries[0]["private_manifest_digest"]
        graph_digest = graph_digests.get(manifest_digest)
        if graph_digest is None:
            try:
                manifest = load_retained_manifest(cas, manifest_digest)
                graph = resolve_source_graph(
                    manifest,
                    cas,
                    root_manifest_digest=manifest_digest,
                )
            except (ArtifactClosureError, CASError) as exc:
                raise CandidateError(
                    f"cannot derive source-reference graph: {exc}"
                ) from exc
            graph_digest = _put_json(cas, graph)
            graph_digests[manifest_digest] = graph_digest
        else:
            graph = _read_canonical_document(
                cas,
                graph_digest,
                "source-reference graph",
            )
        components = sorted(
            component_evidence[cell],
            key=lambda item: item[1]["system"]["name"],
        )
        verdict, reasons = compose_candidate_decision(
            policy,
            graph,
            (item[1] for item in components),
        )
        candidate_evidence = {
            "schema": "aragorn/benchmark-candidate-evidence/v1",
            "suite_digest": dispatch["suite_digest"],
            "case_id": cell[0],
            "tree_digest": entries[0]["tree_digest"],
            "run_id": cell[1],
            "system": candidate_system,
            "verdict": verdict,
            "reason_codes": reasons,
            "private_manifest_digest": manifest_digest,
            "source_graph_digest": graph_digest,
            "dispatch_digest": dispatch_digest,
            "policy_digest": policy_digest,
            "component_evidence_digests": sorted(
                item[0] for item in components
            ),
        }
        evidence_digest = _put_json(cas, candidate_evidence)
        candidate_outcomes.append(_outcome(candidate_evidence, evidence_digest))

    outcomes = sorted(
        [*component_outcomes, *candidate_outcomes],
        key=lambda item: (
            item["system"]["name"],
            item["system"]["version"],
            item["system"]["implementation_digest"],
            item["system"]["config_digest"],
            item["case_id"],
            item["run_id"],
        ),
    )
    expected_outcomes = len(cells) * 3
    if len(outcomes) != expected_outcomes:
        raise CandidateError("candidate composition matrix is incomplete")
    composition = {
        "schema": "aragorn/benchmark-candidate-composition/v1",
        "assurance": COMPOSITION_ASSURANCE,
        "suite_digest": dispatch["suite_digest"],
        "dispatch_digest": dispatch_digest,
        "policy_digest": policy_digest,
        "outcomes_digest": canonical_digest(outcomes),
        "outcomes": outcomes,
    }
    _put_json(cas, composition)
    return composition


def _component(value: object) -> dict[str, Any]:
    component = _exact_object(
        value,
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
        "candidate component",
    )
    if component["schema"] != "aragorn/benchmark-authenticated-worker-evidence/v1":
        raise CandidateError("candidate component schema is unsupported")
    system = _system(component["system"], "candidate component system")
    verdict, reasons = _verdict(
        component["verdict"],
        component["reason_codes"],
        "candidate component",
    )
    return {**component, "system": system, "verdict": verdict, "reason_codes": reasons}


def _source_graph(value: object) -> dict[str, Any]:
    graph = _exact_object(
        value,
        {
            "schema",
            "profile",
            "assurance",
            "source_assurance",
            "root_manifest_digest",
            "tree_digest",
            "nodes",
            "edges",
            "closure",
        },
        "source-reference graph",
    )
    if graph["schema"] != "aragorn/source-artifact-graph/v1":
        raise CandidateError("source-reference graph schema is unsupported")
    if (
        graph["profile"] != SOURCE_GRAPH_PROFILE
        or graph["assurance"] != SOURCE_GRAPH_ASSURANCE
        or graph["source_assurance"]
        not in {
            "local_manifest_reverified",
            "github_api_membership_asserted_blob_identity_reverified",
        }
    ):
        raise CandidateError("source-reference graph profile is unsupported")
    _digest(graph["root_manifest_digest"], "source-reference graph root manifest")
    _digest(graph["tree_digest"], "source-reference graph tree")
    if not isinstance(graph["nodes"], list) or not isinstance(graph["edges"], list):
        raise CandidateError("source-reference graph collections are invalid")
    closure = _exact_object(
        graph["closure"],
        {"scope", "profile", "status", "unresolved"},
        "source-reference graph closure",
    )
    if (
        closure["scope"] != "source_reference_graph"
        or closure["profile"] != SOURCE_GRAPH_PROFILE
        or closure["status"] not in {"complete", "incomplete"}
        or not isinstance(closure["unresolved"], list)
    ):
        raise CandidateError("source-reference graph closure is invalid")
    if (closure["status"] == "complete") != (not closure["unresolved"]):
        raise CandidateError("source-reference graph closure is inconsistent")
    return graph


def _outcome(evidence: dict[str, Any], evidence_digest: str) -> dict[str, Any]:
    return {
        "schema": "aragorn/benchmark-outcome/v1",
        **{
            field: evidence[field]
            for field in (
                "suite_digest",
                "case_id",
                "tree_digest",
                "run_id",
                "system",
            )
        },
        "evidence_digest": evidence_digest,
        "verdict": evidence["verdict"],
        "reason_codes": list(evidence["reason_codes"]),
    }


def _validate_result_observations(cas: CAS, result: dict[str, Any]) -> None:
    raw = b"\n".join(
        cas.read(digest, max_bytes=8 * 1024 * 1024)
        for digest in result["observation_digests"]
    )
    observations, error = _parse_observations(raw, result["tree_digest"])
    if error is not None or len(observations) != len(result["observation_digests"]):
        raise CandidateError("worker result observations do not re-parse")


def _actionable_reasons(components: Iterable[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            reason
            for component in components
            for reason in component["reason_codes"]
            if reason != _NVIDIA_INCOMPLETE
        }
    )


def _reason_name(name: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", name.upper()).strip("_")


def _verdict(
    verdict: object,
    reasons: object,
    label: str,
) -> tuple[str, list[str]]:
    if verdict not in {"ALLOW", "REVIEW", "DENY", "ERROR"}:
        raise CandidateError(f"{label} verdict is unsupported")
    if not isinstance(reasons, list) or any(
        not isinstance(reason, str)
        or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", reason) is None
        for reason in reasons
    ):
        raise CandidateError(f"{label} reason codes are invalid")
    if reasons != sorted(set(reasons)):
        raise CandidateError(f"{label} reason codes must be sorted and unique")
    if (verdict == "ALLOW") != (not reasons):
        raise CandidateError(f"{label} verdict and reason codes are inconsistent")
    return str(verdict), list(reasons)


def _partial_system(value: object, label: str) -> dict[str, str]:
    system = _exact_object(value, _PARTIAL_SYSTEM_KEYS, label)
    return {
        "name": _identifier(system["name"], f"{label}.name"),
        "version": _version(system["version"], f"{label}.version"),
        "implementation_digest": _digest(
            system["implementation_digest"],
            f"{label}.implementation_digest",
        ),
    }


def _system(value: object, label: str) -> dict[str, str]:
    system = _exact_object(value, _SYSTEM_KEYS, label)
    return {
        **_partial_system(
            {field: system[field] for field in _PARTIAL_SYSTEM_KEYS},
            label,
        ),
        "config_digest": _digest(
            system["config_digest"],
            f"{label}.config_digest",
        ),
    }


def _version(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(
            unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise CandidateError(f"{label} is not canonical")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise CandidateError(f"{label} is not a canonical identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CandidateError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _exact_object(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CandidateError(f"{label} has missing or unknown fields")
    return value


def _read_canonical_document(
    cas: CAS,
    digest: str,
    label: str,
) -> dict[str, Any]:
    try:
        raw = cas.read(_digest(digest, f"{label} digest"), max_bytes=_MAX_DOCUMENT_BYTES)
        document = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except (CASError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise CandidateError(f"cannot read {label}: {exc}") from exc
    if not isinstance(document, dict) or canonical_json(document) != raw:
        raise CandidateError(f"{label} must be a canonical JSON object")
    return document


def _put_json(cas: CAS, document: object) -> str:
    raw = canonical_json(document)
    try:
        return cas.put(BytesIO(raw), max_bytes=len(raw))
    except CASError as exc:
        raise CandidateError(f"cannot retain candidate evidence: {exc}") from exc


def _existing_directory(
    value: str | os.PathLike[str],
    label: str,
) -> Path:
    try:
        path = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise CandidateError(f"cannot resolve {label}: {exc}") from exc
    if not path.is_dir():
        raise CandidateError(f"{label} must be a directory")
    return path


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise CandidateError(f"duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_nonfinite(value: str) -> None:
    raise CandidateError(f"non-finite JSON number: {value}")
