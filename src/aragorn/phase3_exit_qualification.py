"""Compose Phase 3 evidence using explicitly selected independent verifiers.

This is an in-process trusted-operator API, not a JSON verdict importer. Verifier
functions are reviewed application code; their source pins identify their bytes,
not their correctness or transitive dependency closure. No verifier is selected
from evidence, imported by name, or provided by an agent under evaluation.

Each semantic verifier must independently establish its requirement, freshness,
isolation, cleanup and deployment/campaign joins from raw evidence. The composer
checks the complete inventory and those joins, and recomputes metrics itself.
There is intentionally no default verifier that accepts recorded PASS flags.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_deployment import resolve_phase3_deployment_identity
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes
from .phase3_quantitative_metrics import (
    build_phase3_measurement_schedule,
    metrics_implementation_digest,
    qualify_phase3_quantitative_metrics_bytes,
)

GATE_MANIFEST_DIGEST = (
    "sha256:aff633a6d0d482cf79e3e540b0e7b8336cf266765eaacf277c9ac23ed5279f1d"
)
VERIFICATION_SCHEMA = "aragorn/phase3-independent-semantic-verification/v1"
_MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_BYTES = 1024 * 1024
_MEASUREMENTS = "MEASUREMENT_SEMANTICS"
_BOUNDARY = "EXTERNAL_OS_BROKER_AND_OUT_OF_PROCESS_SENSOR"


class Phase3ExitQualificationError(ValueError):
    """The complete same-deployment gate cannot be independently evaluated."""


@dataclass(frozen=True)
class Phase3SemanticVerifier:
    """A trusted top-level function and its operator-held source-file identity."""

    verify: Callable[[bytes, dict[str, str], CAS], dict[str, Any]]
    source_digest: str


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pin(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise Phase3ExitQualificationError("expected a caller-held SHA-256 pin")
    return value


def _manifest(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or _digest(raw) != GATE_MANIFEST_DIGEST:
        raise Phase3ExitQualificationError("fixed Phase 3 requirements changed")
    return load_phase3_exit_gate_manifest_bytes(raw)


def required_phase3_evidence_ids(manifest_raw: bytes) -> tuple[str, ...]:
    """Return 31 admission, 15 RUN, one boundary and one metrics requirement."""
    manifest = _manifest(manifest_raw)
    admission = ["DET-01", "ADM-01/exact-admitted-bytes"]
    admission += [
        "ADM-02/" + name.lower().replace("_", "-")
        for name in manifest["admission"]["mandatory_activation_path_classes"]
        if name not in {"UPDATE", "RELOAD"}
    ]
    admission += manifest["admission"]["adm_02_routes"]
    admission += ["ADM-03/policy-failure", "ADM-03/policy-tampering"]
    runtime = manifest["runtime_prevention"]
    result = (
        *admission,
        *(row["id"] for row in runtime["required_properties"]),
        *("EVENT/" + value for value in runtime["required_event_classes"]),
        *("RESPONSE/" + value for value in runtime["required_responses"]),
        _BOUNDARY,
        _MEASUREMENTS,
    )
    if len(admission) != 31 or len(result) != 48 or len(set(result)) != 48:
        raise Phase3ExitQualificationError("fixed gate inventory changed")
    return result


def _verify_source(verifier: Phase3SemanticVerifier) -> dict[str, str]:
    if type(verifier) is not Phase3SemanticVerifier:
        raise Phase3ExitQualificationError("independent verifier is not registered")
    fn = verifier.verify
    module = inspect.getmodule(fn)
    if (
        not inspect.isfunction(fn)
        or fn.__closure__ is not None
        or fn.__name__ != fn.__qualname__
        or module is None
        or getattr(module, fn.__name__, None) is not fn
    ):
        raise Phase3ExitQualificationError(
            "verifier must be a trusted top-level function"
        )
    filename = inspect.getsourcefile(fn)
    if filename is None:
        raise Phase3ExitQualificationError("verifier source is unavailable")
    path = Path(filename).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
        raise Phase3ExitQualificationError("verifier source custody is invalid")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or not 0 < before.st_size <= _MAX_SOURCE_BYTES
        ):
            raise Phase3ExitQualificationError(
                "verifier source is not a bounded regular file"
            )
        raw = stream.read(_MAX_SOURCE_BYTES + 1)
        after = os.fstat(stream.fileno())
    named = path.lstat()
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        len(raw) != before.st_size
        or any(
            getattr(before, field) != getattr(after, field)
            or getattr(after, field) != getattr(named, field)
            for field in fields
        )
        or _digest(raw) != _pin(verifier.source_digest)
    ):
        raise Phase3ExitQualificationError(
            "verifier source differs from its frozen pin"
        )
    return {
        "module": fn.__module__,
        "function": fn.__name__,
        "source_digest": verifier.source_digest,
    }


def _result(value: object, context: dict[str, str]) -> dict[str, Any]:
    if (
        type(value) is not dict
        or set(value) != {"schema", "bindings", "status", "reason_codes"}
        or value["schema"] != VERIFICATION_SCHEMA
        or canonical_json(value["bindings"]) != canonical_json(context)
        or type(value["status"]) is not str
        or value["status"] not in {"PASS", "FAIL", "NOT_TESTED"}
        or type(value["reason_codes"]) is not list
        or not 1 <= len(value["reason_codes"]) <= 32
        or any(
            type(code) is not str
            or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", code) is None
            for code in value["reason_codes"]
        )
    ):
        raise Phase3ExitQualificationError(
            "independent semantic result is invalid or unbound"
        )
    return {
        "schema": VERIFICATION_SCHEMA,
        "bindings": dict(context),
        "status": value["status"],
        "reason_codes": list(value["reason_codes"]),
    }


def qualify_phase3_exit(
    *,
    manifest_raw: bytes,
    deployment_raw: bytes,
    expected_deployment_digest: str,
    expected_campaign_contract_digest: str,
    measurement_schedule: dict[str, Any],
    expected_measurement_schedule_digest: str,
    expected_metrics_implementation_digest: str,
    evidence_by_requirement: dict[str, str],
    verifiers: dict[str, Phase3SemanticVerifier],
    evidence_cas: CAS,
) -> dict[str, Any]:
    """Evaluate the complete gate; never promote old receipts or arithmetic alone.

    The verifier registry and all expected pins must come from the trusted
    operator's frozen plan, not from the evidence being evaluated. Missing
    adapters/evidence are rejected before any verifier is called. Semantic
    failures return a non-eligible result; malformed evidence raises.
    """
    required = required_phase3_evidence_ids(manifest_raw)
    if type(evidence_by_requirement) is not dict or type(verifiers) is not dict:
        raise Phase3ExitQualificationError(
            "gate requires exact evidence and verifier maps"
        )
    for label, inventory in (
        ("evidence", evidence_by_requirement),
        ("verifiers", verifiers),
    ):
        if set(inventory) != set(required):
            missing = sorted(set(required) - set(inventory))
            extra = sorted(set(inventory) - set(required))
            raise Phase3ExitQualificationError(
                f"incomplete {label}: missing={missing}; extra={extra}"
            )
    evidence_pins = {key: _pin(evidence_by_requirement[key]) for key in required}
    selected = dict(verifiers)
    verifier_pins = {key: _verify_source(selected[key]) for key in required}
    metrics_pin = _pin(expected_metrics_implementation_digest)
    if metrics_pin != metrics_implementation_digest():
        raise Phase3ExitQualificationError("metrics verifier differs from frozen plan")
    deployment = resolve_phase3_deployment_identity(
        deployment_raw,
        expected_digest=expected_deployment_digest,
        evidence_cas=evidence_cas,
    )
    contract_pin = _pin(expected_campaign_contract_digest)
    if not evidence_cas.read(contract_pin, max_bytes=1024 * 1024):
        raise Phase3ExitQualificationError("campaign contract is empty")
    for key in required:
        if not evidence_cas.read(evidence_pins[key], max_bytes=_MAX_EVIDENCE_BYTES):
            raise Phase3ExitQualificationError(f"empty evidence for {key}")
    schedule_pin = _pin(expected_measurement_schedule_digest)
    # Rebuild with the fixed metrics implementation: an evidence-supplied schedule
    # cannot change counts, families, negative control, task pairs, or bindings.
    try:
        attempt = measurement_schedule["attempt_schedule"]
        pairs = measurement_schedule["overhead_schedule"]
        arguments = {
            "expected_attempt_ids": attempt["attempt_ids"],
            "expected_attempt_families": attempt["attempt_families"],
            "expected_overhead_pair_bindings": pairs["pair_bindings"],
            "expected_unattributed_attempt_id": attempt[
                "unattributed_negative_control_attempt_id"
            ],
            "expected_gate_manifest_digest": GATE_MANIFEST_DIGEST,
            "expected_campaign_contract_digest": contract_pin,
            "expected_runtime_identity_digest": expected_deployment_digest,
        }
        schedule = build_phase3_measurement_schedule(**arguments)
        if (
            canonical_json(measurement_schedule) != canonical_json(schedule)
            or canonical_digest(schedule) != schedule_pin
        ):
            raise Phase3ExitQualificationError(
                "measurement schedule differs from frozen plan"
            )
        arguments = json.loads(canonical_json(arguments))
    except (KeyError, TypeError, ValueError) as exc:
        raise Phase3ExitQualificationError("measurement schedule is invalid") from exc
    results = {}
    metrics_raw = None
    # Verifiers resolve related receipts through a read-only view. No loader or
    # writable evidence store is supplied by the data under evaluation.
    verifier_cas = CAS(evidence_cas.root, read_only=True)
    for key in required:
        _verify_source(selected[key])
        raw = evidence_cas.read(evidence_pins[key], max_bytes=_MAX_EVIDENCE_BYTES)
        if not raw:
            raise Phase3ExitQualificationError(f"empty evidence for {key}")
        context = {
            "requirement_id": key,
            "evidence_digest": evidence_pins[key],
            "deployment_identity_digest": expected_deployment_digest,
            "gate_manifest_digest": GATE_MANIFEST_DIGEST,
            "campaign_contract_digest": contract_pin,
            "measurement_schedule_digest": schedule_pin,
        }
        result = selected[key].verify(raw, dict(context), verifier_cas)
        _verify_source(selected[key])
        results[key] = _result(result, context)
        if key == _MEASUREMENTS:
            metrics_raw = raw
    # No arithmetic can upgrade unverified observations into an exit PASS.
    semantic_pass = all(result["status"] == "PASS" for result in results.values())
    metrics = None
    if semantic_pass:
        metrics = qualify_phase3_quantitative_metrics_bytes(
            metrics_raw,
            **arguments,
            expected_measurement_schedule_digest=schedule_pin,
            expected_metrics_implementation_digest=metrics_pin,
        )
    # Re-resolve final joins and code pins so changing custody fails closed.
    resolve_phase3_deployment_identity(
        deployment_raw,
        expected_digest=expected_deployment_digest,
        evidence_cas=evidence_cas,
    )
    for key in required:
        _verify_source(selected[key])
        evidence_cas.verify(evidence_pins[key], max_bytes=_MAX_EVIDENCE_BYTES)
    evidence_cas.verify(contract_pin, max_bytes=1024 * 1024)
    if metrics_pin != metrics_implementation_digest():
        raise Phase3ExitQualificationError(
            "metrics verifier changed during qualification"
        )
    return {
        "schema": "aragorn/phase3-exit-qualification/v1",
        "authority": "PHASE3_V1_SAME_DEPLOYMENT_EVIDENCE_COMPOSITION_NOT_INSTALLER_EDR_OR_RELEASE_AUTHORITY",
        "deployment": deployment,
        "deployment_identity_digest": expected_deployment_digest,
        "gate_manifest_digest": GATE_MANIFEST_DIGEST,
        "campaign_contract_digest": contract_pin,
        "measurement_schedule_digest": schedule_pin,
        "metrics_implementation_digest": metrics_pin,
        "verifiers": verifier_pins,
        "requirements": results,
        "quantitative_metrics": metrics,
        "decision": {
            "status": "PASS" if semantic_pass else "FAIL",
            "phase3_exit_eligible": semantic_pass,
            "edr_eligible": False,
            "installer_work_eligible": False,
            "release_eligible": False,
        },
        "limitations": [
            "SEMANTIC_VERIFIER_CODE_AND_OPERATOR_HELD_PINS_ARE_TRUSTED_INPUTS",
            "SOURCE_FILE_PINS_ARE_NOT_PROOF_OF_SEMANTIC_CORRECTNESS_OR_DEPENDENCY_CLOSURE",
            "SAME_DEPLOYMENT_PHASE3_ONLY_NOT_HOSTILE_ROOT_OR_EXTERNAL_ATTESTATION",
        ],
    }
