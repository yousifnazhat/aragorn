"""Validate Aragorn schemas and checked-in contract examples."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

try:
    from jsonschema import FormatChecker
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
except ImportError as exc:  # pragma: no cover - developer setup error
    raise SystemExit(
        "jsonschema is required; run with: uv run --python 3.12 --with jsonschema "
        "python scripts/validate_schemas.py"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aragorn.benchmark import evaluate_files  # noqa: E402
from aragorn.benchmark_handoff_v2 import build_handoff_manifest  # noqa: E402
from aragorn.benchmark_protocol_v2 import (  # noqa: E402
    build_worker_request_v2,
    canonical_request_digest_v2,
    portable_policy_digest,
    validate_worker_result_v2,
    verify_request_result_binding_v2,
)
from aragorn.corpus_audit import audit_suite  # noqa: E402
from aragorn.oci_worker_protocol import canonical_digest  # noqa: E402
from aragorn.standards_gate import validate_standards_gate  # noqa: E402
from aragorn.benchmark_worker_measurement import (  # noqa: E402
    build_worker_measurement,
    build_worker_trust_store,
)


def load(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    schemas = {
        path.name: load(path) for path in sorted((ROOT / "schema").glob("*.json"))
    }
    registry = Registry().with_resources(
        (
            schema["$id"],
            Resource.from_contents(schema),
        )
        for schema in schemas.values()
        if isinstance(schema, dict) and "$id" in schema
    )
    validators = {}
    for name, schema in schemas.items():
        validator_class = validator_for(schema)
        validator_class.check_schema(schema)
        validators[name] = validator_class(
            schema,
            format_checker=FormatChecker(),
            registry=registry,
        )

    baseline_lock = load(ROOT / "benchmark" / "baselines.lock.json")
    validators["baseline-lock-v1.schema.json"].validate(baseline_lock)
    validators["benchmark-corpus-provenance-lock-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "phase0-corpus.lock.json")
    )
    standards_gate = load(ROOT / "benchmark" / "phase0-standards-gate.json")
    validators["phase0-standards-gate-v1.schema.json"].validate(standards_gate)
    validate_standards_gate(standards_gate, repository_root=ROOT)
    validators["benchmark-suite-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "suite.json")
    )
    validators["benchmark-suite-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "oci-suite.json")
    )
    validators["benchmark-suite-v1.schema.json"].validate(
        load(ROOT / "benchmark" / "phase0-oci-pilot-v1.json")
    )
    validators["benchmark-e2e-smoke-receipt-v1.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / "phase0-local-label-free-smoke-2026-07-22.json"
        )
    )
    validators["benchmark-isolated-smoke-receipt-v1.schema.json"].validate(
        load(
            ROOT
            / "benchmark"
            / "receipts"
            / "phase0-isolated-protocol-v2-smoke-2026-07-23.json"
        )
    )
    validators["corpus-audit-v1.schema.json"].validate(
        audit_suite(ROOT / "benchmark" / "phase0-oci-pilot-v1.json")
    )
    outcome_validator = validators["benchmark-outcome-v1.schema.json"]
    for line in (
        (ROOT / "benchmark" / "outcomes.jsonl").read_text(encoding="utf-8").splitlines()
    ):
        outcome_validator.validate(json.loads(line))
    report = evaluate_files(
        ROOT / "benchmark" / "suite.json",
        ROOT / "benchmark" / "outcomes.jsonl",
    )
    validators["benchmark-report-v1.schema.json"].validate(report)
    digest = "sha256:" + "0" * 64
    validators["benchmark-prepare-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-prepare-result/v1",
            "suite_digest": digest,
            "dispatch_digest": digest,
            "worker_identities_digest": digest,
            "worklist_digest": digest,
            "job_count": 1,
        }
    )
    validators["benchmark-collection-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-collection-result/v1",
            "assurance": "unsigned_label_free_protocol_not_isolated_or_attested",
            "suite_digest": digest,
            "dispatch_digest": digest,
            "ledger_id": digest,
            "collection_digest": digest,
            "outcomes_digest": digest,
            "report_digest": digest,
            "job_count": 1,
        }
    )
    baseline = baseline_lock["baselines"][0]
    files = [
        {
            "path": "SKILL.md",
            "size": 0,
            "digest": digest,
            "executable": False,
        }
    ]
    subject = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": canonical_digest(files),
        "files": files,
    }
    portable_policy = {
        "schema": "aragorn/benchmark-portable-policy/v1",
        "system": {
            "name": baseline["name"],
            "version": baseline["version"],
            "implementation_digest": baseline["image"]["platform_manifest_digest"],
        },
        "baseline": {
            "lock_digest": canonical_digest(baseline_lock),
            "entry_digest": canonical_digest(baseline),
        },
        "image": {
            key: baseline["image"][key]
            for key in (
                "index_digest",
                "platform_manifest_digest",
                "config_digest",
                "build_provenance_manifest_digest",
                "os",
                "architecture",
                "size_bytes",
            )
        },
        "entrypoint": ["/opt/venv/bin/skill-scanner"],
        "arguments": [
            ("/workspace" if argument == "{workspace}" else argument)
            for argument in baseline["profile"]["arguments"]
        ],
        "environment": {},
        "runtime_profile": baseline["runtime_profile"],
        "limits": {
            "timeout_seconds": 120.0,
            "output_bytes": 1024 * 1024,
        },
        "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
    }
    validators["benchmark-portable-policy-v1.schema.json"].validate(portable_policy)
    request_v2 = build_worker_request_v2(
        subject,
        portable_policy,
        verifier_challenge="a" * 64,
        token_hex=lambda _size: "b" * 32,
    )
    validators["benchmark-worker-request-v2.schema.json"].validate(request_v2)
    request_v2_digest = canonical_request_digest_v2(request_v2)
    result_v2 = {
        "schema": "aragorn/benchmark-worker-result/v2",
        "job_id": request_v2["job_id"],
        "verifier_challenge": request_v2["verifier_challenge"],
        "request_digest": request_v2_digest,
        "portable_policy_digest": portable_policy_digest(portable_policy),
        "subject_manifest_digest": request_v2["subject"]["manifest_digest"],
        "tree_digest": request_v2["subject"]["tree_digest"],
        "verified_subject_digest": request_v2["subject"]["tree_digest"],
        "system": request_v2["system"],
        "baseline_lock_digest": request_v2["baseline"]["lock_digest"],
        "baseline_entry_digest": request_v2["baseline"]["entry_digest"],
        "effective_config_digest": digest,
        "docker_executable_digest": digest,
        "oci_index_digest": portable_policy["image"]["index_digest"],
        "oci_platform_manifest_digest": portable_policy["image"][
            "platform_manifest_digest"
        ],
        "build_provenance_manifest_digest": portable_policy["image"][
            "build_provenance_manifest_digest"
        ],
        "index_inspect_digest": digest,
        "platform_inspect_digest": digest,
        "image_config_digest": portable_policy["image"]["config_digest"],
        "runner_receipts": {
            phase: {
                "context_inspect_digest": digest,
                "daemon_version_digest": digest,
                "daemon_info_digest": digest,
            }
            for phase in ("pre", "post")
        },
        "prestart_container_inspect_digest": digest,
        "postrun_container_inspect_digest": digest,
        "stdout_digest": digest,
        "stderr_digest": digest,
        "observation_digests": [],
        "execution": {
            "status": "ok",
            "error_code": None,
            "returncode": 0,
            "container_id": "c" * 64,
        },
        "normalization": portable_policy["normalization"],
        "verdict": "ALLOW",
        "reason_codes": [],
    }
    validate_worker_result_v2(result_v2)
    verify_request_result_binding_v2(
        request_v2,
        portable_policy,
        result_v2,
        expected_request_digest=request_v2_digest,
        expected_challenge=request_v2["verifier_challenge"],
    )
    result_v2_validator = validators["benchmark-worker-result-v2.schema.json"]
    result_v2_validator.validate(result_v2)
    invalid_result_v2 = deepcopy(result_v2)
    invalid_result_v2["normalization"] = "nvidia-skillspector-2.4.3/v1"
    if result_v2_validator.is_valid(invalid_result_v2):
        raise AssertionError(
            "worker result v2 schema accepted cross-system normalization"
        )
    invalid_result_v2 = deepcopy(result_v2)
    invalid_result_v2["execution"] = {
        "status": "error",
        "error_code": "TIMEOUT",
        "returncode": -1,
        "container_id": "c" * 64,
    }
    invalid_result_v2["verdict"] = "DENY"
    invalid_result_v2["reason_codes"] = ["ANALYZER_TIMEOUT"]
    if result_v2_validator.is_valid(invalid_result_v2):
        raise AssertionError(
            "worker result v2 schema accepted an unbound error verdict"
        )
    invalid_result_v2 = deepcopy(result_v2)
    invalid_result_v2["observation_digests"] = [digest, digest]
    if result_v2_validator.is_valid(invalid_result_v2):
        raise AssertionError("worker result v2 schema accepted duplicate observations")
    public_key = bytes(range(32))
    key_id = "sha256:" + hashlib.sha256(public_key).hexdigest()
    trust_store = build_worker_trust_store(
        trust_domain="phase0.example",
        keys=[
            {
                "key_id": key_id,
                "algorithm": "Ed25519",
                "public_key": public_key.hex(),
                "worker_id": "isolated-worker-01",
                "scopes": ["aragorn/benchmark-worker-output/v2"],
                "status": "active",
            }
        ],
    )
    validators["benchmark-worker-trust-store-v1.schema.json"].validate(
        trust_store
    )
    measurement = build_worker_measurement(
        trust_domain=trust_store["trust_domain"],
        worker_id=trust_store["keys"][0]["worker_id"],
        key_id=key_id,
        job_id=request_v2["job_id"],
        verifier_challenge=request_v2["verifier_challenge"],
        request_digest=request_v2_digest,
        result_digest=digest,
        handoff_manifest_digest=digest,
    )
    validators["benchmark-worker-measurement-v1.schema.json"].validate(
        measurement
    )
    issuance = {
        "schema": "aragorn/benchmark-worker-measurement-issuance/v1",
        "trust_domain": measurement["trust_domain"],
        "worker_id": measurement["worker_id"],
        "job_id": measurement["job_id"],
        "request_digest": measurement["request_digest"],
        "verifier_challenge": measurement["verifier_challenge"],
    }
    validators[
        "benchmark-worker-measurement-issuance-v1.schema.json"
    ].validate(issuance)
    validators["benchmark-worker-output-acceptance-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-worker-output-acceptance/v1",
            "assurance": "software_key_signature_not_hardware_attested",
            "issuance_digest": canonical_digest(issuance),
            "trust_store_digest": canonical_digest(trust_store),
            "envelope_digest": digest,
            "key_id": key_id,
            "trust_domain": measurement["trust_domain"],
            "worker_id": measurement["worker_id"],
            "job_id": measurement["job_id"],
            "verifier_challenge": measurement["verifier_challenge"],
            "request_digest": measurement["request_digest"],
            "result_digest": measurement["result_digest"],
            "handoff_manifest_digest": measurement["handoff_manifest_digest"],
        }
    )
    validators["benchmark-worker-supervisor-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/benchmark-worker-supervisor-result/v1",
            "assurance": "software_key_signature_not_hardware_attested",
            "request_digest": request_v2_digest,
            "result_digest": digest,
            "handoff_manifest_digest": digest,
            "envelope_digest": digest,
        }
    )
    validators["benchmark-cas-handoff-v1.schema.json"].validate(
        build_handoff_manifest(
            kind="worker_input",
            root_digest=digest,
            blobs={digest: 0},
        )
    )

    expansion_accounting = {
        "references": {
            "total_edges": 0,
            "artifact_references": 0,
            "resolved_in_root": 0,
            "expanded": 0,
            "deduplicated": 0,
            "non_artifact": 0,
            "unresolved": 0,
            "opaque_carriers": 0,
            "scan_complete": True,
            "occurrences_complete": True,
            "occurrences_omitted": 0,
        },
        "budgets": {
            "api_requests": {"limit": 20_050, "used": 2},
            "api_bytes": {"limit": 402_653_184, "used": 1024},
            "retained_bytes": {"limit": 134_217_728, "used": 0},
            "expanded_objects": {"limit": 256, "used": 0},
            "expansion_depth": {"limit": 4, "used": 0},
            "references": {"limit": 10_000, "used": 0},
        },
    }
    expansion = {
        "schema": "aragorn/github-expansion/v1",
        "profile": "phase0-exact-github-blob-expansion/v1",
        "assurance": (
            "evaluation_only_github_api_membership_asserted_blob_identity_reverified"
        ),
        "source": {
            "host": "github.com",
            "owner": "example",
            "repository": "project",
            "commit": "0" * 40,
            "commit_tree": "1" * 40,
            "skill_path": "skills/demo",
            "api_version": "2026-03-10",
        },
        "root_manifest_digest": digest,
        "root_tree_digest": digest,
        "comparator_subject_manifest_digest": digest,
        "comparator_subject_tree_digest": digest,
        "references": [],
        "objects": [],
        "accounting": expansion_accounting,
        "closure": {
            "scope": "phase0_exact_github_blob_expansion",
            "status": "complete",
            "unresolved": [],
        },
    }
    validators["github-expansion-v1.schema.json"].validate(expansion)
    expansion_result = {
        "schema": "aragorn/github-expansion-result/v1",
        "expansion_digest": digest,
        "root_manifest_digest": digest,
        "root_tree_digest": digest,
        "comparator_subject_manifest_digest": digest,
        "comparator_subject_tree_digest": digest,
        "expanded_object_count": 0,
        "accounting": expansion_accounting,
        "closure": expansion["closure"],
    }
    validators["github-expansion-result-v1.schema.json"].validate(expansion_result)
    incomplete_expansion = deepcopy(expansion)
    incomplete_expansion["comparator_subject_manifest_digest"] = None
    incomplete_expansion["comparator_subject_tree_digest"] = None
    incomplete_expansion["closure"] = {
        "scope": "phase0_exact_github_blob_expansion",
        "status": "incomplete",
        "unresolved": [
            {
                "reason_code": "MUTABLE_GITHUB_REFERENCE",
                "subject": "skills/demo/SKILL.md",
            }
        ],
    }
    validators["github-expansion-v1.schema.json"].validate(incomplete_expansion)
    source_graph = {
        "schema": "aragorn/source-artifact-graph/v1",
        "profile": "phase0-literal-source-refs/v1",
        "assurance": "evaluation_only_literal_reference_profile",
        "source_assurance": "local_manifest_reverified",
        "root_manifest_digest": digest,
        "tree_digest": digest,
        "nodes": [
            {
                "path": "SKILL.md",
                "size": 0,
                "digest": digest,
                "executable": False,
                "scan_status": "scanned",
                "opaque_reason": None,
            }
        ],
        "edges": [],
        "closure": {
            "scope": "source_reference_graph",
            "profile": "phase0-literal-source-refs/v1",
            "status": "complete",
            "unresolved": [],
        },
    }
    validators["source-artifact-graph-v1.schema.json"].validate(source_graph)
    validators["resolve-artifacts-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/resolve-artifacts-result/v1",
            "assurance": "evaluation_only_literal_reference_profile",
            "root_manifest_digest": digest,
            "graph_digest": digest,
            "closure": source_graph["closure"],
        }
    )
    graph_validator = validators["source-artifact-graph-v1.schema.json"]
    opaque_complete = deepcopy(source_graph)
    opaque_complete["nodes"][0]["scan_status"] = "opaque"
    opaque_complete["nodes"][0]["opaque_reason"] = "NON_UTF8_CARRIER"
    if graph_validator.is_valid(opaque_complete):
        raise AssertionError("complete source graph accepted an opaque node")
    unresolved_complete = deepcopy(source_graph)
    unresolved_complete["edges"] = [
        {
            "source_path": "SKILL.md",
            "source_blob_digest": digest,
            "byte_offset": 0,
            "literal_digest": digest,
            "reference_kind": "external",
            "status": "unresolved",
            "literal": "https://example.test/payload",
            "target": None,
            "reason_code": "EXTERNAL_REFERENCE_UNSUPPORTED",
        }
    ]
    if graph_validator.is_valid(unresolved_complete):
        raise AssertionError("complete source graph accepted an unresolved edge")
    resolved_dynamic = deepcopy(source_graph)
    resolved_dynamic["edges"] = [
        {
            "source_path": "SKILL.md",
            "source_blob_digest": digest,
            "byte_offset": 0,
            "literal_digest": digest,
            "reference_kind": "dynamic_command",
            "status": "resolved",
            "literal": None,
            "target": {"path": "SKILL.md", "digest": digest},
            "reason_code": None,
        }
    ]
    if graph_validator.is_valid(resolved_dynamic):
        raise AssertionError("source graph accepted a resolved dynamic command")
    decision = {
        "schema": "aragorn/decision/v1",
        "verdict": "ERROR",
        "manifest_digest": digest,
        "tree_digest": digest,
        "artifact_digests": [],
        "policy": {"id": "schema-test", "version": 1, "digest": digest},
        "analyzers": [],
        "reason_codes": ["SCHEMA_TEST"],
    }
    validators["inspect-result-v1.schema.json"].validate(
        {
            "schema": "aragorn/inspect-result/v1",
            "decision_digest": digest,
            "decision": decision,
        }
    )
    print(f"validated {len(schemas)} schemas and checked-in contract examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
