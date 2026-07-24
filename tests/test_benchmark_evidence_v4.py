from __future__ import annotations

import copy
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn.benchmark import BenchmarkError, _verify_evidence
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import (
    build_worker_request,
    canonical_digest,
    canonical_json,
    validate_worker_result,
)
from aragorn import oci_worker_protocol as protocol
from tests import test_benchmark_oci_evidence as evidence_support


def _put(cas: CAS, content: bytes) -> str:
    return cas.put(BytesIO(content), max_bytes=len(content))


def _v4_fixture(cas: CAS) -> tuple[dict, dict, dict]:
    content = b"# inert worker subject\n"
    content_digest = _put(cas, content)
    files = [
        {
            "path": "SKILL.md",
            "size": len(content),
            "digest": content_digest,
            "executable": False,
        }
    ]
    tree_digest = canonical_digest(files)
    with patch.object(evidence_support, "SUBJECT", tree_digest):
        outcome, private_manifest = evidence_support.OciEvidenceTests._evidence(
            cas,
            evidence_support.cisco_report(),
            evidence_version=3,
        )
    nested_digest = outcome["evidence_digest"]
    nested = json.loads(cas.read(nested_digest))

    subject = {
        "schema": "aragorn/benchmark-subject-manifest/v1",
        "tree_digest": tree_digest,
        "files": files,
    }
    subject_digest = _put(cas, canonical_json(subject))
    tokens = iter(("a" * 32, "b" * 64))
    request = build_worker_request(
        subject,
        outcome["system"],
        baseline_lock_digest=nested["baseline_lock_digest"],
        baseline_entry_digest=nested["baseline_entry_digest"],
        timeout_seconds=120.0,
        output_limit_bytes=8 * 1024 * 1024,
        token_hex=lambda _size: next(tokens),
    )
    request_digest = _put(cas, canonical_json(request))
    result = {
        "schema": "aragorn/benchmark-worker-result/v1",
        "job_id": request["job_id"],
        "nonce": request["nonce"],
        "request_digest": request_digest,
        "subject_manifest_digest": subject_digest,
        "tree_digest": tree_digest,
        "verified_subject_digest": nested["verified_subject_digest"],
        "system": copy.deepcopy(outcome["system"]),
        "baseline_lock_digest": nested["baseline_lock_digest"],
        "baseline_entry_digest": nested["baseline_entry_digest"],
        "effective_config_digest": nested["effective_config_digest"],
        "oci_index_digest": nested["oci_index_digest"],
        "oci_platform_manifest_digest": nested["oci_platform_manifest_digest"],
        "build_provenance_manifest_digest": nested[
            "build_provenance_manifest_digest"
        ],
        "index_inspect_digest": nested["index_inspect_digest"],
        "platform_inspect_digest": nested["platform_inspect_digest"],
        "image_config_digest": nested["image_config_digest"],
        "runner_receipts": copy.deepcopy(nested["runner_receipts"]),
        "prestart_container_inspect_digest": nested[
            "prestart_container_inspect_digest"
        ],
        "postrun_container_inspect_digest": nested[
            "postrun_container_inspect_digest"
        ],
        "stdout_digest": nested["stdout_digest"],
        "stderr_digest": nested["stderr_digest"],
        "observation_digests": list(nested["observation_digests"]),
        "execution": copy.deepcopy(nested["execution"]),
        "normalization": nested["normalization"],
        "verdict": nested["verdict"],
        "reason_codes": list(nested["reason_codes"]),
    }
    validate_worker_result(result)
    result_digest = _put(cas, canonical_json(result))

    effective = json.loads(cas.read(result["effective_config_digest"]))
    expected_blobs = {
        request_digest,
        result_digest,
        subject_digest,
        content_digest,
        effective["docker_executable_digest"],
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
        expected_blobs.update(receipt.values())
    blobs = [
        {"digest": digest, "size": len(cas.read(digest))}
        for digest in sorted(expected_blobs)
    ]
    closure = {
        "schema": "aragorn/benchmark-worker-output-closure/v1",
        "job_id": request["job_id"],
        "request_digest": request_digest,
        "result_digest": result_digest,
        "blobs": blobs,
        "total_bytes": sum(item["size"] for item in blobs),
    }
    closure_digest = _put(cas, canonical_json(closure))

    dispatch = {
        "schema": "aragorn/benchmark-private-dispatch/v1",
        "jobs": [
            {
                "job_id": request["job_id"],
                "request_digest": request_digest,
                "suite_digest": outcome["suite_digest"],
                "case_id": outcome["case_id"],
                "run_id": outcome["run_id"],
                "system": copy.deepcopy(outcome["system"]),
                "tree_digest": outcome["tree_digest"],
                "private_manifest_digest": canonical_digest(private_manifest),
            }
        ],
    }
    dispatch_digest = _put(cas, canonical_json(dispatch))
    ledger_id = canonical_digest(
        {
            "schema": "aragorn/benchmark-worker-nonce-ledger-id/v1",
            "suite_digest": outcome["suite_digest"],
            "dispatch_digest": dispatch_digest,
            "jobs": [
                {
                    "job_id": request["job_id"],
                    "nonce": request["nonce"],
                    "request_digest": request_digest,
                    "result_digest": result_digest,
                }
            ],
        }
    )
    nonce_receipt = {
        "schema": "aragorn/benchmark-worker-nonce-consumption/v1",
        "ledger_id": ledger_id,
        "dispatch_digest": dispatch_digest,
        "job_id": request["job_id"],
        "nonce": request["nonce"],
        "request_digest": request_digest,
        "result_digest": result_digest,
    }
    nonce_receipt_digest = _put(cas, canonical_json(nonce_receipt))
    v4 = {
        "schema": "aragorn/benchmark-evidence/v4",
        "suite_digest": outcome["suite_digest"],
        "case_id": outcome["case_id"],
        "tree_digest": outcome["tree_digest"],
        "run_id": outcome["run_id"],
        "system": copy.deepcopy(outcome["system"]),
        "verdict": outcome["verdict"],
        "reason_codes": list(outcome["reason_codes"]),
        "nested_evidence_digest": nested_digest,
        "worker": {
            "assurance": "unsigned_label_free_protocol_not_isolated_or_attested",
            "ledger_id": ledger_id,
            "dispatch_digest": dispatch_digest,
            "job_id": request["job_id"],
            "nonce": request["nonce"],
            "request_digest": request_digest,
            "result_digest": result_digest,
            "subject_manifest_digest": subject_digest,
            "output_closure_digest": closure_digest,
            "nonce_receipt_digest": nonce_receipt_digest,
        },
    }
    outcome["evidence_digest"] = _put(cas, canonical_json(v4))
    return outcome, private_manifest, v4


class BenchmarkEvidenceV4Tests(unittest.TestCase):
    def test_v4_reverifies_worker_binding_exact_closure_and_nested_v3(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
            try:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                    "implementation_digest"
                ] = _synthetic_implementation_digest()
                outcome, manifest, _v4 = _v4_fixture(cas)
                _verify_evidence(
                    cas,
                    outcome,
                    expected_manifest=manifest,
                    label="outcomes[0]",
                )
            finally:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original

    def test_v4_rejects_worker_closure_or_dispatch_drift(self) -> None:
        for mutation in ("closure", "dispatch"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                cas = CAS(Path(temporary) / "state")
                original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
                try:
                    protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                        "implementation_digest"
                    ] = _synthetic_implementation_digest()
                    outcome, manifest, v4 = _v4_fixture(cas)
                    if mutation == "closure":
                        closure = json.loads(
                            cas.read(v4["worker"]["output_closure_digest"])
                        )
                        closure["blobs"].pop()
                        closure["total_bytes"] = sum(
                            item["size"] for item in closure["blobs"]
                        )
                        v4["worker"]["output_closure_digest"] = _put(
                            cas, canonical_json(closure)
                        )
                    else:
                        dispatch = json.loads(
                            cas.read(v4["worker"]["dispatch_digest"])
                        )
                        dispatch["jobs"][0]["case_id"] = "different-case"
                        changed = _put(cas, canonical_json(dispatch))
                        v4["worker"]["dispatch_digest"] = changed
                        receipt = json.loads(
                            cas.read(v4["worker"]["nonce_receipt_digest"])
                        )
                        receipt["dispatch_digest"] = changed
                        v4["worker"]["nonce_receipt_digest"] = _put(
                            cas, canonical_json(receipt)
                        )
                    outcome["evidence_digest"] = _put(cas, canonical_json(v4))
                    with self.assertRaises(BenchmarkError):
                        _verify_evidence(
                            cas,
                            outcome,
                            expected_manifest=manifest,
                            label="outcomes[0]",
                        )
                finally:
                    protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original

    def test_v4_rejects_an_unrelated_second_suite_dispatch_entry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "state")
            original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
            try:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                    "implementation_digest"
                ] = _synthetic_implementation_digest()
                outcome, manifest, v4 = _v4_fixture(cas)
                dispatch = json.loads(cas.read(v4["worker"]["dispatch_digest"]))
                foreign = copy.deepcopy(dispatch["jobs"][0])
                foreign.update(
                    {
                        "job_id": "f" * 32,
                        "request_digest": "sha256:" + "f" * 64,
                        "suite_digest": "sha256:" + "e" * 64,
                        "case_id": "foreign-case",
                    }
                )
                dispatch["jobs"].append(foreign)
                changed = _put(cas, canonical_json(dispatch))
                v4["worker"]["dispatch_digest"] = changed
                receipt = json.loads(
                    cas.read(v4["worker"]["nonce_receipt_digest"])
                )
                receipt["dispatch_digest"] = changed
                v4["worker"]["nonce_receipt_digest"] = _put(
                    cas, canonical_json(receipt)
                )
                outcome["evidence_digest"] = _put(cas, canonical_json(v4))
                with self.assertRaisesRegex(BenchmarkError, "batch-wide"):
                    _verify_evidence(
                        cas,
                        outcome,
                        expected_manifest=manifest,
                        label="outcomes[0]",
                    )
            finally:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original


def _synthetic_implementation_digest() -> str:
    # Derive the helper's synthetic platform digest without retaining a worker job.
    with tempfile.TemporaryDirectory() as temporary:
        scratch = CAS(Path(temporary) / "state")
        _outcome, _manifest = evidence_support.OciEvidenceTests._evidence(
            scratch,
            evidence_support.cisco_report(),
            evidence_version=3,
        )
        nested = json.loads(scratch.read(_outcome["evidence_digest"]))
        return nested["oci_platform_manifest_digest"]


if __name__ == "__main__":
    unittest.main()
