from __future__ import annotations

from io import BytesIO
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn.acquire import inventory_local
from aragorn.benchmark import BenchmarkError, load_suite_for_run
from aragorn.cas import CAS
from aragorn.label_blind_collect import CollectError, collect_files
from aragorn.oci_worker_protocol import (
    build_worker_request,
    canonical_digest,
    canonical_json,
    sanitize_subject_manifest,
    validate_worker_result,
)
from aragorn import oci_worker_protocol as protocol


def _put(cas: CAS, content: bytes) -> str:
    return cas.put(BytesIO(content), max_bytes=len(content))


def _digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _build_batch(root: Path) -> dict:
    suite_root = root / "suite"
    benign = suite_root / "fixtures" / "benign"
    adversarial = suite_root / "fixtures" / "adversarial"
    benign.mkdir(parents=True)
    adversarial.mkdir(parents=True)
    (benign / "SKILL.md").write_text("# Safe formatting helper\n", encoding="utf-8")
    (adversarial / "SKILL.md").write_text(
        "# Inert simulated policy override\n", encoding="utf-8"
    )

    platform_blob = b"synthetic-platform-manifest"
    platform_digest = _digest(platform_blob)
    docker_blob = b"synthetic-docker"
    docker_digest = _digest(docker_blob)
    effective = {"docker_executable_digest": docker_digest}
    config_digest = canonical_digest(effective)
    system = {
        "name": "cisco-skill-scanner",
        "version": "2.0.12",
        "implementation_digest": platform_digest,
        "config_digest": config_digest,
    }
    cases = []
    for case_id, case_class, family, fixture in (
        ("benign-case", "benign", "benign", benign),
        ("adversarial-case", "adversarial", "prompt-injection", adversarial),
    ):
        cases.append(
            {
                "schema": "aragorn/benchmark-case/v1",
                "id": case_id,
                "class": case_class,
                "family": family,
                "lineage": f"lineage-{case_id}",
                "split": "development",
                "path": fixture.relative_to(suite_root).as_posix(),
                "tree_digest": inventory_local(fixture)["tree_digest"],
                "inert": True,
                "source": {
                    "kind": "synthetic",
                    "reference": f"collector-test/{case_id}",
                    "license": "CC0-1.0",
                },
            }
        )
    suite = {
        "schema": "aragorn/benchmark-suite/v1",
        "id": "collector-test",
        "purpose": "evidence_smoke",
        "runs_per_case": 1,
        "systems": [system],
        "cases": cases,
    }
    suite_path = suite_root / "suite.json"
    suite_path.write_text(json.dumps(suite), encoding="utf-8")

    control_path = root / "control"
    control_cas = CAS(control_path)
    loaded = load_suite_for_run(
        suite_path,
        control_cas,
        required_purpose="evidence_smoke",
    )
    jobs_root = root / "jobs"
    jobs_root.mkdir(mode=0o700)
    dispatch_jobs = []
    outputs = []
    for index, case_id in enumerate(sorted(loaded["cases"]), start=1):
        manifest = loaded["manifests"][case_id]
        private_manifest_digest = _put(control_cas, canonical_json(manifest))
        subject = sanitize_subject_manifest(manifest)
        job_id = f"{index:032x}"
        nonce = f"{index:064x}"
        tokens = iter((job_id, nonce))

        lock_blob = f"lock-{index}".encode("ascii")
        entry_blob = f"entry-{index}".encode("ascii")
        lock_digest = _digest(lock_blob)
        entry_digest = _digest(entry_blob)
        request = build_worker_request(
            subject,
            system,
            baseline_lock_digest=lock_digest,
            baseline_entry_digest=entry_digest,
            timeout_seconds=120.0,
            output_limit_bytes=1024 * 1024,
            token_hex=lambda _size: next(tokens),
        )
        request_raw = canonical_json(request)
        request_digest = canonical_digest(request)

        job = jobs_root / job_id
        job.mkdir(mode=0o700)
        request_path = job / "request.json"
        request_path.write_bytes(request_raw)
        request_path.chmod(0o400)
        input_cas = CAS(job / "input")
        subject_digest = _put(input_cas, canonical_json(subject))
        for file in subject["files"]:
            content = control_cas.read(file["digest"], max_bytes=file["size"])
            _put(input_cas, content)

        output_cas = CAS(job / "output")
        for content in (
            request_raw,
            canonical_json(subject),
            lock_blob,
            entry_blob,
            canonical_json(effective),
            platform_blob,
            docker_blob,
        ):
            _put(output_cas, content)
        for file in subject["files"]:
            _put(
                output_cas,
                control_cas.read(file["digest"], max_bytes=file["size"]),
            )
        evidence_blob = f"evidence-{index}".encode("ascii")
        evidence_digest = _put(output_cas, evidence_blob)
        receipt = {
            "context_inspect_digest": evidence_digest,
            "daemon_version_digest": evidence_digest,
            "daemon_info_digest": evidence_digest,
        }
        result = {
            "schema": "aragorn/benchmark-worker-result/v1",
            "job_id": job_id,
            "nonce": nonce,
            "request_digest": request_digest,
            "subject_manifest_digest": subject_digest,
            "tree_digest": subject["tree_digest"],
            "verified_subject_digest": subject["tree_digest"],
            "system": dict(system),
            "baseline_lock_digest": lock_digest,
            "baseline_entry_digest": entry_digest,
            "effective_config_digest": config_digest,
            "oci_index_digest": evidence_digest,
            "oci_platform_manifest_digest": platform_digest,
            "build_provenance_manifest_digest": evidence_digest,
            "index_inspect_digest": evidence_digest,
            "platform_inspect_digest": evidence_digest,
            "image_config_digest": evidence_digest,
            "runner_receipts": {"pre": dict(receipt), "post": dict(receipt)},
            "prestart_container_inspect_digest": evidence_digest,
            "postrun_container_inspect_digest": evidence_digest,
            "stdout_digest": evidence_digest,
            "stderr_digest": evidence_digest,
            "observation_digests": [],
            "execution": {
                "status": "ok",
                "error_code": None,
                "returncode": 0,
                "container_id": f"{index + 10:064x}",
            },
            "normalization": "cisco-ai-skill-scanner-2.0.12/v1",
            "verdict": "ALLOW",
            "reason_codes": [],
        }
        validate_worker_result(result)
        _put(output_cas, canonical_json(result))
        outputs.append(job / "output")
        dispatch_jobs.append(
            {
                "job_id": job_id,
                "request_digest": request_digest,
                "suite_digest": loaded["digest"],
                "case_id": case_id,
                "run_id": 1,
                "system": dict(system),
                "tree_digest": manifest["tree_digest"],
                "private_manifest_digest": private_manifest_digest,
            }
        )
    dispatch = {
        "schema": "aragorn/benchmark-private-dispatch/v1",
        "jobs": sorted(dispatch_jobs, key=lambda item: item["job_id"]),
    }
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
    worklist_path = jobs_root / "worklist.json"
    worklist_path.write_bytes(canonical_json(worklist))
    worklist_path.chmod(0o400)
    dispatch_digest = _put(control_cas, canonical_json(dispatch))
    return {
        "suite": suite_path,
        "control": control_path,
        "jobs": jobs_root,
        "ledger": control_path / "nonce-ledger",
        "dispatch_digest": dispatch_digest,
        "outputs": outputs,
        "implementation_digest": platform_digest,
    }


class LabelBlindCollectTests(unittest.TestCase):
    def test_complete_batch_is_collected_once_without_partial_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
            try:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                    "implementation_digest"
                ] = _digest(b"synthetic-platform-manifest")
                batch = _build_batch(root)
                self.assertEqual(
                    batch["implementation_digest"],
                    protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                        "implementation_digest"
                    ],
                )
                with patch(
                    "aragorn.label_blind_collect.evaluate",
                    side_effect=(
                        {"schema": "aragorn/benchmark-report/v1", "pass": 1},
                        {"schema": "aragorn/benchmark-report/v1", "pass": 2},
                    ),
                ) as evaluator:
                    result = collect_files(
                        batch["suite"],
                        dispatch_digest=batch["dispatch_digest"],
                        control_state=batch["control"],
                        jobs_root=batch["jobs"],
                    )
                self.assertEqual(evaluator.call_count, 2)
                self.assertEqual(result["job_count"], 2)
                self.assertEqual(
                    result["assurance"],
                    "unsigned_label_free_protocol_not_isolated_or_attested",
                )
                committed = list((batch["ledger"] / "batches").glob("*.json"))
                self.assertEqual(len(committed), 1)
                nonce_batch = json.loads(committed[0].read_bytes())
                self.assertEqual(len(nonce_batch["receipts"]), 2)
                self.assertEqual(nonce_batch["ledger_id"], result["ledger_id"])
                retained = CAS(batch["control"])
                collection = json.loads(
                    retained.read(result["collection_digest"])
                )
                self.assertEqual(collection["ledger_id"], result["ledger_id"])
                for job in collection["jobs"]:
                    evidence = json.loads(
                        retained.read(job["evidence_digest"])
                    )
                    self.assertEqual(
                        evidence["worker"]["ledger_id"],
                        result["ledger_id"],
                    )
                self.assertEqual(
                    result["schema"],
                    "aragorn/benchmark-collection-result/v1",
                )

                with patch(
                    "aragorn.label_blind_collect.evaluate",
                    return_value={
                        "schema": "aragorn/benchmark-report/v1",
                        "pass": 2,
                    },
                ):
                    repeated = collect_files(
                        batch["suite"],
                        dispatch_digest=batch["dispatch_digest"],
                        control_state=batch["control"],
                        jobs_root=batch["jobs"],
                    )
                self.assertEqual(
                    repeated["collection_digest"],
                    result["collection_digest"],
                )
                self.assertEqual(
                    len(list((batch["ledger"] / "batches").glob("*.json"))),
                    1,
                )
                with patch(
                    "aragorn.label_blind_collect.evaluate",
                    return_value={
                        "schema": "aragorn/benchmark-report/v1",
                        "pass": 3,
                    },
                ), self.assertRaisesRegex(CollectError, "another batch"):
                    collect_files(
                        batch["suite"],
                        dispatch_digest=batch["dispatch_digest"],
                        control_state=batch["control"],
                        jobs_root=batch["jobs"],
                    )
            finally:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original

    def test_extra_worker_blob_fails_before_evaluation_or_nonce_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
            try:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                    "implementation_digest"
                ] = _digest(b"synthetic-platform-manifest")
                batch = _build_batch(root)
                output = CAS(batch["outputs"][0])
                _put(output, b"unreferenced-extra")
                with patch("aragorn.label_blind_collect.evaluate") as evaluator:
                    with self.assertRaisesRegex(CollectError, "exact result closure"):
                        collect_files(
                            batch["suite"],
                            dispatch_digest=batch["dispatch_digest"],
                            control_state=batch["control"],
                            jobs_root=batch["jobs"],
                        )
                evaluator.assert_not_called()
                self.assertFalse(batch["ledger"].exists())
            finally:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original

    def test_final_evaluation_failure_consumes_no_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
            try:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                    "implementation_digest"
                ] = _digest(b"synthetic-platform-manifest")
                batch = _build_batch(root)
                with patch(
                    "aragorn.label_blind_collect.evaluate",
                    side_effect=(
                        {"schema": "aragorn/benchmark-report/v1", "pass": 1},
                        BenchmarkError("final evaluation failed"),
                    ),
                ), self.assertRaisesRegex(BenchmarkError, "final evaluation failed"):
                    collect_files(
                        batch["suite"],
                        dispatch_digest=batch["dispatch_digest"],
                        control_state=batch["control"],
                        jobs_root=batch["jobs"],
                    )
                self.assertFalse(batch["ledger"].exists())
            finally:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original

    def test_batch_publish_failure_consumes_no_nonce(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = protocol._SYSTEM_IDENTITY["cisco-skill-scanner"].copy()
            try:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"][
                    "implementation_digest"
                ] = _digest(b"synthetic-platform-manifest")
                batch = _build_batch(root)
                with (
                    patch(
                        "aragorn.label_blind_collect.evaluate",
                        side_effect=(
                            {"schema": "aragorn/benchmark-report/v1", "pass": 1},
                            {"schema": "aragorn/benchmark-report/v1", "pass": 2},
                        ),
                    ),
                    patch(
                        "aragorn.label_blind_collect._publish_nonce_batch",
                        side_effect=CollectError("simulated publish failure"),
                    ),
                    self.assertRaisesRegex(CollectError, "simulated publish failure"),
                ):
                    collect_files(
                        batch["suite"],
                        dispatch_digest=batch["dispatch_digest"],
                        control_state=batch["control"],
                        jobs_root=batch["jobs"],
                    )
                self.assertEqual(
                    list((batch["ledger"] / "batches").glob("*.json")),
                    [],
                )
                self.assertEqual(
                    list((batch["ledger"] / ".staging").glob("*.tmp")),
                    [],
                )
            finally:
                protocol._SYSTEM_IDENTITY["cisco-skill-scanner"] = original


if __name__ == "__main__":
    unittest.main()
