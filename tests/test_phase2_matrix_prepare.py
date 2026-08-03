from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn.acquire import ingest_local
from aragorn.artifact_closure import canonical_json
from aragorn.benchmark import load_suite_for_run
from aragorn.cas import CAS
from aragorn.github_gateway import GatewayQuarantineReceipt
from aragorn.phase0_candidate import candidate_implementation_digest
from aragorn.phase2_matrix_prepare import (
    OPERATOR_INDEX_AUTHORITY,
    OPERATOR_INDEX_SCHEMA,
    Phase2MatrixPrepareError,
    prepare_phase2_matrix,
)

ROOT = Path(__file__).parents[1]
CATALOG = ROOT / "benchmark" / "phase2-matrix-catalog-v1.json"


class Phase2MatrixPrepareTests(unittest.TestCase):
    def test_prepare_object_builds_exact_suite_lock_and_relative_index(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            catalog = self._catalog()
            catalog["cases"].reverse()
            gateway = _FakeGateway(base / "fixtures")
            work = base / "work"

            lock_digest = prepare_phase2_matrix(
                catalog,
                work,
                worker_uid=self._worker_uid(),
                worker_gid=self._worker_gid(),
                gateway=gateway,
            )

            expected_ids = sorted(case["case_id"] for case in catalog["cases"])
            self.assertEqual(
                gateway.skill_paths,
                [f"cases/{case_id}" for case_id in expected_ids],
            )
            suite_path = work / "suite" / "phase2-suite.json"
            suite_raw = suite_path.read_bytes()
            suite = json.loads(suite_raw)
            self.assertEqual(suite_raw, canonical_json(suite))
            self.assertEqual(suite["runs_per_case"], 5)
            self.assertEqual(len(suite["systems"]), 1)
            self.assertEqual(suite["systems"][0]["name"], "aragorn")
            self.assertEqual(
                suite["systems"][0]["implementation_digest"],
                candidate_implementation_digest(),
            )
            self.assertEqual([case["id"] for case in suite["cases"]], expected_ids)
            for case_id in expected_ids:
                for path in (work / "suite" / "cases" / case_id).rglob("*"):
                    if path.is_file():
                        self.assertFalse(path.stat().st_mode & 0o111)

            with tempfile.TemporaryDirectory() as state:
                loaded = load_suite_for_run(
                    suite_path,
                    CAS(Path(state) / "cas"),
                    required_purpose="evidence_smoke",
                )
            lock_raw = (work / "coverage-lock.json").read_bytes()
            lock = json.loads(lock_raw)
            self.assertEqual(lock_raw, canonical_json(lock))
            self.assertEqual(lock_digest, self._digest(lock_raw))
            self.assertEqual(lock["suite_digest"], loaded["digest"])
            self.assertEqual(lock["candidate_system"], suite["systems"][0])
            self.assertEqual([case["case_id"] for case in lock["cases"]], expected_ids)
            self.assertTrue(
                all(
                    case["source_manifest_digest"] != case["suite_manifest_digest"]
                    for case in lock["cases"]
                )
            )

            index_raw = (work / "operator-index.json").read_bytes()
            index = json.loads(index_raw)
            self.assertEqual(index_raw, canonical_json(index))
            self.assertEqual(
                index,
                {
                    "schema": OPERATOR_INDEX_SCHEMA,
                    "authority": OPERATOR_INDEX_AUTHORITY,
                    "coverage_lock_digest": lock_digest,
                    "suite_path": "suite/phase2-suite.json",
                    "coverage_lock_path": "coverage-lock.json",
                    "evidence_state_path": "evidence",
                    "results_path": "results",
                    "cases": [
                        {
                            "case_id": case_id,
                            "source_state_path": f"sources/{case_id}",
                        }
                        for case_id in expected_ids
                    ],
                },
            )

    def test_prepare_accepts_catalog_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            work = base / "work"
            digest = prepare_phase2_matrix(
                CATALOG,
                work,
                worker_uid=self._worker_uid(),
                worker_gid=self._worker_gid(),
                gateway=_FakeGateway(base / "fixtures"),
            )
            self.assertEqual(
                digest, self._digest((work / "coverage-lock.json").read_bytes())
            )

    def test_catalog_shape_and_capabilities_fail_before_work_creation(self) -> None:
        variants = []
        extra = self._catalog()
        extra["unexpected"] = True
        variants.append(extra)
        duplicate = self._catalog()
        duplicate["cases"][1]["case_id"] = duplicate["cases"][0]["case_id"]
        variants.append(duplicate)
        capability = self._catalog()
        capability["cases"][0]["declared_capabilities"] = [
            "process-exec",
            "file-read",
        ]
        variants.append(capability)

        for index, catalog in enumerate(variants):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(index=index):
                work = Path(temporary) / "work"
                with self.assertRaises(Phase2MatrixPrepareError):
                    prepare_phase2_matrix(
                        catalog,
                        work,
                        worker_uid=self._worker_uid(),
                        worker_gid=self._worker_gid(),
                        gateway=_FakeGateway(Path(temporary) / "fixtures"),
                    )
                self.assertFalse(work.exists())

    def test_executable_source_and_receipt_tree_substitution_fail_closed(self) -> None:
        first_id = self._catalog()["cases"][0]["case_id"]
        variants = (
            {"executable_case": first_id},
            {"substituted_tree_case": first_id},
        )
        for gateway_options in variants:
            with (
                tempfile.TemporaryDirectory() as temporary,
                self.subTest(gateway_options=gateway_options),
            ):
                base = Path(temporary)
                work = base / "work"
                with self.assertRaises(Phase2MatrixPrepareError):
                    prepare_phase2_matrix(
                        self._catalog(),
                        work,
                        worker_uid=self._worker_uid(),
                        worker_gid=self._worker_gid(),
                        gateway=_FakeGateway(base / "fixtures", **gateway_options),
                    )
                self.assertFalse(work.exists())
                self.assertFalse((work / "coverage-lock.json").exists())
                self.assertFalse((work / "operator-index.json").exists())

    def test_mid_acquisition_failure_cleans_staging_and_allows_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            work = base / "work"
            with self.assertRaisesRegex(RuntimeError, "injected acquisition failure"):
                prepare_phase2_matrix(
                    self._catalog(),
                    work,
                    worker_uid=self._worker_uid(),
                    worker_gid=self._worker_gid(),
                    gateway=_FakeGateway(
                        base / "failed-fixtures",
                        fail_on_call=7,
                    ),
                )
            self.assertFalse(work.exists())
            self.assertEqual(list(base.glob(".work.prepare-*")), [])

            lock_digest = prepare_phase2_matrix(
                self._catalog(),
                work,
                worker_uid=self._worker_uid(),
                worker_gid=self._worker_gid(),
                gateway=_FakeGateway(base / "retry-fixtures"),
            )
            self.assertTrue(work.is_dir())
            self.assertEqual(
                lock_digest,
                self._digest((work / "coverage-lock.json").read_bytes()),
            )
            self.assertEqual(list(base.glob(".work.prepare-*")), [])

    @staticmethod
    def _catalog() -> dict:
        return copy.deepcopy(json.loads(CATALOG.read_text(encoding="utf-8")))

    @staticmethod
    def _worker_uid() -> int:
        return os.geteuid() or 65534

    @staticmethod
    def _worker_gid() -> int:
        return os.getegid() or 65534

    @staticmethod
    def _digest(content: bytes) -> str:
        return "sha256:" + hashlib.sha256(content).hexdigest()


class _FakeGateway:
    def __init__(
        self,
        fixture_root: Path,
        *,
        executable_case: str | None = None,
        substituted_tree_case: str | None = None,
        fail_on_call: int | None = None,
    ) -> None:
        self.fixture_root = fixture_root
        self.executable_case = executable_case
        self.substituted_tree_case = substituted_tree_case
        self.fail_on_call = fail_on_call
        self.skill_paths: list[str] = []

    def __call__(
        self,
        request: dict[str, str],
        *,
        gateway_root: Path,
        quarantine_state: Path,
        worker_uid: int,
        worker_gid: int,
    ) -> GatewayQuarantineReceipt:
        del gateway_root, worker_uid, worker_gid
        skill_path = request["skill_path"]
        self.skill_paths.append(skill_path)
        if len(self.skill_paths) == self.fail_on_call:
            raise RuntimeError("injected acquisition failure")
        case_id = skill_path.rsplit("/", 1)[-1]
        fixture = self.fixture_root / case_id
        fixture.mkdir(parents=True)
        (fixture / "SKILL.md").write_text(
            f"# {case_id}\n\nInert Phase 2 fixture.\n", encoding="utf-8"
        )
        entrypoint = fixture / "run.sh"
        entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        if case_id == self.executable_case:
            entrypoint.chmod(0o755)

        cas = CAS(quarantine_state)
        manifest = ingest_local(fixture, cas)
        manifest_raw = canonical_json(manifest)
        manifest_digest = cas.put(BytesIO(manifest_raw), max_bytes=len(manifest_raw))
        tree_digest = manifest["tree_digest"]
        if case_id == self.substituted_tree_case:
            tree_digest = self._digest(f"substituted:{case_id}")
        return GatewayQuarantineReceipt(
            authority="test-only",
            source_assurance="test-only",
            request_digest=self._digest(f"request:{case_id}"),
            manifest_digest=manifest_digest,
            tree_digest=tree_digest,
            file_count=len(manifest["files"]),
            handoff_manifest_digest=self._digest(f"handoff:{case_id}"),
            quarantine_state=quarantine_state,
            source_proof_digest=self._digest(f"proof:{case_id}"),
            quarantine_receipt_digest=self._digest(f"quarantine:{case_id}"),
            gateway_profile_digest=self._digest(f"gateway:{case_id}"),
        )

    @staticmethod
    def _digest(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    unittest.main()
