from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn.label_blind_prepare import (
    PrepareError,
    prepare_files,
    validate_private_dispatch,
    validate_worker_worklist,
)
from aragorn.oci_worker_protocol import (
    canonical_json,
    canonical_request_digest,
    validate_subject_manifest,
    validate_worker_request,
    verify_request_subject,
)


ROOT = Path(__file__).parents[1]
BENCHMARK = ROOT / "benchmark"
SUITE = BENCHMARK / "phase0-oci-pilot-v1.json"
LOCK = BENCHMARK / "baselines.lock.json"


def _cas_digests(root: Path) -> set[str]:
    return {
        "sha256:" + path.parent.name + path.name
        for path in (root / "blobs" / "sha256").glob("??/*")
    }


def _worker_identities(root: Path) -> Path:
    suite = json.loads(SUITE.read_text(encoding="utf-8"))
    document = {
        "schema": "aragorn/benchmark-system-identities/v1",
        "systems": sorted(suite["systems"], key=lambda item: item["name"]),
    }
    path = root / "worker-identities.json"
    path.write_bytes(canonical_json(document) + b"\n")
    return path


class LabelBlindPrepareTests(unittest.TestCase):
    def test_prepares_exact_label_free_matrix_and_reachable_input_closure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control = root / "control"
            jobs = root / "jobs"
            identities = _worker_identities(root)

            result = prepare_files(
                SUITE,
                worker_identities=identities,
                control_state=control,
                jobs_root=jobs,
                lock_path=LOCK,
            )

            self.assertEqual(
                result["schema"],
                "aragorn/benchmark-prepare-result/v1",
            )
            self.assertEqual(result["job_count"], 36)
            control_cas = CAS(control, read_only=True)
            self.assertEqual(
                control_cas.read(result["worker_identities_digest"]),
                identities.read_bytes().rstrip(b"\n"),
            )
            dispatch_bytes = control_cas.read(result["dispatch_digest"])
            dispatch = json.loads(dispatch_bytes)
            self.assertEqual(dispatch_bytes, canonical_json(dispatch))
            validate_private_dispatch(dispatch)
            suite = json.loads(SUITE.read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    (
                        entry["system"]["name"],
                        entry["case_id"],
                        entry["run_id"],
                    )
                    for entry in dispatch["jobs"]
                },
                {
                    (system["name"], case["id"], run_id)
                    for system in suite["systems"]
                    for case in suite["cases"]
                    for run_id in range(1, suite["runs_per_case"] + 1)
                },
            )
            self.assertEqual(
                {path.name for path in jobs.iterdir()},
                {
                    "worklist.json",
                    *(entry["job_id"] for entry in dispatch["jobs"]),
                },
            )
            worklist_bytes = (jobs / "worklist.json").read_bytes()
            worklist = json.loads(worklist_bytes)
            self.assertEqual(worklist_bytes, canonical_json(worklist))
            validate_worker_worklist(worklist)
            self.assertEqual(
                control_cas.read(result["worklist_digest"]),
                worklist_bytes,
            )
            self.assertEqual(
                worklist["jobs"],
                [
                    {
                        "job_id": entry["job_id"],
                        "request_digest": entry["request_digest"],
                    }
                    for entry in dispatch["jobs"]
                ],
            )

            forbidden = {
                "suite_digest",
                "case_id",
                "class",
                "family",
                "lineage",
                "split",
                "run_id",
                "purpose",
                "source",
                "expected_verdict",
            }
            for entry in dispatch["jobs"]:
                job = jobs / entry["job_id"]
                self.assertEqual(
                    {path.name for path in job.iterdir()},
                    {"input", "request.json"},
                )
                request_bytes = (job / "request.json").read_bytes()
                request = json.loads(request_bytes)
                self.assertEqual(request_bytes, canonical_json(request))
                self.assertEqual(
                    entry["request_digest"],
                    canonical_request_digest(request),
                )
                validate_worker_request(request)
                self.assertTrue(forbidden.isdisjoint(request))

                input_cas = CAS(job / "input", read_only=True)
                subject = json.loads(
                    input_cas.read(request["subject"]["manifest_digest"])
                )
                validate_subject_manifest(subject)
                verify_request_subject(request, subject)
                self.assertTrue(forbidden.isdisjoint(subject))
                expected_closure = {
                    request["subject"]["manifest_digest"],
                    *(file["digest"] for file in subject["files"]),
                }
                self.assertEqual(
                    _cas_digests(job / "input"),
                    expected_closure,
                )
                for digest in expected_closure:
                    input_cas.verify(digest)

                private_manifest = json.loads(
                    control_cas.read(entry["private_manifest_digest"])
                )
                self.assertEqual(
                    private_manifest["tree_digest"],
                    entry["tree_digest"],
                )

    def test_rejects_baseline_and_config_drift_without_contacting_docker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identities = _worker_identities(root)
            suite_root = root / "suite"
            shutil.copytree(BENCHMARK / "oci-fixtures", suite_root / "oci-fixtures")
            for field in ("implementation_digest", "config_digest"):
                suite = json.loads(SUITE.read_text(encoding="utf-8"))
                suite["systems"][0][field] = "sha256:" + "0" * 64
                suite_path = suite_root / f"{field}.json"
                suite_path.write_text(json.dumps(suite), encoding="utf-8")

                with (
                    self.subTest(field=field),
                    patch("aragorn.oci_runtime.resolve_docker") as docker,
                    self.assertRaisesRegex(PrepareError, "identity|baseline lock"),
                ):
                    prepare_files(
                        suite_path,
                        worker_identities=identities,
                        control_state=root / f"control-{field}",
                        jobs_root=root / f"jobs-{field}",
                        lock_path=LOCK,
                    )
                docker.assert_not_called()
                self.assertFalse((root / f"jobs-{field}").exists())

    def test_rejects_overlaps_symlinks_and_existing_jobs_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identities = _worker_identities(root)
            existing = root / "existing"
            existing.mkdir()
            cases = (
                {
                    "control_state": root / "control-a",
                    "jobs_root": existing,
                    "message": "already exists",
                },
                {
                    "control_state": BENCHMARK / "nested-control",
                    "jobs_root": root / "jobs-b",
                    "message": "overlap",
                },
                {
                    "control_state": root / "control-c",
                    "jobs_root": root / "control-c" / "jobs",
                    "message": "overlap",
                },
            )
            for case in cases:
                with self.subTest(case=case["message"]):
                    with self.assertRaisesRegex(PrepareError, case["message"]):
                        prepare_files(
                            SUITE,
                            worker_identities=identities,
                            control_state=case["control_state"],
                            jobs_root=case["jobs_root"],
                            lock_path=LOCK,
                        )

            linked_jobs = root / "linked-jobs"
            linked_jobs.symlink_to(root / "missing", target_is_directory=True)
            with self.assertRaisesRegex(PrepareError, "symlink"):
                prepare_files(
                    SUITE,
                    worker_identities=identities,
                    control_state=root / "control-d",
                    jobs_root=linked_jobs,
                    lock_path=LOCK,
                )

            real_parent = root / "real-parent"
            real_parent.mkdir()
            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(PrepareError, "symlink"):
                prepare_files(
                    SUITE,
                    worker_identities=identities,
                    control_state=root / "control-e",
                    jobs_root=linked_parent / "jobs",
                    lock_path=LOCK,
                )

    def test_duplicate_randomness_fails_without_a_partial_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identities = _worker_identities(root)
            nonces = iter(("1" * 64, "2" * 64, "3" * 64, "4" * 64))

            def repeated_job_id(size: int) -> str:
                if size == 16:
                    return "a" * 32
                return next(nonces)

            with (
                patch(
                    "aragorn.label_blind_prepare._token_hex",
                    side_effect=repeated_job_id,
                ),
                self.assertRaisesRegex(PrepareError, "duplicate cryptographic"),
            ):
                prepare_files(
                    SUITE,
                    worker_identities=identities,
                    control_state=root / "control",
                    jobs_root=root / "jobs",
                    lock_path=LOCK,
                )
            self.assertFalse((root / "jobs").exists())

    def test_requires_canonical_exact_worker_identities(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = json.loads(_worker_identities(root).read_text(encoding="ascii"))
            cases = {
                "noncanonical": json.dumps(valid).encode("ascii"),
                "unknown-field": canonical_json({**valid, "labels": []}),
                "config-drift": canonical_json(
                    {
                        **valid,
                        "systems": [
                            {
                                **valid["systems"][0],
                                "config_digest": "sha256:" + "0" * 64,
                            },
                            *valid["systems"][1:],
                        ],
                    }
                ),
            }
            for name, content in cases.items():
                identity_path = root / f"{name}.json"
                identity_path.write_bytes(content)
                with self.subTest(name=name), self.assertRaises(PrepareError):
                    prepare_files(
                        SUITE,
                        worker_identities=identity_path,
                        control_state=root / f"control-{name}",
                        jobs_root=root / f"jobs-{name}",
                        lock_path=LOCK,
                    )

    def test_private_dispatch_rejects_label_fields(self) -> None:
        digest = "sha256:" + "0" * 64
        dispatch = {
            "schema": "aragorn/benchmark-private-dispatch/v1",
            "jobs": [
                {
                    "job_id": "1" * 32,
                    "request_digest": digest,
                    "suite_digest": digest,
                    "case_id": "case",
                    "run_id": 1,
                    "system": {
                        "name": "system",
                        "version": "1",
                        "implementation_digest": digest,
                        "config_digest": digest,
                    },
                    "tree_digest": digest,
                    "private_manifest_digest": digest,
                }
            ],
        }
        validate_private_dispatch(dispatch)
        labeled = deepcopy(dispatch)
        labeled["jobs"][0]["class"] = "adversarial"
        with self.assertRaisesRegex(PrepareError, "unknown fields"):
            validate_private_dispatch(labeled)


if __name__ == "__main__":
    unittest.main()
