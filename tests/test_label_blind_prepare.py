from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from aragorn import label_blind_prepare as prepare_module
from aragorn.benchmark_handoff_v2 import import_handoff
from aragorn.benchmark_protocol_v2 import (
    canonical_request_digest_v2,
    portable_policy_digest,
    validate_worker_request_v2,
)
from aragorn.benchmark_semantic_closure_v2 import (
    derive_worker_input_cas_closure,
)
from aragorn.cas import CAS
from aragorn.label_blind_prepare import (
    PrepareError,
    prepare_files,
    prepare_files_v2,
    validate_private_dispatch,
    validate_worker_worklist,
)
from aragorn.oci_runtime import load_baseline_lock
from aragorn.oci_worker_protocol import (
    canonical_digest,
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


def _portable_policies() -> list[dict]:
    raw_lock, baselines = load_baseline_lock(LOCK)
    lock_digest = "sha256:" + hashlib.sha256(raw_lock).hexdigest()
    entrypoints = {
        "cisco-skill-scanner": ["/opt/venv/bin/skill-scanner"],
        "skillspector": [
            "/opt/venv/bin/python",
            "-P",
            "-m",
            "skillspector.cli",
        ],
    }
    normalizations = {
        "cisco-skill-scanner": "cisco-ai-skill-scanner-2.0.12/v1",
        "skillspector": "nvidia-skillspector-2.4.3/v1",
    }
    return [
        {
            "schema": "aragorn/benchmark-portable-policy/v1",
            "system": {
                "name": baseline["name"],
                "version": baseline["version"],
                "implementation_digest": baseline["image"][
                    "platform_manifest_digest"
                ],
            },
            "baseline": {
                "lock_digest": lock_digest,
                "entry_digest": canonical_digest(baseline),
            },
            "image": {
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
            },
            "entrypoint": entrypoints[baseline["name"]],
            "arguments": [
                "/workspace" if value == "{workspace}" else value
                for value in baseline["profile"]["arguments"]
            ],
            "environment": baseline["profile"]["environment"],
            "runtime_profile": baseline["runtime_profile"],
            "limits": {
                "timeout_seconds": 120.0,
                "output_bytes": 1024 * 1024,
            },
            "normalization": normalizations[baseline["name"]],
        }
        for baseline in baselines
    ]


def _v2_suite(root: Path, policies: list[dict]) -> Path:
    root.mkdir(mode=0o700)
    shutil.copytree(BENCHMARK / "oci-fixtures", root / "oci-fixtures")
    suite = json.loads((BENCHMARK / "oci-suite.json").read_text(encoding="utf-8"))
    policy_by_name = {policy["system"]["name"]: policy for policy in policies}
    for system in suite["systems"]:
        system["config_digest"] = portable_policy_digest(
            policy_by_name[system["name"]]
        )
    path = root / "v2-suite.json"
    path.write_bytes(canonical_json(suite))
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


class LabelBlindPrepareV2Tests(unittest.TestCase):
    def test_prepares_challenge_bound_cross_owner_input_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            control = root / "control"
            jobs = root / "jobs"
            ledger = root / "ledger"
            policies = _portable_policies()
            suite = _v2_suite(root / "suite-input", policies)

            result = prepare_files_v2(
                suite,
                portable_policies=policies,
                trust_domain="phase0.example",
                worker_id="isolated-worker-01",
                challenge_ledger=ledger,
                control_state=control,
                jobs_root=jobs,
                lock_path=LOCK,
            )

            self.assertEqual(result["schema"], "aragorn/benchmark-prepare-result/v1")
            self.assertEqual(result["job_count"], 4)
            control_cas = CAS(control, read_only=True)
            identities = json.loads(
                control_cas.read(result["worker_identities_digest"])
            )
            self.assertEqual(
                {
                    system["name"]: system["config_digest"]
                    for system in identities["systems"]
                },
                {
                    policy["system"]["name"]: portable_policy_digest(policy)
                    for policy in policies
                },
            )
            dispatch = json.loads(
                control_cas.read(result["dispatch_digest"])
            )
            validate_private_dispatch(dispatch)
            worklist = json.loads((jobs / "worklist.json").read_bytes())
            validate_worker_worklist(worklist)
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
                    {
                        "input-bundle",
                        "input-manifest-digest.txt",
                        "request.json",
                    },
                )
                request_bytes = (job / "request.json").read_bytes()
                request = json.loads(request_bytes)
                validate_worker_request_v2(request)
                self.assertEqual(
                    entry["request_digest"],
                    canonical_request_digest_v2(request),
                )
                self.assertTrue(forbidden.isdisjoint(request))

                challenge = request["verifier_challenge"]
                issuance = json.loads(
                    (
                        ledger
                        / "issuances"
                        / f"{challenge}.json"
                    ).read_bytes()
                )
                self.assertEqual(issuance["job_id"], entry["job_id"])
                self.assertEqual(
                    issuance["request_digest"],
                    entry["request_digest"],
                )

                manifest_digest = (
                    job / "input-manifest-digest.txt"
                ).read_text(encoding="ascii").strip()
                received = CAS(root / "received" / entry["job_id"])
                imported = import_handoff(
                    job / "input-bundle",
                    received,
                    expected_manifest_digest=manifest_digest,
                    expected_kind="worker_input",
                    expected_root_digest=entry["request_digest"],
                    expected_verifier_challenge=challenge,
                )
                expected = derive_worker_input_cas_closure(
                    received,
                    entry["request_digest"],
                    expected_challenge=challenge,
                )
                self.assertEqual(
                    {
                        item["digest"]: item["size"]
                        for item in imported["blobs"]
                    },
                    expected,
                )
                subject = json.loads(
                    received.read(request["subject"]["manifest_digest"])
                )
                validate_subject_manifest(subject)
                self.assertTrue(forbidden.isdisjoint(subject))

    def test_rejects_policy_lock_drift_without_jobs_or_challenges(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            policies = _portable_policies()
            policies[0]["baseline"]["entry_digest"] = "sha256:" + "0" * 64
            suite = _v2_suite(root / "suite-input", policies)
            with self.assertRaisesRegex(PrepareError, "baseline binding"):
                prepare_files_v2(
                    suite,
                    portable_policies=policies,
                    trust_domain="phase0.example",
                    worker_id="isolated-worker-01",
                    challenge_ledger=root / "ledger",
                    control_state=root / "control",
                    jobs_root=root / "jobs",
                    lock_path=LOCK,
                )
            self.assertFalse((root / "jobs").exists())
            self.assertFalse((root / "ledger").exists())

    def test_rejects_legacy_host_bound_suite_config_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            policies = _portable_policies()
            suite_root = root / "suite-input"
            suite_root.mkdir(mode=0o700)
            shutil.copytree(
                BENCHMARK / "oci-fixtures",
                suite_root / "oci-fixtures",
            )
            suite = suite_root / "legacy-suite.json"
            suite.write_bytes((BENCHMARK / "oci-suite.json").read_bytes())
            with self.assertRaisesRegex(PrepareError, "portable policy"):
                prepare_files_v2(
                    suite,
                    portable_policies=policies,
                    trust_domain="phase0.example",
                    worker_id="isolated-worker-01",
                    challenge_ledger=root / "ledger",
                    control_state=root / "control",
                    jobs_root=root / "jobs",
                    lock_path=LOCK,
                )
            self.assertFalse((root / "jobs").exists())
            self.assertFalse((root / "ledger").exists())

    def test_competing_ledger_creation_is_not_deleted_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            policies = _portable_policies()
            suite = _v2_suite(root / "suite-input", policies)
            ledger = root / "ledger"
            original = prepare_module._create_private_directory

            def create_competing_ledger(path: Path, label: str) -> None:
                if label == "challenge ledger":
                    path.mkdir(mode=0o700)
                original(path, label)

            with (
                patch(
                    "aragorn.label_blind_prepare._create_private_directory",
                    side_effect=create_competing_ledger,
                ),
                self.assertRaisesRegex(PrepareError, "already exists"),
            ):
                prepare_files_v2(
                    suite,
                    portable_policies=policies,
                    trust_domain="phase0.example",
                    worker_id="isolated-worker-01",
                    challenge_ledger=ledger,
                    control_state=root / "control",
                    jobs_root=root / "jobs",
                    lock_path=LOCK,
                )
            self.assertTrue(ledger.is_dir())
            self.assertEqual(list(ledger.iterdir()), [])
            self.assertFalse((root / "jobs").exists())


if __name__ == "__main__":
    unittest.main()
