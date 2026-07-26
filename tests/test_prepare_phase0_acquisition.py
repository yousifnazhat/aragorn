from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.prepare_phase0_acquisition as preparation
from aragorn.benchmark import _canonical_json_bytes, _digest_json, load_suite_for_run
from aragorn.cas import CAS
from aragorn.github_expand import (
    TERMINAL_DEPTH_1_ASSURANCE,
    TERMINAL_DEPTH_1_MODE,
    TERMINAL_DEPTH_1_PROFILE,
)
from aragorn.phase0_candidate import candidate_implementation_digest
from scripts.prepare_phase0_acquisition import (
    AcquisitionPreparationError,
    RESULT_SCHEMA,
    _BUDGETS,
    _OWNER,
    _REPOSITORY,
    _ROOT_COMMIT,
    _TARGET_COMMIT,
    _read_bearer_token,
    _raw_github_url,
    prepare_files,
)

ROOT = Path(__file__).parents[1]
POLICY = ROOT / "benchmark" / "phase0-candidate-policy-v4.json"
CORPUS_LOCK = ROOT / "benchmark" / "phase0-acquisition-corpus.lock.json"


def _blob_sha1(content: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(content)).encode("ascii") + b"\0" + content
    ).hexdigest()


def _put(cas: CAS, value: bytes) -> str:
    return cas.put(io.BytesIO(value), max_bytes=len(value))


def _put_json(cas: CAS, value: object) -> str:
    return _put(cas, _canonical_json_bytes(value))


class Phase0AcquisitionPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="aragorn-acquisition-preparation-test-"
        )
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.catalog_path = self.root / "catalog.json"
        self.corpus_lock_path = self.root / "corpus-lock.json"
        self.policy_path = self.root / "candidate-policy.json"
        self.output = self.root / "prepared"
        self.state = self.root / "state"
        self.catalog = self._catalog()
        lock_digest = self._write_catalog(self.catalog)
        self.lock_path_patch = mock.patch.object(
            preparation,
            "_ACQUISITION_CORPUS_LOCK_PATH",
            self.corpus_lock_path,
        )
        self.lock_digest_patch = mock.patch.object(
            preparation,
            "_ACQUISITION_CORPUS_LOCK_DIGEST",
            lock_digest,
        )
        self.lock_path_patch.start()
        self.lock_digest_patch.start()
        self.addCleanup(self.lock_path_patch.stop)
        self.addCleanup(self.lock_digest_patch.stop)
        policy = json.loads(POLICY.read_bytes())
        policy["candidate"]["implementation_digest"] = (
            candidate_implementation_digest()
        )
        self.policy_path.write_bytes(_canonical_json_bytes(policy))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_prepares_digest_bound_paired_inputs_without_outcomes(self) -> None:
        seen_tokens = []
        seen_modes = []

        def acquire(
            repository_url: str,
            commit: str,
            skill_path: str,
            cas: CAS,
            *,
            bearer_token: str | None,
            expansion_mode: str | None,
            **budgets: int,
        ) -> dict[str, object]:
            seen_tokens.append(bearer_token)
            seen_modes.append(expansion_mode)
            return self._retain_expansion(
                repository_url,
                commit,
                skill_path,
                cas,
                budgets,
            )

        result = prepare_files(
            self.catalog_path,
            self.output,
            state_path=self.state,
            candidate_policy_path=self.policy_path,
            bearer_token="github-test-token",
            acquire=acquire,
        )

        self.assertEqual(result["schema"], RESULT_SCHEMA)
        self.assertEqual(result["status"], "prepared_for_authenticated_execution")
        self.assertEqual(result["case_count"], 448)
        self.assertEqual(
            result["corpus_lock_digest"],
            preparation._ACQUISITION_CORPUS_LOCK_DIGEST,
        )
        self.assertEqual(
            result["catalog_digest"],
            "sha256:" + hashlib.sha256(self.catalog_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(seen_tokens, ["github-test-token"] * 448)
        self.assertEqual(seen_modes, [TERMINAL_DEPTH_1_MODE] * 448)
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()),
            [
                "acquisition-oracle.json",
                "expanded-cases",
                "expanded-suite.json",
                "phase0-accounting.json",
                "root-cases",
                "root-suite.json",
            ],
        )
        oracle = json.loads(
            (self.output / "acquisition-oracle.json").read_bytes()
        )
        accounting = json.loads(
            (self.output / "phase0-accounting.json").read_bytes()
        )
        self.assertEqual(oracle["root_suite_digest"], result["root_suite_digest"])
        self.assertEqual(
            oracle["expanded_suite_digest"], result["expanded_suite_digest"]
        )
        self.assertEqual(
            accounting["suite_digest"], result["expanded_suite_digest"]
        )
        self.assertEqual(oracle["budgets"], _BUDGETS)
        self.assertEqual(oracle["expansion_profile"], TERMINAL_DEPTH_1_PROFILE)
        self.assertEqual(
            oracle["expansion_assurance"], TERMINAL_DEPTH_1_ASSURANCE
        )
        self.assertEqual(
            accounting["expansion_profile"], TERMINAL_DEPTH_1_PROFILE
        )
        self.assertEqual(
            accounting["expansion_assurance"], TERMINAL_DEPTH_1_ASSURANCE
        )
        self.assertEqual(len(oracle["cases"]), 448)
        self.assertEqual(len(accounting["cases"]), 448)
        self.assertTrue(
            all(case["expected_references"] for case in oracle["cases"])
        )
        self.assertTrue(
            all(len(case["expected_references"]) == 1 for case in oracle["cases"])
        )
        self.assertEqual(
            {
                case["family"]
                for case in oracle["cases"]
                if case["class"] == "adversarial"
            },
            {"agent-skill-adversarial"},
        )
        self.assertTrue(
            all(case["lineage"] == case["case_id"] for case in oracle["cases"])
        )
        self.assertNotEqual(
            oracle["cases"][0]["root_tree_digest"],
            oracle["cases"][0]["expanded_tree_digest"],
        )
        with tempfile.TemporaryDirectory(
            prefix="aragorn-acquisition-suite-reload-"
        ) as reloaded:
            root = load_suite_for_run(
                self.output / "root-suite.json",
                CAS(Path(reloaded) / "root"),
                required_purpose="evidence_smoke",
            )
            expanded = load_suite_for_run(
                self.output / "expanded-suite.json",
                CAS(Path(reloaded) / "expanded"),
                required_purpose="evidence_smoke",
            )
        self.assertEqual(root["digest"], result["root_suite_digest"])
        self.assertEqual(expanded["digest"], result["expanded_suite_digest"])
        self.assertTrue(
            all(
                case["source"]["license"] == "private-evaluation-only"
                for case in root["cases"].values()
            )
        )
        self.assertEqual(
            {system["name"] for system in root["systems"].values()},
            {"cisco-skill-scanner", "skillspector"},
        )
        self.assertEqual(
            {system["name"] for system in expanded["systems"].values()},
            {"aragorn", "cisco-skill-scanner", "skillspector"},
        )

    def test_incomplete_acquisition_removes_new_output_and_state(self) -> None:
        def acquire(
            repository_url: str,
            commit: str,
            skill_path: str,
            cas: CAS,
            *,
            bearer_token: str | None,
            expansion_mode: str | None,
            **budgets: int,
        ) -> dict[str, object]:
            result = self._retain_expansion(
                repository_url,
                commit,
                skill_path,
                cas,
                budgets,
            )
            result["closure"] = {
                "scope": "phase0_exact_github_blob_expansion_terminal_depth_1",
                "status": "incomplete",
                "unresolved": [
                    {"reason_code": "REFERENCE_BUDGET_EXCEEDED", "subject": "SKILL.md"}
                ],
            }
            result["comparator_subject_manifest_digest"] = None
            result["comparator_subject_tree_digest"] = None
            result["expanded_object_count"] = 0
            return result

        with self.assertRaisesRegex(
            AcquisitionPreparationError, "did not reach complete expansion"
        ):
            prepare_files(
                self.catalog_path,
                self.output,
                state_path=self.state,
                candidate_policy_path=self.policy_path,
                acquire=acquire,
            )

        self.assertFalse(self.output.exists())
        self.assertFalse(self.state.exists())

    def test_rejects_catalog_target_url_drift_before_acquisition(self) -> None:
        self.catalog[0]["expanded_target_url"] += "?raw=1"
        preparation._ACQUISITION_CORPUS_LOCK_DIGEST = self._write_catalog(
            self.catalog
        )
        called = False

        def acquire(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal called
            called = True
            raise AssertionError("acquisition must not start")

        with self.assertRaisesRegex(
            AcquisitionPreparationError, "noncanonical raw GitHub URL"
        ):
            prepare_files(
                self.catalog_path,
                self.output,
                state_path=self.state,
                candidate_policy_path=self.policy_path,
                acquire=acquire,
            )

        self.assertFalse(called)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.state.exists())

    def test_rejects_catalog_byte_drift_before_acquisition(self) -> None:
        self.catalog_path.write_bytes(self.catalog_path.read_bytes() + b"\n")
        called = False

        def acquire(*_args: object, **_kwargs: object) -> dict[str, object]:
            nonlocal called
            called = True
            raise AssertionError("acquisition must not start")

        with self.assertRaisesRegex(
            AcquisitionPreparationError, "frozen plaintext digest"
        ):
            prepare_files(
                self.catalog_path,
                self.output,
                state_path=self.state,
                candidate_policy_path=self.policy_path,
                acquire=acquire,
            )

        self.assertFalse(called)

    def test_rejects_expansion_that_misses_the_authored_target(self) -> None:
        def acquire(
            repository_url: str,
            commit: str,
            skill_path: str,
            cas: CAS,
            *,
            bearer_token: str | None,
            expansion_mode: str | None,
            **budgets: int,
        ) -> dict[str, object]:
            return self._retain_expansion(
                repository_url,
                commit,
                skill_path,
                cas,
                budgets,
                target_case_id="wrong-authored-target",
            )

        with self.assertRaisesRegex(
            AcquisitionPreparationError, "authored root/target reference"
        ):
            prepare_files(
                self.catalog_path,
                self.output,
                state_path=self.state,
                candidate_policy_path=self.policy_path,
                acquire=acquire,
            )

        self.assertFalse(self.output.exists())
        self.assertFalse(self.state.exists())

    def test_token_stdin_is_one_bounded_visible_ascii_line(self) -> None:
        self.assertEqual(
            _read_bearer_token(io.BytesIO(b"github-token\n")),
            "github-token",
        )
        for raw in (
            b"",
            b"token",
            b"token\r\n",
            b"token\nextra\n",
            b"has space\n",
            b"x" * 1025 + b"\n",
        ):
            with self.subTest(raw=raw[:16]):
                with self.assertRaises(AcquisitionPreparationError):
                    _read_bearer_token(io.BytesIO(raw))

    def test_script_entrypoint_loads_from_the_repository_root(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "prepare_phase0_acquisition.py"),
                "--help",
            ],
            cwd=self.root,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @staticmethod
    def _catalog() -> list[dict[str, str]]:
        definitions = [
            (f"adversarial-{index:03d}", "adversarial")
            for index in range(112)
        ]
        definitions.extend(
            (f"benign-{index:03d}", "benign")
            for index in range(336)
        )
        return [
            {
                "case_id": case_id,
                "root_github_url": _raw_github_url(
                    _ROOT_COMMIT, f"roots/{case_id}/SKILL.md"
                ),
                "root_owner": _OWNER,
                "root_repo": _REPOSITORY,
                "root_commit": _ROOT_COMMIT,
                "root_path": f"roots/{case_id}/SKILL.md",
                "expanded_target_url": _raw_github_url(
                    _TARGET_COMMIT, f"targets/{case_id}/SKILL.md"
                ),
                "expanded_target_commit": _TARGET_COMMIT,
                "expanded_target_path": f"targets/{case_id}/SKILL.md",
                "expected_class": case_class,
            }
            for case_id, case_class in definitions
        ]

    def _write_catalog(self, catalog: list[dict[str, str]]) -> str:
        raw = (
            json.dumps(catalog, indent=2, sort_keys=True).encode("utf-8")
            + b"\n"
        )
        self.catalog_path.write_bytes(raw)
        os.chmod(self.catalog_path, 0o600)
        lock = json.loads(CORPUS_LOCK.read_bytes())
        lock["artifacts"]["evaluator_catalog_plaintext"]["sha256"] = (
            "sha256:" + hashlib.sha256(raw).hexdigest()
        )
        lock_raw = _canonical_json_bytes(lock)
        self.corpus_lock_path.write_bytes(lock_raw)
        return "sha256:" + hashlib.sha256(lock_raw).hexdigest()

    @staticmethod
    def _retain_expansion(
        repository_url: str,
        commit: str,
        skill_path: str,
        cas: CAS,
        arguments: dict[str, int],
        *,
        target_case_id: str | None = None,
    ) -> dict[str, object]:
        case_id = skill_path.rsplit("/", 1)[-1]
        target_case_id = target_case_id or case_id
        owner, repository = repository_url.removeprefix(
            "https://github.com/"
        ).split("/")
        target_path = f"targets/{target_case_id}/SKILL.md"
        literal = _raw_github_url(_TARGET_COMMIT, target_path).encode()
        root_content = literal + b"\n"
        target_content = f"retained target for {target_case_id}\n".encode()
        root_digest = _put(cas, root_content)
        target_digest = _put(cas, target_content)
        commit_tree = hashlib.sha1(b"root-commit-tree").hexdigest()
        target_commit_tree = hashlib.sha1(b"target-commit-tree").hexdigest()
        skill_tree = hashlib.sha1(f"{case_id}:skill-tree".encode()).hexdigest()
        root_file = {
            "path": "SKILL.md",
            "size": len(root_content),
            "digest": root_digest,
            "git_blob_sha1": _blob_sha1(root_content),
            "executable": False,
        }
        root_tree_digest = _digest_json(
            [
                {
                    key: root_file[key]
                    for key in ("path", "size", "digest", "executable")
                }
            ]
        )
        root_manifest = {
            "schema": "aragorn/github-manifest/v1",
            "source": {
                "kind": "github_commit",
                "host": "github.com",
                "owner": owner,
                "repository": repository,
                "commit": commit,
                "repository_hash_algorithm": "sha1",
                "commit_tree": commit_tree,
                "skill_path": skill_path,
                "skill_tree": skill_tree,
                "api_version": "2026-03-10",
            },
            "tree_digest": root_tree_digest,
            "files": [root_file],
            "closure": {"scope": "source_tree", "status": "complete"},
        }
        root_manifest_digest = _put_json(cas, root_manifest)
        materialized_path = (
            f"__aragorn_expanded__/{_TARGET_COMMIT}/{target_path}"
        )
        subject_files = [
            {
                "path": "SKILL.md",
                "size": len(root_content),
                "digest": root_digest,
                "executable": False,
            },
            {
                "path": materialized_path,
                "size": len(target_content),
                "digest": target_digest,
                "executable": False,
            },
        ]
        subject_manifest = {
            "schema": "aragorn/benchmark-subject-manifest/v1",
            "tree_digest": _digest_json(subject_files),
            "files": subject_files,
        }
        subject_manifest_digest = _put_json(cas, subject_manifest)
        source_repository_path = f"{skill_path}/SKILL.md"
        occurrence_identity = {
            "source_commit": commit,
            "source_repository_path": source_repository_path,
            "source_blob_digest": root_digest,
            "byte_offset": 0,
            "literal_size": len(literal),
            "literal_digest": "sha256:" + hashlib.sha256(literal).hexdigest(),
        }
        occurrence = {
            **occurrence_identity,
            "target_commit": _TARGET_COMMIT,
            "target_repository_path": target_path,
            "status": "expanded",
            "reason_code": None,
        }
        budgets = {
            name.removeprefix("max_"): {"limit": limit, "used": 1}
            for name, limit in arguments.items()
        }
        budgets["retained_bytes"]["used"] = len(root_content) + len(target_content)
        expansion = {
            "schema": "aragorn/github-expansion/v1",
            "profile": TERMINAL_DEPTH_1_PROFILE,
            "assurance": TERMINAL_DEPTH_1_ASSURANCE,
            "source": {
                "host": "github.com",
                "owner": owner,
                "repository": repository,
                "commit": commit,
                "commit_tree": commit_tree,
                "skill_path": skill_path,
                "api_version": "2026-03-10",
            },
            "root_manifest_digest": root_manifest_digest,
            "root_tree_digest": root_tree_digest,
            "comparator_subject_manifest_digest": subject_manifest_digest,
            "comparator_subject_tree_digest": subject_manifest["tree_digest"],
            "references": [occurrence],
            "objects": [
                {
                    "commit": _TARGET_COMMIT,
                    "commit_tree": target_commit_tree,
                    "repository_path": target_path,
                    "materialized_path": materialized_path,
                    "depth": 1,
                    "size": len(target_content),
                    "digest": target_digest,
                    "git_blob_sha1": _blob_sha1(target_content),
                    "executable": False,
                    "references": [occurrence_identity],
                }
            ],
            "accounting": {
                "references": {
                    "total_edges": 1,
                    "artifact_references": 1,
                    "resolved_in_root": 0,
                    "expanded": 1,
                    "deduplicated": 0,
                    "non_artifact": 0,
                    "unresolved": 0,
                    "opaque_carriers": 0,
                    "scan_complete": True,
                    "occurrences_complete": True,
                    "occurrences_omitted": 0,
                },
                "budgets": budgets,
            },
            "closure": {
                "scope": "phase0_exact_github_blob_expansion_terminal_depth_1",
                "status": "complete",
                "unresolved": [],
            },
        }
        expansion_digest = _put_json(cas, expansion)
        return {
            "schema": "aragorn/github-expansion-result/v1",
            "expansion_digest": expansion_digest,
            "root_manifest_digest": root_manifest_digest,
            "root_tree_digest": root_tree_digest,
            "comparator_subject_manifest_digest": subject_manifest_digest,
            "comparator_subject_tree_digest": subject_manifest["tree_digest"],
            "expanded_object_count": 1,
            "accounting": expansion["accounting"],
            "closure": expansion["closure"],
        }


if __name__ == "__main__":
    unittest.main()
