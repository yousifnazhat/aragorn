from __future__ import annotations

import hashlib
import json
import sys
import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aragorn.oci_worker_protocol import canonical_json
from scripts.freeze_hidden_suite import (
    FreezeError,
    _artifact_map,
    _fresh_openssl_receipt_schema,
    _match_prior_freeze,
    _validate_skill_frontmatter,
    _verify_release_v2,
    _verify_source_freeze,
    freeze,
    validate_freeze_receipt_bindings,
)


class FreezeReceiptTests(unittest.TestCase):
    def test_fresh_openssl_receipt_schema_preserves_v3_and_selects_v4(self) -> None:
        self.assertEqual(
            _fresh_openssl_receipt_schema("independent-v3.0.0"),
            "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v3",
        )
        self.assertEqual(
            _fresh_openssl_receipt_schema("local-v4.0.0"),
            "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v4",
        )
        with self.assertRaises(FreezeError):
            _fresh_openssl_receipt_schema("unknown")

    def test_skill_frontmatter_preflight_accepts_valid_and_rejects_invalid(
        self,
    ) -> None:
        _validate_skill_frontmatter(
            (
                b"---\n"
                b"name: inert-skill-1\n"
                b"description: Inspect an inert local fixture.\n"
                b"license: private-evaluation-only\n"
                b"---\n\n"
                b"# Inert skill\n"
            ),
            "valid",
        )

        invalid = {
            "missing-leading-marker": b"# Skill\n",
            "missing-closing-marker": (
                b"---\nname: inert-skill\ndescription: Inert.\n"
            ),
            "missing-name": b"---\ndescription: Inert.\n---\n",
            "invalid-name": (
                b"---\nname: Not A Slug\ndescription: Inert.\n---\n"
            ),
            "empty-description": (
                b"---\nname: inert-skill\ndescription: \"\"\n---\n"
            ),
            "duplicate-name": (
                b"---\nname: inert-skill\nname: other\n"
                b"description: Inert.\n---\n"
            ),
            "duplicate-extra-key": (
                b"---\nname: inert-skill\ndescription: Inert.\n"
                b"license: one\nlicense: two\n---\n"
            ),
            "control-character": (
                b"---\nname: inert-skill\ndescription: Inert.\x00\n---\n"
            ),
        }
        for label, raw in invalid.items():
            with self.subTest(label=label), self.assertRaisesRegex(
                FreezeError,
                "frontmatter",
            ):
                _validate_skill_frontmatter(raw, label)

    def test_release_artifacts_are_selected_by_signed_role_not_v1_name(self) -> None:
        release = {
            "artifacts": [
                {
                    "path": "worker-independent-v3.0.0.tar.gz",
                    "purpose": "worker cases and public case manifest; no label ledger",
                    "sha256": "1" * 64,
                    "size": 1,
                },
                {
                    "path": "evaluator-independent-v3.0.0.tar.gz.gpg",
                    "purpose": "signed encrypted evaluator ledger and exact builder",
                    "sha256": "2" * 64,
                    "size": 1,
                },
                {
                    "path": "source-independent-v3.0.0.bundle",
                    "purpose": "complete Git history with signed freeze commit and tag",
                    "sha256": "3" * 64,
                    "size": 1,
                },
            ]
        }
        lock = {"worker_archive": {"name": "worker-independent-v3.0.0.tar.gz"}}
        artifacts = _artifact_map(release, lock)
        self.assertEqual(
            {role: artifact["path"] for role, artifact in artifacts.items()},
            {
                "worker": "worker-independent-v3.0.0.tar.gz",
                "evaluator": "evaluator-independent-v3.0.0.tar.gz.gpg",
                "source": "source-independent-v3.0.0.bundle",
            },
        )

        changed = deepcopy(release)
        changed["artifacts"][2]["purpose"] = changed["artifacts"][1]["purpose"]
        with self.assertRaisesRegex(FreezeError, "purpose is repeated"):
            _artifact_map(changed, lock)

    def test_local_v4_release_manifest_is_exact_and_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            release_root = root / "release"
            release_root.mkdir()
            payloads = {
                "release/local-v4.0.0-worker-holdout.tar.gz": b"worker",
                "release/local-v4.0.0-evaluator.tar.gz.enc": b"evaluator",
                "release/local-v4.0.0-git-history.bundle": b"source",
            }
            purposes = [
                (
                    "worker cases and public case manifest; no labels or custody "
                    "material"
                ),
                (
                    "signed encrypted evaluator ledger, v3 source evidence, and "
                    "exact repair builder"
                ),
                (
                    "complete Git history with signed source and freeze commits "
                    "and signed tag"
                ),
            ]
            for path, raw in payloads.items():
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            artifacts = [
                {
                    "path": path,
                    "purpose": purpose,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                }
                for (path, raw), purpose in zip(payloads.items(), purposes)
            ]
            manifest = {
                "aggregate_counts": {
                    "total": 448,
                    "benign": 336,
                    "adversarial": 112,
                },
                "artifacts": artifacts,
                "authorship": {
                    "independent_human_authorship": False,
                    "label_changes": 0,
                    "mode": "technical-codex-metadata-repair",
                    "outcome_driven_content_changes": 0,
                    "outcomes_used_for_tuning": False,
                    "scanner_evaluations": 0,
                    "semantic_case_body_changes": 0,
                },
                "corpus_id": "local-v4.0.0",
                "corpus_version": "local-v4.0.0",
                "custody": {
                    "evaluator_plaintext_sha256": "4" * 64,
                    "freeze_commit": "5" * 40,
                    "freeze_tag": "local-v4.0.0",
                    "generator_sha256": "6" * 64,
                    "keychain_account": "aragorn-local-v4.0.0-author.test",
                    "keychain_service": (
                        "org.openai.codex.aragorn.phase0.local-v4.0.0."
                        "evaluator.test"
                    ),
                    "source_commit": "7" * 40,
                    "tag_object": "8" * 40,
                },
                "repair_scope": "yaml-frontmatter-name-description-only",
                "schema_version": "1.0",
                "signing": {
                    "identity": "aragorn-local-v4-author",
                    "public_key_fingerprint": "SHA256:test",
                    "signed_objects": [
                        "source commit",
                        "freeze commit",
                        "annotated freeze tag",
                        "label ledger",
                        "evaluator manifest",
                        "release manifest",
                    ],
                },
                "source_corpus_version": "independent-v3.0.0",
            }
            manifest_path = (
                release_root / "local-v4.0.0-release-manifest.json"
            )
            manifest_raw = canonical_json(manifest)
            manifest_path.write_bytes(manifest_raw)
            lock = {
                "corpus_id": "local-v4.0.0",
                "evaluator_archive": {
                    "sha256": "sha256:" + artifacts[1]["sha256"]
                },
                "freeze": {
                    "commit": "5" * 40,
                    "tag": "local-v4.0.0",
                    "tag_object": "8" * 40,
                },
                "release_manifest": {
                    "sha256": "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
                },
                "signing": {
                    "fingerprint": "SHA256:test",
                    "principal": "aragorn-local-v4-author",
                },
                "worker_archive": {
                    "name": "local-v4.0.0-worker-holdout.tar.gz",
                    "sha256": "sha256:" + artifacts[0]["sha256"],
                },
            }
            checks = (
                patch(
                    "scripts.freeze_hidden_suite._signer_material",
                    return_value=(b"allowed", b"ssh-ed25519 key\n"),
                ),
                patch("scripts.freeze_hidden_suite._verify_signature"),
                patch("scripts.freeze_hidden_suite._verify_source_freeze"),
            )
            with checks[0], checks[1], checks[2] as source_check:
                verified = _verify_release_v2(root, lock)
                self.assertEqual(
                    verified["worker_archive_digest"],
                    lock["worker_archive"]["sha256"],
                )
                self.assertEqual(
                    source_check.call_args.kwargs,
                    {"source_commit": "7" * 40},
                )

                manifest["authorship"]["scanner_evaluations"] = 1
                changed_raw = canonical_json(manifest)
                manifest_path.write_bytes(changed_raw)
                lock["release_manifest"]["sha256"] = (
                    "sha256:" + hashlib.sha256(changed_raw).hexdigest()
                )
                with self.assertRaisesRegex(
                    FreezeError,
                    "does not match the v2 corpus lock",
                ):
                    _verify_release_v2(root, lock)

    def test_local_v4_source_commit_must_be_direct_freeze_parent(self) -> None:
        source = "1" * 40

        def run(arguments: list[str], **_: object) -> str:
            if "--format=%P" in arguments:
                return "2" * 40
            return ""

        with patch("scripts.freeze_hidden_suite._run", side_effect=run):
            with self.assertRaisesRegex(FreezeError, "direct freeze parent"):
                _verify_source_freeze(
                    b"bundle",
                    b"allowed",
                    {
                        "commit": "3" * 40,
                        "tag": "local-v4.0.0",
                        "tag_object": "4" * 40,
                    },
                    source_commit=source,
                )

    def test_preserved_evaluator_source_is_exclusive_and_bound(self) -> None:
        arguments = {
            "release_dir": ROOT,
            "corpus_lock_path": ROOT / "benchmark" / "phase0-corpus.lock.json",
            "candidate_policy_path": (
                ROOT / "benchmark" / "phase0-candidate-policy-v2.json"
            ),
            "private_suite_root": ROOT / "unused-suite",
            "lock_output": ROOT / "unused-lock",
            "receipt_output": ROOT / "unused-receipt",
            "recorded_on": "2026-07-25",
            "run_state_root": ROOT,
        }
        for evaluator_passphrase, verified_evaluator_package in (
            (None, None),
            (b"secret", ROOT),
        ):
            with self.subTest(
                evaluator_passphrase=evaluator_passphrase is not None,
                verified_evaluator_package=verified_evaluator_package is not None,
            ), self.assertRaisesRegex(FreezeError, "select exactly one"):
                freeze(
                    **arguments,
                    evaluator_passphrase=evaluator_passphrase,
                    verified_evaluator_package=verified_evaluator_package,
                )

        prior = {
            "receipt": {
                "release": {
                    "release_manifest_digest": "release",
                    "worker_archive_digest": "worker",
                    "evaluator_ciphertext_digest": "evaluator",
                    "source_bundle_digest": "source",
                },
                "evaluator": {
                    "manifest_digest": "manifest",
                    "label_ledger_digest": "labels",
                    "public_manifest_digest": "public",
                },
            }
        }
        release = {
            "release_manifest_digest": "release",
            "worker_archive_digest": "worker",
            "evaluator_archive_digest": "evaluator",
            "source_bundle_digest": "source",
        }
        evaluator = {
            "evaluator_manifest_digest": "manifest",
            "label_ledger_digest": "labels",
            "public_manifest_digest": "public",
        }
        _match_prior_freeze(prior, release, evaluator)
        changed = deepcopy(evaluator)
        changed["label_ledger_digest"] = "changed"
        with self.assertRaisesRegex(FreezeError, "prior signed freeze"):
            _match_prior_freeze(prior, release, changed)

    def test_invalid_date_and_symlinked_private_path_fail_first(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_state = root / "run"
            run_state.mkdir(mode=0o700)
            common = {
                "release_dir": root,
                "evaluator_passphrase": b"test-only",
                "corpus_lock_path": ROOT / "benchmark" / "phase0-corpus.lock.json",
                "candidate_policy_path": (
                    ROOT / "benchmark" / "phase0-candidate-policy.json"
                ),
                "private_suite_root": root / "private-suite",
                "lock_output": root / "lock.json",
                "receipt_output": root / "receipt.json",
                "run_state_root": run_state,
            }
            with self.assertRaisesRegex(FreezeError, "real YYYY-MM-DD"):
                freeze(
                    **common,
                    recorded_on="2026-99-99",
                )

            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(FreezeError, "symlink component"):
                freeze(
                    **{**common, "private_suite_root": alias / "private-suite"},
                    recorded_on="2026-07-24",
                )

    def test_schema_valid_label_digest_substitution_is_rejected(self) -> None:
        lock_raw = (ROOT / "benchmark" / "phase0-hidden-suite.lock.json").read_bytes()
        receipt_raw = (
            ROOT
            / "benchmark"
            / "receipts"
            / "phase0-hidden-suite-freeze-2026-07-24.json"
        ).read_bytes()
        corpus_lock_raw = (ROOT / "benchmark" / "phase0-corpus.lock.json").read_bytes()
        lock = json.loads(lock_raw)
        receipt = json.loads(receipt_raw)
        corpus_lock = json.loads(corpus_lock_raw)

        validate_freeze_receipt_bindings(
            receipt,
            receipt_raw,
            lock,
            lock_raw,
            corpus_lock,
            corpus_lock_raw,
        )

        changed = deepcopy(receipt)
        changed["evaluator"]["label_ledger_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            FreezeError,
            "label ledger digest does not match lock",
        ):
            validate_freeze_receipt_bindings(
                changed,
                canonical_json(changed),
                lock,
                lock_raw,
                corpus_lock,
                corpus_lock_raw,
            )


if __name__ == "__main__":
    unittest.main()
