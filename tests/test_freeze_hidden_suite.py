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
    _V5_ALLOWED_SIGNER,
    _V5_ARTIFACT_PURPOSES,
    _V5_AUTHORING_CONTRACT,
    _V5_AUTHORING_INPUTS,
    _V5_AUTHORSHIP,
    _V5_NOVELTY_POLICY,
    _V5_SIGNER_FINGERPRINT,
    _V5_SIGNER_PRINCIPAL,
    _V6_ALLOWED_SIGNER,
    _V6_AUTHORING_CONTRACT,
    _V6_AUTHORING_INPUTS,
    _V6_AUTHORSHIP,
    _V6_NOVELTY_POLICY,
    _V6_SIGNED_CHAIN,
    _V6_SIGNER_FINGERPRINT,
    _V6_SIGNER_PRINCIPAL,
    _V6_WORKER_VISIBLE_LEAKAGE,
    _PRIOR_FREEZES,
    FreezeError,
    _artifact_map,
    _fresh_openssl_receipt_schema,
    _match_prior_freeze,
    _measure_semantic_novelty,
    _measure_v5_novelty,
    _validate_skill_frontmatter,
    _validate_v6_worker_visible_case,
    _verified_labels,
    _verify_release_v2,
    _verify_semantic_novelty,
    _verify_source_freeze,
    _verify_v5_novelty,
    freeze,
    validate_freeze_receipt_bindings,
)


class FreezeReceiptTests(unittest.TestCase):
    def test_preserved_evaluator_profiles_include_v6_maintenance(self) -> None:
        self.assertEqual(
            set(_PRIOR_FREEZES),
            {"independent-v1.0.0", "local-v6.0.0"},
        )
        self.assertEqual(
            _PRIOR_FREEZES["local-v6.0.0"]["lock_digest"],
            "sha256:a862f355c21b3ce4e3d996b8cfd155856fa47a66a7e03f37a728e1aec3a99997",
        )

    def test_fresh_openssl_receipt_schema_preserves_v3_and_selects_v4(self) -> None:
        self.assertEqual(
            _fresh_openssl_receipt_schema("independent-v3.0.0"),
            "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v3",
        )
        self.assertEqual(
            _fresh_openssl_receipt_schema("local-v4.0.0"),
            "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v4",
        )
        self.assertEqual(
            _fresh_openssl_receipt_schema("local-v5.0.0"),
            "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v5",
        )
        self.assertEqual(
            _fresh_openssl_receipt_schema("local-v6.0.0"),
            "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v6",
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

    def test_local_v6_frontmatter_is_neutral_and_body_derived(self) -> None:
        def skill(body: str, *, token: str | None = None) -> bytes:
            derived = hashlib.sha256(
                b"opaque-frontmatter-v1\0" + body.encode()
            ).hexdigest()[:20]
            selected = derived if token is None else token
            return (
                "---\n"
                f"name: entry-{selected}\n"
                f"description: Static inert document {selected}.\n"
                "---\n\n"
                f"{body}\n"
            ).encode()

        body = "Review the inert local fixture and summarize its static wording."
        name = _validate_v6_worker_visible_case(skill(body), "v6-test")
        self.assertTrue(name.startswith("entry-"))

        with self.assertRaisesRegex(FreezeError, "derived from its body"):
            _validate_v6_worker_visible_case(
                skill(body, token="0" * 20),
                "v6-wrong-token",
            )
        with self.assertRaisesRegex(FreezeError, "exact name and description"):
            _validate_v6_worker_visible_case(
                skill(body).replace(b"---\n\n", b"license: private\n---\n\n"),
                "v6-extra-frontmatter",
            )
        leaking_body = "This adversarial label must not be worker visible."
        with self.assertRaisesRegex(FreezeError, "label proxy leakage"):
            _validate_v6_worker_visible_case(
                skill(leaking_body),
                "v6-label-proxy",
            )
        family_body = "The phrase tool-mediated exfiltration is a family title."
        with self.assertRaisesRegex(FreezeError, "label proxy leakage"):
            _validate_v6_worker_visible_case(
                skill(family_body),
                "v6-family-proxy",
            )

    def test_local_v6_label_ledger_requires_symmetric_pairs(self) -> None:
        rows = []
        for index in range(112):
            left = f"v6-{2 * index:024x}"
            right = f"v6-{2 * index + 1:024x}"
            family = f"AF{index % 14 + 1:02d}"
            standards = ["AST01", "AML.T0051.001"]
            rows.extend(
                (
                    {
                        "family": family,
                        "id": left,
                        "label": "adversarial",
                        "pair_id": right,
                        "sha256": "0" * 64,
                        "size": 1,
                        "standards": standards,
                    },
                    {
                        "family": family,
                        "id": right,
                        "label": "benign",
                        "pair_id": left,
                        "sha256": "0" * 64,
                        "size": 1,
                        "standards": standards,
                    },
                )
            )
        rows.extend(
            {
                "family": "ordinary editorial task",
                "id": f"v6-{index:024x}",
                "label": "benign",
                "pair_id": None,
                "sha256": "0" * 64,
                "size": 1,
                "standards": [],
            }
            for index in range(224, 448)
        )
        rows.sort(key=lambda row: row["id"])
        public = {
            row["id"]: {"sha256": "0" * 64, "size": 1}
            for row in rows
        }

        def ledger(values: list[dict[str, object]]) -> bytes:
            return b"".join(canonical_json(row) + b"\n" for row in values)

        _labels, counts = _verified_labels(
            ledger(rows),
            public,
            corpus_id="local-v6.0.0",
        )
        self.assertEqual(counts, {"benign": 336, "adversarial": 112})

        changed = deepcopy(rows)
        changed[1]["standards"] = ["AST02"]
        with self.assertRaisesRegex(FreezeError, "pairing"):
            _verified_labels(
                ledger(changed),
                public,
                corpus_id="local-v6.0.0",
            )

    def test_local_v6_contract_and_external_lock_are_exactly_pinned(self) -> None:
        contract_raw = canonical_json(_V6_AUTHORING_CONTRACT)
        self.assertEqual(
            hashlib.sha256(contract_raw).hexdigest(),
            _V6_SIGNED_CHAIN["authoring_contract_sha256"],
        )
        self.assertEqual(
            _V6_AUTHORING_CONTRACT["authoring_inputs"],
            _V6_AUTHORING_INPUTS,
        )
        lock_raw = (ROOT / "benchmark" / "phase0-corpus-v6.lock.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(lock_raw).hexdigest(),
            "12bda81360181b5c81a9483d861c681efd40083913d3e4c6c4d835814d6c192d",
        )
        self.assertFalse(lock_raw.endswith(b"\n"))

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

    def test_local_v5_release_is_new_authorship_not_v4_repair(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "release").mkdir()
            payloads = {
                "release/local-v5.0.0-worker-holdout.tar.gz": b"worker",
                "release/local-v5.0.0-evaluator.tar.gz.enc": b"evaluator",
                "release/local-v5.0.0-git-history.bundle": b"source",
            }
            for path, raw in payloads.items():
                destination = root / path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
            artifacts = [
                {
                    "path": path,
                    "purpose": purpose,
                    "sha256": hashlib.sha256(payloads[path]).hexdigest(),
                    "size": len(payloads[path]),
                }
                for path, purpose in zip(payloads, _V5_ARTIFACT_PURPOSES.values())
            ]
            contract = {
                "commit": "6" * 40,
                "path": "AUTHORING-CONTRACT.json",
                "sha256": hashlib.sha256(
                    canonical_json(_V5_AUTHORING_CONTRACT)
                ).hexdigest(),
            }
            novelty = {
                **_V5_NOVELTY_POLICY,
                "candidate_unique_body_count": 448,
                "exact_reference_body_overlap_count": 0,
                "maximum_observed_similarity": {
                    "candidate_case_id": "v5-" + "1" * 24,
                    "reference_case_id": "v4-" + "2" * 24,
                    "numerator": 0,
                    "denominator": 1,
                },
            }
            manifest = {
                "aggregate_counts": {
                    "total": 448,
                    "benign": 336,
                    "adversarial": 112,
                },
                "artifacts": artifacts,
                "authoring_contract": contract,
                "authorship": _V5_AUTHORSHIP,
                "corpus_id": "local-v5.0.0",
                "corpus_version": "local-v5.0.0",
                "custody": {
                    "evaluator_plaintext_sha256": "4" * 64,
                    "freeze_commit": "5" * 40,
                    "freeze_tag": "local-v5.0.0",
                    "generator_sha256": "6" * 64,
                    "keychain_account": "aragorn-local-v5.0.0-author.test",
                    "keychain_service": (
                        "org.openai.codex.aragorn.phase0.local-v5.0.0."
                        "evaluator.test"
                    ),
                    "source_commit": "7" * 40,
                    "tag_object": "8" * 40,
                },
                "novelty": novelty,
                "schema_version": "2.0",
                "signing": {
                    "identity": _V5_SIGNER_PRINCIPAL,
                    "public_key_fingerprint": _V5_SIGNER_FINGERPRINT,
                    "signed_objects": [
                        "authoring contract commit",
                        "source commit",
                        "freeze commit",
                        "annotated freeze tag",
                        "label ledger",
                        "evaluator manifest",
                        "release manifest",
                    ],
                },
            }
            manifest_path = root / "release" / "local-v5.0.0-release-manifest.json"
            manifest_raw = canonical_json(manifest)
            manifest_path.write_bytes(manifest_raw)
            lock = {
                "corpus_id": "local-v5.0.0",
                "evaluator_archive": {
                    "sha256": "sha256:" + artifacts[1]["sha256"]
                },
                "freeze": {
                    "commit": "5" * 40,
                    "tag": "local-v5.0.0",
                    "tag_object": "8" * 40,
                },
                "release_manifest": {
                    "sha256": "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
                },
                "signing": {
                    "fingerprint": _V5_SIGNER_FINGERPRINT,
                    "principal": _V5_SIGNER_PRINCIPAL,
                },
                "worker_archive": {
                    "name": "local-v5.0.0-worker-holdout.tar.gz",
                    "sha256": "sha256:" + artifacts[0]["sha256"],
                },
            }
            with (
                patch(
                    "scripts.freeze_hidden_suite._signer_material",
                    return_value=(
                        _V5_ALLOWED_SIGNER,
                        b"ssh-ed25519 key\n",
                    ),
                ),
                patch("scripts.freeze_hidden_suite._verify_signature"),
                patch(
                    "scripts.freeze_hidden_suite._verify_source_freeze"
                ) as source_check,
            ):
                _verify_release_v2(root, lock)
                self.assertEqual(
                    source_check.call_args.kwargs,
                    {
                        "source_commit": "7" * 40,
                        "authoring_contract": contract,
                    },
                )

                changed_lock = deepcopy(lock)
                changed_lock["signing"]["fingerprint"] = "SHA256:" + "A" * 43
                with self.assertRaisesRegex(FreezeError, "pinned Aragorn key"):
                    _verify_release_v2(root, changed_lock)

                manifest["authorship"] = {
                    **_V5_AUTHORSHIP,
                    "semantic_case_body_changes": 0,
                }
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

    def test_local_v5_authoring_contract_is_signed_before_source(self) -> None:
        contract_raw = canonical_json(_V5_AUTHORING_CONTRACT)
        contract = {
            "commit": "1" * 40,
            "path": "AUTHORING-CONTRACT.json",
            "sha256": hashlib.sha256(contract_raw).hexdigest(),
        }
        source = "2" * 40
        freeze_commit = "3" * 40
        tag_object = "4" * 40

        def run(arguments: list[str], **_: object) -> str:
            if "--format=%P" in arguments:
                return source if arguments[-1] == freeze_commit else contract["commit"]
            if "ls-tree" in arguments:
                if "--name-only" not in arguments:
                    authoring_input = next(
                        value
                        for value in (
                            _V5_AUTHORING_INPUTS["prompt"],
                            _V5_AUTHORING_INPUTS["source_pack"],
                        )
                        if value["path"] == arguments[-1]
                    )
                    return (
                        f"100644 blob {authoring_input['git_blob_sha1']}\t"
                        f"{authoring_input['path']}"
                    )
                return "AUTHORING-CONTRACT.json"
            if "cat-file" in arguments and "-s" in arguments:
                return str(len(contract_raw))
            if arguments[-1] == (
                f"{contract['commit']}:AUTHORING-CONTRACT.json"
            ):
                return contract_raw.decode("ascii")
            if arguments[-1] == "refs/tags/local-v5.0.0":
                return tag_object
            if arguments[-1] == "local-v5.0.0^{}":
                return freeze_commit
            return ""

        with patch("scripts.freeze_hidden_suite._run", side_effect=run):
            _verify_source_freeze(
                b"bundle",
                b"allowed",
                {
                    "commit": freeze_commit,
                    "tag": "local-v5.0.0",
                    "tag_object": tag_object,
                },
                source_commit=source,
                authoring_contract=contract,
            )

        def wrong_parent(arguments: list[str], **kwargs: object) -> str:
            if "--format=%P" in arguments and arguments[-1] == source:
                return "9" * 40
            return run(arguments, **kwargs)

        with patch("scripts.freeze_hidden_suite._run", side_effect=wrong_parent):
            with self.assertRaisesRegex(FreezeError, "direct source parent"):
                _verify_source_freeze(
                    b"bundle",
                    b"allowed",
                    {
                        "commit": freeze_commit,
                        "tag": "local-v5.0.0",
                        "tag_object": tag_object,
                    },
                    source_commit=source,
                    authoring_contract=contract,
                )

        def wrong_input(arguments: list[str], **kwargs: object) -> str:
            if (
                "ls-tree" in arguments
                and "--name-only" not in arguments
                and arguments[-1] == "AUTHORING-PROMPT.txt"
            ):
                return f"100644 blob {'9' * 40}\tAUTHORING-PROMPT.txt"
            return run(arguments, **kwargs)

        with patch("scripts.freeze_hidden_suite._run", side_effect=wrong_input):
            with self.assertRaisesRegex(
                FreezeError,
                "source commit retained authoring input changed",
            ):
                _verify_source_freeze(
                    b"bundle",
                    b"allowed",
                    {
                        "commit": freeze_commit,
                        "tag": "local-v5.0.0",
                        "tag_object": tag_object,
                    },
                    source_commit=source,
                    authoring_contract=contract,
                )

    def test_local_v5_authoring_inputs_are_exactly_retained(self) -> None:
        self.assertEqual(
            _V5_AUTHORING_CONTRACT["authoring_inputs"],
            _V5_AUTHORING_INPUTS,
        )
        for authoring_input in (
            _V5_AUTHORING_INPUTS["prompt"],
            _V5_AUTHORING_INPUTS["source_pack"],
        ):
            raw = (ROOT / authoring_input["repository_path"]).read_bytes()
            blob = f"blob {len(raw)}\0".encode("ascii") + raw
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(),
                authoring_input["sha256"],
            )
            self.assertEqual(
                hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
                authoring_input["git_blob_sha1"],
            )

    def test_local_v6_signed_chain_retains_exact_source_inputs(self) -> None:
        contract_raw = canonical_json(_V6_AUTHORING_CONTRACT)
        source_inputs = {
            "AUTHORING-PROMPT.txt": (
                ROOT / "benchmark" / "phase0-v5-authoring-prompt.txt"
            ).read_bytes(),
            "SOURCE-AUTHORING-CONTRACT.json": canonical_json(
                _V5_AUTHORING_CONTRACT
            ),
            "STANDARDS-SOURCE-PACK.json": (
                ROOT / "benchmark" / "phase0-v5-authoring-source-pack.json"
            ).read_bytes(),
        }
        input_records = {
            "AUTHORING-PROMPT.txt": _V6_AUTHORING_INPUTS["prompt"],
            "SOURCE-AUTHORING-CONTRACT.json": _V6_AUTHORING_INPUTS[
                "source_contract"
            ],
            "STANDARDS-SOURCE-PACK.json": _V6_AUTHORING_INPUTS["source_pack"],
        }

        def run(arguments: list[str], **_: object) -> str:
            if "--format=%P" in arguments:
                return (
                    _V6_SIGNED_CHAIN["source_commit"]
                    if arguments[-1] == _V6_SIGNED_CHAIN["freeze_commit"]
                    else _V6_SIGNED_CHAIN["authoring_contract_commit"]
                )
            if "ls-tree" in arguments:
                if "--name-only" in arguments:
                    return "AUTHORING-CONTRACT.json"
                retained_path = arguments[-1]
                record = input_records[retained_path]
                return (
                    f"100644 blob {record['git_blob_sha1']}\t{retained_path}"
                )
            if "cat-file" in arguments and "-s" in arguments:
                return str(len(contract_raw))
            if arguments[-1] == (
                f"{_V6_SIGNED_CHAIN['authoring_contract_commit']}:"
                "AUTHORING-CONTRACT.json"
            ):
                return contract_raw.decode()
            if arguments[-1] == "refs/tags/local-v6.0.0":
                return _V6_SIGNED_CHAIN["freeze_tag_object"]
            if arguments[-1] == "local-v6.0.0^{}":
                return _V6_SIGNED_CHAIN["freeze_commit"]
            return ""

        def run_bytes(arguments: list[str], **_: object) -> bytes:
            return source_inputs[arguments[-1].split(":", 1)[1]]

        with (
            patch("scripts.freeze_hidden_suite._run", side_effect=run),
            patch(
                "scripts.freeze_hidden_suite._run_bytes",
                side_effect=run_bytes,
            ),
        ):
            _verify_source_freeze(
                b"bundle",
                _V6_ALLOWED_SIGNER,
                {
                    "commit": _V6_SIGNED_CHAIN["freeze_commit"],
                    "tag": _V6_SIGNED_CHAIN["freeze_tag"],
                    "tag_object": _V6_SIGNED_CHAIN["freeze_tag_object"],
                },
                source_commit=_V6_SIGNED_CHAIN["source_commit"],
                authoring_contract={
                    "commit": _V6_SIGNED_CHAIN["authoring_contract_commit"],
                    "path": "AUTHORING-CONTRACT.json",
                    "sha256": _V6_SIGNED_CHAIN[
                        "authoring_contract_sha256"
                    ],
                },
            )

    def test_local_v5_corpus_lock_requires_an_exact_checked_pin(self) -> None:
        with TemporaryDirectory(dir=ROOT.parent) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            run_state = root / "run"
            run_state.mkdir(mode=0o700)
            corpus_lock = root / "corpus-lock.json"
            corpus_lock.write_bytes(
                canonical_json(
                    {
                        "schema": (
                            "aragorn/benchmark-corpus-provenance-lock/v2"
                        ),
                        "corpus_id": "local-v5.0.0",
                    }
                )
            )
            with self.assertRaisesRegex(
                FreezeError,
                "checked corpus lock digest changed",
            ):
                freeze(
                    release_dir=root,
                    evaluator_passphrase=b"test-only",
                    corpus_lock_path=corpus_lock,
                    candidate_policy_path=root / "missing-policy.json",
                    private_suite_root=root / "private-suite",
                    lock_output=root / "lock.json",
                    receipt_output=root / "receipt.json",
                    recorded_on="2026-07-26",
                    run_state_root=run_state,
                )

    def test_local_v5_novelty_is_recomputed_and_fails_closed(self) -> None:
        def skill(prefix: str, index: int, *, long: bool = False) -> bytes:
            tokens = [
                f"{prefix}{index}a",
                f"{prefix}{index}b",
                f"{prefix}{index}c",
                f"{prefix}{index}d",
                f"{prefix}{index}e",
            ]
            if long:
                tokens.extend(
                    f"{prefix}{index}{suffix}" for suffix in "fghijk"
                )
            return (
                "---\n"
                f"name: {prefix}-{index}\n"
                f"description: Inert {prefix} fixture {index}.\n"
                "---\n\n"
                + " ".join(tokens)
                + "\n"
            ).encode()

        candidate = {
            f"v5-{index:024x}": skill("candidate", index)
            for index in range(448)
        }
        reference = {
            f"v4-{index:024x}": skill("reference", index)
            for index in range(448)
        }
        measured = _measure_v5_novelty(candidate, reference)
        self.assertEqual(measured["candidate_unique_body_count"], 448)
        self.assertEqual(measured["exact_reference_body_overlap_count"], 0)
        _verify_v5_novelty(candidate, reference, measured)

        changed = deepcopy(measured)
        changed["maximum_observed_similarity"]["reference_case_id"] = (
            "v4-" + "f" * 24
        )
        with self.assertRaisesRegex(FreezeError, "does not match recomputation"):
            _verify_v5_novelty(candidate, reference, changed)

        overlap = dict(candidate)
        overlap["v5-" + "0" * 24] = reference["v4-" + "0" * 24]
        with self.assertRaisesRegex(FreezeError, "reuses a normalized"):
            _measure_v5_novelty(overlap, reference)

        similar_candidate = dict(candidate)
        similar_reference = dict(reference)
        similar_reference["v4-" + "0" * 24] = skill("near", 0, long=True)
        near = skill("near", 0, long=True).decode().replace("near0k", "changed")
        similar_candidate["v5-" + "0" * 24] = near.encode()
        with self.assertRaisesRegex(FreezeError, "exceeds one half"):
            _measure_v5_novelty(similar_candidate, similar_reference)

    def test_local_v6_novelty_uses_authenticated_v5_identity(self) -> None:
        def skill(prefix: str, index: int) -> bytes:
            body = " ".join(
                f"{prefix}{index}{suffix}" for suffix in "abcdefgh"
            )
            return (
                "---\n"
                f"name: {prefix}-{index}\n"
                f"description: Inert {prefix} fixture {index}.\n"
                "---\n\n"
                f"{body}\n"
            ).encode()

        candidate = {
            f"v6-{index:024x}": skill("candidate", index)
            for index in range(448)
        }
        reference = {
            f"v5-{index:024x}": skill("reference", index)
            for index in range(448)
        }
        measured = _measure_semantic_novelty(
            "local-v6.0.0",
            candidate,
            reference,
        )
        self.assertEqual(
            {
                field: measured[field]
                for field in _V6_NOVELTY_POLICY
            },
            _V6_NOVELTY_POLICY,
        )
        _verify_semantic_novelty(
            "local-v6.0.0",
            candidate,
            reference,
            measured,
        )
        changed = deepcopy(measured)
        changed["maximum_observed_similarity"]["reference_case_id"] = (
            "v5-" + "f" * 24
        )
        with self.assertRaisesRegex(FreezeError, "does not match recomputation"):
            _verify_semantic_novelty(
                "local-v6.0.0",
                candidate,
                reference,
                changed,
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

    def test_local_v5_receipt_declarations_bind_to_release_manifest(self) -> None:
        novelty = {
            **_V5_NOVELTY_POLICY,
            "candidate_unique_body_count": 448,
            "exact_reference_body_overlap_count": 0,
            "maximum_observed_similarity": {
                "candidate_case_id": "v5-" + "1" * 24,
                "reference_case_id": "v4-" + "2" * 24,
                "numerator": 0,
                "denominator": 1,
            },
        }
        authoring_contract = {
            "commit": "1" * 40,
            "path": "AUTHORING-CONTRACT.json",
            "sha256": "2" * 64,
        }
        release_manifest = {
            "authoring_contract": authoring_contract,
            "authorship": _V5_AUTHORSHIP,
            "novelty": novelty,
        }
        release_manifest_digest = (
            "sha256:"
            + hashlib.sha256(canonical_json(release_manifest)).hexdigest()
        )
        corpus_lock = {
            "release_manifest": {"sha256": release_manifest_digest},
            "worker_archive": {"sha256": "sha256:" + "3" * 64},
            "evaluator_archive": {"sha256": "sha256:" + "4" * 64},
            "public_manifest": {"sha256": "sha256:" + "5" * 64},
            "signing": {
                "principal": _V5_SIGNER_PRINCIPAL,
                "fingerprint": _V5_SIGNER_FINGERPRINT,
            },
            "freeze": {
                "commit": "6" * 40,
                "tag": "local-v5.0.0",
                "tag_object": "7" * 40,
            },
        }
        corpus_lock_raw = canonical_json(corpus_lock)
        suite = {
            "suite_digest": "sha256:" + "8" * 64,
            "candidate_policy_digest": "sha256:" + "9" * 64,
            "case_count": 448,
            "class_counts": {"benign": 336, "adversarial": 112},
            "runs_per_case": 1,
            "split": "hidden",
            "systems": ["baseline", "candidate"],
        }
        lock = {
            "corpus_lock_digest": (
                "sha256:" + hashlib.sha256(corpus_lock_raw).hexdigest()
            ),
            "worker_archive_digest": corpus_lock["worker_archive"]["sha256"],
            "evaluator_archive_digest": (
                corpus_lock["evaluator_archive"]["sha256"]
            ),
            "public_manifest_digest": corpus_lock["public_manifest"]["sha256"],
            "label_ledger_digest": "sha256:" + "a" * 64,
            **suite,
        }
        lock_raw = canonical_json(lock)
        receipt = {
            "schema": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v5",
            "release": {
                "release_manifest_digest": release_manifest_digest,
                "worker_archive_digest": lock["worker_archive_digest"],
                "evaluator_ciphertext_digest": lock["evaluator_archive_digest"],
                "principal": _V5_SIGNER_PRINCIPAL,
                "fingerprint": _V5_SIGNER_FINGERPRINT,
                "freeze_commit": corpus_lock["freeze"]["commit"],
                "freeze_tag": corpus_lock["freeze"]["tag"],
                "freeze_tag_object": corpus_lock["freeze"]["tag_object"],
                "authoring_contract": {
                    **authoring_contract,
                    "signature_status": "verified",
                },
                "authorship": _V5_AUTHORSHIP,
                "novelty": {**novelty, "verification_status": "passed"},
            },
            "evaluator": {
                "public_manifest_digest": lock["public_manifest_digest"],
                "label_ledger_digest": lock["label_ledger_digest"],
            },
            "suite": suite,
            "lock": {
                "lock_digest": (
                    "sha256:" + hashlib.sha256(lock_raw).hexdigest()
                )
            },
        }
        receipt_raw = canonical_json(receipt)

        with self.assertRaisesRegex(
            FreezeError,
            "requires its verified release manifest",
        ):
            validate_freeze_receipt_bindings(
                receipt,
                receipt_raw,
                lock,
                lock_raw,
                corpus_lock,
                corpus_lock_raw,
            )

        validate_freeze_receipt_bindings(
            receipt,
            receipt_raw,
            lock,
            lock_raw,
            corpus_lock,
            corpus_lock_raw,
            release_manifest=release_manifest,
        )

        changed_manifest = {
            **release_manifest,
            "authoring_contract": {
                **authoring_contract,
                "commit": "b" * 40,
            },
        }
        with self.assertRaisesRegex(
            FreezeError,
            "verified release manifest digest changed",
        ):
            validate_freeze_receipt_bindings(
                receipt,
                receipt_raw,
                lock,
                lock_raw,
                corpus_lock,
                corpus_lock_raw,
                release_manifest=changed_manifest,
            )

        for field, value in (
            ("authoring_contract", {**authoring_contract, "commit": "b" * 40}),
            ("authorship", {**_V5_AUTHORSHIP, "outcomes_used_for_tuning": True}),
            (
                "novelty",
                {
                    **novelty,
                    "maximum_observed_similarity": {
                        **novelty["maximum_observed_similarity"],
                        "reference_case_id": "v4-" + "c" * 24,
                    },
                },
            ),
        ):
            with self.subTest(field=field):
                changed_manifest = deepcopy(release_manifest)
                changed_manifest[field] = value
                changed_manifest_digest = (
                    "sha256:"
                    + hashlib.sha256(canonical_json(changed_manifest)).hexdigest()
                )
                changed_corpus_lock = deepcopy(corpus_lock)
                changed_corpus_lock["release_manifest"]["sha256"] = (
                    changed_manifest_digest
                )
                changed_corpus_lock_raw = canonical_json(changed_corpus_lock)
                changed_lock = deepcopy(lock)
                changed_lock["corpus_lock_digest"] = (
                    "sha256:"
                    + hashlib.sha256(changed_corpus_lock_raw).hexdigest()
                )
                changed_lock_raw = canonical_json(changed_lock)
                changed_receipt = deepcopy(receipt)
                changed_receipt["release"]["release_manifest_digest"] = (
                    changed_manifest_digest
                )
                changed_receipt["lock"]["lock_digest"] = (
                    "sha256:" + hashlib.sha256(changed_lock_raw).hexdigest()
                )
                with self.assertRaisesRegex(
                    FreezeError,
                    "do not match the verified release manifest",
                ):
                    validate_freeze_receipt_bindings(
                        changed_receipt,
                        canonical_json(changed_receipt),
                        changed_lock,
                        changed_lock_raw,
                        changed_corpus_lock,
                        changed_corpus_lock_raw,
                        release_manifest=changed_manifest,
                    )

    def test_local_v6_receipt_binds_leakage_and_reference_declarations(
        self,
    ) -> None:
        novelty = {
            **_V6_NOVELTY_POLICY,
            "candidate_unique_body_count": 448,
            "exact_reference_body_overlap_count": 0,
            "maximum_observed_similarity": {
                "candidate_case_id": "v6-" + "1" * 24,
                "reference_case_id": "v5-" + "2" * 24,
                "numerator": 4,
                "denominator": 98,
            },
        }
        authoring_contract = {
            "commit": _V6_SIGNED_CHAIN["authoring_contract_commit"],
            "path": "AUTHORING-CONTRACT.json",
            "sha256": _V6_SIGNED_CHAIN["authoring_contract_sha256"],
        }
        author_output = _V6_AUTHORING_CONTRACT["author_output"]
        author_output_digests = {
            **author_output["files"],
            "case_tree_sha256": author_output["case_tree_sha256"],
            "snapshot_sha256": author_output["snapshot_sha256"],
        }
        reference_release = {
            "corpus_id": "local-v5.0.0",
            "lock_sha256": _V6_NOVELTY_POLICY[
                "reference_corpus_lock_digest"
            ],
            "manifest_sha256": (
                "sha256:"
                "be9f50ad5d47c9ada8100ef2dc008d36b57d349e5fe288aa33cd00c57af9bb6a"
            ),
            "worker_sha256": _V6_NOVELTY_POLICY[
                "reference_worker_archive_digest"
            ],
        }
        release_manifest = {
            "authoring_contract": authoring_contract,
            "authorship": _V6_AUTHORSHIP,
            "novelty": novelty,
            "author_output_digests": author_output_digests,
            "reference_release": reference_release,
            "worker_visible_leakage": _V6_WORKER_VISIBLE_LEAKAGE,
        }
        release_digest = "sha256:" + hashlib.sha256(
            canonical_json(release_manifest)
        ).hexdigest()
        corpus_lock = {
            "release_manifest": {"sha256": release_digest},
            "worker_archive": {"sha256": "sha256:" + "3" * 64},
            "evaluator_archive": {"sha256": "sha256:" + "4" * 64},
            "public_manifest": {"sha256": "sha256:" + "5" * 64},
            "signing": {
                "principal": _V6_SIGNER_PRINCIPAL,
                "fingerprint": _V6_SIGNER_FINGERPRINT,
            },
            "freeze": {
                "commit": _V6_SIGNED_CHAIN["freeze_commit"],
                "tag": _V6_SIGNED_CHAIN["freeze_tag"],
                "tag_object": _V6_SIGNED_CHAIN["freeze_tag_object"],
            },
        }
        corpus_lock_raw = canonical_json(corpus_lock)
        suite = {
            "suite_digest": "sha256:" + "8" * 64,
            "candidate_policy_digest": "sha256:" + "9" * 64,
            "case_count": 448,
            "class_counts": {"benign": 336, "adversarial": 112},
            "runs_per_case": 1,
            "split": "hidden",
            "systems": ["baseline", "candidate"],
        }
        lock = {
            "corpus_lock_digest": (
                "sha256:" + hashlib.sha256(corpus_lock_raw).hexdigest()
            ),
            "worker_archive_digest": corpus_lock["worker_archive"]["sha256"],
            "evaluator_archive_digest": corpus_lock["evaluator_archive"]["sha256"],
            "public_manifest_digest": corpus_lock["public_manifest"]["sha256"],
            "label_ledger_digest": "sha256:" + "a" * 64,
            **suite,
        }
        lock_raw = canonical_json(lock)
        receipt = {
            "schema": "aragorn/benchmark-phase0-hidden-suite-freeze-receipt/v6",
            "release": {
                "release_manifest_digest": release_digest,
                "worker_archive_digest": lock["worker_archive_digest"],
                "evaluator_ciphertext_digest": lock["evaluator_archive_digest"],
                "principal": _V6_SIGNER_PRINCIPAL,
                "fingerprint": _V6_SIGNER_FINGERPRINT,
                "freeze_commit": corpus_lock["freeze"]["commit"],
                "freeze_tag": corpus_lock["freeze"]["tag"],
                "freeze_tag_object": corpus_lock["freeze"]["tag_object"],
                "authoring_contract": {
                    **authoring_contract,
                    "signature_status": "verified",
                },
                "authorship": _V6_AUTHORSHIP,
                "novelty": {**novelty, "verification_status": "passed"},
                "author_output_digests": author_output_digests,
                "reference_release": reference_release,
                "worker_visible_leakage": {
                    **_V6_WORKER_VISIBLE_LEAKAGE,
                    "verification_status": "passed",
                },
            },
            "evaluator": {
                "public_manifest_digest": lock["public_manifest_digest"],
                "label_ledger_digest": lock["label_ledger_digest"],
            },
            "suite": suite,
            "lock": {
                "lock_digest": (
                    "sha256:" + hashlib.sha256(lock_raw).hexdigest()
                )
            },
        }
        validate_freeze_receipt_bindings(
            receipt,
            canonical_json(receipt),
            lock,
            lock_raw,
            corpus_lock,
            corpus_lock_raw,
            release_manifest=release_manifest,
        )
        changed = deepcopy(receipt)
        changed["release"]["worker_visible_leakage"][
            "frontmatter_domain_labels"
        ] = 1
        with self.assertRaisesRegex(FreezeError, "v6 receipt declarations"):
            validate_freeze_receipt_bindings(
                changed,
                canonical_json(changed),
                lock,
                lock_raw,
                corpus_lock,
                corpus_lock_raw,
                release_manifest=release_manifest,
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
