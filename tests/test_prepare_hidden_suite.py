from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts.prepare_hidden_suite import (
    _CORPUS_LOCK_PATH,
    _FREEZE_COMMIT,
    _FREEZE_TREE,
    _SIGNER_FINGERPRINT,
    _SIGNER_PRINCIPAL,
    _V1_GATE,
    _V2_GATE,
    _V3_GATE,
    _V4_GATE,
    _V5_GATE,
    _V6_GATE,
    PreparationError,
    _committed_document,
    _preflight_suite,
    _receipt,
    _state_paths,
    _verified_release_manifest,
    _verified_repository,
    prepare,
    validate_preparation_receipt_bindings,
    validate_retained_preparation_receipt,
)


class HiddenPreparationReceiptTests(unittest.TestCase):
    def test_gate_selects_its_corpus_lock_without_changing_retained_profiles(
        self,
    ) -> None:
        retained_path = Path("benchmark/phase0-corpus.lock.json")
        self.assertEqual(_V1_GATE.corpus_lock_path, retained_path)
        self.assertEqual(_V2_GATE.corpus_lock_path, retained_path)
        self.assertEqual(
            _V3_GATE.corpus_lock_path,
            Path("benchmark/phase0-corpus-v3.lock.json"),
        )
        self.assertEqual(
            _V4_GATE.corpus_lock_path,
            Path("benchmark/phase0-corpus-v4.lock.json"),
        )
        self.assertEqual(
            _V5_GATE.corpus_lock_path,
            Path("benchmark/phase0-corpus-v5.lock.json"),
        )
        self.assertEqual(
            _V6_GATE.corpus_lock_path,
            Path("benchmark/phase0-corpus-v6.lock.json"),
        )
        self.assertEqual(_CORPUS_LOCK_PATH, retained_path)

        digest = "sha256:" + "1" * 64
        cases = {
            f"case-{index:03d}": {"tree_digest": digest}
            for index in range(448)
        }
        loaded = {
            "digest": _V2_GATE.suite_digest,
            "runs_per_case": 1,
            "cases": cases,
            "systems": {
                "candidate": {
                    "name": "aragorn",
                    "version": "test",
                    "implementation_digest": digest,
                    "config_digest": digest,
                }
            },
            "manifests": {case_id: {"case_id": case_id} for case_id in cases},
        }
        synthetic = replace(
            _V2_GATE,
            corpus_lock_path=Path("benchmark/phase0-corpus-v3.lock.json"),
        )
        with (
            patch(
                "scripts.prepare_hidden_suite.load_suite_for_run",
                return_value=loaded,
            ),
            patch(
                "scripts.prepare_hidden_suite._validate_phase0_hidden_binding"
            ) as validate,
        ):
            _preflight_suite(
                Path("/private/phase0-v3/private-suite.json"),
                {"label_ledger_digest": digest},
                synthetic,
            )
        self.assertEqual(
            validate.call_args.kwargs["corpus_lock_path"],
            ROOT / synthetic.corpus_lock_path,
        )

    def test_v3_gate_binds_fresh_hidden_freeze(self) -> None:
        self.assertEqual(
            _V3_GATE.freeze_commit,
            "4210a5b4305a558016ec7ee6520e13e99f38d576",
        )
        self.assertEqual(
            _V3_GATE.freeze_tree,
            "ab7294a2d096306567a2939065aa68d4fa524bdc",
        )
        self.assertEqual(
            _V3_GATE.lock_digest,
            "sha256:68ed78218e3efe41b2cdef1c0873472b52093a42b4001f9b6a60d860476b9def",
        )
        self.assertEqual(
            _V3_GATE.freeze_receipt_digest,
            "sha256:b6aadf115dd6542cd6d2e0a8005151017efe402bc801db17ffe3bb360080c56b",
        )
        self.assertEqual(
            _V3_GATE.suite_digest,
            "sha256:75bb5723bbc4973f94f5bea7d54eee76025da57cce806e0aef11740ec83305af",
        )
        self.assertEqual(
            _V3_GATE.candidate_policy_digest,
            "sha256:817bc01e97437c2d5a38971c5164dae28570a4d492b78816165ff97d0358ff73",
        )
        self.assertEqual(
            _V3_GATE.state_binding_digest,
            "sha256:e29cd500844122f1c9c4213f1653ca2928bcc49fa1cb2f7ed06005d240ae75ba",
        )
        self.assertEqual(
            _state_paths(
                Path(
                    "/Users/yousi/Documents/Codex/2026-07-25/"
                    "aragorn-phase0-hidden-v3-control/run-state"
                ),
                _V3_GATE,
            )["outcomes"],
            Path(
                "/Users/yousi/Documents/Codex/2026-07-25/"
                "aragorn-phase0-hidden-v3-control/run-state/outcomes.jsonl"
            ),
        )
        self.assertFalse(_V3_GATE.calibration_only)

    def test_v4_gate_binds_local_hidden_freeze(self) -> None:
        self.assertEqual(
            _V4_GATE.freeze_commit,
            "f348b9f16c0e69ebc293b1c043803fc645f452f1",
        )
        self.assertEqual(
            _V4_GATE.freeze_tree,
            "ecf8f360a48055bd4b54af7727fd01a28cd970f5",
        )
        self.assertEqual(
            _V4_GATE.lock_digest,
            "sha256:df5d79e7eac04ceef4d181abfc37f2ed2a11c20266cc74297cea35b7486df587",
        )
        self.assertEqual(
            _V4_GATE.freeze_receipt_digest,
            "sha256:64780dbf3364cc5c3ed94047a4d0f9dff6ee6bf43d1a89b52cc25fe3632c780c",
        )
        self.assertEqual(
            _V4_GATE.suite_digest,
            "sha256:797ded20e3c9b9082e9ea53dd13cbfef463dfe6d7adf8ea88b6698bd34861072",
        )
        self.assertEqual(
            _V4_GATE.candidate_policy_digest,
            "sha256:c9e5e3b1092a427662306608bd1a15de00a306ea30e4e9bab91ce9fb8c3d929c",
        )
        self.assertEqual(
            _V4_GATE.state_binding_digest,
            "sha256:4a590e6577e73def9ff27cb6cdb69a8309afff3a50e44a189abb77a8eacbffba",
        )
        self.assertEqual(
            _state_paths(
                Path(
                    "/Users/yousi/Documents/Codex/2026-07-26/"
                    "aragorn-phase0-hidden-v4-control/run-state"
                ),
                _V4_GATE,
            )["outcomes"],
            Path(
                "/Users/yousi/Documents/Codex/2026-07-26/"
                "aragorn-phase0-hidden-v4-control/run-state/outcomes.jsonl"
            ),
        )
        self.assertEqual(
            _V4_GATE.trust_domain,
            "phase0.hidden-local-v4.0.0",
        )
        self.assertFalse(_V4_GATE.calibration_only)

    def test_v5_gate_binds_fresh_local_hidden_freeze(self) -> None:
        self.assertEqual(
            _V5_GATE.freeze_commit,
            "89ac883edd2c8617d310d90f468c502b8c864ff6",
        )
        self.assertEqual(
            _V5_GATE.freeze_tree,
            "e03e83005e56079cd40d106a41367d978405810d",
        )
        self.assertEqual(
            _V5_GATE.lock_digest,
            "sha256:d96bdbfdd1a8884cbc4dd0293ade0f04708f42627f7f336fb744661b8adbc0c6",
        )
        self.assertEqual(
            _V5_GATE.freeze_receipt_digest,
            "sha256:37a3d49ff1cb451fcc4db34fba55f83f07e3f1bdfea6467fffe60d3567646b4c",
        )
        self.assertEqual(
            _V5_GATE.suite_digest,
            "sha256:2d00bf1e1572d1b7871fab301903e9f695023f125fcaea8e22f537400f9616b7",
        )
        self.assertEqual(
            _V5_GATE.candidate_policy_digest,
            "sha256:59120d59856c30fd803421cd5960f5c9a779f62c7903ee52731d9c4027749aa9",
        )
        self.assertEqual(
            _V5_GATE.state_binding_digest,
            "sha256:0de77709907f1ee4aa332802e4da588c5e3a39e90908c7d5a7d43bf677d9a28f",
        )
        self.assertEqual(
            _state_paths(
                Path(
                    "/Users/yousi/Documents/Codex/2026-07-26/"
                    "aragorn-phase0-v5-evaluation-20260726/hidden-run-state"
                ),
                _V5_GATE,
            )["outcomes"],
            Path(
                "/Users/yousi/Documents/Codex/2026-07-26/"
                "aragorn-phase0-v5-evaluation-20260726/"
                "hidden-run-state/outcomes.jsonl"
            ),
        )
        self.assertEqual(
            _V5_GATE.trust_domain,
            "phase0.hidden-local-v5.0.0",
        )
        self.assertEqual(
            _V5_GATE.preparation_receipt_path,
            Path(
                "benchmark/receipts/"
                "phase0-hidden-v5-preparation-2026-07-26.json"
            ),
        )
        self.assertEqual(
            _V5_GATE.receipt_schema,
            "aragorn/benchmark-phase0-hidden-preparation-receipt/v5",
        )
        self.assertEqual(
            _V5_GATE.run_receipt_schema,
            "aragorn/benchmark-phase0-hidden-worker-run-receipt/v5",
        )
        self.assertEqual(
            _V5_GATE.release_manifest_digest,
            "sha256:be9f50ad5d47c9ada8100ef2dc008d36b57d349e5fe288aa33cd00c57af9bb6a",
        )
        self.assertFalse(_V5_GATE.calibration_only)

    def test_v6_gate_binds_frozen_candidate_and_state(self) -> None:
        self.assertEqual(
            (
                _V6_GATE.freeze_commit,
                _V6_GATE.freeze_tree,
                _V6_GATE.lock_digest,
                _V6_GATE.freeze_receipt_digest,
                _V6_GATE.suite_digest,
                _V6_GATE.candidate_policy_digest,
                _V6_GATE.state_binding_digest,
            ),
            (
                "1ad2b5fd6cba7fb140382596974bf0c72dd6babe",
                "955d2c431b7897254f1a3a6de9b78bc1a5ec38bd",
                "sha256:a862f355c21b3ce4e3d996b8cfd155856fa47a66a7e03f37a728e1aec3a99997",
                "sha256:d0bcb58ea1286e92a519081e31d34ef4062ee0cf6df9449a8f9a37f2fc6dbeb4",
                "sha256:d1bf6f3a8ce547a94e5e4135a486eee17b2e310d1467e0df9e7ad58e99a8db3f",
                "sha256:87fcad8e27c6e9c4e2dc68212b1c630211ea8eefa4501d534c327afe398c3175",
                "sha256:5e477520e56b346b22041862e1936fa0fb11fcd0a19b9d61e86226f5ec71d82f",
            ),
        )
        self.assertEqual(
            _state_paths(
                Path(
                    "/Users/yousi/Documents/Codex/2026-07-26/"
                    "aragorn-phase0-v6-evaluation-20260726/run-state-v6"
                ),
                _V6_GATE,
            )["outcomes"],
            Path(
                "/Users/yousi/Documents/Codex/2026-07-26/"
                "aragorn-phase0-v6-evaluation-20260726/"
                "run-state-v6/outcomes.jsonl"
            ),
        )
        self.assertEqual(
            _V6_GATE.release_manifest_digest,
            "sha256:710352b1ef15c1cf0b184bec46e90d4b07efae1a77f5989a98d7d0010e036a9f",
        )
        self.assertEqual(_V6_GATE.trust_domain, "phase0.hidden-local-v6.0.0")
        self.assertFalse(_V6_GATE.calibration_only)

    def test_v5_release_manifest_input_is_exact_and_fail_closed(self) -> None:
        manifest = {"schema": "example/release-manifest/v1"}
        raw = canonical_json(manifest)
        digest = canonical_digest(manifest)
        gate = replace(_V5_GATE, release_manifest_digest=digest)
        corpus_lock = {"release_manifest": {"sha256": digest}}
        freeze_receipt = {
            "release": {"release_manifest_digest": digest},
        }
        with (
            tempfile.TemporaryDirectory(dir=ROOT) as temporary,
            patch.dict(
                "scripts.prepare_hidden_suite._GATES",
                {gate.name: gate},
            ),
        ):
            path = Path(temporary) / "release-manifest.json"
            path.write_bytes(raw)
            self.assertEqual(
                _verified_release_manifest(
                    path,
                    corpus_lock,
                    freeze_receipt,
                    gate,
                ),
                manifest,
            )
            with self.assertRaisesRegex(PreparationError, "requires"):
                _verified_release_manifest(
                    None,
                    corpus_lock,
                    freeze_receipt,
                    gate,
                )
            changed_lock = deepcopy(corpus_lock)
            changed_lock["release_manifest"]["sha256"] = "sha256:" + "1" * 64
            with self.assertRaisesRegex(PreparationError, "binding changed"):
                _verified_release_manifest(
                    path,
                    changed_lock,
                    freeze_receipt,
                    gate,
                )
            noncanonical = b'{\n  "schema": "example/release-manifest/v1"\n}\n'
            path.write_bytes(noncanonical)
            noncanonical_digest = (
                "sha256:" + hashlib.sha256(noncanonical).hexdigest()
            )
            noncanonical_gate = replace(
                gate,
                release_manifest_digest=noncanonical_digest,
            )
            noncanonical_lock = {
                "release_manifest": {"sha256": noncanonical_digest},
            }
            noncanonical_receipt = {
                "release": {
                    "release_manifest_digest": noncanonical_digest,
                },
            }
            with (
                patch.dict(
                    "scripts.prepare_hidden_suite._GATES",
                    {noncanonical_gate.name: noncanonical_gate},
                ),
                self.assertRaisesRegex(PreparationError, "binding changed"),
            ):
                _verified_release_manifest(
                    path,
                    noncanonical_lock,
                    noncanonical_receipt,
                    noncanonical_gate,
                )

        with self.assertRaisesRegex(PreparationError, "only valid"):
            _verified_release_manifest(
                Path("/tmp/release-manifest.json"),
                {},
                {},
                _V4_GATE,
            )

    def test_v5_preparation_passes_verified_manifest_to_freeze_binding(
        self,
    ) -> None:
        lock = {"schema": "example/hidden-lock/v1"}
        freeze_receipt = {"schema": "example/freeze-receipt/v1"}
        corpus_lock = {"schema": "example/corpus-lock/v1"}
        manifest = {"schema": "example/release-manifest/v1"}
        manifest_path = Path("/public/release-manifest.json")
        with (
            patch(
                "scripts.prepare_hidden_suite._require_preparation_paths",
                return_value={},
            ),
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={},
            ),
            patch(
                "scripts.prepare_hidden_suite._committed_bytes",
                side_effect=[b"lock", b"freeze"],
            ),
            patch(
                "scripts.prepare_hidden_suite._read",
                return_value=b"corpus",
            ),
            patch(
                "scripts.prepare_hidden_suite._decode_json",
                side_effect=[lock, freeze_receipt, corpus_lock],
            ),
            patch(
                "scripts.prepare_hidden_suite._verified_release_manifest",
                return_value=manifest,
            ) as verified_manifest,
            patch(
                "scripts.prepare_hidden_suite.validate_freeze_receipt_bindings"
            ) as validate_freeze,
            patch(
                "scripts.prepare_hidden_suite._preflight_suite",
                side_effect=PreparationError("stop after freeze binding"),
            ),
            self.assertRaisesRegex(PreparationError, "stop after"),
        ):
            prepare(
                private_suite_path=Path("/private/suite.json"),
                run_state_root=Path("/private/run-state"),
                verifier_root=Path("/private/verifier"),
                worker_trust_record=Path("/private/worker.json"),
                receipt_output=ROOT / _V5_GATE.preparation_receipt_path,
                release_manifest_path=manifest_path,
                recorded_on=_V5_GATE.recorded_on,
                gate=_V5_GATE,
            )
        verified_manifest.assert_called_once_with(
            manifest_path,
            corpus_lock,
            freeze_receipt,
            _V5_GATE,
        )
        validate_freeze.assert_called_once_with(
            freeze_receipt,
            b"freeze",
            lock,
            b"lock",
            corpus_lock,
            b"corpus",
            release_manifest=manifest,
        )

    def test_preparation_commit_must_strictly_follow_freeze(self) -> None:
        with (
            patch(
                "scripts.prepare_hidden_suite._git",
                side_effect=[
                    f"{ROOT}\n".encode(),
                    b"sha1\n",
                    b"",
                    f"{_V2_GATE.freeze_commit}\n".encode(),
                ],
            ),
            self.assertRaisesRegex(PreparationError, "strictly follow"),
        ):
            _verified_repository(_V2_GATE)

    def test_calibration_v2_receipt_is_bound_and_not_a_holdout(self) -> None:
        hidden_lock = json.loads(
            (
                ROOT / "benchmark" / "phase0-hidden-suite-calibration-v2.lock.json"
            ).read_bytes()
        )
        freeze_receipt = json.loads(
            (
                ROOT
                / "benchmark"
                / "receipts"
                / "phase0-hidden-suite-calibration-v2-freeze-2026-07-25.json"
            ).read_bytes()
        )
        systems = [
            system for system in hidden_lock["systems"] if system["name"] != "aragorn"
        ]
        digest = "sha256:" + "1" * 64
        commits = {
            "freeze": {
                "commit": _V2_GATE.freeze_commit,
                "tree": _V2_GATE.freeze_tree,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
            "preparation": {
                "commit": "2" * 40,
                "tree": "3" * 40,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
        }
        preparation = {
            "schema": "aragorn/benchmark-prepare-result/v2",
            "suite_digest": hidden_lock["suite_digest"],
            "dispatch_digest": digest,
            "candidate_policy_digest": hidden_lock["candidate_policy_digest"],
            "worker_identities_digest": canonical_digest(
                {
                    "schema": "aragorn/benchmark-system-identities/v1",
                    "systems": systems,
                }
            ),
            "worklist_digest": digest,
            "job_count": 896,
        }
        matrix = {
            "case_count": 448,
            "comparator_count": 2,
            "runs_per_case": 1,
            "job_count": 896,
            "worklist_count": 896,
            "issuance_count": 896,
            "acceptance_count": 0,
            "systems": systems,
        }
        receipt = _receipt(
            recorded_on=_V2_GATE.recorded_on,
            commits=commits,
            trust_store_digest=digest,
            key_id=digest,
            result=preparation,
            matrix=matrix,
            gate=_V2_GATE,
        )
        validate_preparation_receipt_bindings(
            receipt,
            canonical_json(receipt),
            hidden_lock,
            freeze_receipt,
            verified_preparation=commits["preparation"],
            gate=_V2_GATE,
        )
        self.assertEqual(
            receipt["limitations"]["evaluation_status"],
            "calibration_rerun_on_previously_evaluated_corpus_not_fresh_holdout",
        )
        with self.assertRaisesRegex(PreparationError, "contract changed"):
            validate_preparation_receipt_bindings(
                receipt,
                canonical_json(receipt),
                hidden_lock,
                freeze_receipt,
                verified_preparation=commits["preparation"],
            )
        with self.assertRaisesRegex(PreparationError, "registered profile"):
            _receipt(
                recorded_on=_V2_GATE.recorded_on,
                commits=commits,
                trust_store_digest=digest,
                key_id=digest,
                result=preparation,
                matrix=matrix,
                gate=replace(_V2_GATE, calibration_only=False),
            )
        _state_paths(
            Path("/private/tmp/aragorn-phase0-v2-calibration-run"),
            _V2_GATE,
        )
        with self.assertRaisesRegex(PreparationError, "path binding"):
            _state_paths(Path("/private/tmp/wrong-run-root"), _V2_GATE)

        for path, value in (
            (("assurance",), "independent"),
            (("state", "operator_uid_protected"), False),
            (("matrix", "comparator_count"), 1),
            (("worker_surface", "forbidden_evaluator_metadata_absent"), False),
            (("limitations", "evaluation_status"), "fresh_holdout"),
        ):
            changed = deepcopy(receipt)
            target = changed
            for field in path[:-1]:
                target = target[field]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaisesRegex(
                PreparationError,
                "contract changed",
            ):
                validate_preparation_receipt_bindings(
                    changed,
                    canonical_json(changed),
                    hidden_lock,
                    freeze_receipt,
                    verified_preparation=commits["preparation"],
                    gate=_V2_GATE,
                )

    def test_signed_policy_loader_accepts_formatted_json(self) -> None:
        with patch(
            "scripts.prepare_hidden_suite._committed_bytes",
            return_value=b'{\n  "schema": "example/v1"\n}\n',
        ):
            self.assertEqual(
                _committed_document("2" * 40, Path("policy.json"), "policy"),
                {"schema": "example/v1"},
            )

    def test_receipt_rejects_matrix_substitution(self) -> None:
        hidden_lock = json.loads(
            (ROOT / "benchmark" / "phase0-hidden-suite.lock.json").read_bytes()
        )
        freeze_receipt = json.loads(
            (
                ROOT
                / "benchmark"
                / "receipts"
                / "phase0-hidden-suite-freeze-2026-07-24.json"
            ).read_bytes()
        )
        digest = "sha256:" + "1" * 64
        commits = {
            "freeze": {
                "commit": _FREEZE_COMMIT,
                "tree": _FREEZE_TREE,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
            "preparation": {
                "commit": "2" * 40,
                "tree": "3" * 40,
                "signature_status": "verified",
                "principal": _SIGNER_PRINCIPAL,
                "fingerprint": _SIGNER_FINGERPRINT,
            },
        }
        systems = [
            system for system in hidden_lock["systems"] if system["name"] != "aragorn"
        ]
        preparation = {
            "schema": "aragorn/benchmark-prepare-result/v2",
            "suite_digest": hidden_lock["suite_digest"],
            "dispatch_digest": digest,
            "candidate_policy_digest": hidden_lock["candidate_policy_digest"],
            "worker_identities_digest": canonical_digest(
                {
                    "schema": "aragorn/benchmark-system-identities/v1",
                    "systems": systems,
                }
            ),
            "worklist_digest": digest,
            "job_count": 896,
        }
        matrix = {
            "case_count": 448,
            "comparator_count": 2,
            "runs_per_case": 1,
            "job_count": 896,
            "worklist_count": 896,
            "issuance_count": 896,
            "acceptance_count": 0,
            "systems": systems,
        }
        receipt = _receipt(
            recorded_on="2026-07-24",
            commits=commits,
            trust_store_digest=digest,
            key_id=digest,
            result=preparation,
            matrix=matrix,
        )
        validate_preparation_receipt_bindings(
            receipt,
            canonical_json(receipt),
            hidden_lock,
            freeze_receipt,
            verified_preparation=commits["preparation"],
        )

        changed = deepcopy(receipt)
        changed["preparation"]["worker_identities_digest"] = "sha256:" + "4" * 64
        changed["preparation_result_digest"] = canonical_digest(changed["preparation"])
        with self.assertRaisesRegex(
            PreparationError,
            "matrix accounting changed",
        ):
            validate_preparation_receipt_bindings(
                changed,
                canonical_json(changed),
                hidden_lock,
                freeze_receipt,
                verified_preparation=commits["preparation"],
            )

        changed = deepcopy(receipt)
        changed["source"]["preparation_tree"] = "4" * 40
        with self.assertRaisesRegex(PreparationError, "signed source changed"):
            validate_preparation_receipt_bindings(
                changed,
                canonical_json(changed),
                hidden_lock,
                freeze_receipt,
                verified_preparation=commits["preparation"],
            )

    def test_retained_receipt_requires_preparation_before_retention(self) -> None:
        claimed_commit = "2" * 40
        retained_commit = "4" * 40
        receipt = {"source": {"preparation_commit": claimed_commit}}

        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": claimed_commit}},
            ),
            self.assertRaisesRegex(PreparationError, "strictly follow"),
        ):
            validate_retained_preparation_receipt(receipt, b"", {}, {})

        freeze_receipt = {"source": {"preparation_commit": _FREEZE_COMMIT}}
        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": retained_commit}},
            ),
            self.assertRaisesRegex(PreparationError, "strictly follow the freeze"),
        ):
            validate_retained_preparation_receipt(freeze_receipt, b"", {}, {})

        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": retained_commit}},
            ),
            patch(
                "scripts.prepare_hidden_suite._verified_commit",
                return_value={"commit": claimed_commit},
            ),
            patch(
                "scripts.prepare_hidden_suite._git",
                side_effect=[b"", b"", b""],
            ),
            self.assertRaisesRegex(PreparationError, "lacks the regular"),
        ):
            validate_retained_preparation_receipt(receipt, b"", {}, {})

        with (
            patch(
                "scripts.prepare_hidden_suite._verified_repository",
                return_value={"preparation": {"commit": retained_commit}},
            ),
            patch(
                "scripts.prepare_hidden_suite._verified_commit",
                return_value={"commit": claimed_commit},
            ),
            patch(
                "scripts.prepare_hidden_suite._git",
                side_effect=[
                    b"",
                    b"",
                    b"100644 blob "
                    + b"5" * 40
                    + b"\tscripts/prepare_hidden_suite.py\0",
                    b"benchmark/receipts/receipt.json\0",
                ],
            ),
            self.assertRaisesRegex(PreparationError, "already exists"),
        ):
            validate_retained_preparation_receipt(receipt, b"", {}, {})


if __name__ == "__main__":
    unittest.main()
