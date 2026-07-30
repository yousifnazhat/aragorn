from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

import aragorn.github_recursive_artifact_graph_v6 as recursive_artifact_graph_v6
from aragorn.cas import CAS
from aragorn.github_gateway import QUARANTINE_AUTHORITY
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase0_candidate import candidate_implementation_digest
from aragorn.protected_install_coordinator import (
    ASSURANCE,
    INTENT_SCHEMA,
    ProtectedInstallCoordinatorError,
    _atomic_publish,
    _derive_release_pins,
    _load_release_asset_pins,
    _recursive_artifact_graph_verifier_digest,
    _release_analyzer_script,
    _run_submitted,
    _start_fixed_service,
    _submission_error,
    _submission_result_path,
    _validate_coordinator_result,
    _verify_recursive_gateway_receipt,
    _wait_for_submission_result,
    coordinate_intent,
    submit_intent,
)

_ROOT = Path(__file__).resolve().parents[1]
_SERVICE = (
    _ROOT
    / "packaging"
    / "systemd"
    / "aragorn-protected-install-coordinator-evidence.service"
)
_PATH_UNIT = (
    _ROOT
    / "packaging"
    / "systemd"
    / "aragorn-protected-install-coordinator-evidence.path"
)
_ENTRYPOINT = (
    _ROOT
    / "packaging"
    / "libexec"
    / "aragorn-protected-install-coordinator.py"
)
_PRODUCTION_SERVICE = (
    _ROOT
    / "packaging"
    / "systemd"
    / "aragorn-protected-install-coordinator.service"
)
_PRODUCTION_PATH_UNIT = (
    _ROOT
    / "packaging"
    / "systemd"
    / "aragorn-protected-install-coordinator.path"
)


def _load_entrypoint():
    spec = importlib.util.spec_from_file_location(
        "_aragorn_coordinator_entrypoint_test",
        _ENTRYPOINT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load coordinator entrypoint")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _success_result() -> dict[str, object]:
    return {
        "schema": "aragorn/protected-install-coordinator-result/v1",
        "assurance": "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        "operation": "install",
        "source_request": {
            "schema": "aragorn/github-gateway-request/v1",
            "owner": "example",
            "repository": "skills",
            "commit": "1" * 40,
            "skill_path": "sample",
        },
        "manifest_digest": _digest("1"),
        "quarantine_receipt_digest": _digest("2"),
        "gateway_profile_digest": _digest("3"),
        "context_id": _digest("4"),
        "service_request_digest": _digest("5"),
        "installer_work_eligible": False,
        "runtime_conformance_qualified": False,
        "quarantine_authority": QUARANTINE_AUTHORITY,
        "status": "COMPLETED_NOT_INSTALLER_AUTHORITY",
    }


class ProtectedInstallCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory(dir=_ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.uid = os.geteuid()
        self.gateway = self._directory("gateway")
        self.quarantine = self._directory("quarantine")
        self.control = self._directory("control")
        self.protected_parent = self._directory("protected")
        self.protected = self._directory("protected/skills")
        self.request = self.control / "request.json"
        self.state = self.protected_parent / "coordinator-state.json"
        self.receipts: dict[str, dict[str, object]] = {}
        self.service_requests: list[dict[str, object]] = []

    def _directory(self, relative: str) -> Path:
        path = self.root / relative
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
        return path

    def _intent(self, operation: str, commit: str) -> Path:
        path = self.control / f"{operation}-{commit[:8]}.json"
        path.write_bytes(
            canonical_json(
                {
                    "schema": INTENT_SCHEMA,
                    "operation": operation,
                    "owner": "example",
                    "repository": "skills",
                    "commit": commit,
                    "skill_path": "sample",
                }
            )
        )
        path.chmod(0o400)
        return path

    def _pins(self) -> dict[str, str]:
        return {
            "expected_producer_implementation_digest": _digest("1"),
            "expected_analyzer_implementation_digest": _digest("2"),
            "expected_analyzer_executable_digest": _digest("3"),
            "expected_analyzer_configuration_digest": _digest("4"),
            "expected_policy_digest": _digest("5"),
            "expected_analyzer_verifier_digest": _digest("6"),
            "expected_artifact_graph_verifier_digest": _digest("7"),
        }

    def _gateway_result(self, source_request, **kwargs):
        self.assertIsNone(kwargs["release_asset_pins"])
        quarantine = Path(kwargs["quarantine_state"])
        CAS(quarantine)
        suffix = source_request["commit"][0]
        receipt_digest = _digest("a" if suffix == "1" else "b")
        manifest_digest = _digest("c" if suffix == "1" else "d")
        root_manifest_digest = _digest("0" if suffix == "1" else "1")
        tree_digest = _digest("e" if suffix == "1" else "f")
        profile_digest = _digest("8" if suffix == "1" else "9")
        self.receipts[receipt_digest] = {
            "schema": "aragorn/github-quarantine-receipt/v1",
            "authority": QUARANTINE_AUTHORITY,
            "request": source_request,
            "manifest_digest": root_manifest_digest,
            "tree_digest": tree_digest,
            "source_proof_digest": _digest("6"),
            "expanded_tree_digest": tree_digest,
        }
        return SimpleNamespace(
            request_digest="sha256:"
            + hashlib.sha256(canonical_json(source_request)).hexdigest(),
            quarantine_state=quarantine,
            quarantine_receipt_digest=receipt_digest,
            gateway_profile_digest=profile_digest,
            manifest_digest=manifest_digest,
            root_manifest_digest=root_manifest_digest,
            source_proof_digest=_digest("6"),
            expansion_digest=_digest("2" if suffix == "1" else "3"),
            expansion_proof_digest=_digest("4" if suffix == "1" else "5"),
            release_asset_result_digests=(),
            handoff_manifest_digest=_digest("7"),
            release_pin_set_digest=_digest("7" if suffix == "1" else "0"),
        )

    def _verify_receipt(
        self,
        _cas,
        receipt_digest,
        *,
        expected_manifest_digest,
        expected_gateway_profile_digest,
    ):
        document = self.receipts[receipt_digest]
        self.assertEqual(
            document["manifest_digest"],
            expected_manifest_digest,
        )
        self.assertIn(expected_gateway_profile_digest, {_digest("8"), _digest("9")})
        return document

    def _run_service(self) -> None:
        self.assertEqual(stat.S_IMODE(self.request.stat().st_mode), 0o400)
        request = json.loads(self.request.read_bytes())
        self.service_requests.append(request)
        context_id = request["context_id"]
        version_path = (
            f".aragorn-versions/aragorn-admitted/{context_id[7:]}-"
            f"{request['manifest_digest'][7:]}"
        )
        version = self.protected / version_path
        version.mkdir(mode=0o555, parents=True)
        version.chmod(0o555)
        active = self.protected / "aragorn-admitted"
        if os.path.lexists(active):
            active.unlink()
        active.symlink_to(version_path)
        claims = self.protected / ".aragorn-install-claims"
        claims.mkdir(mode=0o700, exist_ok=True)
        claim = {
            "schema": "aragorn/protected-install-transaction/v1",
            "authority": (
                "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
            ),
            "context_id": context_id,
            "context_digest": _digest("0"),
            "operation": request["operation"],
            "expected_active": (
                None
                if request["expected_active"] is None
                else {
                    "context_id": request["expected_active"]["context_id"],
                    "manifest_digest": request["expected_active"][
                        "manifest_digest"
                    ],
                }
            ),
            "manifest_digest": request["manifest_digest"],
            "tree_digest": self.receipts[
                request["quarantine_receipt_digest"]
            ]["expanded_tree_digest"],
            "destination": {
                "root_device": self.protected.stat().st_dev,
                "root_inode": self.protected.stat().st_ino,
                "target_name": "aragorn-admitted",
            },
            "version_path": version_path,
        }
        claim_path = claims / f"{context_id[7:]}.json"
        claim_path.write_bytes(canonical_json(claim))
        claim_path.chmod(0o400)

    def test_install_then_update_derives_every_trust_binding(self) -> None:
        pins = self._pins()
        release = {
            "package_root": self.root,
            "python_path": Path(os.path.realpath(os.sys.executable)),
        }
        patches = (
            mock.patch(
                "aragorn.protected_install_coordinator._derive_release_pins",
                return_value=(pins, release),
            ),
            mock.patch(
                "aragorn.protected_install_coordinator._service_identity",
                return_value=(123, 123),
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "quarantine_recursive_through_gateway",
                side_effect=self._gateway_result,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "verify_github_quarantine_receipt",
                side_effect=self._verify_receipt,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "verify_retained_release_pin_set",
                return_value={},
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "load_verified_retained_manifest",
                side_effect=lambda _cas, digest: {
                    "tree_digest": (
                        _digest("e") if digest == _digest("c") else _digest("f")
                    )
                },
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "diff_verified_manifests_between",
                return_value={
                    "schema": "aragorn/manifest-update-diff/v1",
                    "authority": (
                        "UPDATE_DIFF_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY"
                    ),
                    "old": {
                        "manifest_digest": _digest("c"),
                        "tree_digest": _digest("e"),
                    },
                    "new": {
                        "manifest_digest": _digest("d"),
                        "tree_digest": _digest("f"),
                    },
                    "added_paths": [],
                    "removed_paths": [],
                    "changed_paths": ["SKILL.md"],
                },
            ),
            mock.patch(
                "aragorn.protected_install_coordinator._start_fixed_service",
                side_effect=self._run_service,
            ),
        )
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4] as verify_pin_set,
            patches[5],
            patches[6],
            patches[7],
        ):
            installed = coordinate_intent(
                self._intent("install", "1" * 40),
                release_identity_path=self.root / "unused-identity.json",
                gateway_root=self.gateway,
                quarantine_root=self.quarantine,
                protected_root=self.protected,
                request_path=self.request,
                state_path=self.state,
                release_asset_pins_path=self.control / "absent-pins.json",
                expected_uid=self.uid,
                now_unix=100,
            )
            updated = coordinate_intent(
                self._intent("update", "2" * 40),
                release_identity_path=self.root / "unused-identity.json",
                gateway_root=self.gateway,
                quarantine_root=self.quarantine,
                protected_root=self.protected,
                request_path=self.request,
                state_path=self.state,
                release_asset_pins_path=self.control / "absent-pins.json",
                expected_uid=self.uid,
                now_unix=200,
            )

        self.assertEqual(installed["assurance"], ASSURANCE)
        self.assertFalse(installed["installer_work_eligible"])
        self.assertFalse(updated["runtime_conformance_qualified"])
        self.assertFalse(self.request.exists())
        self.assertEqual(len(self.service_requests), 2)
        first, second = self.service_requests
        self.assertEqual(first["operation"], "install")
        self.assertEqual(
            first["schema"],
            "aragorn/protected-install-broker-request/v4",
        )
        self.assertIsNone(first["expected_active"])
        self.assertIsNone(first["expected_manifest_diff_digest"])
        self.assertEqual(
            {
                field: first[field]
                for field in pins
                if field != "expected_artifact_graph_verifier_digest"
            },
            {
                field: value
                for field, value in pins.items()
                if field != "expected_artifact_graph_verifier_digest"
            },
        )
        self.assertEqual(
            first["recursive"],
            {
                "root_manifest_digest": _digest("0"),
                "expansion_digest": _digest("2"),
                "expansion_proof_digest": _digest("4"),
                "release_asset_result_digests": [],
                "release_pin_set_digest": _digest("7"),
            },
        )
        self.assertEqual(second["operation"], "update")
        self.assertEqual(
            second["expected_active"]["context_id"],
            first["context_id"],
        )
        self.assertEqual(
            second["expected_active"]["source_request"],
            first["source_request"],
        )
        self.assertEqual(
            second["expected_active"]["quarantine_receipt_digest"],
            first["quarantine_receipt_digest"],
        )
        self.assertEqual(
            second["expected_active"]["recursive"],
            first["recursive"],
        )
        self.assertNotEqual(
            second["expected_manifest_diff_digest"],
            first["expected_manifest_diff_digest"],
        )
        self.assertEqual(verify_pin_set.call_count, 5)
        state = json.loads(self.state.read_bytes())
        self.assertEqual(
            state["schema"],
            "aragorn/protected-install-coordinator-state/v3",
        )
        self.assertEqual(
            state["expected_active"]["recursive"]["release_pin_set_digest"],
            _digest("0"),
        )

    def test_automatic_pin_preflight_cannot_downgrade_to_explicit_null(
        self,
    ) -> None:
        source = {
            "schema": "aragorn/github-gateway-request/v1",
            "owner": "example",
            "repository": "skills",
            "commit": "1" * 40,
            "skill_path": "sample",
        }
        quarantine = self.quarantine / "automatic"
        receipt = self._gateway_result(
            source,
            release_asset_pins=None,
            quarantine_state=quarantine,
        )
        receipt.release_pin_set_digest = None
        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "verify_github_quarantine_receipt",
                side_effect=self._verify_receipt,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "load_verified_retained_manifest",
                return_value={"tree_digest": _digest("e")},
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "verify_retained_release_pin_set",
            ) as verify_pin_set,
        ):
            explicit = _verify_recursive_gateway_receipt(
                receipt,
                source,
                quarantine,
                require_release_pin_set=False,
            )
            self.assertIsNone(
                explicit["recursive"]["release_pin_set_digest"],
            )
            verify_pin_set.assert_not_called()
            with self.assertRaisesRegex(
                ProtectedInstallCoordinatorError,
                "mode changed",
            ):
                _verify_recursive_gateway_receipt(
                    receipt,
                    source,
                    quarantine,
                    require_release_pin_set=True,
                )

    def test_intent_cannot_supply_a_trust_pin(self) -> None:
        path = self.control / "bad-intent.json"
        path.write_bytes(
            canonical_json(
                {
                    "schema": INTENT_SCHEMA,
                    "operation": "install",
                    "owner": "example",
                    "repository": "skills",
                    "commit": "1" * 40,
                    "skill_path": "sample",
                    "release_asset_pins": {},
                }
            )
        )
        path.chmod(0o400)
        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "quarantine_recursive_through_gateway"
            ) as gateway,
            self.assertRaisesRegex(
                ProtectedInstallCoordinatorError,
                "exact high-level request",
            ),
        ):
            coordinate_intent(
                path,
                release_identity_path=self.root / "unused-identity.json",
                gateway_root=self.gateway,
                quarantine_root=self.quarantine,
                protected_root=self.protected,
                request_path=self.request,
                state_path=self.state,
                release_asset_pins_path=None,
                expected_uid=self.uid,
            )
        gateway.assert_not_called()

    def test_supported_submit_publishes_only_the_exact_high_level_intent(
        self,
    ) -> None:
        intent_path = self.control / "submitted-intent.json"
        lock_path = self.control / "submission.lock"
        observed: list[tuple[Path, str, str, str, dict]] = []

        def wait(path, submission_id, submission_digest, intent_digest, **_kwargs):
            observed.append(
                (
                    path,
                    submission_id,
                    submission_digest,
                    intent_digest,
                    json.loads(intent_path.read_bytes()),
                )
            )
            return _success_result()

        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_require_production_path"
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_wait_for_submission_result",
                side_effect=wait,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator._new_submission_id",
                return_value="a" * 64,
            ),
        ):
            result = submit_intent(
                "install",
                "example",
                "skills",
                "1" * 40,
                "sample",
                intent_path=intent_path,
                lock_path=lock_path,
                expected_uid=self.uid,
            )

        self.assertEqual(result, _success_result())
        self.assertFalse(intent_path.exists())
        self.assertEqual(len(observed), 1)
        path, submission_id, submission_digest, intent_digest, submission = observed[0]
        self.assertEqual(submission_id, "a" * 64)
        self.assertEqual(
            path,
            self.control / f"submission-result-{'a' * 64}.json",
        )
        self.assertEqual(
            submission,
            {
                "schema": "aragorn/protected-install-submission/v1",
                "submission_id": "a" * 64,
                "intent": {
                    "schema": INTENT_SCHEMA,
                    "operation": "install",
                    "owner": "example",
                    "repository": "skills",
                    "commit": "1" * 40,
                    "skill_path": "sample",
                },
            },
        )
        self.assertEqual(
            submission_digest,
            "sha256:" + hashlib.sha256(canonical_json(submission)).hexdigest(),
        )
        self.assertEqual(
            intent_digest,
            "sha256:"
            + hashlib.sha256(canonical_json(submission["intent"])).hexdigest(),
        )

    def test_supported_submit_is_root_only(self) -> None:
        with (
            mock.patch(
                "aragorn.protected_install_coordinator.os.geteuid",
                return_value=self.uid + 1,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_require_production_path"
            ) as active,
            self.assertRaisesRegex(
                ProtectedInstallCoordinatorError,
                "fixed root UID",
            ),
        ):
            submit_intent(
                "install",
                "example",
                "skills",
                "1" * 40,
                "sample",
                intent_path=self.control / "intent.json",
                lock_path=self.control / "lock",
                expected_uid=self.uid,
            )
        active.assert_not_called()

    def test_identical_retry_gets_a_distinct_result_namespace(self) -> None:
        intent_path = self.control / "intent.json"
        observed = []

        def wait(path, submission_id, *_args, **_kwargs):
            observed.append((path, submission_id))
            return _success_result()

        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_require_production_path"
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_wait_for_submission_result",
                side_effect=wait,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator._new_submission_id",
                side_effect=("a" * 64, "b" * 64),
            ),
        ):
            for _attempt in range(2):
                submit_intent(
                    "install",
                    "example",
                    "skills",
                    "1" * 40,
                    "sample",
                    intent_path=intent_path,
                    lock_path=self.control / "lock",
                    expected_uid=self.uid,
                )

        self.assertEqual(
            observed,
            [
                (
                    self.control / f"submission-result-{'a' * 64}.json",
                    "a" * 64,
                ),
                (
                    self.control / f"submission-result-{'b' * 64}.json",
                    "b" * 64,
                ),
            ],
        )

    def test_timeout_cleans_only_the_current_submission(self) -> None:
        intent_path = self.control / "intent.json"
        old_result = _submission_result_path(self.control, "a" * 64)
        old_result.write_bytes(b"old")
        old_result.chmod(0o400)
        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_require_production_path"
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_wait_for_submission_result",
                side_effect=ProtectedInstallCoordinatorError(
                    "protected install submission timed out"
                ),
            ),
            mock.patch(
                "aragorn.protected_install_coordinator._new_submission_id",
                return_value="b" * 64,
            ),
            self.assertRaisesRegex(
                ProtectedInstallCoordinatorError,
                "timed out",
            ),
        ):
            submit_intent(
                "install",
                "example",
                "skills",
                "1" * 40,
                "sample",
                intent_path=intent_path,
                lock_path=self.control / "lock",
                expected_uid=self.uid,
            )

        self.assertFalse(intent_path.exists())
        self.assertEqual(old_result.read_bytes(), b"old")

    def test_submission_result_must_match_and_is_cleaned(self) -> None:
        submission_id = "a" * 64
        path = _submission_result_path(self.control, submission_id)
        path.write_bytes(
            canonical_json(
                {
                    "schema": "aragorn/protected-install-submission-result/v1",
                    "submission_id": submission_id,
                    "submission_digest": _digest("2"),
                    "intent_digest": _digest("3"),
                    "coordinator_result": _success_result(),
                }
            )
        )
        path.chmod(0o400)
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "not correlated",
        ):
            _wait_for_submission_result(
                path,
                submission_id,
                _digest("1"),
                _digest("3"),
                expected_uid=self.uid,
                deadline=1,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
            )
        self.assertFalse(path.exists())

        path.write_bytes(
            canonical_json(
                {
                    "schema": "aragorn/protected-install-submission-result/v1",
                    "submission_id": submission_id,
                    "submission_digest": _digest("1"),
                    "intent_digest": _digest("3"),
                    "coordinator_result": {
                        **_success_result(),
                        "assurance": "forged",
                    },
                }
            )
        )
        path.chmod(0o400)
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "success result is invalid",
        ):
            _wait_for_submission_result(
                path,
                submission_id,
                _digest("1"),
                _digest("3"),
                expected_uid=self.uid,
                deadline=1,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
            )
        self.assertFalse(path.exists())

    def test_coordinator_result_shapes_are_exact(self) -> None:
        self.assertEqual(
            _validate_coordinator_result(_success_result()),
            _success_result(),
        )
        error = {
            "schema": "aragorn/protected-install-coordinator-result/v1",
            "assurance": (
                "TRUSTED_COORDINATOR_RECORD_ONLY_NOT_INSTALLER_AUTHORITY"
            ),
            "status": "ERROR",
            "error": {"type": "ValueError", "message": "blocked"},
            "installer_work_eligible": False,
            "runtime_conformance_qualified": False,
        }
        self.assertEqual(_validate_coordinator_result(error), error)
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "error result is invalid",
        ):
            _validate_coordinator_result({**error, "extra": True})
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "success result is invalid",
        ):
            _validate_coordinator_result(
                {**_success_result(), "source_request": None}
            )

    def test_submitted_service_derives_v1_and_correlates_result(self) -> None:
        submission_id = "a" * 64
        submission_path = self.control / "submission.json"
        intent = {
            "schema": INTENT_SCHEMA,
            "operation": "install",
            "owner": "example",
            "repository": "skills",
            "commit": "1" * 40,
            "skill_path": "sample",
        }
        submission = {
            "schema": "aragorn/protected-install-submission/v1",
            "submission_id": submission_id,
            "intent": intent,
        }
        submission_path.write_bytes(canonical_json(submission))
        submission_path.chmod(0o400)
        output = BytesIO()
        coordinator_result = _success_result()
        coordinator_result.pop("status")
        with (
            mock.patch(
                "aragorn.protected_install_coordinator.coordinate_intent",
                return_value=coordinator_result,
            ) as coordinate,
            mock.patch(
                "aragorn.protected_install_coordinator.sys.stdout",
                SimpleNamespace(buffer=output),
            ),
        ):
            status = _run_submitted(
                submission_path=submission_path,
                expected_uid=self.uid,
            )

        result_path = _submission_result_path(self.control, submission_id)
        envelope = json.loads(result_path.read_bytes())
        self.assertEqual(status, 0)
        self.assertFalse(submission_path.exists())
        self.assertEqual(envelope["submission_id"], submission_id)
        self.assertEqual(
            envelope["submission_digest"],
            "sha256:"
            + hashlib.sha256(canonical_json(submission)).hexdigest(),
        )
        self.assertEqual(
            envelope["intent_digest"],
            "sha256:" + hashlib.sha256(canonical_json(intent)).hexdigest(),
        )
        derived_path = coordinate.call_args.args[0]
        self.assertEqual(
            derived_path.name,
            f".coordinator-intent-{submission_id}.json",
        )
        self.assertFalse(derived_path.exists())

    def test_malformed_submitted_input_does_not_wedge_the_path(self) -> None:
        submission_path = self.control / "submission.json"
        submission_path.write_bytes(b"not-json")
        submission_path.chmod(0o400)
        output = BytesIO()
        with mock.patch(
            "aragorn.protected_install_coordinator.sys.stdout",
            SimpleNamespace(buffer=output),
        ):
            status = _run_submitted(
                submission_path=submission_path,
                expected_uid=self.uid,
            )

        self.assertEqual(status, 4)
        self.assertFalse(submission_path.exists())
        self.assertEqual(
            json.loads(output.getvalue())["status"],
            "ERROR",
        )

        submission_path.write_bytes(b"x" * (8 * 1024 + 1))
        submission_path.chmod(0o400)
        output = BytesIO()
        with mock.patch(
            "aragorn.protected_install_coordinator.sys.stdout",
            SimpleNamespace(buffer=output),
        ):
            status = _run_submitted(
                submission_path=submission_path,
                expected_uid=self.uid,
            )

        self.assertEqual(status, 4)
        self.assertFalse(submission_path.exists())

    def test_invalid_result_does_not_survive_cleanup(self) -> None:
        path = _submission_result_path(self.control, "a" * 64)
        path.write_bytes(
            canonical_json(
                {
                    "schema": "aragorn/protected-install-submission-result/v1",
                    "submission_id": "a" * 64,
                    "submission_digest": _digest("1"),
                    "intent_digest": _digest("2"),
                    "coordinator_result": {"status": "ERROR"},
                }
            )
        )
        path.chmod(0o400)
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "result is invalid",
        ):
            _wait_for_submission_result(
                path,
                "a" * 64,
                _digest("1"),
                _digest("2"),
                expected_uid=self.uid,
                deadline=1,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
            )
        self.assertFalse(path.exists())

        path.write_bytes(b"x" * (64 * 1024 + 1))
        path.chmod(0o400)
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "byte limit",
        ):
            _wait_for_submission_result(
                path,
                "a" * 64,
                _digest("1"),
                _digest("2"),
                expected_uid=self.uid,
                deadline=1,
                monotonic=lambda: 0,
                sleep=lambda _seconds: None,
            )
        self.assertFalse(path.exists())

    def test_interrupted_fresh_publication_is_cleaned(self) -> None:
        path = self.control / "interrupted.json"
        link = os.link

        def interrupt_after_link(*args, **kwargs):
            link(*args, **kwargs)
            raise KeyboardInterrupt

        with (
            mock.patch(
                "aragorn.protected_install_coordinator.os.link",
                side_effect=interrupt_after_link,
            ),
            self.assertRaises(KeyboardInterrupt),
        ):
            _atomic_publish(
                path,
                canonical_json({"submission_id": "a" * 64}),
                self.uid,
                replace=False,
            )
        self.assertFalse(path.exists())

    def test_public_submission_error_uses_exact_fail_closed_shape(self) -> None:
        output = BytesIO()
        with mock.patch(
            "aragorn.protected_install_coordinator.sys.stderr",
            SimpleNamespace(buffer=output),
        ):
            self.assertEqual(_submission_error(ValueError("blocked")), 4)
        error = json.loads(output.getvalue())
        self.assertEqual(_validate_coordinator_result(error), error)

    def test_release_asset_pins_require_a_protected_operator_file(self) -> None:
        path = self.control / "release-pins.json"
        path.write_bytes(canonical_json({}))
        path.chmod(0o400)

        self.assertEqual(_load_release_asset_pins(path, self.uid), {})
        self.assertIsNone(
            _load_release_asset_pins(self.control / "absent.json", self.uid),
        )
        self.assertIsNone(_load_release_asset_pins(None, self.uid))
        path.chmod(0o600)
        with self.assertRaisesRegex(
            ProtectedInstallCoordinatorError,
            "metadata is unsafe",
        ):
            _load_release_asset_pins(path, self.uid)

    def test_recursive_verifier_pin_covers_the_python_source_closure(self) -> None:
        cas = CAS(self.root / "verifier-cas")
        for release_digests, requires_v6 in (
            ([], False),
            ([_digest("1")], False),
            ([_digest("1")], True),
        ):
            with self.subTest(release_assets=bool(release_digests)):
                with mock.patch.object(
                    recursive_artifact_graph_v6,
                    "release_assets_require_v6",
                    return_value=requires_v6,
                ) as select_v6:
                    self.assertEqual(
                        _recursive_artifact_graph_verifier_digest(
                            cas,
                            release_digests,
                        ),
                        candidate_implementation_digest(),
                    )
                if release_digests:
                    select_v6.assert_called_once_with(cas, release_digests)
                else:
                    select_v6.assert_not_called()

    def test_release_identity_derives_broker_and_analyzer_pins(self) -> None:
        broker = (
            _ROOT
            / "benchmark"
            / "admission"
            / "openclaw-v2026.7.1"
            / "protected-install-broker-recursive-v3.py"
        )
        python = Path(sys.executable).resolve(strict=True)
        raw_broker = broker.read_bytes()
        raw_python = python.read_bytes()
        identity = {
            "schema": "aragorn/protected-broker-launch-identity/v1",
            "broker": {
                "path": broker.relative_to(_ROOT).as_posix(),
                "digest": "sha256:" + hashlib.sha256(raw_broker).hexdigest(),
            },
            "launcher": {
                "path": "/usr/libexec/aragorn/launcher",
                "digest": _digest("0"),
            },
            "package": {
                "root": str(_ROOT),
                "tree_digest": _digest("1"),
            },
            "python": {
                "path": str(python),
                "digest": "sha256:" + hashlib.sha256(raw_python).hexdigest(),
            },
        }
        path = self.control / "release.json"
        path.write_bytes(canonical_json(identity))
        path.chmod(0o400)

        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_require_protected_ancestry"
            ),
            mock.patch(
                "aragorn.protected_install_coordinator._service_identity",
                return_value=(64001, 64002),
            ) as service_identity,
        ):
            pins, release = _derive_release_pins(path, self.uid)

        service_identity.assert_called_once_with(
            "aragorn-analyze",
            "aragorn-analyze",
        )
        self.assertEqual(
            pins["expected_producer_implementation_digest"],
            identity["broker"]["digest"],
        )
        self.assertEqual(
            pins["expected_analyzer_implementation_digest"],
            candidate_implementation_digest(),
        )
        self.assertEqual(
            pins["expected_analyzer_executable_digest"],
            identity["python"]["digest"],
        )
        self.assertEqual(release["package_root"], _ROOT)
        self.assertEqual(release["python_path"], python)

    def test_release_analyzer_script_binds_numeric_worker_identity(self) -> None:
        observed: list[tuple[int, int]] = []

        def builder(
            implementation_digest: str,
            *,
            expected_uid: int,
            expected_gid: int,
        ) -> str:
            self.assertEqual(implementation_digest, _digest("1"))
            observed.append((expected_uid, expected_gid))
            return "bounded"

        with mock.patch(
            "aragorn.protected_install_coordinator._service_identity",
            return_value=(64001, 64002),
        ):
            script = _release_analyzer_script(
                SimpleNamespace(_github_analyzer_script=builder),
                _digest("1"),
            )

        self.assertEqual(script, "bounded")
        self.assertEqual(observed, [(64001, 64002)])

    def test_service_is_internal_and_fixed(self) -> None:
        unit = _SERVICE.read_text()
        path_unit = _PATH_UNIT.read_text()
        self.assertIn(
            "ConditionPathExists="
            "/run/aragorn-protected-install/intent.json",
            unit,
        )
        self.assertIn(
            "ConditionPathExists="
            "/etc/aragorn/phase1-coordinator-evidence-enabled",
            unit,
        )
        self.assertIn(
            "ExecStart=/usr/bin/python3.14 -I -S -B "
            "/usr/libexec/aragorn/"
            "aragorn-protected-install-coordinator.py",
            unit,
        )
        self.assertNotIn("LoadCredential=", unit)
        self.assertNotIn("PrivateMounts=", unit)
        self.assertNotIn("PrivateIPC=", unit)
        self.assertNotIn("PrivateNetwork=", unit)
        self.assertNotIn("ProtectSystem=", unit)
        self.assertNotIn("ProtectKernelLogs=", unit)
        self.assertNotIn("@ipc", unit)
        self.assertIn("process_vm_readv process_vm_writev", unit)
        self.assertIn("IPAddressDeny=any", unit)
        self.assertIn("IPAddressAllow=localhost", unit)
        self.assertIn(
            "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            unit,
        )
        self.assertIn(
            "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
            unit,
        )
        self.assertIn(
            "ARAGORN_DROP_HOST_INSPECTION_CAPABILITY=1",
            unit,
        )
        self.assertNotIn("CAP_CHOWN", unit)
        self.assertNotIn("CAP_FOWNER", unit)
        self.assertNotIn("ExecStart=/bin/sh", unit)
        self.assertNotIn("EnvironmentFile=", unit)
        self.assertIn("RefuseManualStart=yes", unit)
        self.assertIn(
            "PathChanged=/run/aragorn-protected-install/intent.json",
            path_unit,
        )
        self.assertIn(
            "Unit=aragorn-protected-install-coordinator-evidence.service",
            path_unit,
        )

    def test_production_ingress_reuses_the_fixed_coordinator_boundary(
        self,
    ) -> None:
        unit = _PRODUCTION_SERVICE.read_text()
        path_unit = _PRODUCTION_PATH_UNIT.read_text()
        self.assertNotIn("phase1-coordinator-evidence-enabled", unit)
        self.assertIn(
            "ConditionPathExists="
            "/run/aragorn-protected-install/intent.json",
            unit,
        )
        self.assertIn(
            "ExecStart=/usr/bin/python3.14 -I -S -B "
            "/usr/libexec/aragorn/"
            "aragorn-protected-install-coordinator.py run-submitted",
            unit,
        )
        self.assertIn("RefuseManualStart=yes", unit)
        self.assertIn(
            "Conflicts="
            "aragorn-protected-install-coordinator-evidence.service",
            unit,
        )
        self.assertIn("TimeoutStartSec=12min", unit)
        self.assertIn("TimeoutStartSec=10min", _SERVICE.read_text())
        self.assertIn(
            "PathChanged=/run/aragorn-protected-install/intent.json",
            path_unit,
        )
        self.assertIn(
            "Unit=aragorn-protected-install-coordinator.service",
            path_unit,
        )
        self.assertIn(
            "Conflicts="
            "aragorn-protected-install-coordinator-evidence.path",
            path_unit,
        )

    def test_coordinator_starts_only_the_fixed_service_without_a_shell(
        self,
    ) -> None:
        completed = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "_require_root_executable"
            ),
            mock.patch(
                "aragorn.protected_install_coordinator.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            _start_fixed_service()

        argv = run.call_args.args[0]
        options = run.call_args.kwargs
        self.assertEqual(
            argv,
            (
                "/usr/bin/systemctl",
                "--no-ask-password",
                "--wait",
                "start",
                "aragorn-protected-install.service",
            ),
        )
        self.assertNotIn("shell", options)

    def test_entrypoint_reads_only_stable_protected_control_bytes(
        self,
    ) -> None:
        entrypoint = _load_entrypoint()
        path = self.control / "control.json"
        path.write_bytes(b"protected")
        path.chmod(0o400)
        self.assertEqual(
            entrypoint._root_file(
                path,
                16,
                expected_uid=self.uid,
            ),
            b"protected",
        )

        link = self.control / "control-link.json"
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "canonical"):
            entrypoint._root_file(
                link,
                16,
                expected_uid=self.uid,
            )

        path.chmod(0o622)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            entrypoint._root_file(
                path,
                16,
                expected_uid=self.uid,
            )

    def test_entrypoint_forwards_only_after_release_verification(self) -> None:
        entrypoint = _load_entrypoint()
        arguments = (
            "submit",
            "install",
            "example",
            "skills",
            "1" * 40,
            "sample",
        )
        with (
            mock.patch.object(entrypoint.sys, "platform", "linux"),
            mock.patch.object(entrypoint.os, "geteuid", return_value=0),
            mock.patch.object(
                entrypoint,
                "_verified_package_root",
                return_value=_ROOT,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator.main",
                return_value=0,
            ) as coordinate,
            mock.patch.object(sys, "argv", [str(_ENTRYPOINT), *arguments]),
        ):
            self.assertEqual(entrypoint.main(), 0)
        coordinate.assert_called_once_with()
