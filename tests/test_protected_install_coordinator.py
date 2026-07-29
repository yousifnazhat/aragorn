from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from aragorn.cas import CAS
from aragorn.github_gateway import QUARANTINE_AUTHORITY, SOURCE_ASSURANCE
from aragorn.oci_worker_protocol import canonical_json
from aragorn.phase0_candidate import candidate_implementation_digest
from aragorn.protected_install_coordinator import (
    ASSURANCE,
    INTENT_SCHEMA,
    ProtectedInstallCoordinatorError,
    _derive_release_pins,
    _release_analyzer_script,
    _start_fixed_service,
    coordinate_intent,
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
        quarantine = Path(kwargs["quarantine_state"])
        CAS(quarantine)
        suffix = source_request["commit"][0]
        receipt_digest = _digest("a" if suffix == "1" else "b")
        manifest_digest = _digest("c" if suffix == "1" else "d")
        tree_digest = _digest("e" if suffix == "1" else "f")
        profile_digest = _digest("8" if suffix == "1" else "9")
        self.receipts[receipt_digest] = {
            "schema": "aragorn/github-quarantine-receipt/v1",
            "authority": QUARANTINE_AUTHORITY,
            "request": source_request,
            "manifest_digest": manifest_digest,
            "tree_digest": tree_digest,
        }
        return SimpleNamespace(
            authority=QUARANTINE_AUTHORITY,
            source_assurance=SOURCE_ASSURANCE,
            quarantine_state=quarantine,
            quarantine_receipt_digest=receipt_digest,
            gateway_profile_digest=profile_digest,
            manifest_digest=manifest_digest,
            tree_digest=tree_digest,
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
            ]["tree_digest"],
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
                "aragorn.protected_install_coordinator.quarantine_through_gateway",
                side_effect=self._gateway_result,
            ),
            mock.patch(
                "aragorn.protected_install_coordinator."
                "verify_github_quarantine_receipt",
                side_effect=self._verify_receipt,
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
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            installed = coordinate_intent(
                self._intent("install", "1" * 40),
                release_identity_path=self.root / "unused-identity.json",
                gateway_root=self.gateway,
                quarantine_root=self.quarantine,
                protected_root=self.protected,
                request_path=self.request,
                state_path=self.state,
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
        self.assertIsNone(first["expected_active"])
        self.assertIsNone(first["expected_manifest_diff_digest"])
        self.assertEqual(
            {field: first[field] for field in pins},
            pins,
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
        self.assertNotEqual(
            second["expected_manifest_diff_digest"],
            first["expected_manifest_diff_digest"],
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
                    "expected_policy_digest": _digest("1"),
                }
            )
        )
        path.chmod(0o400)
        with (
            mock.patch(
                "aragorn.protected_install_coordinator."
                "quarantine_through_gateway"
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
                expected_uid=self.uid,
            )
        gateway.assert_not_called()

    def test_release_identity_derives_broker_and_analyzer_pins(self) -> None:
        broker = (
            _ROOT
            / "benchmark"
            / "admission"
            / "openclaw-v2026.7.1"
            / "protected-install-broker.py"
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
