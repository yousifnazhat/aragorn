from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from aragorn.github_gateway_live_evidence import (
    verify_github_gateway_live_evidence,
)
from aragorn.oci_worker_protocol import canonical_digest
from scripts.verify_build_inputs import tree_digest

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = (
    _ROOT
    / "packaging"
    / "libexec"
    / "aragorn-protected-install-launcher.py"
)
_BROKER = (
    _ROOT
    / "benchmark"
    / "admission"
    / "openclaw-v2026.7.1"
    / "protected-install-broker.py"
)
_GATEWAY_LIVE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "github-gateway-anthropics-template-live-2026-07-29.json"
)
_LAUNCH_LIVE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / (
        "openclaw-v2026.7.1-agent-skill-protected-launch-live-"
        "8ce3582b-2026-07-29.json"
    )
)
_LAUNCH_RETENTION = (
    _ROOT
    / "benchmark"
    / "evidence"
    / (
        "openclaw-v2026.7.1-protected-launcher-retention-"
        "8ce3582b-2026-07-29.json"
    )
)
_RUNTIME_CONFORMANCE = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-update-reload-route-coverage-v3-2026-07-28.json"
)
_TARGET_RUNTIME = (
    _ROOT
    / "benchmark"
    / "evidence"
    / "openclaw-v2026.7.1-contained-model-activation-probe-2026-07-28.json"
)
_PACKAGE_INCLUDES = (
    "benchmark/admission/openclaw-v2026.7.1/protected-install-broker.py",
    "requirements-worker.lock",
    "scripts/verify_build_inputs.py",
    "src/aragorn",
)


def _load_launcher():
    spec = importlib.util.spec_from_file_location(
        "aragorn_protected_install_launcher_test",
        _SOURCE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load protected install launcher")
    module = importlib.util.module_from_spec(spec)
    with mock.patch.object(sys, "dont_write_bytecode", True):
        spec.loader.exec_module(module)
    return module


def _raw_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(path: Path) -> str:
    return _raw_digest(path.read_bytes())


def _commit_bytes(commit: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        check=True,
        cwd=_ROOT,
        stdout=subprocess.PIPE,
    ).stdout


def _commit_package_digest(
    commit: str,
    *,
    overrides: dict[str, bytes] | None = None,
) -> tuple[str, list[str]]:
    paths = subprocess.run(
        [
            "git",
            "ls-tree",
            "-r",
            "--name-only",
            commit,
            "--",
            *_PACKAGE_INCLUDES,
        ],
        check=True,
        cwd=_ROOT,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.splitlines()
    result = hashlib.sha256()
    replacements = overrides or {}
    for path in paths:
        raw = replacements.get(path)
        if raw is None:
            raw = _commit_bytes(commit, path)
        path_bytes = path.encode()
        mode = 0o444 if path == _PACKAGE_INCLUDES[0] else 0o644
        result.update(len(path_bytes).to_bytes(8, "big"))
        result.update(path_bytes)
        result.update(mode.to_bytes(4, "big"))
        result.update(len(raw).to_bytes(8, "big"))
        result.update(hashlib.sha256(raw).digest())
    return "sha256:" + result.hexdigest(), paths


class ProtectedInstallLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.launcher = _load_launcher()
        self.temporary = TemporaryDirectory(dir=_ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.uid = os.geteuid()
        self.installed_launcher = self.root / "launcher"
        shutil.copyfile(_SOURCE, self.installed_launcher)
        self.installed_launcher.chmod(0o444)
        self.python = self.root / "python"
        self.python.write_bytes(b"fake protected Python")
        self.python.chmod(0o555)
        self.package = self.root / "package"
        self.package.mkdir(mode=0o755)
        self.broker = self.package / "broker.py"
        self.broker.write_bytes(b"raise SystemExit('not executed by unit test')\n")
        self.broker.chmod(0o444)
        self.package.chmod(0o555)
        self.identity_path = self.root / "identity.json"
        self.identity = self._identity()
        self._write_identity()

    def _identity(self) -> dict[str, object]:
        package_digest = self.launcher._measure_package(
            self.package,
            self.uid,
        )
        self.assertEqual(package_digest, "sha256:" + tree_digest(self.package))
        return {
            "schema": "aragorn/protected-broker-launch-identity/v1",
            "launcher": {
                "path": str(self.installed_launcher),
                "digest": _digest(self.installed_launcher),
            },
            "package": {
                "root": str(self.package),
                "tree_digest": package_digest,
            },
            "broker": {
                "path": "broker.py",
                "digest": _digest(self.broker),
            },
            "python": {
                "path": str(self.python),
                "digest": _digest(self.python),
            },
        }

    def _write_identity(self) -> None:
        if self.identity_path.exists():
            self.identity_path.chmod(0o644)
        self.identity_path.write_bytes(self.launcher._canonical_json(self.identity))
        self.identity_path.chmod(0o444)

    def test_validated_launch_is_isolated_and_exact(self) -> None:
        with self._running_python(self.python, isolated=True):
            executable, argv, environment = self.launcher._validated_launch(
                self.identity_path,
                ("--github-live", "--cas-root", "/quarantine"),
                expected_uid=self.uid,
                launcher_path=self.installed_launcher,
            )

        self.assertEqual(executable, self.python)
        self.assertEqual(
            argv,
            (
                str(self.python),
                "-I",
                "-S",
                "-B",
                str(self.broker),
                "--github-live",
                "--cas-root",
                "/quarantine",
            ),
        )
        self.assertEqual(
            environment,
            {
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TZ": "UTC",
            },
        )
        self.assertNotIn("PYTHONPATH", environment)

    def test_package_mutation_and_symlink_fail_before_exec(self) -> None:
        self.broker.chmod(0o644)
        self.broker.write_bytes(b"import aragorn\n")
        self.broker.chmod(0o444)
        with self.assertRaisesRegex(
                self.launcher.LaunchVerificationError,
                "package tree digest does not match",
        ), self._running_python(self.python, isolated=True):
            self.launcher._validated_launch(
                self.identity_path,
                (),
                expected_uid=self.uid,
                launcher_path=self.installed_launcher,
            )

        self.package.chmod(0o755)
        self.broker.unlink()
        self.broker.symlink_to(self.python)
        self.package.chmod(0o555)
        with self.assertRaisesRegex(
            self.launcher.LaunchVerificationError,
            "package entry is unsafe",
        ), self._running_python(self.python, isolated=True):
                self.launcher._validated_launch(
                    self.identity_path,
                    (),
                    expected_uid=self.uid,
                    launcher_path=self.installed_launcher,
                )

    def test_empty_package_directory_is_rejected(self) -> None:
        expected = tree_digest(self.package)
        self.package.chmod(0o755)
        empty = self.package / "empty-namespace"
        empty.mkdir(mode=0o555)
        self.package.chmod(0o555)
        self.assertEqual(tree_digest(self.package), expected)

        with (
            self.assertRaisesRegex(
                self.launcher.LaunchVerificationError,
                "unpinned empty directory",
            ),
            self._running_python(self.python, isolated=True),
        ):
            self.launcher._validated_launch(
                self.identity_path,
                (),
                expected_uid=self.uid,
                launcher_path=self.installed_launcher,
            )

    def test_unprotected_or_caller_substituted_identity_fails(self) -> None:
        self.identity_path.chmod(0o466)
        with self.assertRaisesRegex(
            self.launcher.LaunchVerificationError,
            "release identity metadata is unsafe",
        ), self._running_python(self.python, isolated=True):
            self.launcher._validated_launch(
                self.identity_path,
                (),
                expected_uid=self.uid,
                launcher_path=self.installed_launcher,
            )

        self.identity_path.chmod(0o444)
        other_launcher = self.root / "other-launcher"
        shutil.copyfile(self.installed_launcher, other_launcher)
        other_launcher.chmod(0o555)
        with self.assertRaisesRegex(
            self.launcher.LaunchVerificationError,
            "executed launcher path is not pinned",
        ), self._running_python(self.python, isolated=True):
            self.launcher._validated_launch(
                self.identity_path,
                (),
                expected_uid=self.uid,
                launcher_path=other_launcher,
            )

    def test_wrong_or_nonisolated_running_python_fails(self) -> None:
        for executable, isolated in (
            (self.installed_launcher, True),
            (self.python, False),
        ):
            with (
                self.subTest(executable=executable, isolated=isolated),
                self.assertRaisesRegex(
                    self.launcher.LaunchVerificationError,
                    "pinned Python with -I -S -B",
                ),self._running_python(executable, isolated=isolated)
            ):
                self.launcher._validated_launch(
                    self.identity_path,
                    (),
                    expected_uid=self.uid,
                    launcher_path=self.installed_launcher,
                )

    def test_python_digest_mismatch_fails(self) -> None:
        self.identity["python"]["digest"] = "sha256:" + "0" * 64
        self._write_identity()
        with (
            self._running_python(self.python, isolated=True),
            self.assertRaisesRegex(
                self.launcher.LaunchVerificationError,
                "Python digest does not match",
            ),
        ):
            self.launcher._validated_launch(
                self.identity_path,
                (),
                expected_uid=self.uid,
                launcher_path=self.installed_launcher,
            )

    def test_main_uses_only_the_fixed_release_identity(self) -> None:
        command = (
            self.python,
            (str(self.python), "-I", "-S", "-B", str(self.broker)),
            {"PATH": "/usr/bin:/bin"},
        )
        with (
            mock.patch.object(self.launcher.sys, "platform", "linux"),
            mock.patch.object(
                self.launcher.sys,
                "argv",
                ["launcher", "--", "--github-live"],
            ),
            mock.patch.object(self.launcher.os, "geteuid", return_value=0),
            mock.patch.object(
                self.launcher,
                "_validated_launch",
                return_value=command,
            ) as validate,
            mock.patch.object(
                self.launcher,
                "_exec",
                side_effect=OSError("injected exec failure"),
            ),
            mock.patch("builtins.print"),
        ):
            self.assertEqual(self.launcher.main(), 126)

        validate.assert_called_once_with(
            Path("/etc/aragorn/protected-broker-release.json"),
            ("--github-live",),
            expected_uid=0,
            launcher_path=Path(self.launcher.__file__),
        )

    def test_exec_closes_descriptors_and_replaces_environment(self) -> None:
        with (
            mock.patch.object(self.launcher.os, "chdir") as chdir,
            mock.patch.object(self.launcher.os, "umask") as umask,
            mock.patch.object(
                self.launcher.os,
                "listdir",
                return_value=["0", "1", "2", "8", "9000001", "gone"],
            ),
            mock.patch.object(self.launcher.os, "close") as close,
            mock.patch.object(
                self.launcher.os,
                "execve",
                side_effect=OSError("injected exec failure"),
            ) as execute,
            self.assertRaisesRegex(OSError, "injected exec failure"),
        ):
            self.launcher._exec(
                self.python,
                (str(self.python), "-I", "-S", "-B", str(self.broker)),
                {"PATH": "/usr/bin:/bin"},
            )

        chdir.assert_called_once_with("/")
        umask.assert_called_once_with(0o077)
        self.assertEqual(
            [call.args for call in close.call_args_list],
            [(8,), (9000001,)],
        )
        execute.assert_called_once_with(
            self.python,
            (str(self.python), "-I", "-S", "-B", str(self.broker)),
            {"PATH": "/usr/bin:/bin"},
        )

    def test_retained_live_launch_binds_gateway_custody_without_authority(
        self,
    ) -> None:
        live_raw = _LAUNCH_LIVE.read_bytes()
        retention_raw = _LAUNCH_RETENTION.read_bytes()
        live = json.loads(live_raw)
        retention = json.loads(retention_raw)
        self.assertEqual(
            live_raw,
            self.launcher._canonical_json(live) + b"\n",
        )
        self.assertEqual(
            retention_raw,
            self.launcher._canonical_json(retention) + b"\n",
        )
        self.assertEqual(
            _digest(_LAUNCH_LIVE),
            "sha256:02aaefc8f0221ef545055e6a135da2be"
            "46f8a9a3e1c523fcb7605293d09402a7",
        )
        self.assertEqual(
            _digest(_LAUNCH_RETENTION),
            "sha256:0dde794e61a79ab71582225bae5f4157"
            "43e191cb8724e30a831a6cf93a287e0c",
        )

        self.assertEqual(
            retention["schema"],
            "aragorn/phase1-protected-broker-launch-live-retention/v1",
        )
        self.assertEqual(
            retention["assurance"],
            "PRE_ARAGORN_IMPORT_PACKAGE_PIN_EVIDENCE_ONLY_"
            "NOT_INSTALLER_AUTHORITY",
        )
        self.assertEqual(
            retention["status"],
            "CAPTURE_PASS_PHASE_EXIT_INELIGIBLE",
        )
        self.assertFalse(retention["phase1_exit_eligible"])
        implementation = retention["implementation"]
        commit = implementation["commit"]
        self.assertEqual(
            commit,
            "8ce3582b46df9343ce7bc7904cdf50c20e877a38",
        )
        package_digest, package_paths = _commit_package_digest(
            commit
        )
        launcher_raw = _commit_bytes(
            commit,
            _SOURCE.relative_to(_ROOT).as_posix(),
        )
        broker_raw = _commit_bytes(
            commit,
            _BROKER.relative_to(_ROOT).as_posix(),
        )
        self.assertEqual(len(package_paths), 54)
        self.assertEqual(
            package_digest,
            implementation["package_tree_digest_after"],
        )
        self.assertEqual(
            implementation["launcher_digest"],
            _raw_digest(launcher_raw),
        )
        self.assertEqual(
            implementation["broker_digest"],
            _raw_digest(broker_raw),
        )
        self.assertEqual(
            implementation["package_tree_digest_before"],
            implementation["package_tree_digest_after"],
        )
        self.assertEqual(
            implementation["identity_digest_before"],
            implementation["identity_digest_after"],
        )
        self.assertTrue(implementation["package_no_bytecode_after"])
        identity = implementation["identity_document"]
        identity_digest = "sha256:" + hashlib.sha256(
            self.launcher._canonical_json(identity)
        ).hexdigest()
        self.assertEqual(
            identity_digest,
            implementation["identity_digest_before"],
        )
        self.assertEqual(
            identity["launcher"]["digest"],
            _raw_digest(launcher_raw),
        )
        self.assertEqual(identity["broker"]["digest"], _raw_digest(broker_raw))
        self.assertEqual(
            identity["launcher"]["path"],
            implementation["launcher_path"],
        )
        self.assertEqual(
            identity["python"],
            {
                "digest": implementation["python_executable_digest"],
                "path": implementation["python_path"],
            },
        )
        self.assertEqual(
            identity["package"]["root"],
            implementation["package_path"],
        )
        self.assertEqual(
            str(
                Path(identity["package"]["root"])
                / identity["broker"]["path"]
            ),
            implementation["broker_path"],
        )
        self.assertEqual(
            identity["package"]["tree_digest"],
            implementation["package_tree_digest_after"],
        )

        launch = retention["launch"]
        self.assertEqual(
            launch["invocation"],
            "OPERATOR_ROOT_DIRECT_EXECUTION",
        )
        self.assertEqual(
            launch["broker_arguments_authority"],
            "OPERATOR_ROOT_CONSTRUCTED_NOT_INSTALLER_AUTHORITY",
        )
        self.assertEqual(launch["effective_uid"], 0)
        self.assertEqual(launch["identity_selection"], "FIXED_COMPILED_PATH")
        self.assertEqual(
            launch["argv_prefix"],
            [
                identity["python"]["path"],
                "-I",
                "-S",
                "-B",
                identity["launcher"]["path"],
                "--",
            ],
        )

        gateway = verify_github_gateway_live_evidence(
            json.loads(_GATEWAY_LIVE.read_bytes())
        )
        by_digest = {
            item["digest"]: base64.b64decode(
                item["base64"],
                validate=True,
            )
            for item in gateway["positive"]["cas_blobs"]
        }
        gateway_result = gateway["positive"]["result"]
        manifest = json.loads(by_digest[gateway_result["manifest_digest"]])
        receipt = json.loads(
            by_digest[gateway_result["quarantine_receipt_digest"]]
        )
        self.assertEqual(
            [item["path"] for item in manifest["files"]],
            ["SKILL.md"],
        )
        root_skill = manifest["files"][0]
        self.assertEqual(root_skill["size"], 140)
        self.assertFalse(root_skill["executable"])
        self.assertEqual(
            digest := "sha256:"
            + hashlib.sha256(by_digest[root_skill["digest"]]).hexdigest(),
            root_skill["digest"],
        )
        self.assertEqual(digest, retention["positive"]["active"]["file_digest"])
        self.assertEqual(
            root_skill["size"],
            retention["positive"]["active"]["file_bytes"],
        )
        self.assertEqual(retention["positive"]["active"]["file_mode"], 0o444)

        source = live["source"]
        positive = retention["positive"]
        transaction = live["transaction"]
        context = live["context"]
        active = live["active"]
        self.assertEqual(
            live["assurance"],
            "LIVE_GITHUB_CUSTODY_TO_PROTECTED_INSTALL_EVIDENCE_ONLY_"
            "NOT_INSTALLER_AUTHORITY",
        )
        self.assertEqual(
            live["producer_implementation_digest"],
            implementation["broker_digest"],
        )
        self.assertEqual(
            transaction["authority"],
            "BROKER_TRANSACTION_RECORD_ONLY_NOT_INSTALLER_AUTHORITY",
        )
        self.assertEqual(source["request"], gateway["positive"]["request"])
        self.assertEqual(positive["source"], source["request"])
        self.assertEqual(
            source["manifest_digest"],
            gateway_result["manifest_digest"],
        )
        self.assertEqual(
            source["quarantine_receipt_digest"],
            gateway_result["quarantine_receipt_digest"],
        )
        self.assertEqual(receipt["request"], source["request"])
        self.assertEqual(
            receipt["manifest_digest"],
            source["manifest_digest"],
        )
        self.assertEqual(receipt["tree_digest"], source["tree_digest"])
        self.assertEqual(
            manifest["source"],
            {
                key: value
                for key, value in receipt["request"].items()
                if key != "schema"
            }
            | {
                "api_version": "2026-03-10",
                "commit_tree": (
                    "a87780349fa9dc5c65c9a11dcc7151ec297f21a1"
                ),
                "host": "github.com",
                "kind": "github_commit",
                "repository_hash_algorithm": "sha1",
                "skill_tree": "a38aa7fa73fd2835b9ce77a60274f7dc62d015a6",
            },
        )
        self.assertEqual(manifest["tree_digest"], source["tree_digest"])
        self.assertEqual(positive["manifest_digest"], source["manifest_digest"])
        self.assertEqual(
            positive["quarantine_receipt_digest"],
            source["quarantine_receipt_digest"],
        )
        self.assertEqual(
            positive["result"],
            {
                "installer_work_eligible": live["decision"][
                    "installer_work_eligible"
                ],
                "slice_status": live["slice_status"],
            },
        )

        self.assertEqual(positive["context"], context)
        self.assertEqual(positive["transaction"], transaction)
        self.assertEqual(transaction["context_id"], context["context_id"])
        self.assertEqual(transaction["context_digest"], context["digest"])
        self.assertEqual(transaction["destination"], context["destination"])
        self.assertEqual(
            transaction["manifest_digest"],
            source["manifest_digest"],
        )
        self.assertEqual(transaction["tree_digest"], source["tree_digest"])
        self.assertEqual(active["tree_digest"], transaction["tree_digest"])
        self.assertEqual(
            positive["active"]["tree_digest"],
            transaction["tree_digest"],
        )
        self.assertEqual(
            active["link_target"],
            transaction["version_path"],
        )
        self.assertEqual(
            positive["active"]["link_target"],
            transaction["version_path"],
        )
        self.assertEqual(
            positive["evidence"]["file_digest"],
            _digest(_LAUNCH_LIVE),
        )
        self.assertEqual(
            positive["evidence"]["path"],
            _LAUNCH_LIVE.relative_to(_ROOT).as_posix(),
        )
        self.assertEqual(live["slice_status"], "PASS")
        self.assertFalse(live["decision"]["installer_work_eligible"])
        conformance = json.loads(_RUNTIME_CONFORMANCE.read_bytes())
        runtime = json.loads(_TARGET_RUNTIME.read_bytes())
        self.assertEqual(
            context["runtime_conformance_digest"],
            canonical_digest(conformance),
        )
        self.assertEqual(
            context["target_runtime_digest"],
            runtime["runtime"]["runtime_tree"]["tree_digest"],
        )

        negative = retention["negative"]
        self.assertEqual(
            negative["sequence_assurance"],
            "OPERATOR_CAPTURE_ONLY_NOT_REPLAYABLE_CUSTODY",
        )
        restoration = negative["identity_restoration"]
        self.assertTrue(restoration["restored_exactly"])
        self.assertEqual(
            restoration["before_digest"],
            implementation["identity_digest_before"],
        )
        self.assertEqual(
            restoration["after_digest"],
            implementation["identity_digest_after"],
        )
        mutation = negative["byte_tamper"]["mutation"]
        anchor = mutation["anchor_utf8"].encode()
        insertion = mutation["insertion_utf8"].encode()
        self.assertEqual(broker_raw.count(anchor), 1)
        tampered = broker_raw.replace(anchor, anchor + insertion, 1)
        tamper = negative["byte_tamper"]
        tampered_package_digest, tampered_paths = _commit_package_digest(
            implementation["commit"],
            overrides={_PACKAGE_INCLUDES[0]: tampered},
        )
        self.assertEqual(tampered_paths, package_paths)
        self.assertEqual(
            tampered_package_digest,
            tamper["actual_package_tree_digest"],
        )
        self.assertNotEqual(
            tamper["actual_package_tree_digest"],
            tamper["expected_package_tree_digest"],
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(tampered).hexdigest(),
            tamper["actual_broker_digest"],
        )
        self.assertEqual(
            tamper["expected_broker_digest"],
            _raw_digest(broker_raw),
        )
        self.assertEqual(
            "sha256:"
            + hashlib.sha256(
                self.launcher._canonical_json(tamper["identity_document"])
            ).hexdigest(),
            tamper["identity_digest"],
        )
        self.assertEqual(tamper["exit_status"], 126)
        self.assertTrue(tamper["stdout_empty"])
        self.assertEqual(
            "sha256:" + hashlib.sha256(b"").hexdigest(),
            tamper["stdout_digest"],
        )
        self.assertTrue(tamper["protected_root_empty"])
        self.assertTrue(tamper["import_sentinel_absent"])
        self.assertEqual(
            tamper["stderr_utf8"],
            "aragorn protected launcher: package tree digest "
            "does not match its pin\n",
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(tamper["stderr_utf8"].encode()).hexdigest(),
            tamper["stderr_digest"],
        )

        empty = negative["empty_directory"]
        self.assertEqual(
            empty["legacy_file_only_tree_digest"],
            empty["expected_package_tree_digest"],
        )
        self.assertEqual(empty["directory_mode"], 0o555)
        self.assertEqual(empty["directory_owner_uid"], 0)
        self.assertTrue(empty["directory_empty"])
        self.assertEqual(empty["exit_status"], 126)
        self.assertTrue(empty["stdout_empty"])
        self.assertEqual(
            "sha256:" + hashlib.sha256(b"").hexdigest(),
            empty["stdout_digest"],
        )
        self.assertTrue(empty["protected_root_empty"])
        self.assertEqual(
            "sha256:"
            + hashlib.sha256(
                self.launcher._canonical_json(empty["identity_document"])
            ).hexdigest(),
            empty["identity_digest"],
        )
        self.assertEqual(
            empty["stderr_utf8"],
            "aragorn protected launcher: protected package contains "
            "an unpinned empty directory\n",
        )
        self.assertEqual(
            "sha256:" + hashlib.sha256(empty["stderr_utf8"].encode()).hexdigest(),
            empty["stderr_digest"],
        )
        for case in (tamper, empty):
            negative_identity = case["identity_document"]
            self.assertEqual(
                negative_identity["launcher"],
                identity["launcher"],
            )
            self.assertEqual(negative_identity["python"], identity["python"])
            self.assertEqual(negative_identity["broker"], identity["broker"])
            self.assertEqual(
                negative_identity["package"]["root"],
                case["package_path"],
            )
            self.assertEqual(
                negative_identity["package"]["tree_digest"],
                case["expected_package_tree_digest"],
            )
            self.assertEqual(
                case["expected_package_tree_digest"],
                implementation["package_tree_digest_after"],
            )

        self.assertEqual(
            retention["discarded_attempts"],
            [
                {
                    "implementation_commit": (
                        "6243cb72aa1786f6a3dff80a6a25376ca0628069"
                    ),
                    "reason": (
                        "EMPTY_DIRECTORY_NOT_BOUND_BY_LEGACY_FILE_ONLY_"
                        "TREE_DIGEST"
                    ),
                    "retained_as_exit_evidence": False,
                }
            ],
        )
        self.assertEqual(
            retention["control_evidence"],
            {
                "code_bound": [
                    "ABSOLUTE_PINNED_PYTHON_I_S_B",
                    "FIXED_ROOT_PROTECTED_RELEASE_IDENTITY",
                    "PRE_ARAGORN_PACKAGE_TREE_MEASUREMENT",
                    "EXACT_BROKER_ENTRYPOINT_DIGEST",
                    "SEALED_BROKER_ENVIRONMENT_AND_INHERITED_FD_CLOSURE",
                    "ROOT_SKILL_MD_REQUIRED_BEFORE_ANALYSIS",
                    "EMPTY_PACKAGE_DIRECTORY_REJECTED",
                ],
                "operator_observed": [
                    "TAMPERED_PACKAGE_BLOCKED_BEFORE_BROKER_IMPORT",
                    "EMPTY_DIRECTORY_BLOCKED_BEFORE_BROKER_IMPORT",
                    "POSITIVE_PACKAGE_UNCHANGED_AFTER_INSTALL",
                ],
            },
        )
        for limitation in (
            "OPERATOR_CAPTURE_NOT_INDEPENDENT_ATTESTATION",
            "NEGATIVE_SEQUENCE_OPERATOR_ASSERTED_NOT_REPLAYABLE_CUSTODY",
            "NO_FIXED_ROOT_OWNED_SERVICE_CALL_SITE",
            "BROKER_ARGUMENTS_NOT_BOUND_TO_ROOT_PROTECTED_REQUEST",
            "CURRENT_RUNTIME_CONFORMANCE_LEDGER_IS_FAIL",
            "ROOT_ANALYZER_NOT_SANDBOXED",
            "NO_INSTALLER_AUTHORITY",
        ):
            self.assertIn(limitation, retention["limitations"])

    def _running_python(self, executable: Path, *, isolated: bool):
        flags = SimpleNamespace(
            dont_write_bytecode=int(isolated),
            isolated=int(isolated),
            no_site=int(isolated),
        )
        return mock.patch.multiple(
            self.launcher.sys,
            executable=str(executable),
            flags=flags,
        )


if __name__ == "__main__":
    unittest.main()
