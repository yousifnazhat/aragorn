from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from scripts.verify_build_inputs import tree_digest

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = (
    _ROOT
    / "packaging"
    / "libexec"
    / "aragorn-protected-install-launcher.py"
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


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


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
