from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_INSTALLER = _ROOT / "packaging/install-runtime-action-worker-host.sh"
_BASE_INSTALLER = _ROOT / "packaging/install-runtime-capability-host.sh"
_PLUGIN = _ROOT / "packaging/openclaw/aragorn-runtime-action-worker"


class RuntimeActionWorkerInstallTests(unittest.TestCase):
    def test_installer_stages_exact_inert_worker_files(self) -> None:
        self.assertEqual(stat.S_IMODE(_INSTALLER.stat().st_mode), 0o755)
        subprocess.run(
            ["sh", "-n", str(_INSTALLER)],
            check=True,
            capture_output=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            subprocess.run(
                ["sh", str(_INSTALLER)],
                check=True,
                cwd=_ROOT,
                env={**os.environ, "DESTDIR": temporary},
                capture_output=True,
            )
            plugin = staged / "usr/lib/aragorn/openclaw/aragorn-runtime-action-worker"
            expected = {
                staged / "usr/lib/aragorn/aragorn/runtime_action_worker.py": (
                    _ROOT / "src/aragorn/runtime_action_worker.py",
                    0o644,
                ),
                staged
                / "usr/libexec/aragorn/aragorn-runtime-action-worker-service.py": (
                    _ROOT
                    / "packaging/libexec/aragorn-runtime-action-worker-service.py",
                    0o755,
                ),
                staged
                / "usr/lib/systemd/system/aragorn-runtime-action-worker.service": (
                    _ROOT / "packaging/systemd/aragorn-runtime-action-worker.service",
                    0o644,
                ),
                staged / "usr/lib/sysusers.d/aragorn-runtime-action-worker.conf": (
                    _ROOT / "packaging/systemd/aragorn-runtime-action-worker.sysusers",
                    0o644,
                ),
                plugin / "index.js": (_PLUGIN / "index.js", 0o644),
                plugin / "openclaw.plugin.json": (
                    _PLUGIN / "openclaw.plugin.json",
                    0o644,
                ),
                plugin / "package.json": (_PLUGIN / "package.json", 0o644),
            }
            self.assertEqual(
                {path.name for path in plugin.iterdir()},
                {"index.js", "openclaw.plugin.json", "package.json"},
            )
            self.assertEqual(
                stat.S_IMODE(plugin.parent.stat().st_mode),
                0o755,
            )
            self.assertEqual(stat.S_IMODE(plugin.stat().st_mode), 0o755)
            for installed, (source, mode) in expected.items():
                with self.subTest(installed=installed):
                    self.assertEqual(installed.read_bytes(), source.read_bytes())
                    self.assertEqual(stat.S_IMODE(installed.stat().st_mode), mode)

    def test_installer_has_no_activation_or_configuration_side_effect(self) -> None:
        for installer in (_INSTALLER, _BASE_INSTALLER):
            source = installer.read_text(encoding="utf-8")
            for forbidden in (
                "/etc/",
                "systemctl",
                "systemd-sysusers",
                "systemd-tmpfiles",
            ):
                with self.subTest(installer=installer, forbidden=forbidden):
                    self.assertNotIn(forbidden, source)

        worker_source = _INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("activate-runtime", worker_source)

        with tempfile.TemporaryDirectory() as temporary:
            staged = Path(temporary)
            config_root = staged / "etc/aragorn"
            config_root.mkdir(parents=True)
            sentinel = config_root / "runtime-action-worker.json"
            sentinel.write_bytes(b"operator-owned-sentinel\n")
            sentinel.chmod(0o600)
            subprocess.run(
                ["sh", str(_INSTALLER)],
                check=True,
                cwd=_ROOT,
                env={**os.environ, "DESTDIR": temporary},
                capture_output=True,
            )
            self.assertEqual(sentinel.read_bytes(), b"operator-owned-sentinel\n")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o600)
            self.assertEqual(list(config_root.iterdir()), [sentinel])
            self.assertFalse((staged / "run").exists())
            self.assertFalse((staged / "var").exists())
            self.assertFalse((staged / "opt").exists())
            self.assertFalse(
                any(
                    path.is_symlink()
                    for path in (staged / "usr/lib/systemd/system").iterdir()
                )
            )


if __name__ == "__main__":
    unittest.main()
