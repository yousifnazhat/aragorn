from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import materialize_runtime_quarantine_services as subject

_ROOT = Path(__file__).resolve().parents[1]


def _copy_inputs(root: Path) -> None:
    for name in (*subject._SERVICES, *subject._DEPENDENCIES):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / name, path)


class RuntimeQuarantineServiceOverlayTests(unittest.TestCase):
    def test_exact_source_only_manifest_outputs_and_read_only_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "overlay"
            manifest = subject.materialize_runtime_quarantine_services(output)
            self.assertEqual(manifest["schema"], subject._SCHEMA)
            self.assertEqual(manifest["authority"], subject._AUTHORITY)
            self.assertEqual(
                set(manifest),
                {
                    "schema",
                    "authority",
                    "files",
                    "required_checkout_dependencies_not_included",
                    "standalone_executable",
                    "production_activation_eligible",
                    "runtime_startup_enforcement",
                    "missing_release_inputs",
                },
            )
            for key in (
                "standalone_executable",
                "production_activation_eligible",
                "runtime_startup_enforcement",
            ):
                self.assertIs(manifest[key], False)
            self.assertIn(
                "complete src/aragorn package", manifest["missing_release_inputs"][0]
            )
            self.assertIn("startup byte gate", manifest["missing_release_inputs"][-1])
            self.assertEqual(len(manifest["files"]), 3)
            self.assertEqual(
                sorted(
                    path.relative_to(output).as_posix()
                    for path in output.rglob("*")
                    if path.is_file()
                ),
                sorted(subject._SERVICES),
            )
            self.assertFalse((output / "src/aragorn/__init__.py").exists())
            self.assertFalse((output / "requirements-worker.lock").exists())
            for item in manifest["files"]:
                source = (_ROOT / item["name"]).read_bytes()
                rendered = (output / item["name"]).read_bytes()
                self.assertEqual(
                    item,
                    {
                        "name": item["name"],
                        "source_bytes": len(source),
                        "source_digest": subject.overlay._digest(source),
                        "bytes": len(rendered),
                        "digest": subject.overlay._digest(rendered),
                    },
                )
                self.assertEqual(rendered, subject._transform(source))
                self.assertEqual(
                    stat.S_IMODE((output / item["name"]).stat().st_mode), 0o444
                )
            for path in (output, *(p for p in output.rglob("*") if p.is_dir())):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)
            self.assertEqual(
                manifest["required_checkout_dependencies_not_included"],
                [
                    {"name": name, "bytes": size, "digest": digest}
                    for name, (size, digest) in subject._DEPENDENCIES.items()
                ],
            )
            self.assertTrue(
                all(not (output / name).exists() for name in subject._DEPENDENCIES)
            )

    def test_fresh_package_imports_rendered_services_and_preserves_regressions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            output = base / "overlay"
            subject.materialize_runtime_quarantine_services(output)
            # This complete current package exists only in the test fixture. It
            # is not a bound release or an installed service deployment.
            package_src = base / "fixture/src"
            shutil.copytree(
                _ROOT / "src/aragorn",
                package_src / "aragorn",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            for name in subject._SERVICES:
                shutil.copyfile(output / name, base / "fixture" / name)
            script = """
import json
import sys
import unittest
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import aragorn
from aragorn import runtime_action_broker_v5 as broker
from aragorn import runtime_action_observation_publisher_v4 as sensor
from aragorn import runtime_lineage_capability_issuer as issuer
from aragorn import runtime_active_skill_lineage as legacy
from aragorn import runtime_active_skill_lineage_v2 as successor
package = Path(sys.argv[1]) / 'aragorn'
assert Path(aragorn.__file__).resolve() == package / '__init__.py'
for module in (broker, sensor, issuer, legacy, successor):
    assert Path(module.__file__).resolve() == package / (module.__name__.split('.')[-1] + '.py')
assert broker.hold_runtime_active_skill_lineage is successor.hold_runtime_active_skill_lineage
assert issuer.hold_runtime_active_skill_lineage is successor.hold_runtime_active_skill_lineage
assert sensor.verify_runtime_active_skill_lineage is successor.verify_runtime_active_skill_lineage
assert sensor.hold_profiled_runtime_capability_issuance is issuer.hold_profiled_runtime_capability_issuance
assert broker.hold_runtime_active_skill_lineage is not legacy.hold_runtime_active_skill_lineage
assert sensor.verify_runtime_active_skill_lineage is not legacy.verify_runtime_active_skill_lineage
for module in (broker, sensor, issuer):
    assert module.DEFAULT_PROTECTED_INSTALL_ROOT is legacy.DEFAULT_PROTECTED_INSTALL_ROOT
suite = unittest.defaultTestLoader.loadTestsFromNames([
    'tests.test_runtime_action_broker_v5',
    'tests.test_runtime_action_observation_publisher_v4',
    'tests.test_runtime_active_skill_lineage_v2',
])
result = unittest.TextTestRunner(verbosity=0).run(suite)
assert result.wasSuccessful() and not result.skipped and result.testsRun >= 14
print(json.dumps({'rendered_imports': 3, 'tests_run': result.testsRun}))
"""
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-W",
                    "error::ResourceWarning",
                    "-c",
                    script,
                    str(package_src),
                    str(_ROOT),
                ],
                cwd=base,
                capture_output=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            proof = json.loads(result.stdout)
            self.assertEqual(proof["rendered_imports"], 3)
            self.assertGreaterEqual(proof["tests_run"], 14)

    def test_source_or_dependency_drift_never_creates_output(self) -> None:
        for name in (*subject._SERVICES, *subject._DEPENDENCIES):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(b"!" + raw[1:])
                output = root / "overlay"
                with (
                    mock.patch.object(subject, "_ROOT", root),
                    self.assertRaises(subject.RuntimeQuarantineOverlayError),
                ):
                    subject.materialize_runtime_quarantine_services(output)
                self.assertFalse(output.exists())

    def test_exact_one_import_split_and_output_pins_are_independent(self) -> None:
        for name in subject._SERVICES:
            with self.subTest(name=name):
                raw = (_ROOT / name).read_bytes()
                start = raw.index(b"from .runtime_active_skill_lineage import (\n")
                end = raw.index(b"\n)", start) + 2
                block = raw[start:end]
                self.assertEqual(raw.count(block), 1)
                for changed in (raw.replace(block, b"changed", 1), raw + b"\n" + block):
                    with self.assertRaisesRegex(
                        subject.RuntimeQuarantineOverlayError, "shape changed"
                    ):
                        subject._transform(changed)
                rendered = subject._transform(raw)
                function = (
                    b"verify_runtime_active_skill_lineage"
                    if b"verify_runtime_active_skill_lineage" in block
                    else b"hold_runtime_active_skill_lineage"
                )
                self.assertEqual(
                    rendered,
                    raw.replace(
                        block,
                        b"from .runtime_active_skill_lineage import DEFAULT_PROTECTED_INSTALL_ROOT\n"
                        b"from .runtime_active_skill_lineage_v2 import " + function,
                    ),
                )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "overlay"
            with (
                mock.patch.object(subject, "_transform", side_effect=lambda raw: raw),
                self.assertRaisesRegex(
                    subject.RuntimeQuarantineOverlayError, "rendered runtime"
                ),
            ):
                subject.materialize_runtime_quarantine_services(output)
            self.assertFalse(output.exists())

    def test_symlink_fifo_and_hardlinked_sources_reject_without_blocking(self) -> None:
        for kind in ("symlink", "fifo", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                name = next(iter(subject._SERVICES))
                path = root / name
                if kind == "hardlink":
                    os.link(path, root / "second-link")
                else:
                    path.unlink()
                    if kind == "symlink":
                        path.symlink_to(_ROOT / name)
                    else:
                        os.mkfifo(path, 0o444)
                script = (
                    "import sys\nfrom pathlib import Path\n"
                    "from scripts import materialize_runtime_quarantine_services as m\n"
                    "m._ROOT=Path(sys.argv[1])\n"
                    "try: m.materialize_runtime_quarantine_services(m._ROOT/'overlay')\n"
                    "except m.RuntimeQuarantineOverlayError: pass\n"
                    "else: raise SystemExit(1)\n"
                )
                result = subprocess.run(
                    [sys.executable, "-B", "-c", script, str(root)],
                    cwd=_ROOT,
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertFalse((root / "overlay").exists())

    def test_existing_output_and_partial_failures_never_report_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            alias = root / "alias"
            alias.symlink_to(root)
            for output in (root, alias, str(root / "not-a-Path")):
                with (
                    self.subTest(output=output),
                    self.assertRaises(subject.RuntimeQuarantineOverlayError),
                ):
                    subject.materialize_runtime_quarantine_services(output)
            for phase in ("zero-write", "wrong-bytes", "sync-failure"):
                output = root / phase
                write = os.write

                def wrong_bytes(fd, raw, write=write):
                    return write(fd, b"x" * len(raw))

                failure = (
                    mock.patch.object(subject.overlay.os, "write", return_value=0)
                    if phase == "zero-write"
                    else mock.patch.object(
                        subject.overlay.os, "write", side_effect=wrong_bytes
                    )
                    if phase == "wrong-bytes"
                    else mock.patch.object(
                        subject.overlay.os, "fsync", side_effect=OSError("sync failed")
                    )
                )
                with (
                    self.subTest(phase=phase),
                    failure,
                    self.assertRaises(subject.RuntimeQuarantineOverlayError),
                ):
                    subject.materialize_runtime_quarantine_services(output)


if __name__ == "__main__":
    unittest.main()
