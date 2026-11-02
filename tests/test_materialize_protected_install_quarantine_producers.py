from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aragorn import protected_install_namespace_v2, protected_install_v2
from aragorn.protected_install import ProtectedInstallTransactionError
from scripts import materialize_protected_install_quarantine_producers as subject
from tests.test_protected_install_namespace_v2 import _publish

_ROOT = Path(__file__).resolve().parents[1]


def _load(path):
    spec = importlib.util.spec_from_file_location("quarantine_producer_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # This source-only overlay intentionally lacks src/. Use the checkout for
    # this in-process test, and undo the frozen producer's sys.path insertion.
    before = sys.path[:]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = before
    return module


def _fixture_args(producer, root):
    protected = root / "protected"
    protected.mkdir(mode=0o700)
    return producer._parser().parse_args(
        [
            "--cas-root",
            str(root / "cas"),
            "--protected-root",
            str(protected),
            "--expected-broker-uid",
            str(os.geteuid()),
            "--now-unix",
            "100",
            "--expires-at-unix",
            "200",
            "--target-runtime-digest",
            "sha256:" + "a" * 64,
            "--runtime-conformance-digest",
            "sha256:" + "b" * 64,
        ]
    )


def _copy_inputs(root):
    for name in (*subject._PRODUCERS, *subject._DEPENDENCIES):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_ROOT / name, path)


class ProtectedInstallProducerOverlayTests(unittest.TestCase):
    def test_exact_sources_outputs_dependencies_and_overlay_ceiling(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "overlay"
            manifest = subject.materialize_protected_install_quarantine_producers(
                output
            )
            self.assertEqual(manifest["schema"], subject._SCHEMA)
            self.assertEqual(manifest["authority"], subject._AUTHORITY)
            self.assertIs(manifest["standalone_executable"], False)
            self.assertIs(manifest["production_activation_eligible"], False)
            self.assertIs(manifest["runtime_startup_enforcement"], False)
            self.assertIn(
                "complete src/aragorn package", manifest["missing_release_inputs"][0]
            )
            self.assertFalse((output / "src").exists())
            self.assertFalse((output / "requirements-worker.lock").exists())
            self.assertEqual(
                sorted(
                    path.relative_to(output).as_posix()
                    for path in output.rglob("*")
                    if path.is_file()
                ),
                sorted(subject._PRODUCERS),
            )
            for item in manifest["files"]:
                source = (_ROOT / item["name"]).read_bytes()
                rendered = (output / item["name"]).read_bytes()
                self.assertEqual(subject._digest(source), item["source_digest"])
                self.assertEqual(len(source), item["source_bytes"])
                self.assertEqual(subject._digest(rendered), item["digest"])
                self.assertEqual(len(rendered), item["bytes"])
                self.assertEqual(rendered, subject._transform(source))
                self.assertEqual(
                    stat.S_IMODE((output / item["name"]).stat().st_mode), 0o444
                )
                producer = _load(output / item["name"])
                self.assertEqual(producer._REPOSITORY, output)
                self.assertIs(
                    producer._publish_protected_install_transaction,
                    protected_install_v2._publish_protected_install_transaction,
                )
                self.assertIs(
                    producer.protected_root_entries,
                    protected_install_namespace_v2.protected_root_entries,
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

    def test_both_generated_producers_run_inert_fixture_and_deny_same_skill_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            overlay = base / "overlay"
            subject.materialize_protected_install_quarantine_producers(overlay)
            for index, name in enumerate(subject._PRODUCERS):
                with self.subTest(producer=name):
                    producer = _load(overlay / name)
                    first = base / f"first-{index}"
                    first.mkdir()
                    args = _fixture_args(producer, first)
                    result = producer._run(args)
                    self.assertEqual(result["slice_status"], "PASS")
                    self.assertIs(result["decision"]["installer_work_eligible"], False)
                    root = Path(args.protected_root)
                    skill_digest = (
                        "sha256:"
                        + hashlib.sha256(
                            (root / producer._TARGET / "SKILL.md").read_bytes()
                        ).hexdigest()
                    )
                    _publish(root, skill_digest)
                    # Both existing published/update inventories accept only the
                    # newly validated record, without deleting installed evidence.
                    producer._require_update_protected_root(root, os.geteuid())
                    producer._require_published_protected_root(
                        root, os.geteuid(), result["transactions"][-1]
                    )
                    (root / "unexpected").write_bytes(b"residue")
                    with self.assertRaises(producer.BrokerConformanceError):
                        producer._require_update_protected_root(root, os.geteuid())
                    second = base / f"second-{index}"
                    second.mkdir()
                    denied = _fixture_args(producer, second)
                    denied_root = Path(denied.protected_root)
                    _publish(denied_root, skill_digest)
                    before = sorted(path.name for path in denied_root.iterdir())
                    with self.assertRaisesRegex(
                        ProtectedInstallTransactionError,
                        "before consuming.*installed skill digest is quarantined",
                    ):
                        producer._run(denied)
                    self.assertEqual(
                        sorted(path.name for path in denied_root.iterdir()), before
                    )

    def test_changed_input_or_dependency_never_creates_output(self):
        for name in (*subject._PRODUCERS, *subject._DEPENDENCIES):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(b"!" + raw[1:])
                output = root / "overlay"
                with (
                    mock.patch.object(subject, "_ROOT", root),
                    self.assertRaises(subject.ProducerOverlayError),
                ):
                    subject.materialize_protected_install_quarantine_producers(output)
                self.assertFalse(output.exists())

    def test_replacement_counts_and_output_pins_are_independently_enforced(self):
        raw = (_ROOT / next(iter(subject._PRODUCERS))).read_bytes()
        for old, _new, expected_count in subject._REPLACEMENTS:
            self.assertEqual(raw.count(old), expected_count)
            for changed in (raw.replace(old, b"changed", 1), raw + b"\n" + old):
                with self.assertRaisesRegex(
                    subject.ProducerOverlayError, "shape changed"
                ):
                    subject._transform(changed)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "overlay"
            with (
                mock.patch.object(subject, "_transform", side_effect=lambda raw: raw),
                self.assertRaisesRegex(
                    subject.ProducerOverlayError, "rendered producer"
                ),
            ):
                subject.materialize_protected_install_quarantine_producers(output)
            self.assertFalse(output.exists())

    def test_source_symlink_and_fifo_are_rejected_without_blocking(self):
        for kind in ("symlink", "fifo"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                path = root / next(iter(subject._PRODUCERS))
                path.unlink()
                if kind == "symlink":
                    path.symlink_to(_ROOT / next(iter(subject._PRODUCERS)))
                else:
                    os.mkfifo(path, 0o444)
                # A regression to blocking open must terminate within this bound.
                script = (
                    "import sys\nfrom pathlib import Path\n"
                    "from scripts import materialize_protected_install_quarantine_producers as m\n"
                    "m._ROOT=Path(sys.argv[1])\n"
                    "try: m.materialize_protected_install_quarantine_producers(m._ROOT/'overlay')\n"
                    "except m.ProducerOverlayError: pass\n"
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

    def test_existing_output_and_partial_write_never_report_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for output in (root, root / "alias"):
                if output != root:
                    output.symlink_to(root)
                with self.assertRaises(subject.ProducerOverlayError):
                    subject.materialize_protected_install_quarantine_producers(output)
            for phase in ("zero-write", "wrong-bytes", "sync-failure"):
                output = root / phase
                write = os.write

                def wrong_bytes(fd, raw, write=write):
                    return write(fd, b"x" * len(raw))

                failure = (
                    mock.patch.object(subject.os, "write", return_value=0)
                    if phase == "zero-write"
                    else mock.patch.object(subject.os, "write", side_effect=wrong_bytes)
                    if phase == "wrong-bytes"
                    else mock.patch.object(
                        subject.os, "fsync", side_effect=OSError("sync failed")
                    )
                )
                with failure, self.assertRaises(subject.ProducerOverlayError):
                    subject.materialize_protected_install_quarantine_producers(output)


if __name__ == "__main__":
    unittest.main()
