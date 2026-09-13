from __future__ import annotations

import contextlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import stage_runtime_endpoint_journal_profile as subject

_ROOT = Path(__file__).resolve().parents[1]


def _copy_inputs(root: Path) -> None:
    for name in subject._SOURCE_PINS:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((_ROOT / name).read_bytes())


@contextlib.contextmanager
def _source_root(root: Path):
    with contextlib.ExitStack() as stack:
        for module in (subject, subject.base, subject.journal):
            stack.enter_context(mock.patch.object(module, "_ROOT", root))
        yield


class RuntimeEndpointJournalStageTests(unittest.TestCase):
    def test_exact_55_file_stage_preserves_quarantine_and_is_deterministic(self):
        original, replacements = subject._verified_payloads()
        final = original | replacements
        self.assertEqual((len(original), len(replacements), len(final)), (54, 5, 55))
        expected_changes = {
            subject.base._destination(name)[0]
            for name in (
                subject.journal._WORKER,
                subject.journal._SENSOR,
                subject.journal._BROKER,
                subject.journal._HELPER,
                subject.base.activation._ACTIVATOR,
            )
        }
        self.assertEqual(set(replacements), expected_changes)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "stage"
            report = subject.stage_runtime_endpoint_journal_profile(output)
            self.assertEqual(
                report, subject.stage_runtime_endpoint_journal_profile(root / "second")
            )
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertEqual(report["authority"], subject._AUTHORITY)
            self.assertEqual(len(report["files"]), 55)
            self.assertEqual(len(report["new_dependencies"]), 10)
            self.assertEqual(len(report["base_inputs"]), 47)
            self.assertEqual(len(report["directories"]), 12)
            self.assertEqual(len(report["source_inputs"]), len(subject._SOURCE_PINS))
            for field in (
                "root_deployment",
                "production_activation_eligible",
                "runtime_startup_enforcement",
                "quarantine_response_deployed",
                "producer_release_included",
                "phase3_qualification",
                "runtime_journal_deployed",
                "durable_event_retention",
                "run_qualification",
            ):
                self.assertIs(report[field], False)
            for entry in report["files"]:
                name = entry["path"].removeprefix("/")
                source, mode, raw = final[name]
                path = output / name
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(entry["source_name"], source)
                self.assertEqual(entry["bytes"], len(raw))
                self.assertEqual(entry["digest"], subject.base.overlay._digest(raw))
                self.assertEqual(entry["mode"], f"{mode:04o}")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                self.assertEqual(
                    (path.stat().st_uid, path.stat().st_nlink), (os.geteuid(), 1)
                )
            preserved = (
                subject.journal._ISSUER,
                subject.base.activation._UNIT,
                *subject.base.activation._DEPENDENCIES,
            )
            for name in preserved:
                destination, _ = subject.base._destination(name)
                self.assertEqual(final[destination], original[destination])
            self.assertEqual(
                {path.name for path in root.iterdir()}, {"stage", "second"}
            )
            self.assertFalse((output / "etc").exists())
            self.assertFalse((output / "var").exists())

    def test_activator_has_only_three_pin_replacements_and_one_helper_line(self):
        original, replacements = subject._verified_payloads()
        name = subject.base.activation._ACTIVATOR
        destination, _ = subject.base._destination(name)
        before, after = original[destination][2], replacements[destination][2]
        self.assertEqual(
            (len(before), subject.base.overlay._digest(before)),
            (
                34705,
                "sha256:c01ae51517f7d51428dbbf336eee1cb5213d2e5991ea7b3e7ac9cbc2dec8af8d",
            ),
        )
        self.assertEqual(
            (len(after), subject.base.overlay._digest(after)),
            (
                34827,
                "sha256:a98787da263dd3d01cb14ab31216cae0a67a0b9e56a616e7cf6a0bbb977e8392",
            ),
        )
        restored = after
        for source in (
            subject.journal._WORKER,
            subject.journal._SENSOR,
            subject.journal._BROKER,
        ):
            path, _ = subject.base._destination(source)
            old = subject._pin_line(
                source, subject.base.overlay._digest(original[path][2])
            ).encode()
            new = subject._pin_line(
                source, subject.base.overlay._digest(replacements[path][2])
            ).encode()
            self.assertEqual(restored.count(new), 1)
            self.assertNotIn(old, restored)
            restored = restored.replace(new, old)
        helper = subject._pin_line(
            subject.journal._HELPER, subject.journal._HELPER_PIN[1]
        ).encode()
        self.assertEqual(restored.count(helper), 1)
        self.assertEqual(restored.replace(helper, b""), before)
        shell = subprocess.run(
            ["/bin/sh", "-n"], input=after, capture_output=True, timeout=3, check=False
        )
        self.assertEqual(shell.returncode, 0, shell.stderr)
        for raw in (before + b"\n", before.replace(b"644 ", b"666 ", 1), after):
            with (
                self.subTest(raw_size=len(raw)),
                self.assertRaises(subject.RuntimeEndpointJournalStageError),
            ):
                subject._render_activator(raw)
        with (
            mock.patch.object(
                subject, "_ACTIVATOR_OUTPUT_PIN", (34827, "sha256:" + "0" * 64)
            ),
            self.assertRaises(subject.RuntimeEndpointJournalStageError),
        ):
            subject._render_activator(before)

    def test_invalid_destinations_and_source_drift_fail_before_base_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "existing").mkdir()
            (root / "alias").symlink_to(root / "existing", target_is_directory=True)
            for output in (
                "/not-a-Path",
                Path("relative"),
                root / "existing",
                root / "alias",
                root / "missing" / "stage",
                root / "alias" / "stage",
            ):
                with (
                    self.subTest(output=output),
                    mock.patch.object(
                        subject.base, "stage_runtime_quarantine_profile"
                    ) as stage,
                    self.assertRaises(subject.RuntimeEndpointJournalStageError),
                ):
                    subject.stage_runtime_endpoint_journal_profile(output)
                stage.assert_not_called()
            root.chmod(0o777)
            with (
                mock.patch.object(
                    subject.base, "stage_runtime_quarantine_profile"
                ) as stage,
                self.assertRaises(subject.RuntimeEndpointJournalStageError),
            ):
                subject.stage_runtime_endpoint_journal_profile(root / "unsafe")
            stage.assert_not_called()
            root.chmod(0o700)
        names = {
            *subject._SUPPORT_PINS,
            subject.journal._HELPER,
            subject.journal._WORKER,
            subject.journal._ISSUER,
            "src/aragorn/runtime_skill_startup.py",
        }
        for name in sorted(names):
            with self.subTest(source=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                path = root / name
                raw = path.read_bytes()
                path.write_bytes(b"!" + raw[1:])
                with (
                    _source_root(root),
                    mock.patch.object(
                        subject.base, "stage_runtime_quarantine_profile"
                    ) as stage,
                    self.assertRaises(subject.RuntimeEndpointJournalStageError),
                ):
                    subject.stage_runtime_endpoint_journal_profile(root / "stage")
                stage.assert_not_called()
                self.assertFalse((root / "stage").exists())

    def test_source_change_after_base_snapshot_never_returns_success(self):
        for name in (
            subject.journal._HELPER,
            "scripts/stage_runtime_quarantine_profile.py",
            subject.journal._WORKER,
        ):
            with self.subTest(source=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                _copy_inputs(root)
                apply = subject.base._apply_overrides

                def changed(output, replacements, name=name, root=root, apply=apply):
                    apply(output, replacements)
                    if len(replacements) == 5:
                        path = root / name
                        raw = path.read_bytes()
                        path.write_bytes(b"!" + raw[1:])

                with (
                    _source_root(root),
                    mock.patch.object(
                        subject.base, "_apply_overrides", side_effect=changed
                    ),
                    self.assertRaises(subject.RuntimeEndpointJournalStageError),
                ):
                    subject.stage_runtime_endpoint_journal_profile(root / "stage")
                self.assertTrue((root / "stage").is_dir())
                self.assertFalse(
                    any(
                        path.name.startswith(".aragorn-runtime-stage-")
                        for path in root.iterdir()
                    )
                )

    def test_final_readback_and_parent_custody_reject_partial_or_changed_output(self):
        for mutation in (
            "bytes",
            "mode",
            "hardlink",
            "symlink",
            "missing",
            "extra",
            "partial-write",
            "parent",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary).resolve()
                apply = subject.base._apply_overrides

                def changed(
                    output, replacements, mutation=mutation, root=root, apply=apply
                ):
                    if len(replacements) != 5:
                        return apply(output, replacements)
                    if mutation == "partial-write":
                        apply(output, dict(list(replacements.items())[:1]))
                        raise OSError("partial overlay")
                    apply(output, replacements)
                    target = (
                        output / subject.base._destination(subject.journal._HELPER)[0]
                    )
                    if mutation == "bytes":
                        target.write_bytes(b"changed")
                    elif mutation == "mode":
                        target.chmod(0o666)
                    elif mutation == "hardlink":
                        os.link(target, root / "outside-link")
                    elif mutation == "symlink":
                        target.unlink()
                        target.symlink_to(_ROOT / subject.journal._HELPER)
                    elif mutation == "missing":
                        target.unlink()
                    elif mutation == "extra":
                        (output / "extra").write_bytes(b"extra")
                    else:
                        root.chmod(0o777)

                with (
                    mock.patch.object(
                        subject.base, "_apply_overrides", side_effect=changed
                    ),
                    self.assertRaises(subject.RuntimeEndpointJournalStageError),
                ):
                    subject.stage_runtime_endpoint_journal_profile(root / "stage")
                root.chmod(0o700)
                self.assertFalse(
                    any(
                        path.name.startswith(".aragorn-runtime-stage-")
                        for path in root.iterdir()
                    )
                )

    def test_inherited_failures_and_interrupts_never_become_success(self):
        for error in (
            subject.base.RuntimeQuarantineStageError("base failed"),
            OSError("failed"),
            KeyboardInterrupt(),
        ):
            with (
                self.subTest(error=type(error).__name__),
                tempfile.TemporaryDirectory() as temporary,
            ):
                output = Path(temporary).resolve() / "stage"
                expected = (
                    KeyboardInterrupt
                    if isinstance(error, KeyboardInterrupt)
                    else subject.RuntimeEndpointJournalStageError
                )
                with (
                    mock.patch.object(
                        subject.base,
                        "stage_runtime_quarantine_profile",
                        side_effect=error,
                    ),
                    self.assertRaises(expected),
                    mock.patch.object(subject.base, "_apply_overrides") as apply,
                ):
                    subject.stage_runtime_endpoint_journal_profile(output)
                apply.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
