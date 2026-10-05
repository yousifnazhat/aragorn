"""Only the new inert common composition; no activation or measurement."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import stage_runtime_phase3_common_profile as subject


class Phase3CommonProfileTests(unittest.TestCase):
    def test_composition_preserves_effective_receipts_and_exact_admission_seals(self):
        original, replacements = subject._verified_payloads()
        gateway, _ = subject.admission._destination(subject.admission._GATEWAY)
        activator, _ = subject.admission._destination(subject.admission._ACTIVATOR)
        self.assertEqual(set(replacements), {gateway, activator})
        self.assertEqual(len(original | replacements), 73)
        self.assertEqual(
            replacements[gateway], subject.admission._verified_payloads()[1][gateway]
        )
        before, after = original[activator][2], replacements[activator][2]
        restored = after.replace(subject.admission._DIRECTORIES, b"").replace(
            subject.admission._CHECKS, b""
        )
        restored = restored.replace(
            subject.base.overlay._digest(replacements[gateway][2])[7:].encode(),
            subject.base.overlay._digest(original[gateway][2])[7:].encode(),
        )
        self.assertEqual(restored, before)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "common"
            report = subject.stage_runtime_phase3_common_profile(output)
            self.assertEqual(report["schema"], subject._SCHEMA)
            self.assertEqual(len(report["files"]), 73)
            self.assertEqual(len(report["directories"]), 16)
            for key in (
                "admission_qualified",
                "common_deployment_activated",
                "decision_measurement_deployed",
                "measurement_binding_provisioned",
                "measurement_collected",
                "phase3_qualification",
                "run_qualification",
            ):
                self.assertIs(report[key], False)
            self.assertEqual(
                report["discovery_read_only_paths"],
                list(subject.admission._DISCOVERY_READ_ONLY_PATHS),
            )
            files = {row["path"]: row for row in report["files"]}
            for name, pin in report["binding_source_pins"].items():
                row = next(
                    row
                    for row in report["files"]
                    if Path(row["source_name"]).name == name
                )
                self.assertEqual(row["digest"], pin)
            for row in report["new_dependencies"]:
                target, _ = subject.admission._destination(row["name"])
                self.assertEqual(
                    (row["bytes"], row["digest"]),
                    (files["/" + target]["bytes"], files["/" + target]["digest"]),
                )
            for path, expected in (original | replacements).items():
                self.assertEqual((output / path).read_bytes(), expected[2])
            subprocess.run(
                ["/bin/sh", "-n", str(output / activator)],
                check=True,
                timeout=10,
                capture_output=True,
            )

    def test_changed_anchor_or_source_pin_refuses_without_output(self):
        original, replacements = subject.effective._verified_payloads()
        final = original | replacements
        activator, _ = subject.admission._destination(subject.admission._ACTIVATOR)
        name, mode, raw = final[activator]
        altered = dict(final)
        altered[activator] = (
            name,
            mode,
            raw.replace(subject.admission._CHECK_ANCHOR, b"# missing anchor\n"),
        )
        with patch.object(
            subject.effective, "_verified_payloads", return_value=(altered, {})
        ):
            with self.assertRaises(subject.Phase3CommonStageError):
                subject._verified_payloads()
        read = subject.base.overlay._read_pinned

        def refuse(name, *args, **kwargs):
            if name == subject._EFFECTIVE:
                raise ValueError("inert changed source pin")
            return read(name, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "refused"
            with patch.object(subject.base.overlay, "_read_pinned", side_effect=refuse):
                with self.assertRaises(subject.Phase3CommonStageError):
                    subject.stage_runtime_phase3_common_profile(output)
            self.assertFalse(output.exists())
            with patch.object(
                subject.effective, "stage_runtime_broker_effective_receipt_profile"
            ) as stage:
                with self.assertRaises(subject.Phase3CommonStageError):
                    subject.stage_runtime_phase3_common_profile(
                        Path(temporary).resolve()
                    )
                stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
