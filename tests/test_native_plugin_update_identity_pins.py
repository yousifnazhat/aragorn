"""Only the offline historical-pin preparer; no binary or capture execution."""

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from scripts import prepare_native_plugin_update_identity_pins as subject


class NativePluginUpdateIdentityPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.capture = (subject._ROOT / subject._CAPTURE).read_bytes()
        cls.image = (subject._ROOT / subject._IMAGE_RECORD).read_bytes()

    def invoke(self, *args):
        output = StringIO()
        with redirect_stdout(output):
            code = subject.main(list(args))
        return code, json.loads(output.getvalue())

    def test_real_pinned_records_prepare_exact_eleven_with_historical_ceiling(self):
        manifest, provenance = subject.prepare_pin_documents(self.capture, self.image)
        self.assertEqual(set(manifest), {"schema", "file_digests"})
        self.assertEqual(len(manifest["file_digests"]), 11)
        self.assertEqual(manifest["file_digests"]["/usr/local/bin/node"], subject._NODE)
        self.assertEqual(
            manifest["file_digests"]["/usr/local/bin/python3.12"], subject._PYTHON
        )
        self.assertEqual(len(provenance["selected_profile"]["selected_files"]), 8)
        self.assertEqual(
            provenance["records"]["native_update"]["digest"], subject._CAPTURE_PIN[1]
        )
        self.assertEqual(
            provenance["records"]["exact_image"]["digest"], subject._IMAGE_PIN[1]
        )
        self.assertFalse(provenance["current_image_verified"])
        self.assertFalse(provenance["live_deployment_attested"])
        self.assertFalse(provenance["source_signature_verified"])
        self.assertFalse(provenance["phase3_eligible"])

    def test_changed_or_malformed_records_and_source_fields_refuse(self):
        for capture, image in (
            (b"{}\n", self.image),
            (self.capture, self.image + b" "),
            (self.capture[:-1], self.image),
        ):
            with (
                self.subTest(raw=capture[:10]),
                self.assertRaises(subject.PinPreparationError),
            ):
                subject.prepare_pin_documents(capture, image)
        mutations = (
            lambda c: c["source"].update(commit="0" * 40),
            lambda c: c.update(status="REFUSED"),
            lambda c: c["staged_profile"]["files"][
                next(
                    i
                    for i, item in enumerate(c["staged_profile"]["files"])
                    if item["path"] in subject._SELECTED
                )
            ].update(source_name="wrong/source.py"),
        )
        for mutate in mutations:
            changed = json.loads(self.capture)
            mutate(changed)
            raw = subject.binding.canonical_json(changed) + b"\n"
            with (
                self.subTest(mutation=mutate),
                patch.object(
                    subject, "_CAPTURE_PIN", (len(raw), subject.binding._digest(raw))
                ),
                self.assertRaises(subject.PinPreparationError),
            ):
                subject.prepare_pin_documents(raw, self.image)

    def test_binary_pin_custody_and_exact_image_joins_refuse_rebound_records(self):
        mutations = (
            lambda c: c["harness"]["document"].update(image_id="sha256:" + "0" * 64),
            lambda c: c["composition"]["action"]["harness"]["document"].update(
                source_commit="0" * 40
            ),
            lambda c: c["composition"]["action"]["profiles"]["executables"][
                "node"
            ].update(digest="sha256:" + "0" * 64),
            lambda c: c["composition"]["action"]["profiles"]["executables"][
                "worker_python"
            ]["stat"].update(nlink=2),
        )
        for mutate in mutations:
            changed = json.loads(self.image)
            mutate(changed)
            raw = subject.binding.canonical_json(changed) + b"\n"
            with (
                self.subTest(mutation=mutate),
                patch.object(
                    subject, "_IMAGE_PIN", (len(raw), subject.binding._digest(raw))
                ),
                self.assertRaises(subject.PinPreparationError),
            ):
                subject.prepare_pin_documents(self.capture, raw)

    def test_cli_exclusive_paths_outputs_and_help_are_offline(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest, provenance = root / "pins.json", root / "provenance.json"
            args = (
                "prepare",
                "--out",
                str(manifest),
                "--provenance-out",
                str(provenance),
            )
            code, result = self.invoke(*args)
            self.assertEqual((code, result["status"]), (0, "PREPARED"))
            raw, report = manifest.read_bytes(), provenance.read_bytes()
            self.assertFalse(raw.endswith(b"\n"))
            self.assertEqual(subject.binding._digest(raw), result["manifest"]["digest"])
            self.assertEqual(
                json.loads(report)["static_pin_manifest_digest"],
                result["manifest"]["digest"],
            )
            self.assertEqual(self.invoke(*args)[0], 2)
            self.assertEqual(
                (manifest.read_bytes(), provenance.read_bytes()), (raw, report)
            )
            absent = root / "absent.json"
            self.assertEqual(
                self.invoke(
                    "prepare", "--out", str(absent), "--provenance-out", str(provenance)
                )[0],
                2,
            )
            self.assertFalse(absent.exists())
            self.assertEqual(
                self.invoke(
                    "prepare", "--out", str(absent), "--provenance-out", str(absent)
                )[0],
                2,
            )
            link = root / "link"
            link.symlink_to(root, target_is_directory=True)
            self.assertEqual(
                self.invoke(
                    "prepare",
                    "--out",
                    str(link / "new.json"),
                    "--provenance-out",
                    str(absent),
                )[0],
                2,
            )
            self.assertFalse(absent.exists())
            partial_manifest, partial_provenance = (
                root / "partial-pins.json",
                root / "partial-provenance.json",
            )
            write = subject._write_new

            def fail_second(parent, name, data):
                if name == partial_manifest.name:
                    raise OSError("controlled second-output failure")
                return write(parent, name, data)

            with patch.object(subject, "_write_new", side_effect=fail_second):
                self.assertEqual(
                    self.invoke(
                        "prepare",
                        "--out",
                        str(partial_manifest),
                        "--provenance-out",
                        str(partial_provenance),
                    )[0],
                    2,
                )
            self.assertFalse(partial_manifest.exists())
            self.assertTrue(partial_provenance.exists())
            with (
                patch.object(
                    subject,
                    "_read_fixed",
                    side_effect=AssertionError("help read evidence"),
                ),
                redirect_stdout(StringIO()),
                self.assertRaises(SystemExit) as help_exit,
            ):
                subject.main(["--help"])
            self.assertEqual(help_exit.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
