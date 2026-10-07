"""One focused fixed-task contract check; fixture guard is inert in this test."""

import hashlib
import json
import os
import stat
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

from aragorn import phase3_reference_tasks as tasks
from aragorn.oci_worker_protocol import canonical_json


class Phase3ReferenceTasksTests(unittest.TestCase):
    def test_four_exact_tasks_descriptors_and_copy_refusals(self):
        root = Path(__file__).resolve().parents[1]
        reviewed = json.loads(
            (root / "benchmark/phase3-reference-inputs/lab-data-v1.json").read_bytes()
        )
        source = (root / "src/aragorn/phase3_reference_tasks.py").read_bytes()
        inputs = tasks.reference_inputs()
        self.assertEqual(
            inputs,
            {
                key: reviewed["static_inputs"][key]["utf8"].encode("utf-8")
                for key in inputs
            },
        )
        descriptions = tasks.describe_tasks(source)
        self.assertEqual(
            set(descriptions),
            {
                "BENIGN_JSON_SUM",
                "BENIGN_LINE_COUNT",
                "BENIGN_SHA256",
                "BENIGN_COPY_READBACK",
            },
        )
        for key, descriptor in descriptions.items():
            self.assertEqual(
                descriptor["module_source_digest"],
                "sha256:" + hashlib.sha256(source).hexdigest(),
            )
            self.assertEqual(descriptor["entrypoint"], "execute_reference_task")
            raw = inputs[descriptor["input"]["ref"]]
            self.assertEqual(
                descriptor["input"]["digest"],
                "sha256:" + hashlib.sha256(raw).hexdigest(),
            )
            self.assertFalse(descriptor["paired_measurement_eligible"])
            self.assertFalse(descriptor["phase3_exit_eligible"])
            if key != "BENIGN_COPY_READBACK":
                result = tasks.execute_reference_task(key, raw)
                self.assertEqual(result["output"], descriptor["output"]["expected"])
                self.assertEqual(
                    result["output_digest"],
                    "sha256:"
                    + hashlib.sha256(canonical_json(result["output"])).hexdigest(),
                )
                self.assertFalse(result["paired_measurement_eligible"])
                self.assertFalse(result["phase3_exit_eligible"])
            with self.assertRaisesRegex(ValueError, "EXACT_REVIEWED_INPUT"):
                tasks.execute_reference_task(key, raw + b"x")
        with self.assertRaisesRegex(ValueError, "UNKNOWN_REFERENCE_TASK"):
            tasks.execute_reference_task("../other", b"")
        with self.assertRaisesRegex(ValueError, "SOURCE_BYTES_REQUIRED"):
            tasks.describe_tasks(b"")
        with self.assertRaisesRegex(ValueError, "UNEXPECTED_FIXTURE_ARGUMENTS"):
            tasks.execute_reference_task(
                "BENIGN_JSON_SUM", inputs["numbers_json"], copy_directory_fd=0
            )

        fixture, held, final_failure = {"owned": "test-double"}, MagicMock(), False

        @contextmanager
        def owned(expected):
            self.assertEqual(expected, fixture)
            yield held
            if final_failure:
                raise ValueError("TEST_FIXTURE_FINAL_GUARD_FAILED")

        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(tasks, "owned_http_fixture", owned),
        ):
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            # macOS temporary roots may inherit wheel rather than our group.
            # Model the fixture-owned directory required by the unchanged guard.
            os.chown(directory, -1, os.getegid())
            directory_fd = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                metadata = os.fstat(directory_fd)
                identity = {
                    "device": metadata.st_dev,
                    "inode": metadata.st_ino,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
                arguments = {
                    "copy_directory_fd": directory_fd,
                    "expected_copy_directory_identity": identity,
                    "expected_fixture": fixture,
                }
                raw = inputs["allowed_copy_text"]
                with self.assertRaisesRegex(ValueError, "DIRECTORY_CUSTODY_CHANGED"):
                    tasks.execute_reference_task(
                        "BENIGN_COPY_READBACK",
                        raw,
                        **{
                            **arguments,
                            "expected_copy_directory_identity": {
                                **identity,
                                "inode": identity["inode"] + 1,
                            },
                        },
                    )
                self.assertFalse((directory / tasks.COPY_TARGET).exists())
                result = tasks.execute_reference_task(
                    "BENIGN_COPY_READBACK", raw, **arguments
                )
                self.assertEqual(
                    result["output"],
                    descriptions["BENIGN_COPY_READBACK"]["output"]["expected"],
                )
                self.assertFalse(result["paired_measurement_eligible"])
                self.assertFalse(result["phase3_exit_eligible"])
                self.assertEqual((directory / tasks.COPY_TARGET).read_bytes(), raw)
                self.assertEqual(os.fstat(directory_fd).st_ino, metadata.st_ino)
                with self.assertRaises(FileExistsError):
                    tasks.execute_reference_task(
                        "BENIGN_COPY_READBACK", raw, **arguments
                    )
                self.assertEqual((directory / tasks.COPY_TARGET).read_bytes(), raw)
                (
                    directory / tasks.COPY_TARGET
                ).unlink()  # Test owns this scratch directory.
                outside = directory / "must-not-touch"
                outside.write_bytes(b"retained")
                (directory / tasks.COPY_TARGET).symlink_to(outside)
                with self.assertRaises(FileExistsError):
                    tasks.execute_reference_task(
                        "BENIGN_COPY_READBACK", raw, **arguments
                    )
                self.assertEqual(outside.read_bytes(), b"retained")
                (directory / tasks.COPY_TARGET).unlink()
                final_failure = True
                with self.assertRaisesRegex(
                    ValueError, "TEST_FIXTURE_FINAL_GUARD_FAILED"
                ):
                    tasks.execute_reference_task(
                        "BENIGN_COPY_READBACK", raw, **arguments
                    )
                self.assertEqual((directory / tasks.COPY_TARGET).read_bytes(), raw)
                held.guard.assert_called()
            finally:
                os.close(directory_fd)
