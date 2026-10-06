"""Inert fixed-wrapper checks; native setup and protected reads are doubles.

No historical test class is inherited and no service, guest or clock is used.
The tests exercise the real orchestration and bounded allowlist export code.
"""

import ast
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import io
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import runtime_native_common_setup_capture as subject


CONTAINER = "c" * 64
PIN = "sha256:" + "b" * 64


class NativeCommonSetupCaptureTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.raws = {
            subject._IDENTITY._digest(raw): raw
            for raw in (b'{"public":1}', b'{"public":2}', b'{"public":3}')
        }
        self.candidates = [
            {"digest": pin, "bytes": len(raw)} for pin, raw in self.raws.items()
        ]
        self.sources = {
            name: name.encode("utf-8") for name in subject._CONTROLLER_PATHS
        }
        self.report = {
            "schema": subject.setup.SCHEMA,
            "authority": subject.setup.AUTHORITY,
            "status": "PREPARED_NOT_ACTIVATED",
            "container_id": CONTAINER,
            "public_blob_attempts": deepcopy(self.candidates),
            "preparation": {"retained_blob_digests": sorted(self.raws)},
            "setup_state": {"activation_count": 0},
            **dict.fromkeys(subject._FALSE, False),
        }

    def harness(self, stack, *, missing=None, store_close=False):
        self.environment = stack.enter_context(
            patch.object(
                subject.setup.predecessor,
                "_environment",
                side_effect=lambda *_: self.events.append("environment"),
            )
        )
        self.bundle = stack.enter_context(
            patch.object(
                subject,
                "_read_bundle",
                side_effect=lambda *_: (
                    self.events.append("bundle") or (b"bundle", {"identity": [1]})
                ),
            )
        )
        self.inspected = {
            "setup_arguments": {"expected_setup_digest": PIN},
            "source_raws": self.sources,
        }
        stack.enter_context(
            patch.object(
                subject.contract,
                "inspect_common_setup_inputs",
                return_value=self.inspected,
            )
        )

        def controller(name, raw):
            self.assertEqual(raw, self.sources[name])
            self.events.append("source:" + name)
            return {
                "digest": subject._IDENTITY._digest(raw),
                "bytes": len(raw),
                "identity": [1],
            }

        self.controller = stack.enter_context(
            patch.object(subject, "_read_controller", side_effect=controller)
        )
        self.prepare = stack.enter_context(
            patch.object(
                subject.setup,
                "prepare_common_native_setup",
                side_effect=lambda **_: (
                    self.events.append("setup") or deepcopy(self.report)
                ),
            )
        )

        @contextmanager
        def store():
            self.events.append("store")
            yield 91, lambda: self.events.append("guard")
            self.events.append("store-close")
            if store_close:
                raise OSError("private error must not escape")

        stack.enter_context(patch.object(subject, "_public_store", store))

        def read(descriptor, candidate):
            self.assertEqual(descriptor, 91)
            self.events.append("read:" + candidate["digest"])
            if candidate["digest"] == missing:
                raise FileNotFoundError("SECRET_CREDENTIAL_DIAGNOSTIC")
            return self.raws[candidate["digest"]]

        self.read = stack.enter_context(
            patch.object(subject, "_read_public_blob", side_effect=read)
        )

    def test_success_is_once_and_all_final_readbacks_follow_export(self):
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(result["status"], "PREPARED_NOT_ACTIVATED")
        self.prepare.assert_called_once_with(
            expected_container_id=CONTAINER, expected_setup_digest=PIN
        )
        self.assertEqual(self.read.call_count, 3)
        self.assertEqual(self.bundle.call_count, 2)
        self.assertEqual(self.controller.call_count, 4)
        self.assertEqual(
            result["controller_sources"], result["controller_sources_after"]
        )
        self.assertTrue(result["input_bundle_readback"])
        self.assertEqual(result["export_failures"], [])
        self.assertEqual(result["postcondition_failures"], [])
        self.assertEqual(
            {row["digest"]: row["text"].encode() for row in result["public_blobs"]},
            self.raws,
        )
        self.assertLess(self.events.index("store-close"), len(self.events) - 5)
        self.assertTrue(all(result[key] is False for key in subject._FALSE))

    def test_partial_setup_exports_every_journal_candidate_once_without_secret_text(
        self,
    ):
        self.report["status"] = "REFUSED"
        self.report["preparation"] = None
        missing = self.candidates[1]["digest"]
        with ExitStack() as stack:
            self.harness(stack, missing=missing)
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(
            result["refusal"], {"phase": "SETUP", "reason": "COMMON_SETUP_REFUSED"}
        )
        self.assertEqual(self.read.call_count, 3)
        self.assertEqual(
            [row["digest"] for row in result["public_blobs"]],
            [row["digest"] for row in self.candidates if row["digest"] != missing],
        )
        self.assertEqual(
            result["export_failures"],
            [{"digest": missing, "reason": "PUBLIC_BLOB_EXPORT_REFUSED"}],
        )
        self.assertNotIn(b"SECRET_CREDENTIAL", subject.canonical_json(result))

    def test_input_or_controller_refusal_does_not_call_setup(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.bundle.side_effect = OSError("SECRET")
            result = subject._run(CONTAINER, PIN)
        self.prepare.assert_not_called()
        self.read.assert_not_called()
        self.assertEqual(result["refusal"]["phase"], "INPUT_BUNDLE")
        with ExitStack() as stack:
            self.harness(stack)
            self.controller.side_effect = OSError("SECRET")
            result = subject._run(CONTAINER, PIN)
        self.prepare.assert_not_called()
        self.read.assert_not_called()
        self.assertEqual(self.controller.call_count, 3)
        self.assertEqual(
            result["postcondition_failures"],
            ["WRAPPER_SOURCE_AFTER", "CONTRACT_SOURCE_AFTER"],
        )
        self.assertNotIn(b"SECRET", subject.canonical_json(result))

    def test_final_readbacks_are_independent_and_preserve_original_refusal(self):
        self.report["status"] = "REFUSED"
        with ExitStack() as stack:
            self.harness(stack)
            self.bundle.side_effect = [
                (b"bundle", {}),
                OSError("private bundle detail"),
            ]
            original = self.controller.side_effect
            count = 0

            def sources(*args):
                nonlocal count
                count += 1
                if count == 3:
                    raise OSError("private wrapper detail")
                return original(*args)

            self.controller.side_effect = sources
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(
            result["refusal"], {"phase": "SETUP", "reason": "COMMON_SETUP_REFUSED"}
        )
        self.assertEqual(
            result["postcondition_failures"], ["BUNDLE_AFTER", "WRAPPER_SOURCE_AFTER"]
        )
        self.assertEqual(self.controller.call_count, 4)
        self.assertEqual(len(result["public_blobs"]), 3)

    def test_journal_bounds_exactness_and_complete_success_inventory(self):
        invalid = (
            self.candidates * 11,
            [self.candidates[0], self.candidates[0]],
            [{"digest": "../../private", "bytes": 1}],
            [{"digest": PIN, "bytes": True}],
            [{"digest": PIN, "bytes": subject.MAX_PUBLIC_BLOB + 1}],
            [{"digest": PIN, "bytes": 1, "path": "/private"}],
        )
        for rows in invalid:
            with self.subTest(rows=rows):
                with self.assertRaises(subject.NativeCommonSetupCaptureError):
                    subject._candidates(rows)
        self.report["preparation"]["retained_blob_digests"] = []
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(len(result["public_blobs"]), 3)

    def test_export_budget_and_final_store_failure_preserve_earlier_exports(self):
        with ExitStack() as stack:
            self.harness(stack)
            stack.enter_context(
                patch.object(subject, "MAX_PUBLIC_TOTAL", self.candidates[0]["bytes"])
            )
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(len(result["public_blobs"]), 1)
        self.assertEqual(len(result["export_failures"]), 2)
        self.assertEqual(self.read.call_count, 3)
        self.assertEqual(result["status"], "REFUSED")
        with ExitStack() as stack:
            self.harness(stack, store_close=True)
            result = subject._run(CONTAINER, PIN)
        self.assertEqual(len(result["public_blobs"]), 3)
        self.assertEqual(
            result["refusal"],
            {"phase": "EXPORT", "reason": "PUBLIC_CAS_CUSTODY_REFUSED"},
        )
        self.assertTrue(result["input_bundle_readback"])

    def test_blob_reader_uses_only_digest_path_and_rejects_unsafe_prefix(self):
        row = self.candidates[0]
        metadata = SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0, st_dev=1, st_ino=2
        )
        with ExitStack() as stack:
            opened = stack.enter_context(
                patch.object(subject.os, "open", return_value=90)
            )
            stack.enter_context(patch.object(subject.os, "stat", return_value=metadata))
            stack.enter_context(
                patch.object(subject.os, "fstat", return_value=metadata)
            )
            closed = stack.enter_context(patch.object(subject.os, "close"))
            read = stack.enter_context(
                patch.object(
                    subject._IDENTITY,
                    "_read_at",
                    return_value=(self.raws[row["digest"]], {}),
                )
            )
            self.assertEqual(
                subject._read_public_blob(80, row), self.raws[row["digest"]]
            )
            opened.assert_called_once_with(
                row["digest"][7:9],
                subject.os.O_RDONLY
                | subject.os.O_DIRECTORY
                | subject.os.O_NOFOLLOW
                | subject.os.O_CLOEXEC,
                dir_fd=80,
            )
            read.assert_called_once_with(
                90,
                "/" + row["digest"][9:],
                owner=0,
                owner_gid=0,
                modes={0o444},
                limit=subject.MAX_PUBLIC_BLOB,
            )
            closed.assert_called_once_with(90)
            metadata.st_mode = stat.S_IFLNK | 0o700
            with self.assertRaises(subject.NativeCommonSetupCaptureError):
                subject._read_public_blob(80, row)
            self.assertEqual(read.call_count, 1)

    def test_close_all_attempts_every_descriptor_and_preserves_primary(self):
        with patch.object(
            subject.os, "close", side_effect=OSError("private")
        ) as closed:
            with self.assertRaisesRegex(ValueError, "PRIMARY"):
                try:
                    raise ValueError("PRIMARY")
                finally:
                    subject._close_all([1, 2, 3])
            self.assertEqual(
                [call.args for call in closed.call_args_list], [(3,), (2,), (1,)]
            )
        with patch.object(subject.os, "close", side_effect=OSError("private")):
            with self.assertRaisesRegex(
                subject.NativeCommonSetupCaptureError, "DESCRIPTOR_CLOSE_REFUSED"
            ):
                subject._close_all([1])

    def test_public_store_holds_and_rechecks_only_fixed_existing_directories(self):
        entries = {
            10 + index: SimpleNamespace(
                st_mode=stat.S_IFDIR | (0o755 if index < 2 else 0o700),
                st_uid=0,
                st_gid=0,
                st_dev=1,
                st_ino=10 + index,
            )
            for index in range(5)
        }
        named = {
            (10, "."): 10,
            (10, "run"): 11,
            (11, "aragorn-native-common-setup"): 12,
            (12, "blobs"): 13,
            (13, "sha256"): 14,
        }

        def stat_name(name, *, dir_fd, follow_symlinks):
            self.assertFalse(follow_symlinks)
            return entries[named[(dir_fd, name)]]

        with ExitStack() as stack:
            opened = stack.enter_context(
                patch.object(subject.os, "open", side_effect=range(10, 15))
            )
            stack.enter_context(patch.object(subject.os, "stat", side_effect=stat_name))
            stack.enter_context(
                patch.object(subject.os, "fstat", side_effect=entries.__getitem__)
            )
            closed = stack.enter_context(patch.object(subject.os, "close"))
            with self.assertRaisesRegex(
                subject.NativeCommonSetupCaptureError, "PUBLIC_CAS_DIRECTORY_REPLACED"
            ):
                with subject._public_store() as (sha, guard):
                    self.assertEqual(sha, 14)
                    guard()
                    entries[12].st_ino += 100
                    guard()
            self.assertEqual(
                [call.args[0] for call in opened.call_args_list],
                ["/", "run", "aragorn-native-common-setup", "blobs", "sha256"],
            )
            self.assertEqual(
                [call.args[0] for call in closed.call_args_list], [14, 13, 12, 11, 10]
            )

    def test_fixed_cli_and_standalone_import_bootstrap(self):
        self.assertEqual(subject.BUNDLE_PATH, subject.contract.BUNDLE_PATH)
        self.assertEqual(subject.MAX_INPUT, subject.contract.MAX_BUNDLE)
        self.assertEqual(subject.MAX_RESULT, subject.contract.MAX_RESULT)
        self.assertEqual(subject._LIMITATIONS, list(subject.contract.GUEST_LIMITATIONS))
        self.assertEqual(subject._FALSE, subject.contract.FALSE_FLAGS)
        tree = ast.parse(Path(subject.__file__).read_text())
        paths = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        self.assertIn("/usr/lib/aragorn", paths)
        self.assertIn("/opt/aragorn", paths)
        output = io.BytesIO()
        with patch.object(subject.sys, "stdout", SimpleNamespace(buffer=output)):
            with patch.object(
                subject, "_run", return_value={"status": "REFUSED"}
            ) as run:
                self.assertEqual(subject.main([CONTAINER, PIN]), 126)
        run.assert_called_once_with(CONTAINER, PIN)
        self.assertEqual(output.getvalue(), b'{"status":"REFUSED"}\n')
        with ExitStack() as stack:
            self.harness(stack)
            result = subject._run("/arbitrary/path", PIN)
        self.prepare.assert_not_called()
        self.environment.assert_not_called()
        self.assertIsNone(result["container_id"])


if __name__ == "__main__":
    unittest.main()
