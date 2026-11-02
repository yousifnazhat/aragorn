from __future__ import annotations

import base64
import io
import os
import shutil
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from scripts import capture_openclaw_final_v3_core_updater_modules as subject


def _fixture():
    records, identities = [], {}
    for index, path in enumerate(subject._PATHS):
        raw = f"// inert test module {index}\n".encode()
        identity = {"bytes": len(raw), "digest": subject._digest(raw)}
        identities[path] = identity
        metadata = {"device": 100, "gid": 0, "inode": 1000 + index, "mode": "0644",
                    "nlink": 1, "path": path, "size": len(raw), "type": "file", "uid": 0}
        records.append({"path": path, **identity, "content_base64": base64.b64encode(raw).decode(),
                        "stat_before": metadata, "stat_after": deepcopy(metadata)})
    live = {
        "runtime_tree_before": deepcopy(subject._RUNTIME_TREE),
        "runtime_tree_after": deepcopy(subject._RUNTIME_TREE),
        "module_files": records,
        "runtime_tree_helper": subject._helper_input()[1],
        "mounts": [{"path": "/runtime", "read_only": True, "ready": True}],
    }
    observed = {path: {"path": path, **identities[path]} for path in subject._PATHS[:2]}
    return live, identities, observed


class CoreUpdaterModuleAcquisitionTests(unittest.TestCase):
    def test_original_raw_route_is_bound_and_has_two_observed_modules(self):
        evidence, observed = subject._route_evidence()
        self.assertEqual(evidence["route_id"], subject._ROUTE)
        self.assertEqual(set(observed), set(subject._PATHS[:2]))
        self.assertEqual(len(subject._PATHS), 10)
        self.assertEqual(sum(item["bytes"] for item in subject._MODULE_IDENTITIES.values()), 423947)

    def test_exact_live_fixture_accepts_without_executing_modules(self):
        live, identities, observed = _fixture()
        with patch.object(subject, "_MODULE_IDENTITIES", identities):
            subject._validate_live(live, observed)
        self.assertEqual([record["observed_in_original_route"] for record in live["module_files"]],
                         [True, True] + [False] * 8)

    def test_mutated_acquisition_fails_closed(self):
        mutations = {
            "changed tree": lambda live: live["runtime_tree_after"].update(tree_digest="sha256:" + "0" * 64),
            "missing module": lambda live: live["module_files"].pop(),
            "invalid bytes": lambda live: live["module_files"][0].update(content_base64="!"),
            "different bytes": lambda live: live["module_files"][0].update(content_base64=base64.b64encode(b"other").decode()),
            "stat drift": lambda live: live["module_files"][0]["stat_after"].update(inode=5),
            "boolean integer": lambda live: live["module_files"][0].update(bytes=True),
            "shared inode": lambda live: [live["module_files"][1][field].update(inode=1000) for field in ("stat_before", "stat_after")],
            "symlink": lambda live: [live["module_files"][0][field].update(type="symlink") for field in ("stat_before", "stat_after")],
            "helper digest": lambda live: live["runtime_tree_helper"].update(digest="sha256:" + "0" * 64),
            "writable mount": lambda live: live["mounts"][0].update(read_only=False),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                live, identities, observed = _fixture()
                mutate(live)
                with patch.object(subject, "_MODULE_IDENTITIES", identities), \
                        self.assertRaises((subject.CaptureError, ValueError)):
                    subject._validate_live(live, observed)

    def test_original_module_digest_mismatch_fails_closed(self):
        live, identities, observed = _fixture()
        observed[subject._PATHS[0]]["digest"] = "sha256:" + "0" * 64
        with patch.object(subject, "_MODULE_IDENTITIES", identities), \
                self.assertRaisesRegex(subject.CaptureError, "original route"):
            subject._validate_live(live, observed)

    def test_container_command_is_explicitly_read_only_and_offline(self):
        command = subject._command()
        self.assertEqual(command[:3], subject._DOCKER)
        for flag, value in (("--network", "none"), ("--cap-drop", "ALL"),
                            ("--security-opt", "no-new-privileges"), ("--entrypoint", "/usr/local/bin/node")):
            self.assertEqual(command[command.index(flag) + 1], value)
        self.assertIn("--read-only", command)
        mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
        self.assertEqual(len(mounts), 1)
        self.assertTrue(all(mount.endswith(",readonly") for mount in mounts))
        self.assertNotIn("type=bind", " ".join(command))
        self.assertIn(subject._IMAGE, command)
        program = command[-1]
        self.assertEqual(program.count("await import("), 1)
        self.assertIn("await import(helperUrl)", program)
        self.assertIn("fs.constants.O_NOFOLLOW", program)
        self.assertNotIn("spawn", program)
        self.assertNotIn("eval(", program)

    @unittest.skipUnless(shutil.which("node"), "Node is unavailable")
    def test_node_reader_is_syntactically_valid(self):
        result = subprocess.run([shutil.which("node"), "--check", "--input-type=module"],
                                input=subject._program(), text=True, capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("node"), "Node is unavailable")
    def test_node_reader_reads_native_bytes_without_executing_them(self):
        with tempfile.TemporaryDirectory() as directory:
            native = Path(directory) / "native.js"
            raw = b"throw new Error('selected modules must never execute');\n"
            native.write_bytes(raw)
            helper = Path(directory) / "helper.mjs"
            helper_raw = (b"const SELF = fileURLToPath(import.meta.url);\n"
                          b"export function runtimeTree() { return {test_tree:true}; }\n"
                          b"function decodeMountInfoPath() {}\n"
                          b"export const mountObservation = path => ({path,ready:true,read_only:true});\n")
            helper.write_bytes(helper_raw)
            identities = {str(native): {"bytes": len(raw), "digest": subject._digest(raw)}}
            with patch.object(subject, "_PATHS", (str(native),)), \
                    patch.object(subject, "_MODULE_IDENTITIES", identities), \
                    patch.object(subject, "_HELPER", str(helper)), \
                    patch.object(subject, "_HELPER_PATH", helper), \
                    patch.object(subject, "_HELPER_IDENTITY", {"bytes": len(helper_raw), "digest": subject._digest(helper_raw)}):
                program = subject._program()
            result = subprocess.run([shutil.which("node"), "--input-type=module", "-e", program],
                                    text=True, capture_output=True, timeout=10, check=False,
                                    env={**os.environ, "NODE_OPTIONS": "", "NODE_PATH": ""})
            self.assertEqual(result.returncode, 0, result.stderr)
            acquired = subject._load_json(result.stdout.encode(), "test reader output")
            self.assertEqual(base64.b64decode(acquired["module_files"][0]["content_base64"]), raw)
            self.assertEqual(acquired["runtime_tree_before"], acquired["runtime_tree_after"])

    def test_dirty_acquisition_source_is_rejected_before_docker(self):
        answers = [str(subject._ROOT).encode() + b"\n", b"sha1\n", b"?? unrelated-new-file\n"]
        with patch.object(subject.shared, "_git", side_effect=answers), \
                patch.object(subject, "_run") as run, \
                self.assertRaisesRegex(subject.CaptureError, "clean repository"):
            subject._source_identity()
        run.assert_not_called()

    def test_capture_retains_no_positive_eligibility(self):
        source = {"commit": "1" * 40}
        evidence = {"recorded_at": "2026-09-03T19:49:40.729138Z"}
        with patch.object(subject, "_source_identity", return_value=source), \
                patch.object(subject, "_route_evidence", return_value=(evidence, {})), \
                patch.object(subject, "_live_acquisition", return_value={}):
            result = subject.capture()
        self.assertEqual(result["schema"], subject._SCHEMA)
        self.assertTrue(all(result["decision"][key] is False for key in subject.shared._ELIGIBILITY_KEYS))
        self.assertIs(result["containment"]["selected_modules_executed"], False)

    def test_source_change_during_capture_is_rejected(self):
        with patch.object(subject, "_source_identity", side_effect=[{"commit": "a"}, {"commit": "b"}]), \
                patch.object(subject, "_route_evidence", return_value=({}, {})), \
                patch.object(subject, "_live_acquisition", return_value={}), \
                self.assertRaisesRegex(subject.CaptureError, "source changed"):
            subject.capture()

    def test_output_is_exclusive_and_rejects_symlinks(self):
        raw = b'{"status":"NOT_TESTED"}\n'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "modules.json"
            subject._write_output(output, raw)
            self.assertEqual(output.read_bytes(), raw)
            self.assertEqual(output.stat().st_mode & 0o777, 0o444)
            with self.assertRaises(FileExistsError):
                subject._write_output(output, b"replacement")
            link = Path(directory) / "link.json"
            link.symlink_to(output)
            with self.assertRaises(FileExistsError):
                subject._write_output(link, b"replacement")
            self.assertEqual(output.read_bytes(), raw)

    def test_main_writes_only_complete_canonical_capture_and_reports_identity(self):
        value = {"schema": subject._SCHEMA, "decision": {"phase3_exit_eligible": False}}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "modules.json"
            with patch.object(subject, "capture", return_value=value), patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(subject.main(["--output", str(output)]), 0)
            self.assertEqual(output.read_bytes(), subject._canonical(value) + b"\n")
            self.assertIn(subject._digest(output.read_bytes()), stdout.getvalue())
            with patch.object(subject, "capture") as capture, patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(subject.main(["--output", str(output)]), 2)
            capture.assert_not_called()
            absent = Path(directory) / "failed.json"
            with patch.object(subject, "capture", side_effect=subject.CaptureError("no receipt")), \
                    patch("sys.stderr", new_callable=io.StringIO):
                self.assertEqual(subject.main(["--output", str(absent)]), 2)
            self.assertFalse(os.path.lexists(absent))


if __name__ == "__main__":
    unittest.main()
