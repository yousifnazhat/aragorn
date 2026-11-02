"""Only the changed HTTP source guard; runtime files are in-memory readbacks."""

import ast
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from aragorn import native_phase3_http_collection as http_collection
from scripts import capture_native_phase3_http_attempt as launcher
from scripts import materialize_native_phase3_http_attempt as renderer
from scripts import materialize_native_phase3_http_attempt_capture as assembly
from scripts import runtime_native_blocked_create_workload as frozen_workload
from scripts import stage_runtime_phase3_http_ready_profile as stager


ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "/usr/lib/aragorn/aragorn/native_phase3_common_identity.py"
WRITER = "/opt/aragorn/runtime-native-receipt-systemd-check.py"


class HttpAttemptSourceGuardTests(unittest.TestCase):
    def test_http_replacements_keep_required_frozen_source_guards(self):
        original = {
            name: (ROOT / name).read_bytes() for name in assembly.source_paths()
        }
        generated = assembly.compose(original)
        host = launcher.build_controller(original)
        installed = original | generated
        inherited, replacements, _ = stager._verified_payloads()
        files = {
            "/" + path: (raw, mode)
            for path, (_, mode, raw) in (inherited | replacements).items()
        }
        # Mirror actual host installation, including both bootstrap aliases. Do
        # not replace generated helpers with frozen predecessor bytes in a test.
        for source, path in host._FILES.items():
            self.assertFalse(path in files, "helper overlaps staged payload: " + path)
            files[path] = (installed[source], 0o444)
        for path, source in host._ALIASES.items():
            self.assertFalse(path in files, "alias overlaps installed payload: " + path)
            files[path] = (installed[source], 0o444)
        source_path = "/opt/aragorn/runtime_native_common_attempt.py"
        setup_path = "/opt/aragorn/runtime_native_common_case_setup.py"
        tree = ast.parse(generated[renderer.SOURCE])
        nodes = [
            node
            for node in tree.body
            if (isinstance(node, ast.FunctionDef) and node.name == "_source_guard")
            or (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "SOURCE_PATHS"
                    for target in node.targets
                )
            )
        ]
        self.assertEqual(len(nodes), 2)
        reads = []

        def digest(raw):
            return "sha256:" + hashlib.sha256(raw).hexdigest()

        def require(condition, reason):
            if not condition:
                raise ValueError(reason)

        def read_fixed(path, mode, limit):
            reads.append((path, mode, limit))
            raw, installed_mode = files[path]
            require(
                mode == installed_mode and 0 < len(raw) <= limit, "TEST_FILE_CUSTODY"
            )
            return raw, {
                "bytes": len(raw),
                "digest": digest(raw),
                "identity": {"mode": mode},
            }

        workload = SimpleNamespace(
            __file__=frozen_workload.SOURCE_PATH,
            SOURCE_PATH=frozen_workload.SOURCE_PATH,
            SINK_SOURCE_PATH=frozen_workload.SINK_SOURCE_PATH,
            REVOCATION_SOURCE_PATH=frozen_workload.REVOCATION_SOURCE_PATH,
            DRIVER_PATH=frozen_workload.DRIVER_PATH,
            _FIXED_SOURCES=frozen_workload._FIXED_SOURCES,
            _pin=frozen_workload._pin,
            _read_fixed=read_fixed,
            _sources=Mock(
                side_effect=AssertionError("obsolete workload source delegation")
            ),
        )
        namespace = {
            "__file__": source_path,
            "SOURCE_PATH": source_path,
            "setup": SimpleNamespace(SETUP_PATH=setup_path),
            "workload": workload,
            "http_collection": http_collection,
            "os": os,
            "_require": require,
        }
        exec(
            compile(
                ast.Module(body=nodes, type_ignores=[]), "<http-source-guard>", "exec"
            ),
            namespace,
        )
        self.assertEqual(
            set(namespace["SOURCE_PATHS"]), set(host.inputs.ATTEMPT_SOURCE_PATHS)
        )
        self.assertEqual(
            set(namespace["SOURCE_PATHS"]), set(host.guest.attempt.SOURCE_PATHS)
        )
        self.assertIn(WRITER, namespace["SOURCE_PATHS"])
        for path, (size, pin, mode) in frozen_workload._FIXED_SOURCES.items():
            if path in {IDENTITY, workload.DRIVER_PATH, WRITER}:
                continue
            raw, actual_mode = files[path]
            self.assertEqual((len(raw), digest(raw)), (size, pin))
            self.assertEqual(actual_mode, mode)
        pins = {path: digest(files[path][0]) for path in namespace["SOURCE_PATHS"]}
        self.assertNotEqual(pins[IDENTITY], frozen_workload._FIXED_SOURCES[IDENTITY][1])
        self.assertNotEqual(pins[WRITER], frozen_workload._FIXED_SOURCES[WRITER][1])
        self.assertNotIn(workload.DRIVER_PATH, files)
        guard = namespace["_source_guard"]
        result = guard(pins)
        self.assertEqual(result[IDENTITY]["digest"], pins[IDENTITY])
        self.assertEqual(result[WRITER]["digest"], pins[WRITER])
        self.assertEqual(
            result[http_collection.DRIVER_PATH]["digest"],
            pins[http_collection.DRIVER_PATH],
        )
        self.assertIn((WRITER, 0o444, 1024 * 1024), reads)
        self.assertNotIn(workload.DRIVER_PATH, [row[0] for row in reads])
        workload._sources.assert_not_called()

        for path in (IDENTITY, http_collection.DRIVER_PATH, WRITER):
            original_file = files[path]
            files[path] = (original_file[0] + b"\n", original_file[1])
            with self.assertRaisesRegex(ValueError, "INSTALLED_SOURCE_PIN_CHANGED"):
                guard(pins)
            files[path] = original_file
        # Frozen identity/writer bytes cannot satisfy installed successor pins.
        for path, source in (
            (IDENTITY, "src/aragorn/native_phase3_common_identity.py"),
            (WRITER, "scripts/runtime_native_receipt_systemd_check.py"),
        ):
            successor = files[path]
            files[path] = (original[source], 0o444)
            with self.assertRaisesRegex(ValueError, "INSTALLED_SOURCE_PIN_CHANGED"):
                guard(pins)
            files[path] = successor
        bootstrap = "/opt/aragorn/runtime_native_plugin_package_check.py"
        original_file = files[bootstrap]
        files[bootstrap] = (original_file[0] + b"\n", original_file[1])
        with self.assertRaisesRegex(ValueError, "FIXED_SOURCE_PIN_CHANGED"):
            guard(pins)
        files[bootstrap] = (original_file[0], 0o644)
        with self.assertRaisesRegex(ValueError, "TEST_FILE_CUSTODY"):
            guard(pins)
        files[bootstrap] = original_file
        workload.__file__ = "/tmp/not-the-owned-workload.py"
        with self.assertRaisesRegex(ValueError, "INSTALLED_WORKLOAD_PATH_CHANGED"):
            guard(pins)
        self.assertNotIn(workload.DRIVER_PATH, [row[0] for row in reads])
        workload._sources.assert_not_called()
