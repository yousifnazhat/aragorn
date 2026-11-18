"""Inert offline source-pin checks; no imports of target sources, VM or host execution."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import prepare_pi_core_restricted_host_sources as host


class RestrictedHostSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.manifest = self.root / host.MANIFEST
        self.manifest.parent.mkdir(parents=True)
        self.code = [self.root / "packaging/pi-core/coordinator.py",
                     self.root / "src/aragorn/pi_core_service_source.py"]
        self.code[1].parent.mkdir(parents=True)
        raw = b'raise AssertionError("projected source must never execute")'
        self.rows = []
        for dest, path in zip((host.WRAPPER, "/opt/aragorn/src/aragorn/pi_core_service_source.py"), self.code):
            path.write_bytes(raw)
            self.rows.append({"path": dest, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw)})
        value = {"schema": "aragorn/pi-core-restricted-host-sources/v1", "revision": host.REVISION,
                 "tree": host.TREE, "files": self.rows}
        source = json.dumps(value).encode()
        self.manifest.write_bytes(source)
        self.enterContext(patch.object(host, "MANIFEST_SHA256", hashlib.sha256(source).hexdigest()))

    def test_returns_only_fixed_sorted_rows_never_imports_sources_or_discovers_drafts(self):
        self.code[1].with_name("duplicate 2.py").write_text("raise RuntimeError()")
        self.assertEqual(host.prepare_host_sources(self.root), self.rows)

    def test_changed_wrapper_or_loader_bytes_refused_even_at_same_size(self):
        for path in self.code:
            raw = path.read_bytes()
            path.write_bytes(b"x" * len(raw))
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "differs from release"):
                host.prepare_host_sources(self.root)
            path.write_bytes(raw)

    def test_missing_source_or_resealed_manifest_cannot_substitute_authority(self):
        self.code[1].unlink()
        with self.assertRaises(FileNotFoundError):
            host.prepare_host_sources(self.root)
        self.manifest.write_bytes(b'{"files":[]}')
        with self.assertRaisesRegex(ValueError, "unapproved host source manifest"):
            host.prepare_host_sources(self.root)

    def test_linked_source_leaf_and_linked_ancestor_are_not_inputs(self):
        link = self.code[1]
        actual = link.with_name("target.py")
        link.rename(actual)
        link.symlink_to(actual)
        with self.assertRaisesRegex(ValueError, "linked"):
            host.prepare_host_sources(self.root)
        link.unlink()
        actual.rename(link)
        folder = link.parent
        moved = folder.with_name("other")
        folder.rename(moved)
        folder.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "linked"):
            host.prepare_host_sources(self.root)

    def test_independent_full_profile_requires_exact_code_namespace(self):
        other = {"path": "/usr/bin/busctl", "size": 123, "digest": "sha256:" + "0" * 64}
        host.require_host_source_projection([*self.rows, other], root=self.root)
        for rows in (self.rows[:1], self.rows * 2, list(reversed(self.rows)),
                     [*self.rows, dict(other, path="/opt/aragorn/bin/extra.py")],
                     [self.rows[0], dict(self.rows[1], digest=other["digest"])],
                     [self.rows[0], dict(self.rows[1], size=float(self.rows[1]["size"]))]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                host.require_host_source_projection(rows, root=self.root)

    def test_full_preparation_does_not_dispatch_on_bad_pin_or_added_code(self):
        delegate = Mock()
        with patch.dict(sys.modules, {"scripts.prepare_pi_core_coordinator_host":
                                      SimpleNamespace(prepare_pi_coordinator_host_profile=delegate)}):
            for rows, stale in ((self.rows, True), ([*self.rows, dict(self.rows[0], path="/opt/aragorn/src/extra.py")], False)):
                raw = json.dumps({"files": rows}, separators=(",", ":"), sort_keys=True).encode()
                pin = "sha256:" + ("0" * 64 if stale else hashlib.sha256(raw).hexdigest())
                with self.subTest(stale=stale), self.assertRaises(ValueError):
                    host.prepare_restricted_coordinator_host(raw, expected_profile_digest=pin,
                                                            retained_root=self.root / "absent", root=self.root)
        delegate.assert_not_called()

    def test_full_preparation_delegates_exact_bytes_pin_and_export_once(self):
        delegate = Mock()
        raw = json.dumps({"files": self.rows}, separators=(",", ":"), sort_keys=True).encode()
        pin = "sha256:" + hashlib.sha256(raw).hexdigest()
        target = self.root / "export"
        with patch.dict(sys.modules, {"scripts.prepare_pi_core_coordinator_host":
                                      SimpleNamespace(prepare_pi_coordinator_host_profile=delegate)}):
            result = host.prepare_restricted_coordinator_host(raw, expected_profile_digest=pin,
                                                              retained_root=target, root=self.root)
        delegate.assert_called_once_with(raw, expected_profile_digest=pin, retained_root=target)
        self.assertIs(delegate.call_args.args[0], raw)
        self.assertIs(result, delegate.return_value)
