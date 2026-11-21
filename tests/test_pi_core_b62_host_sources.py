"""Source projection and refusal checks; no imports of guest code or image writes."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_b62_host_sources as sources


class B62Sources(unittest.TestCase):
    def test_b60_projection_changes_only_two_replacements_and_two_additions(self):
        parent = {r["path"]: r for r in sources.b60.expected_rows()}
        rows = sources.expected_rows()
        new = {r["path"]: r for r in rows}
        self.assertEqual(tuple(r["path"] for r in rows), tuple(sorted(new)))
        prefix = sources.b60._PREFIX
        self.assertEqual(new.keys() - parent.keys(), {prefix + "pi_core_mask_capture_" + n + ".py"
                                                      for n in ("entry", "release")})
        self.assertEqual({name for name in parent if new[name] != parent[name]},
                         {sources.WRAPPER, prefix + "pi_core_native_supervisor.py"})
        self.assertEqual(len(new), 115)
        with patch.dict(sources._DELTA, {sources.WRAPPER: (10, "0" * 64)}), \
             self.assertRaisesRegex(ValueError, "projection differs"):
            sources.expected_rows()

    def test_import_graph_includes_loaded_bootstrap_and_lazy_branch_without_execution(self):
        prefix = sources.b60._PREFIX
        rows = {sources.WRAPPER: b"def dispatch():\n from aragorn.entry import run\n",
                prefix + "__init__.py": b"", prefix + "pi_core_service_source.py": b"",
                prefix + "entry.py": b"raise AssertionError('never execute')\ndef run():\n from . import lazy\n",
                prefix + "lazy.py": b""}
        sources._project_imports(rows)
        for absent in ("lazy", "pi_core_service_source"):
            with self.subTest(absent=absent), self.assertRaisesRegex(ValueError, "missing pinned project import"):
                sources._project_imports({p: raw for p, raw in rows.items() if p != prefix + absent + ".py"})
        with self.assertRaisesRegex(ValueError, "unreachable"):
            sources._project_imports(rows | {prefix + "not_installed.py": b""})

    def test_wrapper_uses_packaging_origin_and_refuses_equal_length_or_linked_substitution(self):
        root = Path(self.enterContext(TemporaryDirectory())).resolve()
        path = root / "packaging/pi-core/coordinator.py"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"fake")
        rows = [dict(path=sources.WRAPPER, size=4, digest="sha256:" + sources.sha256(b"real"))]
        with patch.object(sources, "expected_rows", return_value=rows), self.assertRaisesRegex(ValueError, "bytes differ"):
            sources.prepare_host_sources(root)
        other = path.with_name("other")
        other.write_bytes(b"real")
        path.unlink()
        path.symlink_to(other)
        with patch.object(sources, "expected_rows", return_value=rows), self.assertRaisesRegex(ValueError, "linked"):
            sources.prepare_host_sources(root)
