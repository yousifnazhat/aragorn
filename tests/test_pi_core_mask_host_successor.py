"""Inert refusal checks; the coordinator stage owns the single retained-payload readback."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import prepare_pi_core_mask_host_sources as sources
from scripts import verify_pi_core_mask_guest_inputs as guest
from scripts.build_pi_core_linux import BuildError


class SuccessorInputs(unittest.TestCase):
    def test_embedded_helper_must_be_one_pinned_literal_not_an_evaluated_expression(self):
        self.enterContext(patch.object(sources, "PROBE_DIGEST", "sha256:" + hashlib.sha256(b"first").hexdigest()))
        raw = b'_PROGRAM = "first"\n'
        def pin_module(module):
            return patch.dict(sources._DELTA, {"pi_core_mask_probe": (len(module), hashlib.sha256(module).hexdigest())})
        with pin_module(raw):
            self.assertEqual(sources.helper_bytes(raw), b"first")
            with self.assertRaisesRegex(ValueError, "module"):
                sources.helper_bytes(raw.replace(b"first", b"other"))
        for label, malformed in (
                ("foreign bytes", raw.replace(b"first", b"other")),
                ("multiple declarations", raw + raw),
                ("expression", b'_PROGRAM = (_ for _ in ()).throw(AssertionError("never run source"))\n'),
                ("not text", b'_PROGRAM = 123\n'),
                ("wrong name", b'_UNRELATED = "first"\n')):
            with self.subTest(label=label), pin_module(malformed), self.assertRaises(ValueError):
                sources.helper_bytes(malformed)

    def test_old_observer_is_replaced_new_dependency_is_added_and_missing_delta_is_refused(self):
        def row(name, raw):
            return dict(path=sources._PREFIX + name + ".py", size=len(raw),
                        digest="sha256:" + hashlib.sha256(raw).hexdigest())
        approved = [row("new_dependency", b"helper"), row("observer", b"v2")]
        old = [row("observer", b"v1")]
        change = {k: (r["size"], r["digest"][7:]) for k, r in zip(("new_dependency", "observer"), approved)}
        self.enterContext(patch.object(sources.b37, "_release", return_value=old))
        self.enterContext(patch.object(sources, "_DELTA", change))
        self.enterContext(patch.object(sources, "ROWS_DIGEST", "sha256:" +
                                      hashlib.sha256(sources.canonical(approved)).hexdigest()))
        self.assertEqual(sources.expected_rows(), approved)
        for missing in change:
            with self.subTest(missing=missing), patch.object(sources, "_DELTA", change.copy()):
                del sources._DELTA[missing]
                with self.assertRaises(ValueError):
                    sources.expected_rows()

    def test_successor_reads_the_pinned_new_dependency_and_rejects_same_size_or_linked_substitution(self):
        root = Path(self.enterContext(TemporaryDirectory())).resolve()
        code = root / "src/aragorn/pi_core_stopped_mask_view.py"
        code.parent.mkdir(parents=True)
        raw = b'raise AssertionError("never execute projected sources")\n'
        code.write_bytes(raw)
        rows = [dict(path=sources._PREFIX + code.name, size=len(raw),
                     digest="sha256:" + hashlib.sha256(raw).hexdigest())]
        self.enterContext(patch.object(sources, "expected_rows", return_value=rows))
        self.assertEqual(sources.prepare_host_sources(root), rows)
        code.write_bytes(b"x" * len(raw))
        with self.assertRaises(ValueError):
            sources.prepare_host_sources(root)
        sibling = code.with_name("elsewhere")
        sibling.write_bytes(raw)
        code.unlink()
        code.symlink_to(sibling)
        with self.assertRaises(ValueError):
            sources.prepare_host_sources(root)

    def test_interpreter_refuses_foreign_program_before_reading_any_payload(self):
        with TemporaryDirectory() as tmp:
            missing = Path(tmp) / "absent"
            with self.assertRaisesRegex(BuildError, "wrong B59 helper bytes"):
                guest.verify_guest_inputs(payload_dir=missing, helper_source="raise AssertionError('do not run')")
            self.assertFalse(missing.exists())

    def test_guest_extension_requires_matching_logical_and_immutable_physical_member(self):
        path = "/opt/aragorn-cpython/lib/python3.12/lib-dynload/_ctypes.cpython-312-aarch64-linux-gnu.so"
        hex_digest = hashlib.sha256(b"X").hexdigest()
        logical = {"path": path, "size": 1, "digest": "sha256:" + hex_digest}
        physical = {"path": path, "size": 1, "sha256": hex_digest, "uid": 0, "gid": 0,
                    "mode": 0o555, "type": "file"}
        def bind(lrow, prow):
            return guest._bound_row(path, {} if lrow is None else {path:lrow}, {} if prow is None else {path:prow})
        self.assertEqual(bind(logical, physical), (path, logical))
        for label, lrow, prow in (
                ("no caller file", None, physical),
                ("no image member", logical, None),
                ("changed executable hash", logical, dict(physical, sha256="0"*64)),
                ("different length", dict(logical, size=2), physical),
                ("boolean physical size", logical, dict(physical, size=True)),
                ("linked member", logical, dict(physical, type="symlink")),
                ("writable module", logical, dict(physical, mode=0o755)),
                ("nonroot owner", logical, dict(physical, uid=1))):
            with self.subTest(label=label), self.assertRaises(BuildError):
                bind(lrow, prow)

        loader = guest.LOADER
        logical["path"], physical["path"] = loader, "/usr" + loader
        self.assertEqual(guest._bound_row(loader, {loader:logical}, {physical["path"]:physical}),
                         (physical["path"], logical))
        with self.assertRaisesRegex(BuildError, "physical payload row"):
            guest._bound_row(loader, {loader:logical}, {loader:dict(physical, path=loader)})
