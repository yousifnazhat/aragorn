"""Restricted audit refusals only. No build, target execution or live evidence."""

import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_restricted_profile as fixed
from scripts import verify_pi_core_worker_bundle as verifier


class RestrictedBundleChecks(unittest.TestCase):
    def test_missing_extra_substituted_or_reordered_argv_refused_before_audit(self):
        node, flag, entry = fixed.NODE_ARGV
        for args in ((node, entry), (node, flag, entry, flag), (node, entry, flag),
                     (node, "--no-warnings", entry), str(fixed.NODE_ARGV), True):
            with self.subTest(args=args), self.assertRaisesRegex(verifier.BundleVerificationError, "Node argv"):
                verifier.verify_restricted(Path("/unused"), {}, args)

    def test_unbound_gate_receipt_cannot_enable_restricted_parser(self):
        for receipt in (True, {"runtime_enforcement_observed": True},
                        {"schema": "aragorn/pi-core-source-gate-build/v1", "node_argv": list(fixed.NODE_ARGV)}):
            with self.subTest(receipt=receipt), mock.patch.object(verifier, "_verified") as audit:
                with self.assertRaises(verifier.BundleVerificationError):
                    verifier.verify_restricted(Path("/unused"), receipt, fixed.NODE_ARGV)
                audit.assert_not_called()

    def test_each_original_product_identity_checked_before_parsing(self):
        # Isolate the three-way byte comparison using tiny, inert rows. Actual
        # approved pins and a compiled gate are required by the separate real stage.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            folder = root / ".aragorn/pi-core-build/tiny"
            folder.mkdir(parents=True)
            rows = {"entrypoint.js": b"export {};", "receipt.json": b"{}", "meta.json": b"{}\n"}
            def pin(name):
                return hashlib.sha256(rows[name]).hexdigest()
            pins = SimpleNamespace(BUNDLE_SHA256=pin("entrypoint.js"), META_SHA256=pin("meta.json"),
                                   BUNDLE_RECEIPT_SHA256=pin("receipt.json"))
            for name, raw in rows.items():
                (folder / name).write_bytes(raw)
            for name, raw in rows.items():
                with self.subTest(name=name):
                    path = folder / name
                    path.write_bytes(raw + b" ")
                    with self.assertRaisesRegex(verifier.BundleVerificationError, "retained product substitution"):
                        verifier._verified(folder, root, pins)
                    path.write_bytes(raw)

    def test_changed_loader_cannot_use_a_digest_supplied_by_the_producer(self):
        source = b"export const late = name => import(name);"
        pin = SimpleNamespace(BUNDLE_SHA256=hashlib.sha256(source).hexdigest())
        with self.assertRaisesRegex(verifier.BundleVerificationError, "parse/inspection refused"):
            verifier._inspect(source, pin)  # parser independently pins the restricted product

    def test_unrestricted_mode_never_accepts_string_codegen_or_ambient_loader(self):
        for raw in (b"export const make = (...args)=>new globalThis.Function(...args);",
                    b"export const load = (path)=>import(path);"):
            with self.subTest(raw=raw), self.assertRaisesRegex(verifier.BundleVerificationError, "emitted AST"):
                verifier.inspect_js(raw)

    def test_restricted_mode_rejects_unreviewed_introspection_and_loader_bytes(self):
        for raw in (b"export const s = Function.prototype.toString;",
                    b"export const run = new Function('return 1');",
                    b"export { extra } from './other.js';"):
            with self.subTest(raw=raw), self.assertRaisesRegex(verifier.BundleVerificationError, "unreviewed restricted"):
                verifier._inspect(raw, fixed)
