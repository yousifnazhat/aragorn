"""Changed worker-bundle boundaries only; no compiler or worker execution."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import build_pi_core_worker_bundle as builder
from scripts import verify_pi_core_worker_bundle as verifier


ROOT = Path(__file__).resolve().parents[1]


class BundleInputChecks(unittest.TestCase):
    def test_pinned_worker_provider_and_legacy_source_substitution_refused(self):
        pins = builder.load_profile(ROOT)
        with tempfile.TemporaryDirectory() as location:
            root = Path(location).resolve()
            for rel in pins["sources"]:
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((ROOT / rel).read_bytes())
            self.assertEqual(set(builder.read_sources(root, pins)), set(pins["sources"]))
            for rel in ("packaging/pi-core/entrypoint.ts", "packaging/pi-core/worker.ts",
                        "packaging/pi-core/provider.ts", "packaging/openclaw/aragorn-runtime-action-worker/index.js"):
                with self.subTest(rel=rel):
                    path = root / rel
                    original = path.read_bytes()
                    # Equal length: a size-only receipt would accept this replacement.
                    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                    with self.assertRaises(builder.BuildError):
                        builder.read_sources(root, pins)
                    path.write_bytes(original)

    def test_unpinned_compiler_archive_refused_before_extraction(self):
        with tempfile.TemporaryDirectory() as location:
            path = Path(location) / "esbuild.tgz"
            path.write_bytes(b"not the reviewed archive")
            with self.assertRaises(builder.BuildError):
                builder.tool_archive(path, builder.load_profile(ROOT))

    def test_existing_output_preserved_without_reading_tools(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location).resolve()
            existing = root / ".aragorn/pi-core-build/original"
            existing.mkdir(parents=True)
            witness = existing / "entrypoint.js"
            witness.write_bytes(b"prior evidence")
            with self.assertRaises(builder.BuildError):
                builder.build(existing, root=root)
            self.assertEqual(witness.read_bytes(), b"prior evidence")
            self.assertEqual(set(existing.iterdir()), {witness})


class BundleLoaderChecks(unittest.TestCase):
    def test_syntax_only_audit_does_not_execute_candidate_or_match_comments(self):
        # If the checker imports this module it throws. Text mentioning a load is not a load.
        source = (b"import {createHash} from 'node:crypto';\n// import('not-a-module')\n"
                  b"export const hash = createHash; throw new Error('candidate executed');\n")
        self.assertEqual(verifier.inspect_js(source)["static_builtins"], ["node:crypto"])

    def test_unpinned_static_module_or_reexport_refused(self):
        for source in (b"import 'unexpected-package';", b"export * from './extra.js';"):
            with self.subTest(source=source), self.assertRaises(verifier.BundleVerificationError):
                verifier.inspect_js(source)

    def test_late_provider_load_and_computed_specifier_refused_even_when_unreached(self):
        for source in (b"export const protectedStart=()=>import('./provider.js');",
                       b"export const lazy=name=>import(name);"):
            with self.subTest(source=source), self.assertRaises(verifier.BundleVerificationError):
                verifier.inspect_js(source)

    def test_cjs_and_loader_aliases_refused(self):
        for source in (b"export const lazy=()=>require('./extra.cjs');",
                       b"import {createRequire as loader} from 'node:module'; "
                       b"export const late=path=>loader(import.meta.url)(path);"):
            with self.subTest(source=source), self.assertRaises(verifier.BundleVerificationError):
                verifier.inspect_js(source)

    def test_adapted_legacy_builtin_destructuring_but_not_full_module_escape(self):
        prefix = b"import builtin from 'node:crypto'; "
        self.assertEqual(verifier.inspect_js(prefix + b"const {createHash:h}=builtin; export const f=h;")
                         ["static_builtins"], ["node:crypto"])
        for body in (b"export const f=builtin;", b"export const f=builtin.unapproved;",
                     b"export const read=k=>builtin[k];", b"export {builtin};"):
            with self.subTest(body=body), self.assertRaises(verifier.BundleVerificationError):
                verifier.inspect_js(prefix + body)

    def test_invalid_syntax_not_accepted_as_zero_imports(self):
        with self.assertRaises(verifier.BundleVerificationError):
            verifier.inspect_js(b"export const unfinished = ;")


class BundleEvidenceChecks(unittest.TestCase):
    def test_compiler_closure_requires_provider_reachability_and_emitted_bytes(self):
        entry, worker, provider, bridge = ("input/pi-core/entrypoint.ts", "input/pi-core/worker.ts",
            "input/pi-core/provider.ts", "input/openclaw/aragorn-runtime-action-worker/index.mjs")
        sizes = {key: 20 for key in (entry, worker, provider, bridge)}
        ins = {key: {"bytes": size, "imports": []} for key, size in sizes.items()}
        ins[entry]["imports"] = [{"path": key, "kind": kind} for key, kind in
            ((worker, "import-statement"), (provider, "dynamic-import"), (bridge, "import-statement"))]
        js = b"export const sample = 0;"
        out = {"bytes": len(js), "entryPoint": entry, "exports": ["sample"], "imports": [],
               "inputs": {name: {"bytesInOutput": 1} for name in sizes}}
        meta = {"inputs": ins, "outputs": {"out/entrypoint.js": out}}
        verifier._meta(meta, sizes, js, [])
        provider_edge = ins[entry]["imports"].pop(1)
        with self.assertRaisesRegex(verifier.BundleVerificationError, "disconnected"):
            verifier._meta(meta, sizes, js, [])
        ins[entry]["imports"].append(provider_edge)
        out["inputs"][provider]["bytesInOutput"] = 0
        with self.assertRaisesRegex(verifier.BundleVerificationError, "missing connected"):
            verifier._meta(meta, sizes, js, [])
        out["inputs"][provider]["bytesInOutput"] = 1
        with self.assertRaisesRegex(verifier.BundleVerificationError, "external mismatch"):
            verifier._meta(meta, sizes, js, ["node:crypto"])

    def test_changed_output_or_metadata_fails_before_any_provenance_claim(self):
        with tempfile.TemporaryDirectory() as location:
            root = Path(location).resolve()
            path = root / ".aragorn/pi-core-build/original"
            path.mkdir(parents=True)
            raws = {"entrypoint.js": b"export {};", "meta.json": b"{}"}
            receipt = {"schema": "aragorn/pi-core-worker-bundle-build/v1", "status": "EMITTED_NOT_VERIFIED_OR_DEPLOYED",
                "toolchain_sha256": "", "tool_archive_sha256": "", "tool_binary_sha256": "", "dependency_tree_sha256": "",
                "sources": {}, "staged_sources": {}, "recipes": {}, "phase3_exit_eligible": False, "target_executed": False,
                "outputs": {n: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for n, raw in raws.items()}}
            (path / "receipt.json").write_text(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
            for name, raw in raws.items():
                (path / name).write_bytes(raw)
            for name, replacement in (("entrypoint.js", b"export {};\n"), ("meta.json", b"[]")):
                with self.subTest(name=name):
                    (path / name).write_bytes(replacement)
                    with self.assertRaisesRegex(verifier.BundleVerificationError, "emitted bytes or metadata changed"):
                        verifier.verify_one(path, root=root)
                    (path / name).write_bytes(raws[name])
            (path / "unregistered.js").touch()
            with self.assertRaisesRegex(verifier.BundleVerificationError, "unexpected or linked"):
                verifier.verify_one(path, root=root)

    def test_one_directory_or_differing_independent_reports_cannot_certify_reproduction(self):
        with tempfile.TemporaryDirectory() as location:
            first = Path(location) / "first"
            second = Path(location) / "second"
            first.mkdir()
            second.mkdir()
            with self.assertRaisesRegex(verifier.BundleVerificationError, "two distinct"):
                verifier.verify(first, first)
            with mock.patch.object(verifier, "verify_one", side_effect=[{"outputs": "a"}, {"outputs": "b"}]) as audit:
                with self.assertRaisesRegex(verifier.BundleVerificationError, "not byte-reproducible"):
                    verifier.verify(first, second)
                self.assertEqual([row.args for row in audit.call_args_list], [(first,), (second,)])
