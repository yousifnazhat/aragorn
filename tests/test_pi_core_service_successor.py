"""Inert tests for the changed service payload composition only."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts import prepare_pi_core_service_successor as batch
from scripts.build_pi_core_linux import BuildError


class ServicePayload(unittest.TestCase):
    def setUp(self):
        self.base = {"schema": batch.split.SCHEMA, "entries": [batch.split._dir(p, 0o755)
                     for p in ("/etc/aragorn", "/var/lib/aragorn")]}
        self.m = {"directories": ["test"], "files": [dict(path="test/file", size=1,
                   digest=batch._pin(b"x"), executable=False)]}
        self.docs = {batch.DEPLOY + "/" + batch.service.RECEIPT: b"receipt",
                     batch.REFS + "/manifest.json": b"manifest", batch.REFS + "/runtime-binding.json": b"binding"}

    def test_exact_deployment_names_and_coordinator_input_modes(self):
        payload = batch.compose(self.base, self.m, self.docs)
        rows = {r["path"]: r for r in payload["entries"]}
        self.assertEqual(rows[batch.TREE]["mode"], 0o755)
        self.assertEqual(rows[batch.TREE + "/test"]["mode"], 0o555)
        self.assertEqual(rows[batch.TREE + "/test/file"]["mode"], 0o444)
        self.assertEqual(rows[batch.DEPLOY + "/" + batch.service.RECEIPT]["mode"], 0o444)
        self.assertEqual(rows[batch.REFS]["mode"], 0o700)
        for n in batch.PIN_DOCS:
            self.assertEqual((rows[batch.REFS + "/" + n]["mode"], rows[batch.REFS + "/" + n]["uid"]), (0o400, 0))
        self.assertFalse(any(p.startswith(batch.TREE + "/etc/aragorn/") for p in rows))

    def test_never_overlay_existing_names_or_add_authority_documents(self):
        for path in (batch.DEPLOY, batch.TREE + "/already-owned", batch.REFS + "/x"):
            with self.subTest(path=path), self.assertRaisesRegex(BuildError, "conceal"):
                batch._no_collision(["/etc", path])
        with self.assertRaisesRegex(BuildError, "parent"):
            batch.compose({"entries":[]}, self.m, self.docs)
        with self.assertRaisesRegex(BuildError, "document set"):
            batch.compose(self.base, self.m, {**self.docs, batch.REFS + "/approval.json": b"forbidden"})

    def test_missing_reviewed_source_or_native_override_is_rejected(self):
        old = {"source_digests": {"opt/aragorn/src/aragorn/old.py": batch._pin(b"t")},
               "wrappers": {"provider":{"path":"opt/aragorn/bin/provider.py"}}}
        for code in ({}, {p:b"t" for p in ("opt/aragorn/bin/provider.py", "opt/aragorn/src/aragorn/old.py", "usr/bin/python3")}):
            with self.subTest(paths=sorted(code)), self.assertRaisesRegex(BuildError, "omits"):
                batch.service_inputs({"files":[]}, old, code)

    def test_retained_file_links_and_wrong_mode_refuse(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            f = root / "file"
            f.write_bytes(b"ok")
            f.chmod(0o444)
            r = dict(size=2, mode=0o444)
            self.assertEqual(batch._retained(root, "file", r), b"ok")
            (root / "symbolic").symlink_to(f)
            with self.assertRaisesRegex(BuildError, "linked"):
                batch._retained(root, "symbolic", r)
            with self.assertRaisesRegex(BuildError, "type or mode"):
                batch._retained(root, "file", dict(r, mode=0o555))
            os.link(f,root / "hardlink")
            with self.assertRaisesRegex(BuildError, "type or mode"):
                batch._retained(root, "file", r)
