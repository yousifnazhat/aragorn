"""The B69 projection's independent refusal boundaries, with inert Git replies only."""
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b69_sources as sources


class SignedSources(TestCase):
    path = "src/aragorn/example.py"
    data = b"pass\n"
    oid = b"a" * 40

    def records(self):
        signed = "\n".join((sources.REVISION, sources.TREE, "G", sources.SIGNER)).encode() + b"\n"
        header = self.oid + b" blob 5\n"
        entry = b"100644 blob " + self.oid + b"       5\t" + self.path.encode() + b"\x00"
        return [signed, entry, header + self.data + b"\n"]

    def read(self, replies):
        with patch.object(sources, "_git", side_effect=replies) as git:
            result = sources._objects({self.path: sources.image.pin(self.data)})
            self.assertEqual(git.call_args_list[-1].args, (["cat-file", "--batch"], self.oid + b"\n"))
            return result

    def test_exact_signed_tree_and_batch_return_pinned_bytes(self):
        self.assertEqual(self.read(self.records()), {self.path: self.data})

    def test_another_commit_tree_or_signer_cannot_select_any_blob(self):
        for original in (sources.REVISION, sources.TREE, sources.SIGNER, "G"):
            replies = self.records()
            replies[0] = replies[0].replace(original.encode(), b"other")
            with self.subTest(field=original), self.assertRaisesRegex(ValueError, "signature"):
                self.read(replies)

    def test_symlink_duplicate_or_extra_blob_bytes_refuse(self):
        signed, line, body = self.records()
        for entries, blobs in ((line.replace(b"100644", b"120000"), body), (line + line, body),
                               (line, body + b"x"), (line, body.replace(b"pass", b"FAIL"))):
            with self.subTest(entries=entries, blobs=blobs), self.assertRaises(ValueError):
                self.read([signed, entries, blobs])

    def test_unapproved_predecessor_refuses_before_git(self):
        with patch.object(sources, "_git", side_effect=AssertionError("unexpected Git read")), \
                self.assertRaisesRegex(ValueError, "predecessor"):
            sources.prepare(b"{}", b"{}", b"{}")

    def test_alternate_scanner_and_wrapper_bytes_cannot_override_their_pins(self):
        digest = sources.image.pin(b"pass\n")
        inventory = {name.replace(".", "/") + ".py": digest for name in sources.image.SOURCE_SEEDS}
        inventory["aragorn/__init__.py"] = digest
        bad = lambda root, name, expected: b"print(1)\n"
        with self.assertRaisesRegex(ValueError, "alternate source"):
            sources.image.source_closure("src", inventory, set(), reader=bad)
        with self.assertRaisesRegex(ValueError, "alternate wrapper"):
            sources.image._wrappers("wrappers", {r + ".py": digest for r in sources.image.ROLES}, reader=bad)
