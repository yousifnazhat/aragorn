"""Independent B69 metadata projection only; no staging, guest imports, disk build or live reads."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import derive_pi_core_b69_payload as review


class SignedPayloadReview(unittest.TestCase):
    def test_changed_tree_or_signer_cannot_begin_loading_blobs(self):
        identity = [review.REVISION, review.TREE, "G", review.SIGNER]
        for field in (1, 3):
            wrong = identity.copy()
            wrong[field] = "unexpected"
            with self.subTest(field=field), patch.object(review, "_git", return_value="\n".join(wrong).encode()) as read:
                with self.assertRaisesRegex(ValueError, "signed source"):
                    review._blobs({"src/aragorn/__init__.py"})
                self.assertEqual(read.call_count, 1)

    def test_five_pins_match_signed_blob_projection_and_retained_b65_metadata(self):
        published = json.loads((review.REPOSITORY / "packaging/pi-core/managed-payload-b69.json").read_bytes())
        self.assertEqual(review.derive(), published)
        self.assertEqual(set(published), {"schema", "payload_sha256", "host_profile_sha256", "manifest_sha256",
                                          "binding_sha256", "layout_receipt_sha256"})

    def test_review_refuses_substituted_retained_metadata_or_link_to_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            doc = root / "document"
            doc.write_bytes(b'{"entries":[]}')
            expected = review.sha(doc.read_bytes())
            alias = root / "linked"
            alias.symlink_to(doc)
            with self.assertRaisesRegex(ValueError, "path"):
                review.retained(alias, expected)
            doc.write_bytes(b'{"entries":[1]}')
            with self.assertRaisesRegex(ValueError, "digest"):
                review.retained(doc, expected)
