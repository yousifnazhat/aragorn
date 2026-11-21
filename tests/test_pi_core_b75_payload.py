"""Independent B75 metadata review. Read signed source objects; do not execute target code or build media."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import derive_pi_core_b75_payload as review


class PayloadReview(unittest.TestCase):
    def test_independent_projection_matches_five_reviewed_pins_and_the_exact_delta(self):
        pins, stats = review.reviewed_projection()
        catalog = review.prior.REPOSITORY / "packaging/pi-core/managed-payload-b75.json"
        self.assertEqual(pins, json.loads(catalog.read_bytes()))
        self.assertEqual(stats, dict(entries=1779, host_files=812, service_files=802, changed_files=41,
                                     added_files=15, host_additions=6, service_additions=9))

    def test_old_authenticated_revision_cannot_be_used_as_the_new_source_tree(self):
        old = [review.prior.REVISION, review.prior.TREE, "G", review.prior.SIGNER]
        with patch.object(review.prior, "_git", return_value="\n".join(old).encode()) as read:
            with self.assertRaisesRegex(ValueError, "wrong signed source"):
                review.prior._blobs({"src/aragorn/__init__.py"}, revision=review.REVISION, tree=review.TREE)
            self.assertEqual(read.call_count, 1)
            self.assertEqual(read.call_args.args[-1], review.REVISION)

    def test_wrong_retained_outcome_refuses_before_source_or_payload_read(self):
        with tempfile.TemporaryDirectory() as t:
            directory = Path(t).resolve()
            (directory / "outcome.json").write_bytes(b"{}")
            with patch.object(review.prior, "project", side_effect=AssertionError("read after wrong outcome")):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    review.reviewed_projection(directory=directory)

    def test_independent_delta_disallows_changed_worker_files_companion_copies_and_new_unrelated_rows(self):
        prior = review.prior
        root = prior.RUNTIME + "root/"
        row = dict(type="file", mode=0o444, uid=0, gid=0, sha256="1" * 64)
        old = {p: dict(type="dir", uid=0, gid=0, mode=0o755) for p in review.WORKER_ROOTS}
        for p, pin in review.PLAN_PINS.items():
            old[p] = dict(row, sha256=pin)
            if p.startswith("/" + prior.IMPORT):
                old[root + p[1:]] = dict(old[p])
        old[review.WORKER_ROOTS[0] + "/retained"] = dict(row)
        new = old | {"/" + prior.IMPORT + p: row for p in review.HOST_ADDED} | {
            root + prior.IMPORT + p: row for p in review.SERVICE_ADDED}
        for p in (review.WORKER_ROOTS[0] + "/retained", root + prior.IMPORT + "aragorn/pi_core_source_observer.py",
                  "/another-file"):
            with self.subTest(path=p), self.assertRaises(ValueError):
                review._review_delta(old, new | {p: dict(row, sha256="2" * 64)})
