"""Small source-projection refusal cases; the actual retained assembly has its own stage."""
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_service_successor_sources as batch


class ServiceSuccessorSources(TestCase):
    def test_forged_target_manifest_refuses_before_local_source_reads(self):
        with patch.object(batch.image, "source_closure") as walk, self.assertRaisesRegex(ValueError, "foreign"):
            batch.prepare(b'{"files":[]}')
        walk.assert_not_called()

    def test_delta_cannot_repin_unchanged_or_add_unreviewed_files(self):
        pin = batch.image.pin
        before = {"aragorn/one.py": pin(b"one")}
        review = {"source_inventory_digest": pin(batch.image.canonical(before)), "source_changes": before}
        with self.assertRaisesRegex(ValueError, "redundant"):
            batch._inventory(before, review)
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            batch._inventory(before, dict(review, source_changes={"aragorn/other.py": pin(b"two")}))

    def test_new_unsupported_site_must_not_be_silently_carried(self):
        pin = batch.image.pin
        raw = b'{"files":[]}'
        old = {"source_changes": {}, "source_inventory_digest": pin(b"{}"),
               "prior_manifest_digest": pin(raw), "prior_assembly_inputs_digest": pin(b"before"),
               "unsupported_import_sites_digest": pin(b"[]")}
        with patch.object(batch, "_document", side_effect=[old, {"expected_source_inventory": {}, "source_root": "src"}]), \
             patch.object(batch.image, "source_closure", return_value=({}, [], [{"new": True}])), \
             patch.object(batch.image, "_wrappers") as wrappers, self.assertRaisesRegex(ValueError, "unsupported"):
            batch.prepare(raw)
        wrappers.assert_not_called()
