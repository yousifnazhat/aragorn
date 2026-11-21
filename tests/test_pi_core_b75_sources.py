"""Check the B75 material changes against retained B69 metadata, without rebuilding either payload."""
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts import prepare_pi_core_b75_sources as sources


prior = sources.prior
ROOT = Path.home() / "Library/Application Support/Aragorn-B69-Offline/root"
HOST = "etc/aragorn/coordinator-host.json"
BINDING = "etc/aragorn/service-runtime-inputs/runtime-binding.json"
PREFIX = "/opt/aragorn/src/"
ADDED = frozenset("aragorn/pi_core_" + name + ".py" for name in (
    "sensor_state_entry", "sensor_state_observer", "sensor_state_evidence", "sensor_state_custody",
    "stopped_worker_walk", "worker_walk_evidence"))
SERVICE_ONLY_ADDED = frozenset("aragorn/pi_core_" + name + ".py" for name in (
    "coordinator_entry", "managed_bootstrap", "mask_capture_release"))


class B75SignedSources(TestCase):
    def test_exact_additions_and_shared_pins_against_retained_b69(self):
        catalog = prior.previous._document(sources.REVIEW, sources.REVIEW_PIN)
        profile = prior.previous._document(ROOT / HOST, catalog["prior_host_profile_digest"])
        binding = prior.previous._document(ROOT / BINDING, catalog["prior_service_binding_digest"])
        old_host = {r["path"]: r["digest"] for r in profile["files"] if r["path"].startswith(PREFIX)}
        changes = {p: v["digest"] for p, v in catalog["host_changes"].items()}
        old_service = {p.removeprefix(PREFIX[1:]): v for p, v in binding["source_digests"].items()}
        new_service = old_service | catalog["service_changes"]
        self.assertEqual(len(changes), 18)
        self.assertEqual(len(catalog["service_changes"]), 16)
        self.assertEqual({p.removeprefix(PREFIX) for p in changes if p.startswith(PREFIX)} -
                         {p.removeprefix(PREFIX) for p in old_host}, ADDED)
        self.assertEqual(new_service.keys() - old_service.keys(), ADDED | SERVICE_ONLY_ADDED)
        updated_host = old_host | changes
        self.assertTrue(all(updated_host[PREFIX + p] == digest for p, digest in new_service.items()))

    def test_b65_predecessor_and_b69_source_catalog_cannot_substitute_for_b75(self):
        old = prior.previous._document(prior.REVIEW, prior.REVIEW_PIN)
        new = prior.previous._document(sources.REVIEW, sources.REVIEW_PIN)
        for key in ("prior_host_profile_digest", "prior_service_manifest_digest", "prior_service_binding_digest"):
            self.assertNotEqual(old[key], new[key])
        with patch.object(prior, "_git", side_effect=AssertionError("unexpected source read")):
            with self.assertRaisesRegex(ValueError, "predecessor"):
                sources.prepare(b"{}", b"{}", b"{}")
            with self.assertRaisesRegex(ValueError, "catalog differs"):
                prior._prepare(b"{}", b"{}", b"{}", review_path=prior.REVIEW,
                               review_pin=sources.REVIEW_PIN, revision=sources.REVISION, tree=sources.TREE)
            with self.assertRaisesRegex(ValueError, "catalog revision"):
                prior._prepare(b"{}", b"{}", b"{}", review_path=prior.REVIEW,
                               review_pin=prior.REVIEW_PIN, revision=sources.REVISION, tree=sources.TREE)

    def test_nonliteral_revision_or_tree_refused_before_git(self):
        with patch.object(prior, "_git", side_effect=AssertionError("unexpected Git invocation")):
            for revision, tree in (("--all", sources.TREE), (sources.REVISION, "HEAD^{tree}"),
                                   (sources.REVISION.upper(), sources.TREE)):
                with self.subTest(revision=revision, tree=tree), self.assertRaisesRegex(ValueError, "identity"):
                    prior._objects({"src/aragorn/__init__.py": "unused"}, revision=revision, tree=tree)
