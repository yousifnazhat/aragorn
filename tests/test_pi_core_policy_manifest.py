"""Exercise original policy bytes in a temporary CAS; never launch or provision."""

from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_bundle_launch import PiBundleLaunchError, load_pi_core_policy_manifest
from tests.pi_core_policy_fixtures import policy_documents, store_policy_manifest


class PiPolicyManifestTests(TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.store = CAS(Path(directory) / "cas")
        self.manifest = store_policy_manifest(self.store)
        self.archive = CAS(self.store.root, read_only=True)

    def put(self, value):
        raw = value if isinstance(value, bytes) else canonical_json(value)
        return self.store.put(BytesIO(raw), max_bytes=len(raw))

    def test_originals_resolve_under_one_independent_manifest_pin(self):
        self.assertEqual(load_pi_core_policy_manifest(self.archive, canonical_digest(self.manifest)), self.manifest)

    def test_missing_swapped_noncanonical_and_ambiguous_members_refuse(self):
        admission = "admission_policy_digest"
        runtime = "runtime_action_policy_digest"
        m = self.manifest
        documents, _ = policy_documents()
        alternatives = (
            {"schema": m["schema"], admission: m[admission]},
            m | {admission: m[runtime], runtime: m[admission]},
            m | {runtime: m[admission]},
            m | {runtime: canonical_digest(documents[m[runtime]] | {"version": 2})},
            m | {runtime: self.put(documents[m[runtime]] | {"default": "ALLOW"})},
            m | {admission: self.put(documents[m[admission]] | {"required_analyzers": []})},
            m | {runtime: self.put(canonical_json(documents[m[runtime]]) + b"\n")},
            m | {"fallback": m[admission]},
            canonical_json(m) + b"\n",
            canonical_json(m)[:-1] + b',"schema":"aragorn/pi-core-policy-manifest/v1"}',
        )
        for case in alternatives:
            with self.subTest(case=case), self.assertRaises(PiBundleLaunchError):
                load_pi_core_policy_manifest(self.archive, self.put(case))
