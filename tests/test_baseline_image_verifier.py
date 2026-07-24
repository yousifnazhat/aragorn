from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).parents[1]))

from scripts import verify_baseline_images as verifier


def digest(character: str) -> str:
    return "sha256:" + character * 64


class BaselineImageVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.image = {
            "index_digest": digest("1"),
            "platform_manifest_digest": digest("2"),
            "config_digest": digest("3"),
            "build_provenance_manifest_digest": digest("4"),
            "architecture": "arm64",
            "os": "linux",
        }
        self.blobs = {
            digest("2"): 20,
            digest("3"): 30,
            digest("4"): 40,
            digest("5"): 50,
            digest("6"): 60,
            digest("7"): 70,
        }
        self.index = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": digest("2"),
                    "size": 20,
                    "platform": {"architecture": "arm64", "os": "linux"},
                },
                {
                    "digest": digest("4"),
                    "size": 40,
                    "platform": {"architecture": "unknown", "os": "unknown"},
                    "annotations": {
                        "vnd.docker.reference.digest": digest("2"),
                        "vnd.docker.reference.type": "attestation-manifest",
                    },
                },
            ],
        }
        self.platform = {
            "schemaVersion": 2,
            "config": {"digest": digest("3"), "size": 30},
            "layers": [{"digest": digest("5"), "size": 50}],
        }
        self.provenance = {
            "schemaVersion": 2,
            "config": {"digest": digest("6"), "size": 60},
            "layers": [
                {
                    "digest": digest("7"),
                    "size": 70,
                    "mediaType": "application/vnd.in-toto+json",
                    "annotations": {
                        "in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"
                    },
                }
            ],
        }
        self.config = {"architecture": "arm64", "os": "linux"}

    def test_locked_config_and_provenance_are_graph_children(self) -> None:
        verifier._verify_oci_graph(
            self.index,
            self.platform,
            self.provenance,
            self.config,
            self.blobs,
            self.image,
        )

        for field in ("config_digest", "build_provenance_manifest_digest"):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.image)
                changed[field] = digest("8")
                with self.assertRaises(verifier.VerificationError):
                    verifier._verify_oci_graph(
                        self.index,
                        self.platform,
                        self.provenance,
                        self.config,
                        self.blobs,
                        changed,
                    )

    def test_digest_reference_removes_only_a_tag(self) -> None:
        self.assertEqual(
            verifier._digest_reference("registry.example:5000/team/image:tag", digest("a")),
            "registry.example:5000/team/image@" + digest("a"),
        )

    def test_nonfinite_and_oversized_json_fail_before_use(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier._load(b'{"number":1e999}', "test document")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            path.write_bytes(b"12345")
            with self.assertRaises(verifier.VerificationError):
                verifier._read_file_bounded(path, 4, "test document")


if __name__ == "__main__":
    unittest.main()
