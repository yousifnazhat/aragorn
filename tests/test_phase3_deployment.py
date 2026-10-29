"""Focused checks for the new shared-deployment join, not runtime qualification."""

import unittest
from copy import deepcopy
from io import BytesIO
from tempfile import TemporaryDirectory

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.phase3_deployment import (
    BINDING_DIMENSIONS,
    Phase3DeploymentError,
    build_phase3_deployment_identity,
    resolve_phase3_deployment_identity,
    retain_phase3_deployment_identity,
    validate_phase3_deployment_identity,
)


class Phase3DeploymentTests(unittest.TestCase):
    def test_retains_and_resolves_all_seven_identity_artifacts(self):
        with TemporaryDirectory() as root:
            cas = CAS(root)
            bindings = {
                key: cas.put(BytesIO(key.encode()), max_bytes=64)
                for key in BINDING_DIMENSIONS
            }
            identity = build_phase3_deployment_identity(bindings)
            pin = retain_phase3_deployment_identity(identity, evidence_cas=cas)
            self.assertEqual(pin, canonical_digest(identity))
            self.assertEqual(
                resolve_phase3_deployment_identity(
                    cas.read(pin), expected_digest=pin, evidence_cas=cas
                ),
                identity,
            )

    def test_missing_extra_or_non_digest_dimension_is_rejected(self):
        bindings = {key: "sha256:" + "a" * 64 for key in BINDING_DIMENSIONS}
        identity = build_phase3_deployment_identity(bindings)
        detached = validate_phase3_deployment_identity(identity)
        identity["bindings"]["worker"] = "sha256:" + "b" * 64
        self.assertNotEqual(identity, detached)
        for change in ("missing", "extra", "boolean", "path"):
            changed = deepcopy(bindings)
            if change == "missing":
                del changed["worker"]
            elif change == "extra":
                changed["phase3_exit_eligible"] = True
            else:
                changed["worker"] = True if change == "boolean" else "/latest/worker"
            with self.subTest(change=change), self.assertRaises(Phase3DeploymentError):
                build_phase3_deployment_identity(changed)

    def test_changed_identity_dangling_empty_and_noncanonical_artifacts_refuse(self):
        with TemporaryDirectory() as root:
            cas = CAS(root)
            digest = cas.put(BytesIO(b"identity"), max_bytes=64)
            identity = build_phase3_deployment_identity(
                {key: digest for key in BINDING_DIMENSIONS}
            )
            raw = canonical_json(identity)
            pin = canonical_digest(identity)
            with self.assertRaises(Phase3DeploymentError):
                resolve_phase3_deployment_identity(
                    raw, expected_digest="sha256:" + "0" * 64, evidence_cas=cas
                )
            noncanonical = raw + b"\n"
            with self.assertRaises(Phase3DeploymentError):
                resolve_phase3_deployment_identity(
                    noncanonical, expected_digest=pin, evidence_cas=cas
                )
            for bad in ("sha256:" + "0" * 64, cas.put(BytesIO(b""), max_bytes=0)):
                changed = deepcopy(identity)
                changed["bindings"]["worker"] = bad
                with self.subTest(digest=bad), self.assertRaises(Phase3DeploymentError):
                    retain_phase3_deployment_identity(changed, evidence_cas=cas)


if __name__ == "__main__":
    unittest.main()
