from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from aragorn.benchmark_worker_measurement import (
    WorkerMeasurementError,
    build_worker_measurement,
    build_worker_trust_store,
    generate_worker_signing_key,
    sign_worker_measurement,
    validate_worker_measurement,
    validate_worker_trust_store,
    verify_worker_measurement,
)
from aragorn.oci_worker_protocol import canonical_json


try:
    import cryptography  # noqa: F401
except ImportError:
    HAS_CRYPTOGRAPHY = False
else:
    HAS_CRYPTOGRAPHY = True


DIGEST = "sha256:" + "a" * 64
REQUEST_DIGEST = "sha256:" + "b" * 64
RESULT_DIGEST = "sha256:" + "c" * 64
MANIFEST_DIGEST = "sha256:" + "d" * 64
JOB_ID = "e" * 32
CHALLENGE = "f" * 64


def synthetic_key(worker_id: str = "isolated-worker-01") -> dict[str, object]:
    public_key = bytes(range(32))
    return {
        "key_id": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "algorithm": "Ed25519",
        "public_key": public_key.hex(),
        "worker_id": worker_id,
        "scopes": ["aragorn/benchmark-worker-output/v2"],
        "status": "active",
    }


class WorkerMeasurementContractTests(unittest.TestCase):
    def test_statement_and_trust_store_are_exact_and_versioned(self) -> None:
        key = synthetic_key()
        store = build_worker_trust_store(
            trust_domain="phase0.example",
            keys=[key],
        )
        statement = build_worker_measurement(
            trust_domain=store["trust_domain"],
            worker_id=key["worker_id"],
            key_id=key["key_id"],
            job_id=JOB_ID,
            verifier_challenge=CHALLENGE,
            request_digest=REQUEST_DIGEST,
            result_digest=RESULT_DIGEST,
            handoff_manifest_digest=MANIFEST_DIGEST,
        )

        validate_worker_trust_store(store)
        validate_worker_measurement(statement)
        for field in statement:
            changed = deepcopy(statement)
            changed[f"extra_{field}"] = "not permitted"
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WorkerMeasurementError,
                    "fields are invalid",
                ):
                    validate_worker_measurement(changed)

    def test_trust_store_rejects_key_drift_order_and_unsupported_scope(self) -> None:
        first = synthetic_key("worker-a")
        second_public = bytes(reversed(range(32)))
        second = {
            **synthetic_key("worker-b"),
            "key_id": "sha256:" + hashlib.sha256(second_public).hexdigest(),
            "public_key": second_public.hex(),
        }
        sorted_keys = sorted([first, second], key=lambda item: item["key_id"])
        validate_worker_trust_store(
            {
                "schema": "aragorn/benchmark-worker-trust-store/v1",
                "trust_domain": "phase0.example",
                "keys": sorted_keys,
            }
        )

        with self.assertRaisesRegex(WorkerMeasurementError, "sorted and unique"):
            validate_worker_trust_store(
                {
                    "schema": "aragorn/benchmark-worker-trust-store/v1",
                    "trust_domain": "phase0.example",
                    "keys": list(reversed(sorted_keys)),
                }
            )
        changed = deepcopy(first)
        changed["key_id"] = DIGEST
        with self.assertRaisesRegex(WorkerMeasurementError, "does not match"):
            build_worker_trust_store(
                trust_domain="phase0.example",
                keys=[changed],
            )
        changed = deepcopy(first)
        changed["scopes"] = ["aragorn/another-scope/v1"]
        with self.assertRaisesRegex(WorkerMeasurementError, "supported"):
            build_worker_trust_store(
                trust_domain="phase0.example",
                keys=[changed],
            )

    def test_envelope_parser_rejects_duplicate_and_noncanonical_json_first(
        self,
    ) -> None:
        store = build_worker_trust_store(
            trust_domain="phase0.example",
            keys=[synthetic_key()],
        )
        expectations = {
            "expected_worker_id": "isolated-worker-01",
            "expected_job_id": JOB_ID,
            "expected_request_digest": REQUEST_DIGEST,
            "expected_challenge": CHALLENGE,
        }
        duplicate = (
            b'{"payload":"","payloadType":"x","payloadType":"y","signatures":[]}'
        )
        with self.assertRaisesRegex(WorkerMeasurementError, "repeats key"):
            verify_worker_measurement(duplicate, store, **expectations)
        noncanonical = (
            b'{ "payload":"","payloadType":"x","signatures":[]}'
        )
        with self.assertRaisesRegex(WorkerMeasurementError, "canonical JSON"):
            verify_worker_measurement(noncanonical, store, **expectations)


@unittest.skipUnless(
    HAS_CRYPTOGRAPHY,
    "locked cryptography worker dependency is not installed",
)
class WorkerMeasurementCryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.private_key = self.root / "worker.key"
        self.key = generate_worker_signing_key(
            self.private_key,
            worker_id="isolated-worker-01",
        )
        self.store = build_worker_trust_store(
            trust_domain="phase0.example",
            keys=[self.key],
        )
        self.statement = build_worker_measurement(
            trust_domain="phase0.example",
            worker_id="isolated-worker-01",
            key_id=self.key["key_id"],
            job_id=JOB_ID,
            verifier_challenge=CHALLENGE,
            request_digest=REQUEST_DIGEST,
            result_digest=RESULT_DIGEST,
            handoff_manifest_digest=MANIFEST_DIGEST,
        )
        self.envelope = sign_worker_measurement(
            self.statement,
            self.private_key,
        )
        self.expectations = {
            "expected_worker_id": "isolated-worker-01",
            "expected_job_id": JOB_ID,
            "expected_request_digest": REQUEST_DIGEST,
            "expected_challenge": CHALLENGE,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_valid_dsse_ed25519_measurement_verifies_every_binding(self) -> None:
        verified = verify_worker_measurement(
            self.envelope,
            self.store,
            **self.expectations,
        )

        self.assertEqual(verified.statement, self.statement)
        self.assertEqual(
            verified.statement["handoff_manifest_digest"],
            MANIFEST_DIGEST,
        )
        self.assertEqual(verified.statement["result_digest"], RESULT_DIGEST)
        self.assertRegex(verified.envelope_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(verified.trust_store_digest, r"^sha256:[0-9a-f]{64}$")

    def test_every_signed_identity_and_signature_mutation_fails(self) -> None:
        replacements = {
            "trust_domain": "other.example",
            "worker_id": "isolated-worker-02",
            "job_id": "0" * 32,
            "verifier_challenge": "0" * 64,
            "request_digest": DIGEST,
            "result_digest": DIGEST,
            "handoff_manifest_digest": DIGEST,
        }
        for field, value in replacements.items():
            envelope = json.loads(self.envelope)
            payload = json.loads(base64.b64decode(envelope["payload"]))
            payload[field] = value
            envelope["payload"] = base64.b64encode(
                canonical_json(payload)
            ).decode("ascii")
            with self.subTest(field=field):
                with self.assertRaises(WorkerMeasurementError):
                    verify_worker_measurement(
                        canonical_json(envelope),
                        self.store,
                        **self.expectations,
                    )

        envelope = json.loads(self.envelope)
        signature = bytearray(
            base64.b64decode(envelope["signatures"][0]["sig"])
        )
        signature[0] ^= 1
        envelope["signatures"][0]["sig"] = base64.b64encode(signature).decode(
            "ascii"
        )
        with self.assertRaisesRegex(WorkerMeasurementError, "signature is invalid"):
            verify_worker_measurement(
                canonical_json(envelope),
                self.store,
                **self.expectations,
            )

    def test_revoked_unknown_wrong_worker_and_multiple_signatures_fail(self) -> None:
        revoked = deepcopy(self.store)
        revoked["keys"][0]["status"] = "revoked"
        with self.assertRaisesRegex(WorkerMeasurementError, "revoked"):
            verify_worker_measurement(
                self.envelope,
                revoked,
                **self.expectations,
            )

        other_path = self.root / "other.key"
        other = generate_worker_signing_key(other_path, worker_id="worker-other")
        unknown_store = build_worker_trust_store(
            trust_domain="phase0.example",
            keys=[other],
        )
        with self.assertRaisesRegex(WorkerMeasurementError, "not trusted"):
            verify_worker_measurement(
                self.envelope,
                unknown_store,
                **self.expectations,
            )

        wrong_worker = deepcopy(self.store)
        wrong_worker["keys"][0]["worker_id"] = "worker-other"
        with self.assertRaisesRegex(WorkerMeasurementError, "expected worker"):
            verify_worker_measurement(
                self.envelope,
                wrong_worker,
                **self.expectations,
            )

        multiple = json.loads(self.envelope)
        multiple["signatures"].append(deepcopy(multiple["signatures"][0]))
        with self.assertRaisesRegex(WorkerMeasurementError, "exactly one"):
            verify_worker_measurement(
                canonical_json(multiple),
                self.store,
                **self.expectations,
            )

    def test_key_rotation_and_then_revocation_are_explicit(self) -> None:
        rotated_path = self.root / "rotated.key"
        rotated = generate_worker_signing_key(
            rotated_path,
            worker_id="isolated-worker-01",
        )
        overlapping = build_worker_trust_store(
            trust_domain="phase0.example",
            keys=sorted(
                [self.key, rotated],
                key=lambda item: item["key_id"],
            ),
        )
        verify_worker_measurement(
            self.envelope,
            overlapping,
            **self.expectations,
        )

        retired = deepcopy(overlapping)
        for key in retired["keys"]:
            if key["key_id"] == self.key["key_id"]:
                key["status"] = "revoked"
        with self.assertRaisesRegex(WorkerMeasurementError, "revoked"):
            verify_worker_measurement(
                self.envelope,
                retired,
                **self.expectations,
            )

    def test_private_key_permissions_symlinks_and_overwrite_fail_closed(self) -> None:
        with self.assertRaisesRegex(WorkerMeasurementError, "cannot create"):
            generate_worker_signing_key(
                self.private_key,
                worker_id="isolated-worker-01",
            )

        os.chmod(self.private_key, 0o644)
        with self.assertRaisesRegex(WorkerMeasurementError, "private owned"):
            sign_worker_measurement(self.statement, self.private_key)
        os.chmod(self.private_key, 0o600)

        link = self.root / "worker-link.key"
        link.symlink_to(self.private_key)
        with self.assertRaisesRegex(WorkerMeasurementError, "cannot read"):
            sign_worker_measurement(self.statement, link)


if __name__ == "__main__":
    unittest.main()
