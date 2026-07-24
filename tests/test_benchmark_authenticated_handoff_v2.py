from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import aragorn.benchmark_authenticated_handoff_v2 as authenticated_handoff
from aragorn.benchmark_authenticated_handoff_v2 import (
    AuthenticatedHandoffError,
    collect_signed_worker_output,
    issue_worker_measurement_challenge,
)
from aragorn.benchmark_handoff_v2 import (
    build_worker_output_handoff_manifest,
    export_handoff,
)
from aragorn.benchmark_worker_measurement import (
    build_worker_measurement,
    build_worker_trust_store,
    generate_worker_signing_key,
    sign_worker_measurement,
    write_worker_trust_store,
)
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json
from tests import test_benchmark_semantic_closure_v2 as semantic_support


try:
    import cryptography  # noqa: F401
except ImportError:
    HAS_CRYPTOGRAPHY = False
else:
    HAS_CRYPTOGRAPHY = True


@unittest.skipUnless(
    HAS_CRYPTOGRAPHY,
    "locked cryptography worker dependency is not installed",
)
class AuthenticatedWorkerHandoffV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)

        self.evidence = semantic_support.BenchmarkSemanticClosureV2Tests()
        self.evidence.setUp()
        self.addCleanup(self.evidence.doCleanups)
        (
            self.result_digest,
            self.request_digest,
            self.result,
        ) = self.evidence._deep_output()
        self.challenge = "b" * 64
        self.worker_id = "isolated-worker-01"
        self.trust_domain = "phase0.example"

        manifest = build_worker_output_handoff_manifest(
            self.evidence.source,
            self.result_digest,
            expected_request_digest=self.request_digest,
            expected_verifier_challenge=self.challenge,
        )
        self.bundle = self.root / "worker-output"
        self.manifest_digest = export_handoff(
            self.evidence.source,
            manifest,
            self.bundle,
            expected_request_digest=self.request_digest,
            expected_verifier_challenge=self.challenge,
        )

        self.private_key = self.root / "worker.key"
        self.key = generate_worker_signing_key(
            self.private_key,
            worker_id=self.worker_id,
        )
        self.trust_store = build_worker_trust_store(
            trust_domain=self.trust_domain,
            keys=[self.key],
        )
        self.trust_store_path = self.root / "trust-store.json"
        write_worker_trust_store(self.trust_store_path, self.trust_store)
        self.ledger = self.root / "measurement-ledger"
        issue_worker_measurement_challenge(
            self.ledger,
            trust_domain=self.trust_domain,
            worker_id=self.worker_id,
            job_id=self.result["job_id"],
            request_digest=self.request_digest,
            verifier_challenge=self.challenge,
        )
        self.statement = build_worker_measurement(
            trust_domain=self.trust_domain,
            worker_id=self.worker_id,
            key_id=self.key["key_id"],
            job_id=self.result["job_id"],
            verifier_challenge=self.challenge,
            request_digest=self.request_digest,
            result_digest=self.result_digest,
            handoff_manifest_digest=self.manifest_digest,
        )
        self.envelope = sign_worker_measurement(
            self.statement,
            self.private_key,
        )
        self.destination = CAS(self.root / "control-cas")

    def _collect(self, envelope: bytes | None = None) -> dict[str, str]:
        return collect_signed_worker_output(
            self.bundle,
            self.destination,
            self.envelope if envelope is None else envelope,
            trust_store_path=self.trust_store_path,
            ledger_root=self.ledger,
            verifier_challenge=self.challenge,
        )

    def test_valid_signed_output_imports_deep_verifies_and_consumes_once(
        self,
    ) -> None:
        receipt = self._collect()
        repeated = self._collect()

        self.assertEqual(receipt, repeated)
        self.assertEqual(
            receipt["assurance"],
            "software_key_signature_not_hardware_attested",
        )
        self.assertEqual(receipt["result_digest"], self.result_digest)
        self.assertEqual(
            receipt["handoff_manifest_digest"],
            self.manifest_digest,
        )
        self.destination.verify(self.result_digest)
        self.destination.verify(receipt["envelope_digest"])
        self.destination.verify(receipt["trust_store_digest"])
        committed = list((self.ledger / "receipts").glob("*.json"))
        self.assertEqual(len(committed), 1)
        self.assertEqual(json.loads(committed[0].read_bytes()), receipt)

    def test_signature_or_semantic_failure_consumes_nothing(self) -> None:
        changed = bytearray(self.envelope)
        changed[-2] = ord("0") if changed[-2] != ord("0") else ord("1")
        with self.assertRaises(AuthenticatedHandoffError):
            self._collect(bytes(changed))
        self.assertEqual(list((self.ledger / "receipts").glob("*.json")), [])

        wrong_statement = deepcopy(self.statement)
        wrong_statement["handoff_manifest_digest"] = "sha256:" + "0" * 64
        wrong_envelope = sign_worker_measurement(
            wrong_statement,
            self.private_key,
        )
        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "not accepted",
        ):
            self._collect(wrong_envelope)
        self.assertEqual(list((self.ledger / "receipts").glob("*.json")), [])

        receipt = self._collect()
        self.assertEqual(receipt["result_digest"], self.result_digest)

    def test_deep_rejection_never_promotes_forged_result_from_quarantine(
        self,
    ) -> None:
        forged = deepcopy(self.result)
        forged_receipts = {
            phase: dict(receipt)
            for phase, receipt in self.result["runner_receipts"].items()
        }
        forged_receipts["post"]["daemon_info_digest"] = self.evidence._put(
            self.evidence.source,
            b"{}",
        )
        forged["runner_receipts"] = forged_receipts
        forged_digest = self.evidence._put(
            self.evidence.source,
            canonical_json(forged),
        )
        manifest = build_worker_output_handoff_manifest(
            self.evidence.source,
            forged_digest,
            expected_request_digest=self.request_digest,
            expected_verifier_challenge=self.challenge,
        )
        forged_bundle = self.root / "forged-worker-output"
        forged_manifest_digest = export_handoff(
            self.evidence.source,
            manifest,
            forged_bundle,
            expected_request_digest=self.request_digest,
            expected_verifier_challenge=self.challenge,
        )
        forged_statement = deepcopy(self.statement)
        forged_statement["result_digest"] = forged_digest
        forged_statement["handoff_manifest_digest"] = forged_manifest_digest
        forged_envelope = sign_worker_measurement(
            forged_statement,
            self.private_key,
        )

        with self.assertRaisesRegex(AuthenticatedHandoffError, "not accepted"):
            collect_signed_worker_output(
                forged_bundle,
                self.destination,
                forged_envelope,
                trust_store_path=self.trust_store_path,
                ledger_root=self.ledger,
                verifier_challenge=self.challenge,
            )
        with self.assertRaises(CASError):
            self.destination.verify(forged_digest)
        self.assertEqual(list((self.ledger / "receipts").glob("*.json")), [])

    def test_conflicting_replay_is_rejected(self) -> None:
        self._collect()
        changed = deepcopy(self.statement)
        changed["result_digest"] = "sha256:" + "0" * 64
        conflicting = sign_worker_measurement(changed, self.private_key)

        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "consumed by another binding",
        ):
            self._collect(conflicting)

    def test_signed_and_issued_job_must_match_the_imported_result(self) -> None:
        wrong_job = "0" * 32
        wrong_ledger = self.root / "wrong-job-ledger"
        issue_worker_measurement_challenge(
            wrong_ledger,
            trust_domain=self.trust_domain,
            worker_id=self.worker_id,
            job_id=wrong_job,
            request_digest=self.request_digest,
            verifier_challenge=self.challenge,
        )
        wrong_statement = deepcopy(self.statement)
        wrong_statement["job_id"] = wrong_job
        wrong_envelope = sign_worker_measurement(
            wrong_statement,
            self.private_key,
        )

        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "job_id does not match",
        ):
            collect_signed_worker_output(
                self.bundle,
                CAS(self.root / "wrong-job-cas"),
                wrong_envelope,
                trust_store_path=self.trust_store_path,
                ledger_root=wrong_ledger,
                verifier_challenge=self.challenge,
            )
        self.assertEqual(list((wrong_ledger / "receipts").glob("*.json")), [])

    def test_concurrent_conflict_produces_exactly_one_acceptance(self) -> None:
        changed = deepcopy(self.statement)
        changed["handoff_manifest_digest"] = "sha256:" + "0" * 64
        conflicting = sign_worker_measurement(changed, self.private_key)

        def attempt(envelope: bytes) -> str:
            try:
                self._collect(envelope)
            except AuthenticatedHandoffError:
                return "rejected"
            return "accepted"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, (self.envelope, conflicting)))

        self.assertEqual(sorted(outcomes), ["accepted", "rejected"])
        self.assertEqual(len(list((self.ledger / "receipts").glob("*.json"))), 1)

    def test_receipt_publication_failure_is_not_acceptance(self) -> None:
        original = authenticated_handoff._publish_record

        def fail_receipt(
            root,
            content,
            *,
            destination_directory,
            filename,
        ):
            if destination_directory == "receipts":
                raise AuthenticatedHandoffError("simulated receipt failure")
            return original(
                root,
                content,
                destination_directory=destination_directory,
                filename=filename,
            )

        with mock.patch.object(
            authenticated_handoff,
            "_publish_record",
            side_effect=fail_receipt,
        ):
            with self.assertRaisesRegex(
                AuthenticatedHandoffError,
                "simulated receipt failure",
            ):
                self._collect()
        self.assertEqual(list((self.ledger / "receipts").glob("*.json")), [])

        receipt = self._collect()
        self.assertEqual(receipt["result_digest"], self.result_digest)

    def test_exact_retry_rederives_every_receipt_field(self) -> None:
        receipt = self._collect()
        path = next((self.ledger / "receipts").glob("*.json"))
        changed = deepcopy(receipt)
        changed["result_digest"] = "sha256:" + "0" * 64
        path.chmod(0o600)
        path.write_bytes(canonical_json(changed))
        path.chmod(0o400)

        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "does not re-derive",
        ):
            self._collect()

    def test_worker_bundle_cannot_overlap_destination_or_verifier_state(
        self,
    ) -> None:
        nested_bundle = self.destination.root / "worker-bundle"
        nested_bundle.mkdir(mode=0o700)
        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "boundaries overlap",
        ):
            collect_signed_worker_output(
                nested_bundle,
                self.destination,
                self.envelope,
                trust_store_path=self.trust_store_path,
                ledger_root=self.ledger,
                verifier_challenge=self.challenge,
            )

        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "boundaries overlap",
        ):
            collect_signed_worker_output(
                self.ledger,
                self.destination,
                self.envelope,
                trust_store_path=self.trust_store_path,
                ledger_root=self.ledger,
                verifier_challenge=self.challenge,
            )

    def test_issuance_is_idempotent_but_cannot_be_rebound(self) -> None:
        repeated = issue_worker_measurement_challenge(
            self.ledger,
            trust_domain=self.trust_domain,
            worker_id=self.worker_id,
            job_id=self.result["job_id"],
            request_digest=self.request_digest,
            verifier_challenge=self.challenge,
        )
        self.assertEqual(repeated["verifier_challenge"], self.challenge)

        with self.assertRaisesRegex(
            AuthenticatedHandoffError,
            "bound differently",
        ):
            issue_worker_measurement_challenge(
                self.ledger,
                trust_domain=self.trust_domain,
                worker_id="isolated-worker-02",
                job_id=self.result["job_id"],
                request_digest=self.request_digest,
                verifier_challenge=self.challenge,
            )


if __name__ == "__main__":
    unittest.main()
