"""Inert producer-to-independent-consumer contract, never native evidence."""

from __future__ import annotations

import hashlib
import unittest

from aragorn.oci_worker_protocol import canonical_digest
from aragorn.runtime_worker_ingress_verify import (
    WorkerIngressVerificationError,
    verify_worker_ingress_records,
)
from test_runtime_worker_ingress_measurement import (
    BINDING,
    PEER,
    PIN,
    InertStore,
    documents,
)


class WorkerIngressIntegrationTests(unittest.TestCase):
    def retained_chain(self):
        fixture = InertStore()
        self.addCleanup(fixture.close)
        store = fixture.open()
        request, attempt, state, action = documents()
        trace = store.begin(request, PEER)
        store.bind_attempt(trace, attempt, state, PIN)
        store.bind_action(trace, action)
        stages = ("startup", "ingress", "attempt", "action")
        raw = [(fixture.root / f"{stage}.json").read_bytes() for stage in stages]
        expected = {
            "expected_record_digests": {
                stage: "sha256:" + hashlib.sha256(value).hexdigest()
                for stage, value in zip(stages, raw, strict=True)
            },
            "expected_worker": {
                key: fixture.identity[key]
                for key in ("pid", "start_time_ticks", "uid", "gid")
            },
            "expected_binding_digest": canonical_digest(BINDING),
            "expected_genesis_digest": PIN,
        }
        store.close()
        return raw, expected, (request, attempt, state, action)

    def test_actual_emitted_bytes_pass_independent_consumer_without_promotion(self):
        raw, expected, documents_used = self.retained_chain()
        result = verify_worker_ingress_records(*raw, **expected)
        self.assertEqual(result["status"], "RETAINED_WORKER_INGRESS_CHAIN_VERIFIED")
        for name, document in zip(
            (
                "worker_request_digest",
                "attempt_digest",
                "receipt_state_digest",
                "action_request_digest",
            ),
            documents_used,
            strict=True,
        ):
            self.assertEqual(result[name], canonical_digest(document))
        self.assertTrue(result["decision"])
        self.assertTrue(all(value is False for value in result["decision"].values()))
        self.assertEqual(
            result["stage_boottime_ns"],
            dict(
                zip(
                    ("startup", "ingress", "attempt", "action"),
                    range(1000, 1004),
                    strict=True,
                )
            ),
        )

    def test_retained_byte_change_refuses_without_recomputing_caller_pin(self):
        raw, expected, _documents = self.retained_chain()
        raw[1] = raw[1].replace(b"inert-session", b"other-session")
        with self.assertRaises(WorkerIngressVerificationError):
            verify_worker_ingress_records(*raw, **expected)


if __name__ == "__main__":
    unittest.main()
