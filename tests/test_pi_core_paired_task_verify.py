"""Portable replay of inert producer records. These are not qualified measurements."""
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

import test_pi_core_task_service as producer
from aragorn import pi_core_task_reference as reference
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_paired_task_verify import verify_portable


class PortableReplayTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.writer = CAS(temp.name)
        self.reader = CAS(temp.name, read_only=True)
        self.source = self.put(Path(reference.__file__).read_bytes())

    def put(self, raw):
        return self.writer.put(BytesIO(raw), max_bytes=1 << 20)

    def capture(self, task="BENIGN_JSON_SUM", mode="baseline"):
        helper = producer.TaskServiceTests()
        receipt, _ = (helper.copy_roundtrip(mode) if task == "BENIGN_COPY_READBACK"
                      else helper.roundtrip(task, mode))
        return receipt, helper.last_ticket, helper.last_sidecar

    def check(self, receipt, ticket, sidecar, *, request=None, bounds=None, **options):
        raw = canonical_json(receipt)
        self.put(raw)
        return verify_portable(raw, ticket["request"] if request is None else request,
                               receipt["boundaries"] if bounds is None else bounds, **(dict(
            evidence_cas=self.reader, reference_source_pin=self.source,
            ticket_pin=self.put(canonical_json(ticket)), sidecar_pin=self.put(canonical_json(sidecar))) | options))

    def test_producer_records_both_modes_all_tasks_return_only_semantic_completion(self):
        for task in ("BENIGN_JSON_SUM", "BENIGN_LINE_COUNT", "BENIGN_SHA256", "BENIGN_COPY_READBACK"):
            for mode in ("baseline", "instrumented"):
                with self.subTest(task=task, mode=mode):
                    r, t, s = self.capture(task, mode)
                    self.assertEqual(self.check(r,t,s), dict(semantics={"completed":True},
                        receipt_digest=canonical_digest(r), request_digest=canonical_digest(t["request"]),
                        deployment_digest=t["request"]["deployment_digest"]))

    def test_substituted_request_ticket_reference_and_outer_marks_refused(self):
        r,t,s = self.capture()
        for options in (dict(request=t["request"] | {"mode":"instrumented"}), dict(ticket_pin=self.put(canonical_json(t | {
                "environment_digest":canonical_digest("not the one observed")}))),
                dict(reference_source_pin=self.put(b"unrelated reference")),
                dict(bounds=r["boundaries"] | {"TASK_ACCEPTED": r["boundaries"]["TASK_ACCEPTED"] + 1})):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.check(r,t,s, **options)

    def test_noncanonical_sidecar_missing_receipt_and_writable_store_refused(self):
        r,t,s = self.capture()
        with self.assertRaises((CASError, ValueError)):
            verify_portable(canonical_json(r), t["request"], r["boundaries"], evidence_cas=self.reader,
                reference_source_pin=self.source, ticket_pin=self.put(canonical_json(t)), sidecar_pin=self.put(canonical_json(s)))
        for options in (dict(sidecar_pin=self.put(canonical_json(s) + b" ")), dict(evidence_cas=self.writer)):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.check(r,t,s, **options)

    def test_different_peers_and_even_a_unanimous_wrong_answer_refused(self):
        r,t,s = self.capture()
        for key in ("service_response","pi_response"):
            changed = deepcopy(s)
            changed[key]["observation"]["result"]["output"]["sum"] = 100
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(r,t,changed)
        changed, r = deepcopy(s), deepcopy(r)
        result = r["observation"]["result"]
        result["output"] = {"sum":100}
        result["output_digest"] = canonical_digest(result["output"])
        for key in ("service_response", "pi_response"):
            changed[key]["observation"] = deepcopy(r["observation"])
        changed["receipt_digest"] = canonical_digest(r)
        with self.assertRaises(ValueError):
            self.check(r,t,changed)

    def test_missing_malformed_or_different_service_completion_nonce_refused(self):
        receipt, ticket, sidecar = self.capture()
        first, second = "ab" * 32, "cd" * 32
        for service_nonce, pi_nonce in ((None, None), (None, first), (first, None), (first, second),
                                        ("A" * 64, "A" * 64), (first[:-1], first[:-1])):
            changed = deepcopy(sidecar)
            for key, nonce in (("service_response", service_nonce), ("pi_response", pi_nonce)):
                if nonce is None:
                    changed[key].pop("service_nonce", None)
                else:
                    changed[key]["service_nonce"] = nonce
            with self.subTest(service=service_nonce, pi=pi_nonce), self.assertRaises(ValueError):
                self.check(receipt, ticket, changed)

    def test_original_copy_bytes_generation_file_and_false_authority_cannot_be_substituted(self):
        r,t,s = self.capture("BENIGN_COPY_READBACK")
        original = s["copy_observation"]
        for patch in (dict(content_hex="00" + original["content_hex"][2:]),
                      dict(guest=original["guest"] | {"start_ticks":original["guest"]["start_ticks"] + 1}),
                      dict(file_identity=original["file_identity"] | {"nlink":True}),
                      dict(exclusive_writer_verified=True), dict(phase3_exit_eligible=0)):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                self.check(r,t,s | {"copy_observation": original | patch})
