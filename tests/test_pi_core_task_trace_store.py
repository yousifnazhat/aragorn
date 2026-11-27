"""Temporary private roots and real CAS objects; no guest, worker, or tracing."""
from copy import deepcopy
from io import BytesIO
from time import monotonic
from unittest import TestCase
from unittest.mock import Mock

from aragorn import pi_core_task_trace_store as traces
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_mask_custody as private, test_pi_core_task_entry_replay as entry


class TaskTraceStoreTests(TestCase):
    def setUp(self):
        p, e = private.MaskCustodyTests(),entry.StaticEntryReplayTests()
        for fixture in (p,e):
            self.addCleanup(fixture.doCleanups)
            fixture.setUp()
        self.dest = dict(store=p.store,receipt_directory=p.receipts,expected_roots=p.roots)
        self.args = dict(e.f.arguments)
        input_cas = self.args.pop("evidence_cas")
        self.expected = {k:deepcopy(v) for k,v in self.args.items() if not k.endswith("_raw")}
        # The released source/loader bytes have been provisioned in the nominated CAS.
        writer = CAS(p.store)
        for row in (*e.f.record["sources"],*e.f.record["loaders"]):
            raw = input_cas.read(row["digest"],max_bytes=1<<20)
            writer.put_expected(BytesIO(raw),expected_digest=row["digest"],max_bytes=len(raw))
        self.binding = canonical_digest(e.binding)
        self.records = dict(zip(("binding","authorization","exec","transition"),
                                map(canonical_json,(e.binding,e.auth,e.exec,e.link))))
        self.trace = e.f.record
        self.guard = Mock(return_value=None)

    def publish(self):
        return traces.retain_task_trace(**self.dest,records=self.records,observation_raw=canonical_json(self.trace),
                          deadline=monotonic()+10,guard=self.guard,replay_inputs=self.args)

    def replay(self,receipt,**overrides):
        return traces.replay_retired_task_trace(**self.dest,binding_digest=self.binding,receipt_digest=receipt,
                                                **(self.expected | overrides))

    def test_independent_read_only_reopen_needs_no_live_objects(self):
        receipt = self.publish()
        self.records.clear()
        self.trace.clear()
        self.args.clear()
        self.guard.side_effect = AssertionError("retired owner consulted")
        result = self.replay(receipt)
        self.assertEqual(result["status"],"CONSISTENT_RECORDED_STATIC_ENTRY_DELIVERY")
        self.assertEqual(result["entrypoint_bytes"],398741)
        self.assertFalse(result["acquisition_authenticity_verified"])
        with self.assertRaises(ValueError):
            self.replay(receipt,expected_worker=self.expected["expected_worker"] | {"start_ticks":11111})
        with self.assertRaises(ValueError):
            self.replay("sha256:"+"a"*64)

    def test_failed_replay_preserves_spent_slot_and_original_trace_not_success(self):
        self.trace["events"][16]["result"] -= 1
        pin = canonical_digest(self.trace)
        with self.assertRaises(ValueError): self.publish()
        self.assertEqual(CAS(self.dest["store"],read_only=True).read(pin,max_bytes=4<<20),canonical_json(self.trace))
        names = {p.name for p in self.dest["receipt_directory"].iterdir()}
        self.assertEqual(names,{"task-trace-"+self.binding[7:]+"-publishing.json"})
        self.trace["events"][16]["result"] += 1
        with self.assertRaises(FileExistsError): self.publish()

    def test_private_destination_and_named_receipt_are_pinned(self):
        original = self.dest["expected_roots"]
        self.dest["expected_roots"] = original[::-1]
        with self.assertRaises(ValueError): self.publish()
        self.assertFalse(list(self.dest["receipt_directory"].iterdir()))
        self.dest["expected_roots"] = original
        receipt = self.publish()
        path = self.dest["receipt_directory"] / ("task-trace-"+self.binding[7:]+"-receipt.json")
        other = path.with_suffix(".original")
        path.rename(other)
        path.symlink_to(other)
        with self.assertRaises(ValueError): self.replay(receipt)
        self.assertTrue(other.is_file())

    def test_lost_custody_never_returns_receipt_or_reopens_spent_slot(self):
        def check():
            if any(self.dest["receipt_directory"].iterdir()):
                raise ValueError("worker custody lost")
        self.guard.side_effect = check
        with self.assertRaisesRegex(ValueError,"worker custody lost"): self.publish()
        self.guard.side_effect = None
        with self.assertRaises(FileExistsError): self.publish()
