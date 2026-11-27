"""Real private evidence, inert kernel terminal observation; no worker or tracer."""
import json
import os
import select
from time import monotonic
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_task_retired_trace as retired
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_task_trace_store as storage, test_pi_core_task_tracer_lifetime as lifetimes


class RetiredTraceTests(TestCase):
    def setUp(self):
        self.seal = retired.seal_retired_trace
        f = self.f = storage.TaskTraceStoreTests()
        self.addCleanup(f.doCleanups)
        f.setUp()
        t = self.t = lifetimes.TracerLifetimeTests()
        self.addCleanup(t.doCleanups)
        k = t.f = lifetimes.fixtures.StaticWorkerBindingTests()
        # Only the guest kernel/manager seam runs as recorded uid 0. Private CAS IO
        # uses the real Mac identity, permissions and descriptor-relative operations.
        guest_os = SimpleNamespace(**vars(os))
        for module in (lifetimes.fixtures,lifetimes.fixtures.binding,lifetimes.roles,lifetimes.scope):
            t.enterContext(mock.patch.object(module,"os",guest_os))
        t.addCleanup(k.doCleanups)
        k.setUp()
        ref = json.loads(f.records["binding"])
        k.worker.update({key:value for key,value in ref["worker"].items() if key!="cgroup"})
        k.peer.update(k.worker)
        k.clock.update(ref["clock"])
        k.raw["ticket_digest"] = ref["ticket_digest"]
        k.held = lifetimes.roles._Held(k.read,k.held._owner,k.until)
        # The Linux fixture reports the recorded immutable guest identities only for
        # its own package FDs. A switched FD still fails the actual samestat checks.
        identity = {os.fstat(fd).st_ino:ref["files"][path]["identity"] for path,fd in k.paths.items()}
        k.metadata.update({path:ref["files"][path]["identity"] for path in k.paths})
        t.enterContext(mock.patch.object(lifetimes.roles.sources,"_file_identity",
                                         side_effect=lambda stat:identity[stat.st_ino]))
        slot = {"task":"fixed-entry-retirement"}
        claim = dict(schema="aragorn/fixed-task-owner-claim/v1",roles=k.held.record,ticket_digest=ref["ticket_digest"],
                     release_digest=canonical_digest("release"),slot=slot,commitment_digest=canonical_digest(slot))
        t.intake = t.enterContext(lifetimes.static.bind_task_source_observer(k.held,claim_raw=canonical_json(claim),
                                                                          deadline=k.until))
        t.w,t.o = t.intake._subject,t.intake.observer
        # Inert KCMP_FILE substitute distinguishes a fresh open of the same inode:
        # changing the witness position must also change the held FD's position.
        def same_description(pid,a,b):
            if pid!=os.getpid() or not os.path.samestat(os.fstat(a),os.fstat(b)):
                return False
            original = os.lseek(a,0,os.SEEK_CUR)
            try:
                pos = os.lseek(a,original+1,os.SEEK_SET)
                return os.lseek(b,0,os.SEEK_CUR)==pos
            finally:
                os.lseek(a,original,os.SEEK_SET)
        t.enterContext(mock.patch.object(lifetimes.scope,"_same_description",side_effect=same_description))
        self.life = t.life = lifetimes.scope.StaticTracerLifetime(t.intake,deadline=k.until)
        t.addCleanup(t.life.retire)
        binding = t.intake.receipt()
        self.assertEqual(binding,ref | {"claim_digest":canonical_digest(claim)})
        t.active()
        # These are the recording fixture's raw source events. Retain them against
        # this original intake, not an asserted binding_digest on a fake lifetime.
        auth,execution,link = (json.loads(f.records[key]) for key in ("authorization","exec","transition"))
        f.binding = canonical_digest(binding)
        auth.update(claim_digest=binding["claim_digest"],binding_digest=f.binding)
        execution["node"]["tracer_tid"] = t.o._thread
        execution["authorization_digest"] = canonical_digest(auth)
        link["exec_digest"] = canonical_digest(execution)
        f.records = dict(zip(("binding","authorization","exec","transition"),map(canonical_json,(binding,auth,execution,link))))
        f.guard = lambda:t.life.require_active(t.o)
        self.receipt = f.publish()

    def publish(self, **overrides):
        args = self.f.dest | dict(binding_digest=self.f.binding,receipt_digest=self.receipt,
                                  lifetime=self.life,deadline=monotonic()+10)
        return self.seal(**(args | overrides))

    def replay(self, pin, **overrides):
        args = self.f.dest | self.f.expected | dict(binding_digest=self.f.binding,receipt_digest=self.receipt,
                                                    terminal_digest=pin)
        return retired.replay_after_retirement(**(args | overrides))

    def test_offline_reopen_after_terminal_seal_does_not_consult_original_owner(self):
        read = self.t.terminal_readback(select.POLLIN)
        witness = self.life._witness
        pin = self.publish()
        read.assert_called_once_with(lifetimes.roles.WORKER,self.t.f.until)
        self.t.doCleanups()
        with self.assertRaises(OSError): os.fstat(witness)
        self.life = None
        self.f.guard = None
        self.f.args.clear()
        self.f.records.clear()
        self.f.trace.clear()
        replay = self.replay(pin)
        self.assertEqual(replay["retirement"],"RECORDED_ORIGINAL_WORKER_TERMINAL")
        self.assertEqual(replay["entrypoint_bytes"],398741)
        self.assertFalse(replay["phase3_qualified"])
        self.assertFalse(replay["acquisition_authenticity_verified"])

    def test_trace_receipt_is_not_retirement_and_other_receipts_cannot_be_substituted(self):
        with self.assertRaises((FileNotFoundError,ValueError)):
            self.replay(self.receipt)
        with self.assertRaises(ValueError): self.publish(lifetime=object())
        self.t.terminal_readback(select.POLLIN)
        pin = self.publish()
        with self.assertRaises(ValueError): self.replay(pin,receipt_digest="sha256:"+"9"*64)
        with self.assertRaises(ValueError): self.replay(self.receipt)
        with self.assertRaises(ValueError):
            self.replay(pin,expected_worker=self.f.expected["expected_worker"] | {"start_ticks":7777})

    def test_nonterminal_or_foreign_readback_spends_slot_without_terminal_marker(self):
        self.t.terminal_readback(0)
        with self.assertRaises(ValueError): self.publish()
        read = self.t.terminal_readback(select.POLLIN)
        with self.assertRaises(FileExistsError): self.publish()
        read.assert_not_called()
        with self.assertRaises((FileNotFoundError,ValueError)): self.replay(self.receipt)

    def test_changed_terminal_unit_identity_does_not_seal(self):
        self.t.terminal_readback(select.POLLIN,{"InvocationID":"f"*32})
        with self.assertRaises(ValueError): self.publish()
        self.assertFalse(any(p.name.endswith("-terminal.json") for p in self.f.dest["receipt_directory"].iterdir()))

    def test_named_terminal_proof_must_match_the_external_pin_and_still_be_private(self):
        self.t.terminal_readback(select.POLLIN)
        pin = self.publish()
        with self.assertRaises(ValueError): self.replay(pin,expected_clock=self.f.expected["expected_clock"] | {"time_namespace_inode":0})
        name, = self.f.dest["receipt_directory"].glob("*-terminal.json")
        original = name.with_suffix(".preserved")
        name.rename(original)
        name.symlink_to(original)
        with self.assertRaises(ValueError): self.replay(pin)
        self.assertTrue(original.is_file())
