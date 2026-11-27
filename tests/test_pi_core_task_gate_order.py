"""Actual order guard and stop reader, using inert proc data and local file descriptors."""
import threading
from types import SimpleNamespace
from unittest import TestCase

from aragorn import pi_core_task_gate_order as order, pi_core_task_static_source as static
from aragorn import pi_core_task_owner_roles as roles
from aragorn.pi_core_task_owner import _Task
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_task_gate_stop_reader as fixtures


class GateOrderTests(TestCase):
    def setUp(self):
        f = self.f = fixtures.GateStopReaderTests()
        self.addCleanup(f.doCleanups)
        f.setUp()
        f.worker.pidfd = f.fd
        f.worker.files.update({p:f.fd for p in roles._WORKER_PINS})
        self.intake = static._Intake(f.worker,{"ticket_digest":canonical_digest("original ticket")},f.until)
        self.o = self.intake.observer

    def first(self):
        return order.GateStops(self.intake,deadline=self.f.until)

    def final_site(self):
        self.f.syscall = b"-1 0xfff0 0x21054c\n"

    def armed(self):
        # Only model pre-exec tracer ownership. No syscall, thread or worker is started.
        self.o._attached, self.o._state = True, "HELD"
        self.o._node_session = SimpleNamespace(owned=self.f.worker,observer=self.o,thread=threading.current_thread())

    def complete(self):
        g = self.first()
        g.published()
        self.final_site()
        g.final()
        self.armed()
        return g

    def test_first_then_final_and_fresh_tracer_readback_authorize_exact_node_once(self):
        g = self.first()
        g.published()
        held = _Task(None,{},None,self.f.until,None,lambda:None,None,self.intake,g)
        self.final_site()
        held.observe_final_gate_stop()
        self.armed()
        proof = held.authorize_node_transition(self.o)
        self.assertEqual(proof["first"]["site"],"first")
        self.assertEqual(proof["final"]["site"],"final")
        self.assertEqual(proof["pre_exec"]["phase"],"traced-gate")
        self.assertEqual(proof["claim_digest"],self.intake._record["claim_digest"])
        self.assertEqual(proof["node_argv_hex"],roles._NODE_ARGV.hex())
        proof["final"]["worker"]["invocation_id"] = "bad"
        g.require_authorized(self.o)
        self.assertFalse(self.o._executed)
        with self.assertRaises(ValueError): held.authorize_node_transition(self.o)
        with self.assertRaises(ValueError): g.require_authorized(self.o)

    def test_lone_first_stop_missing_publication_or_repeated_first_refuses(self):
        for which in ("first-only","no-publication","twice-first"):
            with self.subTest(which=which):
                g = self.first()
                if which != "no-publication": g.published()
                with self.assertRaises(ValueError):
                    if which=="first-only": g.authorize(self.o)
                    else: g.final()
                self.final_site()
                with self.assertRaises(ValueError): g.final()
                with self.assertRaises(ValueError): g.require_authorized(self.o)
                self.f.syscall = b"-1 0xfff0 0x210524\n"

    def test_reversed_sites_at_start_or_right_before_node_refuse(self):
        self.final_site()
        with self.assertRaises(ValueError): self.first()
        self.f.syscall = b"-1 0xfff0 0x210524\n"
        g = self.complete()
        self.f.syscall = b"-1 0xfff0 0x210524\n"
        with self.assertRaises(ValueError): g.authorize(self.o)
        self.final_site()
        with self.assertRaises(ValueError): g.authorize(self.o)

    def test_same_pid_generation_swap_at_final_or_at_consume_is_terminal(self):
        record = self.f.worker._record["worker"]
        for field,changed,edge in (("start_ticks",712,"final"),("invocation_id","f"*32,"authorize")):
            with self.subTest(field=field):
                self.f.syscall = b"-1 0xfff0 0x210524\n"
                g = self.first()
                g.published()
                self.final_site()
                if edge=="authorize":
                    g.final()
                    self.armed()
                original = record[field]
                record[field] = changed
                with self.assertRaises(ValueError):
                    if edge=="authorize": g.authorize(self.o)
                    else: g.final()
                record[field] = original
                with self.assertRaises(ValueError): g.require_authorized(self.o)
                self.o._state,self.o._attached,self.o._node_session = "STATIC_BOUND",False,None

    def test_already_executed_wrong_observer_thread_or_closed_owner_never_authorizes(self):
        for why in ("executed","thread","foreign","closed"):
            with self.subTest(why=why):
                self.f.syscall = b"-1 0xfff0 0x210524\n"
                g = self.complete()
                candidate = self.o if why!="foreign" else object()
                if why=="executed": self.o._executed = True
                if why=="thread": self.o._thread += 1
                if why=="closed": g.close()
                with self.assertRaises(ValueError): g.authorize(candidate)
                self.o._thread = threading.get_native_id()
                self.o._state,self.o._attached,self.o._executed,self.o._node_session = "STATIC_BOUND",False,False,None
