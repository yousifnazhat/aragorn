"""Actual order guard and stop reader, using inert proc data and local file descriptors."""
import threading
import os
import signal
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_task_gate_order as order, pi_core_task_static_source as static
from aragorn import pi_core_task_owner_roles as roles
from aragorn.pi_core_task_owner import _Task
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_task_gate_stop_reader as fixtures
from tests import test_pi_core_task_observer_binding as bindings


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

    def node_transition(self):
        # Run the actual gate and Node readers on the same open local file handles.
        b = self.proc = bindings.StaticWorkerBindingTests()
        self.addCleanup(b.doCleanups)
        b.setUp()
        worker = self.f.worker = self.enterContext(b.hold())
        self.f.st = os.fstat(worker.files[str(roles.sources.GATE_PATH)])
        self.f.maps = self.f.mapping()
        self.f.syscall = b"-1 0xfff0 0x210524\n"
        read = roles.kernel._read
        self.enterContext(mock.patch.object(roles.kernel,"_read",side_effect=lambda fd,name,*args:
            self.f.syscall if name=="syscall" else self.f.maps if name=="maps" else read(fd,name,*args)))
        self.intake = static._Intake(worker,{"ticket_digest":canonical_digest("original ticket")},self.f.until)
        self.o = self.intake.observer
        g = self.complete()
        b.state,b.tracer = "t",threading.get_native_id()
        kernel = self.o._kernel = object.__new__(static.source._Kernel)
        kernel.message = mock.Mock(return_value=worker.worker["pid"])
        bound = self.intake._record
        pin = bound["files"][str(roles.sources.NODE_PATH)]
        identity = dict(worker=worker.worker,clock=worker.clock,node_digest=pin["digest"],
                        node_identity=pin["identity"],node_argv_hex=bound["node_argv_hex"],
                        tracer_tid=threading.get_native_id())
        siginfo = SimpleNamespace(si_pid=worker.worker["pid"],si_uid=worker.worker["uid"],
                                  si_signo=signal.SIGCHLD,si_code=4,si_status=(4 << 8) | signal.SIGTRAP)
        wait = mock.Mock(return_value=siginfo)
        self.enterContext(mock.patch.multiple(os,create=True,waitid=wait,P_PIDFD=3,WNOWAIT=0x01000000,
                                              WNOHANG=1,WSTOPPED=2,CLD_TRAPPED=4))
        task = _Task(None,{},None,self.f.until,None,lambda:None,None,self.intake,g)
        authorization = task.authorize_node_transition(self.o)
        b.exe,b.argv = str(roles.sources.NODE_PATH),roles._NODE_ARGV
        return g,task,identity,siginfo,wait,authorization

    def test_only_a_fresh_pinned_exec_stop_completes_gate_to_node_handoff(self):
        g,task,row,_,wait,auth = self.node_transition()
        with self.assertRaises(ValueError): g.require_node_observed(self.o)
        receipt = task.observe_node_exec(self.o)
        self.assertEqual(receipt["authorization_digest"],canonical_digest(auth))
        self.assertEqual(receipt["node"],row)
        self.assertEqual(receipt["wait"]["former_tid"],row["worker"]["pid"])
        expected = mock.call(os.P_PIDFD,self.f.worker.pidfd,os.WNOHANG | os.WSTOPPED | os.WNOWAIT)
        self.assertEqual(wait.call_args_list,[expected,expected])
        g.require_node_observed(self.o)
        self.assertFalse(self.o._executed)  # Not an executed/healthy source-observer latch.
        with self.assertRaises(ValueError): task.observe_node_exec(self.o)
        with self.assertRaises(ValueError): g.require_node_observed(self.o)

    def test_substituted_node_argv_or_worker_generation_cannot_reach_release(self):
        for field in ("substituted_exe","argv","start_ticks","invocation_id"):
            with self.subTest(field=field):
                g,task,_,_,_,_ = self.node_transition()
                if field=="substituted_exe": change = mock.patch.object(self.proc,"exe",str(roles.sources.GATE_PATH))
                elif field=="argv": change = mock.patch.object(self.proc,"argv",roles._NODE_ARGV + b"unexpected\0")
                else: change = mock.patch.dict(self.proc.peer,{field:703 if field=="start_ticks" else "9"*32})
                with change,self.assertRaises(ValueError): task.observe_node_exec(self.o)
                with self.assertRaises(ValueError): g.require_node_observed(self.o)
                with self.assertRaises(ValueError): task.observe_node_exec(self.o)
                with self.assertRaises(ValueError):
                    task.release(control=None,directory_fd=None,source_observer=self.o,activation=None)

    def test_signal_stop_foreign_or_consumed_event_and_replaced_tracer_refuse(self):
        for bad in ("no_event","wrong_pid","wrong_uid","not_trapped","plain_trap","old_tid","consumed","session"):
            with self.subTest(bad=bad):
                g,task,_,event,wait,_ = self.node_transition()
                if bad=="no_event": wait.return_value = None
                elif bad=="wrong_pid": event.si_pid += 1
                elif bad=="wrong_uid": event.si_uid = 0
                elif bad=="not_trapped": event.si_code = 5
                elif bad=="plain_trap": event.si_status = signal.SIGTRAP
                elif bad=="old_tid": self.o._kernel.message.return_value = event.si_pid + 1
                elif bad=="consumed": wait.side_effect = [event,None]
                else: self.o._node_session = SimpleNamespace(**vars(self.o._node_session))
                with self.assertRaises(ValueError): task.observe_node_exec(self.o)
                with self.assertRaises(ValueError): g.require_node_observed(self.o)
