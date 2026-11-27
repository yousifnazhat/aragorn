"""Inert kernel responses at the actual Node wait handler; never attach or start."""
import os
import signal
import threading
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_node_source_observer as node, pi_core_source_observer as base
from aragorn import pi_core_task_exec_event as fixed
from aragorn.pi_core_task_observer_binding import _StaticWorker


class TaskExecEventTests(TestCase):
    def setUp(self):
        self.pid, self.uid, self.ticks = 501, 1250, 733
        self.exec = (4 << 8) | signal.SIGTRAP
        w = self.held = object.__new__(_StaticWorker)
        w.pidfd = 83
        w._record = dict(worker=dict(pid=self.pid, uid=self.uid, gid=self.uid, start_ticks=self.ticks,
                                      invocation_id="c"*32,unit="aragorn-pi-task-worker.service"))
        s = self.s = object.__new__(node._NodeSession)
        o = self.o = base.PiSourceObserver(base._SEAL)
        s.observer, s.owned, s.thread = o,w,threading.current_thread()
        s.tasks = {self.pid:dict(joined=True,stopped=False,start_ticks=self.ticks)}
        s.stopping, s.pending_events = False,[]
        o._owned, o._node_session, o._pidfd, o._worker = w,s,w.pidfd,w.worker
        o._attached = True
        o._kernel = mock.Mock()
        o._kernel.message.return_value = self.pid
        o._kernel.info.return_value = ("ENTRY",221,[0]*6,None,None)
        self.enterContext(mock.patch.object(base,"_tick",return_value=444))
        self.task = mock.Mock()
        self.order = []
        self.receipt = dict(schema="aragorn/static-task-node-exec/v1",authorization_digest="sha256:"+"a"*64,
                            wait=dict(signo=signal.SIGCHLD,code=4,status=self.exec,pid=self.pid,uid=self.uid,
                                      former_tid=self.pid),node=dict(worker=w.worker))
        def observation(observer):
            self.assertIs(observer,o)
            self.order.append("check")
            return self.receipt
        self.task.observe_node_exec.side_effect = observation
        self.peek = mock.Mock(side_effect=self.pending)
        self.take = mock.Mock(side_effect=self.consume)
        self.enterContext(mock.patch.multiple(os,create=True,waitid=self.peek,waitpid=self.take,P_PIDFD=3,
                                              WNOHANG=1,WSTOPPED=2,WNOWAIT=0x01000000,CLD_TRAPPED=4))
        self.status = self.exec

    def pending(self, kind, pidfd, flags):
        self.assertEqual((kind,pidfd,flags),(os.P_PIDFD,self.held.pidfd,os.WSTOPPED|os.WNOHANG|os.WNOWAIT))
        self.order.append("peek")
        if self.status is not None:
            return SimpleNamespace(si_signo=signal.SIGCHLD,si_status=self.status,si_code=os.CLD_TRAPPED,
                                   si_pid=self.pid,si_uid=self.uid)

    def consume(self, pid, flags):
        self.assertEqual((pid,flags),(self.pid,os.WNOHANG|0x40000000))
        self.order.append("take")
        return (self.pid,(self.status << 8) | 0x7f)

    def test_exec_checked_before_actual_wait_handler_and_receipt_matches_emitted_stop(self):
        h = fixed.install_task_exec_handler(self.task,self.o)
        self.assertTrue(self.s._wait_one(self.pid))
        stop, = self.o._events
        self.assertEqual(self.order,["peek","check","take"])
        self.assertIs(self.s.pending_events[-1],stop)
        sidecar = h.consumed(self.o)
        self.assertEqual(sidecar,dict(schema="aragorn/static-task-consumed-exec/v1",
                                      exec_digest=base.canonical_digest(self.receipt),
                                      stop_seq=stop["seq"],stop_digest=base.canonical_digest(stop)))
        sidecar["stop_seq"] = -1
        self.assertEqual(h.consumed(self.o)["stop_seq"],1)
        self.o._executed = True
        self.s.tasks[self.pid]["stopped"] = False
        self.status = signal.SIGTRAP|0x80
        self.assertTrue(self.s._wait_one(self.pid))
        self.assertEqual(self.order,["peek","check","take","take"])
        self.assertEqual(self.o._events[-1]["op"],"ENTRY")
        self.assertEqual(h.consumed(self.o)["stop_seq"],1)
        self.task.refuse_node_exec.assert_not_called()
        stop["event_message"] += 1
        with self.assertRaisesRegex(ValueError,"original consumed exec stop changed"):
            h.consumed(self.o)

    def test_no_pending_wait_does_not_consume_new_arrival_and_exec_check_failure_does_not_wait(self):
        h = fixed.install_task_exec_handler(self.task,self.o)
        self.status = None
        self.assertFalse(self.s._wait_one(self.pid))
        self.take.assert_not_called()
        self.status = self.exec
        self.task.observe_node_exec.side_effect = ValueError("stale original")
        with self.assertRaisesRegex(ValueError,"stale original"): self.s._wait_one(self.pid)
        self.take.assert_not_called()
        self.task.refuse_node_exec.assert_called()
        with self.assertRaises(ValueError): h.consumed(self.o)

    def test_wrong_consumed_raw_status_or_foreign_former_tid_leaves_no_receipt(self):
        h = fixed.install_task_exec_handler(self.task,self.o)
        self.o._kernel.message.return_value = self.pid+1
        with self.assertRaises(ValueError): self.s._wait_one(self.pid)
        self.assertEqual(self.order,["peek","check","take"])
        self.task.refuse_node_exec.assert_called()
        with self.assertRaises(ValueError): h.consumed(self.o)

    def test_only_the_actual_exec_stop_triggers_check_and_consumption_mismatch_refuses(self):
        h = fixed.install_task_exec_handler(self.task,self.o)
        self.status = signal.SIGTRAP|0x80
        self.assertTrue(self.s._wait_one(self.pid))
        self.assertEqual(self.order,["peek","take"])
        self.task.observe_node_exec.assert_not_called()
        with self.assertRaises(ValueError): h.consumed(self.o)
        self.s.tasks[self.pid]["stopped"] = False
        self.status = self.exec
        self.take.side_effect = lambda *_:(self.pid, (signal.SIGTRAP << 8)|0x7f)
        with self.assertRaises(ValueError): self.s._wait_one(self.pid)
        self.task.refuse_node_exec.assert_called()
        with self.assertRaises(ValueError): h.consumed(self.o)
