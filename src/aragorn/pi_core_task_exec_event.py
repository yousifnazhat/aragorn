"""Gate the original static task tracer's wait before consuming its exec event."""
import os
import signal
import threading

from .oci_worker_protocol import canonical_digest
from .pi_core_node_source_observer import _NodeSession
from .pi_core_source_observer import PiSourceObserver
from .pi_core_state_admission import _need
from .pi_core_task_observer_binding import _StaticWorker


_EXEC = (4 << 8) | signal.SIGTRAP


class _StaticWait:
    def __init__(self, task, observer, session, original):
        self.task, self.observer, self.session, self.original = task,observer,session,original
        self.owned, self.thread = observer._owned,session.thread
        self.worker = self.owned.worker
        self.proof, self.refused = None,False

    def _held(self, observer):
        _need(not self.refused and self.observer is observer and observer._state=="HELD" and observer._attached
              and observer._owned is self.owned and observer._pidfd==self.owned.pidfd
              and observer._node_session is self.session and self.session._wait_one is self
              and self.session.observer is observer and self.session.owned is self.owned
              and self.session.thread is self.thread and self.thread.native_id==observer._thread
              and self.thread.is_alive(), "lost static exec handler custody")

    def consumed(self, observer):
        self._held(observer)
        _need(self.proof is not None, "no matched consumed static exec")
        seq = self.proof["stop_seq"]
        events = observer._events
        _need(0<seq<=len(events) and canonical_digest(events[seq-1])==self.proof["stop_digest"],
              "original consumed exec stop changed")
        return self.proof.copy()

    def __call__(self, tid):
        try:
            o,s = self.observer,self.session
            self._held(o)
            _need(threading.current_thread() is self.thread and tid in s.tasks, "not the static tracer thread or task")
            if self.proof is not None:
                # Ordinary post-exec reads retain the original thread-aware event handling.
                _need(o._executed, "exec stop has not been interpreted")
                return self.original(tid)
            w = self.worker
            _need(not o._executed and tid==w["pid"] and set(s.tasks)=={tid} and s.tasks[tid]["joined"]
                  and s.tasks[tid]["start_ticks"]==w["start_ticks"], "pre-exec singleton task changed")
            pending = os.waitid(os.P_PIDFD,o._pidfd,os.WSTOPPED|os.WNOHANG|os.WNOWAIT)
            if pending is None:
                return False  # Do not consume a new arrival in the gap after an empty peek.
            _need((pending.si_signo,pending.si_code,pending.si_pid,pending.si_uid)==
                  (signal.SIGCHLD,os.CLD_TRAPPED,tid,w["uid"]),"foreign or non-tracer wait before exec")
            status = pending.si_status
            _need(status in (_EXEC,signal.SIGTRAP|0x80,(128<<8)|signal.SIGTRAP,(128<<8)|signal.SIGSTOP),
                  "unexpected pre-exec wait")
            evidence = None
            if status==_EXEC:
                evidence = self.task.observe_node_exec(o)
                _need(evidence["wait"]==dict(signo=pending.si_signo,code=pending.si_code,status=status,pid=tid,
                      uid=w["uid"],former_tid=tid) and evidence["node"]["worker"]==w,
                      "exec observation differs from pending stop")
            seq = len(o._events)+1
            _need(self.original(tid) and len(o._events)==seq, "pending wait was lost or replaced")
            row = o._events[-1]
            _need(s.pending_events and s.pending_events[-1] is row and row["kind"]=="STOP" and row["seq"]==seq
                  and row["pid"]==tid and row["start_ticks"]==w["start_ticks"] and row["status"]==(status<<8)|0x7f
                  and row["event"]==status>>8 and s.tasks[tid]["stop_seq"]==seq,
                  "consumed wait does not match pending stop")
            if evidence is not None:
                _need(row["event_message"]==tid and row["op"]=="NONE", "consumed exec is not the original singleton")
                self._held(o)
                self.proof = dict(schema="aragorn/static-task-consumed-exec/v1",exec_digest=canonical_digest(evidence),
                                  stop_seq=seq,stop_digest=canonical_digest(row))
            return True
        except BaseException:
            self.refused = True
            self.task.refuse_node_exec()
            raise


def install_task_exec_handler(task, observer):
    """After final gate authorization, bind only this session's original wait method."""
    _need(type(observer) is PiSourceObserver and type(observer._owned) is _StaticWorker and not observer._executed,
          "fixed-task pre-exec observer required")
    session = observer._node_session
    original = getattr(session,"_wait_one",None)
    _need(getattr(original,"__func__",None) is _NodeSession._wait_one and original.__self__ is session
          and session.thread is threading.current_thread(), "original tracer wait handler required")
    handler = _StaticWait(task,observer,session,original)
    session._wait_one = handler
    handler._held(observer)
    return handler
