"""Custody of the fixed-task tracer from its original stopped worker to retirement."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
import select
import threading

from . import pi_core_task_owner_roles as roles
from .oci_worker_protocol import canonical_digest
from .pi_core_identity_handoff import validate_deadline
from .pi_core_node_source_observer import _NodeSession
from .pi_core_source_observer import _Kernel, ENTRY_PATH
from .pi_core_state_admission import _need, _same
from .pi_core_task_observer_binding import _StaticWorker
from .pi_core_task_owner_copy import _same_description
from .pi_core_task_static_source import _Intake


class _StaticSession:
    """Borrow the raw wait/record format, not the transient launcher or its pump."""
    _event, _wait_one = _NodeSession._event, _NodeSession._wait_one

    def __init__(self, lifetime):
        self._life = lifetime
        self.owned, self.observer, self.thread = lifetime._subject,lifetime._observer,threading.current_thread()
        w = self.owned.worker
        self.tasks = {w["pid"]:dict(start_ticks=w["start_ticks"],stopped=True,joined=True,call=None,
                                    stop_seq=None,stop_event=None)}
        self.pending_events,self.retired,self.stopping = [],set(),False
        self.loaders,self.profile = [],{"required_sources":[ENTRY_PATH]}

    def snapshot(self):
        _need(threading.current_thread() is self.thread,"static snapshot outside tracer thread")
        self._life.require_active(self.observer)
        raw = _NodeSession._snapshot(self)
        self._life.require_active(self.observer)
        return raw

    def command(self, *args):
        raise ValueError("no static observation command pump armed")


class StaticTracerLifetime:
    """One spent claim, one stopped worker, one bound thread. Never attach or resume."""
    def __init__(self, intake, *, deadline):
        _need(type(intake) is _Intake and type(intake._subject) is _StaticWorker and deadline==intake._deadline,
              "original static intake and deadline required")
        self._bound = intake.receipt()
        self._binding_digest = canonical_digest(self._bound)
        self._intake,self._subject,self._observer = intake,intake._subject,intake.observer
        self._owner,self._deadline = os.getpid(),deadline
        self._holder,self._read = self._subject._holder,self._subject._read
        self._pidfd,self._proc,self._files = self._subject.pidfd,self._subject._proc,dict(self._subject.files)
        self._session,self._tracer,self._kernel = None,None,None
        self._lock,self._state = threading.Lock(),"RESERVED"
        # This reference, not a PID reopened after exit, is the retirement witness.
        self._witness = os.dup(self._pidfd)
        try:
            self._original()
        except BaseException:
            self.retire()
            raise

    @property
    def binding_digest(self):
        return self._binding_digest

    def _original(self):
        w,o = self._subject,self._observer
        validate_deadline(self._deadline)
        _need(self._owner==os.getpid() and os.geteuid()==os.getegid()==0 and self._intake._subject is w
              and self._intake.observer is o and o._owned is w and self._read is not None
              and w._holder is self._holder and w._read is self._holder._read is self._read
              and w._proc==self._proc and dict(w.files)==self._files
              and o._pidfd==w.pidfd==self._pidfd and o._source_fds.get(ENTRY_PATH)==self._files[ENTRY_PATH]
              and _same_description(self._owner,self._witness,self._pidfd),"lost original static tracer handles")
        _same([w.worker,o._worker,w.clock,o._clock],
              [self._bound["worker"]]*2+[self._bound["clock"]]*2,"static tracer generation or clock changed")

    @contextmanager
    def _step(self, before, after):
        with self._lock:
            original,self._state = self._state,"REFUSED"
            _need(original==before and self._witness is not None,"static tracer lifetime spent or out of order")
            self._original()
            yield
            self._original()
            self._state = after

    def bind(self):
        """The nominated tracer thread accepts the still-untraced claimed worker."""
        with self._step("RESERVED","BOUND"):
            o = self._observer
            _need(o._state=="STATIC_BOUND" and not o._attached and not o._executed and o._kernel is None
                  and o._node_session is None,"original unarmed source observer required")
            self._subject.guard(phase="stopped",deadline=self._deadline)
            s = self._session = _StaticSession(self)
            self._tracer = s.thread
            o._node_session,o._thread = s,self._tracer.native_id
            return s

    def _session_held(self, candidate, *, terminal=False):
        s,o = self._session,self._observer
        _need(candidate is o and o._node_session is s and s.owned is self._subject and s.observer is o
              and s.thread is self._tracer and (terminal or self._tracer.is_alive()) and o._thread==self._tracer.native_id,
              "changed static tracer session or thread")

    def require_traced(self, candidate):
        with self._step("BOUND","TRACED"):
            self._session_held(candidate)
            _need(threading.current_thread() is self._tracer and candidate._state=="STATIC_BOUND"
                  and not candidate._attached and not candidate._executed and candidate._kernel is None,
                  "already armed or foreign tracer")
            # This guard verifies /proc TracerPid + singleton tracing-stop, not a caller's flag.
            self._subject.guard(phase="traced-gate",deadline=self._deadline)
            self._kernel = candidate._kernel = _Kernel()
            candidate._state,candidate._attached,candidate._stopped = "HELD",True,True

    def require_active(self, candidate):
        with self._step("TRACED","TRACED"):
            self._session_held(candidate)
            _need(candidate._kernel is self._kernel,"static tracer kernel binding changed")
            self._intake.require_active(candidate)
            # A release may be on the manager thread: verify the original tracer TID, not this caller.
            self._subject._guard(phase="node",deadline=self._deadline,tracer_tid=self._tracer.native_id)
            self._session_held(candidate)

    def terminal(self):
        """One read-only check of process retirement, not detach or full deployment cleanup."""
        with self._step("TRACED","TERMINAL"):
            self._session_held(self._observer,terminal=True)
            _need(self._observer._kernel is self._kernel,"terminal static tracer kernel binding changed")
            poller = select.poll()
            poller.register(self._witness,select.POLLIN|select.POLLERR|select.POLLHUP)
            events = poller.poll(0)
            _need(events in ([(self._witness,select.POLLIN)],[(self._witness,select.POLLIN|select.POLLHUP)]),
                  "original static worker has no definitive terminal pidfd event")
            w,clock = self._bound["worker"],self._bound["clock"]
            with ExitStack() as stack:
                root,mount = roles.kernel._proc(stack)
                _,manager = roles.kernel._role(stack,root,self._owner,mount)
                _need(mount==self._subject._mount and roles.sensor._boot_id(stack,root,mount,self._deadline)==clock["boot_id"]
                      and roles.sensor._namespace(stack,manager,"time",mount)==clock["time_namespace_inode"],
                      "terminal observation outside original clock/procfs")
            unit = roles.binding._show(roles.binding._unit_show(roles.WORKER,self._deadline))
            _need(unit["Id"]==w["unit"]==roles.WORKER and unit["LoadState"]=="loaded" and unit["FragmentPath"]==roles.WORKER_UNIT
                  and unit["NeedDaemonReload"]=="no" and not unit["DropInPaths"]
                  and (unit["ActiveState"],unit["SubState"],unit["MainPID"],unit["ControlPID"])==("inactive","dead","0","0")
                  and unit["ExecMainPID"] in ("0",str(w["pid"])) and unit["ControlGroup"] in ("",w["cgroup"])
                  and unit["InvocationID"] in ("","0"*32,w["invocation_id"]),"static worker unit not retired or replaced")
            return dict(schema="aragorn/static-task-tracer-terminal/v1",binding_digest=self.binding_digest,
                        worker=deepcopy(w),clock=deepcopy(clock),pidfd_events=events[0][1],
                        unit_state={k:unit[k] for k in ("Id","ActiveState","SubState","MainPID","ControlPID","InvocationID")})

    def retire(self):
        """Revoke the binding. Closing our duplicate does not claim any process exited."""
        with self._lock:
            self._state = "RETIRED"
            if self._session is not None and self._observer._node_session is self._session and self._observer._owned is self._subject:
                self._observer._state = "STATIC_RETIRED"
            witness,self._witness = self._witness,None
            if witness is not None:
                os.close(witness)
