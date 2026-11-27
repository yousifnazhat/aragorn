"""One ordered static-gate transition for the claimed fixed task."""
from contextlib import contextmanager
from copy import deepcopy
import os
import signal
import threading

from .oci_worker_protocol import canonical_digest
from .pi_core_identity_handoff import validate_deadline
from .pi_core_source_observer import GATE_PATH, NODE_PATH, _Kernel
from .pi_core_state_admission import _need, _same
from .pi_core_task_gate_stop_reader import read_gate_stop
from .pi_core_task_static_source import _Intake


class GateStops:
    """Observe the gate; never attach, signal, or resume it. Receipts are not release tokens."""
    def __init__(self, intake, *, deadline):
        _need(type(intake) is _Intake and deadline == intake._deadline,"original static observer intake required")
        self._intake, self._deadline = intake,deadline
        self._bound = intake.receipt()
        self._subject, self._observer = intake._subject,intake.observer
        self._owner = os.getpid(),threading.get_native_id()
        self._closed, self._state, self._lock = False,"NEW",threading.Lock()
        self._rows = {}
        with self._step("NEW","FIRST"):
            self._sample("first","first","stopped")

    @contextmanager
    def _step(self, expected, result):
        _need(self._lock.acquire(blocking=False),"concurrent static gate transition")
        try:
            state, self._state = self._state,"REFUSED"
            _need(not self._closed and state == expected and self._intake._subject is self._subject
                  and self._observer._owned is self._subject and os.getpid()==self._owner[0],
                  "closed, refused or out-of-order static gate transition")
            validate_deadline(self._deadline)
            yield
            validate_deadline(self._deadline)
            _need(not self._closed and self._intake._subject is self._subject,"static gate custody ended")
            self._state = result
        finally:
            self._lock.release()

    def _sample(self, label, expected, phase):
        if phase=="stopped":
            _need(threading.get_native_id()==self._owner[1] and self._observer._state=="STATIC_BOUND"
                  and not self._observer._attached and not self._observer._executed,"original stopped gate owner required")
        row = read_gate_stop(self._subject,phase=phase,deadline=self._deadline)
        _need(row["site"]==expected and row["phase"]==phase,"wrong static gate stop site")
        _same(row["worker"],self._bound["worker"],"different gate worker generation")
        _same(row["clock"],self._bound["clock"],"different gate clock")
        _same(dict(digest=row["gate_digest"],identity=row["gate_identity"]),self._bound["files"][str(GATE_PATH)],
              "different gate executable")
        if self._rows:
            _need(row["mapping_raw_hex"] == self._rows["first"]["mapping_raw_hex"],"static gate mapping changed")
        self._rows[label] = row

    def published(self):
        """The owner must still see FIRST after publishing its protected endpoints."""
        with self._step("FIRST","PUBLISHED"):
            self._sample("after_publication","first","stopped")

    def final(self):
        with self._step("PUBLISHED","FINAL"):
            self._sample("final","final","stopped")

    def authorize(self, observer):
        """One readback at the tracer-owned final stop, before the pinned Node transition."""
        with self._step("FINAL","AUTHORIZED"):
            _need(observer is self._observer and observer._state=="HELD" and observer._attached
                  and not observer._executed and observer._thread==threading.get_native_id()
                  and observer._node_session is not None and observer._node_session.owned is self._subject
                  and observer._node_session.observer is observer and observer._node_session.thread is threading.current_thread(),
                  "original pre-exec gate tracer required")
            self._sample("pre_exec","final","traced-gate")
            proof = dict(schema="aragorn/static-task-gate-order/v1",claim_digest=self._bound["claim_digest"],
                         binding_digest=canonical_digest(self._bound),node_argv_hex=self._bound["node_argv_hex"],
                         **deepcopy(self._rows))
            self._session, self._thread, self._kernel = observer._node_session,threading.current_thread(),observer._kernel
            self._authorization_digest = canonical_digest(proof)
        return proof

    def _require_held(self, observer):
        _need(not self._closed and observer is self._observer
              and os.getpid()==self._owner[0] and self._intake._subject is self._subject
              and observer._owned is self._subject and observer._pidfd==self._subject.pidfd
              and observer._state=="HELD" and observer._attached and observer._node_session is self._session
              and self._session.owned is self._subject and self._session.observer is observer
              and self._session.thread is self._thread and self._thread.is_alive() and observer._thread==self._thread.native_id
              and observer._kernel is self._kernel,"no matching Node transition for this observer")
        validate_deadline(self._deadline)

    def require_authorized(self, observer):
        _need(self._state=="AUTHORIZED","missing final gate authorization")
        self._require_held(observer)

    def _peek_exec(self):
        # Linux waitid returns the event code, not waitpid's shifted status.
        # WNOWAIT leaves the notification for the tracer's normal event handling.
        event = os.waitid(os.P_PIDFD,self._subject.pidfd,os.WSTOPPED | os.WNOHANG | os.WNOWAIT)
        w = self._bound["worker"]
        _need(event is not None and (event.si_signo,event.si_code,event.si_status,event.si_pid,event.si_uid)==
              (signal.SIGCHLD,os.CLD_TRAPPED,(4 << 8) | signal.SIGTRAP,w["pid"],w["uid"]),
              "missing exact pending Node exec-stop")
        return dict(signo=event.si_signo,code=event.si_code,status=event.si_status,pid=event.si_pid,uid=event.si_uid)

    def observe_node_exec(self, observer):
        with self._step("AUTHORIZED","NODE_OBSERVED"):
            self._require_held(observer)
            _need(threading.current_thread() is self._thread and not observer._executed
                  and type(self._kernel) is _Kernel,"original pre-consumption tracer required")
            event = self._peek_exec()
            row = self._subject.read_node_stop(deadline=self._deadline)
            _same(row["worker"],self._bound["worker"],"different Node worker generation")
            _same(row["clock"],self._bound["clock"],"different Node clock")
            _same(dict(digest=row["node_digest"],identity=row["node_identity"]),self._bound["files"][str(NODE_PATH)],
                  "different Node executable")
            _need(row["node_argv_hex"]==self._bound["node_argv_hex"] and row["tracer_tid"]==self._thread.native_id,
                  "different Node invocation or tracer")
            former = self._kernel.message(event["pid"])
            _need(former==event["pid"] and self._peek_exec()==event,"Node exec-stop changed or came from another thread")
            self._require_held(observer)
            return dict(schema="aragorn/static-task-node-exec/v1",authorization_digest=self._authorization_digest,
                        wait=event | {"former_tid":former},node=deepcopy(row))

    def require_node_observed(self, observer):
        _need(self._state=="NODE_OBSERVED","Node exec-stop has not been observed")
        self._require_held(observer)

    def close(self):
        self._closed = True
