"""One ordered static-gate transition for the claimed fixed task."""
from contextlib import contextmanager
from copy import deepcopy
import os
import threading

from .oci_worker_protocol import canonical_digest
from .pi_core_identity_handoff import validate_deadline
from .pi_core_source_observer import GATE_PATH
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
        return proof

    def require_authorized(self, observer):
        _need(not self._closed and self._state=="AUTHORIZED" and observer is self._observer
              and os.getpid()==self._owner[0] and self._intake._subject is self._subject
              and observer._owned is self._subject,"no ordered Node transition for this observer")
        validate_deadline(self._deadline)

    def close(self):
        self._closed = True
