"""Source-observer intake for the fixed systemd task worker."""
from contextlib import contextmanager
from copy import deepcopy
import json
import os

from . import pi_core_source_observer as source, pi_core_task_owner_roles as roles
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_state_admission import _keys, _need, _pin, _same
from .pi_core_task_observer_binding import bind_static_worker


class _Intake:
    """A binding is not an attach, source read, sensor challenge, or release."""
    def __init__(self, subject, claim, deadline):
        self._subject, self._deadline = subject, deadline
        self._observer = o = source.PiSourceObserver(source._SEAL)
        o._state = "STATIC_BOUND"
        # Borrow these from the original custody scope. Nothing here may reopen a PID
        # or start a transient Node session as a substitute for the static worker.
        o._owned, o._pidfd, o._deadline = subject, subject.pidfd, deadline
        o._worker, o._clock = deepcopy(subject.worker), deepcopy(subject.clock)
        entry = source.ENTRY_PATH
        files = {p:dict(digest=roles._WORKER_PINS[p][0],identity=source._file_identity(os.fstat(fd)))
                 for p,fd in subject.files.items()}
        o._source_fds[entry] = subject.files[entry]
        o._sources = [dict(path=entry,**deepcopy(files[entry]),readonly_view=True)]
        o._ranges[entry] = []
        o._executable_identities = {k:deepcopy(files[str(p)]["identity"]) for k,p in
                                    (("gate",source.GATE_PATH),("node",source.NODE_PATH))}
        o._bindings = {k+"_digest":files[str(p)]["digest"] for k,p in
                       (("gate",source.GATE_PATH),("node",source.NODE_PATH))}
        self._record = dict(schema="aragorn/static-task-source-binding/v1",claim_digest=canonical_digest(claim),
            ticket_digest=claim["ticket_digest"],worker=deepcopy(o._worker),clock=deepcopy(o._clock),files=files,
            gate_argv_hex=roles._GATE_ARGV.hex(), node_argv_hex=roles._NODE_ARGV.hex(),
            observation="STOPPED_BINDING_ONLY")

    @property
    def observer(self):
        return self._observer

    def receipt(self):
        _need(self._subject is not None and self.observer._state == "STATIC_BOUND","static source intake not held")
        try:
            self._subject.guard(phase="stopped",deadline=self._deadline)
        except BaseException:
            self.observer._state = "STATIC_REFUSED"
            raise
        return deepcopy(self._record)

    def require_active(self, candidate):
        o = self.observer
        _need(self._subject is not None and candidate is o and o._owned is self._subject,
              "source observer not bound to this task claim")
        _need(o._state == "HELD" and o._attached and o._executed and o._node_session is not None
              and o._node_session.owned is self._subject and o._node_session.observer is o,
              "static observer bound but not armed for source health")
        _same(o._worker,self._record["worker"],"different source observer worker generation")
        _same(o._clock,self._record["clock"],"different source observer clock")
        _need(o._pidfd == self._subject.pidfd and o._source_fds.get(source.ENTRY_PATH) == self._subject.files[source.ENTRY_PATH],
              "source observer left the held worker descriptors")
        files = self._record["files"]
        _need(all(o._bindings.get(k+"_digest") == files[str(p)]["digest"] and
                  o._executable_identities.get(k) == files[str(p)]["identity"] for k,p in
                  (("gate",source.GATE_PATH),("node",source.NODE_PATH))) and
              [r for r in o._sources if r["path"] == source.ENTRY_PATH] ==
              [dict(path=source.ENTRY_PATH,**files[source.ENTRY_PATH],readonly_view=True)],
              "active observer differs from bound task code")


@contextmanager
def bind_task_source_observer(held_roles, *, claim_raw, deadline):
    """Consume original spent-claim bytes and the roles held across its publication."""
    _need(type(claim_raw) is bytes and 0 < len(claim_raw) <= 4096,"original task claim required")
    claim = json.loads(claim_raw)
    _keys(claim, ("schema","roles","ticket_digest","release_digest","slot","commitment_digest"))
    _need(canonical_json(claim) == claim_raw and claim["schema"] == "aragorn/fixed-task-owner-claim/v1"
          and canonical_digest(claim["slot"]) == claim["commitment_digest"]
          and _pin(claim["ticket_digest"]) == held_roles.record["ticket_digest"],"different static task claim")
    _pin(claim["release_digest"])
    with bind_static_worker(held_roles,deadline=deadline) as subject:
        _same(claim["roles"],subject.record,"task claim names a different stopped generation")
        intake = _Intake(subject,claim,deadline)
        try:
            intake.receipt()
            yield intake
        finally:
            # The binding scope, not this non-attaching consumer, owns the duplicated FDs.
            intake._subject = None
            o = intake.observer
            o._pidfd, o._owned, o._state = -1, None, "CLOSED"
            o._source_fds.clear()
