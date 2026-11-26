"""Manager-side fixed-task handoff. Never starts, resumes or retries either role."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
from pathlib import Path

from . import pi_core_mask_capture_release as ledger, pi_core_task_guest_binding as guest, pi_core_task_service as task
from .cas import CAS
from .oci_worker_protocol import canonical_digest
from .phase3_measurement_collector import _prepared_attempt_claim
from .pi_core_coordinator_entry import _Inputs
from .pi_core_identity_handoff import validate_deadline
from .pi_core_state_admission import _keys, _need, _pin, _same
from .pi_core_state_mounts import direct_mount_inventory
from .pi_core_task_owner_copy import _same_description, check_source_fd, resolve_service_copy
from .pi_core_task_owner_health import guard_task_health
from .pi_core_task_owner_roles import hold_stopped_roles
from .pi_core_task_static_source import bind_task_source_observer


RELEASE = Path("/etc/aragorn/approvals/fixed-task-owner.json")
CLAIMS = Path("/var/lib/aragorn-task-owner-claims")


@contextmanager
def _ledger(doc, ticket, deadline):
    identity = doc["claim_directory"]
    _keys(identity, ("dev","ino","mnt_id"))
    with ledger.custody._roots(RELEASE.parent, CLAIMS, deadline) as (fd, roots_guard, _):
        def guard():
            roots_guard()
            stat = ledger.view._stat(fd)
            _same(identity, {k:stat[k] for k in identity}, "fixed task claim directory changed")
            boot, raw = ledger._kernel_inputs(deadline)
            table = direct_mount_inventory(raw)
            path = next(p for p in (CLAIMS,*CLAIMS.parents) if str(p) in table)
            m = table[str(path)]
            _need(boot == ticket["clock"]["boot_id"] and m.mount_id == stat["mnt_id"]
                  and m.device == stat["dev"] and not m.device.startswith("0:") and m.filesystem in (b"ext4",b"xfs")
                  and b"rw" in m.options and b"rw" in m.super_options
                  and not any(Path(s) != CLAIMS and Path(s).is_relative_to(CLAIMS) for s in table),
                  "a nominated persistent writable task ledger is required")
            ledger._window(doc,deadline)
        guard()
        # This release may claim an entry, not provision or select a new evidence root.
        yield CAS(CLAIMS,read_only=True), guard
        guard()


def _send_release(*args, **kwargs):
    # Packaged alongside the owner from the already reviewed guest source; no alternate sender.
    from .pi_core_task_guest_entry import send_release
    return send_release(*args, **kwargs)


class _Task:
    def __init__(self, scope, ticket, nomination, deadline, roles, custody, service_listener, source_binding):
        self._scope, self._t, self._n, self._deadline = scope,ticket,nomination,deadline
        self._roles, self._custody = roles,custody
        self._listener = service_listener
        self._source_binding = source_binding
        self._phase, self._directory = "CLAIMED", None

    @property
    def source_binding(self):
        _need(self._phase == "CLAIMED","task source binding outside claimed lifetime")
        self._custody()
        return self._source_binding

    def guard(self):
        """Use for the release and the service's repeated authenticated OBSERVE requests."""
        _need(self._phase in ("RELEASING","RELEASED","MEASURING","RETAINED"),"task owner not active")
        try:
            self._custody()
            self._roles.guard(stopped=False)
            self._source_binding.require_active(self._source)
            guard_task_health(self._t,source_observer=self._source,activation=self._activation,
                              worker=self._roles.record["worker"],deadline=self._deadline)
            return self._t["environment_digest"]
        except BaseException:
            self._phase = "FAILED"
            raise

    def release(self, *, control, directory_fd, source_observer, activation):
        _need(self._phase == "CLAIMED","task release unavailable or already spent")
        self._phase = "RELEASING"
        try:
            self._source, self._activation = source_observer, deepcopy(activation)
            self.guard()
            check_source_fd(self._t,directory_fd)
            if directory_fd is not None:
                self._directory = os.dup(directory_fd)
                self._scope.callback(os.close,self._directory)
                check_source_fd(self._t,self._directory)
            _send_release(control,ticket=self._t,ticket_pin=canonical_digest(self._t),nomination=self._n,
                nomination_pin=self._t["environment_digest"],service_listener=self._listener,
                copy_directory_fd=self._directory,deadline=self._deadline,guard=self.guard)
            self._phase = "RELEASED"
        except BaseException:
            self._phase = "FAILED"
            raise

    def measure(self, request, mark, *, pi, witness, retain):
        _need(self._phase == "RELEASED","task dispatch unavailable or already spent")
        self._phase = "MEASURING"
        try:
            self.guard()
            observer = None
            if "copy" in self._t:
                observer = resolve_service_copy(self._t,nomination=self._n,nomination_pin=self._t["environment_digest"],
                    service_start_ticks=self._roles.record["service"]["start_ticks"],directory_fd=self._directory,
                    deadline=self._deadline)
            def boundary(name):
                stamp = mark(name)
                if name == "TASK_ACCEPTED":
                    # The callback and copy setup may have consumed the old challenge's freshness.
                    guest.observe_task_guest(self._t,nomination=self._n,nomination_pin=self._t["environment_digest"],
                                             deadline=self._deadline)
                    self.guard()
                    if observer is not None:
                        _need(_same_description(self._t["service_peer"][0],self._directory,observer._remote),
                              "service-side copy FD changed before first task byte")
                    validate_deadline(self._deadline)
                return stamp
            receipt = task.measure_via_pi(request,boundary,ticket=self._t,ticket_pin=canonical_digest(self._t),pi=pi,
                witness=witness,guard=self.guard,deadline=self._deadline,retain=retain,copy_observation=observer)
            self._phase = "RETAINED"
            return receipt
        except BaseException:
            self._phase = "FAILED"
            raise


@contextmanager
def hold_task_owner(*, inputs, release_pin, ticket, nomination, publish):
    """Spend the approved pair/mode slot with both generations held and still stopped."""
    _need(type(inputs) is _Inputs,"protected owner inputs required")
    deadline = inputs.deadline
    validate_deadline(deadline)
    doc = inputs.read(RELEASE,_pin(release_pin),4096)
    _keys(doc,("schema","ticket_digest","worker_invocation_id","claim_directory","not_before_unix_ns","expires_unix_ns"))
    _need(doc["schema"] == "aragorn/pi-task-owner-release/v1" and canonical_digest(doc) == release_pin,
          "wrong fixed task release")
    t, desc = task._ticket(ticket,doc["ticket_digest"])
    task._copy_ticket(t,desc)
    n = deepcopy(nomination)
    ledger._window(doc,deadline)
    request = t["request"]
    # A different ticket, nonce, generation or approval cannot buy another use of the same slot.
    slot = dict(schema="aragorn/fixed-task-slot/v1",**{k:request[k] for k in ("collection_digest","pair_id","mode")})
    with ExitStack() as scope:
        store, storage_guard = scope.enter_context(_ledger(doc,t,deadline))
        roles = scope.enter_context(hold_stopped_roles(t,nomination=n,nomination_pin=t["environment_digest"],
                                    worker_invocation_id=doc["worker_invocation_id"],deadline=deadline))
        claim = dict(schema="aragorn/fixed-task-owner-claim/v1",commitment_digest=canonical_digest(slot),slot=slot,
                     ticket_digest=doc["ticket_digest"],release_digest=release_pin,roles=roles.record)
        def authority():
            validate_deadline(deadline)
            inputs.guard()
            storage_guard()
            ledger._window(doc,deadline)
        authority()
        roles.guard(stopped=True)
        spent, claim_raw = scope.enter_context(_prepared_attempt_claim(store,claim))
        def custody():
            authority()
            spent()
        custody()
        roles.guard(stopped=True)
        source_binding = scope.enter_context(bind_task_source_observer(roles,claim_raw=claim_raw,deadline=deadline))
        custody()
        roles.guard(stopped=True)
        # Only the manager's held task namespace supplies this one-shot publisher.
        listeners, channel_guard = publish(t["pi_peer"][2],t["service_peer"][2])
        def joined():
            custody()
            channel_guard()
        joined()
        roles.guard(stopped=True)
        handle = _Task(scope,t,n,deadline,roles,joined,listeners["service.sock"],source_binding)
        try:
            yield handle
        finally:
            handle._phase = "CLOSED"
