"""Manager-side fixed-task handoff. Never starts, resumes or retries either role."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
from pathlib import Path
from threading import Lock

from . import pi_core_mask_capture_release as ledger, pi_core_task_guest_binding as guest, pi_core_task_service as task
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .phase3_measurement_collector import _prepared_attempt_claim
from .pi_core_coordinator_entry import _Inputs
from .pi_core_identity_handoff import validate_deadline
from .pi_core_state_admission import _keys, _need, _pin, _same
from .pi_core_state_mounts import direct_mount_inventory
from .pi_core_task_gate_order import GateStops
from .pi_core_task_exec_event import install_task_exec_handler
from .pi_core_task_owner_copy import _same_description, check_source_fd, resolve_service_copy
from .pi_core_task_owner_health import guard_task_health
from .pi_core_task_owner_roles import WORKER, hold_stopped_roles
from .pi_core_task_static_source import bind_task_source_observer
from .pi_core_task_tracer_lifetime import StaticTracerLifetime
from .pi_core_task_trace_store import retain_task_trace
from .pi_core_task_retired_trace import seal_retired_trace


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
    def __init__(self, scope, ticket, nomination, deadline, roles, custody, service_listener, source_binding, gates, lifetime):
        self._scope, self._t, self._n, self._deadline = scope,ticket,nomination,deadline
        self._roles, self._custody = roles,custody
        self._listener = service_listener
        self._source_binding = source_binding
        self._gates = gates
        self._lifetime, self._archive = lifetime, None
        self._phase_lock = Lock()
        self._exec_handler = None
        self._phase, self._directory = "CLAIMED", None

    def _move(self, allowed, dest):
        with self._phase_lock:
            old = self._phase
            _need(old in allowed,"task owner operation unavailable or already spent")
            self._phase = dest
            return old

    @property
    def source_binding(self):
        _need(self._phase == "CLAIMED","task source binding outside claimed lifetime")
        self._custody()
        return self._source_binding

    def _gate_step(self, step, *args):
        _need(self._phase == "CLAIMED","task gate outside claimed lifetime")
        try:
            self._custody()
            result = step(*args)
            self._custody()
            return result
        except BaseException:
            self.refuse_node_exec()
            raise

    def bind_static_tracer(self):
        return self._gate_step(self._lifetime.bind)

    def observe_final_gate_stop(self):
        self._gate_step(self._gates.final)

    def authorize_node_transition(self, observer):
        def authorize():
            self._lifetime.require_traced(observer)
            proof = self._gates.authorize(observer)
            self._exec_handler = install_task_exec_handler(self,observer)
            return proof
        return self._gate_step(authorize)

    def observe_node_exec(self, observer):
        return self._gate_step(self._gates.observe_node_exec,observer)

    def refuse_node_exec(self):
        with self._phase_lock:
            if self._phase != "CLOSED":
                self._phase = "FAILED"
        self._gates.close()
        self._lifetime.retire()

    def entry_replay_records(self, observer):
        """Return detached originals for private retention, not an active health receipt."""
        _need(self._phase in ("CLAIMED","RELEASED","RETAINED","ARCHIVING"),"task evidence outside held lifetime")
        try:
            self._custody()
            _need(self._exec_handler is not None,"static exec handler not installed")
            link = self._exec_handler.consumed(observer)
            records = self._gates.replay_records(observer)
            self._custody()
            return records | {"transition":canonical_json(link)}
        except BaseException:
            self.refuse_node_exec()
            raise

    def retain_entry_trace(self, observer, *, store, receipt_directory, expected_roots, replay_inputs):
        prior = self._move(("CLAIMED","RELEASED","RETAINED"),"ARCHIVING")
        try:
            _need(self._archive is None,"entry trace already retained")
            destination = dict(store=store,receipt_directory=receipt_directory,expected_roots=deepcopy(expected_roots))
            def active():
                _need(self._phase=="ARCHIVING","trace publication lost custody")
                self._custody()
                self._lifetime.require_active(observer)
            active()
            _same([replay_inputs["expected_worker"],replay_inputs["expected_clock"],
                   replay_inputs["expected_bindings"]["deployment_digest"]],
                  [self._roles.record["worker"]|{"cgroup":"/system.slice/"+WORKER},self._t["clock"],
                   self._t["request"]["deployment_digest"]],"different fixed-task replay nomination")
            records = self.entry_replay_records(observer)
            binding = self._lifetime.binding_digest
            _need(ledger.custody._digest(records["binding"])==binding,"different original tracer binding")
            raw = canonical_json(observer.observation)
            receipt = retain_task_trace(**destination,records=records,observation_raw=raw,
                deadline=self._deadline,guard=active,replay_inputs=replay_inputs)
            active()
            self._archive = (destination,binding,receipt)
            self._move(("ARCHIVING",),prior)
            return receipt
        except BaseException:
            self.refuse_node_exec()
            raise

    def retire_entry_trace(self):
        _need(self._archive is not None,"verified private trace required before retirement")
        self._move(("CLAIMED","RELEASED","RETAINED"),"RETIRING")
        try:
            self._gates.close()
            self._custody()
            destination,binding,receipt = self._archive
            pin = seal_retired_trace(**destination,binding_digest=binding,receipt_digest=receipt,
                                     lifetime=self._lifetime,deadline=self._deadline)
            self._custody()
            self._move(("RETIRING",),"RETIRED")
            return pin
        except BaseException:
            self.refuse_node_exec()
            raise
        finally:
            self._lifetime.retire()

    def guard(self):
        """Use for the release and the service's repeated authenticated OBSERVE requests."""
        _need(self._phase in ("RELEASING","RELEASED","MEASURING","RETAINED"),"task owner not active")
        try:
            self._custody()
            self._gates.require_node_observed(self._source)
            _need(self._exec_handler is not None,"static exec handler not installed")
            self._exec_handler.consumed(self._source)
            self._roles.guard(stopped=False)
            self._lifetime.require_active(self._source)
            def custody():
                self._lifetime.require_active(self._source)
                self._custody()
            guard_task_health(self._t,source_observer=self._source,activation=self._activation,
                              worker=self._roles.record["worker"],deadline=self._deadline,custody=custody)
            return self._t["environment_digest"]
        except BaseException:
            self.refuse_node_exec()
            raise

    def release(self, *, control, directory_fd, source_observer, activation):
        self._move(("CLAIMED",),"RELEASING")
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
            self._move(("RELEASING",),"RELEASED")
        except BaseException:
            self.refuse_node_exec()
            raise

    def measure(self, request, mark, *, pi, witness, retain):
        self._move(("RELEASED",),"MEASURING")
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
            self._move(("MEASURING",),"RETAINED")
            return receipt
        except BaseException:
            self.refuse_node_exec()
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
        lifetime = StaticTracerLifetime(source_binding,deadline=deadline)
        scope.callback(lifetime.retire)
        gates = GateStops(source_binding,deadline=deadline)
        scope.callback(gates.close)
        # Only the manager's held task namespace supplies this one-shot publisher.
        listeners, channel_guard = publish(t["pi_peer"][2],t["service_peer"][2])
        def joined():
            custody()
            channel_guard()
        joined()
        roles.guard(stopped=True)
        gates.published()
        joined()
        handle = _Task(scope,t,n,deadline,roles,joined,listeners["service.sock"],source_binding,gates,lifetime)
        try:
            yield handle
        finally:
            with handle._phase_lock:
                handle._phase = "CLOSED"
