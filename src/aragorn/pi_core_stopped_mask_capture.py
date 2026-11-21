"""Protected stopped-worker acquisition and local replay. Not a launcher or a B58 independent head."""
from contextlib import ExitStack
from dataclasses import dataclass, field
import hashlib
from itertools import chain
import json
import math
import os
from pathlib import Path
import re
import threading
import time

from .oci_worker_protocol import canonical_json
from .phase3_exit_gate_manifest import load_phase3_exit_gate_manifest_bytes
from .pi_core_manager_state_view import verify_manager_state
from .pi_core_mask_custody import check_mask_destinations, replay_mask_observation, retain_mask_observation
from .pi_core_mask_probe import _PROGRAM, _names, observe_mask_denials
from .pi_core_state_admission import _dev, _keys, _pin, _uint, _uuid
from .pi_core_state_masks import verify_masks
from .pi_core_state_mounts import verify_mounts
from .pi_core_stopped_mask_view import hold_stopped_mask_view


def _need(ok, reason):
    if not ok:
        raise ValueError("stopped mask capture: " + reason)


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class StoppedMaskCapture:
    """Explicit protected caller inputs: no host nomination, default store or grant."""
    store: Path
    receipt_directory: Path
    attempt_id: str
    deployment_digest: str
    profile_digest: str
    interpreter_digest: str
    volume_device: str
    backing_devices: tuple[str, ...]
    fs_type: str
    worker_spine: bool = False
    _lock: object = field(default_factory=threading.Lock, init=False, repr=False, compare=False)
    _state: str = field(default="new", init=False, repr=False, compare=False)
    _roots: tuple = field(default=(), init=False, repr=False, compare=False)
    _deadline: float = field(default=0.0, init=False, repr=False, compare=False)

    def preflight(self, *, deployment_digest, profile_digest, deadline):
        from .pi_core_node_source_observer import _hash_readonly
        with self._lock:
            _need(self._state == "new", "capture request already used")
            object.__setattr__(self, "_state", "spent")
            _need(type(self.worker_spine) is bool, "invalid worker spine selection")
            _need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline,
                  "invalid operation deadline")
            _need(type(self.attempt_id) is str and re.fullmatch(r"[a-f0-9]{32}", self.attempt_id)
                  and int(self.attempt_id, 16), "invalid attempt identity")
            _need(_pin(self.deployment_digest) == deployment_digest and _pin(self.profile_digest) == profile_digest,
                  "different deployment or source profile")
            _volume(self.volume_device, self.backing_devices, self.fs_type)
            roots = check_mask_destinations(store=self.store, receipt_directory=self.receipt_directory, deadline=deadline)
            _pin(self.interpreter_digest)
            fd = os.open("/proc/self/exe", os.O_RDONLY | os.O_CLOEXEC)
            try:
                _need(_hash_readonly(fd, deadline, 128 << 20)[0] == self.interpreter_digest, "wrong interpreter")
            finally:
                os.close(fd)
            object.__setattr__(self, "_roots", roots)
            object.__setattr__(self, "_deadline", deadline)
            object.__setattr__(self, "_state", "prepared")

    def _claim(self, session, deadline):
        with self._lock:
            _need(self._state == "prepared", "missing preflight or capture already attempted")
            object.__setattr__(self, "_state", "spent")
            _need(deadline == self._deadline == session.operation_deadline and time.monotonic() < deadline
                  and session.owned.plan.prepared.deployment_digest == self.deployment_digest
                  and session.owned.plan.source_observation_digest == self.profile_digest, "stale capture preflight")
            return self._roots


def _volume(device, backing, fs_type):
    _dev(device)
    _need(isinstance(backing, (list, tuple)) and 1 <= len(backing) <= 16 and
          len({_dev(d) for d in backing}) == len(backing) and device not in backing
          and fs_type in ("ext4", "xfs"), "unrecognized storage mapping")


def _sole_stop(session):
    from .pi_core_node_source_observer import _NodeSession
    owned, ob = session.owned, session.observer
    _need(type(session) is _NodeSession and threading.get_native_id() == ob._thread and
          session._mask_capture is not None and not ob._executed and not session.gate_release_seen and
          session.failure is None and not session.stopping and session.tasks.keys() == {owned.pid} and
          session.tasks[owned.pid]["stopped"] and session.tasks[owned.pid]["joined"] and
          session.tasks[owned.pid]["start_ticks"] == owned.start_ticks and
          not session.pending_events and session._inventory() == [owned.pid], "gate is not in sole, unreleased custody")


def _stopped(session, deadline):
    _sole_stop(session)
    session._guard(deadline)


def _assemble(view, frames):
    before, after, names_before, names_after, calls = frames
    dirs = {p: {**row, "probe": calls[p[5:]]} for p,row in view["directories"].items()}
    ptmx = view["ptmx"]
    return {"names_before": names_before, "names_after": names_after, "witness": {
        "schema": "aragorn/pi-core-mask-witness/v1", "manager": view["manager"], "worker": view["worker"],
        "source": view["source"], "before": before, "after": after, "directories": dirs,
        "ptmx": None if ptmx is None else {**ptmx, "probe": calls["ptmx"]}}}


def _mount_views(vol, worker_raw, manager_raw):
    _keys(vol, ("device", "backing_devices", "fs_type"))
    _volume(vol["device"], vol["backing_devices"], vol["fs_type"])
    namespace, pi, manager = {}, {}, {}
    verify_mounts("pi", worker_raw, **vol, namespace=namespace, mount_details=pi)
    verify_mounts("manager", manager_raw, **vol, mount_details=manager)
    return namespace, pi, manager


def _destination_coordinates(capture, roots, pi_details, manager_details):
    # A different pathname or mount ID need not mean different backing bytes.
    coordinates, mount_ids = [], []
    mounts = {Path(p): row for p, row in manager_details.items()}
    visible = tuple((m["dev"], Path(m["root"])) for m in pi_details.values())
    for directory, identity in zip((capture.store, capture.receipt_directory), roots, strict=True):
        _need(not any(p != directory and p.is_relative_to(directory) for p in mounts), "overmounted evidence subtree")
        point = next(p for p in (directory, *directory.parents) if p in mounts)
        row = mounts[point]
        dev = row["dev"]
        _need(dev == f"{os.major(identity[0])}:{os.minor(identity[0])}", "evidence device changed")
        _need(row["fs_type"] in ("ext4", "xfs") and "rw" in row["options"]
              and dev not in (capture.volume_device, *capture.backing_devices),
              "evidence requires writable durable storage separate from service state")
        subtree = Path(row["root"]) / directory.relative_to(point)
        for other_dev, other in chain(coordinates, visible):
            _need(dev != other_dev or not (subtree.is_relative_to(other) or other.is_relative_to(subtree)),
                  "evidence reachable through a worker or custody mount alias")
        coordinates.append((dev, subtree))
        mount_ids.append(row["mount_id"])
    return tuple(mount_ids)


def _verify_slice(bindings, view, proof, worker_raw, manager_raw, projections=None, *,
                  worker_spine_raw=None, spine_projection=None):
    versions = {f"aragorn/pi-core-stopped-mask-binding/v{i}": i for i in (1, 2, 3)}
    version = versions.get(bindings["schema"])
    _keys(bindings, ("schema", "attempt_id", "deployment", "profile", "interpreter", "probe_source",
                     "unit", "invocation", "launch", "clock", "worker", "manager", "storage") +
          (("capture_mode", "admitted_path", "worker_spine_digest") if version == 3 else ()))
    _need(version is not None and type(view) is dict and
          view.get("schema") == f"aragorn/pi-core-stopped-mask-view/v{version}", "unknown or mixed capture format")
    _need((worker_spine_raw is not None) == (version == 3) and
          (spine_projection is None or type(spine_projection) is dict and not spine_projection),
          "missing or unexpected worker spine")
    fields = ("schema", "worker", "manager", "source", "directories", "ptmx", "dev_names", "worker_root",
              "worker_dev", "opened_boottime_ns", "closed_boottime_ns", "worker_mountinfo_digest",
              "manager_mountinfo_digest")
    _keys(view, fields + (("manager_state",) if version >= 2 else ()) + (("worker_spine_digest",) if version == 3 else ()))
    _keys(proof, ("witness", "names_before", "names_after"))
    for key in ("deployment", "profile", "interpreter", "launch"):
        _pin(bindings[key])
    for key in ("attempt_id", "invocation"):
        value = bindings[key]
        _need(type(value) is str and re.fullmatch(r"[0-9a-f]{32}", value) and int(value, 16),
              "invalid attempt or invocation identity")
    _need(type(bindings["unit"]) is str and re.fullmatch(r"aragorn-pi-[0-9a-f]{32}\.service", bindings["unit"])
          and bindings["probe_source"] == _digest(_PROGRAM.encode("ascii")), "unknown unit or probe implementation")
    clock = bindings["clock"]
    _keys(clock, ("boot_id", "clock_id", "time_namespace_inode"))
    _uuid(clock["boot_id"])
    _uint(clock["time_namespace_inode"])
    _need(clock["clock_id"] == "CLOCK_BOOTTIME", "unknown observation clock")
    for key in ("opened_boottime_ns", "closed_boottime_ns"):
        _uint(view[key])
    _need(all(canonical_json(view[k]) == canonical_json(bindings[k]) for k in ("worker", "manager")) and
          _digest(worker_raw) == view["worker_mountinfo_digest"] and
          _digest(manager_raw) == view["manager_mountinfo_digest"], "different process or raw mount stream")
    witness = proof["witness"]
    _need(type(witness) is dict and type(view["directories"]) is dict and type(witness["directories"]) is dict
          and (view["ptmx"] is None or type(view["ptmx"]) is dict), "malformed mask inventory")
    _names(view["dev_names"])
    _need(proof["names_before"] == proof["names_after"] == view["dev_names"] and
          view["opened_boottime_ns"] <= witness["before"]["boottime_ns"] <
          witness["after"]["boottime_ns"] <= view["closed_boottime_ns"] and
          view["closed_boottime_ns"] - view["opened_boottime_ns"] <= 5_000_000_000,
          "changed /dev or unbound observation interval")
    _need(canonical_json(view["source"]) == canonical_json(witness["source"])
          and view["directories"].keys() == witness["directories"].keys()
          and (view["ptmx"] is None) == (witness["ptmx"] is None), "different mask source or inventory")
    tree = {"/dev": dict(stat=view["worker_dev"], before=proof["names_before"], after=proof["names_after"])}
    for path, source in list(view["directories"].items()) + ([("/dev/ptmx", view["ptmx"])] if view["ptmx"] else []):
        link = path == "/dev/ptmx"
        row = witness["ptmx"] if link else witness["directories"][path]
        _need(type(row) is dict and type(source) is dict and
              canonical_json({k:v for k,v in row.items() if k != "probe"}) == canonical_json(source),
              "witness differs from held object")
        tree[path] = dict(stat=source["before"], mask_proof="denied-ptmx" if link else "denied-directory")
    vol = bindings["storage"]
    namespace, pi, manager = projections or _mount_views(vol, worker_raw, manager_raw)
    verify_masks({"root": view["worker_root"], "tree": tree}, witness, subject=bindings["worker"],
                 manager_subject=bindings["manager"], device=vol["device"], backing_devices=vol["backing_devices"],
                 namespace=namespace, worker_mounts=pi, manager_mounts=manager)
    manager_state = verify_manager_state(view["manager_state"], vol, manager) if version >= 2 else None
    if version == 3:
        from .pi_core_worker_walk_evidence import verify_worker_spine
        _need(bindings["capture_mode"] == "STOPPED_WORKER_HANDLE_SPINE" and
              type(worker_spine_raw) is bytes and 0 < len(worker_spine_raw) <= 65535 and
              _pin(bindings["worker_spine_digest"]) == view["worker_spine_digest"] == _digest(worker_spine_raw),
              "worker spine bytes or selected capture mode differs")
        spine = load_phase3_exit_gate_manifest_bytes(worker_spine_raw + b"\n")
        verified = verify_worker_spine(spine, binding=bindings, view=view, namespace=namespace, worker_mounts=pi)
        _need(spine["opened_boottime_ns"] <= witness["before"]["boottime_ns"] <
              witness["after"]["boottime_ns"] <= spine["closed_boottime_ns"], "worker spine did not bracket mask probes")
        if spine_projection is not None:
            spine_projection.update(verified)
    return manager_state


def _finding(bindings, view, proof, worker_raw, manager_raw, projections=None, *, worker_spine_raw=None):
    try:
        _verify_slice(bindings, view, proof, worker_raw, manager_raw, projections, worker_spine_raw=worker_spine_raw)
    except (KeyError, ValueError, TypeError) as error:
        return False, str(error)[:256]
    return True, None


def capture_stopped_masks(session, capture, *, deadline):
    """Called on the armed observer's thread, before its first resume or readiness signal."""
    _need(type(capture) is StoppedMaskCapture and session._mask_capture is capture, "wrong capture owner")
    roots = capture._claim(session, deadline)
    _stopped(session, deadline)
    owned = session.owned
    with ExitStack() as scope:
        live = scope.enter_context(hold_stopped_mask_view(pid=owned.pid, start_ticks=owned.start_ticks, deadline=deadline))
        _need((live.worker["pid"], live.worker["start_ticks"], live.worker["uid"], live.worker["gid"]) ==
              (owned.pid, owned.start_ticks, owned.plan.worker_uid, owned.plan.worker_gid), "different worker")
        def sample_masks():
            return observe_mask_denials(live, deadline=deadline, cleanup_deadline=session.cleanup_deadline,
                                        interpreter_digest=capture.interpreter_digest)
        if capture.worker_spine:
            from . import pi_core_node_source_observer as node
            from .pi_core_stopped_worker_walk import hold_worker_spine
            # No caller-supplied lookup or PID: only the actual admitted worker's exact cwd.
            admitted = owned.plan.prepared.skill_path.parent
            with hold_worker_spine(live, admitted_path=admitted, deadline=deadline) as finish:
                frames = sample_masks()
                spine_raw = canonical_json(finish())
            view, worker_raw, manager_raw = live.finish()
            _stopped(session, deadline)
            pidfd = session.observer._pidfd
            def guard():
                _sole_stop(session)
                _need(session._mask_capture is capture and session.owned is owned and session.observer._pidfd == pidfd,
                      "different stopped-worker owner during retention")
                node.base.process.require_live_pidfd(pidfd)
                live.guard_retained_topology(worker_raw, manager_raw)
            result = _retain(session, capture, roots, deadline, view, worker_raw, manager_raw, frames,
                             spine_raw=spine_raw, admitted=admitted, guard=guard)
            try:
                _stopped(session, deadline)
                scope.close()
            except BaseException:
                # Final owned-generation or descriptor cleanup failed after verified
                # publication. Keep known pins available to the existing supervisor.
                session._mask_receipt = dict(result, mask_consistent=False,
                                             reason="post-publication custody or cleanup unconfirmed")
                raise
            return result
        frames = sample_masks()
        view, worker_raw, manager_raw = live.finish()
    _stopped(session, deadline)
    return _retain(session, capture, roots, deadline, view, worker_raw, manager_raw, frames)


def _retain(session, capture, roots, deadline, view, worker_raw, manager_raw, frames, *,
            spine_raw=None, admitted=None, guard=None):
    owned, observer = session.owned, session.observer
    _need(view.get("schema") == "aragorn/pi-core-stopped-mask-view/v2" and "manager_state" in view,
          "new capture requires manager source and target observations")
    bindings = dict(schema="aragorn/pi-core-stopped-mask-binding/v2", attempt_id=capture.attempt_id,
                    deployment=capture.deployment_digest, profile=capture.profile_digest,
                    interpreter=capture.interpreter_digest, probe_source=_digest(_PROGRAM.encode("ascii")),
                    unit=owned.plan.unit_name, invocation=owned.invocation, launch=owned.immutable_digest,
                    clock=dict(observer._clock), worker=view["worker"], manager=view["manager"],
                    storage=dict(device=capture.volume_device, backing_devices=list(capture.backing_devices), fs_type=capture.fs_type))
    extra = {}
    if spine_raw is not None:
        _need(capture.worker_spine is True and isinstance(admitted, Path) and admitted == owned.plan.prepared.skill_path.parent
              and callable(guard) and 0 < len(spine_raw) <= 65535, "spine is not from this protected invocation")
        extra["worker_spine_digest"] = _digest(spine_raw)
        view = dict(view, schema="aragorn/pi-core-stopped-mask-view/v3", **extra)
        bindings.update(schema="aragorn/pi-core-stopped-mask-binding/v3", capture_mode="STOPPED_WORKER_HANDLE_SPINE",
                        admitted_path=str(admitted), **extra)
    else:
        _need(capture.worker_spine is False and admitted is None and guard is None, "missing requested spine")
    proof = _assemble(view, frames)
    views = _mount_views(bindings["storage"], worker_raw, manager_raw)
    mount_ids = _destination_coordinates(capture, roots, views[1], views[2])
    consistent, reason = _finding(bindings, view, proof, worker_raw, manager_raw, views, worker_spine_raw=spine_raw)
    raw = canonical_json(bindings)
    pin = _digest(raw)
    receipt = retain_mask_observation(store=capture.store, receipt_directory=capture.receipt_directory,
        capture_digest=pin, bindings_raw=raw, worker_raw=worker_raw, manager_raw=manager_raw,
        proof_raw=canonical_json(proof), vantage_raw=canonical_json(view), expected_roots=roots, deadline=deadline,
        **(dict(worker_spine_raw=spine_raw, topology_guard=guard, expected_mounts=mount_ids) if extra else {}))
    return dict(capture_digest=pin, receipt_digest=receipt, mask_consistent=consistent, reason=reason,
                activation_authorized=False, installed_isolation_verified=False, phase3_exit_eligible=False, **extra)


def replay_stopped_masks(*, store, receipt_directory, capture_digest, receipt_digest):
    """Replay the recorded version's checks; never turn a v1 mask into a manager-state observation."""
    raw = replay_mask_observation(store=store, receipt_directory=receipt_directory,
                                  capture_digest=capture_digest, receipt_digest=receipt_digest)
    spine_raw = raw.get("worker_spine")
    ok, why = _finding(json.loads(raw["bindings"]), json.loads(raw["vantage"]), json.loads(raw["proof"]),
                       raw["worker"], raw["manager"], worker_spine_raw=spine_raw)
    return dict(capture_digest=capture_digest, receipt_digest=receipt_digest, mask_consistent=ok, reason=why,
                activation_authorized=False, installed_isolation_verified=False, phase3_exit_eligible=False,
                **({"worker_spine_digest": _digest(spine_raw)} if spine_raw is not None else {}))
