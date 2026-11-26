"""Root-owner readback of the two fixed-task generations; no attach, signal or resume.

A group-stop sample cannot distinguish the gate's two SIGSTOPs or establish
who can send a future signal. The claim must be durable before releasing
either role; this identity check does not attest source reads or sensor health.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
from pathlib import Path
import re
import threading
import time
from types import MappingProxyType

from . import pi_core_task_guest_binding as binding
from . import pi_core_sensor_state_observer as sensor, pi_core_stopped_mask_view as kernel
from . import pi_core_source_observer as sources
from .oci_worker_protocol import canonical_digest
from .pi_core_identity_handoff import validate_deadline
from .pi_core_state_admission import _need, _same

# Reviewed e251a22 task guest package / worker build. Do not discover these
# pins from a nomination, a mutable checkout or a running worker.
SERVICE_CODE = MappingProxyType({
    "interpreter_digest":"sha256:7863a4d5e03fde7791c7f8c2c304cf3522f435e19745364ad18a6b7a0458af57",
    "unit_digest":"sha256:cc97083bb2cdf56caf4a1b611eb1f7a20a02734908e7bb6fe42b912e945ae69b",
    "wrapper_digest":"sha256:0dff78497a4d00f7844053e45b43e769c61c87bc4688e43ba72afff2927a45ca",
})
WORKER = "aragorn-pi-task-worker.service"
WORKER_UNIT = "/usr/lib/systemd/system/" + WORKER
_WORKER_PINS = {
    WORKER_UNIT:("sha256:136338c6b771a8081a26fb5098a3551ae73b6537bf29971d75bec60cd2540618", 16384),
    str(sources.GATE_PATH):("sha256:2a54fd7f91e1349ceecad3ac27ec6d111230c1913f4030ae91a67fa4210cab7a", 1<<16),
    str(sources.NODE_PATH):("sha256:b4855de8c4781130b722ceaec9718fed77cca3eed2e5cfc5455e267c0b9ee3b0", 128<<20),
    sources.ENTRY_PATH:("sha256:062508c46c4dcfa5bf5663ce3681b5347715af79e0db1c9414d5e5cf40f1afcb", 1<<20),
}
_NODE_ARGV = ("\0".join((str(sources.NODE_PATH), "--disallow-code-generation-from-strings", sources.ENTRY_PATH))+"\0").encode()
_GATE_ARGV = str(sources.GATE_PATH).encode() + b"\0" + _NODE_ARGV


def _bound_process(peer, stat, status, *, stopped, owned_tracer=None):
    pid, uid, gid = peer
    ticks, _, states, threads, credentials = kernel._parse_subject(stat, status, pid)
    kernel._limited(credentials)
    _need((credentials["uid"],credentials["gid"]) == (uid,gid), "different task role identity")
    tracer = [line for line in status.splitlines() if line.startswith(b"TracerPid:")]
    _need(len(tracer) == 1 and re.fullmatch(rb"TracerPid:[ \t]+[0-9]{1,10}", tracer[0]), "unknown role tracer")
    traced_by = int(tracer[0].split(b":")[1])
    if stopped:
        _need(states == ("T","T") and threads == 1 and traced_by == 0, "role not untraced singleton group-stop")
    else:
        allowed = ("R","S","D","T") if not traced_by else ("R","S","D","T","t")
        _need((not traced_by or (owned_tracer is not None and owned_tracer(traced_by))) and all(s in allowed for s in states)
              and 1 <= threads <= 64, "unowned tracer, dead role or unexpected role state")
    return ticks


def _bound_unit(unit, pid, invocation, cgroup, raw_show):
    fragment = "/usr/lib/systemd/system/" + unit
    _need(cgroup == ("0::/system.slice/"+unit+"\n").encode("ascii") and
          binding._show(raw_show) == binding._active(unit, pid, invocation, fragment),
          "fixed task role unit or generation changed")


def _owned_tracer(stack, own_proc, manager, tid, mount, deadline):
    # TracerPid denotes a *thread*. A bare process PID or a tracer ID asserted by
    # the worker cannot authenticate it. Look only inside this held owner's task tree.
    task = kernel._proc_child(stack,own_proc,"task",os.O_RDONLY | os.O_DIRECTORY,mount)
    _, thread = kernel._role(stack,task,tid,mount)
    _, _, states, _, creds = kernel._parse_subject(kernel._read(thread,"stat",8192,mount,deadline),
        kernel._read(thread,"status",65536,mount,deadline),tid,tgid=manager)
    return all(s in ("S","R","D") for s in states) and all(creds[p+k] == 0
        for p in ("","e","s","fs") for k in ("uid","gid"))


def _view(stack, pid, path):
    fd = sources._open_view(pid, Path(path))
    stack.callback(os.close, fd)
    _need(os.fstatvfs(fd).f_flag & os.ST_RDONLY, "writable role code")
    return fd


def _same_file(fd, other):
    return os.path.samestat(os.fstat(fd), os.fstat(other))


def _executable(stack, pfd, mount, candidates, deadline):
    validate_deadline(deadline)
    exe = kernel._magic(stack,pfd,"exe",os.O_RDONLY,mount)
    cmd = kernel._proc_child(stack,pfd,"cmdline",os.O_RDONLY,mount)
    raw = os.read(cmd, max(len(argv) for _,argv in candidates)+1)
    _need(any(_same_file(fd, exe) and raw == argv for fd,argv in candidates), "unexpected role executable or arguments")


@contextmanager
def _observe_held(ticket, n, worker_id, deadline):
    kernel._platform()
    with ExitStack() as held:
        root, mount = kernel._proc(held)
        peers = {"worker": n["pi_peer"], "service": n["service_peer"]}
        units = {"worker":(WORKER,worker_id), "service":(binding._TASK,n["service_invocation_id"])}
        pfds, handles = {}, {}
        for name, peer in peers.items():
            handle = os.pidfd_open(peer[0], 0)
            held.callback(os.close,handle)
            binding.native.process.require_live_pidfd(handle)
            handles[name] = handle
            _, pfds[name] = kernel._role(held, root, peer[0], mount)
        _, own_proc = kernel._role(held,root,n["manager_peer"][0],mount)
        worker, service = peers["worker"][0], peers["service"][0]
        # Hash each immutable worker input once; keep the underlying FDs alive
        # across the claim. The worker is chrooted: systemd reads its fragment
        # from PID 1's view, not from the worker's root.
        paths, metadata = {}, {}
        for path,(pin,bound) in _WORKER_PINS.items():
            fd = paths[path] = _view(held, 1 if path == WORKER_UNIT else worker, path)
            digest, metadata[path] = sources._hash(fd,deadline,bound)
            _need(digest == pin, "substituted fixed-task worker package")
        service_exe = _view(held,service,binding._PYTHON)
        with ExitStack() as tmp:
            same_code = binding._service_code(tmp, service, pfds["service"], mount, deadline)
            _same(same_code, dict(SERVICE_CODE), "installed role service does not match the release")
            _need(_same_file(service_exe,kernel._magic(tmp,pfds["service"],"exe",os.O_RDONLY,mount)),
                  "service interpreter replaced during readback")

        def read(stopped):
            with ExitStack() as tmp:
                for fd in handles.values():
                    binding.native.process.require_live_pidfd(fd)
                tids = {sensor._namespace(tmp,p,"time",mount) for p in (own_proc,*pfds.values())}
                clock = n["clock"]
                _need(tids == {clock["time_namespace_inode"]} and sensor._boot_id(tmp,root,mount,deadline) == clock["boot_id"],
                      "different guest boot or time namespace")
                result = dict(schema="aragorn/pi-core-task-owner-roles/v1", ticket_digest=canonical_digest(ticket),
                              environment_digest=canonical_digest(n), clock=deepcopy(clock))
                def generation(name):
                    role = pfds[name]
                    def traced_by_owner(tid):
                        return (_same_file(paths[str(sources.NODE_PATH)],kernel._magic(tmp,role,"exe",os.O_RDONLY,mount))
                                and _owned_tracer(tmp,own_proc,n["manager_peer"][0],tid,mount,deadline))
                    return _bound_process(peers[name],kernel._read(role,"stat",8192,mount,deadline),
                                          kernel._read(role,"status",65536,mount,deadline),stopped=stopped,
                                          owned_tracer=traced_by_owner if name=="worker" else None)
                before = {name:generation(name) for name in peers}
                for name,(unit,invocation) in units.items():
                    pid,uid,gid = peers[name]
                    group = kernel._read(pfds[name],"cgroup",8192,mount,deadline)
                    _bound_unit(unit,pid,invocation,group,binding._unit_show(unit,deadline))
                    result[name] = dict(pid=pid,uid=uid,gid=gid,start_ticks=before[name],unit=unit,invocation_id=invocation)
                for path, fd in paths.items():
                    current = _view(tmp,1 if path == WORKER_UNIT else worker,path)
                    _need(_same_file(fd, current), "fixed task worker view replaced")
                permitted = [(paths[str(sources.GATE_PATH)],_GATE_ARGV)]
                if not stopped:
                    permitted.append((paths[str(sources.NODE_PATH)],_NODE_ARGV))
                _executable(tmp,pfds["worker"],mount,permitted,deadline)
                _executable(tmp,pfds["service"],mount,[(service_exe,binding._ARGV)],deadline)
                _need(before == {name:generation(name) for name in peers}, "task generation changed during readback")
                for fd in handles.values():
                    binding.native.process.require_live_pidfd(fd)
                validate_deadline(deadline)
                return result
        # Lend only this generation's already-open descriptors to the observer intake.
        read.observer_fds = handles["worker"], pfds["worker"], mount, paths, metadata
        yield read


class _Held:
    def __init__(self, read, owner, deadline):
        self._read, self._owner, self._deadline = read, owner, deadline
        self._record = read(True)

    @property
    def record(self):
        return deepcopy(self._record)

    def guard(self, *, stopped):
        _need(type(stopped) is bool and self._read is not None and
              (os.getpid(),threading.get_native_id(),os.geteuid(),os.getegid()) == self._owner,
              "closed, transferred, or invalid task role custody")
        validate_deadline(self._deadline)
        _same(self._record, self._read(stopped), "fixed task role generation changed")


@contextmanager
def hold_stopped_roles(ticket, *, nomination, nomination_pin, worker_invocation_id, deadline):
    validate_deadline(deadline)
    ticket, n = deepcopy(ticket), deepcopy(nomination)
    binding._nomination(ticket,n,nomination_pin)
    binding._invocation(worker_invocation_id)
    _need(worker_invocation_id not in (n["service_invocation_id"],n["sensor_invocation_id"]) and
          n["manager_peer"] == [os.getpid(),os.geteuid(),os.getegid()], "wrong role owner or shared invocation")
    _same(n["service_code"],dict(SERVICE_CODE),"nominated task service is not the released package")
    owner = (os.getpid(),threading.get_native_id(),os.geteuid(),os.getegid())
    with _observe_held(ticket,n,worker_invocation_id,deadline) as read:
        held = _Held(read,owner,deadline)
        try:
            yield held
        finally:
            held._read = None
