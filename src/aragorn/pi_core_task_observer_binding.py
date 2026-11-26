"""Borrow the exact packaged fixed-task worker for independent source observation."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import os
import re
import threading
from types import MappingProxyType

from . import pi_core_task_owner_roles as roles
from .pi_core_identity_handoff import validate_deadline
from .pi_core_state_admission import _need


def _live(fd, pid, manager, mount, deadline):
    roles.binding.native.process.require_live_pidfd(fd)
    with ExitStack() as tmp:
        infos = roles.kernel._proc_child(tmp,manager,"fdinfo",os.O_RDONLY | os.O_DIRECTORY,mount)
        raw = roles.kernel._read(infos,str(fd),4096,mount,deadline)
        pids = [line.split(b":",1)[1].strip() for line in raw.splitlines() if line.startswith(b"Pid:")]
        _need(pids == [str(pid).encode("ascii")], "borrowed pidfd no longer identifies the worker")


class _StaticWorker:
    def __init__(self, holder, deadline, stack):
        self._holder, self._read, self._deadline = holder, holder._read, deadline
        self._record = holder.record
        pidfd, proc, self._mount, paths, metadata = self._read.observer_fds
        _need(set(paths) == set(metadata) == set(roles._WORKER_PINS), "incomplete packaged worker handles")
        def dup(fd):
            duplicate = os.dup(fd)
            stack.callback(os.close, duplicate)
            return duplicate
        self.pidfd, self._proc = dup(pidfd), dup(proc)
        self.files = MappingProxyType({p:dup(fd) for p,fd in paths.items()})
        # These identities come from the same successful hash reads that authorized the stopped roles.
        self._metadata = deepcopy(metadata)

    @property
    def record(self):
        return deepcopy(self._record)

    @property
    def worker(self):
        return self._record["worker"] | {"cgroup":"/system.slice/" + roles.WORKER}

    @property
    def clock(self):
        return dict(self._record["clock"])

    def guard(self, *, phase, deadline):
        def custody():
            validate_deadline(deadline)
            _need(self._read is not None and self._holder._read is self._read and
                  self._holder._owner[0] == os.getpid() and os.geteuid() == os.getegid() == 0 and
                  deadline <= self._deadline, "closed, transferred, or expired static observer binding")
        custody()
        _need(phase in ("stopped","traced-gate","node"), "unknown observer phase")
        worker, clock = self.worker, self.clock
        pid, tid = worker["pid"], threading.get_native_id()
        path = str(roles.sources.NODE_PATH if phase=="node" else roles.sources.GATE_PATH)
        argv = roles._NODE_ARGV if phase=="node" else roles._GATE_ARGV
        with ExitStack() as stack:
            root, mount = roles.kernel._proc(stack)
            _need(mount == self._mount, "different procfs mount")
            _, manager = roles.kernel._role(stack,root,os.getpid(),mount)
            _, named = roles.kernel._role(stack,root,pid,mount)
            _need(roles._same_file(self._proc,named), "worker proc generation replaced")
            _live(self.pidfd,pid,manager,mount,deadline)
            def generation():
                stat = roles.kernel._read(self._proc,"stat",8192,mount,deadline)
                status = roles.kernel._read(self._proc,"status",65536,mount,deadline)
                ticks = roles._bound_process([pid,worker["uid"],worker["gid"]],stat,status,
                                            stopped=phase=="stopped",owned_tracer=lambda t:t==tid)
                _need(ticks == worker["start_ticks"], "different static worker generation")
                if phase != "stopped":
                    _need(re.search(rb"^TracerPid:[ \t]+"+str(tid).encode()+rb"$",status,re.M),
                          "current observer does not trace this worker")
                    if phase == "traced-gate":
                        _,_,states,threads,_ = roles.kernel._parse_subject(stat,status,pid)
                        _need(states == ("t","t") and threads == 1, "not the stopped traced singleton gate")
            generation()
            roles._bound_unit(roles.WORKER,pid,worker["invocation_id"],
                roles.kernel._read(self._proc,"cgroup",8192,mount,deadline),roles.binding._unit_show(roles.WORKER,deadline))
            _need(roles.sensor._boot_id(stack,root,mount,deadline)==clock["boot_id"] and
                  all(roles.sensor._namespace(stack,p,"time",mount)==clock["time_namespace_inode"]
                      for p in (self._proc,manager)), "different task worker clock")
            for p,fd in self.files.items():
                named = roles._view(stack,1 if p==roles.WORKER_UNIT else pid,p)
                _need(roles._same_file(named,fd) and self._metadata[p] ==
                      roles.sources._protected_file(fd,roles._WORKER_PINS[p][1]), "packaged static code changed")
            roles._executable(stack,self._proc,mount,[(self.files[path],argv)],deadline)
            generation()
            _live(self.pidfd,pid,manager,mount,deadline)
            custody()


@contextmanager
def bind_static_worker(holder, *, deadline):
    """Only the original stopped-role owner can lend these handles. No attach, signal or new process."""
    _need(type(holder) is roles._Held and deadline <= holder._deadline, "original stopped task role holder required")
    holder.guard(stopped=True)
    roles.kernel._platform()
    with ExitStack() as stack:
        worker = _StaticWorker(holder,deadline,stack)
        try:
            worker.guard(phase="stopped",deadline=deadline)
            yield worker
        finally:
            worker._read = None
