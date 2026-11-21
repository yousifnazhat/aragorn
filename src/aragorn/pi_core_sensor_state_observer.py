"""Read held kernel objects for a sensor already owned by the service lifecycle.

No task is started, joined, signalled or stopped. Return raw mount streams and
partial observations, not evidence of absent paths, end-to-end health or authority.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import os
import re
import threading
import time

from . import pi_core_stopped_mask_view as kernel
from .pi_core_state_admission import _keys, _need, _same, _uint, _uuid
from .pi_core_state_mounts import ACTION, ANCHOR, PROVIDER


SCHEMA = "aragorn/pi-core-sensor-state-view/v1"
_UNIT = "aragorn-pi-sensor.service"
_CGROUP = ("0::/system.slice/" + _UNIT + "\n").encode("ascii")


def _identity(i):
    _keys(i, ("role", "unit", "pid", "start_ticks", "uid", "gid", "invocation_id"))
    _need(i["role"] == "sensor" and i["unit"] == _UNIT and type(i["invocation_id"]) is str and
          re.fullmatch("[0-9a-f]{32}", i["invocation_id"]) and int(i["invocation_id"], 16) != 0,
          "invalid sensor role or invocation")
    for key in ("pid", "uid", "gid"):
        _uint(i[key], high=1 << 31)
    _uint(i["start_ticks"])
    return i.copy()


def _namespace(stack, proc, name, mount):
    ns = kernel._proc_child(stack, proc, "ns", os.O_RDONLY | os.O_DIRECTORY, mount)
    fd = kernel._magic(stack, ns, name, os.O_RDONLY, mount)
    _need(kernel._filesystem(fd) == kernel._NSFS, "unexpected sensor observation namespace handle")
    return _uint(os.fstat(fd).st_ino)


def _boot_id(stack, proc, mount, deadline):
    for part in ("sys", "kernel", "random"):
        proc = kernel._proc_child(stack, proc, part, os.O_RDONLY | os.O_DIRECTORY, mount)
    raw = kernel._read(proc, "boot_id", 37, mount, deadline)
    _need(len(raw) == 37 and raw.endswith(b"\n"), "incomplete kernel boot ID")
    return _uuid(raw[:-1].decode("ascii"))


def _sensor(stack, role, mount, identity, deadline):
    # A service sensor is not the stopped Pi worker or its credential probe:
    # it may have the action group and special caps. Do not apply a worker frame
    # or claim which service code was consumed from these task credentials.
    pid, proc = role
    ticks, _, states, threads, creds = kernel._parse_subject(kernel._read(proc, "stat", 8192, mount, deadline),
        kernel._read(proc, "status", 65536, mount, deadline), pid)
    _need(ticks == identity["start_ticks"] and threads == 1 and all(s in ("S","R","D") for s in states) and
          all(creds[p + key] == identity[key] for p in ("", "e", "s", "fs") for key in ("uid","gid")),
          "different sensor process generation or effective identity")
    cgroup = kernel._read(proc, "cgroup", 8192, mount, deadline)
    _need(cgroup == _CGROUP, "sensor does not occupy its exact unified service cgroup")
    root = kernel._magic(stack, proc, "root", os.O_PATH | os.O_DIRECTORY, mount)
    subject = dict(pid=pid, start_ticks=ticks, uid=creds["uid"], gid=creds["gid"],
                   **{field: _namespace(stack, proc, key, mount) for key,field in kernel._NS.items()})
    return subject, (creds, kernel._stat(root)), root, cgroup


def _subjects(stack, proc, mount, roles, identity, deadline):
    mgr, mc, mroot, _ = kernel._frame(stack, roles["manager"], mount, deadline, kind="manager")
    _, cc, _, _ = kernel._frame(stack, roles["caller"], mount, deadline, kind="caller")
    _need(all(mc[k] == v for k,v in cc.items() if k not in ("pid", "start_ticks")),
          "collector thread does not share the manager's view")
    sensor, sc, sroot, cgroup = _sensor(stack, roles["sensor"], mount, identity, deadline)
    _need(mgr["mount_namespace"] != sensor["mount_namespace"], "sensor shares the manager mount namespace")
    clocks = {_namespace(stack, role[1], "time", mount) for role in roles.values()}
    _need(len(clocks) == 1, "collector, manager and sensor do not share a clock")
    clock = dict(clock_id="CLOCK_BOOTTIME", time_namespace_inode=clocks.pop(),
                 boot_id=_boot_id(stack, proc, mount, deadline))
    return (mgr, sensor, clock, cgroup, mc, cc, sc), mroot, sroot


def _action_fds(stack, root):
    held = {"/": root}
    path = ""
    for part in ACTION[1:].split("/"):
        root = kernel._pin(stack, root, part, directory=True)
        path += "/" + part
        held[path] = root
    return held


def _edge(stack, subjects, mroot, sroot, held, roles, mount, deadline):
    # Compare fresh component walks to all the original descriptors, not just
    # a pathname string or a fresh inode from an independently resolved root.
    manager = kernel._manager_state_stats(held[0])
    sensor = kernel._manager_state_stats(held[1])
    _need(manager == kernel._manager_state_stats(kernel._manager_state_fds(stack, mroot)) and
          sensor == kernel._manager_state_stats(_action_fds(stack, sroot)), "held sensor state paths changed")
    raw = _streams(roles, mount, deadline)
    kernel._check(deadline)
    return subjects, manager, sensor, raw


def _manager_record(stats):
    return dict(sources={ANCHOR:stats[ANCHOR], ACTION:stats[ANCHOR + ACTION], PROVIDER:stats[ANCHOR + PROVIDER]},
                targets={p:stats[p] for p in (ACTION, PROVIDER)})


def _roles(stack, expected):
    proc, mount = kernel._proc(stack)
    roles = {k: kernel._role(stack, proc, n, mount) for k,n in
             (("manager", os.getpid()), ("sensor", expected["pid"]))}
    tasks = kernel._proc_child(stack, roles["manager"][1], "task", os.O_RDONLY | os.O_DIRECTORY, mount)
    roles["caller"] = kernel._role(stack, tasks, threading.get_native_id(), mount)
    return proc, mount, roles


def _streams(roles, mount, deadline):
    raw = {key: kernel._read(role[1], "mountinfo", 1 << 20, mount, deadline) for key,role in roles.items()}
    _need(raw["manager"] == raw.pop("caller"), "collector mount stream differs from manager")
    return raw


def capture_sensor_state(*, identity, guard, deadline):
    """The protected caller supplies a live pidfd/InvocationID guard; the sensor cannot nominate itself."""
    expected = _identity(identity)
    kernel._check(deadline)
    kernel._platform()
    kernel._generation(expected["pid"], expected["start_ticks"])
    _same(expected, _identity(guard(deadline=deadline)), "initial lifecycle sensor binding differs")
    kernel._check(deadline)
    with ExitStack() as stack:
        proc, mount, roles = _roles(stack, expected)
        start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        args = proc, mount, roles, expected, deadline
        first, mroot, sroot = _subjects(stack, *args)
        held = kernel._manager_state_fds(stack, mroot), _action_fds(stack, sroot)
        with ExitStack() as edge:
            before = _edge(edge, first, mroot, sroot, held, roles, mount, deadline)
        with ExitStack() as edge:
            after = _edge(edge, *_subjects(edge, *args), held, roles, mount, deadline)
        _need(before == after, "sensor state, namespace, identities, or mount streams changed")
        end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _need(start > 0 and 0 < end - start <= 5_000_000_000, "sensor capture outside observation window")
        _same(expected, _identity(guard(deadline=deadline)), "final lifecycle sensor binding differs")
        kernel._check(deadline)
        manager, sensor, clock, cgroup = first[:4]
        raw = before[3]
        view = dict(schema=SCHEMA, identity=expected, manager=manager, sensor=sensor, clock=clock,
                    sensor_cgroup=cgroup.decode("ascii"), opened_boottime_ns=start, closed_boottime_ns=end,
                    manager_state={k:_manager_record(e[1]) for k,e in (("before",before), ("after",after))},
                    sensor_targets={k:{ACTION:e[2][ACTION]}
                                    for k,e in (("before",before), ("after",after))},
                    **{k+"_mountinfo_digest":"sha256:"+hashlib.sha256(v).hexdigest() for k,v in raw.items()})
    kernel._check(deadline)
    return view, raw["manager"], raw["sensor"]


@contextmanager
def hold_sensor_mount_guard(*, identity, view, manager_raw, sensor_raw, guard, deadline):
    """Sample the owned namespaces at each publication boundary. Not continuous monitoring."""
    expected = _identity(identity)
    _same(view["identity"], expected, "foreign sensor capture owner")
    _need(view["schema"] == SCHEMA, "foreign sensor observation")
    raw = {"manager": manager_raw, "sensor": sensor_raw}
    for role, data in raw.items():
        _need(type(data) is bytes and 0 < len(data) <= 1 << 20 and data.endswith(b"\n")
              and view[role + "_mountinfo_digest"] == "sha256:" + hashlib.sha256(data).hexdigest(),
              "foreign sensor observation mount streams")
    kernel._check(deadline)
    kernel._platform()
    kernel._generation(expected["pid"], expected["start_ticks"])
    _same(expected, _identity(guard(deadline=deadline)), "retention lifecycle identity differs")
    with ExitStack() as stack:
        proc, mount, roles = _roles(stack, expected)
        args = proc, mount, roles, expected, deadline
        initial, mroot, sroot = _subjects(stack, *args)
        mgr, sensor, clock, cgroup = initial[:4]
        _same([view["manager"], view["sensor"], view["clock"], view["sensor_cgroup"]],
              [mgr, sensor, clock, cgroup.decode("ascii")], "different process or clock at retention")
        # Keep original roots and namespace handles live through the publication.
        # For complete negative captures, the fixed state paths may be wrong;
        # never convert a failed storage-semantic verdict into a pass here.
        _need(_streams(roles, mount, deadline) == raw, "mount topology changed before retention")
        active = True

        def current():
            nonlocal active
            _need(active and roles["caller"][0] == threading.get_native_id(), "inactive or foreign retention guard")
            try:
                kernel._check(deadline)
                with ExitStack() as edge:
                    fresh, _, _ = _subjects(edge, *args)
                    _need(fresh == initial and kernel._stat(mroot) == initial[4]["root"] and
                          kernel._stat(sroot) == initial[6][1] and _streams(roles, mount, deadline) == raw,
                          "sensor or manager topology changed during retention")
                kernel._check(deadline)
            except BaseException:
                active = False
                raise

        try:
            yield current
            current()
            _same(expected, _identity(guard(deadline=deadline)), "final retention lifecycle identity differs")
        finally:
            active = False
    kernel._check(deadline)
