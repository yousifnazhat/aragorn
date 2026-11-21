"""Read-only custody of two existing, held Pi endpoint directories.

The stopped-worker guard compares fixed names as the manager, not as Pi.
No connection, credential change, or conclusion about Pi's lookup or listing behavior.
"""
from contextlib import ExitStack
import math
import os
import re
import socket
import stat
import threading
import time

from . import pi_core_native_provider as provider
from . import pi_core_native_request as request
from . import pi_core_native_supervisor as native
from . import pi_core_sensor_state_observer as sensor
from . import pi_core_stopped_mask_view as kernel
from . import runtime_action_broker as broker
from .pi_core_state_admission import _uuid


SCHEMA = "aragorn/pi-core-owned-socket-directories/v1"
_BOOT = "/run/aragorn-pi-bootstrap"
_ROLES = {"request": ("requests", "request.sock"), "provider": ("provider", "provider.sock")}
_META = {"dev", "ino", "mnt_id", "mode", "uid", "gid", "nlink"}


def _need(ok, why):
    if not ok:
        raise ValueError("owned socket directory evidence: " + why)


def _keys(v, names):
    _need(type(v) is dict and set(v) == set(names), "unexpected fields")


def _num(n, low=0, high=1 << 64):
    return type(n) is int and low <= n < high


def _meta(v, mode, gid):
    sock = stat.S_ISSOCK(mode)
    _keys(v, _META | ({"size", "mtime_ns", "ctime_ns"} if sock else set()))
    _need(type(v["dev"]) is str and re.fullmatch(r"0:[1-9][0-9]{0,6}", v["dev"]) and
          int(v["dev"][2:]) < 1 << 20 and _num(v["ino"], 1) and _num(v["mnt_id"], 1, 1 << 32) and
          _num(v["mode"]) and v["mode"] == mode and _num(v["uid"]) and v["uid"] == 0 and
          _num(v["gid"]) and v["gid"] == gid and _num(v["nlink"], 1, 1 << 32), "unexpected object identity")
    if sock:
        _need(v["nlink"] == 1 and all(_num(v[k], high=1 << 63) for k in ("size", "mtime_ns", "ctime_ns")),
              "unexpected endpoint identity")


def _edge_valid(v, uid, gid):
    _keys(v, ("schema", "worker_uid", "worker_gid", "bootstrap", "directories", "manager", "boot_id",
              "time_namespace_inode", "opened_boottime_ns", "closed_boottime_ns"))
    _uuid(v["boot_id"])
    _need(_num(v["time_namespace_inode"], 1) and _num(v["opened_boottime_ns"], 1) and
          _num(v["closed_boottime_ns"], 1) and v["opened_boottime_ns"] < v["closed_boottime_ns"],
          "invalid manager clock window")
    manager = v["manager"]
    _keys(manager, ("pid","start_ticks","uid","gid","mount_namespace","user_namespace"))
    _need(_num(manager["pid"],1,1 << 31) and all(_num(manager[k],1) for k in
          ("start_ticks","mount_namespace","user_namespace")) and all(_num(manager[k]) and manager[k] == 0
          for k in ("uid","gid")), "invalid root manager identity")
    _need(v["schema"] == SCHEMA and _num(v["worker_uid"], 1, 0xffffffff) and _num(v["worker_gid"], 1, 0xffffffff)
          and (v["worker_uid"], v["worker_gid"]) == (uid, gid), "worker or schema differs")
    _keys(v["bootstrap"], ("path", "object"))
    _need(v["bootstrap"]["path"] == _BOOT, "wrong bootstrap path")
    base = v["bootstrap"]["object"]
    _meta(base, stat.S_IFDIR | 0o755, 0)
    _keys(v["directories"], _ROLES)
    seen = {base["ino"]}
    handles = set()
    for role, (directory, name) in _ROLES.items():
        row = v["directories"][role]
        _keys(row, ("path", "object", "names", "endpoint", "listener_handle"))
        _keys(row["endpoint"], ("path", "object"))
        handle = row["listener_handle"]
        _keys(handle, ("dev", "ino"))
        _need(type(handle["dev"]) is str and re.fullmatch(r"0:[1-9][0-9]{0,6}", handle["dev"]) and
              int(handle["dev"][2:]) < 1 << 20 and handle["dev"] != base["dev"] and _num(handle["ino"], 1)
              and (handle["dev"], handle["ino"]) not in handles, "invalid or aliased sockfs handle")
        handles.add((handle["dev"], handle["ino"]))
        path = _BOOT + "/" + directory
        _need(row["path"] == path and type(row["names"]) is list and row["names"] == [name] and
              row["endpoint"]["path"] == path + "/" + name, "unexpected fixed path or complete membership")
        for obj, mode in ((row["object"], stat.S_IFDIR | 0o711), (row["endpoint"]["object"], stat.S_IFSOCK | 0o660)):
            _meta(obj, mode, gid)
            _need((obj["mnt_id"], obj["dev"]) == (base["mnt_id"], base["dev"]) and obj["ino"] not in seen,
                  "aliased or overmounted endpoint tree")
            seen.add(obj["ino"])


def verify_owned_socket_directories(before, stopped, *, worker_uid, worker_gid):
    """Require identical complete manager observations. No OS access or worker inference."""
    _need(_num(worker_uid, 1, 0xffffffff) and _num(worker_gid, 1, 0xffffffff), "expected a non-root worker")
    _edge_valid(before, worker_uid, worker_gid)
    _edge_valid(stopped, worker_uid, worker_gid)
    _need(before["closed_boottime_ns"] < stopped["opened_boottime_ns"] and all(
        before[k] == stopped[k] for k in before if k not in ("opened_boottime_ns", "closed_boottime_ns")),
        "overlapping bounds or changed manager socket directory membership/identity")
    return dict(manager_socket_membership_observed=True, worker_lookup_observed=False, worker_listing_observed=False,
                listener_readiness_observed=False, phase3_exit_eligible=False)


def _project(fd, pinned, *, endpoint=False):
    s, x = os.fstat(fd), kernel._stat(fd, owner=True)
    original = broker._file_identity(s) if endpoint else broker._directory_identity(s)
    dev = f"{os.major(s.st_dev)}:{os.minor(s.st_dev)}"
    _need(original == pinned and (x["dev"], x["ino"], x["mode"], x["uid"], x["gid"]) ==
          (dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid), "held descriptor differs from owner's identity")
    obj = {k: x[k] for k in ("dev", "ino", "mode", "uid", "gid", "mnt_id")}
    obj["nlink"] = s.st_nlink
    if endpoint:
        obj.update(size=s.st_size, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns)
    return obj


def _owners(owned, req, prov, deadline):
    kernel._check(deadline)
    _need(type(owned) is native._Owned and type(req) is request.PiNativeRequestDispatch and
          type(prov) is provider.PiNativeProviderDispatch, "not original native dispatchers")
    plan = request._plan(owned, deadline)
    _need(owned.request_dispatch_active is True and owned.provider_dispatch_active is True and
          getattr(owned, "_pi_request_dispatch", None) is req and getattr(owned, "_pi_provider_dispatch", None) is prov
          and prov._seal is provider._SEAL and prov._plan is plan, "dispatchers do not belong to this owner")
    sockets, socket_objects, fds = [], [], [owned.run_fd, owned.directory_fd]
    for dispatch in (req, prov):
        _need(dispatch.owned is owned and dispatch.created is True and dispatch.active is True and dispatch.closed is False
              and type(dispatch.deadline) in (int, float) and math.isfinite(dispatch.deadline) and
              deadline <= dispatch.deadline and dispatch.directory_identity and dispatch.socket_identity,
              "dispatcher no longer holds its original directory, endpoint or budget")
        fds.append(dispatch.directory_fd)
    for handle in (owned.listener, req.listener, prov.listener):
        _need(isinstance(handle, socket.socket) and handle.family == socket.AF_UNIX and handle.type == socket.SOCK_STREAM,
              "missing local stream handle")
        fd = handle.fileno()
        _need(_num(fd, 0, 1 << 31), "closed listener handle")
        s = os.fstat(fd)
        _need(stat.S_ISSOCK(s.st_mode) and kernel._filesystem(fd) == 0x534F434B, "not a held sockfs handle")
        sockets.append((s.st_dev, s.st_ino))
        socket_objects.append(id(handle))
        fds.append(fd)
    _need(all(_num(fd, 0, 1 << 31) for fd in fds) and len(set(fds)) == len(fds) and
          len(set(sockets)) == 3 and len(set(socket_objects)) == 3, "aliased owned resources")
    # The sockfs handles are distinct from the VFS socket *names*. Do not
    # equate those inode numbers or probe whether an endpoint accepts calls.
    return (plan.worker_uid, plan.worker_gid, id(plan), tuple(fds), tuple(socket_objects), tuple(sockets))


def _snapshot(stack, root, owned, req, prov, uid, gid, sock_ids, deadline):
    # root is held from the verified manager proc frame, not a new lookup
    # of an unbound caller "/" or a proc casting of the worker namespace.
    named_run = kernel._pin(stack, root, "run", directory=True)
    run = kernel._stat(owned.run_fd, owner=True)
    _need(run == kernel._stat(named_run, owner=True) and stat.S_ISDIR(run["mode"]) and run["uid"] == 0 and
          not run["mode"] & 0o022 and kernel._filesystem(owned.run_fd) == kernel._TMPFS, "untrusted original /run")
    named = kernel._pin(stack, owned.run_fd, "aragorn-pi-bootstrap", directory=True)
    base = _project(owned.directory_fd, owned.directory_identity)
    _need(base == _project(named, owned.directory_identity) and
          (run["mnt_id"], run["dev"]) == (base["mnt_id"], base["dev"]), "replaced or overmounted bootstrap")
    dirs = {}
    for (role, (dn, sn)), dispatcher, (dev, ino) in zip(_ROLES.items(), (req, prov), sock_ids):
        kernel._check(deadline)
        directory = _project(dispatcher.directory_fd, dispatcher.directory_identity)
        named_dir = kernel._pin(stack, owned.directory_fd, dn, directory=True)
        _need(_project(named_dir, dispatcher.directory_identity) == directory, "named directory no longer held")
        names = kernel._names(dispatcher.directory_fd, deadline, 1)
        _need(names == [sn], "owned directory no longer contains exactly its named socket")
        endpoint = kernel._pin(stack, dispatcher.directory_fd, sn)
        dirs[role] = dict(path=_BOOT+"/"+dn, object=directory, names=names,
                          listener_handle=dict(dev=f"{os.major(dev)}:{os.minor(dev)}", ino=ino),
                          endpoint=dict(path=_BOOT+"/"+dn+"/"+sn,
                                        object=_project(endpoint, dispatcher.socket_identity, endpoint=True)))
    edge = dict(schema=SCHEMA, worker_uid=uid, worker_gid=gid, bootstrap=dict(path=_BOOT, object=base), directories=dirs)
    return edge


def _context(stack, deadline):
    proc, mount = kernel._proc(stack)
    leader = kernel._role(stack, proc, os.getpid(), mount)
    task = kernel._proc_child(stack, leader[1], "task", os.O_RDONLY | os.O_DIRECTORY, mount)
    caller = kernel._role(stack, task, threading.get_native_id(), mount)
    manager, manager_ctx, root, _ = kernel._frame(stack, leader, mount, deadline, kind="manager")
    _, caller_ctx, _, _ = kernel._frame(stack, caller, mount, deadline, kind="caller")
    _need(all(manager_ctx[k] == v for k, v in caller_ctx.items() if k not in ("pid","start_ticks")),
          "collector thread does not share the manager's trusted view")
    time_ns = sensor._namespace(stack, leader[1], "time", mount)
    _need(sensor._namespace(stack, caller[1], "time", mount) == time_ns, "manager clock domains differ")
    return (manager, sensor._boot_id(stack, proc, mount, deadline), time_ns), (manager_ctx, caller_ctx), root


def _tick():
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


def capture_owned_socket_directories(owned, request_dispatch, provider_dispatch, *, deadline):
    """One manager edge; bracket bounded independent observations with both actual owners' guards."""
    kernel._platform()
    opened = _tick()
    req, prov = request_dispatch, provider_dispatch
    owner = _owners(owned, req, prov, deadline)
    uid, gid = owner[:2]
    with ExitStack() as held:
        ctx, guard, root = _context(held, deadline)
        # The owner's existing guards use listdir; bound their protected
        # inputs first. Neither a name nor a new directory is adopted here.
        _need(kernel._names(owned.directory_fd, deadline, 3) == ["bootstrap.sock", "provider", "requests"],
              "unexpected bootstrap membership")
        for d, n in ((req, "request.sock"), (prov, "provider.sock")):
            _need(kernel._names(d.directory_fd, deadline, 1) == [n], "unexpected dispatcher membership")
        req._ownership()
        prov._ownership()
        first = _snapshot(held, root, owned, req, prov, uid, gid, owner[-1][1:], deadline)
        req._ownership()
        prov._ownership()
        with ExitStack() as last:
            ctx2, guard2, root2 = _context(last, deadline)
            _need((ctx, guard) == (ctx2, guard2), "manager/caller context changed")
            second = _snapshot(last, root2, owned, req, prov, uid, gid, owner[-1][1:], deadline)
        _need(first == second and owner == _owners(owned, req, prov, deadline), "custody changed during observation")
        kernel._check(deadline)
        first.update(manager=ctx[0],boot_id=ctx[1],time_namespace_inode=ctx[2],opened_boottime_ns=opened,
                     closed_boottime_ns=_tick())
        _edge_valid(first, uid, gid)
        return first


def _worker_socket_sample(stack, role, mount, owned, stopped, dispatchers, bootstrap_pin, deadline):
    # _frame follows only verified kernel magic links, holds this generation's
    # root and namespaces, and requires one stopped task with confined credentials.
    worker, context, root, _ = kernel._frame(stack, role, mount, deadline, kind="worker", ticks=owned.start_ticks)
    _need((worker["pid"], worker["uid"], worker["gid"]) == (owned.pid, owned.plan.worker_uid, owned.plan.worker_gid)
          and worker["mount_namespace"] != stopped["manager"]["mount_namespace"], "not the stopped worker's private view")
    _need(kernel._read(role[1], "cgroup", 8192, mount, deadline) == ("0::" + owned.plan.profile.cgroup + "\n").encode("ascii"),
          "different worker cgroup")
    # Ordinary names are metadata-only O_PATH|O_NOFOLLOW; every intermediate
    # component is also O_DIRECTORY. Never enumerate the worker's directory.
    run = kernel._pin(stack, root, "run", directory=True)
    base = kernel._pin(stack, run, "aragorn-pi-bootstrap", directory=True)
    base_obj = _project(base, owned.directory_identity)
    view_mount = base_obj["mnt_id"]
    _need(kernel._filesystem(base) == kernel._TMPFS and
          view_mount not in (kernel._stat(run, owner=True)["mnt_id"], stopped["bootstrap"]["object"]["mnt_id"]),
          "missing separate worker bootstrap bind")

    def same(fd, obj, expected):
        # A read-only bind has its own mount ID. All other recorded metadata,
        # including the underlying dentry inode, must match the original owner.
        _need(obj == {**expected, "mnt_id": view_mount} and os.fstatvfs(fd).f_flag & os.ST_RDONLY,
              "worker endpoint projection changed, writable, or overmounted")

    same(base, base_obj, stopped["bootstrap"]["object"])
    # The supervisor pinned the named socket at creation, not its sockfs listener inode.
    sock = kernel._pin(stack, base, "bootstrap.sock")
    bootstrap = _project(sock, bootstrap_pin, endpoint=True)
    _meta(bootstrap, stat.S_IFSOCK | 0o660, worker["gid"])
    _need((bootstrap["dev"], bootstrap["mnt_id"]) == (base_obj["dev"], view_mount) and
          os.fstatvfs(sock).f_flag & os.ST_RDONLY and all(bootstrap["ino"] != row["endpoint"]["object"]["ino"]
          for row in stopped["directories"].values()), "worker bootstrap endpoint aliased, writable, or overmounted")
    for (key, (dirname, filename)), dispatch in zip(_ROLES.items(), dispatchers):
        expected = stopped["directories"][key]
        directory = kernel._pin(stack, base, dirname, directory=True)
        same(directory, _project(directory, dispatch.directory_identity), expected["object"])
        leaf = kernel._pin(stack, directory, filename)
        same(leaf, _project(leaf, dispatch.socket_identity, endpoint=True), expected["endpoint"]["object"])
    return context, view_mount


def require_stopped_worker_socket_view(owned, stopped, *, deadline):
    """Refuse a foreign/writable projection before the held worker resumes; emit no evidence or permission."""
    kernel._platform()

    def guard():
        kernel._check(deadline)
        _need(type(owned) is native._Owned and owned.started is True and owned.exit_observed is False and
              _num(owned.pidfd, 0, 1 << 31) and type(owned.socket_directory_owners) is tuple and
              len(owned.socket_directory_owners) == 2, "no original stopped worker or socket owners")
        kernel._generation(owned.pid, owned.start_ticks)
        recv = owned.socket_directory_record
        owner = _owners(owned, *owned.socket_directory_owners, deadline)
        _edge_valid(stopped, *owner[:2])
        worker = dict(pid=owned.pid, start_ticks=owned.start_ticks, uid=owned.plan.worker_uid, gid=owned.plan.worker_gid,
                      cgroup=owned.plan.profile.cgroup, unit=owned.plan.unit_name, invocation_id=owned.invocation)
        _need(type(recv) is dict and recv.get("stopped") is stopped and recv.get("status") == native._SOCKET_INCOMPLETE
              and _num(recv.get("gate_stop_seq"), 1) and recv.get("worker") == worker and
              recv.get("immutable_launch_digest") == owned.immutable_digest and
              recv.get("clock") == dict(boot_id=stopped["boot_id"], clock_id="CLOCK_BOOTTIME",
                                        time_namespace_inode=stopped["time_namespace_inode"]), "different worker or stopped manager edge")
        native.process.require_live_pidfd(owned.pidfd)
        return owner, worker, owned.pidfd, owned.immutable_digest, recv["gate_stop_seq"]

    first = guard()
    bootstrap_pin = owned.socket_identity
    _need(type(bootstrap_pin) is tuple and bootstrap_pin, "missing original named bootstrap socket identity")
    with ExitStack() as held:
        proc, mount = kernel._proc(held)
        role = kernel._role(held, proc, owned.pid, mount)
        args = (role, mount, owned, stopped, owned.socket_directory_owners, bootstrap_pin, deadline)
        before = _worker_socket_sample(held, *args)
        with ExitStack() as end:
            _need(_worker_socket_sample(end, *args) == before, "worker root, credentials, namespace or mount changed")
        _need(guard() == first and owned.socket_identity == bootstrap_pin, "stopped worker or dispatch ownership changed")
