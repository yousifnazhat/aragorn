"""Inert manager-side stopped-root walk: no real sockets, procfs, worker, or namespace."""
from contextlib import ExitStack
import os
import stat
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from aragorn import pi_core_owned_socket_directories as sockets
from tests.test_pi_core_owned_socket_directories import Kernel, sample_socket_edge


_ROOT = "/"
_BOOT = "/run/aragorn-pi-bootstrap"
_REQ = _BOOT + "/requests"
_PROV = _BOOT + "/provider"
_LEAVES = {_REQ + "/request.sock", _PROV + "/provider.sock"}


class StoppedView:
    # Portable bits belonging to the mocked Linux, not the test runner's OS.
    O_PATH, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC = 1, 2, 4, 8

    def __init__(self):
        k = self.manager = Kernel()
        owned = self.owned = k.own
        owned.started = owned.start_attempted = True
        owned.pid, owned.pidfd, owned.start_ticks = 73, 18, 1173
        owned.invocation, owned.immutable_digest = "b" * 32, "sha256:" + "c" * 64
        k.plan.unit_name = "aragorn-pi-" + "a"*32 + ".service"
        k.plan.profile = NS(cgroup="/system.slice/" + k.plan.unit_name)
        worker = dict(pid=73, start_ticks=1173, uid=1001, gid=1002, unit=k.plan.unit_name,
                      invocation_id=owned.invocation, cgroup=k.plan.profile.cgroup)
        self.worker = worker
        k.plan.source_observation_digest = "sha256:"+"1"*64
        k.plan.prepared = NS(deployment_digest="sha256:"+"2"*64)
        self.stopped = sample_socket_edge(opened_boottime_ns=1040, closed_boottime_ns=1050)
        owned.socket_directory_owners = (k.req, k.prov)
        owned.socket_directory_record = dict(schema="aragorn/pi-core-manager-socket-membership/v1",
            status=sockets.native._SOCKET_INCOMPLETE, before_start=k.expected, stopped=self.stopped,
            gate_stop_seq=1, worker=worker.copy(), immutable_launch_digest=owned.immutable_digest,
            deployment_digest=k.plan.prepared.deployment_digest, source_profile_digest=k.plan.source_observation_digest,
            clock=dict(clock_id="CLOCK_BOOTTIME", boot_id=self.stopped["boot_id"],
                       time_namespace_inode=self.stopped["time_namespace_inode"]))
        self.rows = {_ROOT:dict(k.objs[1], ino=191, mnt_id=502, dev="8:1"),
                     "/run":dict(k.objs[1], ino=390, mnt_id=502, dev="8:1"),
                     _BOOT:dict(k.objs[2], mnt_id=504), _REQ:dict(k.objs[3], mnt_id=504),
                     _PROV:dict(k.objs[4], mnt_id=504),
                     _REQ + "/request.sock":dict(k.objs[5], mnt_id=504),
                     _PROV + "/provider.sock":dict(k.objs[6], mnt_id=504)}
        self.handles, self.opened, self.closed = {}, [], []
        self.next = 100
        self.writable, self.links = set(), set()
        self.frames = 0
        self.on_frame = lambda number: None

    def allocate(self, name):
        self.next += 1
        self.handles[self.next] = name
        return self.next

    def held(self, stack, name):
        fd = self.allocate(name)
        stack.callback(self.close, fd)
        return fd

    def getpid(self):
        return self.stopped["manager"]["pid"]

    def open(self, name, flags, *, dir_fd):
        assert dir_fd in self.handles and "/" not in name and name not in (".","..")
        path = self.handles[dir_fd].rstrip("/") + "/" + name
        expected = self.O_PATH | self.O_NOFOLLOW | self.O_CLOEXEC
        if path not in _LEAVES:
            expected |= self.O_DIRECTORY
        assert flags == expected and path in self.rows, (path,flags)
        self.opened.append(path)
        if path in self.links and flags & self.O_DIRECTORY:
            raise NotADirectoryError(path)
        return self.allocate(path)

    def close(self, fd):
        self.handles.pop(fd)
        self.closed.append(fd)

    def meta(self, fd, *, owner=False):
        row = self.rows[self.handles[fd]] if fd in self.handles else self.manager.objs[fd]
        data = {k:row[k] for k in ("ino","dev","mode","mnt_id")}
        if owner:
            data.update(uid=row["uid"],gid=row["gid"])
        if self.handles.get(fd) in self.links:
            data["mode"] = stat.S_IFLNK | 0o777
        return {**data, "rdev":"0:0"}

    def fstat(self, fd):
        if fd not in self.handles:
            return self.manager.stat(fd)
        row = self.rows[self.handles[fd]]
        return NS(st_dev=os.makedev(*map(int,row["dev"].split(":"))), st_ino=row["ino"], st_uid=row["uid"],
                  st_gid=row["gid"], st_mode=self.meta(fd)["mode"], st_nlink=row["nlink"], st_size=row.get("size",0),
                  st_ctime_ns=row.get("ctime_ns",0), st_mtime_ns=row.get("mtime_ns",0))

    def frame(self, stack, role, mount, deadline, *, kind, ticks):
        self.frames += 1
        self.on_frame(self.frames)
        assert role[0] == 73 and (mount,deadline,kind,ticks) == (10,70,"worker",1173)
        subject = dict(pid=73,start_ticks=1173,uid=1001,gid=1002,mount_namespace=177,user_namespace=222)
        root = self.held(stack, _ROOT)
        return subject, {**subject, "root":self.meta(root)}, root, {}

    def run(self):
        s, k = sockets, self.manager
        with ExitStack() as st:
            def use(obj, fn, **kw):
                return st.enter_context(patch.object(obj,fn,**kw))
            # Reuse the established owner's manager descriptors but do not
            # bypass the real no-follow _pin/_own/ExitStack path under test.
            use(s, "socket", new=NS(socket=type(k.req.listener), AF_UNIX=k.req.listener.family,
                                    SOCK_STREAM=k.req.listener.type))
            use(s.kernel, "_platform")
            use(s.kernel, "_check")
            use(s.request, "_plan", return_value=k.plan)
            use(s.native.process, "require_live_pidfd")
            use(s.kernel, "_proc", side_effect=lambda stack:(self.held(stack,"proc"),10))
            use(s.kernel, "_role", side_effect=lambda stack,proc,pid,mount:(pid,self.held(stack,"worker")))
            use(s.kernel, "_frame", side_effect=self.frame)
            def read(fd, name, limit, mount, deadline):
                assert self.handles[fd] == "worker" and name == "cgroup" and (mount,deadline) == (10,70)
                return ("0::" + k.plan.profile.cgroup + "\n").encode()
            use(s.kernel, "_read", side_effect=read)
            use(s.kernel, "_filesystem", side_effect=lambda fd:0x534f434b if fd in (30,31,32) else 0x01021994)
            use(s.kernel, "_stat", side_effect=self.meta)
            use(s.kernel, "os", new=self)
            # No ordinary open(), socket connect(), or listdir() exists on this OS.
            use(s, "os", new=NS(fstat=self.fstat, major=os.major, minor=os.minor, ST_RDONLY=1,
                                 fstatvfs=lambda fd:NS(f_flag=0 if self.handles[fd] in self.writable else 1)))
            return s.require_stopped_worker_socket_view(self.owned, self.stopped, deadline=70)


class StoppedSocketMountTests(unittest.TestCase):
    def test_manager_resolves_only_fixed_no_follow_components_and_closes_all_handles(self):
        fixture = StoppedView()
        self.assertIsNone(fixture.run())  # Guard only, no Pi access/permission/health receipt.
        self.assertEqual(fixture.frames, 2)
        for path in ("/run",_BOOT,_REQ,_PROV,*_LEAVES):
            self.assertEqual(fixture.opened.count(path), 2, path)
        self.assertEqual(fixture.handles,{})
        self.assertEqual(len(set(fixture.closed)), len(fixture.closed))

    def test_substitution_of_a_named_directory_or_a_leaf_refuses_and_releases_handles(self):
        for path in (_REQ,_PROV,_REQ+"/request.sock",_PROV+"/provider.sock"):
            f = StoppedView()
            f.rows[path]["ino"] += 10
            with self.subTest(path=path), self.assertRaisesRegex(ValueError,"descriptor differs"):
                f.run()
            self.assertEqual(f.handles,{})

    def test_writable_parent_writable_child_and_distinct_nested_mounts_refuse(self):
        for path in (_BOOT,_REQ,_PROV,*sorted(_LEAVES)):
            f = StoppedView()
            f.writable.add(path)
            with self.subTest(writable=path), self.assertRaisesRegex(ValueError,"writable, or overmounted"):
                f.run()
            self.assertEqual(f.handles,{})
        for path in (_REQ, _PROV+"/provider.sock"):
            f = StoppedView()
            f.rows[path]["mnt_id"] += 1  # Same dev/inode alone is not enough for a new bind.
            with self.subTest(overmount=path), self.assertRaisesRegex(ValueError,"writable, or overmounted"):
                f.run()
            self.assertEqual(f.handles,{})

    def test_symlinked_ordinary_components_and_same_name_replacement_at_second_edge_fail(self):
        for path in ("/run",_BOOT,_REQ,_PROV+"/provider.sock"):
            f = StoppedView()
            f.links.add(path)
            with self.subTest(link=path), self.assertRaises((ValueError,NotADirectoryError)):
                f.run()
            self.assertEqual(f.handles,{})
        f = StoppedView()
        def replace_on_second_frame(n):
            if n == 2:
                f.rows[_PROV+"/provider.sock"]["ctime_ns"] += 1
        f.on_frame = replace_on_second_frame
        with self.assertRaises(ValueError):
            f.run()
        self.assertEqual(f.frames,2)
        self.assertEqual(f.handles,{})

    def test_match_must_belong_to_original_stop_and_same_worker_root_at_both_edges(self):
        f = StoppedView()
        f.owned.socket_directory_record["stopped"] = f.stopped.copy()
        with self.assertRaisesRegex(ValueError,"different worker or stopped manager edge"):
            f.run()
        self.assertEqual(f.opened,[])
        f = StoppedView()
        def retarget_root(n):
            if n == 2:
                f.rows[_ROOT]["ino"] += 1
        f.on_frame = retarget_root
        with self.assertRaisesRegex(ValueError,"worker root, credentials, namespace or mount changed"):
            f.run()
        self.assertEqual(f.handles,{})
