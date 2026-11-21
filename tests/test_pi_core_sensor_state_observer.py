"""Fake proc, directories, clocks and an existing lifecycle; no process, device or mount is opened."""
from contextlib import ExitStack
import hashlib
from types import SimpleNamespace
import stat
import unittest
from unittest.mock import patch

from aragorn import pi_core_sensor_state_observer as observer
from tests.test_pi_core_stopped_mask_view import Kernel


ID = dict(role="sensor", unit="aragorn-pi-sensor.service", pid=73, start_ticks=1173, uid=40, gid=40,
          invocation_id="ca" * 16)
BOOT = "12345678-1234-4234-8234-123456789abc"


class SensorKernel(Kernel):
    def __init__(self):
        super().__init__()
        self.state, self.midpoint, self.boot_id = "S", None, BOOT
        self.cgroup = b"0::/system.slice/aragorn-pi-sensor.service\n"
        self.time_ns = {23: 901, 24: 901, 73: 901}
        self.reads = []
        self.mounts[73] = b"sensor rows\n"

    def metadata(self, fd, owner=False):
        s = super().metadata(fd, owner)
        path = self.fds[fd]
        if path == self.ROOT + observer.ACTION:
            s.update(ino=101, dev="8:2", mode=stat.S_IFDIR | 0o755, mnt_id=81)
        if path in (self.MAN + observer.ACTION, self.MAN + observer.ANCHOR + observer.ACTION):
            s["mode"] = stat.S_IFDIR | 0o755
        return s | self.pinned[fd]

    def fstat(self, fd):
        p = self.fds[fd]
        if p.endswith("/ns/time"):
            return SimpleNamespace(st_ino=self.time_ns[int(p.split("/")[-3])])
        return super().fstat(fd)

    def read(self, proc, name, maximum, mount, deadline):
        path = self.fds[proc]
        self.reads.append((path, name))
        if name == "boot_id":
            assert path == "/proc/sys/kernel/random" and maximum == 37
            return (self.boot_id + "\n").encode()
        if name == "cgroup":
            assert path == "/proc/73"
            return self.cgroup
        raw = super().read(proc, name, maximum, mount, deadline)
        if path == "/proc/73" and name == "mountinfo" and self.midpoint:
            change, self.midpoint = self.midpoint, None
            change(self)
        return raw

    def install(self, stack):
        super().install(stack)
        stack.enter_context(patch.object(observer, "os", self))
        stack.enter_context(patch.object(observer, "threading", observer.kernel.threading))
        stack.enter_context(patch.object(observer, "time", observer.kernel.time))


class SensorStateObserverTests(unittest.TestCase):
    def test_complete_kernel_bracket_contains_real_fake_streams_and_no_path_absence_claim(self):
        with ExitStack() as scope:
            k, calls = SensorKernel(), []
            k.install(scope)
            def guard(*, deadline):
                calls.append(deadline)
                return dict(ID)
            view, manager, sensor = observer.capture_sensor_state(identity=ID, guard=guard, deadline=14)
        self.assertEqual(calls, [14, 14])
        self.assertFalse(k.fds)
        self.assertEqual((manager, sensor), (b"manager rows\n", b"sensor rows\n"))
        self.assertEqual(view["identity"], ID)
        self.assertEqual(view["sensor"]["mount_namespace"], 602)
        self.assertEqual(view["manager"]["mount_namespace"], 601)
        self.assertEqual(view["sensor_cgroup"].encode(), k.cgroup)
        self.assertEqual(view["clock"], dict(clock_id="CLOCK_BOOTTIME", time_namespace_inode=901, boot_id=BOOT))
        self.assertLess(view["opened_boottime_ns"], view["closed_boottime_ns"])
        for role, raw in (("manager", manager), ("sensor", sensor)):
            self.assertEqual(view[role + "_mountinfo_digest"], "sha256:" + hashlib.sha256(raw).hexdigest())
        self.assertEqual(view["manager_state"]["before"], view["manager_state"]["after"])
        self.assertEqual(view["sensor_targets"]["before"], view["sensor_targets"]["after"])
        self.assertEqual(set(view["sensor_targets"]["before"]), {observer.ACTION})
        src = view["manager_state"]["before"]["sources"][observer.ACTION]
        self.assertEqual(view["sensor_targets"]["before"][observer.ACTION], src | {"mnt_id":81})
        # Never try to turn a missing sensor provider pathname into an absence proof.
        self.assertFalse(any(p.startswith(k.ROOT + observer.PROVIDER) for p,_ in k.calls))

    def test_wrong_unit_or_ambiguous_lifecycle_never_returns_evidence(self):
        for label, identity, guards in (
                ("other role", ID | {"role":"action"}, []),
                ("invalid invocation", ID | {"invocation_id":"0"*32}, []),
                ("bad gid", ID | {"gid":True}, []),
                ("opening mismatch", ID, [ID | {"pid":74}]),
                ("closing mismatch", ID, [ID, ID | {"invocation_id":"ef"*16}]),
                ("uid not the stored sensor's", ID | {"uid":41}, [ID | {"uid":41}])):
            with self.subTest(label=label), ExitStack() as scope:
                k = SensorKernel()
                k.install(scope)
                results = iter(guards)
                with self.assertRaises(ValueError):
                    observer.capture_sensor_state(identity=identity, guard=lambda **kw: next(results), deadline=14)
                self.assertFalse(k.fds)

    def test_retention_guard_checks_original_streams_owner_and_held_generations_at_writes(self):
        for changed in ("unchanged", "manager alias", "new sensor alias", "reused PID", "different clock"):
            with self.subTest(changed=changed), ExitStack() as stack:
                k, calls = SensorKernel(), []
                k.install(stack)
                guard = lambda **kw: dict(ID)
                view, manager, sensor = observer.capture_sensor_state(identity=ID, guard=guard, deadline=14)
                def owner(*, deadline):
                    calls.append(deadline)
                    return dict(ID)
                def scope():
                    return observer.hold_sensor_mount_guard(identity=ID, view=view, manager_raw=manager,
                        sensor_raw=sensor, guard=owner, deadline=14)
                if changed == "unchanged":
                    with scope() as current:
                        current()
                    self.assertEqual(calls, [14, 14])
                    with self.assertRaises(ValueError):
                        current()
                else:
                    with self.assertRaises(ValueError):
                        with scope() as current:
                            if changed == "manager alias":
                                k.mounts.update({23:b"alias\n",24:b"alias\n"})
                            elif changed == "new sensor alias":
                                k.mounts[73] = b"sensor alias\n"
                            elif changed == "reused PID":
                                k.tick += 1
                            else:
                                k.time_ns[73] += 1
                            current()
                    self.assertFalse(k.fds)

    def test_mid_capture_changes_refuse_even_when_the_lifecycle_id_is_unchanged(self):
        for label, change in (
                ("reused PID", lambda k: setattr(k, "tick", 1174)),
                ("multi-task", lambda k: setattr(k, "count", 2)),
                ("dead task", lambda k: setattr(k, "state", "Z")),
                ("cgroup moved", lambda k: setattr(k, "cgroup", b"0::/else\n")),
                ("time namespace", lambda k: k.time_ns.update({73:902})),
                ("boot changed", lambda k: setattr(k, "boot_id", "a" + BOOT[1:])),
                ("caller namespace", lambda k: setattr(k, "thread_mnt", 811)),
                ("sensor mount changed", lambda k: k.mounts.update({73:b"changed\n"})),
                ("source renamed", lambda k: k.renamed.update({k.MAN + observer.ANCHOR + observer.ACTION: {"ino": 777}})),
                ("target rebound", lambda k: k.renamed.update({k.ROOT + observer.ACTION: {"mnt_id": 777}})),
                ("missing source", lambda k: k.missing.add(k.MAN + observer.ANCHOR + observer.PROVIDER)),
                ("late read", lambda k: setattr(k, "now", 14))):
            with self.subTest(label=label), ExitStack() as scope:
                k = SensorKernel()
                k.install(scope)
                k.midpoint = change
                with self.assertRaises((ValueError, FileNotFoundError)):
                    observer.capture_sensor_state(identity=ID, guard=lambda **kw: dict(ID), deadline=14)
                self.assertFalse(k.fds)
