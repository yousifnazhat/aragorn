"""Recorded kernel readbacks; no live worker, systemd command, signal, or tracing."""
from copy import deepcopy
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest import TestCase, mock

from aragorn import pi_core_task_owner_roles as roles, pi_core_task_observer_binding as binding
from tests.test_pi_core_task_owner_roles import subject


class StaticWorkerBindingTests(TestCase):
    def setUp(self):
        self.until = monotonic()+10
        self.worker = dict(pid=502,uid=1250,gid=1250,start_ticks=701,unit=roles.WORKER,invocation_id="1"*32)
        self.clock = dict(clock_id="CLOCK_BOOTTIME", boot_id="11111111-1111-4111-8111-111111111111",
                          time_namespace_inode=661)
        self.raw = dict(worker=self.worker,clock=self.clock,service=dict(pid=503,start_ticks=702),
                        environment_digest="sha256:"+"a"*64,ticket_digest="sha256:"+"b"*64)
        self.read = mock.Mock(side_effect=lambda _:deepcopy(self.raw))
        own = (os.getpid(),roles.threading.get_native_id(),0,0)
        self.held = roles._Held(self.read,own,self.until)
        self.os = {k:self.enterContext(mock.patch.object(os,k,return_value=0)) for k in ("geteuid","getegid")}
        temp = Path(self.enterContext(TemporaryDirectory()))
        def file(name):
            f = self.enterContext((temp/name).open("w+b")); f.write(b"pinned"); f.flush()
            return f.fileno()
        self.pidfd,self.proc = file("pidfd"),file("proc")
        self.paths = {p:file(str(i)) for i,p in enumerate(roles._WORKER_PINS)}
        self.cmd = file("cmdline")
        self.metadata = {p:roles.sources._file_identity(os.fstat(fd)) for p,fd in self.paths.items()}
        self.read.observer_fds = self.pidfd,self.proc,44,self.paths,self.metadata
        self.peer = self.worker.copy()
        self.tracer,self.state,self.exe,self.argv = 0,"T",str(roles.sources.GATE_PATH),roles._GATE_ARGV
        self.threads = 1
        self.cg = ("0::/system.slice/"+roles.WORKER+"\n").encode()
        def show(*_):
            row=roles.binding._active(roles.WORKER,self.peer["pid"],self.peer["invocation_id"],roles.WORKER_UNIT)
            return "".join(f"{k}={v}\n" for k,v in row.items()).encode()
        def raw(proc,name,*_):
            if name=="cgroup": return self.cg
            w = self.peer
            stat,status=subject(w["pid"],w["uid"],w["gid"],w["start_ticks"],self.state,self.threads,self.tracer)
            return stat if name=="stat" else status
        def cmdline(_stack, _proc, name, *_):
            self.assertEqual(name,"cmdline")
            os.ftruncate(self.cmd,0)
            os.pwrite(self.cmd,self.argv,0)
            os.lseek(self.cmd,0,os.SEEK_SET)
            return self.cmd
        def patch(o,k,fn):
            self.enterContext(mock.patch.object(o,k,fn))
        patch(roles.kernel,"_platform",lambda:None)
        patch(roles.kernel,"_proc",lambda *_:(88,44))
        patch(roles.kernel,"_role",lambda _s,_r,pid,_m:(pid,self.proc))
        patch(roles.kernel,"_read",raw)
        patch(roles.binding,"_unit_show",show)
        patch(roles.sensor,"_boot_id",lambda *_:self.clock["boot_id"])
        patch(roles.sensor,"_namespace",lambda *_:self.clock["time_namespace_inode"])
        patch(roles,"_view",lambda _s,_pid,p:self.paths[p])
        patch(roles.kernel,"_magic",lambda _stack,_proc,name,*_: self.paths[self.exe] if name=="exe" else self.fail(name))
        patch(roles.kernel,"_proc_child",cmdline)
        patch(roles.sources,"_protected_file",lambda fd,_:roles.sources._file_identity(os.fstat(fd)))
        self.real_live = binding._live
        self.live = mock.Mock()
        patch(binding,"_live",self.live)

    def hold(self):
        return binding.bind_static_worker(self.held,deadline=self.until)

    def test_original_live_handles_and_package_survive_handoff_until_scope_closes(self):
        with self.hold() as worker:
            self.assertEqual(worker.worker,self.worker|{"cgroup":"/system.slice/"+roles.WORKER})
            self.assertEqual(worker.clock,self.clock)
            self.assertNotEqual(worker.pidfd,self.pidfd)
            self.assertTrue(os.path.samestat(os.fstat(worker.pidfd),os.fstat(self.pidfd)))
            self.assertEqual(set(worker.files),self.paths.keys())
            worker.guard(phase="stopped",deadline=self.until)
            self.assertTrue(self.live.called)
        with self.assertRaises(ValueError):
            worker.guard(phase="stopped",deadline=self.until)
        os.fstat(self.pidfd)

    def test_same_pid_swapped_generation_unit_or_code_refuses(self):
        with self.hold() as worker:
            for key,new in (("start_ticks",809),("invocation_id","2"*32)):
                with self.subTest(key=key),mock.patch.dict(self.peer,{key:new}),self.assertRaises(ValueError):
                    worker.guard(phase="stopped",deadline=self.until)
            for path in (str(roles.sources.GATE_PATH),roles.sources.ENTRY_PATH):
                with self.subTest(path=path),mock.patch.dict(self.paths,{path:self.proc}),self.assertRaises(ValueError):
                    worker.guard(phase="stopped",deadline=self.until)
            with mock.patch.object(self.held,"_read",None),self.assertRaises(ValueError):
                worker.guard(phase="stopped",deadline=self.until)

    def test_traced_phase_requires_own_tracer_and_exact_executable_arguments(self):
        with self.hold() as worker:
            self.tracer,self.state = roles.threading.get_native_id(),"t"
            worker.guard(phase="traced-gate",deadline=self.until)
            with self.assertRaises(ValueError):
                worker.guard(phase="node",deadline=self.until)
            self.argv,self.exe=roles._NODE_ARGV,str(roles.sources.NODE_PATH)
            worker.guard(phase="node",deadline=self.until)
            self.argv=self.argv.replace(b"--disallow-code-generation-from-strings\0",b"")
            with self.assertRaises(ValueError): worker.guard(phase="node",deadline=self.until)
            self.argv,self.tracer=roles._NODE_ARGV,self.tracer+1
            with self.assertRaises(ValueError): worker.guard(phase="node",deadline=self.until)

    def test_borrowed_pidfd_must_still_identify_exactly_the_claimed_pid(self):
        with mock.patch.object(roles.binding.native.process,"require_live_pidfd") as live, \
                mock.patch.object(roles.kernel,"_proc_child",return_value=61), \
                mock.patch.object(roles.kernel,"_read") as read:
            read.return_value = b"Pid:\t502\nNSpid:\t502\n"
            self.real_live(22,502,90,44,self.until)
            live.assert_called_once_with(22)
            self.assertEqual(read.call_args.args[:2],(61,"22"))
            for wrong in (b"Pid:\t504\n", b"Pid:\t502\nPid:\t502\n", b"NSpid:\t502\n"):
                read.return_value = wrong
                with self.assertRaisesRegex(ValueError,"borrowed pidfd"): self.real_live(22,502,90,44,self.until)

    def test_only_original_singleton_node_identity_argv_and_generation_are_observed(self):
        with self.hold() as worker:
            node = str(roles.sources.NODE_PATH)
            self.exe,self.argv,self.state,self.tracer = node,roles._NODE_ARGV,"t",roles.threading.get_native_id()
            record = worker.read_node_stop(deadline=self.until)
            self.assertEqual(record,dict(worker=worker.worker,clock=worker.clock,tracer_tid=self.tracer,
                node_identity=self.metadata[node],node_digest=roles._WORKER_PINS[node][0],node_argv_hex=self.argv.hex()))
            for key,changed in (("exe",str(roles.sources.GATE_PATH)),("argv",self.argv+b"extra\0"),
                                ("argv",self.argv[:-1]),("threads",2),("state","S"),("tracer",self.tracer+1)):
                with self.subTest(key=key),mock.patch.object(self,key,changed),self.assertRaises(ValueError):
                    worker.read_node_stop(deadline=self.until)
            for changed in (dict(start_ticks=970),dict(invocation_id="f"*32)):
                with self.subTest(generation=changed),mock.patch.dict(self.peer,changed),self.assertRaises(ValueError):
                    worker.read_node_stop(deadline=self.until)
            # A short first read can look exactly right even when more argv bytes remain.
            self.argv += b"unexpected\0"
            read = os.read
            with mock.patch.object(os,"read",side_effect=lambda fd,n:read(fd,min(n,len(roles._NODE_ARGV)))), \
                    self.assertRaisesRegex(ValueError,"trailing role arguments"):
                worker.read_node_stop(deadline=self.until)

    def test_wrong_kernel_clock_or_owner_closing_during_read_cannot_match(self):
        with self.hold() as worker:
            for key,value in (("boot_id","22222222-2222-4222-8222-222222222222"),("time_namespace_inode",662)):
                with self.subTest(key=key),mock.patch.dict(self.clock,{key:value}),self.assertRaisesRegex(ValueError,"clock"):
                    worker.guard(phase="stopped",deadline=self.until)
            def close_on_final_read(*_):
                if self.live.call_count == 2:
                    self.held._read = None
            self.live.reset_mock()
            self.live.side_effect = close_on_final_read
            with self.assertRaisesRegex(ValueError,"closed"):
                worker.guard(phase="stopped",deadline=self.until)
