"""Held task generations. All role, unit and kernel observations are inert fixtures."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
from unittest import TestCase, mock

from aragorn import pi_core_task_guest_binding as binding, pi_core_task_owner_roles as roles
from aragorn.oci_worker_protocol import canonical_digest


def subject(pid, uid, gid, ticks, state="T", threads=1, tracer=0):
    raw_stat = (f"{pid} (fixed role) {state} 1 " + "0 " * 17 + f"{ticks} 0\n").encode()
    raw_status = (f"State:\t{state} (state)\nTgid: {pid}\nPid: {pid}\nPPid: 1\n"
                  f"Uid: {uid} {uid} {uid} {uid}\nGid: {gid} {gid} {gid} {gid}\nGroups:\n"
                  f"Threads: {threads}\nTracerPid:\t{tracer}\nNoNewPrivs: 1\n" +
                  "".join(f"{field}: 0000000000000000\n" for field in
                          ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))).encode()
    return raw_stat, raw_status


class OwnerRolesTests(TestCase):
    def test_requires_real_group_stop_and_matching_dynamic_identity(self):
        for peer in ([502, 1250, 1250], [503, 1350, 1350]):
            with self.subTest(peer=peer):
                self.assertEqual(roles._bound_process(peer, *subject(*peer, 121), stopped=True), 121)
                for state, threads, tracer in (("S", 1, 0), ("t", 1, 42), ("T", 2, 0), ("T", 1, 42)):
                    with self.assertRaises(ValueError):
                        roles._bound_process(peer, *subject(*peer, 121, state, threads, tracer), stopped=True)
                stat, status = subject(*peer, 121)
                for corrupt in (status.replace(b"TracerPid:\t0\n", b""), status + b"TracerPid: 0\n",
                                status.replace(b"NoNewPrivs: 1", b"NoNewPrivs: 0")):
                    with self.assertRaises(ValueError):
                        roles._bound_process(peer, stat, corrupt, stopped=True)
                with self.assertRaises(ValueError):
                    roles._bound_process(peer, *subject(peer[0], peer[1]+1, peer[2], 121), stopped=True)

    def test_substitution_of_either_unit_or_membership_refuses(self):
        for unit in ("aragorn-pi-task-worker.service", "aragorn-pi-task.service"):
            expected = binding._active(unit, 501, "a"*32, "/usr/lib/systemd/system/"+unit)
            def raw(**changes):
                return "".join(f"{k}={v}\n" for k, v in (expected | changes).items()).encode()
            cgroup = f"0::/system.slice/{unit}\n".encode()
            roles._bound_unit(unit, 501, "a"*32, cgroup, raw())
            for cg, show in ((cgroup, raw(InvocationID="b"*32)), (cgroup, raw(MainPID="508")),
                             (cgroup, raw(DropInPaths="/substitution")), (cgroup+b"other", raw())):
                with self.subTest(unit=unit), self.assertRaises(ValueError):
                    roles._bound_unit(unit, 501, "a"*32, cg, show)

    def test_held_record_is_detached_and_guard_rejects_new_generation_or_owner(self):
        import os
        manager = [os.getpid(), 0, 0]
        req = dict(kind="task", mode="baseline", pair_id="pair-1",
                   **{k:canonical_digest(k) for k in ("task_digest","input_digest","collection_digest",
                                                      "host_profile_digest","deployment_digest")})
        clock = dict(clock_id="CLOCK_BOOTTIME",boot_id="11111111-1111-4111-8111-111111111111",time_namespace_inode=19)
        peers = dict(manager_peer=manager, pi_peer=[52,1250,1250],service_peer=[53,1350,1350])
        n = dict(schema="aragorn/pi-task-guest-nomination/v1",request_digest=canonical_digest(req),clock=clock, **peers,
                 service_invocation_id="1"*32,sensor_invocation_id=None,sensor_pid=0,
                 service_code=dict(roles.SERVICE_CODE))
        pin = canonical_digest(n)
        ticket = dict(schema="aragorn/pi-core-task-ticket/v1",request=req,clock=clock,environment_digest=pin,**peers)
        generations = {"worker":{"start_ticks":125},"service":{"start_ticks":254}}
        stopped_reads = []
        @contextmanager
        def acquired(*args):
            def read(stopped):
                stopped_reads.append(stopped)
                return deepcopy(generations)
            yield read
        with mock.patch.object(roles, "_observe_held", acquired), mock.patch.object(roles.os,"geteuid",return_value=0), \
                mock.patch.object(roles.os,"getegid",return_value=0):
            with roles.hold_stopped_roles(ticket, nomination=n, nomination_pin=pin,
                                          worker_invocation_id="2"*32, deadline=roles.time.monotonic()+8) as held:
                seen=held.record
                seen["worker"]["start_ticks"]=1
                held.guard(stopped=True)
                held.guard(stopped=False)
                self.assertEqual(stopped_reads[:3], [True,True,False])
                for role in ("service","worker"):
                    generations[role]["start_ticks"] += 1
                    with self.assertRaises(ValueError):
                        held.guard(stopped=True)
                    generations[role]["start_ticks"] -= 1
                with mock.patch.object(roles.os,"getpid",return_value=manager[0]+1), self.assertRaises(ValueError):
                    held.guard(stopped=True)
            with self.assertRaises(ValueError):
                held.guard(stopped=False)

    def test_reader_joins_packaged_code_with_held_processes(self):
        # Only the I/O layer is recorded. No actual pidfd, /proc, proc command,
        # unit or task is used. Verify pins against the independent package.
        base = Path(__file__).resolve().parents[1]/"packaging/pi-core"
        def catalog(path):
            return json.loads((base/path).read_bytes())
        worker = catalog("task-worker-v1/build.json")["outputs"]
        compiled = catalog("compiled-artifact-v3.json")
        node, = (r["sha256"] for r in compiled["selected_output_files"] if r["path"]=="node/bin/node")
        code = catalog("task-guest-payload-v1.json")["service_code"]
        pins = {roles.WORKER_UNIT:"sha256:"+catalog("task-guest-sources-v1.json")["units"][roles.WORKER],
                str(roles.sources.GATE_PATH):"sha256:"+worker["source-gate"]["sha256"],
                str(roles.sources.NODE_PATH):"sha256:"+node,
                roles.sources.ENTRY_PATH:"sha256:"+worker["entrypoint.js"]["sha256"]}
        self.assertEqual(dict(roles.SERVICE_CODE),code)
        boot = "11111111-1111-4111-8111-111111111111"
        clock = dict(clock_id="CLOCK_BOOTTIME",boot_id=boot,time_namespace_inode=21)
        n = dict(clock=clock,manager_peer=[501,0,0],pi_peer=[502,1250,1250],service_peer=[503,1350,1350],
                 service_invocation_id="1"*32)
        ids = {roles.WORKER:(502,"2"*32), binding._TASK:(503,"1"*32)}
        exe = {502:str(roles.sources.GATE_PATH),503:binding._PYTHON}
        argv = {502:roles._GATE_ARGV,503:binding._ARGV}
        tracers = {502:0,503:0}
        tracer_tgid = {80:501,81:999}
        def show(unit, _):
            row=binding._active(unit,*ids[unit],"/usr/lib/systemd/system/"+unit)
            return "".join(f"{k}={v}\n" for k,v in row.items()).encode()
        def raw(pid,name,*_):
            if pid in tracer_tgid:
                stat, status = subject(pid,0,0,900,"S")
                return stat if name=="stat" else status.replace(f"Tgid: {pid}".encode(),
                                                                  f"Tgid: {tracer_tgid[pid]}".encode())
            peer, unit = (n["pi_peer"],roles.WORKER) if pid==502 else (n["service_peer"],binding._TASK)
            if name == "cgroup":
                return ("0::/system.slice/"+unit+"\n").encode()
            return subject(*peer,pid+1000,state="t" if tracers[pid] else "T",
                           tracer=tracers[pid])[{"stat":0,"status":1}[name]]
        with ExitStack() as s:
            def patch(obj,name,fn):
                s.enter_context(mock.patch.object(obj,name,fn,create=True))
            patch(roles.kernel,"_platform",lambda:None)
            patch(roles.kernel,"_proc",lambda _: (100,44))
            patch(roles.os,"pidfd_open",lambda pid,_:pid)
            patch(roles.os,"close",lambda _:None)
            poll=mock.Mock()
            patch(binding.native.process,"require_live_pidfd",poll)
            patch(roles.kernel,"_role",lambda _,root,pid,m:(pid,pid))
            patch(roles.kernel,"_magic",lambda _,pid,*args:exe[pid])
            patch(roles.kernel,"_proc_child",lambda _,pid,name,*args:BytesIO(argv[pid]) if name=="cmdline" else pid)
            patch(roles,"_same_file",lambda a,b:a==b)
            patch(roles.os,"read",BytesIO.read)
            patch(roles,"_view",lambda _,pid,path:path)
            patch(roles.sources,"_hash",lambda path,*args:(pins[path],{}))
            patch(binding,"_service_code",lambda *args:code)
            patch(roles.sensor,"_namespace",lambda *_:21)
            patch(roles.sensor,"_boot_id",lambda *_:boot)
            patch(roles.kernel,"_read",raw)
            patch(binding,"_unit_show",show)
            def held():
                return roles._observe_held({"request":{}},n,"2"*32,roles.time.monotonic()+8)
            with held() as read:
                record = read(True)
                self.assertEqual((record["worker"]["start_ticks"],record["service"]["start_ticks"]),(1502,1503))
                self.assertIn(mock.call(502),poll.call_args_list)
                self.assertIn(mock.call(503),poll.call_args_list)
                exe[502] = str(roles.sources.NODE_PATH)
                argv[502] = roles._NODE_ARGV
                self.assertEqual(read(False),record)
                with self.assertRaisesRegex(ValueError,"executable"):
                    read(True)
                tracers[502] = 80
                self.assertEqual(read(False),record)
                with self.assertRaisesRegex(ValueError,"untraced"):
                    read(True)
                tracers[502] = 81
                with self.assertRaisesRegex(ValueError,"process identity"):
                    read(False)
                tracers[502],tracers[503] = 0,80
                with self.assertRaisesRegex(ValueError,"tracer"):
                    read(False)
                tracers[503] = 0
                argv[503] += b"other\x00"
                with self.assertRaisesRegex(ValueError,"executable"):
                    read(False)
            pins[str(roles.sources.GATE_PATH)] = canonical_digest("changed gate")
            with self.assertRaisesRegex(ValueError,"substituted fixed-task worker"), held():
                pass
