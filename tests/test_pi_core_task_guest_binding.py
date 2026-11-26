"""Recorded unit/clock/code observations only; these tests do not query a manager."""
from contextlib import ExitStack
from hashlib import sha256
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn.oci_worker_protocol import canonical_digest
from aragorn import pi_core_task_guest_binding as binding
from aragorn.pi_core_task_guest_binding import bound_environment


class TaskGuestBindingTests(TestCase):
    def setUp(self):
        self.task = "aragorn-pi-task.service"
        self.sensor = "aragorn-pi-sensor.service"
        self.code = {k:canonical_digest(k) for k in ("unit_digest","wrapper_digest","interpreter_digest")}
        self.clock = dict(clock_id="CLOCK_BOOTTIME", boot_id="11111111-1111-4111-8111-111111111111",
                          time_namespace_inode=4026531834)
        self.req = dict(kind="task", mode="instrumented", pair_id="pair-1",
            **{k:canonical_digest(k) for k in ("task_digest","input_digest","collection_digest","host_profile_digest","deployment_digest")})
        self.peers = dict(manager_peer=[501,0,0], pi_peer=[502,1250,1250], service_peer=[503,1350,1350])

    def active(self, name, pid, invocation):
        return dict(Id=name, LoadState="loaded", ActiveState="active", SubState="running", MainPID=str(pid),
                    ExecMainPID=str(pid), ControlPID="0", InvocationID=invocation, ControlGroup="/system.slice/"+name,
                    FragmentPath=("/usr/lib/systemd/system/" if name==self.task else "/run/systemd/transient/")+name,
                    NeedDaemonReload="no", DropInPaths="")

    def absent(self):
        return dict(Id=self.sensor,LoadState="not-found",ActiveState="inactive",SubState="dead",MainPID="0",
                    ExecMainPID="0",ControlPID="0",InvocationID="",ControlGroup="",FragmentPath="",NeedDaemonReload="no",DropInPaths="")

    @staticmethod
    def encode(properties):
        return "".join(k+"="+v+"\n" for k,v in properties.items()).encode("ascii")

    def inputs(self, mode):
        req = self.req | {"mode":mode}
        nid = "2"*32 if mode=="instrumented" else None
        nomination = dict(schema="aragorn/pi-task-guest-nomination/v1", request_digest=canonical_digest(req),
            clock=self.clock, **self.peers, service_invocation_id="1"*32, sensor_invocation_id=nid,
            sensor_pid=504 if nid else 0, service_code=self.code)
        pin = canonical_digest(nomination)
        ticket = dict(schema="aragorn/pi-core-task-ticket/v1",request=req,clock=self.clock,**self.peers,environment_digest=pin)
        service = self.active(self.task,503,"1"*32)
        sensor = self.active(self.sensor,504,nid) if nid else self.absent()
        return ticket, dict(nomination=nomination,nomination_pin=pin,installed_service_pin=canonical_digest(self.code),
                            service_show=self.encode(service),sensor_show=self.encode(sensor),clock=self.clock)

    def test_distinct_captured_unit_states_match_only_the_nominated_mode(self):
        for mode in ("baseline","instrumented"):
            ticket,args = self.inputs(mode)
            self.assertEqual(bound_environment(ticket, **args),ticket["environment_digest"])
            other = "baseline" if mode=="instrumented" else "instrumented"
            with self.assertRaises(ValueError):
                bound_environment(ticket, **(args | {"sensor_show":self.inputs(other)[1]["sensor_show"]}))

    def test_service_code_generation_or_substituted_fragment_refused(self):
        ticket,args = self.inputs("instrumented")
        for patch in (dict(installed_service_pin=canonical_digest("other bytes")),
                      dict(service_show=args["service_show"].replace(b"MainPID=503",b"MainPID=509")),
                      dict(service_show=args["service_show"].replace(b"InvocationID=11",b"InvocationID=99")),
                      dict(service_show=args["service_show"].replace(b"DropInPaths=\n",b"DropInPaths=/etc/other.conf\n")),
                      dict(service_show=args["service_show"].replace(b"/usr/lib/systemd/system/",b"/tmp/")),
                      dict(clock=self.clock | {"time_namespace_inode":999})):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                bound_environment(ticket, **(args | patch))

    def test_relabelling_or_incomplete_evidence_cannot_supply_mode(self):
        ticket,args = self.inputs("instrumented")
        with self.assertRaises(ValueError):
            bound_environment(ticket | {"request":ticket["request"] | {"mode":"baseline"}}, **args)
        for raw in (b"", args["sensor_show"]+b"MainPID=504\n", args["sensor_show"].replace(b"ActiveState=active",b"ActiveState=failed"),
                    args["sensor_show"].replace(b"InvocationID=22",b"InvocationID=aa"),
                    args["sensor_show"].replace(b"NeedDaemonReload=no",b"NeedDaemonReload=yes")):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                bound_environment(ticket, **(args | {"sensor_show":raw}))

    def test_acquisition_hashes_open_bytes_and_refuses_substituted_exe_or_argv(self):
        # Temp descriptors stand in for protected guest inodes; no procfs or systemd.
        with TemporaryDirectory() as temp, ExitStack() as scope:
            directory = Path(temp)
            payload = {binding._UNIT:b"unit",binding._WRAPPER:b"wrapper",binding._PYTHON:b"interpreter"}
            paths = {name:directory / str(i) for i,name in enumerate(payload)}
            for name, raw in payload.items():
                paths[name].write_bytes(raw)
            cmd = directory/"cmd"
            cmd.write_bytes(binding._ARGV)
            current_exe = [paths[binding._PYTHON]]
            def held(stack,path):
                fd = os.open(path,os.O_RDONLY)
                stack.callback(os.close,fd)
                return fd
            scope.enter_context(mock.patch.object(binding.sources,"_open_view",side_effect=lambda _pid,p:os.open(paths[str(p)],os.O_RDONLY)))
            scope.enter_context(mock.patch.object(binding.kernel,"_magic",side_effect=lambda stack,*_:held(stack,current_exe[0])))
            scope.enter_context(mock.patch.object(binding.kernel,"_proc_child",side_effect=lambda stack,*_:held(stack,cmd)))
            scope.enter_context(mock.patch.object(binding.os,"fstatvfs",return_value=SimpleNamespace(f_flag=os.ST_RDONLY)))
            scope.enter_context(mock.patch.object(binding.sources,"_protected_file",side_effect=lambda fd,limit:{
                "size":os.fstat(fd).st_size, "inode":os.fstat(fd).st_ino}))
            def read():
                with ExitStack() as opened:
                    return binding._service_code(opened,503,99,40,float("inf"))
            expected = {k:"sha256:"+sha256(payload[p]).hexdigest() for k,p in (
                ("unit_digest",binding._UNIT),("wrapper_digest",binding._WRAPPER),("interpreter_digest",binding._PYTHON))}
            self.assertEqual(read(),expected)
            paths[binding._WRAPPER].write_bytes(b"changed wrapper")
            self.assertNotEqual(read()["wrapper_digest"],expected["wrapper_digest"])
            current_exe[0] = paths[binding._WRAPPER]
            with self.assertRaisesRegex(ValueError,"different executing"):
                read()
            current_exe[0] = paths[binding._PYTHON]
            cmd.write_bytes(binding._ARGV+b"-c\x00")
            with self.assertRaisesRegex(ValueError,"arguments"):
                read()
