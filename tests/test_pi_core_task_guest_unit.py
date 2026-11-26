"""Static service packaging, authenticated one-shot release, and no ambient mode switches."""
from contextlib import ExitStack, nullcontext
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
from time import monotonic, monotonic_ns
from unittest import TestCase, mock

from aragorn.oci_worker_protocol import canonical_digest


FILES = Path(__file__).resolve().parents[1] / "packaging/pi-core/task-guest-v1"
spec = spec_from_file_location("aragorn.pi_core_task_guest_entry", FILES / "pi_core_task_guest_entry.py")
role = module_from_spec(spec)
spec.loader.exec_module(role)


class GuestUnitTests(TestCase):
    def test_fixed_unenabled_service_reads_only_successor_code_and_private_owner_sockets(self):
        unit = (FILES / "aragorn-pi-task.service").read_text().splitlines()
        for line in ("Type=exec", "User=aragorn-pi-task", "DynamicUser=yes", "Restart=no",
                     "ExecStart=/opt/aragorn-cpython/bin/python3.12 -I -S -B /opt/aragorn/bin/pi-fixed-task.py",
                     "BindReadOnlyPaths=/opt/aragorn/fixed-task/src:/opt/aragorn/src",
                     "TemporaryFileSystem=/run:ro", "BindReadOnlyPaths=/run/aragorn-pi-task-owner",
                     "NoNewPrivileges=yes", "RestrictAddressFamilies=AF_UNIX", "CapabilityBoundingSet="):
            self.assertIn(line, unit)
        self.assertEqual([x for x in unit if x.startswith("ExecStart")], [next(x for x in unit if x.startswith("ExecStart="))])
        self.assertFalse(any(x.startswith(("[Install]", "Environment=", "EnvironmentFile=", "Sockets=", "WantedBy=")) for x in unit))
        wrapper = (FILES / "pi-fixed-task.py").read_text()
        self.assertIn("_ARAGORN_SOURCE_DIGESTS = None  # assembled source pins", wrapper)
        self.assertIn("from aragorn.pi_core_task_guest_entry import run", wrapper)

    def packet(self):
        keys = ("task_digest","input_digest","host_profile_digest","collection_digest","deployment_digest")
        request = dict(kind="task", pair_id="a", mode="baseline", **{k:canonical_digest(k) for k in keys})
        peers = dict(manager_peer=[12,0,0], service_peer=[13,61112,61112], pi_peer=[14,61113,61113])
        clock = dict(clock_id="CLOCK_BOOTTIME",boot_id="12345678-1234-1234-1234-123456789abc",time_namespace_inode=9)
        nomination = dict(schema="aragorn/pi-task-guest-nomination/v1", request_digest=canonical_digest(request),
            **peers, clock=clock, service_invocation_id="a"*32, sensor_invocation_id=None, sensor_pid=0,
            service_code=dict(wrapper_digest=canonical_digest("exact wrapper"),unit_digest=canonical_digest("unit"),
                              interpreter_digest=canonical_digest("interpreter")))
        ticket = dict(schema="aragorn/pi-core-task-ticket/v1", request=request,
            environment_digest=canonical_digest(nomination), clock=clock, **peers)
        return dict(schema="aragorn/pi-core-task-owner-release/v1", ticket=ticket, ticket_pin=canonical_digest(ticket),
            nomination=nomination, nomination_pin=canonical_digest(nomination), deadline_ns=monotonic_ns()+5_000_000_000)

    def validate(self, packet, service_pin=None):
        return role.validate_release(packet, owner=(12,0,0), service=(13,61112,61112),
            service_pin=service_pin or canonical_digest("exact wrapper"), outer_deadline=monotonic()+10)

    def test_authorized_release_matches_role_and_mode_before_adopting_task(self):
        good = self.packet()
        self.assertGreater(self.validate(good), monotonic())
        for change in ("wrapper","mode","peer","timeout","extra"):
            p = self.packet()
            if change == "mode":
                p["ticket"]["request"]["mode"] = "instrumented"
                p["ticket_pin"] = canonical_digest(p["ticket"])
            elif change == "peer":
                p["ticket"]["manager_peer"][0] = 999
                p["ticket_pin"] = canonical_digest(p["ticket"])
            elif change == "timeout":
                p["deadline_ns"] = monotonic_ns()-1
            elif change == "extra":
                p["service_path"] = "/tmp/other.py"
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(p, canonical_digest("other wrapper") if change == "wrapper" else None)

    def test_substituted_kernel_socket_or_unconnected_listener_never_reaches_service(self):
        import socket
        sock = mock.Mock()
        sock.family, sock.type = socket.AF_UNIX, socket.SOCK_STREAM
        sock.getsockopt.return_value = 0
        sock.getsockname.return_value = "/proc/self/fd/17/service.sock"
        with mock.patch.object(role.wire, "_peer_credentials", return_value=(14,61113,61113)), \
                mock.patch.object(role, "_fd_id", return_value=[6,21]):
            role.check_pi(sock, self.packet()["ticket"], [6,21])
            sock.getsockopt.return_value = 1
            with self.assertRaises(ValueError):
                role.check_pi(sock, self.packet()["ticket"], [6,21])
            sock.getsockopt.return_value = 0
            with self.assertRaises(ValueError):
                role.check_pi(sock, self.packet()["ticket"], [6,22])
            sock.getsockname.return_value = "/proc/self/fd/17/control.sock"
            with self.assertRaises(ValueError):
                role.check_pi(sock, self.packet()["ticket"], [6,21])

    def test_manager_requires_service_listener_its_original_parent_and_named_node(self):
        import socket, stat
        from types import SimpleNamespace
        ticket = self.packet()["ticket"]
        addr = "/proc/self/fd/17/service.sock"
        listener, pi = mock.Mock(), mock.Mock()
        listener.getsockname.return_value = pi.getsockname.return_value = addr
        def options(listening):
            return lambda _,opt: {role.channel._DOMAIN:socket.AF_UNIX,socket.SO_TYPE:socket.SOCK_STREAM,
                                  socket.SO_ACCEPTCONN:int(listening)}[opt]
        listener.getsockopt.side_effect, pi.getsockopt.side_effect = options(True), options(False)
        parent = SimpleNamespace(st_dev=2,st_ino=44,st_mode=stat.S_IFDIR|0o710,st_uid=0,st_gid=61113,st_nlink=2)
        node = SimpleNamespace(st_dev=2,st_ino=108,st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=61113,st_nlink=1)
        def info(name, **k):
            return parent if str(name).endswith("/tasks") else node
        with mock.patch.object(role.os,"fstat",return_value=parent), mock.patch.object(role.os,"stat",side_effect=info) as named:
            role.check_service_listener(pi,listener,ticket)
            pi.getsockname.return_value = "/proc/self/fd/17/control.sock"
            with self.assertRaises(ValueError): role.check_service_listener(pi,listener,ticket)
            pi.getsockname.return_value = addr
            listener.getsockopt.side_effect = options(False)
            with self.assertRaises(ValueError): role.check_service_listener(pi,listener,ticket)
            listener.getsockopt.side_effect = options(True)
            named.side_effect = lambda name,**k: SimpleNamespace(**(vars(parent)|{"st_ino":45})) if str(name).endswith("/tasks") else node
            with self.assertRaises(ValueError): role.check_service_listener(pi,listener,ticket)

    def test_service_demands_fresh_mode_readback_from_private_owner_not_previous_reply(self):
        p = self.packet()
        nonce, stale = "b"*64, "c"*64
        owner = tuple(p["ticket"]["manager_peer"])
        original = dict(installed_service_pin=canonical_digest(p["nomination"]["service_code"]),
            service_show="raw service\n", sensor_show="raw sensor\n", clock=p["ticket"]["clock"])
        with mock.patch.object(role.secrets,"token_hex",return_value=nonce), mock.patch.object(role,"_send") as send, \
                mock.patch.object(role,"_recv") as recv, mock.patch.object(role.mode,"bound_environment") as bind:
            reply = role._packet("OBSERVED",stale,p["ticket_pin"],observation=original)
            recv.return_value = (reply,())
            with self.assertRaises(ValueError):
                role._observed("owner",owner,p,1.)
            bind.assert_not_called()
            reply["nonce"] = nonce
            bind.return_value = p["nomination_pin"]
            self.assertEqual(role._observed("owner",owner,p,1.),p["nomination_pin"])
            self.assertEqual(send.call_args.args[1],role._packet("OBSERVE",nonce,p["ticket_pin"]))
            self.assertEqual(bind.call_args.kwargs, {**original,"nomination":p["nomination"],"nomination_pin":p["nomination_pin"],
                "service_show":b"raw service\n","sensor_show":b"raw sensor\n"})

    def test_entry_runs_fixed_task_only_after_matching_private_readback_and_waits_for_retirement(self):
        # Only transports, process identities and deadlines/guest queries are simulated;
        # run, serve_one, baseline binding and the fixed calculation are the production path.
        import socket
        from test_pi_core_task_guest_binding import TaskGuestBindingTests
        f = TaskGuestBindingTests()
        f.setUp()
        for wrong_mode in (False, True):
            with self.subTest(substitution=wrong_mode), ExitStack() as s:
                p = self.packet()
                t, n = p["ticket"], p["nomination"]
                desc = role.task.original.describe_tasks(Path(role.task.reference.__file__).read_bytes())["BENIGN_JSON_SUM"]
                t["request"].update(task_digest=canonical_digest(desc),input_digest=desc["input"]["digest"])
                n["request_digest"] = canonical_digest(t["request"])
                t["environment_digest"] = p["nomination_pin"] = canonical_digest(n)
                p["ticket_pin"] = canonical_digest(t)
                if wrong_mode:
                    sensor = f.active(f.sensor,15,"b"*32)
                else:
                    sensor = f.absent()
                fields = dict(clock=t["clock"],installed_service_pin=canonical_digest(n["service_code"]),
                    sensor_show=f.encode(sensor).decode(),service_show=f.encode(f.active(f.task,13,"a"*32)).decode())
                sent, returns = [], []
                pi = mock.Mock(family=socket.AF_UNIX,type=socket.SOCK_STREAM)
                pi.getsockname.return_value = "/proc/self/fd/17/service.sock"
                fd = s.enter_context(open(os.devnull,"rb")).fileno()
                pi.fileno.return_value = fd
                pi.getsockopt.side_effect = lambda _level, opt: {role.channel._DOMAIN:socket.AF_UNIX,
                    socket.SO_TYPE:socket.SOCK_STREAM, socket.SO_ACCEPTCONN:0}[opt]
                def receive(_control, owner, _deadline, **kw):
                    self.assertEqual(owner,(12,0,0))
                    q = sent[-1]
                    key = q["kind"]
                    if key == "HELLO":
                        return role._packet("RELEASE",q["nonce"],p["ticket_pin"],
                            release=p,pi_inode=role._fd_id(fd)), (os.dup(fd),)
                    if key == "OBSERVE":
                        return role._packet("OBSERVED",q["nonce"],p["ticket_pin"],observation=fields), ()
                    self.assertEqual(key,"RETIRE_READY")
                    self.assertEqual(returns, ["witness", pi])
                    return role._packet("RETIRE",q["nonce"],p["ticket_pin"]), ()
                def sub(obj, name, **kw):
                    return s.enter_context(mock.patch.object(obj,name,**kw))
                sub(role.protected,"_flags")
                sub(role,"_local",return_value=(13,61112,61112))
                sub(role.os,"getresuid",create=True,return_value=(61112,)*3)
                sub(role.os,"getresgid",create=True,return_value=(61112,)*3)
                sub(role.os,"getgroups",return_value=[])
                sub(role.os,"kill")
                sub(role,"_wrapper_pin",return_value=n["service_code"]["wrapper_digest"])
                sub(role.protected,"_connect",side_effect=lambda path,*a,**kw:nullcontext("witness" if path.name=="witness.sock" else "hand"))
                sub(role.socket,"fromfd",return_value=nullcontext(pi))
                sub(role.wire,"_peer_credentials",side_effect=lambda sock:t["pi_peer"] if sock is pi else t["manager_peer"])
                sub(role,"_send",side_effect=lambda _control,doc,*a:sent.append(doc))
                sub(role,"_recv",side_effect=receive)
                sub(role.task,"_edge",side_effect=lambda *a:nullcontext(lambda:None))
                sub(role.task,"_read",return_value=role.task._call(t,p["ticket_pin"]))
                sub(role.task,"_write",side_effect=lambda sock,*a:returns.append(sock))
                work = sub(role.task.reference,"execute_reference_task",wraps=role.task.reference.execute_reference_task)
                if wrong_mode:
                    with self.assertRaises(ValueError):
                        role.run(loader=mock.Mock(),deadline=monotonic()+10)
                    work.assert_not_called()
                    self.assertFalse(returns)
                else:
                    role.run(loader=mock.Mock(),deadline=monotonic()+10)
                    work.assert_called_once()
                    self.assertEqual(sent[-1]["kind"],"RETIRE_READY")
