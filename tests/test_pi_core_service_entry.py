"""New wrapper checks with an inert filesystem/socket/process table only.

Real strict codecs, configuration construction and wrapper lifecycle run against
mocked kernel edges. No wrapper process, listener, service or provider is run.
"""

from contextlib import ExitStack
import ast
import copy
import io
import linecache
import os
from pathlib import Path, PurePosixPath
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_service_entry as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_runtime_capability_grant as fixtures

_WRAPPER_SOURCES = {role: (Path(__file__).absolute().parents[1] / "packaging" / "pi-core" / "services" /
                          (role + ".py")).read_text(encoding="utf-8") for role in subject.ROLES}


def info(inode, mode, uid=0, gid=0, size=0):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=uid, st_gid=gid,
        st_nlink=1, st_size=size, st_mtime_ns=1, st_ctime_ns=1)


def attribute_name(node):
    """Inspect an AST path directly; do not lazy-import the source unparser."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join([node.id, *reversed(parts)])


class InertSocket:
    def __init__(self, owner, kind, peer=None):
        self.owner, self.kind, self.peer = owner, kind, peer
        self.fd = 2000 + len(owner.sockets)
        self.closed = False
        self.timeout = None
        owner.sockets.append(self)

    def fileno(self): return self.fd
    def settimeout(self, value): self.timeout = value
    def set_inheritable(self, value): self.owner.events.append(("inheritable", value))
    def connect(self, path):
        resolved = self.owner.path(path)
        self.owner.events.append(("connect", resolved))
        if self.owner.fail_connect:
            raise OSError("sensitive connection diagnostic")
        self.owner.assertIn(resolved, self.owner.files)
        self.peer = (9000, 0, 0) if resolved.endswith("supervisor.sock") else (8001, 1201, 1301)
    def bind(self, path):
        path = self.owner.path(path)
        self.owner.events.append(("bind", path))
        self.owner.assertNotIn(path, self.owner.files)
        self.owner.files[path] = info(888, stat.S_IFSOCK | 0o755, 1201, 1301)
    def listen(self, count): self.owner.events.append(("listen", count))
    def accept(self):
        self.owner.events.append(("accept",))
        if self.owner.fail_accept:
            raise TimeoutError("inert accept deadline")
        return InertSocket(self.owner, socket.SOCK_STREAM, self.owner.sensor_peer), None
    def close(self):
        self.owner.events.append(("socket_close", self.fd))
        self.owner.assertFalse(self.closed, "no close retry")
        self.closed = True
        if self.fd in self.owner.fail_socket_close:
            raise OSError("inert socket cleanup uncertainty")


class PiServiceEntryTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(linecache, "getlines", return_value=[]))
        self.stack.enter_context(mock.patch.object(linecache, "checkcache", return_value=None))
        for owner, name in ((socket, "socket"), (socket, "socketpair"), (socket, "create_connection"),
                            (socket, "getaddrinfo"), (subprocess, "run"), (subprocess, "Popen"), (os, "system")):
            self.stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError("live operation forbidden")))
        for name in ("open", "close", "read", "write", "stat", "lstat", "fstat", "scandir", "readlink", "unlink",
                     "mkdir", "chmod", "chown", "fsync"):
            self.stack.enter_context(mock.patch.object(os, name, side_effect=AssertionError("unmocked file operation")))
        self.stack.enter_context(mock.patch.object(socket, "SOCK_CLOEXEC", 0x80000, create=True))
        # Scope the simulated interpreter to the module under test. Replacing
        # the real sys.flags with Mock turns numeric flags into child mocks and
        # breaks importlib and traceback reporting before cleanup can run.
        self.flags = SimpleNamespace(isolated=1, no_site=1)
        self.stack.enter_context(mock.patch.object(subject, "sys", SimpleNamespace(
            platform="linux", flags=self.flags, dont_write_bytecode=True,
            argv=list(sys.argv), stderr=sys.stderr)))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.clock = self.stack.enter_context(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.stack.enter_context(mock.patch.object(subject.time, "monotonic_ns", side_effect=lambda: int(self.clock.return_value * 1e9)))
        self.stack.enter_context(mock.patch.object(subject.time, "time", return_value=102.0))
        self.stack.enter_context(mock.patch.object(os, "getpid", return_value=8000))
        self.uid = self.stack.enter_context(mock.patch.object(os, "getuid", return_value=1201))
        self.euid = self.stack.enter_context(mock.patch.object(os, "geteuid", return_value=1201))
        self.gid = self.stack.enter_context(mock.patch.object(os, "getgid", return_value=1301))
        self.egid = self.stack.enter_context(mock.patch.object(os, "getegid", return_value=1301))
        self.resuid = self.stack.enter_context(mock.patch.object(os, "getresuid", create=True,
            side_effect=lambda: (self.uid.return_value,) * 3))
        self.resgid = self.stack.enter_context(mock.patch.object(os, "getresgid", create=True,
            side_effect=lambda: (self.gid.return_value,) * 3))
        self.groups = self.stack.enter_context(mock.patch.object(os, "getgroups", return_value=[]))
        self.ids = {name: {"uid": 1201 + index, "gid": 1301 + index}
                    for index, name in enumerate(("action", "sensor", "provider", "worker"))}
        self.events, self.sockets = [], []
        self.fail_connect = self.fail_accept = False
        self.fail_socket_close, self.fail_fd_close = set(), set()
        self.sensor_peer = (8002, 1202, 1302)
        self.files, self.bytes, self.fds, self.offsets = {}, {}, {}, {}
        self.next_fd = 100
        paths = ["/", "/etc", "/etc/aragorn", "/run", "/run/aragorn-pi-services",
                 "/run/aragorn-pi-services/action", "/run/aragorn-pi-services/sensor",
                 "/run/aragorn-pi-services/provider", "/run/aragorn-pi-action"]
        for inode, path in enumerate(paths, 1):
            self.files[path] = info(inode, stat.S_IFDIR | 0o755)
        self.files[str(subject.ACTION_DIRECTORY)] = info(9, stat.S_IFDIR | 0o750, 1201, 1301)
        for role in subject.ROLES:
            self.files[str(subject.CHANNEL_ROOT / role / "supervisor.sock")] = info(
                20 + self.ids[role]["uid"], stat.S_IFSOCK | 0o660, 0, self.ids[role]["gid"])
        self.stack.enter_context(mock.patch.object(os, "open", side_effect=self.open))
        self.close_fd = self.stack.enter_context(mock.patch.object(os, "close", side_effect=self.close))
        self.read_fd = self.stack.enter_context(mock.patch.object(os, "read", side_effect=self.read))
        self.stat = self.stack.enter_context(mock.patch.object(os, "stat", side_effect=self.stat_path))
        self.stack.enter_context(mock.patch.object(os, "fstat", side_effect=lambda fd: copy.copy(self.files[self.fds[fd]])))
        self.unlink = self.stack.enter_context(mock.patch.object(os, "unlink", side_effect=self.remove))
        self.chmod = self.stack.enter_context(mock.patch.object(os, "chmod", side_effect=self.change_mode))
        self.sync = self.stack.enter_context(mock.patch.object(os, "fsync", side_effect=lambda fd: self.events.append(("sync", fd))))
        self.socket = self.stack.enter_context(mock.patch.object(socket, "socket",
            side_effect=lambda domain, kind: InertSocket(self, kind)))
        self.stack.enter_context(mock.patch.object(os, "supports_dir_fd", {os.link, os.open, os.stat, os.unlink}))
        self.stack.enter_context(mock.patch.object(os, "supports_follow_symlinks", {os.link}))
        self.stack.enter_context(mock.patch.object(subject.broker, "_peer_credentials", side_effect=lambda connection: connection.peer))
        self.guard = self.stack.enter_context(mock.patch.object(subject.channel, "guard_channel",
            side_effect=lambda connection, peer, deadline: self.peer_fd(peer[0])))
        self.stack.enter_context(mock.patch.object(subject.process, "open_peer_pidfd",
            side_effect=lambda connection, pid: self.peer_fd(pid)))
        self.stack.enter_context(mock.patch.object(subject.channel, "require_peer_live"))
        self.cgroup = self.stack.enter_context(mock.patch.object(subject.process, "_read_virtual_file",
            return_value=b"0::/system.slice/aragorn-pi-action.service\n"))
        self.security = self.stack.enter_context(mock.patch.object(subject.process, "_require_process_status"))
        self.provider_profile = self.stack.enter_context(mock.patch.object(subject.provider_transport, "read_profile",
            return_value={"service_uid": 1203, "service_gid": 1303}))
        self.provider_identity = self.stack.enter_context(mock.patch.object(subject.provider_transport, "_identity"))
        self.action = self.stack.enter_context(mock.patch.object(subject.action, "handle_pi_broker_request",
            side_effect=self.handler))
        self.sensor = self.stack.enter_context(mock.patch.object(subject.sensor, "run_pi_sensor_request",
            side_effect=self.handler))
        self.provider = self.stack.enter_context(mock.patch.object(subject.provider, "handle_pi_provider_service",
            side_effect=self.handler))
        self.stack.enter_context(mock.patch.object(subject.action, "initialize_pi_broker_request_service",
            side_effect=AssertionError("request wrapper must not initialize a grant")))
        self.stack.enter_context(mock.patch.object(subject.broker_v4, "initialize_runtime_capability_grant",
            side_effect=AssertionError("legacy grant initialization forbidden")))
        self.stack.enter_context(mock.patch.object(subject.broker_v5, "serve_runtime_action_broker_v5",
            side_effect=AssertionError("legacy service loop forbidden")))
        self.stack.enter_context(mock.patch.object(subject.observation_v4, "serve_runtime_action_observation_publisher_v4",
            side_effect=AssertionError("legacy sensor loop forbidden")))
        self.configure("action")

    def path(self, path, dir_fd=None):
        text = str(path)
        if text.startswith("/proc/self/fd/"):
            fd, leaf = text[len("/proc/self/fd/"):].split("/", 1)
            return str(PurePosixPath(self.fds[int(fd)]) / leaf)
        return str(PurePosixPath(self.fds[dir_fd]) / text) if dir_fd is not None else text

    def stat_path(self, path, *, dir_fd=None, follow_symlinks=False):
        self.assertFalse(follow_symlinks)
        path = self.path(path, dir_fd)
        if path not in self.files: raise FileNotFoundError(path)
        return copy.copy(self.files[path])

    def open(self, path, flags, *, dir_fd=None):
        path = self.path(path, dir_fd)
        if path not in self.files: raise FileNotFoundError(path)
        self.assertTrue(flags & os.O_NOFOLLOW)
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.fds[fd], self.offsets[fd] = path, 0
        return fd

    def close(self, fd):
        self.events.append(("fd_close", fd))
        self.assertIn(fd, self.fds)
        del self.fds[fd]
        if fd in self.fail_fd_close: raise OSError("inert handle uncertainty")

    def peer_fd(self, pid):
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.fds[fd] = "peer:" + str(pid)
        return fd

    def read(self, fd, maximum):
        raw, offset = self.bytes[self.fds[fd]], self.offsets[fd]
        result = raw[offset:offset + maximum]
        self.offsets[fd] += len(result)
        return result

    def remove(self, path, *, dir_fd):
        path = self.path(path, dir_fd)
        self.events.append(("unlink", path))
        del self.files[path]

    def change_mode(self, path, mode, *, dir_fd, follow_symlinks):
        self.assertFalse(follow_symlinks)
        node = self.files[self.path(path, dir_fd)]
        node.st_mode = stat.S_IFMT(node.st_mode) | mode
        node.st_ctime_ns += 1

    def handler(self, *args, **kwargs):
        self.events.append(("handler",))
        self.assertEqual(kwargs["expected_supervisor_pid"], 9000)
        self.assertLess(kwargs["deadline"], 105.0)
        return {"status": "COMPLETED"}

    def document(self, role):
        value = {"schema": subject.SCHEMA, "role": role, "identities": copy.deepcopy(self.ids)}
        if role == "action":
            grant = fixtures._grant()
            value.update(capability_grant=grant, runtime_binding={
                "schema": "aragorn/runtime-action-runtime-binding/v2", "runtime_digest": grant["runtime_digest"],
                "runtime_profile_digest": grant["runtime_profile_digest"]})
        elif role == "sensor":
            profile = {"schema": subject.process.PROFILE_SCHEMA, "authority": subject.process.PROFILE_AUTHORITY,
                "runtime_digest": "sha256:" + "4" * 64, "executable_digest": "sha256:" + "b" * 64,
                "cgroup": "/system.slice/aragorn-pi-worker.service", "skill_path": "/var/lib/aragorn/admitted/versions/example/SKILL.md"}
            grant = fixtures._grant(runtime_profile_digest=canonical_digest(profile))
            value.update(capability_grant=grant, observation_binding={
                "schema": "aragorn/runtime-observation-binding/v2", "sensor_digest": grant["sensor_digest"],
                "runtime_profile": profile})
        return value

    def configure(self, role):
        self.value = self.document(role)
        path = str(subject.CONFIG_ROOT / ("pi-" + role + "-service.json"))
        raw = canonical_json(self.value)
        self.files[path] = info(99, stat.S_IFREG | 0o444, size=len(raw))
        self.bytes[path] = raw
        own = self.ids[role]
        self.uid.return_value = self.euid.return_value = own["uid"]
        self.gid.return_value = self.egid.return_value = own["gid"]
        self.groups.return_value = [1301] if role == "sensor" else []
        self.cgroup.return_value = ("0::/system.slice/aragorn-pi-" + role + ".service\n").encode()
        if role == "sensor":
            self.files[str(subject.ACTION_SOCKET)] = info(888, stat.S_IFSOCK | 0o660, 1201, 1301)

    def run_role(self, role="action"):
        return subject.run(role, ["9000", "105000000000"])

    def test_action_dispatches_one_existing_handler_and_cleans_owned_listener(self):
        self.assertEqual(self.run_role(), {"status": "COMPLETED"})
        self.action.assert_called_once()
        self.assertNotIn(str(subject.ACTION_SOCKET), self.files)
        self.assertEqual([event for event in self.events if event[0] == "listen"], [("listen", 1)])
        self.assertFalse(self.fds)
        self.assertTrue(all(item.closed for item in self.sockets))
        config = self.action.call_args.args[2]
        self.assertEqual(config.protected_install_root, subject.ADMITTED_ROOT)
        self.assertEqual(config.broker.broker.broker.expected_runtime_gid, 1304)

    def test_sensor_dispatches_real_adoption_wrapper_with_direct_stream(self):
        self.configure("sensor")
        self.run_role("sensor")
        self.sensor.assert_called_once()
        self.assertEqual([event[1] for event in self.events if event[0] == "connect"],
            ["/run/aragorn-pi-services/sensor/supervisor.sock", str(subject.ACTION_SOCKET)])
        config = self.sensor.call_args.args[2]
        self.assertEqual(config.publisher.expected_broker_gid, 1301)
        self.assertEqual(config.publisher.expected_runtime_gid, 1304)
        self.assertFalse(self.fds)

    def test_provider_dispatches_exact_handler_without_reading_credentials(self):
        self.configure("provider")
        self.run_role("provider")
        self.provider.assert_called_once()
        self.provider_identity.assert_called_once()
        self.assertFalse(self.fds)
        self.assertEqual(len(self.sockets), 1)

    def test_fixed_wrapper_ast_checks_environment_before_source_import(self):
        self.assertIsNot(subject.sys, sys)
        self.assertIsInstance(sys.flags.verbose, int)
        for role, raw in _WRAPPER_SOURCES.items():
            tree = ast.parse(raw)
            imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
            self.assertEqual([(node.module, [alias.name for alias in node.names]) for node in imports],
                             [("aragorn.pi_core_service_entry", ["main"])])
            calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and
                     isinstance(node.func, ast.Name) and node.func.id == "main"]
            self.assertEqual(len(calls), 1)
            self.assertEqual(ast.literal_eval(calls[0].args[0]), role)
            source_import = imports[0].lineno
            early_guards = [node for node in ast.walk(tree) if isinstance(node, ast.If) and node.lineno < source_import]
            self.assertTrue(any(any(attribute_name(part) == "sys.flags.isolated" for part in ast.walk(node.test))
                                for node in early_guards))
            self.assertTrue(any(any(attribute_name(part) == "os.environ" for part in ast.walk(node.test)) and
                                any(isinstance(part, ast.Constant) and part.value == "openssl_"
                                    for part in ast.walk(node.test)) for node in early_guards))
            self.assertIn('sys.path.insert(0, "/opt/aragorn/src")', raw)
            denied = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign) and
                          any(isinstance(target, ast.Name) and target.id == "denied" for target in node.targets))
            self.assertEqual(ast.literal_eval(denied), subject._DENIED_ENVIRONMENT)

    def test_ambient_loader_proxy_ca_and_provider_overrides_refuse_before_io(self):
        for name in ("OPENSSL_CONF", "OPENSSL_MODULES", "OPENSSL_ENGINES", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES",
                     "HTTPS_PROXY", "SSL_CERT_FILE", "OPENAI_API_KEY", "PYTHONPATH", "GLIBC_TUNABLES"):
            with mock.patch.dict(os.environ, {name: "inert-denied"}), self.assertRaises(subject.PiServiceEntryError):
                self.run_role()
        self.socket.assert_not_called()

    def test_action_and_provider_require_capability_free_no_new_privs_profile(self):
        subject._identity(self.value)
        self.security.assert_called_once_with(8000, 1201, 1301)
        self.security.side_effect = RuntimeError("inert retained capability")
        with self.assertRaises(Exception): self.run_role()
        self.socket.assert_not_called()

    def test_sensor_does_not_incorrectly_require_zero_setup_capabilities(self):
        self.configure("sensor")
        subject._identity(self.value)
        self.security.assert_not_called()

    def test_sensor_can_complete_after_peer_removes_its_owned_listener(self):
        self.configure("sensor")
        def removed(*args, **kwargs):
            del self.files[str(subject.ACTION_SOCKET)]
            return self.handler(*args, **kwargs)
        self.sensor.side_effect = removed
        self.assertEqual(self.run_role("sensor"), {"status": "COMPLETED"})
        self.assertFalse(self.fds)

    def test_deadline_integer_conversion_never_extends_authority(self):
        pid, deadline = subject._arguments(["9000", "105000000001"])
        self.assertEqual(pid, 9000)
        self.assertLessEqual(deadline * 1e9, 105000000001)

    def test_arguments_reject_extra_paths_and_invalid_numbers(self):
        for args in (["9000", "105000000000", "/etc/override"], ["09000", "105000000000"],
                     ["8000", "105000000000"], ["0", "105000000000"], ["9000", "131000000000"],
                     ["9000", "100000000000"], [9000, "105000000000"], ["9000", "1e12"]):
            with self.subTest(args=args), self.assertRaises(Exception): subject._arguments(args)

    def test_missing_isolation_flags_refuses_before_io(self):
        for field in ("isolated", "no_site"):
            setattr(self.flags, field, 0)
            with self.assertRaises(subject.PiServiceEntryError): self.run_role()
            setattr(self.flags, field, 1)
        self.assertFalse(self.fds)
        self.socket.assert_not_called()

    def test_nonlinux_refuses_before_io(self):
        with mock.patch.object(subject.sys, "platform", "darwin"), self.assertRaises(subject.PiServiceEntryError): self.run_role()
        self.socket.assert_not_called()

    def test_config_rejects_unknown_fields_and_wrong_role(self):
        for patch in ({"endpoint": "/tmp/override"}, {"role": "sensor"}, {"schema": "wrong"}):
            value = {**self.value, **patch}
            with self.assertRaises(subject.PiServiceEntryError): subject.validate_configuration(value, "action")

    def test_provider_config_cannot_carry_credentials_or_grants(self):
        value = self.document("provider")
        value["api_key"] = "not-a-real-key"
        with self.assertRaises(subject.PiServiceEntryError): subject.validate_configuration(value, "provider")

    def test_config_requires_four_distinct_positive_numeric_roles(self):
        for field, replacement in (("uid", 0), ("uid", True), ("gid", 2**31), ("gid", 1301)):
            value = copy.deepcopy(self.value)
            value["identities"]["worker"][field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(subject.PiServiceEntryError):
                subject.validate_configuration(value, "action")

    def test_runtime_binding_must_match_real_grant(self):
        self.value["runtime_binding"]["runtime_digest"] = "sha256:" + "f" * 64
        with self.assertRaises(subject.PiServiceEntryError): subject.validate_configuration(self.value, "action")

    def test_observation_profile_must_match_grant_and_admitted_path(self):
        value = self.document("sensor")
        value["observation_binding"]["runtime_profile"]["skill_path"] = "/tmp/SKILL.md"
        value["capability_grant"]["runtime_profile_digest"] = canonical_digest(value["observation_binding"]["runtime_profile"])
        with self.assertRaises(subject.PiServiceEntryError): subject.validate_configuration(value, "sensor")

    def test_configuration_requires_exact_root_owned_readonly_regular_file(self):
        path = str(subject.CONFIG_ROOT / "pi-action-service.json")
        original = copy.copy(self.files[path])
        for field, replacement in (("st_uid", 1201), ("st_gid", 1301), ("st_mode", stat.S_IFREG | 0o644),
                                   ("st_mode", stat.S_IFLNK | 0o444), ("st_nlink", 2), ("st_size", subject.MAX_CONFIG + 1)):
            self.files[path] = copy.copy(original)
            setattr(self.files[path], field, replacement)
            with self.subTest(field=field, replacement=replacement), self.assertRaises(Exception):
                subject.read_configuration("action", 105.0)
            self.assertFalse(self.fds)

    def test_configuration_rejects_duplicate_or_noncanonical_json(self):
        path = str(subject.CONFIG_ROOT / "pi-action-service.json")
        self.bytes[path] = b'{"schema":"one","schema":"two"}'
        self.files[path].st_size = len(self.bytes[path])
        with self.assertRaises(Exception): subject.read_configuration("action", 105.0)
        self.assertFalse(self.fds)

    def test_configuration_growth_refuses_and_closes_once(self):
        path = str(subject.CONFIG_ROOT / "pi-action-service.json")
        self.files[path].st_size -= 1
        with self.assertRaises(Exception): subject.read_configuration("action", 105.0)
        self.assertFalse(self.fds)

    def test_parent_symlink_or_writable_ancestry_refuses(self):
        for mode in (stat.S_IFLNK | 0o755, stat.S_IFDIR | 0o777):
            self.files["/etc"].st_mode = mode
            with self.assertRaises(Exception): subject.read_configuration("action", 105.0)
            self.assertFalse(self.fds)

    def test_parent_named_identity_change_refuses(self):
        original = self.stat_path
        def changed(path, **kwargs):
            observed = original(path, **kwargs)
            if self.path(path, kwargs.get("dir_fd")) == "/etc": observed.st_ino += 1
            return observed
        self.stat.side_effect = changed
        with self.assertRaises(Exception): subject.read_configuration("action", 105.0)
        self.assertFalse(self.fds)

    def test_expired_config_read_stops_before_socket_creation(self):
        original = self.read
        def expires(fd, size):
            self.clock.return_value = 105.0
            return original(fd, size)
        self.read_fd.side_effect = expires
        with self.assertRaises(Exception): self.run_role()
        self.socket.assert_not_called()
        self.assertFalse(self.fds)

    def test_uid_gid_and_cgroup_must_match_protected_role(self):
        for field, bad in ((self.euid, 0), (self.gid, 1304), (self.cgroup, b"0::/unrelated.service\n")):
            before = field.return_value
            field.return_value = bad
            with self.assertRaises(subject.PiServiceEntryError): subject._identity(self.value)
            field.return_value = before

    def test_action_extra_supplementary_group_refused(self):
        self.groups.return_value = [0]
        with self.assertRaises(subject.PiServiceEntryError): self.run_role()
        self.socket.assert_not_called()

    def test_saved_root_identity_refused_before_channel_acquisition(self):
        for selected, value in ((self.resuid, (1201, 1201, 0)), (self.resgid, (1301, 1301, 0))):
            original = selected.side_effect
            selected.side_effect = None
            selected.return_value = value
            with self.assertRaises(subject.PiServiceEntryError): self.run_role()
            selected.side_effect = original
        self.socket.assert_not_called()

    def test_config_reader_uses_nonblocking_open_before_type_recheck(self):
        original = self.open
        observed = []
        def record(path, flags, **kwargs):
            if str(path).endswith(".json"): observed.append(flags)
            return original(path, flags, **kwargs)
        with mock.patch.object(os, "open", side_effect=record):
            subject.read_configuration("action", 105.0)
        self.assertEqual(len(observed), 1)
        self.assertTrue(observed[0] & os.O_NONBLOCK)

    def test_sensor_requires_only_broker_supplementary_group(self):
        self.configure("sensor")
        for groups in ([], [1301, 0], [1304]):
            self.groups.return_value = groups
            with self.assertRaises(subject.PiServiceEntryError): subject._identity(self.value)
        self.groups.return_value = [1301, 1302]
        subject._identity(self.value)

    def test_provider_public_profile_must_match_service_role(self):
        self.configure("provider")
        self.provider_profile.return_value["service_uid"] = 1204
        with self.assertRaises(subject.PiServiceEntryError): self.run_role("provider")
        self.socket.assert_not_called()

    def test_root_endpoint_requires_protected_owner_group_and_mode(self):
        path = str(subject.CHANNEL_ROOT / "action" / "supervisor.sock")
        self.files[path].st_uid = 1201
        with self.assertRaises(Exception): self.run_role()
        self.socket.assert_not_called()

    def test_root_endpoint_inode_replacement_before_authentication_refused(self):
        original = InertSocket.connect
        def replaces(connection, path):
            original(connection, path)
            self.files[self.path(path)].st_ino += 1
        with mock.patch.object(InertSocket, "connect", replaces), self.assertRaises(Exception): self.run_role()
        self.guard.assert_not_called()
        self.assertTrue(all(item.closed for item in self.sockets))

    def test_root_created_socketpair_peer_identity_is_refused(self):
        original = InertSocket.connect
        def wrong(connection, path):
            original(connection, path)
            connection.peer = (1, 0, 0)
        with mock.patch.object(InertSocket, "connect", wrong), self.assertRaises(Exception): self.run_role()
        self.guard.assert_not_called()

    def test_connect_failure_never_retries(self):
        self.fail_connect = True
        with self.assertRaises(Exception): self.run_role()
        self.assertEqual(len([event for event in self.events if event[0] == "connect"]), 1)
        self.action.assert_not_called()
        self.assertFalse(self.fds)

    def test_existing_listener_is_never_unlinked_or_replaced(self):
        self.files[str(subject.ACTION_SOCKET)] = info(889, stat.S_IFSOCK | 0o660, 1201, 1301)
        with self.assertRaises(Exception): self.run_role()
        self.unlink.assert_not_called()
        self.assertEqual(self.files[str(subject.ACTION_SOCKET)].st_ino, 889)

    def test_listener_requires_exact_action_owned_parent(self):
        self.files[str(subject.ACTION_DIRECTORY)].st_mode = stat.S_IFDIR | 0o755
        with self.assertRaises(Exception): self.run_role()
        self.assertFalse(any(event[0] == "bind" for event in self.events))

    def test_accept_failure_closes_and_removes_only_owned_endpoint(self):
        self.fail_accept = True
        with self.assertRaises(Exception): self.run_role()
        self.assertNotIn(str(subject.ACTION_SOCKET), self.files)
        self.assertEqual(len([event for event in self.events if event[0] == "accept"]), 1)
        self.action.assert_not_called()

    def test_wrong_sensor_credentials_refuse_before_handler(self):
        self.sensor_peer = (8002, 1204, 1304)
        with self.assertRaises(Exception): self.run_role()
        self.action.assert_not_called()
        self.assertNotIn(str(subject.ACTION_SOCKET), self.files)

    def test_listener_inode_changed_during_chmod_is_retained(self):
        original = self.change_mode
        def changes(path, mode, **kwargs):
            original(path, mode, **kwargs)
            self.files[self.path(path, kwargs["dir_fd"])].st_ino += 1
        self.chmod.side_effect = changes
        with self.assertRaises(Exception): self.run_role()
        self.unlink.assert_not_called()
        self.action.assert_not_called()

    def test_replaced_listener_after_handler_is_retained_and_success_refused(self):
        def replaced(*args, **kwargs):
            self.files[str(subject.ACTION_SOCKET)].st_ino += 1
            return self.handler(*args, **kwargs)
        self.action.side_effect = replaced
        with self.assertRaises(Exception): self.run_role()
        self.unlink.assert_not_called()
        self.assertIn(str(subject.ACTION_SOCKET), self.files)

    def test_handler_failure_never_invokes_second_handler_or_retry(self):
        self.action.side_effect = RuntimeError("sensitive request text")
        with self.assertRaises(Exception): self.run_role()
        self.action.assert_called_once()
        self.sensor.assert_not_called()
        self.provider.assert_not_called()
        self.assertFalse(self.fds)

    def test_expiry_after_handler_retains_endpoint_cleanup_hold(self):
        def expires(*args, **kwargs):
            result = self.handler(*args, **kwargs)
            self.clock.return_value = 105.0
            return result
        self.action.side_effect = expires
        with self.assertRaises(Exception): self.run_role()
        self.assertIn(str(subject.ACTION_SOCKET), self.files)
        self.unlink.assert_not_called()
        self.assertFalse(self.fds)

    def test_socket_close_failure_attempts_all_other_owned_closes_once(self):
        self.fail_socket_close.add(2001)
        with self.assertRaises(Exception): self.run_role()
        self.assertTrue(all(item.closed for item in self.sockets))
        self.assertFalse(self.fds)
        closed = [event[1] for event in self.events if event[0] == "socket_close"]
        self.assertEqual(len(closed), len(set(closed)))

    def test_config_descriptor_close_failure_is_not_silently_successful(self):
        self.fail_fd_close.add(103)
        with self.assertRaises(Exception): self.run_role()
        self.socket.assert_not_called()
        self.assertFalse(self.fds)

    def test_main_redacts_failures_and_returns_nonzero(self):
        output = io.StringIO()
        with mock.patch.object(subject, "run", side_effect=RuntimeError("secret diagnostic")), mock.patch.object(subject.sys, "stderr", output):
            result = subject.main("provider", ["9000", "105000000000"])
        self.assertEqual(result, 126)
        self.assertEqual(output.getvalue(), "PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD\n")

    def test_main_success_requires_completed_owned_cleanup(self):
        self.assertEqual(subject.main("action", ["9000", "105000000000"]), 0)
        self.assertFalse(self.fds)
        self.assertNotIn(str(subject.ACTION_SOCKET), self.files)


if __name__ == "__main__":
    unittest.main()
