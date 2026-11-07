"""Fixed one-shot service callers, not a service manager or activation proof.

The lifecycle owner provisions the protected files/directories and root listeners
before executing one reviewed wrapper under its final nonroot identity. Channels
are connected after exec, never inherited root-created socketpairs. No grant is
initialized, service restarted, endpoint retried, or worker START enabled here.
"""

from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
from types import ModuleType

from . import pi_core_identity_handoff as channel
from . import pi_core_openai_transport as provider_transport
from . import pi_core_provider_service as provider
from . import pi_core_request_sensor as sensor
from . import pi_core_request_service as action
from . import runtime_action_broker as broker
from . import runtime_action_broker_v2 as broker_v2
from . import runtime_action_broker_v4 as broker_v4
from . import runtime_action_broker_v5 as broker_v5
from . import runtime_action_observation_publisher_v2 as observation_v2
from . import runtime_action_observation_publisher_v4 as observation_v4
from . import runtime_capability_grant as capability
from . import runtime_process_profile as process
from .oci_worker_protocol import canonical_digest, canonical_json

SCHEMA = "aragorn/pi-core-service-entry/v1"
ROLES = ("action", "sensor", "provider")
CONFIG_ROOT = Path("/etc/aragorn")
CHANNEL_ROOT = Path("/run/aragorn-pi-services")
ACTION_DIRECTORY = Path("/run/aragorn-pi-action")
ACTION_SOCKET = ACTION_DIRECTORY / "sensor.sock"
EFFECT_ROOT = Path("/var/lib/aragorn-runtime-action")
ADMITTED_ROOT = Path("/var/lib/aragorn/admitted")
MAX_CONFIG = 64 * 1024
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")
_DENIED_ENVIRONMENT = {"http_proxy", "https_proxy", "all_proxy", "no_proxy", "ssl_cert_file", "ssl_cert_dir",
    "requests_ca_bundle", "curl_ca_bundle", "node_extra_ca_certs", "pythonhttpsverify", "pythonpath", "pythonhome",
    "randfile", "glibc_tunables"}
SOURCE_STARTUP_SCHEMA = "aragorn/pi-core-service-source-startup/v1"
SOURCE_PACKET_LIMIT = 64 * 1024
_SOURCE_CHALLENGE_FIELDS = {"schema", "kind", "role", "nonce", "runtime_closure_digest",
                          "binding_digest", "source_inventory_digest"}


def _source_handshake(root, role, supervisor_pid, deadline, source_loader):
    """A trusted fixed wrapper reports only its successfully executed sources."""
    bootstrap = sys.modules.get("_aragorn_pi_service_source")
    _require(type(bootstrap) is ModuleType and
             type(source_loader) is getattr(bootstrap, "PiServiceSourceLoader", None))
    challenge, _ = channel.receive_authenticated_packet(root, (supervisor_pid, 0, 0), deadline,
        expected_rights=0, max_bytes=SOURCE_PACKET_LIMIT)
    _require(type(challenge) is dict and set(challenge) == _SOURCE_CHALLENGE_FIELDS and
             challenge["schema"] == SOURCE_STARTUP_SCHEMA and challenge["kind"] == "CHALLENGE" and
             challenge["role"] == role and type(challenge["nonce"]) is str and
             re.fullmatch(r"[0-9a-f]{64}", challenge["nonce"]) is not None and
             all(type(challenge[key]) is str and channel._DIGEST.fullmatch(challenge[key])
                 for key in ("runtime_closure_digest", "binding_digest", "source_inventory_digest")) and
             challenge["source_inventory_digest"] == canonical_digest(source_loader.source_digests))
    sources = source_loader.snapshot()
    _require(type(sources) is list and 0 < len(sources) <= 512)
    digest = canonical_digest(sources)
    base = {key: value for key, value in challenge.items() if key != "kind"}
    receipt = {**base, "kind": "CONSUMED", "sources": sources, "sources_digest": digest}
    channel.send_authenticated_packet(root, receipt, deadline, max_bytes=SOURCE_PACKET_LIMIT)
    accepted, _ = channel.receive_authenticated_packet(root, (supervisor_pid, 0, 0), deadline,
        expected_rights=0, max_bytes=SOURCE_PACKET_LIMIT)
    _require(accepted == {**base, "kind": "ACCEPTED", "sources_digest": digest})
    _require(source_loader.snapshot() == sources)
    _remaining(deadline)


class PiServiceEntryError(RuntimeError):
    """Finite redacted refusal, including uncertain endpoint/handle cleanup."""


def _require(value):
    if not value:
        raise PiServiceEntryError("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD")


def _remaining(deadline):
    channel.validate_deadline(deadline)
    return deadline - time.monotonic()


def _arguments(argv):
    _require(type(argv) is list and len(argv) == 2 and
             all(type(value) is str and _DECIMAL.fullmatch(value) for value in argv))
    pid, deadline_ns = map(int, argv)
    _require(0 < pid < 2**31 and pid != os.getpid() and 0 < deadline_ns < 2**63)
    # Never round an integer authorization deadline upward through float.
    deadline = math.nextafter(deadline_ns / 1_000_000_000, 0.0)
    _remaining(deadline)
    _require(time.monotonic_ns() < deadline_ns)
    return pid, deadline


def _flags():
    _require(sys.platform == "linux" and sys.flags.isolated == 1 and
             sys.flags.no_site == 1 and sys.dont_write_bytecode is True)
    _require(not any(key.lower() in _DENIED_ENVIRONMENT or
                     key.lower().startswith(("openssl_", "ld_", "dyld_", "openai_")) for key in os.environ))


class _Parent:
    def __init__(self, path, deadline, *, uid=0, gid=0, mode=None):
        self.path, self.deadline = path, deadline
        self.uid, self.gid, self.mode = uid, gid, mode
        self.fds, self.identities = [], []

    @property
    def fd(self):
        return self.fds[-1]

    def open(self):
        _require(type(self.path) is type(Path("/")) and self.path.is_absolute() and
                 ".." not in self.path.parts)
        self.fds.append(os.open("/", _DIRECTORY))
        for index, part in enumerate(self.path.parts):
            if index:
                self.fds.append(os.open(part, _DIRECTORY, dir_fd=self.fds[-1]))
            _remaining(self.deadline)
            info = os.fstat(self.fds[-1])
            final = index == len(self.path.parts) - 1
            uid, gid = (self.uid, self.gid) if final else (0, 0)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
                     not stat.S_IMODE(info.st_mode) & 0o022 and info.st_nlink >= 1)
            if final and self.mode is not None:
                _require(stat.S_IMODE(info.st_mode) == self.mode)
            self.identities.append(broker._directory_identity(info))
        self.guard()
        return self

    def guard(self):
        _remaining(self.deadline)
        _require(len(self.identities) == len(self.fds))
        for index, (fd, identity) in enumerate(zip(self.fds, self.identities)):
            _require(broker._directory_identity(os.fstat(fd)) == identity)
            named = os.stat("/", follow_symlinks=False) if index == 0 else os.stat(
                self.path.parts[index], dir_fd=self.fds[index - 1], follow_symlinks=False)
            _require(broker._directory_identity(named) == identity)
            _remaining(self.deadline)

    def close(self):
        pending, self.fds = list(reversed(self.fds)), []
        channel._close_installed(pending)


@contextmanager
def _parent(path, deadline, **identity):
    held = _Parent(path, deadline, **identity)
    try:
        yield held.open()
    finally:
        held.close()


def read_configuration(role, deadline):
    _require(role in ROLES)
    leaf = "pi-" + role + "-service.json"
    with _parent(CONFIG_ROOT, deadline) as parent:
        before = os.stat(leaf, dir_fd=parent.fd, follow_symlinks=False)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0 and
                 stat.S_IMODE(before.st_mode) == 0o444 and before.st_nlink == 1 and
                 0 < before.st_size <= MAX_CONFIG)
        descriptor = os.open(leaf, _FILE, dir_fd=parent.fd)
        try:
            _require(broker._file_identity(os.fstat(descriptor)) == broker._file_identity(before))
            chunks, size = [], 0
            while True:
                _remaining(deadline)
                chunk = os.read(descriptor, min(8192, MAX_CONFIG + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                _require(size <= before.st_size and size <= MAX_CONFIG)
            parent.guard()
            _require(size == before.st_size and broker._file_identity(os.fstat(descriptor)) ==
                     broker._file_identity(before) == broker._file_identity(
                         os.stat(leaf, dir_fd=parent.fd, follow_symlinks=False)))
            raw = b"".join(chunks)
        finally:
            os.close(descriptor)
    _remaining(deadline)
    return validate_configuration(broker._parse_canonical_document(raw, "Pi service configuration"), role)


def validate_configuration(value, role):
    """Strict protected data only: no import names, endpoints or path overrides."""
    extras = {"action": {"runtime_binding", "capability_grant"},
              "sensor": {"observation_binding", "capability_grant"}, "provider": set()}
    _require(role in ROLES and type(value) is dict and
             set(value) == {"schema", "role", "identities"} | extras[role] and
             value["schema"] == SCHEMA and value["role"] == role)
    identities = value["identities"]
    _require(type(identities) is dict and set(identities) == {*ROLES, "worker"})
    for identity in identities.values():
        _require(type(identity) is dict and set(identity) == {"uid", "gid"} and
                 all(type(item) is int and 0 < item < 2**31 for item in identity.values()))
    _require(all(len({identity[field] for identity in identities.values()}) == 4 for field in ("uid", "gid")))
    if role != "provider":
        raw = canonical_json(value["capability_grant"])
        grant = capability.parse_runtime_capability_grant(raw)
        if role == "action":
            binding = value["runtime_binding"]
            _require(type(binding) is dict and set(binding) == {"schema", "runtime_digest", "runtime_profile_digest"} and
                     binding["schema"] == "aragorn/runtime-action-runtime-binding/v2" and
                     binding["runtime_digest"] == grant["runtime_digest"] and
                     binding["runtime_profile_digest"] == grant["runtime_profile_digest"])
        else:
            binding = value["observation_binding"]
            _require(type(binding) is dict and set(binding) == {"schema", "sensor_digest", "runtime_profile"} and
                     binding["schema"] == "aragorn/runtime-observation-binding/v2")
            profile = process.runtime_process_profile(binding["runtime_profile"])
            _require(binding["sensor_digest"] == grant["sensor_digest"] and
                     profile.runtime_digest == grant["runtime_digest"] and profile.digest == grant["runtime_profile_digest"] and
                     profile.skill_path.is_relative_to(ADMITTED_ROOT / ".aragorn-versions"))
    return value


def _identity(value):
    role, identities = value["role"], value["identities"]
    own = identities[role]
    _require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
             (own["uid"], own["uid"], own["gid"], own["gid"]))
    _require(os.getresuid() == (own["uid"],) * 3 and os.getresgid() == (own["gid"],) * 3)
    groups = set(os.getgroups())
    if role == "sensor":
        _require(identities["action"]["gid"] in groups and
                 groups <= {own["gid"], identities["action"]["gid"]})
    else:
        _require(groups <= {own["gid"]})
        process._require_process_status(os.getpid(), own["uid"], own["gid"])
    _require(process._read_virtual_file(Path("/proc/self/cgroup"), 4096) ==
             ("0::/system.slice/aragorn-pi-" + role + ".service\n").encode("ascii"))


def _action_config(value):
    ids, binding = value["identities"], value["runtime_binding"]
    control = EFFECT_ROOT / "control"
    base = broker.RuntimeActionBrokerConfig(control / "broker.sock", control / "broker.instance.lock",
        control / "broker.lock", control, EFFECT_ROOT / "protected", EFFECT_ROOT / "staging",
        *(control / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
        ids["action"]["uid"], ids["sensor"]["uid"], ids["sensor"]["gid"], binding["runtime_digest"],
        ids["worker"]["uid"], ids["worker"]["gid"])
    profiled = broker_v2.RuntimeActionBrokerV2Config(base, binding["runtime_profile_digest"],
        control / "profile-pending.json", control / "profile-receipt.json")
    granted = broker_v4.RuntimeActionBrokerV4Config(profiled, canonical_json(value["capability_grant"]),
        control / "capability-grant-state.json")
    config = broker_v5.RuntimeActionBrokerV5Config(granted, ADMITTED_ROOT)
    broker_v5._validate_config(config)
    return config


def _sensor_config(value):
    ids, binding = value["identities"], value["observation_binding"]
    directory = CHANNEL_ROOT / "sensor"
    profile = process.runtime_process_profile(binding["runtime_profile"])
    configured = observation_v2.RuntimeActionObservationPublisherV2Config(
        directory / "worker.sock", directory, directory / "sensor.instance.lock", ACTION_SOCKET,
        EFFECT_ROOT / "protected", ids["sensor"]["uid"], ids["sensor"]["gid"],
        ids["worker"]["uid"], ids["worker"]["gid"], ids["action"]["uid"], ids["action"]["gid"],
        profile.runtime_digest, binding["sensor_digest"], profile)
    config = observation_v4.RuntimeActionObservationPublisherV4Config(
        configured, canonical_json(value["capability_grant"]), ADMITTED_ROOT)
    observation_v4._validate_config(config)
    return config


def _socket_metadata(parent, name, uid, gid):
    parent.guard()
    info = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
    _require(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid and info.st_gid == gid and
             stat.S_IMODE(info.st_mode) == 0o660 and info.st_nlink == 1)
    return broker._file_identity(info)


@contextmanager
def _connect(path, kind, peer, deadline, *, parent_identity, socket_identity):
    connection, peer_fd = None, -1
    try:
        with _parent(path.parent, deadline, **parent_identity) as parent:
            before = _socket_metadata(parent, path.name, *socket_identity)
            connection = socket.socket(socket.AF_UNIX, kind | socket.SOCK_CLOEXEC)
            connection.settimeout(_remaining(deadline))
            connection.connect(f"/proc/self/fd/{parent.fd}/{path.name}")
            _require(_socket_metadata(parent, path.name, *socket_identity) == before)
            actual = broker._peer_credentials(connection)
            _require(actual[1:] == peer[1:] and (peer[0] is None or actual[0] == peer[0]))
            if kind == socket.SOCK_SEQPACKET:
                peer_fd = channel.guard_channel(connection, actual, deadline)
            else:
                peer_fd = process.open_peer_pidfd(connection, actual[0])
                channel.require_peer_live(connection, actual, peer_fd, deadline)
            _remaining(deadline)
            yield connection
            parent.guard()
            # A peer may remove its owned listener after its terminal reply.
            # Existing handlers retain exact peer/PIDFD authority; connected
            # channel identity never depends on the pathname remaining present.
    finally:
        failed = False
        if peer_fd >= 0:
            try:
                os.close(peer_fd)
            except BaseException:
                failed = True
        if connection is not None:
            try:
                connection.close()
            except BaseException:
                failed = True
        _require(not failed)


@contextmanager
def _accept_sensor(value, deadline):
    own, sensor_identity = value["identities"]["action"], value["identities"]["sensor"]
    listener, accepted, captured = None, None, None
    with _parent(ACTION_DIRECTORY, deadline, uid=own["uid"], gid=own["gid"], mode=0o750) as parent:
        try:
            try:
                os.stat(ACTION_SOCKET.name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise PiServiceEntryError("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            listener.settimeout(_remaining(deadline))
            listener.bind(f"/proc/self/fd/{parent.fd}/{ACTION_SOCKET.name}")
            # Capture only our freshly bound name. Never unlink a preexisting or
            # replaced inode, including bind/publication uncertainty.
            before = os.stat(ACTION_SOCKET.name, dir_fd=parent.fd, follow_symlinks=False)
            _require(stat.S_ISSOCK(before.st_mode) and before.st_uid == own["uid"] and
                     before.st_gid == own["gid"] and before.st_nlink == 1)
            captured = broker._file_identity(before)
            os.chmod(ACTION_SOCKET.name, 0o660, dir_fd=parent.fd, follow_symlinks=False)
            changed = _socket_metadata(parent, ACTION_SOCKET.name, own["uid"], own["gid"])
            _require(changed[:2] == captured[:2])
            captured = changed
            os.fsync(parent.fd)
            listener.listen(1)
            accepted, _ = listener.accept()
            accepted.set_inheritable(False)
            accepted.settimeout(_remaining(deadline))
            _require(broker._peer_credentials(accepted)[1:] == (sensor_identity["uid"], sensor_identity["gid"]))
            _require(_socket_metadata(parent, ACTION_SOCKET.name, own["uid"], own["gid"]) == captured)
            yield accepted
        finally:
            failed = False
            for connection in (accepted, listener):
                if connection is not None:
                    try:
                        connection.close()
                    except BaseException:
                        failed = True
            if captured is not None:
                try:
                    parent.guard()
                    _require(_socket_metadata(parent, ACTION_SOCKET.name, own["uid"], own["gid"]) == captured)
                    os.unlink(ACTION_SOCKET.name, dir_fd=parent.fd)
                    os.fsync(parent.fd)
                except BaseException:
                    failed = True
            _require(not failed)


def run(role, argv, *, source_loader=None):
    """Exactly one real handler call; no injected transport, handler or config."""
    _flags()
    _require(role in ROLES)
    supervisor_pid, deadline = _arguments(argv)
    value = read_configuration(role, deadline)
    _identity(value)
    config = _action_config(value) if role == "action" else _sensor_config(value) if role == "sensor" else None
    if role == "provider":
        profile = provider_transport.read_profile()
        _require((profile["service_uid"], profile["service_gid"]) ==
                 (value["identities"][role]["uid"], value["identities"][role]["gid"]))
        provider_transport._identity(profile)
    own = value["identities"][role]
    path = CHANNEL_ROOT / role / "supervisor.sock"
    with _connect(path, socket.SOCK_SEQPACKET, (supervisor_pid, 0, 0), deadline,
            parent_identity={"mode": 0o755}, socket_identity=(0, own["gid"])) as root:
        if source_loader is not None:
            _source_handshake(root, role, supervisor_pid, deadline, source_loader)
        if role == "provider":
            result = provider.handle_pi_provider_service(root, expected_supervisor_pid=supervisor_pid, deadline=deadline)
        elif role == "action":
            with _accept_sensor(value, deadline) as peer:
                result = action.handle_pi_broker_request(root, peer, config,
                    expected_supervisor_pid=supervisor_pid, deadline=deadline)
        else:
            broker_identity = value["identities"]["action"]
            with _connect(ACTION_SOCKET, socket.SOCK_STREAM,
                    (None, broker_identity["uid"], broker_identity["gid"]), deadline,
                    parent_identity={"uid": broker_identity["uid"], "gid": broker_identity["gid"], "mode": 0o750},
                    socket_identity=(broker_identity["uid"], broker_identity["gid"])) as peer:
                result = sensor.run_pi_sensor_request(root, peer, config,
                    expected_supervisor_pid=supervisor_pid, deadline=deadline)
        _remaining(deadline)
    return result


def main(role, argv=None, *, source_loader=None):
    try:
        run(role, list(sys.argv[1:] if argv is None else argv), source_loader=source_loader)
        return 0
    except BaseException:
        # Never echo request/config/credential/OS error bytes or a traceback.
        print("PI_SERVICE_ENTRY_REFUSED_OR_CLEANUP_HOLD", file=sys.stderr)
        return 126
