"""Finite protected-credential successor over the frozen HTTP94 payloads.

Only source bytes are returned. Root provisioning and service credential loading
have separate APIs; no direct-path fallback or live operation is provided.
"""

from __future__ import annotations

import json

ACTION = "src/aragorn/runtime_http_action.py"
READINESS = "src/aragorn/runtime_http_readiness.py"
PROVISION = "src/aragorn/runtime_http_provisioning.py"
SENSOR_SERVICE = "src/aragorn/runtime_observation_service_v4.py"
BROKER_UNIT = "packaging/systemd/aragorn-runtime-lineage-capability-action-broker.service"
WORKER_UNIT = "packaging/systemd/aragorn-runtime-action-worker.service"
SENSOR_UNIT = "packaging/systemd/aragorn-runtime-lineage-capability-observation-publisher.service"
GATEWAY_UNIT = "packaging/systemd/aragorn-agent-gateway.service"
GATEWAY_CONFIG = "benchmark/admission/openclaw-v2026.7.1/protected-final-combined-config-v3.json"
LIFECYCLE_LOG = "/var/lib/aragorn-agent-gateway/gateway-lifecycle.log"
FIXTURE_SOURCE = "/etc/aragorn/runtime-http-fixture.json"
READINESS_SOURCE = "/etc/aragorn/runtime-http-readiness.json"
FIXTURE_NAME = "http-fixture"
READINESS_NAME = "http-readiness"
SOURCES = (ACTION, READINESS, PROVISION, SENSOR_SERVICE, BROKER_UNIT, WORKER_UNIT,
           SENSOR_UNIT, GATEWAY_UNIT, GATEWAY_CONFIG)


def change(raw, before, after, count=1):
    before, after = before.encode("ascii"), after.encode("ascii")
    if before == after or raw.count(before) != count or after in raw:
        raise ValueError("HTTP credential successor anchor changed: " + before[:100].decode())
    rendered = raw.replace(before, after)
    if rendered.replace(after, before) != raw:
        raise ValueError("HTTP credential successor reversal changed")
    return rendered


def function(raw, name, before, after, count=1):
    marker = ("def " + name + "(").encode("ascii")
    if raw.count(marker) != 1:
        raise ValueError("HTTP credential successor function changed")
    start = raw.index(marker)
    end = raw.find(b"\n\ndef ", start + len(marker))
    end = len(raw) if end < 0 else end
    section = raw[start:end].decode("ascii")
    return change(raw, section, change(section.encode(), before, after, count).decode())


_SERVICE_READER = '''# Sensor filesystem credentials change after startup. Only this held read-only
# descriptor survives that drop; no pathname is reopened by the sensor loop.
_SENSOR_FIXTURE = None
_CREDENTIAL_UNITS = {
    "aragorn-runtime-action-worker.service": ("aragorn-runtime", "aragorn-runtime"),
    "aragorn-runtime-lineage-capability-observation-publisher.service": ("aragorn-sensor", "aragorn-sensor"),
    BROKER_UNIT: ("aragorn-broker", "aragorn-runtime"),
}


def _credential_context(name):
    import grp
    import pwd
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    units = {"/run/credentials/" + unit: unit for unit in _CREDENTIAL_UNITS}
    _require(sys.platform == "linux" and directory in units
        and name in {"http-fixture", "http-readiness"}, "HTTP_BINDING_REFUSED")
    unit = units[directory]
    _require(name != "http-readiness" or unit == BROKER_UNIT, "HTTP_BINDING_REFUSED")
    user, group = _CREDENTIAL_UNITS[unit]
    uid, gid = pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    _require(uid > 0 and gid > 0 and os.getresuid() == (uid, uid, uid)
        and os.getresgid() == (gid, gid, gid)
        and os.getpid() == threading.get_native_id(), "HTTP_BINDING_REFUSED")
    identities = {}
    for line in _read("/proc/self/status", 16384).splitlines():
        key, separator, value = line.partition(b":")
        if separator and key in {b"Uid", b"Gid"}:
            _require(key not in identities, "HTTP_BINDING_REFUSED")
            identities[key] = value.split()
    expected = {b"Uid": [str(uid).encode()] * 4,
                b"Gid": [str(gid).encode()] * 4}
    adopted = None
    if unit == "aragorn-runtime-lineage-capability-observation-publisher.service" and _SENSOR_FIXTURE is not None:
        runtime_uid = pwd.getpwnam("aragorn-runtime").pw_uid
        runtime_gid = grp.getgrnam("aragorn-runtime").gr_gid
        _require(runtime_uid > 0 and runtime_gid > 0, "HTTP_BINDING_REFUSED")
        adopted = {b"Uid": expected[b"Uid"][:3] + [str(runtime_uid).encode()],
                   b"Gid": expected[b"Gid"][:3] + [str(runtime_gid).encode()]}
    _require(identities == expected or (adopted is not None and identities == adopted),
        "HTTP_BINDING_REFUSED")
    return Path(directory) / name, unit, uid, gid


def _close_credentials(descriptors):
    primary, failure = sys.exception(), None
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException as error:
            failure = error if failure is None else failure
    if failure is not None:
        if primary is not None:
            primary.add_note("HTTP_CREDENTIAL_DESCRIPTOR_CLOSE_FAILED")
        else:
            raise RuntimeHttpActionError("HTTP_BINDING_REFUSED") from failure


def _credential_guard(held, *, named):
    path, unit, uid, gid, pid, start, descriptors, ancestors, metadata = held
    _require(_credential_context(path.name) == (path, unit, uid, gid)
        and os.getpid() == pid and _process_start_time(pid) == start,
        "HTTP_BINDING_REFUSED")
    for parent, name, child, identity, regular in ancestors:
        current = _file_identity(os.fstat(child))
        _require((current if regular else current[:5]) == identity, "HTTP_BINDING_REFUSED")
        if named:
            current = _file_identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
            _require((current if regular else current[:5]) == identity,
                "HTTP_BINDING_REFUSED")
    _require(_file_identity(os.fstat(descriptors[-1])) == metadata
        and os.fstatvfs(descriptors[-1]).f_flag & os.ST_RDONLY
        and os.fstatvfs(descriptors[-2]).f_flag & os.ST_RDONLY,
        "HTTP_BINDING_REFUSED")


def _process_start_time(pid):
    from . import runtime_process_profile
    return runtime_process_profile._process_start_time(pid)


def _open_service_credential(name):
    path, unit, uid, gid = _credential_context(name)
    _require(unit != "aragorn-runtime-lineage-capability-observation-publisher.service"
        or _SENSOR_FIXTURE is None, "HTTP_BINDING_REFUSED")
    descriptors, ancestors = [], []
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        root = os.open("/", flags | os.O_DIRECTORY)
        descriptors.append(root)
        root_metadata = os.fstat(root)
        _require(stat.S_ISDIR(root_metadata.st_mode) and root_metadata.st_uid == 0
            and not stat.S_IMODE(root_metadata.st_mode) & 0o022,
            "HTTP_BINDING_REFUSED")
        ancestors.append((root, ".", root, _file_identity(root_metadata)[:5], False))
        parent = root
        for part in path.parts[1:-1]:
            before = os.stat(part, dir_fd=parent, follow_symlinks=False)
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
            descriptors.append(child)
            metadata = os.fstat(child)
            _require(stat.S_ISDIR(metadata.st_mode)
                and metadata.st_uid in ({0, uid} if part == unit else {0})
                and not stat.S_IMODE(metadata.st_mode) & 0o022
                and _file_identity(metadata)[:5] == _file_identity(before)[:5],
                "HTTP_BINDING_REFUSED")
            ancestors.append((parent, part, child, _file_identity(metadata)[:5], False))
            parent = child
        descriptor = os.open(name, flags, dir_fd=parent)
        descriptors.append(descriptor)
        metadata = os.fstat(descriptor)
        _require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
            and 0 < metadata.st_size <= 4096
            and ((metadata.st_uid == uid and metadata.st_gid in {0, gid}
                  and stat.S_IMODE(metadata.st_mode) == 0o400)
                 or (metadata.st_uid == 0 and metadata.st_gid in {0, gid}
                     and stat.S_IMODE(metadata.st_mode) in {0o400, 0o440})),
            "HTTP_BINDING_REFUSED")
        ancestors.append((parent, name, descriptor, _file_identity(metadata), True))
        held = (path, unit, uid, gid, os.getpid(), _process_start_time(os.getpid()),
                descriptors, ancestors, _file_identity(metadata))
        _credential_guard(held, named=True)
        return held
    except BaseException:
        _close_credentials(descriptors)
        raise


def _read_service_credential(held, *, named):
    _credential_guard(held, named=named)
    raw = os.pread(held[6][-1], 4097, 0)
    _require(len(raw) == held[-1][6] and 0 < len(raw) <= 4096,
        "HTTP_BINDING_REFUSED")
    _credential_guard(held, named=named)
    return raw, {"identity": list(held[-1]), "bytes": len(raw)}


def read_service_credential(name):
    """Only the exact service credential view; never the root provisioning path."""
    held = _open_service_credential(name)
    try:
        return _read_service_credential(held, named=True)
    finally:
        _close_credentials(held[6])


@contextmanager
def hold_service_fixture_binding():
    """Sensor-only descriptor custody before the irreversible filesystem drop."""
    global _SENSOR_FIXTURE
    held = _open_service_credential("http-fixture")
    try:
        _require(held[1] == "aragorn-runtime-lineage-capability-observation-publisher.service"
            and _SENSOR_FIXTURE is None, "HTTP_BINDING_REFUSED")
        _SENSOR_FIXTURE = held
        load_fixture_binding()
        try:
            yield
        finally:
            primary = sys.exception()
            try:
                _credential_guard(held, named=False)
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("HTTP_SENSOR_CREDENTIAL_FINAL_GUARD_FAILED")
    finally:
        if _SENSOR_FIXTURE is held:
            _SENSOR_FIXTURE = None
        _close_credentials(held[6])


def load_fixture_binding():
    """Service-only loaded credential, including the sensor's held startup FD."""
    try:
        path, unit, uid, gid = _credential_context("http-fixture")
        if unit == "aragorn-runtime-lineage-capability-observation-publisher.service":
            _require(_SENSOR_FIXTURE is not None, "HTTP_BINDING_REFUSED")
            raw, _ = _read_service_credential(_SENSOR_FIXTURE, named=False)
        else:
            raw, _ = read_service_credential("http-fixture")
        binding = validate_fixture_binding(json.loads(raw))
        _require(canonical_json(binding) == raw
            and (unit != BROKER_UNIT or (uid, gid) ==
                (binding["expected_broker_uid"], binding["expected_broker_gid"]))
            and _read("/proc/self/cgroup", 1024) ==
                f"0::/docker/{binding['fixture']['container_id']}/system.slice/{unit}\\n".encode()
            and _read(BOOT_PATH, 64) ==
                (binding["fixture"]["boot_id"] + "\\n").encode(),
            "HTTP_BINDING_REFUSED")
        return binding
    except (OSError, ValueError, TypeError, KeyError):
        raise RuntimeHttpActionError("HTTP_BINDING_REFUSED") from None


'''


def render(original):
    if type(original) is not dict or not set(SOURCES) <= set(original):
        raise ValueError("HTTP credential successor inventory changed")
    result = {}
    action = change(original[ACTION], "from . import runtime_process_profile as process\n", "from contextlib import contextmanager\n")
    action = change(action, "def load_fixture_binding():\n", _SERVICE_READER + "def load_provisioned_fixture_binding():\n")
    action = function(action, "load_provisioned_fixture_binding", "    descriptor = -1\n", '    _require(os.getresuid() == (0, 0, 0), "HTTP_BINDING_REFUSED")\n    descriptor = -1\n')
    action = function(action, "_read", '    return process._read_virtual_file(Path(path), limit)', '    from . import runtime_process_profile as process\n    return process._read_virtual_file(Path(path), limit)')
    action = change(action, "            self.start = process._process_start_time(self.pid)", "            self.start = _process_start_time(self.pid)")
    action = change(action, "and process._process_start_time(self.pid) == self.start,", "and _process_start_time(self.pid) == self.start,")
    result[ACTION] = action
    result[PROVISION] = change(original[PROVISION], "http.load_fixture_binding()", "http.load_provisioned_fixture_binding()", 3)
    ready = function(original[READINESS], "provision_readiness_input", "http.load_fixture_binding()", "http.load_provisioned_fixture_binding()", 2)
    ready = function(ready, "validate_activation_readiness", "http.load_fixture_binding()", "http.load_provisioned_fixture_binding()", 2)
    ready = change(ready, '    request_raw, metadata = _read_owned(\n        CREDENTIAL, uid=0, gid=binding["expected_broker_gid"], mode=0o440\n    )', '    request_raw, metadata = http.read_service_credential("http-readiness")')
    ready = change(ready, '            _read_owned(\n                CREDENTIAL, uid=0, gid=binding["expected_broker_gid"], mode=0o440\n            )', '            http.read_service_credential("http-readiness")', 2)
    result[READINESS] = ready
    sensor = change(original[SENSOR_SERVICE], "from .runtime_action_observation_publisher import (", "from . import runtime_http_action as http\nfrom .runtime_action_observation_publisher import (")
    result[SENSOR_SERVICE] = change(sensor, "def _run(observation_binding_path: Path, capability_grant_path: Path) -> None:", "@http.hold_service_fixture_binding()\ndef _run(observation_binding_path: Path, capability_grant_path: Path) -> None:")
    for source in (BROKER_UNIT, WORKER_UNIT, SENSOR_UNIT):
        raw = original[source]
        # The credentials are copied by PID1; services never traverse /etc/aragorn.
        if source != SENSOR_UNIT:
            raw = change(raw, "ReadOnlyPaths=" + FIXTURE_SOURCE + "\n", "# Fixture input is read only from the PID1 credential view.\n")
        if source == BROKER_UNIT:
            raw = change(raw, "ReadOnlyPaths=" + READINESS_SOURCE + "\n", "# Readiness input is read only from the PID1 credential view.\n")
        addition = "LoadCredential=http-fixture:" + FIXTURE_SOURCE + "\n"
        if source == BROKER_UNIT:
            addition += "LoadCredential=http-readiness:" + READINESS_SOURCE + "\n"
        boot_bind = "BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/aragorn-broker-boot-id\n"
        if source == BROKER_UNIT:
            if raw.count(boot_bind.encode("ascii")) != 1:
                raise ValueError("HTTP broker protected boot binding changed")
        else:
            if b"/run/aragorn-broker-boot-id" in raw:
                raise ValueError("HTTP service boot binding already present")
            addition += boot_bind
        result[source] = change(raw, "[Service]\n", "[Service]\n" + addition)
    result[GATEWAY_UNIT] = change(original[GATEWAY_UNIT], "Environment=HOME=", "Environment=OPENCLAW_NO_RESPAWN=1 HOME=")
    raw = original[GATEWAY_CONFIG]
    config = json.loads(raw)
    if type(config) is not dict or "logging" in config or json.dumps(config, sort_keys=True, separators=(",", ":")).encode("ascii") != raw:
        raise ValueError("HTTP gateway configuration predecessor changed")
    config["logging"] = {"level": "info", "file": LIFECYCLE_LOG}
    result[GATEWAY_CONFIG] = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("ascii")
    return result
