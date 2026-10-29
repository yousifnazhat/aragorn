"""One bounded, read-only Linux snapshot of a caller-bound tg_stats_map.

Only OBJ_GET (read-only), OBJ_GET_INFO_BY_FD and LOOKUP_ELEM are issued.
The kernel copies per-CPU values sequentially: this is not an atomic snapshot.
Pin and sensor continuity do not prove that the sensor or its programs use this
map. No health verdict, metric substitution, or qualification is performed.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import re
import select
import stat
import struct
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Any

TETRAGON_COMMIT = "1de2ed8ebea18e56257dc59597aa13bf8f0e471e"
LINUX_UAPI_COMMIT = "e8f897f4afef0031fe618a8e94127a0934896aba"
SOURCE_SLICE_DIGEST = (
    "sha256:24ebc77c050db856177d3880e05c08ea0a1c33a2942391fac619e06dcfe4abe8"
)
MAX_CPUS = 256
VALUE_SIZE = 256 * 7 * 8
ERROR_ORDER = ("UNKNOWN", "ENOENT", "E2BIG", "EBUSY", "EINVAL", "ENOSPC", "EAGAIN")
_POSSIBLE = Path("/sys/devices/system/cpu/possible")
_BOOT = Path("/proc/sys/kernel/random/boot_id")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAP_FIELDS = (
    "type",
    "id",
    "key_size",
    "value_size",
    "max_entries",
    "map_flags",
    "name",
    "ifindex",
    "btf_vmlinux_value_type_id",
    "netns_dev",
    "netns_ino",
    "btf_id",
    "btf_key_type_id",
    "btf_value_type_id",
    "map_extra",
)
_NAMESPACES = ("mnt", "pid", "user", "time")
_SENSOR_FIELDS = {
    "pid",
    "start_time_ticks",
    "uid",
    "gid",
    "cgroup",
    "executable_digest",
    "namespaces",
}
_READONLY = 8
_PATH_FD = 16384
_OBJ_GET, _INFO, _LOOKUP = 7, 15, 1


class TetragonStatsMapError(ValueError):
    """Unsupported ABI, unsafe custody, or an unbound/failed map read."""


class _ObjGet(ctypes.Structure):
    _fields_ = (
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
        ("path_fd", ctypes.c_int32),
    )


class _Info(ctypes.Structure):
    _fields_ = (
        ("bpf_fd", ctypes.c_uint32),
        ("info_len", ctypes.c_uint32),
        ("info", ctypes.c_uint64),
    )


class _Lookup(ctypes.Structure):
    _fields_ = (
        ("map_fd", ctypes.c_uint32),
        ("padding", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    )


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise TetragonStatsMapError(message)


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _raw(raw: bytes) -> dict:
    return {
        "bytes": len(raw),
        "digest": _sha(raw),
        "base64": base64.b64encode(raw).decode("ascii"),
    }


def _identity(info: os.stat_result) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _small(path: Path, maximum: int, *, expected_uid: int = 0) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _need(
            stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid,
            "unsafe virtual file",
        )
        value = bytearray()
        while chunk := os.read(fd, min(8192, maximum + 1 - len(value))):
            value.extend(chunk)
            _need(len(value) <= maximum, "virtual file exceeds bound")
        _need(
            _identity(before) == _identity(os.fstat(fd)) == _identity(path.lstat()),
            "virtual file changed",
        )
        return bytes(value)
    finally:
        os.close(fd)


def _cpu_ids(raw: bytes) -> list[int]:
    _need(
        type(raw) is bytes and 0 < len(raw) <= 4096 and raw.endswith(b"\n"),
        "invalid CPU topology framing",
    )
    text = raw[:-1].decode("ascii")
    _need(
        re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", text) is not None,
        "invalid possible CPU list",
    )
    result = []
    for item in text.split(","):
        edges = item.split("-")
        _need(all(len(value) <= 5 for value in edges), "CPU index exceeds bound")
        first, last = int(edges[0]), int(edges[-1])
        _need(
            0 <= first <= last < 65536
            and (not result or first > result[-1])
            and len(result) + last - first + 1 <= MAX_CPUS,
            "unsupported possible CPU inventory",
        )
        result.extend(range(first, last + 1))
    return result


def _mount_path(raw: bytes) -> bytes:
    _need(
        re.search(rb"\\(?!040|011|012|134)", raw) is None,
        "unsupported mount path escape",
    )
    value = re.sub(
        rb"\\(040|011|012|134)", lambda match: bytes([int(match[1], 8)]), raw
    )
    _need(value.startswith(b"/") and b"\0" not in value, "invalid mount path")
    _need(
        value == b"/"
        or all(part not in {b"", b".", b".."} for part in value[1:].split(b"/")),
        "noncanonical mount path",
    )
    return value


def _topology_view() -> dict:
    """Require the real sysfs root, not a substituted CPU-mask file/subtree.

    Linux's possible mask is immutable after boot (retained source contract).
    LOOKUP_ELEM has no output-length argument, so this guard precedes lookup;
    a post-write topology comparison alone could not make allocation safe.
    Kernel/procfs and the local root observer are trusted, not attested here.
    """
    namespace = os.readlink("/proc/self/ns/mnt")
    _need(
        re.fullmatch(r"mnt:\[[1-9][0-9]{0,19}\]", namespace) is not None,
        "invalid reader mount namespace",
    )
    raw = _small(Path("/proc/self/mountinfo"), 1024 * 1024)
    lines = raw.splitlines()
    _need(
        raw.endswith(b"\n") and 0 < len(lines) <= 8192,
        "mount inventory exceeds bound or is malformed",
    )
    target, covering = os.fsencode(_POSSIBLE), []
    for line in lines:
        sides = line.split(b" - ")
        _need(len(sides) == 2, "malformed mount inventory separator")
        left, right = sides[0].split(), sides[1].split()
        _need(
            len(left) >= 6
            and len(right) == 3
            and left[0].isdigit()
            and left[1].isdigit()
            and re.fullmatch(rb"[0-9]+:[0-9]+", left[2]) is not None,
            "malformed mount inventory fields",
        )
        root, mount = _mount_path(left[3]), _mount_path(left[4])
        if target == mount or target.startswith(mount.rstrip(b"/") + b"/"):
            covering.append((mount, root, right[0], line))
    _need(bool(covering), "CPU topology has no covering mount")
    deepest = max(len(row[0]) for row in covering)
    selected = [row for row in covering if len(row[0]) == deepest]
    _need(
        len(selected) == 1 and selected[0][:3] == (b"/sys", b"/", b"sysfs"),
        "CPU topology is substituted, nested, stacked or not root sysfs",
    )
    _need(
        os.readlink("/proc/self/ns/mnt") == namespace, "reader mount namespace changed"
    )
    return {"mount_namespace": namespace, "sysfs_mount": _raw(selected[0][3])}


def _platform() -> int:
    _need(
        sys.platform == "linux"
        and sys.byteorder == "little"
        and ctypes.sizeof(ctypes.c_void_p) == 8
        and os.geteuid() == 0,
        "root 64-bit little-endian Linux required",
    )
    machine = os.uname().machine
    _need(machine in {"aarch64", "x86_64"}, "unsupported BPF syscall architecture")
    _need(
        (ctypes.sizeof(_ObjGet), ctypes.sizeof(_Info), ctypes.sizeof(_Lookup))
        == (24, 16, 32)
        and _ObjGet.path_fd.offset == 16
        and _Info.info.offset == 8
        and _Lookup.key.offset == 8
        and _Lookup.value.offset == 16
        and _Lookup.flags.offset == 24,
        "unsupported ctypes ABI",
    )
    return 280 if machine == "aarch64" else 321


def _syscall(number: int, command: int, attributes: ctypes.Structure) -> int:
    # This allowlist is intentionally not a general BPF command interface.
    _need(
        (command, type(attributes))
        in {(_OBJ_GET, _ObjGet), (_INFO, _Info), (_LOOKUP, _Lookup)},
        "unsupported BPF read operation",
    )
    _need(number in {280, 321}, "unsupported BPF syscall number")
    if command == _OBJ_GET:
        _need(
            attributes.bpf_fd == 0
            and attributes.file_flags == (_READONLY | _PATH_FD)
            and attributes.path_fd >= 0,
            "BPF map open must be read-only and directory-bound",
        )
    if command == _LOOKUP:
        _need(
            attributes.flags == 0 and attributes.padding == 0,
            "unsupported map lookup flags",
        )
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    value = library.syscall(
        ctypes.c_long(number),
        ctypes.c_int(command),
        ctypes.byref(attributes),
        ctypes.c_uint(ctypes.sizeof(attributes)),
    )
    if value < 0:
        raise TetragonStatsMapError(
            "read-only BPF operation refused (errno=" + str(ctypes.get_errno()) + ")"
        )
    return int(value)


def _open_map(number: int, parent_fd: int) -> int:
    name = ctypes.create_string_buffer(b"tg_stats_map\0")
    attributes = _ObjGet(ctypes.addressof(name), 0, _READONLY | _PATH_FD, parent_fd)
    fd = _syscall(number, _OBJ_GET, attributes)
    try:
        os.set_inheritable(fd, False)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _map_info(number: int, fd: int) -> tuple[dict, bytes]:
    buffer = ctypes.create_string_buffer(88)
    attributes = _Info(fd, 88, ctypes.addressof(buffer))
    _need(
        _syscall(number, _INFO, attributes) == 0 and attributes.info_len == 88,
        "incomplete map-info ABI",
    )
    raw = buffer.raw
    fields = list(struct.unpack("<6I16s2I2Q4IQ", raw))
    name = fields[6]
    _need(
        name == b"tg_stats_map" + b"\0" * 4 and fields[-2] == 0,
        "unsupported map name or padding",
    )
    fields[6] = "tg_stats_map"
    del fields[-2]
    result = dict(zip(_MAP_FIELDS, fields, strict=True))
    _need(
        result["id"] > 0
        and result["type"] == 6
        and result["key_size"] == 4
        and result["value_size"] == VALUE_SIZE
        and result["max_entries"] == 1,
        "unsupported tg_stats_map type or layout",
    )
    return result, raw


def _lookup(number: int, fd: int, cpus: list[int]) -> bytes:
    # Linux copies round_up(value_size, 8) bytes for every possible CPU.
    key = ctypes.c_uint32(0)
    size = ((VALUE_SIZE + 7) // 8) * 8 * len(cpus)
    _need(0 < size <= VALUE_SIZE * MAX_CPUS, "per-CPU buffer bound exceeded")
    values = ctypes.create_string_buffer(size)
    attributes = _Lookup(fd, 0, ctypes.addressof(key), ctypes.addressof(values), 0)
    _need(_syscall(number, _LOOKUP, attributes) == 0, "map lookup did not complete")
    return values.raw


def _validate_expected(expected: object) -> dict:
    _need(
        type(expected) is dict
        and set(expected) == {"boot_id", "sensor", "map", "possible_cpus_digest"},
        "incomplete expected binding",
    )
    _need(
        type(expected["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", expected["boot_id"]
        )
        is not None,
        "invalid expected boot",
    )
    _need(
        type(expected["possible_cpus_digest"]) is str
        and _DIGEST.fullmatch(expected["possible_cpus_digest"]) is not None,
        "invalid expected CPU digest",
    )
    sensor, info = expected["sensor"], expected["map"]
    _need(
        type(sensor) is dict
        and set(sensor) == _SENSOR_FIELDS
        and type(info) is dict
        and set(info) == set(_MAP_FIELDS),
        "incomplete sensor or map binding",
    )
    for key in ("pid", "start_time_ticks", "uid", "gid"):
        limit = 2**64 if key == "start_time_ticks" else 2**32
        _need(
            type(sensor[key]) is int
            and int(key in {"pid", "start_time_ticks"}) <= sensor[key] < limit,
            "invalid expected sensor integer",
        )
    _need(
        type(sensor["executable_digest"]) is str
        and _DIGEST.fullmatch(sensor["executable_digest"]) is not None,
        "invalid executable digest",
    )
    group = sensor["cgroup"]
    _need(
        type(group) is str
        and 1 < len(group) <= 1024
        and group.startswith("/")
        and all(part not in {"", ".", ".."} for part in group[1:].split("/")),
        "invalid expected cgroup",
    )
    namespaces = sensor["namespaces"]
    _need(
        type(namespaces) is dict and set(namespaces) == set(_NAMESPACES),
        "incomplete expected namespaces",
    )
    for name in _NAMESPACES:
        _need(
            type(namespaces[name]) is str
            and re.fullmatch(name + r":\[[1-9][0-9]{0,19}\]", namespaces[name])
            is not None,
            "invalid expected namespace",
        )
    for key in _MAP_FIELDS:
        if key == "name":
            _need(info[key] == "tg_stats_map", "unbound map name")
        else:
            limit = 2**64 if key in {"netns_dev", "netns_ino", "map_extra"} else 2**32
            _need(
                type(info[key]) is int and 0 <= info[key] < limit,
                "invalid expected map integer",
            )
    _need(
        info["id"] > 0
        and (info["type"], info["key_size"], info["value_size"], info["max_entries"])
        == (6, 4, VALUE_SIZE, 1),
        "unsupported expected map layout",
    )
    return {
        **expected,
        "sensor": {**sensor, "namespaces": dict(namespaces)},
        "map": dict(info),
    }


def _sensor(expected: dict) -> dict:
    pid = expected["pid"]
    root = Path("/proc") / str(pid)
    raw = _small(root / "stat", 16384, expected_uid=expected["uid"])
    marker = raw.rfind(b") ")
    fields = raw[marker + 2 :].split() if marker >= 0 else []
    _need(
        raw.startswith(str(pid).encode() + b" (")
        and len(fields) >= 20
        and fields[19].isdigit(),
        "invalid sensor process stat",
    )
    status = dict(
        line.split(":", 1)
        for line in _small(root / "status", 16384, expected_uid=expected["uid"])
        .decode("ascii")
        .splitlines()
        if ":" in line
    )
    uids, gids = (
        [int(v) for v in status["Uid"].split()],
        [int(v) for v in status["Gid"].split()],
    )
    _need(
        uids == [expected["uid"]] * 4 and gids == [expected["gid"]] * 4,
        "sensor credentials changed",
    )
    group = _small(root / "cgroup", 4096, expected_uid=expected["uid"]).decode("ascii")
    _need(
        group.startswith("0::/") and group.endswith("\n") and group.count("\n") == 1,
        "sensor cgroup is not unified",
    )
    fd = os.open(root / "exe", os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and not stat.S_IMODE(before.st_mode) & 0o022
            and 0 < before.st_size <= 256 * 1024 * 1024,
            "unsafe sensor executable",
        )
        digest, count = hashlib.sha256(), 0
        while chunk := os.read(fd, min(65536, before.st_size + 1 - count)):
            count += len(chunk)
            _need(count <= before.st_size, "sensor executable grew")
            digest.update(chunk)
        _need(
            count == before.st_size
            and _identity(before)
            == _identity(os.fstat(fd))
            == _identity((root / "exe").stat()),
            "sensor executable changed",
        )
    finally:
        os.close(fd)
    return {
        "pid": pid,
        "start_time_ticks": int(fields[19]),
        "uid": uids[0],
        "gid": gids[0],
        "cgroup": group[3:-1],
        "executable_digest": "sha256:" + digest.hexdigest(),
        "namespaces": {name: os.readlink(root / "ns" / name) for name in _NAMESPACES},
    }


def _live(pidfd: int, expected_pid: int) -> None:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    _need(not poller.poll(0), "bound sensor exited")
    raw = _small(Path(f"/proc/self/fdinfo/{pidfd}"), 4096).decode("ascii")
    pids = [
        line.partition(":")[2].strip()
        for line in raw.splitlines()
        if line.startswith("Pid:")
    ]
    _need(pids == [str(expected_pid)], "pidfd does not identify expected sensor")


def _pin_metadata(parent: int) -> tuple:
    metadata = os.stat("tg_stats_map", dir_fd=parent, follow_symlinks=False)
    _need(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == metadata.st_gid == 0
        and metadata.st_nlink == 1
        and not stat.S_IMODE(metadata.st_mode) & 0o022,
        "unsafe BPF pin custody",
    )
    return _identity(metadata)


def _directories(pin: Path, stack: ExitStack) -> list[tuple[Path, int, tuple]]:
    _need(
        isinstance(pin, Path)
        and pin.is_absolute()
        and pin.name == "tg_stats_map"
        and pin.parts[:4] == ("/", "sys", "fs", "bpf")
        and len(pin.parts) >= 6
        and all(part not in {".", ".."} for part in pin.parts[1:])
        and len(str(pin)) <= 4096,
        "unsupported protected BPF pin path",
    )
    held = []
    parent = None
    for index, part in enumerate(pin.parent.parts):
        fd = os.open(
            part,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent,
        )
        stack.callback(os.close, fd)
        path = Path(*pin.parent.parts[: index + 1])
        identity = os.fstat(fd)
        _need(
            identity.st_uid == identity.st_gid == 0
            and not stat.S_IMODE(identity.st_mode) & 0o022,
            "unsafe BPF pin ancestry",
        )
        # Directory times can change due to unrelated pinned objects; identity,
        # owner and access mode, rather than directory content, bind custody.
        held.append((path, fd, _identity(identity)[:5]))
        parent = fd
    return held


def _decoded(raw: bytes, cpus: list[int]) -> dict:
    _need(len(raw) == len(cpus) * VALUE_SIZE, "truncated per-CPU values")
    totals = [0] * (256 * 7)
    per_cpu = []
    for index, cpu in enumerate(cpus):
        values = struct.unpack_from("<1792Q", raw, index * VALUE_SIZE)
        per_cpu.append({"cpu": cpu, "sent_failed_total": sum(values)})
        for offset, value in enumerate(values):
            totals[offset] += value
    return {
        "possible_cpu_order": cpus,
        "error_order": list(ERROR_ORDER),
        "per_cpu_totals": per_cpu,
        "sent_failed_total": sum(totals),
        "sent_failed_by_opcode": [
            totals[index : index + 7] for index in range(0, len(totals), 7)
        ],
    }


def snapshot_tetragon_stats_map(pin_path: Path, *, expected: object) -> dict[str, Any]:
    """Read key zero once; caller-held identities must match before and after.

    Linux/BPF permission or layout failures are terminal refusals. There is no
    fallback to a writable FD, numeric-PID authority, absent-as-zero, or a tool.
    """
    try:
        binding = _validate_expected(expected)
        number = _platform()
        with ExitStack() as stack:
            boot = _small(_BOOT, 64)
            _need(boot == (binding["boot_id"] + "\n").encode(), "boot identity changed")
            topology_view = _topology_view()
            topology = _small(_POSSIBLE, 4096)
            _need(
                _topology_view() == topology_view,
                "topology view changed during CPU read",
            )
            _need(
                _sha(topology) == binding["possible_cpus_digest"],
                "CPU topology differs from expectation",
            )
            cpus = _cpu_ids(topology)
            pidfd = os.pidfd_open(binding["sensor"]["pid"], 0)
            stack.callback(os.close, pidfd)
            _live(pidfd, binding["sensor"]["pid"])
            _need(
                _sensor(binding["sensor"]) == binding["sensor"],
                "sensor identity differs from expectation",
            )
            held = _directories(pin_path, stack)
            parent = held[-1][1]
            pin = _pin_metadata(parent)
            fd = _open_map(number, parent)
            stack.callback(os.close, fd)
            first, first_raw = _map_info(number, fd)
            _need(first == binding["map"], "opened map differs from expectation")
            _need(
                _topology_view() == topology_view, "topology view changed before lookup"
            )
            values = _lookup(number, fd, cpus)
            last, last_raw = _map_info(number, fd)
            reopened = _open_map(number, parent)
            stack.callback(os.close, reopened)
            named, named_raw = _map_info(number, reopened)
            _need(
                first == last == named
                and first_raw == last_raw == named_raw
                and _pin_metadata(parent) == pin,
                "map or pin identity changed",
            )
            for path, directory_fd, identity in held:
                _need(
                    _identity(os.fstat(directory_fd))[:5]
                    == identity
                    == _identity(path.lstat())[:5],
                    "BPF pin ancestry changed",
                )
            _need(
                _small(_POSSIBLE, 4096) == topology and _small(_BOOT, 64) == boot,
                "CPU topology or boot changed during lookup",
            )
            _need(
                _topology_view() == topology_view, "topology view changed during lookup"
            )
            _need(
                _sensor(binding["sensor"]) == binding["sensor"],
                "sensor identity changed during lookup",
            )
            _live(pidfd, binding["sensor"]["pid"])
            return {
                "schema": "aragorn/tetragon-read-only-stats-map-snapshot/v1",
                "authority": "BOUND_PINNED_MAP_BYTES_NOT_SENSOR_PROGRAM_OWNERSHIP_OR_HEALTH",
                "status": "OBSERVED",
                "source_contract": {
                    "tetragon_commit": TETRAGON_COMMIT,
                    "linux_uapi_commit": LINUX_UAPI_COMMIT,
                    "selected_source_slice_digest": SOURCE_SLICE_DIGEST,
                    "runtime_source_custody_verified": False,
                    "executed_image_verified": False,
                },
                "binding": binding,
                "pin_path": str(pin_path),
                "pin_identity": list(pin),
                "reader_topology_view": topology_view,
                "map_info_before": _raw(first_raw),
                "map_info_after": _raw(last_raw),
                "reopened_pin_map_info": _raw(named_raw),
                "possible_cpus": _raw(topology),
                "key": 0,
                "value_size": VALUE_SIZE,
                "per_cpu_stride": VALUE_SIZE,
                "values": _raw(values),
                "decoded": _decoded(values, cpus),
                "limitations": [
                    "SEQUENTIAL_PER_CPU_COPY_NOT_ATOMIC_SNAPSHOT",
                    "PIN_AND_SENSOR_CONTINUITY_DO_NOT_PROVE_SENSOR_OR_PROGRAM_USES_MAP",
                    "MAP_VALUES_DO_NOT_ESTABLISH_READER_PROGRESS_OR_EVENT_DELIVERY",
                    "CALLER_EXPECTATIONS_NOT_INDEPENDENT_SENSOR_AUTHENTICATION",
                ],
                "sensor_map_ownership_verified": False,
                "sensor_health_verified": False,
                "delivery_completeness_verified": False,
                "runtime_attribution_verified": False,
                "run_conformance_eligible": False,
                "phase3_eligible": False,
                "production_activation_eligible": False,
            }
    except TetragonStatsMapError:
        raise
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
    ) as exc:
        raise TetragonStatsMapError(
            "bound read-only stats-map snapshot refused"
        ) from exc
