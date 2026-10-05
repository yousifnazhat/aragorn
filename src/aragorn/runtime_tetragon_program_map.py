"""Bounded sensor-held exit-program/map/perf-link association, not execution.

Only pidfd_getfd(flags=0) and BPF_OBJ_GET_INFO_BY_FD are used for BPF objects.
Duplicated descriptors extend object lifetime until closed. Re-reading the
original sensor slots is a point-in-time check, not continuous custody proof.
The selected Linux source contract does not attest the running kernel/image.
"""

from __future__ import annotations

import ctypes
import os
import re
import struct
from contextlib import ExitStack
from typing import Any

from aragorn import runtime_tetragon_stats_map as stats

SOURCE_SLICE_DIGEST = (
    "sha256:d8b0789bf6ef615cafa344fda959a6992ddc74401f60b10eacafcfe000221649"
)
MAX_MAP_IDS = 256
SYMBOL_CAPACITY = 128
_PROGRAM_SIZE = 232
_LINK_SIZE = 64
_PIDFD_GETFD = 438
_PROGRAM_FIELDS = {
    "type",
    "id",
    "tag",
    "name",
    "load_time",
    "created_by_uid",
    "map_ids",
}
_LINK_FIELDS = {"type", "id", "prog_id", "perf_type", "symbol", "offset", "addr"}
_KINDS = ("program", "map", "link")


class TetragonProgramMapError(ValueError):
    """Unbound, unsupported, changed, or unavailable association observation."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise TetragonProgramMapError(message)


def _uint(value: object, bits: int, *, positive: bool = False) -> bool:
    return type(value) is int and int(positive) <= value < 2**bits


def _expected(value: object) -> dict:
    _need(
        type(value) is dict
        and set(value) == {"stats_map_binding", "sensor_fds", "program", "link"},
        "incomplete association binding",
    )
    bound = stats._validate_expected(value["stats_map_binding"])
    fds, program, link = value["sensor_fds"], value["program"], value["link"]
    _need(
        type(fds) is dict
        and set(fds) == set(_KINDS)
        and all(_uint(fd, 31) for fd in fds.values())
        and len(set(fds.values())) == 3,
        "invalid selected sensor descriptors",
    )
    _need(
        type(program) is dict
        and set(program) == _PROGRAM_FIELDS
        and type(link) is dict
        and set(link) == _LINK_FIELDS,
        "incomplete program or link identity",
    )
    for key in ("type", "id", "created_by_uid"):
        _need(_uint(program[key], 32, positive=key == "id"), "invalid program integer")
    _need(
        program["type"] == 2
        and _uint(program["load_time"], 64, positive=True)
        and type(program["tag"]) is str
        and re.fullmatch(r"[0-9a-f]{16}", program["tag"]) is not None
        and type(program["name"]) is str
        and re.fullmatch(r"[A-Za-z0-9_]{1,15}", program["name"]) is not None,
        "unsupported program identity",
    )
    ids = program["map_ids"]
    _need(
        type(ids) is list
        and 0 < len(ids) <= MAX_MAP_IDS
        and all(_uint(item, 32, positive=True) for item in ids)
        and len(set(ids)) == len(ids)
        and bound["map"]["id"] in ids,
        "invalid or unassociated expected map inventory",
    )
    for key in ("type", "id", "prog_id", "perf_type", "offset", "addr"):
        _need(
            _uint(
                link[key],
                64 if key == "addr" else 32,
                positive=key in {"id", "prog_id"},
            ),
            "invalid link integer",
        )
    _need(
        (link["type"], link["perf_type"], link["offset"]) == (7, 3, 0)
        and link["prog_id"] == program["id"]
        and link["symbol"] in {"acct_process", "disassociate_ctty"},
        "unsupported or unassociated selected exit link",
    )
    return {
        "stats_map_binding": bound,
        "sensor_fds": dict(fds),
        "program": {**program, "map_ids": list(ids)},
        "link": dict(link),
    }


def _duplicate(pidfd: int, target: int) -> int:
    """Selected x86-64/aarch64 ABI only; no permission or numeric-PID fallback."""
    stats._platform()
    _need(_uint(pidfd, 31) and _uint(target, 31), "invalid duplicate descriptor")
    library = ctypes.CDLL(None, use_errno=True)
    library.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    result = library.syscall(
        ctypes.c_long(_PIDFD_GETFD),
        ctypes.c_int(pidfd),
        ctypes.c_int(target),
        ctypes.c_uint(0),
    )
    if result < 0:
        raise TetragonProgramMapError(
            "sensor descriptor duplication refused (errno="
            + str(ctypes.get_errno())
            + ")"
        )
    fd = int(result)
    try:
        os.set_inheritable(fd, False)
        _need(not os.get_inheritable(fd), "duplicated descriptor is inheritable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _info(number: int, fd: int, buffer: ctypes.Array) -> bytes:
    attrs = stats._Info(fd, ctypes.sizeof(buffer), ctypes.addressof(buffer))
    _need(
        stats._syscall(number, stats._INFO, attrs) == 0
        and attrs.info_len == ctypes.sizeof(buffer),
        "incomplete object-info ABI",
    )
    return buffer.raw


def _program_info(number: int, fd: int) -> dict:
    # nr_map_ids is capacity on input and full used_map_cnt on output. Never
    # retry a truncated inventory; BPF_PROG_BIND_MAP can mutate it after load.
    ids = (ctypes.c_uint32 * MAX_MAP_IDS)()
    buffer = ctypes.create_string_buffer(_PROGRAM_SIZE)
    struct.pack_into("<IQ", buffer, 52, MAX_MAP_IDS, ctypes.addressof(ids))
    raw = _info(number, fd, buffer)
    count = struct.unpack_from("<I", raw, 52)[0]
    _need(0 < count <= MAX_MAP_IDS, "program map inventory absent or truncated")
    _need(
        struct.unpack_from("<Q", raw, 56)[0] == ctypes.addressof(ids),
        "map buffer pointer changed",
    )
    map_ids = list(ids[:count])
    _need(all(map_ids) and len(set(map_ids)) == count, "invalid program map inventory")
    name = raw[64:80]
    first_nul = name.find(b"\0")
    _need(
        0 < first_nul < 16
        and name[first_nul:] == b"\0" * (16 - first_nul)
        and re.fullmatch(rb"[A-Za-z0-9_]{1,15}", name[:first_nul]) is not None,
        "invalid program name",
    )
    identity = {
        "type": struct.unpack_from("<I", raw, 0)[0],
        "id": struct.unpack_from("<I", raw, 4)[0],
        "tag": raw[8:16].hex(),
        "name": name[:first_nul].decode("ascii"),
        "load_time": struct.unpack_from("<Q", raw, 40)[0],
        "created_by_uid": struct.unpack_from("<I", raw, 48)[0],
        "map_ids": map_ids,
    }
    _need(
        identity["type"] == 2
        and identity["id"] > 0
        and identity["load_time"] > 0
        and struct.unpack_from("<I", raw, 84)[0] in {0, 1}
        and raw[228:] == b"\0" * 4,
        "unsupported program ABI or type",
    )
    stable = bytearray(raw)
    stable[56:64] = b"\0" * 8  # Supplied userspace pointer, not object identity.
    stable[192:216] = b"\0" * 24  # Volatile diagnostics, not health/loss evidence.
    return {
        "identity": identity,
        "raw_info": stats._raw(raw),
        "raw_map_ids": stats._raw(bytes(ids)[: count * 4]),
        "stable_info_digest": stats._sha(bytes(stable)),
        "diagnostic_counters": dict(
            zip(
                ("run_time_ns", "run_cnt", "recursion_misses"),
                struct.unpack_from("<3Q", raw, 192),
                strict=True,
            )
        ),
    }


def _link_info(number: int, fd: int) -> dict:
    # Linux 6.8 name_len is input capacity, not a returned size-discovery API.
    symbol = ctypes.create_string_buffer(SYMBOL_CAPACITY)
    buffer = ctypes.create_string_buffer(_LINK_SIZE)
    struct.pack_into("<QI", buffer, 24, ctypes.addressof(symbol), SYMBOL_CAPACITY)
    raw = _info(number, fd, buffer)
    link_type, link_id, prog_id = struct.unpack_from("<3I", raw)
    perf_type = struct.unpack_from("<I", raw, 16)[0]
    pointer, capacity, offset, address, missed = struct.unpack_from("<QIIQQ", raw, 24)
    _need(
        (link_type, perf_type) == (7, 3)
        and link_id > 0
        and prog_id > 0
        and pointer == ctypes.addressof(symbol)
        and capacity == SYMBOL_CAPACITY
        and offset == 0
        and raw[12:16] == raw[20:24] == b"\0" * 4
        and raw[56:] == b"\0" * 8,
        "unsupported perf-link type or ABI",
    )
    names = {
        name.encode() + b"\0" * (SYMBOL_CAPACITY - len(name)): name
        for name in ("acct_process", "disassociate_ctty")
    }
    _need(symbol.raw in names, "unbound or malformed exit-probe symbol")
    stable = bytearray(raw)
    stable[24:32] = b"\0" * 8
    stable[48:56] = b"\0" * 8
    return {
        "identity": {
            "type": link_type,
            "id": link_id,
            "prog_id": prog_id,
            "perf_type": perf_type,
            "symbol": names[symbol.raw],
            "offset": offset,
            "addr": address,
        },
        "raw_info": stats._raw(raw),
        "raw_symbol": stats._raw(symbol.raw),
        "stable_info_digest": stats._sha(bytes(stable)),
        "diagnostic_counters": {"missed": missed},
    }


def _observe(number: int, fd: int, kind: str) -> dict:
    if kind == "program":
        return _program_info(number, fd)
    if kind == "link":
        return _link_info(number, fd)
    _need(kind == "map", "unsupported selected object")
    identity, raw = stats._map_info(number, fd)
    return {
        "identity": identity,
        "raw_info": stats._raw(raw),
        "stable_info_digest": stats._sha(raw),
    }


def snapshot_tetragon_program_map_association(*, expected: object) -> dict[str, Any]:
    """Observe one caller-selected exit association, without discovery/retries.

    stats_map_binding is the unchanged stats-map caller contract for joining
    reports. CPU topology, map pin, map values, and source custody are NOT
    measured by this API. Permission failures terminate the observation.
    """
    try:
        binding = _expected(expected)
        number = stats._platform()
        bound = binding["stats_map_binding"]
        sensor = bound["sensor"]
        identities = {
            "program": binding["program"],
            "map": bound["map"],
            "link": binding["link"],
        }
        with ExitStack() as stack:
            boot = stats._small(stats._BOOT, 64)
            _need(boot == (bound["boot_id"] + "\n").encode(), "boot identity changed")
            pidfd = os.pidfd_open(sensor["pid"], 0)
            stack.callback(os.close, pidfd)
            stats._live(pidfd, sensor["pid"])
            _need(stats._sensor(sensor) == sensor, "sensor differs from expectation")
            held, before, after, original = {}, {}, {}, {}
            for kind in _KINDS:
                stats._live(pidfd, sensor["pid"])
                fd = _duplicate(pidfd, binding["sensor_fds"][kind])
                stack.callback(os.close, fd)
                held[kind] = fd
                before[kind] = _observe(number, fd, kind)
                _need(
                    before[kind]["identity"] == identities[kind],
                    "selected object differs from expectation",
                )
                stats._live(pidfd, sensor["pid"])
            for kind in _KINDS:
                after[kind] = _observe(number, held[kind], kind)
                stats._live(pidfd, sensor["pid"])
                # Do not confuse our lifetime-extending copy with the original
                # process slot. Query a fresh PIDFD-bound duplicate of it.
                with ExitStack() as current:
                    fd = _duplicate(pidfd, binding["sensor_fds"][kind])
                    current.callback(os.close, fd)
                    original[kind] = _observe(number, fd, kind)
                stats._live(pidfd, sensor["pid"])
                for row in (after[kind], original[kind]):
                    _need(
                        row["identity"] == identities[kind]
                        and row["stable_info_digest"]
                        == before[kind]["stable_info_digest"],
                        "object or original sensor descriptor changed",
                    )
            _need(
                stats._sensor(sensor) == sensor,
                "sensor changed during association read",
            )
            _need(
                stats._small(stats._BOOT, 64) == boot,
                "boot changed during association read",
            )
            stats._live(pidfd, sensor["pid"])
            result = {
                "schema": "aragorn/tetragon-program-map-association/v1",
                "authority": "SENSOR_FD_EXIT_PROGRAM_MAP_PERF_LINK_ASSOCIATION_ONLY",
                "status": "OBSERVED_ASSOCIATION",
                "source_contract": {
                    "tetragon_commit": stats.TETRAGON_COMMIT,
                    "linux_uapi_commit": stats.LINUX_UAPI_COMMIT,
                    "selected_source_slice_digest": SOURCE_SLICE_DIGEST,
                    "stats_map_source_slice_digest": stats.SOURCE_SLICE_DIGEST,
                    "runtime_source_custody_verified": False,
                    "running_kernel_attested": False,
                    "executed_image_verified": False,
                },
                "caller_binding": binding,
                "objects_before": before,
                "held_objects_after": after,
                "original_sensor_objects_after": original,
                "limits": {"map_ids": MAX_MAP_IDS, "symbol_bytes": SYMBOL_CAPACITY},
                "limitations": [
                    "PROGRAM_MAP_MEMBERSHIP_DOES_NOT_PROVE_INSTRUCTION_USE",
                    "PERF_LINK_INFO_DOES_NOT_PROVE_ENABLED_OR_RESPONSIVE_ATTACHMENT",
                    "DUPLICATED_FDS_EXTEND_OBJECT_LIFETIME_UNTIL_CLOSED",
                    "BEFORE_AFTER_ORIGINAL_FD_CHECKS_NOT_CONTINUOUS_CUSTODY",
                    "PIN_TOPOLOGY_MAP_VALUES_AND_SCRAPES_NOT_READ",
                    "EXEC_TAIL_CALLS_LEGACY_LINKS_AND_OTHER_PRODUCERS_UNSUPPORTED",
                    "RAW_INFO_CONTAINS_QUERY_POINTERS_AND_PRIVILEGE_DEPENDENT_ADDRESS",
                    "DIAGNOSTIC_COUNTERS_NOT_LOSS_ACCOUNTING_OR_HEALTH_EVIDENCE",
                    "CALLER_EXPECTATIONS_AND_LOCAL_KERNEL_ROOT_ARE_TRUSTED_NOT_ATTESTED",
                ],
                "sensor_fd_association_observed": True,
                "program_execution_verified": False,
                "sensor_uses_map_verified": False,
                "attachment_enabled_verified": False,
                "sensor_health_verified": False,
                "delivery_completeness_verified": False,
                "runtime_attribution_verified": False,
                "run_conformance_eligible": False,
                "phase3_eligible": False,
                "production_activation_eligible": False,
            }
        # All observer copies, including the PIDFD, close before publication.
        return result
    except TetragonProgramMapError:
        raise
    except (
        stats.TetragonStatsMapError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        OverflowError,
    ) as exc:
        raise TetragonProgramMapError(
            "bound sensor program-map association refused"
        ) from exc
