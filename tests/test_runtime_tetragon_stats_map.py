"""Synthetic syscall plumbing only; no live process, map, or kernel BPF calls."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import struct
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aragorn import runtime_tetragon_stats_map as subject

_ROOT = Path(__file__).resolve().parents[1]
_PIN = Path("/sys/fs/bpf/owned-fixture/tg_stats_map")


def _info():
    raw = struct.pack(
        "<6I16s2I2Q4IQ",
        6,
        19,
        4,
        subject.VALUE_SIZE,
        1,
        0,
        b"tg_stats_map\0\0\0\0",
        0,
        0,
        0,
        0,
        11,
        12,
        13,
        0,
        0,
    )
    values = [
        6,
        19,
        4,
        subject.VALUE_SIZE,
        1,
        0,
        "tg_stats_map",
        0,
        0,
        0,
        0,
        11,
        12,
        13,
        0,
    ]
    return dict(zip(subject._MAP_FIELDS, values, strict=True)), raw


def _expected():
    return {
        "boot_id": "11111111-2222-3333-4444-555555555555",
        "possible_cpus_digest": subject._sha(b"0,2\n"),
        "map": _info()[0],
        "sensor": {
            "pid": 73,
            "start_time_ticks": 1234,
            "uid": 0,
            "gid": 0,
            "cgroup": "/docker/owned-synthetic",
            "executable_digest": "sha256:" + "a" * 64,
            "namespaces": {name: name + ":[123]" for name in subject._NAMESPACES},
        },
    }


class TetragonStatsMapTests(unittest.TestCase):
    def test_new_source_slice_custody_and_layout_constants(self):
        lock = _ROOT / "benchmark/tetragon-stats-map-source-v1.lock.json"
        with lock.open("rb") as stream:
            raw = stream.read(65537)
        self.assertLessEqual(len(raw), 65536)
        self.assertEqual(subject._sha(raw), subject.SOURCE_SLICE_DIGEST)
        self.assertEqual(
            subject.SOURCE_SLICE_DIGEST,
            "sha256:24ebc77c050db856177d3880e05c08ea0a1c33a2942391fac619e06dcfe4abe8",
        )
        manifest = json.loads(raw)
        self.assertEqual(manifest["commit"], subject.TETRAGON_COMMIT)
        self.assertEqual(len(manifest["files"]), 2)
        self.assertEqual(len({row["local_path"] for row in manifest["files"]}), 2)
        for row in manifest["files"]:
            path = _ROOT / row["local_path"]
            self.assertEqual(
                row["local_path"],
                "benchmark/tetragon-stats-map-source-v1/" + row["path"],
            )
            self.assertEqual(path.resolve(strict=True), path)
            with path.open("rb") as stream:
                content = stream.read(row["bytes"] + 1)
            self.assertEqual(len(content), row["bytes"])
            self.assertEqual(subject._sha(content), row["digest"])
            self.assertEqual(
                hashlib.sha1(
                    b"blob " + str(len(content)).encode() + b"\0" + content
                ).hexdigest(),
                row["git_blob"],
            )
        excerpt = manifest["linux_abi_excerpts"]
        path = _ROOT / excerpt["local_path"]
        self.assertEqual(path.resolve(strict=True), path)
        with path.open("rb") as stream:
            content = stream.read(65537)
        self.assertLessEqual(len(content), 65536)
        self.assertEqual(subject._sha(content), excerpt["digest"])
        self.assertEqual(excerpt["commit"], subject.LINUX_UAPI_COMMIT)
        self.assertFalse(excerpt["full_sources_retained"])
        self.assertEqual(manifest["layout"]["value_size"], subject.VALUE_SIZE)
        self.assertEqual(manifest["layout"]["error_order"], list(subject.ERROR_ORDER))
        self.assertEqual(
            (
                ctypes.sizeof(subject._ObjGet),
                ctypes.sizeof(subject._Info),
                ctypes.sizeof(subject._Lookup),
            ),
            (24, 16, 32),
        )
        self.assertEqual(
            (
                subject._ObjGet.path_fd.offset,
                subject._Info.info.offset,
                subject._Lookup.key.offset,
                subject._Lookup.value.offset,
                subject._Lookup.flags.offset,
            ),
            (16, 8, 8, 16, 24),
        )

    def test_readonly_commands_exact_buffers_and_decoding(self):
        info, raw = _info()
        values = bytearray(subject.VALUE_SIZE * 2)
        struct.pack_into("<Q", values, (7 + 2) * 8, 9)
        struct.pack_into("<Q", values, subject.VALUE_SIZE + (7 + 2) * 8, 4)
        commands = []

        def syscall(number, command, attributes):
            self.assertEqual(number, 321)
            commands.append(command)
            if command == subject._OBJ_GET:
                self.assertEqual(attributes.file_flags, 8 | 16384)
                self.assertEqual(attributes.path_fd, 41)
                self.assertEqual(attributes.bpf_fd, 0)
                self.assertEqual(ctypes.string_at(attributes.pathname), b"tg_stats_map")
                return 51
            self.assertEqual(
                attributes.bpf_fd if command == subject._INFO else attributes.map_fd, 51
            )
            if command == subject._INFO:
                self.assertEqual(attributes.info_len, 88)
                ctypes.memmove(attributes.info, raw, len(raw))
            else:
                self.assertEqual(command, subject._LOOKUP)
                self.assertEqual(ctypes.string_at(attributes.key, 4), b"\0" * 4)
                self.assertEqual(attributes.flags, 0)
                ctypes.memmove(attributes.value, bytes(values), len(values))
            return 0

        with (
            patch.object(subject, "_syscall", side_effect=syscall),
            patch.object(subject.os, "set_inheritable") as inheritable,
        ):
            self.assertEqual(subject._open_map(321, 41), 51)
            self.assertEqual(subject._map_info(321, 51), (info, raw))
            captured = subject._lookup(321, 51, [0, 2])
        inheritable.assert_called_once_with(51, False)
        self.assertEqual(commands, [7, 15, 1])
        self.assertEqual(captured, bytes(values))
        decoded = subject._decoded(captured, [0, 2])
        self.assertEqual(decoded["sent_failed_by_opcode"][1][2], 13)
        self.assertEqual(
            decoded["per_cpu_totals"],
            [{"cpu": 0, "sent_failed_total": 9}, {"cpu": 2, "sent_failed_total": 4}],
        )

    def test_fd_cleanup_and_unsupported_inputs_fail_closed(self):
        with (
            patch.object(subject, "_syscall", return_value=51),
            patch.object(
                subject.os, "set_inheritable", side_effect=OSError("synthetic")
            ),
            patch.object(subject.os, "close") as close,
        ):
            with self.assertRaises(OSError):
                subject._open_map(321, 41)
            close.assert_called_once_with(51)
        with (
            patch.object(subject.sys, "platform", "darwin"),
            patch.object(subject.ctypes, "CDLL") as library,
        ):
            with self.assertRaises(subject.TetragonStatsMapError):
                subject._platform()
            with self.assertRaises(subject.TetragonStatsMapError):
                subject._syscall(321, 2, subject._Lookup())
            library.assert_not_called()
        self.assertEqual(subject._cpu_ids(b"0-2,5\n"), [0, 1, 2, 5])
        for raw in (
            b"",
            b"0",
            b"0,0\n",
            b"2-1\n",
            b"0-256\n",
            b"0-999999999\n",
            b"1,0\n",
        ):
            with (
                self.subTest(raw=raw),
                self.assertRaises(subject.TetragonStatsMapError),
            ):
                subject._cpu_ids(raw)
        for info_len, offset, value in ((87, None, None), (88, 0, 1), (88, 12, 8)):

            def invalid(
                number,
                command,
                attributes,
                *,
                offset=offset,
                value=value,
                info_len=info_len,
            ):
                raw = bytearray(_info()[1])
                if offset is not None:
                    struct.pack_into("<I", raw, offset, value)
                ctypes.memmove(attributes.info, bytes(raw), len(raw))
                attributes.info_len = info_len
                return 0

            with (
                patch.object(subject, "_syscall", side_effect=invalid),
                self.assertRaises(subject.TetragonStatsMapError),
            ):
                subject._map_info(321, 51)

    def test_bound_snapshot_rechecks_every_authority_and_closes_all_fds(self):
        expected = _expected()
        metadata = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=0o40755,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=0,
            st_ctime_ns=0,
        )
        directory_identity = subject._identity(metadata)[:5]
        values = b"\0" * (subject.VALUE_SIZE * 2)
        for mutation in (
            None,
            "map",
            "pin",
            "cpu",
            "sensor",
            "boot",
            "ancestry",
            "lookup",
            "topology",
        ):
            reads = {subject._BOOT: 0, subject._POSSIBLE: 0}

            def small(path, maximum, *, reads=reads, mutation=mutation, **kwargs):
                reads[path] += 1
                if path == subject._BOOT:
                    return (
                        (
                            "changed"
                            if mutation == "boot" and reads[path] == 2
                            else expected["boot_id"]
                        )
                        + "\n"
                    ).encode()
                return b"0\n" if mutation == "cpu" and reads[path] == 2 else b"0,2\n"

            infos = [_info(), _info(), _info()]
            if mutation == "map":
                infos[-1] = ({**infos[-1][0], "id": 99}, infos[-1][1])
            sensors = [expected["sensor"], {**expected["sensor"]}]
            if mutation == "sensor":
                sensors[-1]["start_time_ticks"] += 1
            with self.subTest(mutation=mutation), ExitStack() as stack:
                stack.enter_context(
                    patch.object(subject, "_platform", return_value=321)
                )
                stack.enter_context(patch.object(subject, "_small", side_effect=small))
                views = [{"inert": 1}] * 4
                if mutation == "topology":
                    views[2] = {"inert": 2}
                stack.enter_context(
                    patch.object(subject, "_topology_view", side_effect=views)
                )
                stack.enter_context(
                    patch.object(subject.os, "pidfd_open", return_value=70, create=True)
                )
                live = stack.enter_context(patch.object(subject, "_live"))
                stack.enter_context(
                    patch.object(subject, "_sensor", side_effect=sensors)
                )
                stack.enter_context(
                    patch.object(
                        subject,
                        "_directories",
                        return_value=[(_PIN.parent, 41, directory_identity)],
                    )
                )
                stack.enter_context(
                    patch.object(
                        subject,
                        "_pin_metadata",
                        side_effect=[(1,), (2,) if mutation == "pin" else (1,)],
                    )
                )
                stack.enter_context(
                    patch.object(subject, "_open_map", side_effect=[71, 72])
                )
                stack.enter_context(
                    patch.object(subject, "_map_info", side_effect=infos)
                )
                lookup = stack.enter_context(
                    patch.object(
                        subject,
                        "_lookup",
                        return_value=values,
                        side_effect=OSError("synthetic")
                        if mutation == "lookup"
                        else None,
                    )
                )
                stack.enter_context(
                    patch.object(subject.os, "fstat", return_value=metadata)
                )
                changed = SimpleNamespace(**{**vars(metadata), "st_ino": 99})
                stack.enter_context(
                    patch.object(
                        Path,
                        "lstat",
                        return_value=changed if mutation == "ancestry" else metadata,
                    )
                )
                closed = stack.enter_context(patch.object(subject.os, "close"))
                if mutation:
                    with self.assertRaises(subject.TetragonStatsMapError):
                        subject.snapshot_tetragon_stats_map(_PIN, expected=expected)
                else:
                    result = subject.snapshot_tetragon_stats_map(
                        _PIN, expected=expected
                    )
                    self.assertEqual(result["values"]["digest"], subject._sha(values))
                    self.assertEqual(result["decoded"]["sent_failed_total"], 0)
                    self.assertFalse(result["sensor_health_verified"])
                    self.assertFalse(result["sensor_map_ownership_verified"])
                    self.assertIn(
                        "SEQUENTIAL_PER_CPU_COPY_NOT_ATOMIC_SNAPSHOT",
                        result["limitations"],
                    )
                    self.assertEqual(live.call_count, 2)
                if mutation == "topology":
                    lookup.assert_not_called()
                self.assertEqual(
                    {item.args[0] for item in closed.call_args_list},
                    {70, 71} if mutation in {"lookup", "topology"} else {70, 71, 72},
                )

    def test_topology_view_requires_unsubstituted_sysfs_and_stable_namespace(self):
        root = b"1 0 0:1 / / rw - overlay overlay rw\n"
        sysfs = b"2 1 0:2 / /sys ro,nosuid,nodev,noexec - sysfs sysfs ro\n"
        other = b"3 1 0:3 / /unrelated\\040name rw - tmpfs tmpfs rw\n"
        with (
            patch.object(subject, "_small", return_value=root + sysfs + other),
            patch.object(subject.os, "readlink", return_value="mnt:[123]"),
        ):
            value = subject._topology_view()
            self.assertEqual(value["mount_namespace"], "mnt:[123]")
            self.assertEqual(value["sysfs_mount"]["digest"], subject._sha(sysfs[:-1]))
        cases = (
            root,
            root + sysfs + sysfs,
            root
            + sysfs
            + b"3 2 0:3 / /sys/devices/system/cpu/possible ro - tmpfs tmpfs ro\n",
            root + sysfs.replace(b" / /sys", b" /subtree /sys"),
            root + sysfs.replace(b" - sysfs ", b" - tmpfs "),
            root + sysfs + b"3 2 0:3 / /bad\\999 rw - tmpfs tmpfs rw\n",
            b"malformed\n",
            root + sysfs.rstrip(b"\n"),
        )
        for raw in cases:
            with (
                self.subTest(raw=raw),
                patch.object(subject, "_small", return_value=raw),
                patch.object(subject.os, "readlink", return_value="mnt:[123]"),
                self.assertRaises(subject.TetragonStatsMapError),
            ):
                subject._topology_view()
        with (
            patch.object(subject, "_small", return_value=root + sysfs),
            patch.object(
                subject.os, "readlink", side_effect=["mnt:[123]", "mnt:[124]"]
            ),
            self.assertRaises(subject.TetragonStatsMapError),
        ):
            subject._topology_view()

    def test_pidfd_must_identify_caller_sensor(self):
        poller = Mock()
        poller.poll.return_value = []
        with (
            patch.object(subject.select, "poll", return_value=poller),
            patch.object(subject, "_small", return_value=b"Pid:\t74\n"),
            self.assertRaisesRegex(subject.TetragonStatsMapError, "pidfd"),
        ):
            subject._live(70, 73)

    def test_sensor_parser_binds_credentials_executable_and_namespaces(self):
        executable = b"inert unit fixture, never executed\n"
        expected = {
            **_expected()["sensor"],
            "uid": 1001,
            "gid": 1002,
            "executable_digest": subject._sha(executable),
        }
        metadata = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=0o100555,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=len(executable),
            st_mtime_ns=0,
            st_ctime_ns=0,
        )
        for mutation in (None, "uid", "gid", "stat", "cgroup", "writable_executable"):

            def small(path, maximum, *, expected_uid, mutation=mutation):
                self.assertEqual(expected_uid, 1001)
                if path.name == "stat":
                    tail = [
                        b"S",
                        *([b"0"] * 18),
                        b"bad" if mutation == "stat" else b"1234",
                    ]
                    return b"73 (tetragon fixture) " + b" ".join(tail) + b"\n"
                if path.name == "status":
                    return (
                        "Uid:\t1001 "
                        + ("9" if mutation == "uid" else "1001")
                        + " 1001 1001\nGid:\t1002 "
                        + ("9" if mutation == "gid" else "1002")
                        + " 1002 1002\n"
                    ).encode()
                self.assertEqual(path.name, "cgroup")
                return (
                    "0::"
                    + expected["cgroup"]
                    + "\n"
                    + ("0::/other\n" if mutation == "cgroup" else "")
                ).encode()

            actual_metadata = (
                SimpleNamespace(**{**vars(metadata), "st_mode": 0o100777})
                if mutation == "writable_executable"
                else metadata
            )
            with self.subTest(mutation=mutation), ExitStack() as stack:
                reads = stack.enter_context(
                    patch.object(subject, "_small", side_effect=small)
                )
                opened = stack.enter_context(
                    patch.object(subject.os, "open", return_value=90)
                )
                stack.enter_context(
                    patch.object(subject.os, "fstat", return_value=actual_metadata)
                )
                stack.enter_context(
                    patch.object(subject.os, "read", side_effect=[executable, b""])
                )
                stack.enter_context(patch.object(Path, "stat", return_value=metadata))
                stack.enter_context(
                    patch.object(
                        subject.os,
                        "readlink",
                        side_effect=lambda path: expected["namespaces"][path.name],
                    )
                )
                closed = stack.enter_context(patch.object(subject.os, "close"))
                if mutation:
                    with self.assertRaises(subject.TetragonStatsMapError):
                        subject._sensor(expected)
                else:
                    self.assertEqual(subject._sensor(expected), expected)
                    self.assertEqual(reads.call_count, 3)
                self.assertEqual(closed.call_count, opened.call_count)
        with (
            patch.object(subject.os, "open", return_value=90),
            patch.object(subject.os, "fstat", return_value=metadata),
            patch.object(subject.os, "close") as closed,
            patch.object(subject.os, "read") as read,
        ):
            with self.assertRaisesRegex(
                subject.TetragonStatsMapError, "unsafe virtual"
            ):
                subject._small(Path("/proc/73/status"), 16384, expected_uid=1001)
            read.assert_not_called()
            closed.assert_called_once_with(90)

    def test_pin_ancestry_nofollow_owner_and_failure_cleanup(self):
        metadata = SimpleNamespace(
            st_dev=1,
            st_ino=2,
            st_mode=0o40755,
            st_uid=0,
            st_gid=0,
            st_nlink=1,
            st_size=0,
            st_mtime_ns=0,
            st_ctime_ns=0,
        )
        for mutation in ("owner", "symlink"):
            descriptors = (
                [10, 11, 12, 13]
                if mutation == "owner"
                else [10, 11, 12, OSError(errno.ELOOP, "synthetic symlink")]
            )

            def fstat(fd, *, mutation=mutation):
                return (
                    SimpleNamespace(**{**vars(metadata), "st_uid": 1001})
                    if mutation == "owner" and fd == 13
                    else metadata
                )

            with (
                self.subTest(mutation=mutation),
                patch.object(subject.os, "open", side_effect=descriptors) as opened,
                patch.object(subject.os, "fstat", side_effect=fstat),
                patch.object(subject.os, "close") as closed,
            ):
                with (
                    self.assertRaises((subject.TetragonStatsMapError, OSError)),
                    ExitStack() as held,
                ):
                    subject._directories(_PIN, held)
                self.assertEqual(
                    [call.args[0] for call in closed.call_args_list],
                    [13, 12, 11, 10] if mutation == "owner" else [12, 11, 10],
                )
                for call in opened.call_args_list:
                    self.assertTrue(call.args[1] & subject.os.O_NOFOLLOW)
                    self.assertTrue(call.args[1] & subject.os.O_DIRECTORY)
                self.assertEqual(
                    [call.kwargs["dir_fd"] for call in opened.call_args_list],
                    [None, 10, 11, 12],
                )
        with patch.object(subject.os, "open") as opened, ExitStack() as held:
            with self.assertRaises(subject.TetragonStatsMapError):
                subject._directories(Path("/tmp/tg_stats_map"), held)
            opened.assert_not_called()


if __name__ == "__main__":
    unittest.main()
