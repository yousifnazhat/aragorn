"""Synthetic syscall fixtures only: no live PIDFD, BPF, sensor, or VM calls."""

from __future__ import annotations

import copy
import ctypes
import errno
import struct
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from aragorn import runtime_tetragon_program_map as subject


def _map():
    values = [
        6,
        19,
        4,
        subject.stats.VALUE_SIZE,
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
    info = dict(zip(subject.stats._MAP_FIELDS, values, strict=True))
    raw = struct.pack(
        "<6I16s2I2Q4IQ",
        6,
        19,
        4,
        subject.stats.VALUE_SIZE,
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
    return info, raw


def _binding():
    return {
        "stats_map_binding": {
            "boot_id": "11111111-2222-3333-4444-555555555555",
            "possible_cpus_digest": "sha256:" + "e" * 64,
            "map": _map()[0],
            "sensor": {
                "pid": 73,
                "start_time_ticks": 1234,
                "uid": 0,
                "gid": 0,
                "cgroup": "/owned/synthetic",
                "executable_digest": "sha256:" + "a" * 64,
                "namespaces": {
                    name: name + ":[123]" for name in subject.stats._NAMESPACES
                },
            },
        },
        "sensor_fds": {"program": 31, "map": 32, "link": 33},
        "program": {
            "type": 2,
            "id": 29,
            "tag": "0123456789abcdef",
            "name": "event_exit_acct",
            "load_time": 987654321,
            "created_by_uid": 0,
            "map_ids": [19, 20],
        },
        "link": {
            "type": 7,
            "id": 39,
            "prog_id": 29,
            "perf_type": 3,
            "symbol": "acct_process",
            "offset": 0,
            "addr": 0,
        },
    }


class _Kernel:
    """Inert ABI renderer, deliberately never forwarding to the kernel."""

    def __init__(self, case, mutate=None):
        self.case, self.mutate = case, mutate
        self.calls = []

    def __call__(self, number, command, attrs):
        case = self.case
        case.assertEqual((number, command, type(attrs)), (321, 15, subject.stats._Info))
        kind = {
            101: "program",
            102: "map",
            103: "link",
            111: "program",
            112: "map",
            113: "link",
        }[attrs.bpf_fd]
        self.calls.append((kind, attrs.bpf_fd))
        binding = _binding()
        size = {"program": 232, "map": 88, "link": 64}[kind]
        case.assertEqual(attrs.info_len, size)
        raw = bytearray(ctypes.string_at(attrs.info, size))
        extra = None
        if kind == "program":
            capacity, pointer = struct.unpack_from("<IQ", raw, 52)
            case.assertEqual(capacity, subject.MAX_MAP_IDS)
            case.assertTrue(pointer)
            clean = bytearray(raw)
            clean[52:64] = b"\0" * 12
            case.assertEqual(clean, b"\0" * size)
            program = binding["program"]
            struct.pack_into(
                "<II8s", raw, 0, 2, program["id"], bytes.fromhex(program["tag"])
            )
            struct.pack_into("<QII", raw, 40, program["load_time"], 0, 2)
            raw[64:80] = program["name"].encode().ljust(16, b"\0")
            struct.pack_into("<I", raw, 84, 1)
            struct.pack_into("<3Q", raw, 192, len(self.calls) * 10, len(self.calls), 0)
            extra = bytearray(struct.pack("<2I", *program["map_ids"]))
        elif kind == "link":
            pointer, capacity = struct.unpack_from("<QI", raw, 24)
            case.assertEqual(capacity, subject.SYMBOL_CAPACITY)
            case.assertTrue(pointer)
            clean = bytearray(raw)
            clean[24:36] = b"\0" * 12
            case.assertEqual(clean, b"\0" * size)
            struct.pack_into("<3I", raw, 0, 7, 39, 29)
            struct.pack_into("<I", raw, 16, 3)
            struct.pack_into("<Q", raw, 48, len(self.calls))
            extra = bytearray(b"acct_process".ljust(capacity, b"\0"))
        else:
            case.assertEqual(raw, b"\0" * size)
            raw = bytearray(_map()[1])
        if self.mutate:
            self.mutate(kind, attrs, raw, extra)
        if extra is not None:
            ctypes.memmove(pointer, bytes(extra), len(extra))
        ctypes.memmove(attrs.info, bytes(raw), len(raw))
        return 0


def _harness(case, *, kernel=None, duplicate=None, sensor=None, boot=None):
    stack = ExitStack()
    binding = _binding()
    stack.enter_context(patch.object(subject.stats, "_platform", return_value=321))
    stack.enter_context(
        patch.object(subject.os, "pidfd_open", return_value=90, create=True)
    )
    close = stack.enter_context(patch.object(subject.os, "close"))
    live = stack.enter_context(patch.object(subject.stats, "_live"))
    measure = stack.enter_context(
        patch.object(
            subject.stats,
            "_sensor",
            side_effect=sensor,
            return_value=binding["stats_map_binding"]["sensor"],
        )
    )
    raw_boot = (binding["stats_map_binding"]["boot_id"] + "\n").encode()
    small = stack.enter_context(
        patch.object(subject.stats, "_small", side_effect=boot, return_value=raw_boot)
    )
    dup = stack.enter_context(
        patch.object(
            subject,
            "_duplicate",
            side_effect=duplicate or [101, 102, 103, 111, 112, 113],
        )
    )
    fake = kernel or _Kernel(case)
    stack.enter_context(patch.object(subject.stats, "_syscall", side_effect=fake))
    return stack, close, live, measure, small, dup, fake


class TetragonProgramMapTests(unittest.TestCase):
    def test_exact_info_abi_bounded_output_and_no_mutating_commands(self):
        fake = _Kernel(self)
        with patch.object(subject.stats, "_syscall", side_effect=fake):
            program = subject._program_info(321, 101)
            link = subject._link_info(321, 103)
            map_row = subject._observe(321, 102, "map")
        self.assertEqual(program["identity"], _binding()["program"])
        self.assertEqual(link["identity"], _binding()["link"])
        self.assertEqual(map_row["identity"], _binding()["stats_map_binding"]["map"])
        self.assertEqual(program["raw_info"]["bytes"], 232)
        self.assertEqual(program["raw_map_ids"]["bytes"], 8)
        self.assertEqual(link["raw_info"]["bytes"], 64)
        self.assertEqual(link["raw_symbol"]["bytes"], 128)
        self.assertEqual(fake.calls, [("program", 101), ("link", 103), ("map", 102)])

    def test_program_inventory_truncation_duplicate_zero_and_abi_refused(self):
        def change(kind, attrs, raw, extra, failure):
            if failure == "short":
                attrs.info_len = 231
            elif failure == "duplicate":
                struct.pack_into("<I", extra, 4, 19)
            elif failure == "zero_id":
                struct.pack_into("<I", extra, 4, 0)
            elif failure == "type":
                struct.pack_into("<I", raw, 0, 5)
            elif failure == "name":
                raw[64:80] = b"x" * 16
            else:
                struct.pack_into(
                    "<I", raw, 52, 0 if failure == "empty" else subject.MAX_MAP_IDS + 1
                )

        for failure in (
            "empty",
            "oversize",
            "duplicate",
            "zero_id",
            "short",
            "type",
            "name",
        ):
            fake = _Kernel(self, lambda *args, f=failure: change(*args, f))
            with (
                self.subTest(failure=failure),
                patch.object(subject.stats, "_syscall", side_effect=fake),
            ):
                with self.assertRaises(subject.TetragonProgramMapError):
                    subject._program_info(321, 101)
            self.assertEqual(len(fake.calls), 1)

    def test_link_legacy_wrong_subtype_symbol_offset_and_short_buffer_refused(self):
        def change(kind, attrs, raw, extra, failure):
            if failure == "symbol":
                extra[:] = b"unbound".ljust(subject.SYMBOL_CAPACITY, b"\0")
            elif failure == "not_nul":
                extra[:] = b"x" * subject.SYMBOL_CAPACITY
            elif failure == "short":
                attrs.info_len = 63
            else:
                offset, value = {
                    "type": (0, 1),
                    "subtype": (16, 4),
                    "offset": (36, 1),
                    "capacity": (32, 0),
                }[failure]
                struct.pack_into("<I", raw, offset, value)

        for failure in (
            "type",
            "subtype",
            "offset",
            "capacity",
            "symbol",
            "not_nul",
            "short",
        ):
            fake = _Kernel(self, lambda *args, f=failure: change(*args, f))
            with (
                self.subTest(failure=failure),
                patch.object(subject.stats, "_syscall", side_effect=fake),
            ):
                with self.assertRaises(subject.TetragonProgramMapError):
                    subject._link_info(321, 103)
            self.assertEqual(len(fake.calls), 1)

    def test_pidfd_getfd_exact_flags_permission_refusal_and_fd_cleanup(self):
        library = Mock()
        library.syscall.return_value = 51
        with (
            patch.object(subject.stats, "_platform", return_value=321),
            patch.object(subject.ctypes, "CDLL", return_value=library) as cdll,
            patch.object(subject.os, "set_inheritable") as set_inheritable,
            patch.object(subject.os, "get_inheritable", return_value=False),
            patch.object(subject.os, "close") as close,
        ):
            self.assertEqual(subject._duplicate(90, 31), 51)
            self.assertEqual(
                [arg.value for arg in library.syscall.call_args.args], [438, 90, 31, 0]
            )
            self.assertIs(library.syscall.restype, ctypes.c_long)
            cdll.assert_called_once_with(None, use_errno=True)
            set_inheritable.assert_called_once_with(51, False)
            close.assert_not_called()
            set_inheritable.side_effect = OSError("synthetic descriptor failure")
            with self.assertRaises(OSError):
                subject._duplicate(90, 31)
            close.assert_called_once_with(51)
            library.syscall.return_value = -1
            with patch.object(subject.ctypes, "get_errno", return_value=errno.EPERM):
                with self.assertRaisesRegex(subject.TetragonProgramMapError, "errno=1"):
                    subject._duplicate(90, 31)
            self.assertEqual(close.call_count, 1)

    def test_bound_association_rechecks_original_slots_and_closes_before_return(self):
        harness = _harness(self)
        stack, close, live, measure, small, duplicate, fake = harness
        with stack:
            result = subject.snapshot_tetragon_program_map_association(
                expected=_binding()
            )
            self.assertEqual(
                sorted(call.args[0] for call in close.call_args_list),
                [90, 101, 102, 103, 111, 112, 113],
            )
            self.assertEqual(measure.call_count, 2)
            self.assertEqual(small.call_count, 2)
            self.assertGreaterEqual(live.call_count, 14)
            self.assertEqual(
                [call.args for call in duplicate.call_args_list],
                [(90, fd) for fd in [31, 32, 33, 31, 32, 33]],
            )
        self.assertEqual(len(fake.calls), 9)
        self.assertEqual(result["status"], "OBSERVED_ASSOCIATION")
        self.assertTrue(result["sensor_fd_association_observed"])
        for field in (
            "program_execution_verified",
            "sensor_uses_map_verified",
            "attachment_enabled_verified",
            "sensor_health_verified",
            "delivery_completeness_verified",
            "runtime_attribution_verified",
            "run_conformance_eligible",
            "phase3_eligible",
            "production_activation_eligible",
        ):
            self.assertIs(result[field], False)
        self.assertIn(
            "DUPLICATED_FDS_EXTEND_OBJECT_LIFETIME_UNTIL_CLOSED", result["limitations"]
        )
        self.assertEqual(result["caller_binding"], _binding())
        self.assertNotEqual(
            result["objects_before"]["program"]["diagnostic_counters"],
            result["held_objects_after"]["program"]["diagnostic_counters"],
        )

    def test_original_slot_replacement_held_drift_and_disappearance_fail_closed(self):
        for failure in ("replaced", "map_inventory", "stable_field", "disappeared"):

            def change(kind, attrs, raw, extra):
                if failure == "replaced" and attrs.bpf_fd == 111:
                    struct.pack_into("<I", raw, 4, 30)
                if kind == "program" and len(fake.calls) > 3:
                    if failure == "map_inventory":
                        struct.pack_into("<I", extra, 4, 21)
                    if failure == "stable_field":
                        struct.pack_into("<I", raw, 20, 999)

            fake = _Kernel(self, change)
            dup = (
                [101, 102, 103, OSError("synthetic missing original slot")]
                if failure == "disappeared"
                else None
            )
            harness = _harness(self, kernel=fake, duplicate=dup)
            stack, close = harness[:2]
            with self.subTest(failure=failure), stack:
                with self.assertRaises(subject.TetragonProgramMapError):
                    subject.snapshot_tetragon_program_map_association(
                        expected=_binding()
                    )
                closed = [call.args[0] for call in close.call_args_list]
                self.assertTrue({90, 101, 102, 103}.issubset(closed))
                self.assertEqual(len(closed), len(set(closed)))

    def test_identity_or_boot_change_and_permission_error_never_publish(self):
        sensor = _binding()["stats_map_binding"]["sensor"]
        raw_boot = (_binding()["stats_map_binding"]["boot_id"] + "\n").encode()
        for kwargs in (
            {"sensor": [sensor, {**sensor, "start_time_ticks": 999}]},
            {"boot": [raw_boot, b"changed\n"]},
            {"duplicate": [OSError(errno.EPERM, "synthetic denial")]},
        ):
            harness = _harness(self, **kwargs)
            with self.subTest(change=list(kwargs)), harness[0]:
                with self.assertRaises(subject.TetragonProgramMapError):
                    subject.snapshot_tetragon_program_map_association(
                        expected=_binding()
                    )
                self.assertIn(90, [call.args[0] for call in harness[1].call_args_list])

    def test_invalid_caller_binding_refused_before_any_runtime_operation(self):
        changes = (
            lambda value: value["sensor_fds"].update(link=31),
            lambda value: value["sensor_fds"].update(program=True),
            lambda value: value["program"].update(map_ids=[20]),
            lambda value: value["program"].update(map_ids=[19, 19]),
            lambda value: value["link"].update(symbol="anything_else"),
            lambda value: value["link"].update(prog_id=1),
            lambda value: value["link"].update(perf_type=5),
            lambda value: value.update(extra=True),
        )
        for change in changes:
            binding = copy.deepcopy(_binding())
            change(binding)
            with patch.object(subject.stats, "_platform") as platform:
                with self.assertRaises(subject.TetragonProgramMapError):
                    subject.snapshot_tetragon_program_map_association(expected=binding)
                platform.assert_not_called()


if __name__ == "__main__":
    unittest.main()
