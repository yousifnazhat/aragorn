"""B78 synthetic ABI buffers only; no kernel, driver, root or data-device access."""
import json
import os
import stat
import struct
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from unittest.mock import patch

from aragorn import pi_core_state_dm_mapping as dm
from aragorn.pi_core_state_mounts import ANCHOR, direct_mount_inventory


MOUNTS = (b"1 99 7:0 / / ro - squashfs /dev/root ro\n"
          b"2 1 0:5 / /dev rw - devtmpfs devtmpfs rw\n"
          b"3 1 253:7 / /run/aragorn-pilot-state rw - ext4 /dev/dm-0 rw\n")


def _linux_dev(text):
    maj, minor = map(int, text.split(":"))
    return (maj << 8) | ((minor >> 8) << 20) | (minor % 256)


def _output(info, device, backing, event, opens=1):
    raw = bytearray(512)
    start, size = 312, 353 if info else 328
    struct.pack_into("<III", raw, 0, 4, 50, 0)
    struct.pack_into("<IIIiIIIQ", raw, 12, size, start, 1, opens, 32 + (2048 if info else 0),
                     event, 0, _linux_dev(device))
    raw[48:62] = b"PRIVATE-MAPPER"
    raw[176:188] = b"PRIVATE-UUID"
    if info:
        struct.pack_into("<QQiI16s", raw, start, 0, 4096, 0, 48, b"crypt")
    else:
        struct.pack_into("<IIQ", raw, start, 1, 0, _linux_dev(backing))
    return raw


def sample_record(device="253:7", backing="259:0", event_nr=12):
    """Pure offline projection for use in other B78 reader integration checks."""
    record = {"schema": "aragorn-pi-core-dm-live-mapping/v1"}
    for index, name in enumerate(("before", "dependencies", "after")):
        info = name != "dependencies"
        buf = _output(info, device, backing, event_nr, opens=index + 1)
        record[name] = {"header_hex": buf[:48].hex(), "payload_hex": buf[312:353 if info else 328].hex()}
    return record


def _verified(record, device="253:7", backing="259:0"):
    return dm.verify_dm_mapping(record, expected_device=device, expected_backing_device=backing)


def _change(record, section, field, offset, fmt, new):
    b = bytearray.fromhex(record[section][field])
    struct.pack_into(fmt, b, offset, new)
    record[section][field] = b.hex()


class DMMapping(unittest.TestCase):
    def test_fixed_read_only_sequence_excludes_names_private_data_and_replays(self):
        calls = []
        def dispatch(fd, cmd, b, mutate):
            self.assertEqual((fd, mutate, len(b)), (901, True, 512))
            self.assertEqual(struct.unpack_from("<III", b), (4, 50, 0))
            self.assertEqual(struct.unpack_from("<IIIiIIIQ", b, 12),
                             (512, 312, 0, 0, 2048 if cmd == 0xc138fd0c else 0, 0, 0, _linux_dev("253:700")))
            self.assertFalse(any(b[48:]))
            calls.append(cmd)
            b[:] = _output(cmd == 0xc138fd0c, "253:700", "259:1024", 18, len(calls))
            return 0
        with patch.object(dm, "_control", return_value=nullcontext(901)) as control, \
             patch.object(dm.kernel, "_check") as check, patch.object(dm.fcntl, "ioctl", side_effect=dispatch):
            got = dm.capture_dm_mapping("253:700", "259:1024", deadline=88)
        self.assertEqual(calls, [0xc138fd0c, 0xc138fd0b, 0xc138fd0c])
        self.assertEqual(got, sample_record("253:700", "259:1024", 18))
        control.assert_called_once_with("253:700", 88)
        self.assertTrue(all(c.args == (88,) for c in check.call_args_list))
        self.assertNotIn(b"PRIVATE".hex(), json.dumps(got))
        self.assertEqual(_verified(got, "253:700", "259:1024"), dict(type="dm-crypt", device="253:700",
                         backing_devices=["259:1024"], start_sector=0, length_sectors=4096, event_nr=18))

    def test_invalid_scope_does_not_open_control(self):
        with patch.object(dm, "_control") as control:
            for dev, slave in (("0253:1", "8:1"), ("253:2", "253:2"), ("4096:1", "8:1"),
                               ("8:4", "8:1048576"), ("0:1", "8:1"), ("253:1", "/dev/sda")):
                with self.subTest(dev=dev, slave=slave), self.assertRaises(ValueError):
                    dm.capture_dm_mapping(dev, slave, deadline=1)
        control.assert_not_called()

    def test_header_and_generation_must_bind_both_edges_and_dependency(self):
        cases = [(0, 5), (4, 49), (12, 352), (16, 320), (20, 0), (20, 2), (32, 13), (36, 1), (40, 0)]
        for offset, val in cases:
            record = sample_record()
            _change(record, "before", "header_hex", offset, "<I", val)
            with self.subTest(offset=offset, value=val), self.assertRaises(ValueError):
                _verified(record)
        for section in ("after", "dependencies"):
            for offset, val in ((8, 1), (24, 0), (24, 0xffffffff), (32, 13)):
                record = sample_record()
                _change(record, section, "header_hex", offset, "<I", val)
                with self.subTest(section=section, offset=offset), self.assertRaises(ValueError):
                    _verified(record)
        for offset, future in ((4, 51), (8, 1)):
            record = sample_record()
            for name in ("before", "dependencies", "after"):
                _change(record, name, "header_hex", offset, "<I", future)
            with self.subTest(unreviewed_abi=(offset, future)), self.assertRaises(ValueError):
                _verified(record)

    def test_table_flags_are_closed_for_each_operation(self):
        for section in ("before", "dependencies"):
            for bits in (0, 1, 2, 16, 64, 256, 4096, 1 << 17, 1 << 18, 1 << 19, 1 << 31):
                record = sample_record()
                flags = ((2080 if section == "before" else 32) | bits) if bits else 0
                _change(record, section, "header_hex", 28, "<I", flags)
                with self.subTest(section=section, bits=bits), self.assertRaises(ValueError):
                    _verified(record)

    def test_requires_single_approved_dependency_and_complete_single_extent(self):
        for section, offset, fmt, val in (("dependencies", 0, "<I", 2), ("dependencies", 4, "<I", 1),
                ("dependencies", 8, "<Q", _linux_dev("253:7")), ("dependencies", 8, "<Q", 1 << 40),
                ("before", 0, "<Q", 1), ("before", 8, "<Q", 0), ("before", 8, "<Q", 1 << 55),
                ("before", 8, "<Q", 4095), ("before", 16, "<i", -1), ("before", 20, "<I", 40),
                ("before", 24, "<16s", b"linear"), ("after", 40, "B", 3)):
            record = sample_record()
            _change(record, section, "payload_hex", offset, fmt, val)
            with self.subTest(section=section, offset=offset, value=val), self.assertRaises(ValueError):
                _verified(record)
        for d, b in (("253:8", "259:0"), ("253:7", "259:1")):
            with self.assertRaises(ValueError):
                _verified(sample_record(), d, b)

    def test_strict_raw_projection_does_not_accept_a_self_report_or_private_suffix(self):
        record = sample_record()
        for changes in ({"pass": True}, {"schema": "other"}, {"dependencies": None},
                        {"before": record["before"] | {"name": "not collected"}},
                        {"before": record["before"] | {"payload_hex": record["before"]["payload_hex"] + "00"}},
                        {"before": record["before"] | {"header_hex": record["before"]["header_hex"].upper()}},
                        {"before": record["before"] | {"header_hex": "x" * 96}}):
            with self.subTest(fields=tuple(changes)), self.assertRaises(ValueError):
                _verified(record | changes)

    def test_unknown_status_text_short_buffer_and_failed_call_not_retained_or_retried(self):
        for mode in ("private text", "too long", "ioctl error", "nonzero"):
            def result(fd, cmd, b, mutate):
                b[:] = _output(True, "253:7", "259:0", 8)
                if mode == "private text":
                    b[352:358] = b"SECRET"
                if mode == "too long":
                    struct.pack_into("<I", b, 12, 10000)
                if mode == "ioctl error":
                    raise OSError("kernel refused")
                return int(mode == "nonzero")
            with self.subTest(mode=mode), patch.object(dm, "_control", return_value=nullcontext(7)), \
                 patch.object(dm.kernel, "_check"), patch.object(dm.fcntl, "ioctl", side_effect=result) as call:
                with self.assertRaises((ValueError, OSError)) as caught:
                    dm.capture_dm_mapping("253:7", "259:0", deadline=7)
                self.assertNotIn("SECRET", str(caught.exception))
                self.assertEqual(call.call_count, 1)
                self.assertFalse(any(call.call_args.args[2]))  # temporary ioctl storage wiped on refusal

    def test_custody_and_original_deadline_must_close_before_return(self):
        @contextmanager
        def changed(*args):
            yield 4
            raise ValueError("control changed")
        r = sample_record()
        with patch.object(dm, "_control", changed), patch.object(dm, "_query", side_effect=[
                r[k] for k in ("before", "dependencies", "after")]), self.assertRaisesRegex(ValueError, "changed"):
            dm.capture_dm_mapping("253:7", "259:0", deadline=8)
        with patch.object(dm, "_control", return_value=nullcontext(7)), \
             patch.object(dm.kernel, "_check", side_effect=ValueError("deadline")), \
             patch.object(dm.fcntl, "ioctl") as call, self.assertRaisesRegex(ValueError, "deadline"):
            dm.capture_dm_mapping("253:7", "259:0", deadline=8)
        call.assert_not_called()

    def test_refuses_forged_or_overmounted_control_parent_and_wrong_manager_mount(self):
        rows = direct_mount_inventory(MOUNTS)
        def identity(mnt, dev, mode, rdev="0:0"):
            return dict(mnt_id=mnt, dev=dev, mode=mode, rdev=rdev, uid=0, gid=0)
        d = identity(2, "0:5", stat.S_IFDIR | 0o755)
        observed = {"root": identity(1, "7:0", stat.S_IFDIR | 0o755), "dev": d, "mapper": d.copy(),
                    "control": identity(2, "0:5", stat.S_IFCHR | 0o600, "10:236")}
        dm._nodes(observed, rows, 0x01021994, "253:7")
        for key, diff in (("control", {"rdev": "10:237"}), ("control", {"mode": stat.S_IFBLK | 0o600}),
                          ("control", {"mnt_id": 44}), ("mapper", {"gid": 1234}),
                          ("mapper", {"mode": stat.S_IFDIR | 0o777}), ("dev", {"dev": "0:4"}),
                          ("root", {"uid": 1}), ("dev", {"mode": stat.S_IFLNK})):
            with self.subTest(key=key, diff=diff), self.assertRaises(ValueError):
                dm._nodes(observed | {key: observed[key] | diff}, rows, 0x01021994, "253:7")
        for changed_rows, magic, dev in ((rows | {"/dev/mapper": rows["/dev"]}, 0x01021994, "253:7"),
                (rows | {"/dev/mapper/control": rows["/dev"]}, 0x01021994, "253:7"),
                (rows | {"/dev": rows["/dev"]._replace(filesystem=b"tmpfs")}, 0x01021994, "253:7"),
                (rows, 0x9fa0, "253:7"), (rows, 0x01021994, "253:8"),
                (rows | {ANCHOR: rows[ANCHOR]._replace(root="/other")}, 0x01021994, "253:7")):
            with self.assertRaises(ValueError):
                dm._nodes(observed, changed_rows, magic, dev)

    def test_only_pinned_misc_inode_reopened_and_named_paths_rechecked(self):
        for swap in ("none", "wrong reopened driver", "renamed parent"):
            with self.subTest(swap=swap), ExitStack() as mocks:
                def fake(fn, **kwargs):
                    return mocks.enter_context(patch.object(dm.kernel, fn, **kwargs))
                fake("_platform")
                fake("_check")
                fake("_proc", return_value=(30, 2))
                fake("_role", side_effect=lambda stack, proc, pid, pm: (pid, 31))
                fake("_proc_child", return_value=32)
                fake("_frame", return_value=(None, {"pid": 7, "uid": 0}, 21, None))
                fake("_read", return_value=MOUNTS)
                fake("_filesystem", return_value=0x01021994)
                leaves = {(21, "dev", True): 22, (22, "mapper", True): 23, (23, "control", False): 24}
                fake("_pin", side_effect=lambda stack, parent, name, directory=False: leaves[parent, name, directory])
                magic = fake("_magic", return_value=25)
                renamed = False
                def stats(fd, *, owner):
                    self.assertTrue(owner)
                    node = fd in (24, 25)
                    return dict(mnt_id=1 if fd == 21 else 2, dev="7:0" if fd == 21 else "0:5", uid=0, gid=0,
                                mode=stat.S_IFCHR | 0o600 if node else stat.S_IFDIR | 0o755,
                                rdev="10:236" if node else "0:0", ino=24 if node else (fd + int(renamed and fd == 23))) | (
                                {"rdev": "9:1"} if fd == 25 and swap == "wrong reopened driver" else {})
                fake("_stat", side_effect=stats)
                verdict = nullcontext() if swap == "none" else self.assertRaises(ValueError)
                with verdict, dm._control("253:7", 10) as control:
                    self.assertNotEqual(swap, "wrong reopened driver")
                    self.assertEqual(control, 25)
                    renamed = swap == "renamed parent"
                self.assertEqual(magic.call_args.args[1:], (32, "24", os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY, 2))
