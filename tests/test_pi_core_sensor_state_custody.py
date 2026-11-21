"""Private files plus modelled mount tables; no actual device, namespace or service."""
import os
import time
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_sensor_state_custody as s
from tests import test_pi_core_mask_custody as fixture


class SensorCustody(unittest.TestCase):
    def setUp(self):
        old = fixture.MaskCustodyTests()
        self.addCleanup(old.doCleanups)
        old.setUp()
        self.base, self.dst = old.root, {"store": old.store, "receipt_directory": old.receipts}
        for key, value in (("BASE", old.root), ("STORE", old.store), ("RECEIPTS", old.receipts)):
            self.enterContext(patch.object(s, key, value))
        self.deadline = time.monotonic() + 15
        self.roots = s.check_sensor_destinations(**self.dst, deadline=self.deadline, attempt_id="a"*32)
        self.storage = dict(device="253:7", backing_devices=["259:9"], fs_type="ext4")
        self.kernel_root = b"1 9 0:4 / / ro - squashfs /dev/root ro\n"
        anchor = f"2 1 0:16 / {old.root.parent} rw - tmpfs tmpfs rw\n"
        self.carrier = f"3 2 8:35 / {old.root} rw,nodev,nosuid,noexec - ext4 /dev/sdx rw\n".encode()
        self.manager = self.kernel_root + anchor.encode() + self.carrier
        self.sensor = self.kernel_root + b"4 1 253:7 /state /action rw - ext4 /dev/statedisk rw\n"
        self.enterContext(patch.object(os, "major", return_value=8))
        self.enterContext(patch.object(os, "minor", return_value=35))
        self.mid = 3
        self.topology = Mock()
        self.enterContext(patch.object(s.kernel, "_stat",
            side_effect=lambda fd, owner: dict(ino=os.fstat(fd).st_ino, dev="8:35", mnt_id=self.mid)))

    def members(self, manager=None, sensor=None):
        m = self.manager if manager is None else manager
        r = self.sensor if sensor is None else sensor
        doc = dict(schema="aragorn/pi-core-sensor-state-record/v1", attempt_id="a"*32, storage=self.storage,
                   manager_mountinfo_digest=s._digest(m), sensor_mountinfo_digest=s._digest(r))
        return dict(record_raw=s.canonical_json(doc), manager_raw=m, sensor_raw=r)

    def retain(self, members):
        return s.retain_sensor_observation(**self.dst, **members, expected_roots=self.roots,
                                          storage=self.storage, deadline=self.deadline, topology_guard=self.topology)

    def test_stable_writable_sensor_finding_survives_readback_and_cannot_be_replaced(self):
        data = self.members()
        pin = self.retain(data)
        args = dict(**self.dst, capture_digest=s._digest(data["record_raw"]), receipt_digest=pin)
        self.assertEqual(s.replay_sensor_observation(**args), {k[:-4]: v for k,v in data.items()})
        changed = self.members(sensor=self.sensor.replace(b"/action rw", b"/action ro"))
        with self.assertRaises(FileExistsError):
            self.retain(changed)
        with self.assertRaises(FileExistsError):
            s.check_sensor_destinations(**self.dst, deadline=self.deadline, attempt_id="a"*32)
        with self.assertRaises(ValueError):
            s.replay_sensor_observation(**(args | {"receipt_digest": "sha256:"+"4"*64}))
        self.assertEqual(s.replay_sensor_observation(**args)["sensor"], self.sensor)
        self.assertGreater(self.topology.call_count, len(data))

    def test_capture_mount_change_after_preflight_cannot_publish_a_receipt(self):
        self.topology.side_effect = lambda: setattr(self, "mid", 12)
        with self.assertRaisesRegex(ValueError, "mount identity"):
            self.retain(self.members())
        self.assertEqual(list(self.dst["receipt_directory"].iterdir()), [])

    def test_wrong_mounted_volume_or_visible_evidence_refuses_before_publication(self):
        for m, r in ((self.manager.replace(b"8:35", b"253:7"), self.sensor),
                     (self.manager.replace(b"8:35", b"259:9"), self.sensor),
                     (self.manager.replace(b"rw,nodev", b"ro,nodev"), self.sensor),
                     (self.manager.replace(b"rw,nodev", b"rw shared:5"), self.sensor),
                     (self.manager.replace(b"8:35", b"8:34"), self.sensor),
                     (self.manager + b"5 1 8:35 /cas /another rw - ext4 /dev/sdx rw\n", self.sensor),
                     (self.manager, self.sensor + b"5 1 8:35 /cas /another ro - ext4 /dev/sdx ro\n"),
                     (self.manager, self.sensor + b"5 1 8:33 / /another ro - ext4 /dev/sdx ro\n"),
                     (self.manager, self.sensor[:-1])):
            with self.subTest(manager=m, sensor=r), self.assertRaises(ValueError):
                self.retain(self.members(m, r))
        self.assertEqual(list(self.dst["receipt_directory"].iterdir()), [])

    def test_capture_pin_and_fixed_destination_both_required(self):
        data = self.members()
        with self.assertRaises(ValueError):
            self.retain(data | {"manager_raw": self.sensor})
        with self.assertRaises(ValueError):
            s.check_sensor_destinations(store=self.base, receipt_directory=self.dst["receipt_directory"],
                                        deadline=self.deadline, attempt_id="a"*32)
        self.dst["store"].rename(self.base / "old-store")
        self.dst["store"].mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.retain(data)
        self.assertEqual(list(self.dst["receipt_directory"].iterdir()), [])
