"""Inert statx frames; no live mounts, processes or device reads."""
from copy import deepcopy
import stat
import unittest

from aragorn.pi_core_manager_state_view import verify_manager_state
from aragorn.pi_core_state_mounts import ACTION, ANCHOR, PROVIDER, verify_mounts
from test_pi_core_state_mounts import sample_mountinfo


def manager_record():
    sources = {
        p: dict(dev="253:7", ino=1000 + i, uid=0, gid=0, rdev="0:0", mnt_id=3,
                mode=stat.S_IFDIR | (0o755 if p == ACTION else 0o700))
        for i, p in enumerate((ANCHOR, ACTION, PROVIDER))
    }
    frame = {"sources": sources, "targets": {ACTION: {**sources[ACTION], "mnt_id": 4},
                                             PROVIDER: {**sources[PROVIDER], "mnt_id": 5}}}
    return {"before": frame, "after": deepcopy(frame)}


class ManagerState(unittest.TestCase):
    def setUp(self):
        self.storage = dict(device="253:7", backing_devices=["259:0"], fs_type="ext4")
        self.mounts = {}
        verify_mounts("manager", sample_mountinfo("manager", device="253:7"),
                      **self.storage, mount_details=self.mounts)

    def check(self, record):
        return verify_manager_state(record, self.storage, self.mounts)

    def test_returns_exact_b58_source_roots_and_manager_targets_including_anchor(self):
        source, targets = self.check(manager_record())
        expected = {p: dict(dev="253:7", ino=1000 + i, uid=0, gid=0,
                            mode=stat.S_IFDIR | (0o755 if p == ACTION else 0o700))
                    for i, p in enumerate((ANCHOR, ACTION, PROVIDER))}
        self.assertEqual(source, expected)
        self.assertEqual(targets, {p: dict(row, mount_id=i) for i, (p, row) in enumerate(expected.items(), 3)})

    def test_rejects_incomplete_or_unexpected_observation_in_either_frame(self):
        for when, table, path in (("before", "sources", ACTION), ("after", "targets", PROVIDER)):
            for mutation in ("missing", "extra", "unexpected_field"):
                record = manager_record()
                rows = record[when][table]
                if mutation == "missing":
                    del rows[path]
                elif mutation == "extra":
                    rows["/new-state"] = rows[path].copy()
                else:
                    rows[path]["mount_id"] = rows[path]["mnt_id"]
                with self.subTest(when=when, mutation=mutation), self.assertRaises(ValueError):
                    self.check(record)

    def test_rejects_change_across_otherwise_internally_consistent_frames(self):
        record = manager_record()
        for table in ("sources", "targets"):
            record["after"][table][ACTION]["ino"] += 10
        with self.assertRaises(ValueError):
            self.check(record)

    def test_rejects_same_path_other_inode_source_mount_or_role_alias(self):
        for table, path, field, value in (
            ("targets", PROVIDER, "ino", 555), ("sources", ACTION, "ino", 1000),
            ("sources", PROVIDER, "mnt_id", 5), ("targets", ACTION, "mnt_id", 3),
            ("targets", ACTION, "mnt_id", 5), ("targets", PROVIDER, "dev", "259:0"),
        ):
            record = manager_record()
            for frame in record.values():
                frame[table][path][field] = value
            with self.subTest(table=table, path=path, field=field), self.assertRaises(ValueError):
                self.check(record)

    def test_rejects_wrong_type_principal_permissions_special_device_and_unbounded_integer(self):
        for field, value in (("mode", stat.S_IFREG | 0o755), ("mode", stat.S_IFDIR | 0o777),
                             ("uid", 1), ("gid", False), ("rdev", "1:3"),
                             ("ino", True), ("ino", 1 << 64), ("mnt_id", 1 << 32)):
            record = manager_record()
            for frame in record.values():
                frame["sources"][ACTION][field] = value
                frame["targets"][ACTION][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.check(record)

    def test_mount_type_root_device_ids_and_separate_anchor_required(self):
        for field, value in (("dev", "253:8"), ("fs_type", "xfs"), ("root", "/"), ("mount_id", 3),
                             ("options", frozenset({"ro", "nosuid", "nodev", "noexec"}))):
            mounts = deepcopy(self.mounts)
            mounts[ACTION][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_manager_state(manager_record(), self.storage, mounts)
        for path, dev in (("/foreign", "253:7"), ("/disguised", "259:0"), (ANCHOR + "/var", "0:29")):
            mounts = {**self.mounts, path: {**self.mounts[ACTION], "mount_id": 22, "dev": dev}}
            with self.subTest(path=path), self.assertRaises(ValueError):
                verify_manager_state(manager_record(), self.storage, mounts)
