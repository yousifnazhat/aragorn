"""Offline comparison of null handles with the mount IDs actually present in the stopped view."""
import stat
import unittest

from aragorn.pi_core_state_exposure import verify_pi_exposure
from scripts.verify_pi_core_joined_mask_receipts import verify_joined_masks
import test_pi_core_state_exposure as walks
import test_pi_core_worker_walk_evidence as spines


def check_walk(walk):
    return verify_pi_exposure(walk, device="253:7", backing_devices=["259:0"],
                              pid=71, start_ticks=955, mount_namespace=9001,
                              worker_root=walks.WORKER_ROOT, admitted_cwd=walks.ADMITTED,
                              namespace=walks.NAMESPACE)


def with_null_link(walk, **target):
    tree = walk["tree"]
    null = tree["/dev/null"]["stat"]
    tree["/dev/stdin"] = dict(stat=dict(null, mode=stat.S_IFLNK | 0o777, ino=991, rdev="0:0"),
                              resolved=dict(null, **target))
    for edge in ("before", "after"):
        tree["/dev"][edge] = sorted([*tree["/dev"][edge], "stdin"])
    return walk


class NullMountRecords(unittest.TestCase):
    def test_walk_refuses_known_mount_device_disagreement_for_an_inherited_descriptor(self):
        walk = walks.pi_exposure_sample()
        # A mount number listed as /dev (0:21) cannot also identify device 0:88.
        walk["fds"]["2"] = dict(walk["fds"]["2"], dev="0:88")
        with self.assertRaisesRegex(ValueError, "stdio device differs from its visible mount"):
            check_walk(walk)

    def test_walk_refuses_known_mount_device_disagreement_on_a_resolved_null_link(self):
        walk = with_null_link(walks.pi_exposure_sample(), dev="0:88")
        with self.assertRaisesRegex(ValueError, "link resolves outside worker namespace"):
            check_walk(walk)

    def test_resolved_null_on_an_unlisted_inherited_mount_remains_valid(self):
        walk = with_null_link(walks.pi_exposure_sample(), dev="0:88", mnt_id=770)
        self.assertIsNone(check_walk(walk))

    def test_local_spine_refuses_two_identical_fd_frames_that_contradict_raw_mountinfo(self):
        frame = spines.WorkerSpine()
        frame.setUp()
        for edge in frame.spine["objects"].values():
            edge["fds"]["1"] = dict(edge["fds"]["1"], dev="0:88")
        with self.assertRaisesRegex(ValueError, "stdio device differs from its visible mount"):
            frame.verify()


class JoinedNullMountRecords(unittest.TestCase):
    def setUp(self):
        self.join = spines.JoinedWorkerSpine()
        self.addCleanup(self.join.doCleanups)
        self.join.setUp()  # Original-format private fixture archives; no historical test methods.

    def join_fd(self, *, dev, mnt_id):
        h = self.join.archive
        fds = h.outer.walk["fds"]
        fds["0"] = dict(fds["0"], dev=dev, mnt_id=mnt_id)
        # seal the archive walk and local v3 spine separately, with the same FD record
        return verify_joined_masks(**h.keys(), **self.join.retain(), require_worker_spine=True)

    def test_matching_archives_cannot_confirm_a_null_on_a_contradictory_mapped_device(self):
        with self.assertRaisesRegex(ValueError, "stdio device differs from its visible mount"):
            self.join_fd(dev="0:88", mnt_id=2)

    def test_joined_archives_allow_a_realistic_inherited_null_without_adding_authority(self):
        report = self.join_fd(dev="0:88", mnt_id=770)
        self.assertTrue(report["stopped_worker_handles_and_admitted_cwd_matched"])
        for field in ("local_full_namespace_walk_observed", "activation_authorized", "phase3_exit_eligible"):
            self.assertIs(report[field], False)
