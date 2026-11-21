"""Inert stopped frames and original-format receipts only; no process, namespace, device, or launch."""
from copy import deepcopy
import stat
import unittest
from unittest.mock import patch

from aragorn.oci_worker_protocol import canonical_digest
from aragorn.pi_core_state_mounts import verify_mounts
from aragorn.pi_core_worker_walk_evidence import SCHEMA, verify_worker_spine
from scripts.verify_pi_core_joined_mask_receipts import verify_joined_masks
import test_pi_core_join_mask_receipts as archives
from test_pi_core_state_exposure import CWD_PATH, pi_exposure_sample
from test_pi_core_state_masks import masked_pi_mountinfo


PATH = CWD_PATH + "/" + "a" * 64 + "-" + "b" * 64


def spine_for(walk, worker):
    obj = {k: deepcopy(walk[k]) for k in ("root", "cwd", "fds")}
    obj["named_cwd"] = deepcopy(obj["cwd"])
    return dict(schema=SCHEMA, worker=deepcopy(worker), admitted_path=PATH,
                before=deepcopy(walk["before"]), after=deepcopy(walk["after"]),
                objects=dict(before=obj, after=deepcopy(obj)), opened_boottime_ns=9500, closed_boottime_ns=20500)


class WorkerSpine(unittest.TestCase):
    def setUp(self):
        self.walk = pi_exposure_sample()
        self.worker = {k: self.walk["before"][k] for k in ("pid", "start_ticks", "mount_namespace")}
        self.worker.update(uid=203, gid=204, user_namespace=8000)
        self.spine = spine_for(self.walk, self.worker)
        self.storage = dict(device="253:7", backing_devices=["259:0"], fs_type="ext4")
        self.ns, self.mounts = {}, {}
        raw = masked_pi_mountinfo().replace(CWD_PATH.encode(), PATH.encode())
        verify_mounts("pi", raw, **self.storage, namespace=self.ns, mount_details=self.mounts)
        self.binding = dict(schema="aragorn/pi-core-stopped-mask-binding/v3", worker=self.worker, storage=self.storage,
                            capture_mode="STOPPED_WORKER_HANDLE_SPINE", admitted_path=PATH)
        self.view = dict(schema="aragorn/pi-core-stopped-mask-view/v3", worker=self.worker, worker_root=self.walk["root"],
                         opened_boottime_ns=9000, closed_boottime_ns=21000)

    def verify(self):
        return verify_worker_spine(self.spine, binding=self.binding, view=self.view,
                                   namespace=self.ns, worker_mounts=self.mounts)

    def test_returns_only_observed_handles_and_allows_inherited_manager_null_devices(self):
        for edge in self.spine["objects"].values():
            edge["fds"]["0"].update(dev="0:88", mnt_id=770, ino=1142)
        actual = self.verify()
        self.assertEqual(set(actual), {"before", "after", "root", "cwd", "fds", "admitted_path"})
        self.assertEqual(actual["fds"]["0"]["mnt_id"], 770)
        self.assertEqual(actual["admitted_path"], PATH)

    def test_changing_gate_or_forged_frame_cannot_become_stopped_evidence(self):
        base = deepcopy(self.spine)
        for name, updates in (("task_ids", [self.worker["pid"], 300]), ("fd_numbers", [False, True, 2]),
                              ("state", "S"), ("start_ticks", self.worker["start_ticks"] + 1)):
            self.spine = deepcopy(base)
            for edge in ("before", "after"):
                self.spine[edge][name] = updates
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
        self.spine = deepcopy(base)
        self.spine["objects"]["after"]["fds"]["1"]["ino"] += 1
        with self.assertRaisesRegex(ValueError, "handles changed"):
            self.verify()

    def test_wrong_named_or_unmounted_cwd_and_state_handles_refuse(self):
        for label, key, updates in (("mismatched named cwd", "named_cwd", {"ino":500}),
                                     ("wrong directory mount", "cwd", {"mnt_id":17}),
                                     ("state-backed null", "0", {"dev":"253:7"}),
                                     ("raw backing fd", "1", {"dev":"259:0"}),
                                     ("wrong null type", "2", {"mode":stat.S_IFBLK | 0o600})):
            self.spine = spine_for(self.walk, self.worker)
            for edge in self.spine["objects"].values():
                (edge[key] if key in edge else edge["fds"][key]).update(updates)
            with self.subTest(label=label), self.assertRaises(ValueError):
                self.verify()
        self.spine = spine_for(self.walk, self.worker)
        self.mounts[PATH]["options"] = frozenset({"rw"})
        with self.assertRaisesRegex(ValueError, "read-only bind"):
            self.verify()

    def test_unbounded_window_substituted_launch_path_or_extra_tree_refuse(self):
        for key, value in (("opened_boottime_ns", 8000), ("closed_boottime_ns", 22000),
                           ("admitted_path", PATH + "0"), ("tree", {})):
            self.spine = spine_for(self.walk, self.worker)
            self.spine[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify()


class JoinedWorkerSpine(unittest.TestCase):
    def setUp(self):
        self.archive = archives.JoinedMasks()
        self.addCleanup(self.archive.doCleanups)
        self.archive.setUp()  # No historical tests executed.
        h = self.archive
        walk = h.outer.walk
        old_leaf = walk["tree"][CWD_PATH]
        parent_stat = deepcopy(walk["tree"][CWD_PATH.rpartition("/")[0]]["stat"])
        parent_stat["ino"] = 11148
        version = PATH.rpartition("/")[2]
        walk["tree"][CWD_PATH] = dict(stat=parent_stat, before=[version], after=[version])
        walk["tree"][PATH] = old_leaf
        pi = h.base.capture["roles"]["pi"]
        pi["mountinfo"] = h.base.put(h.base.reader.read(pi["mountinfo"]).replace(CWD_PATH.encode(), PATH.encode()))

    def retain(self, change=None):
        h = self.archive
        retain = h.local.retain
        def members(parts):
            h.manager_view(parts)
            spine = spine_for(h.outer.walk, parts["bindings"]["worker"])
            if change is not None:
                change(spine)
            pin = canonical_digest(spine)
            parts["bindings"].update(schema="aragorn/pi-core-stopped-mask-binding/v3", worker_spine_digest=pin,
                                     admitted_path=PATH, capture_mode="STOPPED_WORKER_HANDLE_SPINE")
            parts["vantage"].update(schema="aragorn/pi-core-stopped-mask-view/v3", worker_spine_digest=pin)
            parts["worker_spine"] = spine
        # Only offline fixture custody: a test callback supplies no operating-system authority.
        with patch("aragorn.pi_core_mask_custody._mount_id", return_value=81), patch.object(
                h.local, "retain", side_effect=lambda **kwargs: retain(
                    topology_guard=lambda: None, expected_mounts=(81, 81), **kwargs)):
            return h.retain(members)

    def test_new_receipt_matches_actual_b58_fields_without_turning_spine_into_local_walk(self):
        report = verify_joined_masks(**self.archive.keys(), **self.retain(), require_worker_spine=True)
        self.assertTrue(report["stopped_worker_handles_and_admitted_cwd_matched"])
        self.assertTrue(report["manager_state_roots_and_targets_matched"])
        for key in ("local_full_namespace_walk_observed", "installed_isolation_verified", "activation_authorized",
                    "same_capture_interval_verified", "external_freshness_verified", "phase3_exit_eligible"):
            self.assertIs(report[key], False)

    def test_obsolete_receipt_cannot_produce_worker_handle_finding(self):
        args = self.archive.keys() | self.archive.retain(self.archive.manager_view)
        self.assertIs(verify_joined_masks(**args)["stopped_worker_handles_and_admitted_cwd_matched"], False)
        with self.assertRaisesRegex(ValueError, "worker-spine evidence required"):
            verify_joined_masks(**args, require_worker_spine=True)

    def test_independently_repinned_inherited_fd_mismatch_refuses_even_in_compatibility_mode(self):
        def change(spine):
            for edge in spine["objects"].values():
                edge["fds"]["0"]["ino"] += 500
        with self.assertRaisesRegex(ValueError, "different external stopped-worker fds"):
            verify_joined_masks(**self.archive.keys(), **self.retain(change))

    def test_mask_observation_cannot_outlive_local_stopped_handle_brackets(self):
        with self.assertRaises(ValueError):
            verify_joined_masks(**self.archive.keys(), **self.retain(lambda s: s.update(opened_boottime_ns=10500)))
