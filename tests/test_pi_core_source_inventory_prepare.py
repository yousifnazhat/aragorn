"""Inert installed-view fixtures; no mounts, targets, services or real artifacts."""

from contextlib import ExitStack
import copy
import hashlib
from io import BytesIO
import json
import math
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_source_inventory_prepare as prepare
from aragorn import pi_core_node_source_observer as node
from aragorn import pi_core_source_observer as base
from aragorn import pi_core_node_source_observation_verify as replay


SOURCE = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js"
LOADER = "/usr/lib/libc.so.6"


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class Views:
    """A finite descriptor-backed filesystem fixture, not an active view."""

    def __init__(self):
        self.nodes, self.descriptors, self.closed = {}, {}, []
        self.next_inode, self.next_fd = 30, 100
        self.before_stat = self.before_fstat = None
        self.close_failure = None
        for role, fd, device in (("worker", 10, 1), ("observer", 11, 2)):
            self.add(role, (), directory=True, device=device, readonly=role == "worker")
            self.descriptors[fd] = (role, ())
        self.contents = {
            ("worker", str(base.GATE_PATH)): b"pinned-static-gate",
            ("worker", str(base.NODE_PATH)): b"pinned-node-elf",
            ("observer", str(base.PRODUCER_PATH)): b"pinned-source-observer",
            ("observer", str(node.ORIGIN)): b"pinned-node-observer",
            ("worker", SOURCE): b"abc",
            ("worker", LOADER): b"\x7fELF",
        }
        for (role, path), raw in self.contents.items():
            self.add(role, tuple(path.split("/")[1:]), raw=raw)

    def add(self, role, parts, raw=b"", *, directory=False, device=None, readonly=None):
        if (role, parts) in self.nodes:
            return self.nodes[role, parts]
        if parts:
            self.add(role, parts[:-1], directory=True)
        self.next_inode += 1
        info = SimpleNamespace(st_dev=device or (1 if role == "worker" else 2), st_ino=self.next_inode,
            st_mode=(stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | (0o644 if role == "worker" else 0o444)),
            st_uid=0, st_gid=0, st_nlink=2 if directory else 1, st_size=0 if directory else len(raw),
            st_mtime_ns=1, st_ctime_ns=1)
        value = dict(info=info, raw=raw, readonly=role == "worker" if readonly is None else readonly)
        self.nodes[role, parts] = value
        return value

    def row(self, role, path):
        return self.nodes[role, tuple(path.split("/")[1:])]

    def allocate(self, key):
        self.next_fd += 1
        self.descriptors[self.next_fd] = key
        return self.next_fd

    def dup(self, fd):
        return self.allocate(self.descriptors[fd])

    def fstat(self, fd):
        if self.before_fstat:
            self.before_fstat(fd)
        return copy.copy(self.nodes[self.descriptors[fd]]["info"])

    def stat(self, name, *, dir_fd, follow_symlinks):
        if self.before_stat:
            self.before_stat(name, dir_fd)
        role, parent = self.descriptors[dir_fd]
        return copy.copy(self.nodes[role, parent + (name,)]["info"])

    def open(self, name, flags, *, dir_fd):
        role, parent = self.descriptors[dir_fd]
        key = role, parent + (name,)
        info = self.nodes[key]["info"]
        if stat.S_ISLNK(info.st_mode) or flags & os.O_DIRECTORY and not stat.S_ISDIR(info.st_mode):
            raise OSError("inert nofollow/type refusal")
        if not flags & os.O_NOFOLLOW:
            raise AssertionError("every fixture open must refuse links")
        return self.allocate(key)

    def pread(self, fd, count, offset):
        return self.nodes[self.descriptors[fd]]["raw"][offset:offset+count]

    def fstatvfs(self, fd):
        return SimpleNamespace(f_flag=os.ST_RDONLY if self.nodes[self.descriptors[fd]]["readonly"] else 0)

    def close(self, fd):
        self.closed.append(fd)
        if self.close_failure is not None and self.close_failure(fd):
            raise OSError("inert ambiguous close")
        del self.descriptors[fd]

    def plan(self):
        return dict(schema=prepare.PLAN_SCHEMA, pins={
            "gate_digest": digest(self.contents["worker", str(base.GATE_PATH)]),
            "node_digest": digest(self.contents["worker", str(base.NODE_PATH)]),
            "producer_digest": digest(self.contents["observer", str(base.PRODUCER_PATH)]),
            "node_observer_digest": digest(self.contents["observer", str(node.ORIGIN)]),
        }, sources=[dict(path=SOURCE, digest=digest(b"abc"))], required_sources=[SOURCE],
            loader_files=[dict(path=LOADER, digest=digest(b"\x7fELF"))])


class SourceInventoryPreparationTests(unittest.TestCase):
    def setUp(self):
        self.views = Views()
        self.plan = self.views.plan()
        self.arguments = dict(worker_root_fd=10, observer_root_fd=11, deadline=20.0,
            expected_worker_root_identity=base._file_identity(self.views.fstat(10)),
            expected_observer_root_identity=base._file_identity(self.views.fstat(11)))

    def environment(self):
        stack = ExitStack()
        stack.enter_context(patch.object(prepare.platform, "system", return_value="Linux"))
        stack.enter_context(patch.object(prepare.platform, "machine", return_value="aarch64"))
        stack.enter_context(patch.object(prepare.provision.time, "monotonic", return_value=1.0))
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            stack.enter_context(patch.object(prepare.os, name, return_value=0))
        for name in ("dup", "fstat", "stat", "open", "pread", "fstatvfs", "close"):
            stack.enter_context(patch.object(prepare.os, name, side_effect=getattr(self.views, name)))
        return stack

    def run_preparation(self, *, raw=None, pin=None):
        raw = base.canonical_json(self.plan) if raw is None else raw
        pin = digest(raw) if pin is None else pin
        with self.environment():
            return prepare.prepare_pi_source_inventories(raw, expected_manifest_digest=pin, **self.arguments)

    def refuse(self, reason=None):
        with self.assertRaisesRegex(prepare.PiSourceInventoryPreparationError, reason or ".+"):
            self.run_preparation()
        self.assertEqual(set(self.views.descriptors), {10, 11})

    def test_prepares_actual_identity_profile_without_authority(self):
        result = self.run_preparation()
        source, loader = json.loads(result.source_inventory_raw), json.loads(result.loader_inventory_raw)
        profile = json.loads(result.profile_raw)
        receipt = json.loads(result.preparation_raw)
        self.assertEqual(source["schema"], node.SOURCE_SCHEMA)
        self.assertEqual(loader["schema"], node.LOADER_SCHEMA)
        self.assertEqual(source["sources"][0]["identity"], base._file_identity(self.views.row("worker", SOURCE)["info"]))
        self.assertEqual(profile["pins"]["source_inventory_digest"], digest(result.source_inventory_raw))
        self.assertEqual(profile["pins"]["loader_inventory_digest"], digest(result.loader_inventory_raw))
        self.assertEqual(node.validate_node_profile(profile), profile)
        self.assertEqual(receipt["authority"], prepare.AUTHORITY)
        self.assertFalse(receipt["phase3_exit_eligible"])
        self.assertEqual(set(self.views.descriptors), {10, 11})
        self.assertNotIn(10, self.views.closed)
        self.assertNotIn(11, self.views.closed)

    def test_independent_replay_accepts_exact_inventory_shapes_and_bytes(self):
        result = self.run_preparation()
        profile = json.loads(result.profile_raw)
        blobs = {digest(raw): raw for raw in (*self.views.contents.values(), result.source_inventory_raw, result.loader_inventory_raw)}
        cas = Mock()
        cas.read.side_effect = lambda pin, max_bytes: blobs[pin]
        source, _ = replay._inventory(result.source_inventory_raw, profile["pins"]["source_inventory_digest"], cas)
        loader, _ = replay._inventory(result.loader_inventory_raw, profile["pins"]["loader_inventory_digest"], cas, loaders=True)
        self.assertEqual(source["sources"][0]["path"], SOURCE)
        self.assertEqual(loader["loaders"][0]["path"], LOADER)

    def test_manifest_pin_is_checked_before_descriptor_access(self):
        with self.environment(), patch.object(prepare.os, "dup") as duplicate:
            with self.assertRaisesRegex(prepare.PiSourceInventoryPreparationError, "PLAN_PIN"):
                prepare.prepare_pi_source_inventories(base.canonical_json(self.plan),
                    expected_manifest_digest="sha256:" + "f" * 64, **self.arguments)
            duplicate.assert_not_called()

    def test_noncanonical_manifest_is_refused(self):
        with self.assertRaises(prepare.PiSourceInventoryPreparationError):
            self.run_preparation(raw=json.dumps(self.plan).encode())
        self.assertEqual(self.views.closed, [])

    def test_duplicate_manifest_key_is_refused(self):
        raw = b'{"schema":"one","schema":"two"}'
        with self.assertRaises(prepare.PiSourceInventoryPreparationError):
            self.run_preparation(raw=raw)
        self.assertEqual(self.views.closed, [])

    def test_no_runtime_or_deployment_cycle_pin_is_accepted(self):
        self.plan["pins"]["deployment_digest"] = digest(b"deployment")
        self.refuse()

    def test_required_subset_is_reviewed_not_inferred(self):
        self.plan["required_sources"] = ["/unlisted.js"]
        self.refuse("REQUIRED_SUBSET")

    def test_duplicate_source_path_is_refused(self):
        self.plan["sources"] *= 2
        self.refuse("DUPLICATE_PATH")

    def test_source_loader_role_overlap_is_refused(self):
        self.plan["loader_files"] = copy.deepcopy(self.plan["sources"])
        self.refuse("ROLE_ALIAS")

    def test_del_path_is_refused_before_access(self):
        self.plan["sources"][0]["path"] += "\x7f"
        self.refuse("PLAN_PATH")

    def test_dot_path_is_refused_before_access(self):
        self.plan["sources"][0]["path"] = "/opt/../entrypoint.js"
        self.refuse("PLAN_PATH")

    def test_root_identity_substitution_is_refused(self):
        self.arguments["expected_worker_root_identity"]["inode"] += 1
        self.refuse("ROOT_IDENTITY")

    def test_writable_worker_root_is_not_installed_readonly_evidence(self):
        self.views.nodes["worker", ()]["readonly"] = False
        self.refuse("NOT_READONLY")

    def test_readonly_root_does_not_mask_writable_leaf_submount(self):
        self.views.row("worker", SOURCE)["readonly"] = False
        self.refuse("READONLY_VIEW")

    def test_writable_worker_subdirectory_is_refused(self):
        self.views.nodes["worker", ("opt", "aragorn")]["readonly"] = False
        self.refuse("NOT_READONLY")

    def test_observer_source_must_be_nonwritable_even_on_readonly_view(self):
        row = self.views.row("observer", str(base.PRODUCER_PATH))
        row["readonly"] = True
        row["info"].st_mode = stat.S_IFREG | 0o644
        self.refuse("SOURCE_FILE_METADATA")

    def test_worker_owner_write_bit_is_allowed_only_with_readonly_view(self):
        self.views.row("worker", SOURCE)["info"].st_mode = stat.S_IFREG | 0o644
        result = self.run_preparation()
        self.assertEqual(json.loads(result.source_inventory_raw)["sources"][0]["identity"]["mode"], stat.S_IFREG | 0o644)

    def test_group_writable_source_is_refused(self):
        self.views.row("worker", SOURCE)["info"].st_mode = stat.S_IFREG | 0o664
        self.refuse("READONLY_VIEW")

    def test_hardlinked_source_is_refused(self):
        self.views.row("worker", SOURCE)["info"].st_nlink = 2
        self.refuse("READONLY_VIEW")

    def test_changed_source_bytes_do_not_create_new_trust(self):
        self.views.row("worker", SOURCE)["raw"] = b"bad"
        self.refuse("CONTENT_PIN")

    def test_fixed_code_pin_conflict_is_refused_before_access(self):
        self.plan["loader_files"].append(dict(path=str(base.NODE_PATH), digest=digest(b"wrong")))
        self.refuse("FIXED_CODE_CONFLICT")

    def test_same_fixed_node_path_can_join_loader_inventory(self):
        self.plan["loader_files"].append(dict(path=str(base.NODE_PATH), digest=self.plan["pins"]["node_digest"]))
        result = self.run_preparation()
        paths = [row["path"] for row in json.loads(result.loader_inventory_raw)["loaders"]]
        self.assertEqual(paths, sorted([LOADER, str(base.NODE_PATH)]))

    def test_distinct_paths_cannot_alias_fixed_code_object(self):
        self.views.row("worker", SOURCE)["info"].st_ino = self.views.row("worker", str(base.NODE_PATH))["info"].st_ino
        self.refuse("CODE_OR_FILE_ALIAS")

    def test_symlink_ancestry_is_refused_without_fd_leak(self):
        self.views.nodes["worker", ("opt",)]["info"].st_mode = stat.S_IFLNK | 0o777
        self.refuse("nofollow")

    def test_symlink_leaf_is_refused_without_fd_leak(self):
        self.views.row("worker", SOURCE)["info"].st_mode = stat.S_IFLNK | 0o777
        self.refuse("nofollow")

    def test_named_leaf_replacement_is_refused(self):
        original = self.views.stat
        calls = 0
        def changed(name, *, dir_fd, follow_symlinks):
            nonlocal calls
            info = original(name, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
            if name == "entrypoint.js":
                calls += 1
                if calls == 2:
                    info.st_ino += 100
            return info
        self.views.stat = changed
        self.refuse("FILE_CHANGED")

    def test_empty_required_sources_are_refused(self):
        self.plan["required_sources"] = []
        self.refuse("REQUIRED_SUBSET")

    def test_source_size_limit_is_preserved(self):
        self.views.row("worker", SOURCE)["info"].st_size = base.MAX_FILE + 1
        self.refuse("READONLY_VIEW")

    def test_original_deadline_cannot_be_expired_or_unbounded(self):
        for deadline in (1.0, 602.0, math.inf, math.nan, True):
            with self.subTest(deadline=deadline):
                self.arguments["deadline"] = deadline
                self.refuse("deadline")
        self.assertEqual(self.views.closed, [])

    def test_non_linux_refuses_before_any_descriptor_use(self):
        with self.environment(), patch.object(prepare.platform, "system", return_value="Darwin"), \
             patch.object(prepare.os, "dup") as duplicate:
            with self.assertRaisesRegex(prepare.PiSourceInventoryPreparationError, "LINUX_ARM64_ROOT"):
                prepare.prepare_pi_source_inventories(base.canonical_json(self.plan),
                    expected_manifest_digest=digest(base.canonical_json(self.plan)), **self.arguments)
            duplicate.assert_not_called()

    def test_close_ambiguity_does_not_return_prepared_artifacts_or_retry(self):
        self.views.close_failure = lambda fd: fd == 101
        with self.assertRaisesRegex(prepare.PiSourceInventoryPreparationError, "CLOSE_AMBIGUOUS") as caught:
            self.run_preparation()
        self.assertEqual(caught.exception.held_fds, (101,))
        self.assertEqual(caught.exception.ambiguous_fds, (101,))
        self.assertEqual(self.views.closed.count(101), 1)
        self.assertEqual(set(self.views.descriptors), {10, 11, 101})

    def test_root_identity_inputs_are_snapshotted_before_descriptor_use(self):
        original = self.views.dup
        expected = copy.deepcopy(self.arguments["expected_worker_root_identity"])
        def mutate(fd):
            self.arguments["expected_worker_root_identity"]["inode"] = 9999
            return original(fd)
        self.views.dup = mutate
        result = self.run_preparation()
        self.assertEqual(json.loads(result.preparation_raw)["worker_root_identity"], expected)

    def test_profile_has_only_six_expected_pins_and_no_automatic_approval(self):
        result = self.run_preparation()
        profile = json.loads(result.profile_raw)
        self.assertEqual(set(profile["pins"]), node._PINS)
        self.assertEqual(profile["required_sources"], self.plan["required_sources"])
        self.assertNotIn("approved", json.loads(result.preparation_raw))


if __name__ == "__main__":
    unittest.main()
