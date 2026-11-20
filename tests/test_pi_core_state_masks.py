"""Inert mask-acquisition records, never a mounted guest or an authorization."""
from copy import deepcopy
import stat
import unittest

from aragorn.pi_core_state_exposure import _verify_pi_exposure, verify_pi_exposure
from aragorn.pi_core_state_masks import verify_masks
from aragorn.pi_core_state_mounts import verify_mounts
from test_pi_core_state_exposure import ADMITTED, WORKER_ROOT, pi_exposure_sample
from test_pi_core_state_mounts import sample_mountinfo


_IDS = {"/dev/pts": 11, "/dev/shm": 12, "/dev/hugepages": 13}
_PATHS = tuple(_IDS)
_PI = dict(pid=75, start_ticks=959, mount_namespace=9005, user_namespace=101, uid=40, gid=40)
_MANAGER = dict(pid=71, start_ticks=955, mount_namespace=9001, user_namespace=101, uid=0, gid=0)


def masked_pi_mountinfo(*, device="253:7", paths=_PATHS):
    rows = [f"{_IDS[p]} 2 0:28 /systemd/inaccessible/dir {p} ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
            for p in paths]
    return sample_mountinfo("pi", device=device) + "".join(rows).encode("ascii")


def mask_sample(*, subject, manager_subject, device="253:7", paths=_PATHS, ptmx=True):
    """Fresh worker walk and independent proof content; callers own their custody envelope."""
    walk = pi_exposure_sample(device=device, **{k: subject[k] for k in ("pid", "start_ticks", "mount_namespace")})
    tree = walk["tree"]
    source = dict(mode=stat.S_IFDIR, dev="0:28", ino=501, rdev="0:0", mnt_id=2, uid=0, gid=0)
    ctx = dict(**subject, euid=subject["uid"], suid=subject["uid"], fsuid=subject["uid"],
               egid=subject["gid"], sgid=subject["gid"], fsgid=subject["gid"], groups=[],
               cap_effective=0, cap_permitted=0, cap_inheritable=0, cap_ambient=0, cap_bounding=0,
               no_new_privs=True, root=deepcopy(walk["root"]))
    frame = dict(worker=ctx, probe=(deepcopy(ctx) | dict(pid=subject["pid"] + 300, start_ticks=subject["start_ticks"] + 20)),
                 dev_fd=3, dev_stat=deepcopy(tree["/dev"]["stat"]), boottime_ns=10000)
    proof = dict(schema="aragorn/pi-core-mask-witness/v1", manager=deepcopy(manager_subject), worker=deepcopy(subject),
                 source=dict(path="/run/systemd/inaccessible/dir", fd=5, path_before=deepcopy(source),
                             path_after=deepcopy(source), before=deepcopy(source), after=deepcopy(source),
                             entries_before=[], entries_after=[]), before=frame,
                 after=(deepcopy(frame) | dict(boottime_ns=20000)), directories={}, ptmx=None)
    def probe(name, *, link=False, index):
        return dict(syscall="newfstatat" if link else "openat", name=name, dirfd=3,
                    flags=0 if link else 0o2140000, result=-1, errno=13,
                    started_ns=10100 + index * 20, finished_ns=10110 + index * 20)
    for index, path in enumerate(paths):
        name = path.split("/")[-1]
        obj = dict(mode=stat.S_IFDIR, dev="0:28", ino=501, rdev="0:0", mnt_id=_IDS[path])
        tree[path] = dict(stat=deepcopy(obj), mask_proof="denied-directory")
        proof["directories"][path] = dict(before=obj, after=deepcopy(obj), probe=probe(name, index=index))
    if ptmx:
        obj = dict(mode=stat.S_IFLNK | 0o777, dev="0:21", ino=502, rdev="0:0", mnt_id=2)
        tree["/dev/ptmx"] = dict(stat=deepcopy(obj), mask_proof="denied-ptmx")
        proof["ptmx"] = dict(before=obj, after=deepcopy(obj), readlink_before="pts/ptmx", readlink_after="pts/ptmx",
                             probe=probe("ptmx", link=True, index=len(paths)))
    names = sorted(["null"] + [p.split("/")[-1] for p in paths] + (["ptmx"] if ptmx else []))
    tree["/dev"].update(before=list(names), after=list(names))
    return walk, proof


class MaskWitnessTests(unittest.TestCase):
    def records(self, *, paths=_PATHS, ptmx=True):
        walk, proof = mask_sample(subject=_PI, manager_subject=_MANAGER, paths=paths, ptmx=ptmx)
        namespace, worker_mounts, manager_mounts = {}, {}, {}
        verify_mounts("pi", masked_pi_mountinfo(paths=paths), device="253:7", fs_type="ext4", backing_devices=["259:0"],
                      namespace=namespace, mount_details=worker_mounts)
        verify_mounts("manager", sample_mountinfo("manager", device="253:7"), device="253:7", fs_type="ext4",
                      backing_devices=["259:0"], mount_details=manager_mounts)
        return walk, proof, dict(subject=_PI.copy(), manager_subject=_MANAGER.copy(), namespace=namespace,
                                device="253:7", backing_devices=["259:0"], worker_mounts=worker_mounts,
                                manager_mounts=manager_mounts)

    def check(self, walk, proof, kwargs):
        leaves = verify_masks(walk, proof, **kwargs)
        context = {k: kwargs[k] for k in ("device", "backing_devices", "namespace")}
        context.update({k: kwargs["subject"][k] for k in ("pid", "start_ticks", "mount_namespace")})
        context.update(worker_root=WORKER_ROOT, admitted_cwd=ADMITTED)
        _verify_pi_exposure(walk, verified_masks=leaves, **context)
        return leaves, context

    def test_only_corroborated_named_leaves_replace_enumeration_in_the_successor(self):
        for paths, ptmx in (((_PATHS[0],), False), (_PATHS, True)):
            with self.subTest(paths=paths, ptmx=ptmx):
                walk, proof, kwargs = self.records(paths=paths, ptmx=ptmx)
                leaves, context = self.check(walk, proof, kwargs)
                self.assertEqual(set(leaves), set(paths) | ({"/dev/ptmx"} if ptmx else set()))
                with self.assertRaises(ValueError):
                    verify_pi_exposure(walk, **context)

    def test_backing_requires_root_owned_stable_empty_source_and_exact_tmpfs_binds(self):
        for label, mutate in (
                ("alternate source", lambda p, k: p["source"].update(path="/tmp/dir")),
                ("nonempty", lambda p, k: p["source"]["entries_before"].append("child")),
                ("writable", lambda p, k: p["source"]["before"].update(mode=stat.S_IFDIR | 0o200)),
                ("unprivileged owner", lambda p, k: p["source"]["after"].update(uid=40)),
                ("changed inode", lambda p, k: p["source"]["after"].update(ino=505)),
                ("held fd omitted", lambda p, k: p["source"].pop("fd")),
                ("named object missing", lambda p, k: p["source"].pop("path_after")),
                ("stable held FD but replaced name", lambda p, k: p["source"]["path_after"].update(ino=504)),
                ("stable but wrong name", lambda p, k: [p["source"][edge].update(ino=504)
                                                        for edge in ("path_before", "path_after")]),
                ("wrong manager mount", lambda p, k: k["manager_mounts"]["/run"].update(mount_id=98)),
                ("foreign manager filesystem", lambda p, k: k["manager_mounts"]["/run"].update(fs_type="ext4")),
                ("shadow bind", lambda p, k: k["worker_mounts"]["/dev/pts"].update(root="/other/dir")),
                ("substituted target inode", lambda p, k: p["directories"]["/dev/pts"]["before"].update(ino=990))):
            with self.subTest(label=label):
                walk, proof, kwargs = self.records()
                mutate(proof, kwargs)
                with self.assertRaises(ValueError):
                    self.check(walk, proof, kwargs)

    def test_probe_and_worker_credentials_namespace_root_and_fd_must_remain_bound(self):
        for label, mutate in (
                ("new user namespace", lambda p: p["before"]["probe"].update(user_namespace=808)),
                ("privileged credentials", lambda p: p["before"]["probe"].update(fsuid=0)),
                ("retained saved UID", lambda p: [p[edge][party].update(suid=0) for edge in ("before", "after")
                                                  for party in ("worker", "probe")]),
                ("effective GID omitted", lambda p: p["after"]["worker"].pop("egid")),
                ("supplementary group", lambda p: p["after"]["probe"].update(groups=[0])),
                ("effective capability", lambda p: p["after"]["probe"].update(cap_effective=1)),
                ("can gain privileges", lambda p: p["before"]["worker"].update(no_new_privs=False)),
                ("wrong root", lambda p: p["before"]["probe"]["root"].update(ino=890)),
                ("same process", lambda p: p["before"].update(probe=deepcopy(p["before"]["worker"]))),
                ("swapped dev descriptor", lambda p: p["after"]["dev_stat"].update(mnt_id=98)),
                ("changed worker namespace", lambda p: p["after"]["worker"].update(mount_namespace=199))):
            with self.subTest(label=label):
                walk, proof, kwargs = self.records()
                mutate(proof)
                with self.assertRaises(ValueError):
                    self.check(walk, proof, kwargs)

    def test_exact_worker_relative_failed_syscall_and_bounded_interval_required(self):
        for change in (dict(name="../dev/pts"), dict(name="/dev/pts"), dict(dirfd=4), dict(syscall="access"),
                       dict(flags=0), dict(flags=720896), dict(result=3), dict(errno=2), dict(errno=True),
                       dict(started_ns=1), dict(finished_ns=10001), dict(finished_ns=21000)):
            with self.subTest(change=change):
                walk, proof, kwargs = self.records()
                proof["directories"]["/dev/pts"]["probe"].update(change)
                with self.assertRaises(ValueError):
                    self.check(walk, proof, kwargs)

    def test_ptmx_requires_the_one_stable_symlink_and_actual_follow_denial(self):
        for label, mutate in (
                ("different target", lambda l: l.update(readlink_after="../pts/ptmx")),
                ("switched link", lambda l: l["after"].update(ino=999)),
                ("inaccessible char device", lambda l: l["before"].update(mode=stat.S_IFCHR, rdev="5:2")),
                ("lstat not follow", lambda l: l["probe"].update(flags=256)),
                ("dangling not denial", lambda l: l["probe"].update(errno=2)),
                ("other link", lambda l: l["probe"].update(name="pts/ptmx"))):
            with self.subTest(label=label):
                walk, proof, kwargs = self.records()
                mutate(proof["ptmx"])
                with self.assertRaises(ValueError):
                    self.check(walk, proof, kwargs)

    def test_mask_exception_never_excuses_another_unreadable_subtree_or_hidden_mount(self):
        for label in ("unproved", "unknown proof", "descendant", "different marker", "ordinary inaccessible"):
            with self.subTest(label=label):
                walk, proof, kwargs = self.records()
                if label == "unproved":
                    del proof["directories"]["/dev/shm"]
                elif label == "unknown proof":
                    proof["directories"]["/dev/work"] = deepcopy(proof["directories"]["/dev/pts"])
                elif label == "descendant":
                    walk["tree"]["/dev/pts/hidden"] = {"stat": deepcopy(walk["tree"]["/dev/null"]["stat"])}
                elif label == "different marker":
                    walk["tree"]["/dev/pts"]["mask_proof"] = True
                else:
                    walk["tree"]["/var"].pop("before")
                with self.assertRaises(ValueError):
                    self.check(walk, proof, kwargs)
