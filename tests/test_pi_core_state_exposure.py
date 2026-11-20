"""Inert pre-Node records only. No worker, file handle or device is inspected."""
import copy
import stat
import unittest

from aragorn.pi_core_state_exposure import verify_pi_exposure


CWD_PATH = "/var/lib/aragorn/admitted/.aragorn-versions/example"
WORKER_ROOT = {"dev": "8:1", "ino": 2}
ADMITTED = {"dev": "8:2", "ino": 30}
NAMESPACE = {"/": (1, "8:1"), "/dev": (2, "0:21"), CWD_PATH: (3, "8:2")}


def _stat(mode, dev="8:1", ino=100, rdev="0:0", mnt_id=1):
    perms = 0o555 if mode == stat.S_IFDIR else 0o666 if mode == stat.S_IFCHR else 0o444
    return {"mode": mode | perms, "dev": dev, "ino": ino, "rdev": rdev, "mnt_id": mnt_id}


def pi_exposure_sample(*, device="253:7", pid=71, start_ticks=955, mount_namespace=9001,
                       worker_root=None, admitted_cwd=None):
    worker_root = WORKER_ROOT if worker_root is None else worker_root
    admitted_cwd = ADMITTED if admitted_cwd is None else admitted_cwd
    root = _stat(stat.S_IFDIR, **worker_root)
    cwd = _stat(stat.S_IFDIR, **admitted_cwd, mnt_id=3)
    null = _stat(stat.S_IFCHR, dev="0:21", ino=55, rdev="1:3", mnt_id=2)
    sample = {"pid": pid, "start_ticks": start_ticks, "mount_namespace": mount_namespace,
              "state": "T", "task_ids": [pid], "fd_numbers": [0, 1, 2]}
    tree = {}
    def directory(path, metadata, names):
        tree[path] = {"stat": metadata, "before": names, "after": list(names)}
    directory("/", root, ["dev", "var"])
    directory("/dev", _stat(stat.S_IFDIR, dev="0:21", mnt_id=2), ["null"])
    tree["/dev/null"] = {"stat": null}
    path = ""
    pieces = CWD_PATH[1:].split("/")
    for i, name in enumerate(pieces):
        path += "/" + name
        directory(path, cwd if path == CWD_PATH else _stat(stat.S_IFDIR, ino=i + 200, dev=worker_root["dev"]), pieces[i+1:i+2])
    return {"before": sample, "after": copy.deepcopy(sample), "fds": {str(i): null for i in range(3)},
            "root": root, "cwd": cwd, "tree": tree}


class PiExposureTests(unittest.TestCase):
    def check(self, value, namespace=NAMESPACE):
        return verify_pi_exposure(value, device="253:7", backing_devices=["259:0"], pid=71, start_ticks=955,
                                  mount_namespace=9001, worker_root=WORKER_ROOT, admitted_cwd=ADMITTED,
                                  namespace=namespace)

    def test_bound_gate_and_complete_device_free_walk(self):
        self.assertIsNone(self.check(pi_exposure_sample()))

    def test_mountinfo_and_pinned_tree_must_agree_at_every_boundary(self):
        for namespace in (NAMESPACE | {"/dev": (22, "0:21")}, NAMESPACE | {"/invisible": (9, "8:1")},
                          NAMESPACE | {CWD_PATH: (3, "8:9")}, {k:v for k,v in NAMESPACE.items() if k != CWD_PATH}):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                self.check(pi_exposure_sample(), namespace)

    def test_descriptor_substitution_and_changed_tasks_refused(self):
        for name, change in (("other thread", lambda e: e["before"]["task_ids"].append(72)),
                ("extra fd", lambda e: e["after"]["fd_numbers"].append(4)),
                ("omitted stat", lambda e: e["fds"].pop("2")),
                ("stdio file", lambda e: e["fds"].update({"0": _stat(stat.S_IFREG, dev="253:7")})),
                ("host directory fd", lambda e: e["fds"].update({"2": _stat(stat.S_IFDIR, dev="8:1")})),
                ("not stopped", lambda e: e["before"].update(state="R")),
                ("stale process", lambda e: e["before"].update(start_ticks=54)),
                ("different namespace", lambda e: e["after"].update(mount_namespace=33)),
                ("forged numeric boolean", lambda e: e["before"].update(fd_numbers=[False, True, 2]))):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence = pi_exposure_sample()
                change(evidence)
                self.check(evidence)

    def test_wrong_directory_and_incomplete_walk_refused(self):
        for name, change in (("state cwd", lambda e: e.update(cwd=_stat(stat.S_IFDIR, dev="253:7"))),
                ("other root", lambda e: e.update(root=_stat(stat.S_IFDIR, ino=900))),
                ("detached cwd", lambda e: e["tree"][CWD_PATH].update(stat=_stat(stat.S_IFDIR, ino=901))),
                ("walk omitted listed device", lambda e: e["tree"].pop("/dev/null")),
                ("foreign root bind", lambda e: e["tree"]["/"].update(stat=e["root"] | {"mnt_id": 999})),
                ("directory unavailable", lambda e: e["tree"]["/dev"].pop("before")),
                ("new child", lambda e: e["tree"]["/dev"]["after"].append("changed")),
                ("unlisted stat", lambda e: e["tree"].update({"/foreign": {"stat": e["cwd"]}}))):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence = pi_exposure_sample()
                change(evidence)
                self.check(evidence)

    def test_state_files_under_aliases_and_mapped_or_raw_block_nodes_refused(self):
        for member in ({"stat": _stat(stat.S_IFREG, dev="253:7")},
                       {"stat": _stat(stat.S_IFBLK, rdev="253:7")},
                       {"stat": _stat(stat.S_IFBLK, rdev="259:0")},
                       {"stat": _stat(stat.S_IFCHR, rdev="10:236")},
                       {"stat": _stat(stat.S_IFLNK), "resolved": _stat(stat.S_IFREG, dev="253:7")},
                       {"stat": _stat(stat.S_IFLNK), "resolved": _stat(stat.S_IFBLK, rdev="259:0")},
                       {"stat": _stat(stat.S_IFLNK), "resolved": _stat(stat.S_IFDIR, dev="1:2", ino=11)},
                       {"stat": _stat(stat.S_IFLNK), "resolved": _stat(stat.S_IFDIR, **WORKER_ROOT, mnt_id=999)}):
            with self.subTest(member=member), self.assertRaises(ValueError):
                evidence = pi_exposure_sample()
                evidence["tree"]["/var"]["before"].append("mirror")
                evidence["tree"]["/var"]["after"].append("mirror")
                evidence["tree"]["/var/mirror"] = member
                self.check(evidence)

    def test_reserved_names_refused_even_as_ordinary_files_on_another_device(self):
        for path in ("/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-provider", "/run/aragorn-pilot-state"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "state path visible"):
                evidence = pi_exposure_sample()
                t = evidence["tree"]
                if path.startswith("/run/"):
                    for edge in ("before", "after"):
                        t["/"][edge] = sorted(t["/"][edge] + ["run"])
                    t["/run"] = {"stat": _stat(stat.S_IFDIR, ino=900), "before": [], "after": []}
                parent, _, leaf = path.rpartition("/")
                for edge in ("before", "after"):
                    t[parent][edge] = sorted(t[parent][edge] + [leaf])
                t[path] = {"stat": _stat(stat.S_IFREG)}
                self.check(evidence)
