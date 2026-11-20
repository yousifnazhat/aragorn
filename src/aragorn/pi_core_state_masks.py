"""Verify retained, independently witnessed negative lookups for the fixed private /dev.

The enclosing reader authenticates capture, latest head, witness, and both raw
mountinfo streams. No observation is produced here. Every returned leaf still
goes through the ordinary root-to-child namespace walk.
"""
import stat

from .pi_core_state_exposure import _device


_DIRS = {"/dev/pts", "/dev/shm", "/dev/hugepages"}
_LINK = "/dev/ptmx"
_SOURCE = "/run/systemd/inaccessible/dir"
_BASE = ("mode", "dev", "ino", "rdev", "mnt_id")
_PRINCIPAL = ("pid", "start_ticks", "mount_namespace", "user_namespace", "uid", "gid")
_CAPS = ("cap_effective", "cap_permitted", "cap_inheritable", "cap_ambient", "cap_bounding")
# Linux arm64 asm/fcntl.h overrides the asm-generic O_DIRECTORY and O_NOFOLLOW.
_DIR_FLAGS = 0o40000 | 0o100000 | 0o2000000
_MAX_WINDOW_NS = 5_000_000_000


def _need(value, message):
    if not value:
        raise ValueError("Pi mask proof: " + message)


def _fields(value, *keys):
    _need(type(value) is dict and value.keys() == set(keys), "incomplete or unexpected fields")


def _int(value, lo=1, hi=(1 << 64) - 1):
    _need(type(value) is int and lo <= value <= hi, "invalid integer")
    return value


def _subject(value, manager=False):
    _fields(value, *_PRINCIPAL)
    _int(value["pid"], 1, (1 << 31) - 1)
    for key in ("start_ticks", "mount_namespace", "user_namespace"):
        _int(value[key])
    for key in ("uid", "gid"):
        _int(value[key], 0 if manager else 1, 0 if manager else (1 << 31) - 1)


def _stat(value, forbidden, *, owner=False):
    _fields(value, *_BASE, *(("uid", "gid") if owner else ()))
    _int(value["mode"], 1, 0o177777)
    _int(value["ino"])
    _int(value["mnt_id"])
    _need(_device(value["dev"]) not in forbidden and _device(value["rdev"]) == "0:0",
          "backing volume exposed or unexpected special object")
    if owner:
        _int(value["uid"], 0, 0)
        _int(value["gid"], 0, 0)
    return {k: value[k] for k in _BASE}


def _mount(table, path):
    _need(type(table) is dict and path in table, "missing mount")
    mount = table[path]
    _fields(mount, "mount_id", "dev", "fs_type", "root", "options")
    _int(mount["mount_id"])
    _device(mount["dev"])
    _need(type(mount["fs_type"]) is str and type(mount["root"]) is str and
          type(mount["options"]) is frozenset and all(type(v) is str for v in mount["options"]), "invalid mount")
    return mount


def _binding(namespace, path, observed):
    binding = namespace.get(path)
    _need(type(binding) is tuple and len(binding) == 2 and _int(binding[0]) == observed["mnt_id"]
          and _device(binding[1]) == observed["dev"], "unbound namespace member")


def _context(ctx, subject, root, forbidden, *, probe):
    _fields(ctx, *_PRINCIPAL, "euid", "suid", "fsuid", "egid", "sgid", "fsgid",
            "groups", *_CAPS, "no_new_privs", "root")
    principal = {k: ctx[k] for k in _PRINCIPAL}
    _subject(principal)
    _need(all(principal[k] == value for k, value in subject.items()
              if not probe or k not in ("pid", "start_ticks")), "foreign principal or namespace")
    for key in ("uid", "gid"):
        _need(all(_int(ctx[prefix + key]) == subject[key] for prefix in ("e", "s", "fs")),
              "different effective, saved or filesystem credentials")
    for key in _CAPS:
        _int(ctx[key], 0, 0)
    _need(type(ctx["groups"]) is list and not ctx["groups"] and ctx["no_new_privs"] is True,
          "unexpected groups or privilege")
    _need(_stat(ctx["root"], forbidden) == root, "different filesystem root")


def _probe(record, name, fd, start, stop, *, link=False):
    _fields(record, "syscall", "dirfd", "name", "flags", "result", "errno", "started_ns", "finished_ns")
    _need(record["syscall"] == ("newfstatat" if link else "openat") and record["name"] == name,
          "wrong lookup path or operation")
    _need(_int(record["dirfd"], 3, (1 << 31) - 1) == fd, "lookup not anchored to held /dev")
    flags = 0 if link else _DIR_FLAGS
    _int(record["flags"], flags, flags)
    _int(record["result"], -1, -1)
    _int(record["errno"], 13, 13)  # Linux EACCES; absence or an arbitrary failure is not denial.
    begin, end = _int(record["started_ns"]), _int(record["finished_ns"])
    _need(start <= begin < end <= stop, "lookup outside bounded witness interval")


def verify_masks(exposure, witness, *, subject, namespace, device, backing_devices,
                 manager_subject, manager_mounts, worker_mounts):
    """Return only exact, corroborated walk leaves (never an empty directory listing)."""
    _fields(witness, "schema", "manager", "worker", "source", "before", "after", "directories", "ptmx")
    _need(witness["schema"] == "aragorn/pi-core-mask-witness/v1", "wrong proof version")
    for expected, actual, manager in ((subject, witness["worker"], False),
                                      (manager_subject, witness["manager"], True)):
        _subject(expected, manager)
        _subject(actual, manager)
        _need(expected == actual, "witness for another role")
    _need(subject["pid"] != manager_subject["pid"] and subject["mount_namespace"] != manager_subject["mount_namespace"],
          "worker and manager must be distinct")
    _need(isinstance(backing_devices, (list, tuple, set, frozenset)) and 0 < len(backing_devices) <= 64,
          "missing physical backing")
    for table in (worker_mounts, manager_mounts, namespace):
        _need(type(table) is dict and 0 < len(table) <= 8192 and
              all(type(p) is str and p.startswith("/") for p in table), "invalid mount projection")
    forbidden = {_device(device), *(_device(v) for v in backing_devices), "0:0"}
    source = witness["source"]
    _fields(source, "path", "fd", "before", "after", "path_before", "path_after", "entries_before", "entries_after")
    _need(source["path"] == _SOURCE, "wrong manager source")
    _int(source["fd"], 3, (1 << 31) - 1)
    for key in ("entries_before", "entries_after"):
        _need(type(source[key]) is list and not source[key], "manager did not witness an empty backing")
    backing = _stat(source["before"], forbidden, owner=True)
    # The two privileged enumerations refer to the same held manager fd.
    # Its opening and closing fstat must both match the separately named path.
    _need(all(backing == _stat(source[k], forbidden, owner=True) for k in ("after", "path_before", "path_after"))
          and backing["mode"] == stat.S_IFDIR, "manager backing changed or is not mode 0000")
    run = _mount(manager_mounts, "/run")
    _need((run["mount_id"], run["dev"], run["fs_type"], run["root"]) ==
          (backing["mnt_id"], backing["dev"], "tmpfs", "/"),
          "manager backing is not directly on /run tmpfs")
    _need(all(type(p) is str and not (p in ("/run/systemd", "/run/systemd/inaccessible", _SOURCE)
              or p.startswith(_SOURCE + "/")) for p in manager_mounts), "source is overmounted")

    _need(type(exposure) is dict and {"root", "tree"} <= exposure.keys(), "missing exposure")
    tree = exposure["tree"]
    _need(type(tree) is dict and "/dev" in tree and type(tree["/dev"]) is dict, "missing /dev walk")
    root = _stat(exposure["root"], forbidden)
    _need(stat.S_ISDIR(root["mode"]), "wrong worker root")
    parent = tree["/dev"]
    _fields(parent, "stat", "before", "after")
    dev_stat = _stat(parent["stat"], forbidden)
    _need(stat.S_ISDIR(dev_stat["mode"]), "invalid /dev directory")
    _binding(namespace, "/dev", dev_stat)
    dev_mount = _mount(worker_mounts, "/dev")
    _need((dev_stat["mnt_id"], dev_stat["dev"]) == (dev_mount["mount_id"], dev_mount["dev"]),
          "unbound worker mount")
    for listing in (parent["before"], parent["after"]):
        _need(type(listing) is list and all(type(n) is str for n in listing)
              and listing == sorted(set(listing)), "incomplete /dev enumeration")
    _need(parent["before"] == parent["after"], "/dev enumeration changed")
    names = {"/dev/" + n for n in parent["before"]}
    visible = tree.keys() & (_DIRS | {_LINK})
    _need("/dev/pts" in visible and visible == names & (_DIRS | {_LINK}), "missing /dev mask coverage")
    _need(type(witness["directories"]) is dict and witness["directories"].keys() == visible & _DIRS,
          "wrong directory proof set")
    _need((witness["ptmx"] is not None) == (_LINK in visible), "wrong ptmx proof presence")
    frames = [witness["before"], witness["after"]]
    for frame in frames:
        _fields(frame, "worker", "probe", "dev_fd", "dev_stat", "boottime_ns")
        _context(frame["worker"], subject, root, forbidden, probe=False)
        _context(frame["probe"], subject, root, forbidden, probe=True)
        _need(frame["probe"]["pid"] not in (subject["pid"], manager_subject["pid"]), "probe not independent")
        _int(frame["dev_fd"], 3, (1 << 31) - 1)
        _need(_stat(frame["dev_stat"], forbidden) == dev_stat, "held dirfd is not worker /dev")
        _int(frame["boottime_ns"])
    first, last = frames
    _need(all(first[k] == last[k] for k in ("worker", "probe", "dev_fd", "dev_stat")), "probe context changed")
    start, stop = first["boottime_ns"], last["boottime_ns"]
    _need(0 < stop - start <= _MAX_WINDOW_NS, "unbounded probe window")

    leaves = {}
    mounts_seen = {backing["mnt_id"], dev_stat["mnt_id"]}
    for path in sorted(visible):
        link = path == _LINK
        proof = witness["ptmx"] if link else witness["directories"][path]
        _fields(proof, "before", "after", "probe", *(("readlink_before", "readlink_after") if link else ()))
        member = tree[path]
        _fields(member, "stat", "mask_proof")
        obj = _stat(proof["before"], forbidden)
        _need(obj == _stat(proof["after"], forbidden) == _stat(member["stat"], forbidden), "path object changed")
        _probe(proof["probe"], path[5:], first["dev_fd"], start, stop, link=link)
        if link:
            _need(proof["readlink_before"] == proof["readlink_after"] == "pts/ptmx" and
                  member["mask_proof"] == "denied-ptmx" and path not in worker_mounts and path not in namespace
                  and obj["mode"] == (stat.S_IFLNK | 0o777) and
                  (obj["dev"], obj["mnt_id"]) == (dev_stat["dev"], dev_stat["mnt_id"]), "unproven ptmx link")
        else:
            # Structural DAC proof for the actual worker (not a claim that a
            # helper's seccomp/LSM policy is identical): no effective DAC
            # capabilities, no supplementary groups, no read/search permission
            # for *any* owner class on this manager-verified root-owned inode.
            _need(member["mask_proof"] == "denied-directory" and obj == {**backing, "mnt_id": obj["mnt_id"]}
                  and obj["mnt_id"] not in mounts_seen, "masked inode does not match separate manager backing")
            mount = _mount(worker_mounts, path)
            _need((mount["mount_id"], mount["dev"], mount["fs_type"], mount["root"]) ==
                  (obj["mnt_id"], obj["dev"], "tmpfs", _SOURCE[4:]) and
                  {"ro", "noexec"} <= mount["options"], "wrong mask mount")
            _binding(namespace, path, obj)
            _need(not any(p.startswith(path + "/") for p in worker_mounts), "nested mount under named mask")
            mounts_seen.add(obj["mnt_id"])
        leaves[path] = member
    return leaves
