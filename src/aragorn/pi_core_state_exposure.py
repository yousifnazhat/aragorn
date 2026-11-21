"""Check a retained, worker-visible namespace walk and stopped-gate handle inventory.

Offline comparison only. Origin, consistent acquisition under Pi's visibility rules,
the stopped executable, and the independently supplied bindings are caller obligations.
"""
import re
import stat


_RESERVED = {"/run/aragorn-pilot-state", "/var/lib/aragorn-runtime-action", "/var/lib/aragorn-runtime-provider"}
_MASK_DIRS = frozenset({"/dev/pts", "/dev/shm", "/dev/hugepages"})
_PTMX = "/dev/ptmx"
_STDIO_LINKS = {"/dev/stdin": "0", "/dev/stdout": "1", "/dev/stderr": "2"}


def _need(condition, reason):
    if not condition:
        raise ValueError("Pi state exposure: " + reason)


def _fields(value, *keys):
    _need(type(value) is dict and value.keys() == set(keys), "incomplete or unexpected fields")


def _uint(value, maximum=(1 << 64) - 1):
    return type(value) is int and 0 < value <= maximum


def _device(value):
    _need(type(value) is str and len(value) <= 21
          and re.fullmatch(r"(?:0|[1-9][0-9]{0,9}):(?:0|[1-9][0-9]{0,9})", value)
          and all(int(n) < 1 << 32 for n in value.split(":")), "invalid device number")
    return value


def _matches_visible_mount(record, devices_by_id):
    # An inherited /dev/null can come from outside Pi's namespace. A known
    # mount ID, however, cannot identify two different filesystem devices.
    mid = record["mnt_id"]
    if mid in devices_by_id:
        return record["dev"] == devices_by_id[mid]
    return stat.S_ISCHR(record["mode"]) and record["rdev"] == "1:3"


def _name(s):
    return (type(s) is str and 0 < len(s) <= 255 and s not in {".", ".."} and "/" not in s
            and all(32 <= ord(c) < 127 for c in s))


def verify_pi_exposure(evidence, *, device, backing_devices, pid, start_ticks, mount_namespace,
                       worker_root, admitted_cwd, namespace):
    """Raise ValueError for exposure or incomplete evidence; return no execution grant.

    dev/rdev are Linux major:minor strings; mnt_id is Linux STATX_MNT_ID for
    the inspected object (including resolved link targets). 'tree' is keyed by absolute path:
    each directory has two independently captured child-name lists surrounding the
    walk, each symlink has a resolved referent stat from the worker's view. No
    pruned, unreadable or unclassified subtrees are accepted.
    """
    return _verify_pi_exposure(evidence, verified_masks={}, device=device, backing_devices=backing_devices,
                               pid=pid, start_ticks=start_ticks, mount_namespace=mount_namespace,
                               worker_root=worker_root, admitted_cwd=admitted_cwd, namespace=namespace)


def _verify_pi_exposure(evidence, *, verified_masks, device, backing_devices, pid, start_ticks,
                        mount_namespace, worker_root, admitted_cwd, namespace, strict_worker_devices=False):
    """Shared walk. Only the successor verifier supplies independently corroborated leaves."""
    _need(isinstance(backing_devices, (tuple, list, set, frozenset)) and
          0 < len(backing_devices) <= 64, "physical backing identities required")
    forbidden = {_device(device), *(_device(d) for d in backing_devices)}
    _need("0:0" not in forbidden, "missing device binding")
    if strict_worker_devices:
        # An unknown filesystem identity cannot exclude service state. This is
        # st_dev only; st_rdev remains zero for objects that are not devices.
        forbidden.add("0:0")
    _need(all(_uint(x) for x in (pid, start_ticks, mount_namespace)), "invalid process binding")
    for expected in (worker_root, admitted_cwd):
        _fields(expected, "dev", "ino")
        _need(_device(expected["dev"]) not in forbidden and _uint(expected["ino"]), "unsafe directory binding")
    _need(worker_root != admitted_cwd, "aliased root and cwd")
    _need(type(namespace) is dict and "/" in namespace and len(namespace) <= 8192,
          "missing mount namespace inventory")
    by_id = {}
    for mount, binding in namespace.items():
        _need(type(mount) is str and mount.startswith("/") and len(mount) <= 4096 and
              (mount == "/" or all(_name(n) for n in mount[1:].split("/"))) and
              type(binding) is tuple and len(binding) == 2, "invalid mount namespace inventory")
        mid, dev = binding
        _need(_uint(mid) and mid not in by_id and _device(dev) not in forbidden, "duplicate mount or state visible")
        by_id[mid] = dev

    def checked_stat(record):
        _fields(record, "mode", "dev", "ino", "rdev", "mnt_id")
        mode = record["mode"]
        _need(_uint(mode, 0o177777) and _uint(record["ino"]) and _uint(record["mnt_id"]), "invalid stat metadata")
        kind = stat.S_IFMT(mode)
        dev, rdev = _device(record["dev"]), _device(record["rdev"])
        _need(dev not in forbidden, "object on state volume or missing device binding")
        # The confined profile exposes no block devices, including aliases for a whole-disk parent.
        _need(kind != stat.S_IFBLK, "block device visible")
        _need(kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO, stat.S_IFSOCK)
              and (rdev in {"1:3", "1:5", "1:7", "1:8", "1:9", "5:0"} if kind == stat.S_IFCHR else rdev == "0:0"),
              "unknown file type or unapproved device node")
        return kind, (dev, record["ino"], record["mnt_id"])

    _fields(evidence, "before", "after", "fds", "root", "cwd", "tree")
    for edge in ("before", "after"):
        sample = evidence[edge]
        _fields(sample, "pid", "start_ticks", "mount_namespace", "state", "task_ids", "fd_numbers")
        for name, value in (("pid", pid), ("start_ticks", start_ticks), ("mount_namespace", mount_namespace)):
            _need(type(sample[name]) is int and sample[name] == value, "wrong process or mount namespace")
        _need(sample["state"] in ("T", "t") and type(sample["task_ids"]) is list
              and len(sample["task_ids"]) == 1 and type(sample["task_ids"][0]) is int
              and sample["task_ids"][0] == pid, "not the stopped, single-task gate")
        _need(type(sample["fd_numbers"]) is list and sample["fd_numbers"] == [0, 1, 2]
              and all(type(n) is int for n in sample["fd_numbers"]), "missing or inherited descriptor")
    _need(evidence["before"] == evidence["after"], "gate changed during capture")
    fds = evidence["fds"]
    _fields(fds, "0", "1", "2")
    for record in fds.values():
        _need(checked_stat(record)[0] == stat.S_IFCHR and record["rdev"] == "1:3", "stdio not /dev/null")
        _need(_matches_visible_mount(record, by_id), "stdio device differs from its visible mount")

    def pinned_directory(record, expected):
        kind, obj = checked_stat(record)
        return kind == stat.S_IFDIR and obj[:2] == (expected["dev"], expected["ino"])
    _need(pinned_directory(evidence["root"], worker_root) and pinned_directory(evidence["cwd"], admitted_cwd),
          "wrong process root or working directory")

    tree = evidence["tree"]
    _need(type(tree) is dict and 0 < len(tree) <= 131072 and namespace.keys() <= tree.keys(),
          "unbounded namespace walk or uninspected mount")
    _need(type(verified_masks) is dict and verified_masks.keys() <= _MASK_DIRS | {_PTMX}
          and verified_masks.keys() <= tree.keys(), "unrecognised or absent mask")
    if verified_masks:
        _need("/dev/pts" in verified_masks
              and verified_masks.keys() == (tree.keys() & (_MASK_DIRS | {_PTMX})),
              "incomplete mask coverage")
    masked_children = tuple(path + "/" for path in verified_masks.keys() & _MASK_DIRS)
    denied_objects = {(entry["stat"]["dev"], entry["stat"]["ino"])
                      for path, entry in verified_masks.items() if path in _MASK_DIRS}
    dirs, dir_links, named = set(), set(), {"/"}
    saw_cwd = False
    for path, member in tree.items():
        _need(type(path) is str and len(path) <= 4096 and path.startswith("/")
              and (path == "/" or all(_name(n) for n in path[1:].split("/"))), "invalid namespace path")
        _need(path not in _RESERVED, "state path visible")
        _need(not path.startswith(masked_children), "descendant of denied mount")
        _need(type(member) is dict and "stat" in member, "missing namespace metadata")
        kind, obj = checked_stat(member["stat"])
        stdio_fd = _STDIO_LINKS.get(path) if strict_worker_devices else None
        if stdio_fd is not None:
            _need(kind == stat.S_IFLNK, "standard descriptor path is not a link")
        mount = path
        while mount not in namespace:
            mount = mount.rpartition("/")[0] or "/"
        _need((obj[2], obj[0]) == namespace[mount], "path stat differs from enclosing mount")
        if path == "/":
            _need(member["stat"] == evidence["root"], "namespace walk is for another root")
        if path in verified_masks:
            # A marker in the witness cannot supply its own proof. Object type,
            # pinned enclosing mount and reachable parent are still mandatory.
            _fields(member, "stat", "mask_proof")
            _need(member == verified_masks[path], "mask differs from independently verified member")
            if path == _PTMX:
                _need(kind == stat.S_IFLNK and member["mask_proof"] == "denied-ptmx"
                      and path not in namespace, "not the confined terminal symlink")
            else:
                _need(kind == stat.S_IFDIR and stat.S_IMODE(member["stat"]["mode"]) == 0
                      and member["mask_proof"] == "denied-directory" and path in namespace,
                      "not a denied directory mount")
            continue
        if kind == stat.S_IFDIR:
            _fields(member, "stat", "before", "after")
            names = member["before"]
            if verified_masks:
                # A capability-free worker cannot supply a successful listing for this object.
                mode = member["stat"]["mode"]
                _need(obj[:2] not in denied_objects and mode & 0o444 and (not names or mode & 0o111),
                      "unproved access to an unreadable directory")
            _need(type(names) is list and len(names) <= len(tree) and all(_name(n) for n in names)
                  and names == sorted(set(names)) and names == member["after"], "incomplete or changed directory")
            for n in names:
                name = path.rstrip("/") + "/" + n
                _need(name in tree, "listed namespace entry not inspected")
                named.add(name)
            dirs.add(obj)
            if path.startswith("/var/lib/aragorn/admitted/.aragorn-versions/"):
                saw_cwd |= member["stat"] == evidence["cwd"]
        elif kind == stat.S_IFLNK:
            _fields(member, "stat", "resolved")
            target_kind, target = checked_stat(member["resolved"])
            _need(target_kind != stat.S_IFLNK, "link resolution incomplete")
            if stdio_fd is not None:
                _need(member["resolved"] == fds[stdio_fd], "standard link differs from held descriptor")
            elif strict_worker_devices:
                _need(target[2] in by_id, "link resolves outside worker namespace")
            _need(_matches_visible_mount(member["resolved"], by_id),
                  "link resolves outside worker namespace")
            if target_kind == stat.S_IFDIR:
                dir_links.add(target)
        else:
            _fields(member, "stat")
    _need(named == tree.keys() and dir_links <= dirs and saw_cwd, "unlisted entry, unwalked directory link or missing admitted cwd")
