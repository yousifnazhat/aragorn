"""Read a retained Linux mountinfo stream; never open a namespace, device or mount."""
import re

from .runtime_tetragon_stats_map import _mount_path


ANCHOR = "/run/aragorn-pilot-state"
ACTION = "/var/lib/aragorn-runtime-action"
PROVIDER = "/var/lib/aragorn-runtime-provider"
_TARGETS = {ANCHOR, ACTION, PROVIDER}
_EXPECTED = {"manager": _TARGETS, "action": {ACTION}, "sensor": {ACTION}, "provider": set(), "pi": set()}
_DEVICE = re.compile(rb"(?:0|[1-9][0-9]{0,6}):(?:0|[1-9][0-9]{0,6})")
_ID = re.compile(rb"[1-9][0-9]{0,9}")
# A layered/network/user filesystem could re-export state under a different st_dev.
_DIRECT_FS = frozenset(b"squashfs erofs ext4 xfs tmpfs ramfs rootfs proc sysfs cgroup2 devtmpfs devpts "
                       b"mqueue hugetlbfs securityfs bpf tracefs debugfs configfs efivarfs pstore nsfs".split())


def _need(ok, why):
    if not ok:
        raise ValueError(why)


def _options(raw):
    fields = raw.split(b",")
    values = set(fields)
    _need(b"" not in values and len(values) == len(fields)
          and len(values & {b"ro", b"rw"}) == 1
          and all(not pair <= values for pair in ({b"dev", b"nodev"}, {b"exec", b"noexec"}, {b"suid", b"nosuid"})),
          "ambiguous mount options")
    return values


def verify_mounts(role: str, raw: bytes, *, device: str, fs_type: str, backing_devices=(),
                  namespace=None, mount_details=None) -> dict[str, int]:
    """Return admitted state mounts by target/ID. Caller authenticates capture, volume and role."""
    _need(type(role) is str and role in _EXPECTED and type(device) is str and device.isascii()
          and _DEVICE.fullmatch(device.encode()) and not device.startswith("0:") and fs_type in ("ext4", "xfs"),
          "unsupported role or local block filesystem identity")
    _need(isinstance(backing_devices, (list, tuple, set, frozenset)) and len(backing_devices) <= 64
          and all(type(v) is str and v.isascii() and _DEVICE.fullmatch(v.encode())
                  and not v.startswith("0:") and v != device for v in backing_devices), "bad backing chain")
    backing = {v.encode() for v in backing_devices}
    _need(len(backing) == len(backing_devices), "duplicate backing device")
    _need(type(raw) is bytes and 0 < len(raw) <= 1 << 20 and raw.endswith(b"\n"), "incomplete mountinfo")
    _need(namespace is None or (type(namespace) is dict and not namespace), "expected fresh namespace projection")
    _need(mount_details is None or (type(mount_details) is dict and not mount_details
          and mount_details is not namespace), "expected separate empty mount detail projection")
    details = {} if mount_details is not None else None
    lines = raw[:-1].split(b"\n")
    _need(len(lines) <= 8192, "mountinfo row limit")
    dev = device.encode()
    paths, ids, admitted, block_sources = {}, set(), {}, {}
    state_source = None
    for line in lines:
        sides = line.split(b" - ")
        _need(len(line) <= 16384 and len(sides) == 2 and not re.search(rb"[\x00-\x1f\x7f]", line),
              "malformed mountinfo row")
        left, right = (side.split(b" ") for side in sides)
        _need(len(left) >= 6 and len(right) == 3 and all(left) and all(right)
              and _ID.fullmatch(left[0]) and _ID.fullmatch(left[1]) and _DEVICE.fullmatch(left[2]),
              "malformed mountinfo fields")
        _need(all(v == b"unbindable" or re.fullmatch(rb"(shared|master|propagate_from):[1-9][0-9]{0,9}", v)
                  for v in left[6:]), "unknown optional mountinfo field")
        ident, parent = int(left[0]), int(left[1])
        _need(left[2] not in backing, "physical backing device mounted")
        _need(ident < 1 << 32 and parent < 1 << 32 and right[0] in _DIRECT_FS, "unsupported mount ID or filesystem")
        root, path = (_mount_path(v).decode("utf-8") for v in left[3:5])
        _need(len(left[4]) <= 4096 and len(left[3]) <= 4096, "mount path exceeds bound")
        if right[0] in (b"ext4", b"xfs"):
            source = _mount_path(right[1])
            _need(source.startswith(b"/dev/") and block_sources.setdefault(source, left[2]) == left[2],
                  "conflicting local block source")
        flags, super_flags = _options(left[5]), _options(right[2])
        _need(ident not in ids and path not in paths, "stacked or duplicate mount")
        ids.add(ident)
        paths[path] = (ident, parent, left[2].decode("ascii"))
        if details is not None:
            details[path] = dict(mount_id=ident, dev=paths[path][2], fs_type=right[0].decode("ascii"),
                                 root=root, options=frozenset(flag.decode("ascii") for flag in flags))
        if path == "/var/lib" or any(path.startswith(t + "/") for t in _TARGETS):
            raise ValueError("state parent overmount or nested shadow")
        if left[2] != dev and path not in _TARGETS:
            _need(not any(root == t or root.startswith(t + "/") for t in _TARGETS),
                  "unverified service-state subtree")
            continue
        _need(path in _EXPECTED[role] and left[2] == dev and right[0] == fs_type.encode()
              and _mount_path(right[1]).startswith(b"/dev/") and root == ("/" if path == ANCHOR else path),
              "unapproved backing, subtree or state visibility")
        _need(state_source is None or state_source == right[1], "conflicting backing source")
        state_source = right[1]
        _need(len(left) == 6 and {b"nodev", b"nosuid", b"noexec", b"ro" if role == "sensor" else b"rw"} <= flags
              and b"rw" in super_flags, "state mount access or propagation differs")
        admitted[path] = ident
    _need("/" in paths and set(admitted) == _EXPECTED[role], "missing namespace root or required state mount")
    root_id, parent, _ = paths["/"]
    _need(parent == root_id or parent not in ids, "ambiguous namespace root")
    for path, (_, parent, _) in paths.items():
        if path == "/":
            continue
        ancestor = path.rpartition("/")[0] or "/"
        while ancestor not in paths:
            ancestor = ancestor.rpartition("/")[0] or "/"
        _need(paths[ancestor][0] == parent, "incomplete or shadowed mount topology")
    if namespace is not None:
        namespace.update({path: (ident, devnum) for path, (ident, _, devnum) in paths.items()})
    if mount_details is not None:
        mount_details.update(details)
    return admitted
