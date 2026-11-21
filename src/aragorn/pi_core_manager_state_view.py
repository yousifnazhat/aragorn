"""Compare retained manager statx frames against its independently parsed mountinfo.

The caller authenticates the stopped observation, original mount stream and storage
binding. Matching records do not establish POSIX ACLs, a safe recovery, or readiness.
"""
import stat

from .pi_core_state_admission import _dev, _keys, _need, _same, _uint
from .pi_core_state_masks import _mount
from .pi_core_state_mounts import ACTION, ANCHOR, PROVIDER


_ROOTS = (ANCHOR, ACTION, PROVIDER)
_BINDS = (ACTION, PROVIDER)
_OBJECT = ("dev", "ino", "uid", "gid", "mode")


def _mount_ids(storage, mounts):
    _keys(storage, ("device", "backing_devices", "fs_type"))
    dev = _dev(storage["device"])
    backing = storage["backing_devices"]
    _need(type(backing) is list and 1 <= len(backing) <= 16 and
          len({_dev(b) for b in backing}) == len(backing) and dev not in backing and
          storage["fs_type"] in ("ext4", "xfs"), "unknown manager storage mapping")
    _need(type(mounts) is dict and 0 < len(mounts) <= 8192 and set(_ROOTS) <= mounts.keys(),
          "missing manager state mounts")
    ids, seen = {}, set()
    for path in mounts:
        _need(type(path) is str and path.startswith("/"), "invalid manager mount path")
        m = _mount(mounts, path)
        mid = _uint(m["mount_id"], high=1 << 32)
        _need(mid not in seen and m["dev"] not in backing, "aliased manager mount or exposed backing")
        seen.add(mid)
        if path not in _ROOTS:
            _need(m["dev"] != dev and path != "/var/lib" and not any(path.startswith(p + "/") for p in _ROOTS),
                  "aliased or overmounted manager state")
            continue
        _need(m["dev"] == dev and m["fs_type"] == storage["fs_type"] and
              m["root"] == ("/" if path == ANCHOR else path) and
              {"rw", "nodev", "nosuid", "noexec"} <= m["options"] and
              m["options"].isdisjoint({"ro", "dev", "suid", "exec"}), "wrong manager state mount")
        ids[path] = mid
    return ids


def _object(row, path, device, mount_id):
    _keys(row, (*_OBJECT, "rdev", "mnt_id"))
    _uint(row["ino"])
    _uint(row["uid"], 0, 1)
    _uint(row["gid"], 0, 1)
    _need(_uint(row["mode"], high=1 << 16) == (stat.S_IFDIR | (0o755 if path == ACTION else 0o700)) and
          _uint(row["mnt_id"], high=1 << 32) == mount_id and type(row["dev"]) is str and row["dev"] == device
          and type(row["rdev"]) is str and row["rdev"] == "0:0",
          "manager directory type, mode, device or mount differs")
    return {k: row[k] for k in _OBJECT}


def verify_manager_state(record, storage, manager_mounts):
    """Return B58 source_roots and manager targets (including the directly observed anchor).

    Source rows refer to the anchor and to subdirectories looked up *on that
    mount*. The two separately held service destinations must be distinct bind
    mounts of those same directory objects. No filesystem or process is opened.
    """
    ids = _mount_ids(storage, manager_mounts)
    _keys(record, ("before", "after"))
    observed = _frame(record["before"], storage["device"], ids)
    _frame(record["after"], storage["device"], ids)
    _same(record["before"], record["after"], "manager state sources or targets changed")
    return observed


def _frame(frame, device, ids):
    _keys(frame, ("sources", "targets"))
    _keys(frame["sources"], _ROOTS)
    _keys(frame["targets"], _BINDS)
    source = {p: _object(frame["sources"][p], p, device, ids[ANCHOR]) for p in _ROOTS}
    _need(len({v["ino"] for v in source.values()}) == len(source), "manager source directories alias")
    targets = {ANCHOR: {**source[ANCHOR], "mount_id": ids[ANCHOR]}}
    for p in _BINDS:
        observed = _object(frame["targets"][p], p, device, ids[p])
        _same(observed, source[p], "manager service target differs from its backing directory")
        targets[p] = {**observed, "mount_id": ids[p]}
    return source, targets
