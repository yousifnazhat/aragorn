"""Verify the measured stopped-worker handles, not a substitute for its directory walk."""
import re
import stat

from .pi_core_state_admission import _keys, _need, _same, _uint
from .pi_core_state_exposure import _device, _matches_visible_mount
from .pi_core_state_masks import _binding, _mount, _stat, _subject


SCHEMA = "aragorn/pi-core-stopped-worker-spine/v1"
_VERSION_DIR = re.compile(r"/var/lib/aragorn/admitted/\.aragorn-versions/"
                          r"[a-z0-9][a-z0-9._-]{0,127}/[0-9a-f]{64}-[0-9a-f]{64}\Z")


def verify_worker_spine(spine, *, binding, view, namespace, worker_mounts):
    """The enclosing verifier authenticates original bytes, mount streams and the B67 mask probe."""
    _keys(spine, ("schema", "worker", "admitted_path", "before", "after", "objects",
                  "opened_boottime_ns", "closed_boottime_ns"))
    _need(spine["schema"] == SCHEMA and binding["schema"] == "aragorn/pi-core-stopped-mask-binding/v3"
          and binding["capture_mode"] == "STOPPED_WORKER_HANDLE_SPINE"
          and view["schema"] == "aragorn/pi-core-stopped-mask-view/v3", "wrong stopped-worker spine format")
    worker, path = spine["worker"], spine["admitted_path"]
    _subject(worker)
    _same(worker, binding["worker"], "different stopped worker")
    _same(worker, view["worker"], "different worker view")
    _need(type(path) is str and _VERSION_DIR.fullmatch(path) and path == binding["admitted_path"],
          "different prepared admitted path")
    start, stop = (_uint(spine[k]) for k in ("opened_boottime_ns", "closed_boottime_ns"))
    outer_start, outer_stop = (_uint(view[k]) for k in ("opened_boottime_ns", "closed_boottime_ns"))
    _need(outer_start <= start < stop <= outer_stop and outer_stop - outer_start <= 5_000_000_000,
          "worker spine outside stopped observation interval")
    for key in ("before", "after"):
        frame = spine[key]
        _keys(frame, ("pid", "start_ticks", "mount_namespace", "state", "task_ids", "fd_numbers"))
        _same({k: frame[k] for k in ("pid", "start_ticks", "mount_namespace")},
              {k: worker[k] for k in ("pid", "start_ticks", "mount_namespace")}, "stopped subject changed")
        _need(frame["state"] in ("T", "t"), "worker not stopped")
        _same(frame["task_ids"], [worker["pid"]], "worker is not a singleton")
        _same(frame["fd_numbers"], [0, 1, 2], "unexpected stopped worker handles")
    _same(spine["before"], spine["after"], "stopped-worker frame changed")
    obj = spine["objects"]
    _keys(obj, ("before", "after"))
    _same(obj["before"], obj["after"], "stopped-worker handles changed")
    held = obj["before"]
    _keys(held, ("root", "cwd", "named_cwd", "fds"))
    storage = binding["storage"]
    forbidden = {_device(storage["device"]), *(_device(d) for d in storage["backing_devices"])}
    for key, location in (("root", "/"), ("cwd", path)):
        row = _stat(held[key], forbidden)
        _need(stat.S_ISDIR(row["mode"]), "not a stopped-worker directory")
        _binding(namespace, location, row)
    _need("ro" in _mount(worker_mounts, path)["options"], "admitted cwd is not a read-only bind")
    _need((held["cwd"]["dev"], held["cwd"]["ino"]) != (held["root"]["dev"], held["root"]["ino"]),
          "worker root aliases its cwd")
    _same(held["named_cwd"], held["cwd"], "named installed bundle is not the stopped process cwd")
    _same(held["root"], view["worker_root"], "root differs from independently held mask view")
    _keys(held["fds"], ("0", "1", "2"))
    devices_by_id = dict(namespace.values())  # From the verified original worker mountinfo.
    for row in held["fds"].values():
        _keys(row, ("dev", "rdev", "mode", "ino", "mnt_id"))
        _uint(row["ino"])
        _uint(row["mnt_id"])
        _need(stat.S_ISCHR(_uint(row["mode"], high=1 << 16)) and row["rdev"] == "1:3"
              and _device(row["dev"]) not in forbidden, "stdio is not a safe null device")
        _need(_matches_visible_mount(row, devices_by_id), "stdio device differs from its visible mount")
    # stdio can be inherited from the service manager's /dev. Do not demand
    # private-/dev inode or mount equality, and do not synthesize a tree here.
    return {k: spine[k] for k in ("before", "after", "admitted_path")} | {
        k: held[k] for k in ("root", "cwd", "fds")}
