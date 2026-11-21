"""Read held kernel objects for a sensor already owned by the service lifecycle.

No task is started, joined, signalled or stopped. Return raw mount streams and
partial observations, not evidence of absent paths, end-to-end health or authority.
"""
from contextlib import ExitStack, contextmanager
import fcntl
import hashlib
import os
import re
import threading
import time

from . import pi_core_stopped_mask_view as kernel
from .pi_core_manager_state_view import _object
from .pi_core_state_admission import _dev, _keys, _need, _same, _uint, _uuid
from .pi_core_state_mounts import ACTION, ANCHOR, PROVIDER, verify_mounts


SCHEMA = "aragorn/pi-core-sensor-state-view/v1"
UUID_SCHEMA = "aragorn/pi-core-sensor-state-view/v2"
DM_SCHEMA = "aragorn/pi-core-sensor-state-view/v3"
LEAF_SCHEMA = "aragorn/pi-core-sensor-state-view/v4"
LUKS_SCHEMA = "aragorn/pi-core-sensor-state-view/v5"
_FS_IOC_GETFSUUID = 0x80111500  # ARM64 Linux _IOR(0x15, 0, struct fsuuid2)
_STATE_MAGIC = {"ext4": 0xef53, "xfs": 0x58465342}
_UNIT = "aragorn-pi-sensor.service"
_CGROUP = ("0::/system.slice/" + _UNIT + "\n").encode("ascii")


def _identity(i):
    _keys(i, ("role", "unit", "pid", "start_ticks", "uid", "gid", "invocation_id"))
    _need(i["role"] == "sensor" and i["unit"] == _UNIT and type(i["invocation_id"]) is str and
          re.fullmatch("[0-9a-f]{32}", i["invocation_id"]) and int(i["invocation_id"], 16) != 0,
          "invalid sensor role or invocation")
    for key in ("pid", "uid", "gid"):
        _uint(i[key], high=1 << 31)
    _uint(i["start_ticks"])
    return i.copy()


def _namespace(stack, proc, name, mount):
    ns = kernel._proc_child(stack, proc, "ns", os.O_RDONLY | os.O_DIRECTORY, mount)
    fd = kernel._magic(stack, ns, name, os.O_RDONLY, mount)
    _need(kernel._filesystem(fd) == kernel._NSFS, "unexpected sensor observation namespace handle")
    return _uint(os.fstat(fd).st_ino)


def _boot_id(stack, proc, mount, deadline):
    for part in ("sys", "kernel", "random"):
        proc = kernel._proc_child(stack, proc, part, os.O_RDONLY | os.O_DIRECTORY, mount)
    raw = kernel._read(proc, "boot_id", 37, mount, deadline)
    _need(len(raw) == 37 and raw.endswith(b"\n"), "incomplete kernel boot ID")
    return _uuid(raw[:-1].decode("ascii"))


def _sensor(stack, role, mount, identity, deadline):
    # A service sensor is not the stopped Pi worker or its credential probe:
    # it may have the action group and special caps. Do not apply a worker frame
    # or claim which service code was consumed from these task credentials.
    pid, proc = role
    ticks, _, states, threads, creds = kernel._parse_subject(kernel._read(proc, "stat", 8192, mount, deadline),
        kernel._read(proc, "status", 65536, mount, deadline), pid)
    _need(ticks == identity["start_ticks"] and threads == 1 and all(s in ("S","R","D") for s in states) and
          all(creds[p + key] == identity[key] for p in ("", "e", "s", "fs") for key in ("uid","gid")),
          "different sensor process generation or effective identity")
    cgroup = kernel._read(proc, "cgroup", 8192, mount, deadline)
    _need(cgroup == _CGROUP, "sensor does not occupy its exact unified service cgroup")
    root = kernel._magic(stack, proc, "root", os.O_PATH | os.O_DIRECTORY, mount)
    subject = dict(pid=pid, start_ticks=ticks, uid=creds["uid"], gid=creds["gid"],
                   **{field: _namespace(stack, proc, key, mount) for key,field in kernel._NS.items()})
    return subject, (creds, kernel._stat(root)), root, cgroup


def _subjects(stack, proc, mount, roles, identity, deadline):
    mgr, mc, mroot, _ = kernel._frame(stack, roles["manager"], mount, deadline, kind="manager")
    _, cc, _, _ = kernel._frame(stack, roles["caller"], mount, deadline, kind="caller")
    _need(all(mc[k] == v for k,v in cc.items() if k not in ("pid", "start_ticks")),
          "collector thread does not share the manager's view")
    sensor, sc, sroot, cgroup = _sensor(stack, roles["sensor"], mount, identity, deadline)
    _need(mgr["mount_namespace"] != sensor["mount_namespace"], "sensor shares the manager mount namespace")
    clocks = {_namespace(stack, role[1], "time", mount) for role in roles.values()}
    _need(len(clocks) == 1, "collector, manager and sensor do not share a clock")
    clock = dict(clock_id="CLOCK_BOOTTIME", time_namespace_inode=clocks.pop(),
                 boot_id=_boot_id(stack, proc, mount, deadline))
    return (mgr, sensor, clock, cgroup, mc, cc, sc), mroot, sroot


def _action_fds(stack, root):
    held = {"/": root}
    path = ""
    for part in ACTION[1:].split("/"):
        root = kernel._pin(stack, root, part, directory=True)
        path += "/" + part
        held[path] = root
    return held


def _uuid_storage(storage):
    _keys(storage, ("device", "backing_devices", "fs_type"))
    device = _dev(storage["device"])
    backing = storage["backing_devices"]
    _need(type(backing) is list and 1 <= len(backing) <= 16, "invalid UUID storage backing")
    back = [_dev(d) for d in backing]
    _need(device not in back and len(set(back)) == len(back) and
          type(storage["fs_type"]) is str and storage["fs_type"] in _STATE_MAGIC, "unapproved UUID storage")
    return dict(device=device, backing_devices=back, fs_type=storage["fs_type"])


def _uuid_reply(raw):
    _need(type(raw) is bytes and len(raw) == 17 and raw[0] == 16 and any(raw[1:]),
          "unsupported or incomplete filesystem UUID reply")
    return raw.hex()


def _observed_uuid(stack, anchor, expected, raw, storage, deadline):
    # B55 verifies parentage, mount flags, source, aliases and the role's target
    # inventory. A filesystem name in mountinfo alone cannot authorize the ioctl.
    mounts = verify_mounts("manager", raw, **storage)
    _object(expected, ANCHOR, storage["device"], mounts[ANCHOR])
    magic = _STATE_MAGIC[storage["fs_type"]]
    def match(fd):
        kernel._check(deadline)
        _same(kernel._stat(fd, owner=True), expected, "filesystem UUID descriptor is not the observed anchor")
        _need(kernel._filesystem(fd) == magic, "wrong actual filesystem for UUID observation")
    match(anchor)
    # O_PATH cannot service this ioctl. Open only "." at the held anchor;
    # never open a device or resolve an operator-supplied path.
    fd = kernel._own(stack, ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, anchor)
    match(fd)
    kernel._check(deadline)
    result = _uuid_reply(fcntl.ioctl(fd, _FS_IOC_GETFSUUID, bytes(17)))
    match(fd)
    match(anchor)
    return result


def capture_dm_mapping(expected_device, expected_backing_device, *, deadline):
    # Previous profiles do not load or acquire kernel mapping evidence.
    from .pi_core_state_dm_mapping import capture_dm_mapping as capture
    return capture(expected_device, expected_backing_device, deadline=deadline)


def capture_backing_leaf(expected_backing_device, *, deadline):
    from .pi_core_state_backing_leaf import capture_backing_leaf as capture
    return capture(expected_backing_device, deadline=deadline)


def capture_luks_headers(expected_device, expected_diskseq, profile, *, deadline):
    from .pi_core_state_luks_headers import capture_luks_headers as capture
    return capture(expected_device, expected_diskseq, profile, deadline=deadline)


def _edge(stack, subjects, mroot, sroot, held, roles, mount, deadline, uuid_storage=None, observe_dm_mapping=False,
          observe_backing_leaf=False, *, opening_dependency=None):
    # Compare fresh component walks to all the original descriptors, not just
    # a pathname string or a fresh inode from an independently resolved root.
    manager = kernel._manager_state_stats(held[0])
    sensor = kernel._manager_state_stats(held[1])
    _need(manager == kernel._manager_state_stats(kernel._manager_state_fds(stack, mroot)) and
          sensor == kernel._manager_state_stats(_action_fds(stack, sroot)), "held sensor state paths changed")
    raw = _streams(roles, mount, deadline)
    kernel._check(deadline)
    result = subjects, manager, sensor, raw
    if uuid_storage is not None:
        reply = _observed_uuid(stack, held[0][ANCHOR], manager[ANCHOR], raw["manager"], uuid_storage, deadline)
        result = (*result, reply)
        if observe_dm_mapping:
            # The held object is a directory, never a device node. Its filesystem's st_dev
            # selects the mapped device; the directory's own rdev must remain 0:0.
            anchor = held[0][ANCHOR]
            measured = kernel._stat(anchor, owner=True)
            _same(measured, manager[ANCHOR], "mapping anchor changed before capture")
            _need(measured["dev"] == uuid_storage["device"] and measured["rdev"] == "0:0",
                  "mapping source differs from the mounted state directory")
            # At the closing edge, sample the opening mapping's decoded dependency
            # *before* the final mapping query. Both sysfs samples are inside the
            # original B78 bracket; no third device-mapper inquiry is needed.
            if observe_backing_leaf and opening_dependency is not None:
                leaf = capture_backing_leaf(opening_dependency, deadline=deadline)
                kernel._check(deadline)
            mapping = capture_dm_mapping(measured["dev"], uuid_storage["backing_devices"][0], deadline=deadline)
            kernel._check(deadline)
            _need(type(mapping) is dict, "missing raw device-mapper observation")
            result = (*result, mapping)
            if observe_backing_leaf:
                from .pi_core_state_dm_mapping import verify_dm_mapping
                decoded = verify_dm_mapping(mapping, expected_device=measured["dev"],
                                            expected_backing_device=uuid_storage["backing_devices"][0])
                dependency, = decoded["backing_devices"]
                if opening_dependency is None:
                    leaf = capture_backing_leaf(dependency, deadline=deadline)
                else:
                    _same(dependency, opening_dependency, "backing device changed during leaf observations")
                kernel._check(deadline)
                _need(type(leaf) is dict, "missing raw backing-leaf observation")
                result = (*result, leaf, dependency)
            _same(kernel._stat(anchor, owner=True), measured, "mapping anchor changed during capture")
        fresh_anchor = kernel._manager_state_fds(stack, mroot)[ANCHOR]
        _same(kernel._stat(fresh_anchor, owner=True), manager[ANCHOR], "named UUID anchor changed during observation")
        _need(_streams(roles, mount, deadline) == raw, "mount streams changed during UUID observation")
    return result


def _manager_record(stats):
    return dict(sources={ANCHOR:stats[ANCHOR], ACTION:stats[ANCHOR + ACTION], PROVIDER:stats[ANCHOR + PROVIDER]},
                targets={p:stats[p] for p in (ACTION, PROVIDER)})


def _roles(stack, expected):
    proc, mount = kernel._proc(stack)
    roles = {k: kernel._role(stack, proc, n, mount) for k,n in
             (("manager", os.getpid()), ("sensor", expected["pid"]))}
    tasks = kernel._proc_child(stack, roles["manager"][1], "task", os.O_RDONLY | os.O_DIRECTORY, mount)
    roles["caller"] = kernel._role(stack, tasks, threading.get_native_id(), mount)
    return proc, mount, roles


def _streams(roles, mount, deadline):
    raw = {key: kernel._read(role[1], "mountinfo", 1 << 20, mount, deadline) for key,role in roles.items()}
    _need(raw["manager"] == raw.pop("caller"), "collector mount stream differs from manager")
    return raw


def capture_sensor_state(*, identity, guard, deadline, uuid_storage=None, observe_dm_mapping=False,
                         observe_backing_leaf=False, luks_header_profile=None):
    """The protected caller supplies a live pidfd/InvocationID guard; the sensor cannot nominate itself."""
    expected = _identity(identity)
    storage = None if uuid_storage is None else _uuid_storage(uuid_storage)
    _need(type(observe_dm_mapping) is bool and (not observe_dm_mapping or
          (storage is not None and len(storage["backing_devices"]) == 1)), "one approved state backing device required")
    _need(type(observe_backing_leaf) is bool and (not observe_backing_leaf or observe_dm_mapping),
          "backing-leaf observation requires the direct crypt mapping")
    if luks_header_profile is not None:
        _need(observe_backing_leaf and type(luks_header_profile) is dict,
              "pinned LUKS header observation requires the backing-leaf profile")
        from .pi_core_state_luks_headers import validate_header_profile, verify_luks_headers
        header_profile = validate_header_profile(luks_header_profile)
    kernel._check(deadline)
    kernel._platform()
    kernel._generation(expected["pid"], expected["start_ticks"])
    _same(expected, _identity(guard(deadline=deadline)), "initial lifecycle sensor binding differs")
    kernel._check(deadline)
    with ExitStack() as stack:
        proc, mount, roles = _roles(stack, expected)
        start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        args = proc, mount, roles, expected, deadline
        first, mroot, sroot = _subjects(stack, *args)
        held = kernel._manager_state_fds(stack, mroot), _action_fds(stack, sroot)
        with ExitStack() as edge:
            before = _edge(edge, first, mroot, sroot, held, roles, mount, deadline, storage, observe_dm_mapping,
                           observe_backing_leaf)
        if luks_header_profile is not None:
            # This is an original, single acquisition, inside both independent
            # leaf/mapping samples. No device name or diskseq is taken on trust.
            from .pi_core_state_backing_leaf import verify_backing_leaf
            leaf = verify_backing_leaf(before[6], expected_backing_device=before[7])
            diskseq = _uint(leaf["diskseq"])
            _need(before[4] != "10" + header_profile["encryption_uuid"].replace("-", ""),
                  "filesystem UUID cannot double as the LUKS header identity")
            kernel._check(deadline)
            header = capture_luks_headers(leaf["device"], diskseq, header_profile, deadline=deadline)
            kernel._check(deadline)
            # Admit only the sanitized wire shape before producing a retainable view.
            verify_luks_headers(header, expected_device=leaf["device"], expected_diskseq=diskseq, profile=header_profile)
            kernel._check(deadline)
        with ExitStack() as edge:
            after = _edge(edge, *_subjects(edge, *args), held, roles, mount, deadline, storage, observe_dm_mapping,
                          observe_backing_leaf, opening_dependency=before[7] if observe_backing_leaf else None)
        _need(before == after, "sensor state, namespace, identities, or mount streams changed")
        end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        _need(start > 0 and 0 < end - start <= 5_000_000_000, "sensor capture outside observation window")
        _same(expected, _identity(guard(deadline=deadline)), "final lifecycle sensor binding differs")
        kernel._check(deadline)
        manager, sensor, clock, cgroup = first[:4]
        raw = before[3]
        view = dict(schema=SCHEMA, identity=expected, manager=manager, sensor=sensor, clock=clock,
                    sensor_cgroup=cgroup.decode("ascii"), opened_boottime_ns=start, closed_boottime_ns=end,
                    manager_state={k:_manager_record(e[1]) for k,e in (("before",before), ("after",after))},
                    sensor_targets={k:{ACTION:e[2][ACTION]}
                                    for k,e in (("before",before), ("after",after))},
                    **{k+"_mountinfo_digest":"sha256:"+hashlib.sha256(v).hexdigest() for k,v in raw.items()})
        if storage is not None:
            view.update(schema=UUID_SCHEMA, filesystem_uuid_observation={"before": before[4], "after": after[4]})
        if observe_dm_mapping:
            _same(before[5], after[5], "device-mapper metadata changed between captures")
            view.update(schema=DM_SCHEMA, dm_mapping_observation={"before": before[5], "after": after[5]})
        if observe_backing_leaf:
            _same(before[6], after[6], "kernel backing leaf changed between captures")
            view.update(schema=LEAF_SCHEMA, backing_leaf_observation={"before": before[6], "after": after[6]})
        if luks_header_profile is not None:
            view.update(schema=LUKS_SCHEMA, luks_header_observation=header)
    kernel._check(deadline)
    return view, raw["manager"], raw["sensor"]


@contextmanager
def hold_sensor_mount_guard(*, identity, view, manager_raw, sensor_raw, guard, deadline):
    """Sample the owned namespaces at each publication boundary. Not continuous monitoring."""
    expected = _identity(identity)
    _same(view["identity"], expected, "foreign sensor capture owner")
    schema = view["schema"]
    has_leaf, has_header = schema in (LEAF_SCHEMA, LUKS_SCHEMA), schema == LUKS_SCHEMA
    has_dm = schema == DM_SCHEMA or has_leaf
    _need(schema in (SCHEMA, UUID_SCHEMA, DM_SCHEMA, LEAF_SCHEMA, LUKS_SCHEMA) and
          ("filesystem_uuid_observation" in view) == (schema != SCHEMA) and
          ("dm_mapping_observation" in view) == has_dm and
          ("backing_leaf_observation" in view) == has_leaf and
          ("luks_header_observation" in view) == has_header, "foreign sensor observation")
    if has_header:
        _need(type(view["luks_header_observation"]) is dict, "missing pinned LUKS metadata observation")
    if schema != SCHEMA:
        u = view["filesystem_uuid_observation"]
        _keys(u, ("before", "after"))
        _need(type(u["before"]) is str and re.fullmatch("[0-9a-f]{34}", u["before"])
              and u["after"] == _uuid_reply(bytes.fromhex(u["before"])), "unstable filesystem UUID observation")
    if has_dm:
        edges = view["dm_mapping_observation"]
        _keys(edges, ("before", "after"))
        _need(type(edges["before"]) is dict, "missing mapping observations")
        _same(edges["before"], edges["after"], "unstable device-mapper observation")
    if has_leaf:
        edges = view["backing_leaf_observation"]
        _keys(edges, ("before", "after"))
        _need(type(edges["before"]) is dict, "missing kernel backing-leaf observations")
        _same(edges["before"], edges["after"], "unstable kernel backing leaf")
    raw = {"manager": manager_raw, "sensor": sensor_raw}
    for role, data in raw.items():
        _need(type(data) is bytes and 0 < len(data) <= 1 << 20 and data.endswith(b"\n")
              and view[role + "_mountinfo_digest"] == "sha256:" + hashlib.sha256(data).hexdigest(),
              "foreign sensor observation mount streams")
    kernel._check(deadline)
    kernel._platform()
    kernel._generation(expected["pid"], expected["start_ticks"])
    _same(expected, _identity(guard(deadline=deadline)), "retention lifecycle identity differs")
    with ExitStack() as stack:
        proc, mount, roles = _roles(stack, expected)
        args = proc, mount, roles, expected, deadline
        initial, mroot, sroot = _subjects(stack, *args)
        mgr, sensor, clock, cgroup = initial[:4]
        _same([view["manager"], view["sensor"], view["clock"], view["sensor_cgroup"]],
              [mgr, sensor, clock, cgroup.decode("ascii")], "different process or clock at retention")
        # Keep original roots and namespace handles live through the publication.
        # For complete negative captures, the fixed state paths may be wrong;
        # never convert a failed storage-semantic verdict into a pass here.
        _need(_streams(roles, mount, deadline) == raw, "mount topology changed before retention")
        if has_dm:
            # Publication rechecks the same mounted object, but never repeats the DM acquisition.
            anchor = kernel._manager_state_fds(stack, mroot)[ANCHOR]
            anchor_stat = view["manager_state"]["before"]["sources"][ANCHOR].copy()
            _same(anchor_stat, view["manager_state"]["after"]["sources"][ANCHOR], "recorded mapping anchor changed")
            _same(kernel._stat(anchor, owner=True), anchor_stat, "different mapping anchor before retention")
        active = True

        def current():
            nonlocal active
            _need(active and roles["caller"][0] == threading.get_native_id(), "inactive or foreign retention guard")
            try:
                kernel._check(deadline)
                with ExitStack() as edge:
                    fresh, _, _ = _subjects(edge, *args)
                    _need(fresh == initial and kernel._stat(mroot) == initial[4]["root"] and
                          kernel._stat(sroot) == initial[6][1] and _streams(roles, mount, deadline) == raw,
                          "sensor or manager topology changed during retention")
                    if has_dm:
                        named = kernel._manager_state_fds(edge, mroot)[ANCHOR]
                        _same(kernel._stat(anchor, owner=True), anchor_stat, "held mapping anchor changed during retention")
                        _same(kernel._stat(named, owner=True), anchor_stat, "named mapping anchor changed during retention")
                kernel._check(deadline)
            except BaseException:
                active = False
                raise

        try:
            yield current
            current()
            _same(expected, _identity(guard(deadline=deadline)), "final retention lifecycle identity differs")
        finally:
            active = False
    kernel._check(deadline)
