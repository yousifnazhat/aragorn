"""Replay a root observer's two-ended manager/sensor measurement; never open a process or device."""
import hashlib
import re
from uuid import UUID

from .pi_core_manager_state_view import _object, verify_manager_state
from .pi_core_configuration_carrier import _mounts as carrier_mounts
from .pi_core_state_admission import _dev, _keys, _need, _pin, _same, _uint, _uuid
from .pi_core_state_masks import _subject
from .pi_core_state_mounts import ACTION, ANCHOR, direct_mount_inventory, verify_mounts
from .pi_core_stopped_mask_view import _check


UNIT = "aragorn-pi-sensor.service"
VIEW = "aragorn/pi-core-sensor-state-view/v1"
UUID_VIEW = "aragorn/pi-core-sensor-state-view/v2"
DM_VIEW = "aragorn/pi-core-sensor-state-view/v3"
_IDENTITY = ("role", "unit", "pid", "start_ticks", "uid", "gid", "invocation_id")


def _digest(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= 1 << 20, "missing or oversized raw sensor evidence")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_identity(value):
    _keys(value, _IDENTITY)
    _need(value["role"] == "sensor" and value["unit"] == UNIT and type(value["invocation_id"]) is str
          and re.fullmatch("[0-9a-f]{32}", value["invocation_id"]) and int(value["invocation_id"], 16),
          "wrong sensor role, unit or invocation")
    for key in ("pid", "uid", "gid"):
        _uint(value[key], high=1 << 31)
    _uint(value["start_ticks"])


def validate_sensor_configuration_mounts(manager_raw, sensor_raw, device, *, deadline):
    """Compare mount records only; no device reads, inode attribution or image-byte claim."""
    _, basename = carrier_mounts(manager_raw, _dev(device), deadline)
    source = ("/dev/" + basename).encode("ascii")
    # The unit binds one file from the installed tree, not the manager's full
    # carrier. Mount IDs are local; the device, source and filesystem root
    # tie the two namespace projections together.
    target = "/etc/aragorn/pi-sensor-service.json"
    _check(deadline)
    mounts = direct_mount_inventory(sensor_raw)
    row = mounts.get(target)
    _need(row is not None and row.device == device and row.source == source and row.filesystem == b"squashfs"
          and row.root == "/installed/root" + target and b"ro" in row.options and b"ro" in row.super_options,
          "retained sensor configuration file does not match the manager carrier")
    _need(all(path == target or (other.device != device and other.source != source
                                 and not path.startswith(target + "/")) for path, other in mounts.items()),
          "sensor configuration carrier is aliased or the file mount is shadowed")
    _check(deadline)


def verify_dm_mapping(record, *, expected_device, expected_backing_device):
    from .pi_core_state_dm_mapping import verify_dm_mapping as verify
    return verify(record, expected_device=expected_device, expected_backing_device=expected_backing_device)


def verify_sensor_state(view, manager_raw, sensor_raw, *, identity, storage, expected_filesystem_uuid=None,
                        require_direct_crypt_mapping=False):
    """Validate actual observer projections against the caller's protected service generation and mapping."""
    has_uuid = expected_filesystem_uuid is not None
    _need(type(require_direct_crypt_mapping) is bool and (not require_direct_crypt_mapping or has_uuid),
          "direct crypt mapping requires an approved mounted filesystem UUID")
    fields = ("schema", "identity", "manager", "sensor", "clock", "sensor_cgroup", "opened_boottime_ns",
              "closed_boottime_ns", "manager_state", "sensor_targets", "manager_mountinfo_digest", "sensor_mountinfo_digest")
    _keys(view, fields + (("filesystem_uuid_observation",) if has_uuid else ()) +
          (("dm_mapping_observation",) if require_direct_crypt_mapping else ()))
    _need(view["schema"] == (DM_VIEW if require_direct_crypt_mapping else UUID_VIEW if has_uuid else VIEW)
          and view["sensor_cgroup"] == "0::/system.slice/" + UNIT + "\n",
          "unknown sensor record or incorrect unified cgroup")
    _validate_identity(identity)
    _same(view["identity"], identity, "sensor lifecycle generation differs")
    manager, sensor, clock = view["manager"], view["sensor"], view["clock"]
    _subject(manager, manager=True)
    _subject(sensor)
    _need(sensor["pid"] != manager["pid"] and sensor["mount_namespace"] != manager["mount_namespace"],
          "manager and sensor are not distinct processes and mount views")
    for key in ("pid", "start_ticks", "uid", "gid"):
        _same(sensor[key], identity[key], "kernel subject differs from owned sensor generation")
    _keys(clock, ("boot_id", "clock_id", "time_namespace_inode"))
    _uuid(clock["boot_id"])
    _uint(clock["time_namespace_inode"])
    _need(clock["clock_id"] == "CLOCK_BOOTTIME" and
          0 < _uint(view["closed_boottime_ns"]) - _uint(view["opened_boottime_ns"]) <= 5_000_000_000,
          "unknown clock or incomplete sensor observation interval")
    _keys(storage, ("device", "backing_devices", "fs_type"))
    _same([_digest(manager_raw), _digest(sensor_raw)],
          [_pin(view["manager_mountinfo_digest"]), _pin(view["sensor_mountinfo_digest"])],
          "observation differs from raw mount streams")
    mounts = {}
    verify_mounts("manager", manager_raw, **storage, mount_details=mounts)
    source_roots, manager_targets = verify_manager_state(view["manager_state"], storage, mounts)
    sensor_id = verify_mounts("sensor", sensor_raw, **storage)[ACTION]
    frames = view["sensor_targets"]
    _keys(frames, ("before", "after"))
    for row in frames.values():
        _keys(row, (ACTION,))
        measured = _object(row[ACTION], ACTION, storage["device"], sensor_id)
        _same(measured, source_roots[ACTION], "sensor target is not the manager's backing directory")
    _same(frames["before"], frames["after"], "sensor target changed during observation")
    if has_uuid:
        # fsuuid2: one length byte followed by the raw filesystem identifier.
        want = (b"\x10" + UUID(_uuid(expected_filesystem_uuid)).bytes).hex()
        _same(view["filesystem_uuid_observation"], {"before": want, "after": want},
              "mounted state filesystem UUID does not match approved identity at both bounds")
    result = dict(status="consistent-offline-records-only", manager=manager, sensor=sensor, clock=clock,
                source_roots=source_roots, manager_targets=manager_targets,
                sensor_targets={ACTION: dict(source_roots[ACTION], mount_id=sensor_id)},
                sensor_read_only_bind_matched=True, state_filesystem_uuid_matched=has_uuid,
                installed_isolation_verified=False, sensor_health_verified=False,
                activation_authorized=False, recovery_authorized=False, phase3_exit_eligible=False)
    if require_direct_crypt_mapping:
        back = storage["backing_devices"]
        _need(type(back) is list and len(back) == 1 and _dev(back[0]) != _dev(storage["device"]),
              "mapping requires a single distinct approved backing device")
        raw_edges = view["dm_mapping_observation"]
        _keys(raw_edges, ("before", "after"))
        mappings = {}
        for edge in ("before", "after"):
            # verify_manager_state already established the exact mount ID, type and fixed path.
            anchor = view["manager_state"][edge]["sources"][ANCHOR]
            _same([anchor["dev"], anchor["rdev"]], [storage["device"], "0:0"],
                  "mapping device is not the independently observed state anchor")
            mappings[edge] = verify_dm_mapping(raw_edges[edge], expected_device=anchor["dev"], expected_backing_device=back[0])
        _same(raw_edges["before"], raw_edges["after"], "original mapping records changed between bounds")
        _same(mappings["before"], mappings["after"], "verified mapping changed between bounds")
        verified = mappings["before"]
        result.update(active_dm_crypt_single_backing_matched=True, observed_mapping_device=verified["device"],
                      observed_sole_kernel_dependency=verified["backing_devices"][0], encryption_uuid_measured=False,
                      inline_luks2_header_verified=False, physical_backing_identity_verified=False)
    return result
