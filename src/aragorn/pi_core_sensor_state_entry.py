"""One protected-plan observation of an already owned sensor; no start or recovery authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import threading

from . import pi_core_configuration_carrier as carrier
from . import pi_core_sensor_state_custody as custody
from . import pi_core_sensor_state_evidence as evidence
from . import pi_core_sensor_state_observer as observer
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_state_admission import _dev, _keys, _need, _pin, _same, _uint, _uuid


FIELD = "sensor_state_observation"
DIRECT_LAYOUT = "DIRECT_LUKS2_INLINE_HEADER_V1"
_SEAL = object()
_SOURCES = ("pi_core_sensor_state_entry", "pi_core_sensor_state_observer",
            "pi_core_sensor_state_custody", "pi_core_sensor_state_evidence")
_DM_SOURCES = ("pi_core_state_dm_mapping",)
_LEAF_SOURCES = ("pi_core_state_backing_leaf",)


def validate_section(value):
    fields = ("store", "receipt_directory", "attempt_id", "clock", "storage")
    if type(value) is dict and "filesystem_uuid" in value:
        _uuid(value["filesystem_uuid"])
        fields += ("filesystem_uuid",)
    direct = type(value) is dict and "state_volume_layout" in value
    if direct:
        _need(value["state_volume_layout"] == DIRECT_LAYOUT and "filesystem_uuid" in value,
              "direct crypt mapping observation requires an explicit layout and a filesystem UUID")
        fields += ("state_volume_layout",)
    leaf = type(value) is dict and "observe_backing_leaf" in value
    if leaf:
        _need(direct and value["observe_backing_leaf"] is True, "backing leaf observation requires explicit direct layout")
        fields += ("observe_backing_leaf",)
    _keys(value, fields)
    _need(value["store"] == str(custody.STORE) and value["receipt_directory"] == str(custody.RECEIPTS),
          "fixed private sensor evidence destinations required")
    attempt = value["attempt_id"]
    _need(type(attempt) is str and re.fullmatch(r"[0-9a-f]{32}", attempt) and int(attempt, 16),
          "invalid sensor observation attempt")
    clock = value["clock"]
    _keys(clock, ("clock_id", "boot_id", "time_namespace_inode"))
    _uuid(clock["boot_id"])
    _uint(clock["time_namespace_inode"])
    _need(clock["clock_id"] == "CLOCK_BOOTTIME", "unknown sensor observation clock")
    st = value["storage"]
    _keys(st, ("device", "backing_devices", "fs_type"))
    dev = _dev(st["device"])
    backing = st["backing_devices"]
    _need(type(backing) is list and 1 <= len(backing) <= 16 and len({_dev(x) for x in backing}) == len(backing)
          and dev not in backing and st["fs_type"] in ("ext4", "xfs"), "invalid sensor storage binding")
    _need(not direct or len(backing) == 1, "direct crypt mapping requires one distinct planned backing device")
    if direct:
        # _plan validates this section before taking its final verified-loader
        # snapshot. Importing definitions is inert; no device is opened here.
        from . import pi_core_state_dm_mapping
        _need(callable(pi_core_state_dm_mapping.capture_dm_mapping) and
              callable(pi_core_state_dm_mapping.verify_dm_mapping), "direct crypt mapping implementation missing")
    if leaf:
        from . import pi_core_state_backing_leaf
        _need(callable(pi_core_state_backing_leaf.capture_backing_leaf) and
              callable(pi_core_state_backing_leaf.verify_backing_leaf), "backing leaf implementation missing")
    return value


def from_held_plan(inputs, path, plan, plan_digest, host_digest, records, source_digests, host_observation):
    from .pi_core_coordinator_entry import _Inputs, _configuration_section

    _need(type(inputs) is _Inputs and plan["mode"] == "UNAVAILABLE" and plan["provider"] is None
          and _pin(host_digest) == plan["host_profile_digest"] and canonical_digest(plan) == _pin(plan_digest)
          and sum(r["path"] == path and r["pin"] == plan_digest and r["raw"] == canonical_json(plan)
                  for r in inputs.rows) == 1, "sensor observation requires the exact independently held managed plan")
    inputs.guard()
    _need(type(host_observation) is dict and host_observation.get("host_profile_digest") == host_digest and
          _uint(host_observation.get("pid"), high=1 << 31) == os.getpid(), "sensor manager differs from held host")
    section = validate_section(plan[FIELD])
    direct = "state_volume_layout" in section
    leaf = section.get("observe_backing_leaf") is True
    for name in _SOURCES + (_DM_SOURCES if direct else ()) + (_LEAF_SOURCES if leaf else ()):
        p = "opt/aragorn/src/aragorn/" + name + ".py"
        pin = _pin(source_digests.get(p))
        _need(sum(row == {"module": "aragorn." + name, "path": p, "digest": pin} for row in records) == 1,
              "sensor observation implementation not consumed from held host")
    config = _configuration_section(plan["service_configuration"])
    _need("carrier" in config and config["carrier"]["device"] not in
          (section["storage"]["device"], *section["storage"]["backing_devices"]),
          "sensor state requires an independent protected configuration carrier")
    binding = dict(attempt_id=section["attempt_id"], clock=section["clock"], storage=section["storage"],
                   host_profile_digest=host_digest, plan_digest=plan_digest, deployment_digest=_pin(plan["deployment"]["digest"]),
                   launch_digest=_pin(plan["launch"]["digest"]),
                   configuration_digest=_pin(plan["service_configuration"]["configurations"]["digest"]))
    return SensorStateRequest(_SEAL, inputs, canonical_json(binding), host_observation["pid"],
                              config["carrier"]["device"], section.get("filesystem_uuid"), direct, leaf)


class SensorStateRequest:
    """Thread- and deadline-bound single-use read request; not a service principal."""
    __slots__ = ("_seal", "_inputs", "_raw", "_thread", "_state", "_deadline", "_roots", "_manager_pid",
                 "_config_device", "_filesystem_uuid", "_direct", "_leaf")

    def __init__(self, seal, inputs, raw, manager_pid, config_device, filesystem_uuid=None, direct=False, leaf=False):
        _need(seal is _SEAL, "protected sensor plan required")
        self._seal, self._inputs, self._raw, self._manager_pid = seal, inputs, raw, manager_pid
        self._config_device = _dev(config_device)
        self._filesystem_uuid = None if filesystem_uuid is None else _uuid(filesystem_uuid)
        _need(type(direct) is bool and (not direct or self._filesystem_uuid is not None),
              "direct crypt mapping observation requires protected filesystem UUID")
        _need(type(leaf) is bool and (not leaf or direct), "backing leaf requires direct crypt mapping")
        self._leaf = leaf
        self._direct = direct
        self._thread, self._state, self._roots, self._deadline = threading.get_ident(), "new", (), None

    def _enter(self, state):
        _need(type(self) is SensorStateRequest and self._seal is _SEAL and self._thread == threading.get_ident()
              and self._state == state, "sensor observation is unavailable or already spent")
        self._state = "spent"  # A refusal or interruption cannot spend this request again.
        self._inputs.guard()

    def preflight(self, *, deployment, service_configuration, config, protected_root, deadline):
        self._enter("new")
        doc = json.loads(self._raw)
        launch = {k: str(v) if isinstance(v, Path) else v for k in config.__dataclass_fields__
                  for v in (getattr(config, k),)}
        _need(deadline <= self._inputs.deadline and canonical_digest(deployment) == doc["deployment_digest"] and
              canonical_digest(service_configuration.configurations) == doc["configuration_digest"] and
              canonical_digest(launch) == doc["launch_digest"],
              "sensor observation is not bound to this deployment or held configuration")
        # The managed owner has guarded the concrete configuration holder; a
        # different holder for identical bytes must not substitute a legacy root.
        dev = os.fstat(service_configuration.root_fd).st_dev
        _need(service_configuration.root == carrier.ROOT / "installed/root" and
              self._config_device == f"{os.major(dev)}:{os.minor(dev)}", "sensor configuration medium differs")
        parent = custody.STORE.parent
        # The custody reader separately checks actual mounted device/alias separation.
        for p in (config.root_directory, config.runtime_directory, config.activation_directory, protected_root,
                  Path("/run/aragorn-pi-bootstrap"), *(r["path"] for r in self._inputs.rows),
                  *(r[0] for r in self._inputs.directories)):
            _need(isinstance(p, Path) and p.anchor == "/" and ".." not in p.parts and
                  not p.is_relative_to(parent) and not parent.is_relative_to(p), "sensor evidence overlaps protected inputs")
        self._roots = custody.check_sensor_destinations(store=custody.STORE, receipt_directory=custody.RECEIPTS,
                                                       deadline=deadline, attempt_id=doc["attempt_id"])
        _need(all(r[0] != dev for r in self._roots), "sensor evidence shares the configuration medium")
        self._state, self._deadline = "prepared", deadline

    def acquire(self, *, identity, guard, deadline):
        self._enter("prepared")
        _need(deadline == self._deadline, "sensor observation deadline changed")
        binding = json.loads(self._raw)
        uuid_check = self._filesystem_uuid is not None
        view, manager, sensor = observer.capture_sensor_state(identity=identity, guard=guard, deadline=deadline,
            **({"uuid_storage": binding["storage"]} if uuid_check else {}),
            **({"observe_dm_mapping": True} if self._direct else {}),
            **({"observe_backing_leaf": True} if self._leaf else {}))
        _same(guard(deadline=deadline), identity, "sensor generation changed after observation")
        _need(type(manager) is bytes and type(sensor) is bytes and 0 < len(manager) <= 1 << 20
              and 0 < len(sensor) <= 1 << 20 and type(view) is dict, "incomplete original sensor observation")
        record = dict(binding, schema="aragorn/pi-core-sensor-state-record/v1", identity=identity, view=view,
                      manager_mountinfo_digest="sha256:" + hashlib.sha256(manager).hexdigest(),
                      sensor_mountinfo_digest="sha256:" + hashlib.sha256(sensor).hexdigest())
        ok = True
        try:
            replay = evidence.verify_sensor_state(view, manager, sensor, identity=identity, storage=binding["storage"],
                expected_filesystem_uuid=self._filesystem_uuid, **({"require_direct_crypt_mapping": True} if self._direct else {}),
                **({"require_backing_leaf": True} if self._leaf else {}))
            if self._direct:
                version = 4 if self._leaf else 3
                _need(view.get("schema") == f"aragorn/pi-core-sensor-state-view/v{version}" and
                      replay.get("active_dm_crypt_single_backing_matched") is True and
                      replay.get("state_filesystem_uuid_matched") is True,
                      "missing directly observed crypt mapping or mounted filesystem UUID")
            if self._leaf:
                _need(replay.get("kernel_whole_disk_leaf_matched") is True,
                      "missing whole-disk leaf observation for the mapping dependency")
                _uint(replay.get("observed_backing_diskseq"))
            _need(replay["sensor_read_only_bind_matched"] is True and replay["manager"]["pid"] == self._manager_pid,
                  "sensor state or manager differs from the held invocation")
            _same(replay["clock"], binding["clock"], "sensor observation clock differs from approved plan")
            evidence.validate_sensor_configuration_mounts(manager, sensor, self._config_device, deadline=deadline)
        except ValueError:
            ok = False  # A complete negative is admissible for private retention, never for dispatch.
        raw = canonical_json(record)
        self._inputs.guard()
        result = None
        try:
            with observer.hold_sensor_mount_guard(identity=identity, view=view, manager_raw=manager, sensor_raw=sensor,
                                                   guard=guard, deadline=deadline) as topology:
                receipt = custody.retain_sensor_observation(store=custody.STORE, receipt_directory=custody.RECEIPTS,
                    expected_roots=self._roots, record_raw=raw, manager_raw=manager, sensor_raw=sensor,
                    storage=binding["storage"], deadline=deadline, topology_guard=topology)
                result = dict(attempt_id=binding["attempt_id"], status="RETAINED_SENSOR_STATE_ONLY" if ok else
                              "RETAINED_SENSOR_STATE_INCONSISTENT", capture_digest=canonical_digest(record),
                              receipt_digest=_pin(receipt), sensor_health_verified=False, activation_authorized=False,
                              phase3_exit_eligible=False)
            _same(guard(deadline=deadline), identity, "sensor generation changed during retention")
            self._inputs.guard()
        except BaseException as exc:
            if result is not None:
                exc.pi_sensor_state_receipt = dict(result, status="RETAINED_SENSOR_STATE_INCONSISTENT")
            raise
        return result
