"""Bounded inert replay; no live processes, service, storage device or kernel observations."""
from copy import deepcopy
import hashlib
from io import BytesIO
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_sensor_state_evidence import verify_sensor_state, UNIT, VIEW
from aragorn.pi_core_state_mounts import ACTION
from scripts.verify_pi_core_joined_sensor_state import verify_joined_sensor_state
import test_pi_core_mask_custody as local
import test_pi_core_state_mask_archive as outer
from test_pi_core_manager_state_view import manager_record
from test_pi_core_state_mounts import sample_mountinfo


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def fixture():
    manager = dict(pid=71, start_ticks=955, uid=0, gid=0, mount_namespace=9001, user_namespace=4026531837)
    sensor = dict(pid=73, start_ticks=957, uid=20, gid=20, mount_namespace=9003, user_namespace=4026531837)
    ident = {k: sensor[k] for k in ("pid", "start_ticks", "uid", "gid")}
    ident.update(role="sensor", unit=UNIT, invocation_id="b" * 32)
    storage = dict(device="253:7", fs_type="ext4", backing_devices=["259:0"])
    m, s = (sample_mountinfo(role, device="253:7") for role in ("manager", "sensor"))
    frame = manager_record()
    view = dict(schema=VIEW, identity=deepcopy(ident), sensor_cgroup="0::/system.slice/" + UNIT + "\n",
                sensor=sensor, manager=manager, manager_state=frame, opened_boottime_ns=1, closed_boottime_ns=32,
                clock=dict(boot_id="d362104a-845f-4b13-9e21-ebaf13ebd96c", clock_id="CLOCK_BOOTTIME",
                           time_namespace_inode=8100), manager_mountinfo_digest=digest(m), sensor_mountinfo_digest=digest(s),
                sensor_targets={edge: {ACTION: deepcopy(frame[edge]["targets"][ACTION])} for edge in frame})
    return view, m, s, ident, storage


class SemanticSensorState(unittest.TestCase):
    def test_complete_b58_projection_is_scoped_to_the_read_only_sensor_bind(self):
        v, m, s, identity, storage = fixture()
        result = verify_sensor_state(v, m, s, identity=identity, storage=storage)
        self.assertIs(result["sensor_read_only_bind_matched"], True)
        self.assertEqual(result["sensor_targets"][ACTION], {**result["source_roots"][ACTION], "mount_id": 4})
        for k in ("installed_isolation_verified", "sensor_health_verified", "activation_authorized",
                  "recovery_authorized", "phase3_exit_eligible"):
            self.assertIs(result[k], False)

    def test_exact_kernel_role_generation_cgroup_clock_and_bracket_required(self):
        for mutate in (lambda v: v["sensor"].update(pid=444), lambda v: v["sensor"].update(start_ticks=True),
                       lambda v: v["identity"].update(invocation_id="c"*32), lambda v: v["sensor"].update(uid=0),
                       lambda v: v["manager"].update(gid=2),
                       lambda v: v["sensor"].update(mount_namespace=v["manager"]["mount_namespace"]),
                       lambda v: v.update(sensor_cgroup="0::/other.service\n"),
                       lambda v: v["clock"].update(clock_id="CLOCK_MONOTONIC"),
                       lambda v: v.update(closed_boottime_ns=v["opened_boottime_ns"]),
                       lambda v: v.update(closed_boottime_ns=v["opened_boottime_ns"] + 5_000_000_001)):
            v, m, s, identity, storage = fixture()
            mutate(v)
            with self.subTest(view=v["sensor"]), self.assertRaises(ValueError):
                verify_sensor_state(v, m, s, identity=identity, storage=storage)

    def test_changed_source_or_target_at_either_bound_cannot_be_replaced_by_a_sensor_claim(self):
        for mutate in (lambda v: v["sensor_targets"].pop("before"),
                       lambda v: v["sensor_targets"]["after"][ACTION].update(ino=1999),
                       lambda v: [v["sensor_targets"][edge][ACTION].update(mnt_id=3) for edge in ("before", "after")],
                       lambda v: [frame[side][ACTION].update(ino=1200)
                                  for frame in v["manager_state"].values() for side in ("sources", "targets")]):
            v, m, s, identity, storage = fixture()
            mutate(v)
            with self.assertRaises(ValueError):
                verify_sensor_state(v, m, s, identity=identity, storage=storage)

    def test_resealed_raw_mounts_must_still_be_read_only_and_exclude_unapproved_aliases(self):
        for make in (lambda s: s.replace(b" ro,nodev", b" rw,nodev"),
                     lambda s: s + b"8 1 253:7 / /tmp ro,nodev,nosuid,noexec - ext4 /dev/mapper/pilot rw\n",
                     lambda s: s + b"8 1 259:0 / /tmp ro - ext4 /dev/nvme2n1 ro\n",
                     lambda s: s.replace(ACTION.encode(), b"/different", 1)):
            v, m, s, identity, storage = fixture()
            altered = make(s)
            self.assertNotEqual(altered, s)
            v["sensor_mountinfo_digest"] = digest(altered)
            with self.assertRaises(ValueError):
                verify_sensor_state(v, m, altered, identity=identity, storage=storage)


_CONFIG_MANAGER = (b"8 2 7:7 / /run/aragorn-pi-config ro,nosuid,nodev,noexec "
                   b"- squashfs /dev/loop7 ro\n")
_CONFIG_SENSOR = (b"9 1 7:7 /installed/root/etc/aragorn/pi-sensor-service.json /etc/aragorn/pi-sensor-service.json "
                  b"ro,nosuid,nodev,noexec - squashfs /dev/loop7 ro\n")


class _JoinedSensorFixture(unittest.TestCase):
    def setUp(self, *, change_streams=None, prepare_observation=None):
        self.outer, self.local = outer.MaskArchiveTests(), local.MaskCustodyTests()
        for f in (self.outer, self.local):
            self.addCleanup(f.doCleanups)
            f.setUp()
        self.b = b = self.outer.base
        self.v, manager, sensor, ident, storage = fixture()
        manager += (b"6 2 8:77 / /run/aragorn-sensor-state-evidence rw,nodev,nosuid,noexec "
                    b"- ext4 /dev/nvme7n1 rw\n7 1 0:51 / /dev rw,nosuid - devtmpfs devtmpfs rw\n")
        manager += _CONFIG_MANAGER
        sensor += _CONFIG_SENSOR
        if change_streams is not None:
            updated = change_streams(manager, sensor)
            self.assertNotEqual(updated, (manager, sensor))
            manager, sensor = updated
        for role, raw in (("manager", manager), ("sensor", sensor)):
            b.capture["roles"][role]["mountinfo"] = b.put(raw)
            self.v[role + "_mountinfo_digest"] = digest(raw)
        self.identity = ident
        self.plan = dict(schema="aragorn/pi-core-coordinator-plan/v1", mode="UNAVAILABLE", provider=None,
                         host_profile_digest=digest(b"host"),
                         service_configuration=dict(deployment_path="/run/aragorn-pi-config/installed",
                           receipt_digest=digest(b"configuration receipt"),
                           configurations={"path": "/run/aragorn-pi-config/inputs/configurations.json",
                                           "digest": b.capture["configuration"]},
                           manifest={"path": "/run/aragorn-pi-config/inputs/manifest.json", "digest": digest(b"manifest")},
                           carrier={"device": "7:7", "image_bytes": 1537, "image_sha256": "f"*64}),
                         launch={"digest": digest(b"launch")}, deployment={"digest": b.capture["deployment"]},
                         sensor_state_observation=dict(store="/run/aragorn-sensor-state-evidence/cas",
                            receipt_directory="/run/aragorn-sensor-state-evidence/receipts", attempt_id="a"*32,
                            clock=self.v["clock"], storage=storage))
        if prepare_observation is not None:
            prepare_observation(self.plan["sensor_state_observation"], self.v, b.capture["volume"])
        plan = b.put(canonical_json(self.plan))
        record = dict(schema="aragorn/pi-core-sensor-state-record/v1", view=self.v, identity=ident,
                      attempt_id="a"*32, host_profile_digest=digest(b"host"), launch_digest=digest(b"launch"),
                      deployment_digest=b.capture["deployment"], plan_digest=plan,
                      configuration_digest=b.capture["configuration"], clock=self.v["clock"], storage=storage,
                      manager_mountinfo_digest=digest(manager), sensor_mountinfo_digest=digest(sensor))
        local_store = CAS(self.local.store)
        def put(raw):
            return local_store.put(BytesIO(raw), max_bytes=len(raw))
        pins = {k: put(raw) for k, raw in (("record", canonical_json(record)), ("manager", manager), ("sensor", sensor))}
        receipt = canonical_json(dict(schema="aragorn/pi-core-sensor-state-local-custody/v1", members=pins))
        receipt_pin = put(receipt)
        local_store.materialize(receipt_pin, self.local.receipts / ("sensor-state-" + "a"*32 + ".json"),
                                root=self.local.receipts)
        generation = {k: ident[k] for k in ("pid", "start_ticks", "uid", "gid", "invocation_id")}
        host = dict(schema="aragorn/pi-core-coordinator-host-observation/v1", pid=self.v["manager"]["pid"],
                    authority="PINNED_HOST_TCB_ONLY_NOT_CONSUMED_CODE_OR_PHASE3", host_profile_digest=digest(b"host"),
                    python_executable="/opt/aragorn-cpython/bin/python3.12", files=806, phase3_exit_eligible=False)
        self.owner = dict(schema="aragorn/pi-core-coordinator-observation/v1", managed_call_attempted=True,
                          host_before=host, host_after=host.copy(), owned_inputs_closed=True, phase3_exit_eligible=False,
                          status="MANAGED_CALL_RETURNED_NOT_QUALIFIED",
                          authority="ROOT_CALLER_CUSTODY_NOT_PILOT_OR_PHASE3_QUALIFICATION", plan_digest=plan,
                          deployment_digest=b.capture["deployment"], managed_result=dict(
                            schema="aragorn/pi-core-managed-bootstrap-result/v1", status="BOOTSTRAP_COMPLETE",
                            worker=dict(cleanup=dict(status="VERIFIED_OWNED_CLEANUP")), services=dict(
                            cleanup=dict(status="VERIFIED_OWNED_CLEANUP"),
                            schema="aragorn/pi-core-service-lifecycle/v1",
                            trusted_source_startup=dict(sensor=dict(status="AUTHENTICATED_TRUSTED_SOURCE_STARTUP",
                              authority="TRUSTED_ARAGORN_STARTUP_IMPORTS_NOT_WORKER_STDLIB_OR_LATER_CODE",
                              process={**generation, "cgroup": "/system.slice/" + UNIT})),
                            sensor_state_observation=dict(status="RETAINED_SENSOR_STATE_ONLY", attempt_id="a"*32,
                              capture_digest=pins["record"], receipt_digest=receipt_pin, sensor_health_verified=False,
                              activation_authorized=False, phase3_exit_eligible=False))))
        self.args = dict(archive=b.reader, plan_pin=plan, capture_pin=pins["record"], receipt_pin=receipt_pin,
                         store=self.local.store, receipt_directory=self.local.receipts)

    def replay_args(self, *, public_changes=None):
        a, b, c = self.outer.pins()
        wrapper = runpy.run_path(str(Path(__file__).resolve().parents[1] / "packaging/pi-core/coordinator.py"))
        with patch("os.getpid", return_value=self.v["manager"]["pid"]):
            report = wrapper["_public_observation"](self.owner)
        report.update(status="MANAGED_BOOTSTRAP_RETURNED_NOT_QUALIFIED", wrapper_stage="POST_CALL_CUSTODY",
                      wrapper_cleanup=dict(host="CLOSED", source_loader="CLOSED"), entry_call_attempted=True)
        report.update(public_changes or {})
        stdout = wrapper["_canonical"](report) + b"\n"
        return dict(self.args, profile_pin=a, latest_pin=b, witness_pin=c, owner_pin=self.b.put(stdout))

    def check(self, *, public_changes=None, **options):
        return verify_joined_sensor_state(**self.replay_args(public_changes=public_changes), **options)


class SeparateSensorArchives(_JoinedSensorFixture):
    def test_owner_and_separately_admitted_role_match_without_promoting_timing_or_health(self):
        result = self.check(require_same_manager=True)
        for k in ("owner_sensor_generation_matched", "archive_sensor_subject_and_mount_bytes_matched",
                  "archive_manager_subject_and_mount_bytes_matched", "independent_state_source_roots_matched",
                  "guest_evidence_mount_topology_matched", "manager_configuration_carrier_mount_matched",
                  "sensor_configuration_file_mount_matched"):
            self.assertIs(result[k], True)
        self.assertIs(result["configuration_image_bytes_verified_by_replay"], False)
        self.assertFalse(result["same_capture_interval_verified"] or result["external_freshness_verified"]
                         or result["phase3_exit_eligible"] or result["sensor_health_verified"])

    def test_authenticated_owner_cannot_substitute_other_sensor_invocation_or_stale_outcome(self):
        services = self.owner["managed_result"]["services"]
        services["trusted_source_startup"]["sensor"]["process"]["invocation_id"] = "d"*32
        with self.assertRaisesRegex(ValueError, "generation"):
            self.check()
        services["trusted_source_startup"]["sensor"]["process"]["invocation_id"] = self.identity["invocation_id"]
        services["sensor_state_observation"]["status"] = "RETAINED_SENSOR_STATE_INCONSISTENT"
        with self.assertRaisesRegex(ValueError, "consistent sensor receipt"):
            self.check()

    def test_public_owner_with_uncertain_cleanup_cannot_upgrade_retained_sensor_bytes(self):
        for suspect in (dict(managed_cleanup_complete=False), dict(wrapper_cleanup={"host": "CLEANUP_HOLD",
                         "source_loader": "CLOSED"}), dict(owned_inputs_closed=False)):
            with self.subTest(suspect=suspect), self.assertRaisesRegex(ValueError, "cleanup"):
                self.check(public_changes=suspect)

    def test_resealed_archive_can_corroborate_a_directory_without_the_same_manager_or_reject_a_substitute(self):
        b = self.b
        # Re-seal the other archive with a different PID throughout its own witness.
        for obj in (b.head["subjects"]["manager"], b.capture["roles"]["manager"]["before"],
                    b.capture["roles"]["manager"]["after"], self.outer.proof["manager"]):
            obj["pid"] = 170
        self.assertIs(self.check()["archive_manager_subject_and_mount_bytes_matched"], False)
        with self.assertRaisesRegex(ValueError, "independent manager"):
            self.check(require_same_manager=True)
        b.capture["source_roots"][ACTION]["ino"] += 1_000
        for role in ("manager", "action", "sensor"):
            b.capture["roles"][role]["targets"][ACTION]["ino"] += 1_000
        with self.assertRaisesRegex(ValueError, "state source directories differ"):
            self.check()


class CarrierArchiveJoins(unittest.TestCase):
    def refuse(self, change):
        fixture = _JoinedSensorFixture()
        try:
            fixture.setUp(change_streams=change)
            # Original bytes, independent archive, local receipt and actual wrapper
            # export agree. Refusal must not depend on an out-of-date digest.
            with self.assertRaises(ValueError):
                fixture.check()
        finally:
            fixture.doCleanups()

    def test_missing_manager_carrier_or_sensor_projection_cannot_join(self):
        for role in ("manager", "sensor"):
            with self.subTest(role=role):
                self.refuse(lambda m, s: (m.replace(_CONFIG_MANAGER, b""), s) if role == "manager"
                            else (m, s.replace(_CONFIG_SENSOR, b"")))

    def test_wrong_device_source_or_config_object_refuses_even_when_archives_agree(self):
        for role, old, new in (("manager", b"7:7", b"7:8"), ("sensor", b"7:7", b"7:8"),
                               ("sensor", b"/dev/loop7", b"/dev/loop8"),
                               ("sensor", b"/installed/root/etc/aragorn/pi-sensor-service.json",
                                b"/installed/root/etc/aragorn/pi-action-service.json")):
            with self.subTest(role=role, old=old):
                self.refuse(lambda m, s: (m.replace(_CONFIG_MANAGER, _CONFIG_MANAGER.replace(old, new)), s)
                            if role == "manager" else (m, s.replace(_CONFIG_SENSOR, _CONFIG_SENSOR.replace(old, new))))

    def test_extra_carrier_alias_or_writable_projection_refuses(self):
        for role, row in (("manager", _CONFIG_MANAGER), ("sensor", _CONFIG_SENSOR)):
            for kind in ("alias", "writable"):
                if kind == "alias":
                    changed = row + b"10 1 7:7 / /alternate-config ro,nosuid,nodev,noexec - squashfs /dev/loop7 ro\n"
                else:
                    changed = row.replace(b" ro,nosuid", b" rw,nosuid")
                with self.subTest(role=role, kind=kind):
                    self.refuse(lambda m, s: (m.replace(row, changed), s) if role == "manager"
                                else (m, s.replace(row, changed)))
