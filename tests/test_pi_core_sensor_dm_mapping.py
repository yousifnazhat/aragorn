"""B78 integration only: fake kernel descriptors, held-plan bytes and fixture archives."""
from contextlib import ExitStack, nullcontext, redirect_stderr
from copy import deepcopy
from io import StringIO
import unittest
from unittest.mock import Mock, call, patch

from aragorn import pi_core_sensor_state_entry as sensor
from scripts.verify_pi_core_joined_sensor_state import main
import test_pi_core_sensor_filesystem_uuid_entry as plans
import test_pi_core_sensor_filesystem_uuid_observer as kernel
import test_pi_core_sensor_filesystem_uuid_replay as replay
from test_pi_core_state_dm_mapping import sample_record


def add_mapping(section, view, volume):
    replay.prepare()(section, view, volume)
    section["state_volume_layout"] = sensor.DIRECT_LAYOUT
    view.update(schema=sensor.evidence.DM_VIEW, dm_mapping_observation={
        edge: sample_record() for edge in ("before", "after")})


class DirectMappingIntegration(unittest.TestCase):
    def archive(self, setup):
        fixture = replay.archives._JoinedSensorFixture()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp(prepare_observation=setup)
        return fixture

    def test_strict_plan_requires_known_layout_uuid_and_one_distinct_backing(self):
        section = {**plans.entry.section(), "state_volume_layout": sensor.DIRECT_LAYOUT,
                   "filesystem_uuid": plans.PIN}
        self.assertIs(sensor.validate_section(section), section)
        for name, mutate in (("UUID absent", lambda s:s.pop("filesystem_uuid")),
            ("detached", lambda s:s.update(state_volume_layout="DETACHED")),
            ("two data devices", lambda s:s["storage"]["backing_devices"].append("259:1")),
            ("self reference", lambda s:s["storage"].update(backing_devices=[s["storage"]["device"]]))):
            with self.subTest(name=name), self.assertRaises(ValueError):
                changed = deepcopy(section)
                mutate(changed)
                sensor.validate_section(changed)

    def test_held_plan_requires_consumed_mapping_source_and_dispatches_without_authorizing(self):
        view, manager, service, ident, storage = plans.frames.fixture()
        plan = plans.entry.protected_plan()
        plan[sensor.FIELD].update(clock=view["clock"], state_volume_layout=sensor.DIRECT_LAYOUT,
                                 filesystem_uuid=plans.PIN)
        fixture = plans.NominatedFilesystem()
        with patch.object(sensor.os, "getpid", return_value=view["manager"]["pid"]):
            with self.assertRaises(ValueError):
                fixture.mint(plan)  # historical consumed rows omit the mapper module
            from pathlib import Path
            from aragorn.oci_worker_protocol import canonical_digest, canonical_json
            path, pin = Path("/private/plan"), canonical_digest(plan)
            inputs = plans.entry.entry._Inputs(120.)
            inputs.guard = Mock()
            inputs.rows = [dict(path=path, pin=pin, raw=canonical_json(plan))]
            modules = (*sensor._SOURCES, "pi_core_state_dm_mapping")
            rows = [dict(module="aragorn."+n, path="opt/aragorn/src/aragorn/"+n+".py", digest=plans.entry.plans.pin("8"))
                    for n in modules]
            host = plan["host_profile_digest"]
            req = sensor.from_held_plan(inputs, path, plan, pin, host, rows, {r["path"]: r["digest"] for r in rows},
                                        dict(pid=view["manager"]["pid"], host_profile_digest=host))
        view.update(schema=sensor.evidence.DM_VIEW, filesystem_uuid_observation=dict(before=plans.REPLY, after=plans.REPLY),
                    dm_mapping_observation={k: sample_record() for k in ("before","after")})
        req._state, req._deadline = "prepared", 60.
        guard = Mock(return_value=ident)
        with (patch.object(sensor.observer, "capture_sensor_state", return_value=(view, manager, service)) as capture,
              patch.object(sensor.observer, "hold_sensor_mount_guard", return_value=nullcontext(Mock())),
              patch.object(sensor.evidence, "validate_sensor_configuration_mounts"),
              patch.object(sensor.custody, "retain_sensor_observation", return_value=plans.entry.plans.pin("9")) as retain):
            result = req.acquire(identity=ident, guard=guard, deadline=60.)
        capture.assert_called_once_with(identity=ident, guard=guard, deadline=60., uuid_storage=storage, observe_dm_mapping=True)
        self.assertIn(canonical_json(view), retain.call_args.kwargs["record_raw"])
        self.assertEqual(result["status"], "RETAINED_SENSOR_STATE_ONLY")
        self.assertIs(result["activation_authorized"], False)

    def test_both_edges_use_held_directory_device_and_retention_does_not_requery_mapper(self):
        with ExitStack() as s:
            k = kernel.fixture(s)
            read = s.enter_context(patch.object(kernel.obs, "capture_dm_mapping",
                return_value=sample_record(device=k.storage["device"])))
            view, mgr, svc = kernel.acquire(uuid_storage=k.storage, observe_dm_mapping=True)
            self.assertEqual(view["schema"], sensor.evidence.DM_VIEW)
            with kernel.obs.hold_sensor_mount_guard(identity=kernel.ID, view=view, manager_raw=mgr,
                    sensor_raw=svc, guard=lambda **_: dict(kernel.ID), deadline=14) as current:
                current()
            self.assertEqual(read.call_args_list, [call("8:2", "259:0", deadline=14)] * 2)
            self.assertFalse(k.fds)

    def test_changed_generation_refuses_without_a_third_read(self):
        with ExitStack() as s:
            k = kernel.fixture(s)
            read = s.enter_context(patch.object(kernel.obs, "capture_dm_mapping", side_effect=[
                sample_record(device="8:2", event_nr=n) for n in (12, 13)]))
            with self.assertRaises(ValueError):
                kernel.acquire(uuid_storage=k.storage, observe_dm_mapping=True)
            self.assertEqual(read.call_count, 2)
            self.assertFalse(k.fds)

    def test_original_archive_and_private_observation_yield_only_a_mapping_finding(self):
        report = self.archive(add_mapping).check(require_direct_crypt_mapping=True)
        self.assertIs(report["active_dm_crypt_single_backing_matched"], True)
        self.assertEqual((report["observed_mapping_device"], report["observed_sole_kernel_dependency"]),
                         ("253:7", "259:0"))
        for field in ("encryption_uuid_measured", "inline_luks2_header_verified", "authenticated_unlock_verified",
                      "physical_asset_verified", "external_freshness_verified", "sensor_health_verified", "phase3_exit_eligible"):
            self.assertIs(report[field], False, field)

    def test_archive_does_not_upgrade_v2_accept_downgrade_or_adopt_a_substituted_backing(self):
        archive = self.archive(replay.prepare())
        params = archive.replay_args()
        params["archive"] = params["archive"].root
        flags = [x for name,value in params.items() for x in ("--"+name.replace("_", "-"), str(value))]
        with redirect_stderr(StringIO()) as errors:
            self.assertEqual(main([*flags, "--require-direct-crypt-mapping"]), 2)
        self.assertIn("direct crypt mapping observation required", errors.getvalue())
        for name in ("downgrade", "undeclared", "substitution"):
            def changed(section, view, volume):
                add_mapping(section, view, volume)
                if name == "downgrade":
                    view.pop("dm_mapping_observation")
                    view["schema"] = sensor.evidence.UUID_VIEW
                elif name == "undeclared":
                    section.pop("state_volume_layout")
                else:
                    view["dm_mapping_observation"] = {k: sample_record(backing="259:1") for k in ("before", "after")}
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.archive(changed).check()
