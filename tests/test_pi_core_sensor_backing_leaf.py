"""Only B79 changes: fake kernel edges and replay from private fixture archives."""
from contextlib import ExitStack, nullcontext, redirect_stderr
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
import test_pi_core_sensor_dm_mapping as b78
from test_pi_core_state_backing_leaf import sample_leaf


sensor, plans, kernel = b78.sensor, b78.plans, b78.kernel
SYSFS_MOUNT = b"82 1 0:50 / /sys ro,nosuid,nodev,noexec - sysfs sysfs ro\n"


def add_leaf(section, view, volume):
    b78.add_mapping(section, view, volume)
    section["observe_backing_leaf"] = True
    view.update(schema="aragorn/pi-core-sensor-state-view/v4",
                backing_leaf_observation={k: sample_leaf() for k in ("before", "after")})


class JoinedBackingLeaf(unittest.TestCase):
    def archive(self, prepare):
        fixture = b78.replay.archives._JoinedSensorFixture()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp(prepare_observation=prepare, change_streams=lambda m,s:(m + SYSFS_MOUNT,s))
        return fixture

    def test_plan_cannot_opt_in_without_full_v3_contract_or_use_truthy_values(self):
        for fields in ({"observe_backing_leaf": True}, {"observe_backing_leaf":True, "filesystem_uuid":plans.PIN},
                       *({"observe_backing_leaf":v, "filesystem_uuid":plans.PIN,
                          "state_volume_layout":sensor.DIRECT_LAYOUT} for v in (False, 1, "true", None))):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                sensor.validate_section({**plans.entry.section(), **fields})

    def test_held_unavailable_plan_needs_consumed_leaf_source_and_retains_original_v4(self):
        view, mgr, svc, identity, storage = plans.frames.fixture()
        mgr += SYSFS_MOUNT
        view["manager_mountinfo_digest"] = plans.frames.digest(mgr)
        plan, path = plans.entry.protected_plan(), Path("/private/plan")
        section = plan[sensor.FIELD]
        section.update(clock=view["clock"])
        add_leaf(section, view, {"filesystem_uuid":plans.PIN})
        host, pin = plan["host_profile_digest"], canonical_digest(plan)
        inputs = plans.entry.entry._Inputs(60.)
        inputs.guard = Mock()
        inputs.rows = [dict(path=path, pin=pin, raw=canonical_json(plan))]
        rows = [dict(module="aragorn."+n, path="opt/aragorn/src/aragorn/"+n+".py", digest=plans.entry.plans.pin("8"))
                for n in (*sensor._SOURCES, "pi_core_state_dm_mapping", "pi_core_state_backing_leaf")]
        pins = {r["path"]: r["digest"] for r in rows}
        def mint(records):
            return sensor.from_held_plan(inputs, path, plan, pin, host, records, pins,
                dict(pid=view["manager"]["pid"], host_profile_digest=host))
        with patch.object(sensor.os, "getpid", return_value=view["manager"]["pid"]):
            with self.assertRaises(ValueError):
                mint(rows[:-1])
            req = mint(rows)
        req._state, req._deadline = "prepared", 60.
        guard = Mock(return_value=identity)
        with (patch.object(sensor.observer, "capture_sensor_state", return_value=(view, mgr, svc)) as capture,
              patch.object(sensor.observer, "hold_sensor_mount_guard", return_value=nullcontext(Mock())),
              patch.object(sensor.evidence, "validate_sensor_configuration_mounts"),
              patch.object(sensor.custody, "retain_sensor_observation", return_value=plans.entry.plans.pin("9")) as retain):
            result = req.acquire(identity=identity, guard=guard, deadline=60.)
        capture.assert_called_once_with(identity=identity, guard=guard, deadline=60., uuid_storage=storage,
                                        observe_dm_mapping=True, observe_backing_leaf=True)
        self.assertEqual(result["status"], "RETAINED_SENSOR_STATE_ONLY")
        self.assertIs(result["activation_authorized"], False)
        self.assertIn(canonical_json(view), retain.call_args.kwargs["record_raw"])

    def test_sysfs_observations_are_inside_mapping_bracket_without_repeat_on_publication(self):
        events = []
        def mapper(dev, backing, *, deadline):
            events.append(("mapper", backing, deadline))
            return b78.sample_record(device=dev, backing=backing)
        def backing(dev, *, deadline):
            events.append(("leaf", dev, deadline))
            return sample_leaf(device=dev)
        with ExitStack() as s:
            k = kernel.fixture(s)
            s.enter_context(patch.object(kernel.obs, "capture_dm_mapping", side_effect=mapper))
            s.enter_context(patch.object(kernel.obs, "capture_backing_leaf", side_effect=backing))
            view, mgr, svc = kernel.acquire(uuid_storage=k.storage, observe_dm_mapping=True, observe_backing_leaf=True)
            with kernel.obs.hold_sensor_mount_guard(identity=kernel.ID, view=view, manager_raw=mgr, sensor_raw=svc,
                                                    guard=lambda **_: dict(kernel.ID), deadline=14) as current:
                current()
            self.assertEqual(events, [(name,"259:0",14) for name in ("mapper","leaf","leaf","mapper")])
            self.assertEqual(view["schema"], "aragorn/pi-core-sensor-state-view/v4")
            self.assertFalse(k.fds)

    def test_public_finding_is_not_header_attachment_or_continuous_exclusivity(self):
        report = self.archive(add_leaf).check(require_backing_leaf=True)
        self.assertIs(report["kernel_whole_disk_leaf_matched"], True)
        self.assertEqual(report["observed_backing_diskseq"], 19)
        for field in ("physical_asset_verified", "authenticated_unlock_verified", "inline_luks2_header_verified",
                      "external_attachment_verified", "exclusive_writer_verified", "phase3_exit_eligible"):
            self.assertIs(report[field], False, field)

    def test_replay_refuses_substituted_device_disk_incarnation_and_mode_downgrade(self):
        for case in ("wrong device", "replacement", "different sysfs", "v3 under v4", "v4 without opt-in"):
            def changed(section, view, volume):
                add_leaf(section, view, volume)
                if case == "wrong device":
                    view["backing_leaf_observation"] = {k:sample_leaf(device="259:1") for k in ("before","after")}
                elif case == "replacement":
                    view["backing_leaf_observation"]["after"] = sample_leaf(diskseq=20)
                elif case == "different sysfs":
                    for sample in view["backing_leaf_observation"].values():
                        for edge in ("before", "after"):
                            sample[edge]["sysfs_mount_id"] = 83
                elif case == "v3 under v4":
                    view["schema"] = sensor.evidence.DM_VIEW
                    view.pop("backing_leaf_observation")
                else:
                    section.pop("observe_backing_leaf")
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.archive(changed).check()

    def test_strict_reader_cannot_adopt_historical_v3(self):
        args = self.archive(b78.add_mapping).replay_args()
        args["archive"] = args["archive"].root
        flags = [v for k,x in args.items() for v in ("--"+k.replace("_","-"), str(x))]
        with redirect_stderr(StringIO()) as errors:
            self.assertEqual(b78.main([*flags, "--require-backing-leaf"]), 2)
        self.assertIn("backing leaf observation required", errors.getvalue())
