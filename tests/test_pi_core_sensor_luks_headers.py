"""B80 caller and separate archive replay. All devices and lifetimes are inert."""
from contextlib import ExitStack, nullcontext, redirect_stderr
from io import StringIO
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from aragorn.oci_worker_protocol import canonical_digest, canonical_json
import test_pi_core_sensor_backing_leaf as b79
from test_pi_core_state_luks_headers import sample_headers


sensor, plans, kernel = b79.sensor, b79.plans, b79.kernel
UUID = "ac1fc095-d8de-4ad8-9c6d-a8593cfb1fcc"


def add_headers(section, view, volume, *, encryption_uuid=None):
    b79.add_leaf(section, view, volume)
    profile, record = sample_headers(encryption_uuid=encryption_uuid or volume["encryption_uuid"])
    section["luks_header_profile"] = profile
    view.update(schema="aragorn/pi-core-sensor-state-view/v5", luks_header_observation=record)


class CurrentHeaders(unittest.TestCase):
    archive = b79.JoinedBackingLeaf.archive

    def test_requires_whole_disk_opt_in_and_a_distinct_encryption_identity(self):
        profile, _ = sample_headers(encryption_uuid=UUID)
        base = {**plans.entry.section(), "filesystem_uuid":plans.PIN, "state_volume_layout":sensor.DIRECT_LAYOUT,
                "luks_header_profile":profile}
        with self.assertRaises(ValueError):
            sensor.validate_section(base)
        with self.assertRaises(ValueError):
            sensor.validate_section({**base, "observe_backing_leaf":True, "filesystem_uuid":UUID})
        with self.assertRaises(ValueError):
            sensor.validate_section({**base, "observe_backing_leaf":True, "luks_header_profile":None})

    def test_protected_plan_needs_exact_loaded_reader_and_retains_the_original_v5_bytes(self):
        view, manager, svc, ident, storage = plans.frames.fixture()
        manager += b79.SYSFS_MOUNT + b"7 1 0:51 / /dev rw - devtmpfs devtmpfs rw\n"
        view["manager_mountinfo_digest"] = plans.frames.digest(manager)
        plan, path = plans.entry.protected_plan(), Path("/private/plan")
        section = plan[sensor.FIELD]
        section["clock"] = view["clock"]
        add_headers(section, view, {"filesystem_uuid":plans.PIN, "encryption_uuid":UUID})
        host, pin = plan["host_profile_digest"], canonical_digest(plan)
        inputs = plans.entry.entry._Inputs(60.)
        inputs.guard, inputs.rows = Mock(), [dict(path=path, pin=pin, raw=canonical_json(plan))]
        names = (*sensor._SOURCES, "pi_core_state_dm_mapping", "pi_core_state_backing_leaf", "pi_core_state_luks_headers")
        rows = [dict(module="aragorn."+n,path="opt/aragorn/src/aragorn/"+n+".py",digest=plans.entry.plans.pin("8"))
                for n in names]
        def mint(records):
            return sensor.from_held_plan(inputs, path, plan, pin, host, records, {r["path"]:r["digest"] for r in rows},
                dict(pid=view["manager"]["pid"], host_profile_digest=host))
        with patch.object(sensor.os, "getpid", return_value=view["manager"]["pid"]):
            with self.assertRaises(ValueError):
                mint(rows[:-1])
            req = mint(rows)
        req._state, req._deadline = "prepared", 60.
        guard = Mock(return_value=ident)
        with (patch.object(sensor.observer, "capture_sensor_state", return_value=(view, manager, svc)) as capture,
              patch.object(sensor.observer, "hold_sensor_mount_guard", return_value=nullcontext(Mock())),
              patch.object(sensor.evidence, "validate_sensor_configuration_mounts"),
              patch.object(sensor.custody, "retain_sensor_observation", return_value=plans.entry.plans.pin("9")) as retain):
            result = req.acquire(identity=ident, guard=guard, deadline=60.)
        capture.assert_called_once_with(identity=ident, guard=guard, deadline=60., uuid_storage=storage,
            observe_dm_mapping=True, observe_backing_leaf=True, luks_header_profile=section["luks_header_profile"])
        self.assertIn(canonical_json(view), retain.call_args.kwargs["record_raw"])
        self.assertEqual(result["status"], "RETAINED_SENSOR_STATE_ONLY")
        self.assertIs(result["activation_authorized"], False)

    def test_single_header_acquisition_is_bracketed_by_leaf_and_mapping_no_retention_requery(self):
        events = []
        profile, observed = sample_headers(encryption_uuid=UUID)
        def mapping(dev, backing, *, deadline):
            events.append("mapping")
            return b79.b78.sample_record(device=dev, backing=backing)
        def leaf(dev, *, deadline):
            events.append("leaf")
            return b79.sample_leaf(device=dev)
        def headers(dev, seq, nominated, *, deadline):
            events.append("headers")
            self.assertEqual((dev,seq,nominated,deadline), ("259:0",19,profile,14))
            return observed
        with ExitStack() as s:
            k = kernel.fixture(s)
            for name, handler in (("capture_dm_mapping",mapping),("capture_backing_leaf",leaf),
                                  ("capture_luks_headers",headers)):
                s.enter_context(patch.object(kernel.obs, name, side_effect=handler))
            view,mgr,svc = kernel.acquire(uuid_storage=k.storage, observe_dm_mapping=True,
                                           observe_backing_leaf=True, luks_header_profile=profile)
            with kernel.obs.hold_sensor_mount_guard(identity=kernel.ID,view=view,manager_raw=mgr,sensor_raw=svc,
                    guard=lambda **_:dict(kernel.ID), deadline=14) as current:
                current()
            self.assertEqual(events, ["mapping","leaf","headers","leaf","mapping"])
            self.assertEqual(view["luks_header_observation"], observed)
            self.assertFalse(k.fds)

    def test_joined_current_header_is_not_unlock_attachment_fence_or_qualification(self):
        fixture = self.archive(add_headers)
        result = fixture.check(require_inline_luks_headers=True)
        for key in ("current_inline_luks2_metadata_matched","inline_luks2_header_verified","encryption_uuid_measured"):
            self.assertIs(result[key], True, key)
        for key in ("authenticated_unlock_verified","physical_asset_verified","external_attachment_verified",
                    "exclusive_writer_verified","phase3_exit_eligible"):
            self.assertIs(result[key], False, key)
        for key,value in fixture.plan[sensor.FIELD]["luks_header_profile"].items():
            if key != "metadata_area_bytes":
                self.assertNotIn(value.encode(), canonical_json(result))

    def test_separately_pinned_volume_refuses_self_consistent_foreign_headers_and_incomplete_contract(self):
        for case in ("wrong volume", "missing record", "foreign diskseq", "wrong dev mount", "different approved bytes", "v4 downgrade"):
            def change(section, view, volume):
                add_headers(section, view, volume, encryption_uuid="bb3479d7-1f3a-4706-a333-996c2b1cc1a9"
                            if case == "wrong volume" else None)
                if case == "missing record":
                    view.pop("luks_header_observation")
                elif case == "foreign diskseq":
                    _, view["luks_header_observation"] = sample_headers(diskseq=20, encryption_uuid=volume["encryption_uuid"])
                elif case == "wrong dev mount":
                    view["luks_header_observation"]["node"]["mount_id"] = 83
                elif case == "different approved bytes":
                    section["luks_header_profile"]["primary_sha256"] = "sha256:" + "f"*64
                elif case == "v4 downgrade":
                    section.pop("luks_header_profile")
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.archive(change).check()

    def test_strict_cli_refuses_old_observation_without_opening_a_device(self):
        args = self.archive(b79.add_leaf).replay_args()
        args["archive"] = args["archive"].root
        flags = [v for k,x in args.items() for v in ("--"+k.replace("_","-"),str(x))]
        with redirect_stderr(StringIO()):
            self.assertEqual(b79.b78.main([*flags, "--require-inline-luks-headers"]), 2)
