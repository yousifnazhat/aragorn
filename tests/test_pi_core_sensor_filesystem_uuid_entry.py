"""Only inert manager/sensor frames and a held-plan fixture. No ioctl or service."""
from contextlib import nullcontext
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_sensor_state_entry as sensor
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
import test_pi_core_sensor_state_entry as entry
import test_pi_core_sensor_state_evidence as frames


PIN = "03202fed-ed69-43dc-81b4-d6cb7309c17e"
REPLY = "1003202feded6943dc81b4d6cb7309c17e"


class NominatedFilesystem(unittest.TestCase):
    def mint(self, plan):
        path, host = Path("/private/plan"), plan["host_profile_digest"]
        entry.entry._plan(plan, host, path, allow_sensor_state=True)
        inputs = entry.entry._Inputs(120.)
        inputs.guard = Mock()
        pin = canonical_digest(plan)
        inputs.rows = [dict(path=path, pin=pin, raw=canonical_json(plan))]
        rows = [dict(module="aragorn."+n, path="opt/aragorn/src/aragorn/"+n+".py", digest=entry.plans.pin("8"))
                for n in sensor._SOURCES]
        return sensor.from_held_plan(inputs, path, plan, pin, host, rows, {r["path"]: r["digest"] for r in rows},
                                     dict(host_profile_digest=host, pid=sensor.os.getpid()))

    def test_pin_must_be_canonical_and_nonzero_when_declared(self):
        for wrong in (None, PIN.upper(), "00000000-0000-0000-0000-000000000000", True):
            plan = entry.protected_plan()
            plan[sensor.FIELD]["filesystem_uuid"] = wrong
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                self.mint(plan)

    def test_only_explicit_plan_requests_measurement_and_matching_original_bytes_pass(self):
        for opt_in, returned, status in (
            (False, None, "RETAINED_SENSOR_STATE_ONLY"), (True, REPLY, "RETAINED_SENSOR_STATE_ONLY"),
            (True, "10" + "7f"*16, "RETAINED_SENSOR_STATE_INCONSISTENT"),
            (True, None, "RETAINED_SENSOR_STATE_INCONSISTENT"), (False, REPLY, "RETAINED_SENSOR_STATE_INCONSISTENT"),
        ):
            with self.subTest(opt_in=opt_in, returned=returned):
                view, manager, service, ident, storage = frames.fixture()
                plan = entry.protected_plan()
                plan[sensor.FIELD]["clock"] = view["clock"]
                if opt_in:
                    plan[sensor.FIELD]["filesystem_uuid"] = PIN
                with patch.object(sensor.os, "getpid", return_value=view["manager"]["pid"]):
                    req = self.mint(plan)
                req._state, req._deadline = "prepared", 60.
                if returned is not None:
                    view.update(schema=sensor.evidence.UUID_VIEW,
                                filesystem_uuid_observation=dict(before=returned, after=returned))
                guard = Mock(return_value=ident)
                with (
                    patch.object(sensor.observer, "capture_sensor_state", return_value=(view, manager, service)) as read,
                    patch.object(sensor.observer, "hold_sensor_mount_guard", return_value=nullcontext(Mock())),
                    patch.object(sensor.evidence, "validate_sensor_configuration_mounts"),
                    patch.object(sensor.custody, "retain_sensor_observation", return_value=entry.plans.pin("9")) as retain,
                ):
                    result = req.acquire(identity=ident, guard=guard, deadline=60.)
                    read.assert_called_once_with(identity=ident, guard=guard, deadline=60.,
                        **({"uuid_storage": storage} if opt_in else {}))
                    self.assertEqual(result["status"], status)
                    self.assertIs(result["activation_authorized"], False)
                    self.assertIn(canonical_json(view), retain.call_args.kwargs["record_raw"])
