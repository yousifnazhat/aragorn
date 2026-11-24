"""B108's protected plan, held sink and managed handoff. All OS/service edges are inert."""
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_coordinator_entry as caller
from aragorn.pi_core_pilot_output_observer import PilotOutputRequest
from tests import test_pi_core_coordinator_entry as coordinator, test_pi_core_provider_managed as managed


def descriptor():
    return dict(schema="aragorn/runtime-protected-path/v1", root_device=10, root_inode=101, target_name="result.json")


def section():
    return dict(reader_source_digest=coordinator.pin("1"), path_descriptor=descriptor())


class PilotCallerTests(TestCase):
    def fixture(self):
        f = managed.fixture(self, coordinator.CoordinatorEntryTests)
        f.plan, f.documents = coordinator.prepared(True)
        f.plan["pilot_output"] = section()
        f.configs["action"]["identities"] = {"action": {"uid": 2201, "gid": 2202}}
        f.input_holder.hold_pilot_directory.return_value = 17
        name = "opt/aragorn/src/aragorn/pi_core_pilot_output_observer.py"
        f.source.source_digests[name] = coordinator.pin("1")
        f.custody.return_value[1].append(dict(module="aragorn.pi_core_pilot_output_observer", path=name,
                                              digest=coordinator.pin("1")))
        return f

    def test_protected_caller_forwards_request_and_action_principal_only_for_opt_in(self):
        f = self.fixture()
        result = f.invoke()
        f.input_holder.hold_pilot_directory.assert_called_once_with(descriptor(), {"uid": 2201, "gid": 2202})
        self.assertIs(type(f.call.call_args.kwargs["pilot_output"]), PilotOutputRequest)
        self.assertTrue(result["owned_inputs_closed"])
        del f.plan["pilot_output"]
        f.invoke()
        self.assertNotIn("pilot_output", f.call.call_args.kwargs)
        self.assertEqual(f.input_holder.hold_pilot_directory.call_count, 1)

    def test_mismatched_or_unconsumed_source_never_acquires_credentials_or_starts(self):
        f = self.fixture()
        host_pin, rows_before, host_snapshot = f.custody.return_value
        base_rows, original = rows_before[:-1], rows_before[-1]
        for rows, pin in (([], coordinator.pin("1")), ([original], coordinator.pin("2")),
                          ([original, original], coordinator.pin("1"))):
            f.plan["pilot_output"]["reader_source_digest"] = pin
            with self.subTest(rows=len(rows), pin=pin):
                f.custody.return_value = (host_pin, base_rows + rows, host_snapshot)
                self.assertEqual(f.refuse()["failure_stage"], "HELD_INPUTS")
        f.input_holder.hold_pilot_directory.assert_not_called()
        f.credential_hold.assert_not_called()
        f.approval_hold.assert_not_called()

    def test_no_other_plan_can_select_an_arbitrary_reader_or_enable_this_mode(self):
        protected, _ = coordinator.prepared(True)
        unavailable, _ = coordinator.prepared(False)
        plan_path = Path("/var/lib/pi/plan.json")
        for document, allow in ((protected | {"pilot_output": section()}, False),
                                (unavailable | {"pilot_output": section()}, True),
                                (protected | {"pilot_output": section() | {"path": "/elsewhere"}}, True),
                                (protected | {"pilot_output": section(), "sensor_state_observation": {}}, True)):
            with self.subTest(mode=document["mode"], allow=allow), self.assertRaises(caller.PiCoordinatorEntryError):
                caller._plan(document, document["host_profile_digest"], plan_path, allow_sensor_state=True,
                             allow_pilot_output=allow)

    def test_owned_fixed_directory_refuses_replacement_and_does_not_retry_uncertain_close(self):
        principal = {"uid": 2201, "gid": 2202}
        info = SimpleNamespace(st_dev=10, st_ino=101, st_mode=stat.S_IFDIR | 0o710, st_uid=2201, st_gid=2202)
        path = caller.managed.entry.EFFECT_ROOT / "protected"
        with mock.patch.object(caller.time, "monotonic", return_value=100), \
                mock.patch.object(caller.broker, "_open_protected_directory", return_value=17) as opened, \
                mock.patch.object(caller.broker, "_require_protected_ancestry"), \
                mock.patch.object(caller.os, "fstat", return_value=info), \
                mock.patch.object(caller.os, "lstat", return_value=info) as named, \
                mock.patch.object(caller.os, "get_inheritable", return_value=False), \
                mock.patch.object(caller.os, "close", side_effect=OSError("uncertain inert close")) as close:
            holder = caller._Inputs(120)
            self.assertEqual(holder.hold_pilot_directory(descriptor(), principal), 17)
            opened.assert_called_once_with(path, 2201, "pilot output")
            named.return_value = SimpleNamespace(**(vars(info) | {"st_ino": 102}))
            with self.assertRaisesRegex(caller.PiCoordinatorEntryError, "DIRECTORY_CHANGED"):
                holder.guard()
            with self.assertRaises(caller.runtime.provision.PiOsProvisionError):
                holder.close()
            with self.assertRaisesRegex(caller.PiCoordinatorEntryError, "CLOSE_ALREADY_ATTEMPTED"):
                holder.close()
            self.assertEqual(holder.cleanup_uncertainty, [{"scope": "DESCRIPTOR_CLOSE", "descriptors": [17]}])
            close.assert_called_once_with(17)

    def test_managed_owner_forwards_exact_concrete_request_only_to_a_protected_worker(self):
        f = managed.fixture(self, managed.ManagedProviderTests)
        request = PilotOutputRequest(17, descriptor())
        for changes in (dict(config=f.f.config), dict(sensor_state_request=object()), dict(pilot_output={})):
            with self.subTest(fields=tuple(changes)), self.assertRaisesRegex(caller.managed.PiManagedBootstrapError,
                                                                           "pilot output requires"):
                f.run_enabled(**({"pilot_output": request} | changes))
        f.f.hold.assert_not_called()
        result = f.run_enabled(pilot_output=request)
        self.assertIs(f.f.worker.call_args.kwargs["pilot_output"], request)
        self.assertNotIn("pilot_output", f.f.hold.call_args.kwargs)
        self.assertFalse(result["useful_task_verified"])
