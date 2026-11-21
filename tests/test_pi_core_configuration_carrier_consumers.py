"""All protected callers receive the same independently pinned test carrier; no guest operations."""
from copy import deepcopy
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn import pi_core_coordinator_entry as coordinator
from aragorn import pi_core_mask_capture_entry as masks
from aragorn import pi_core_service_configuration as service
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_broker_preparation_entry as broker_cases
from tests import test_pi_core_coordinator_entry as coordinator_cases
from tests import test_pi_core_mask_capture_entry as mask_cases
from tests import test_pi_core_service_configuration as service_cases


ROOT = "/run/aragorn-pi-config"
PIN = {"device": "7:19", "image_bytes": 4097, "image_sha256": "1" * 64}


def select(plan, docs=None):
    config = plan["service_configuration"]
    config.update(deployment_path=ROOT + "/installed", carrier=PIN.copy())
    for key in ("manifest", "configurations"):
        ref = config[key]
        path = ROOT + "/inputs/" + key + ".json"
        if docs is not None:
            docs[path] = docs[ref["path"]]
        ref["path"] = path
    return config


class CarrierConsumers(unittest.TestCase):
    def test_capture_cannot_skip_consumption_of_the_carrier_reader_or_manager_observer(self):
        required = ("pi_core_configuration_carrier", "pi_core_manager_state_view")
        self.assertTrue(set(required) <= set(masks._CORE))
        pins = {"opt/aragorn/src/aragorn/" + name + ".py": mask_cases.pin(i + 10)
                for i, name in enumerate(masks._CORE)}
        rows = [dict(module="aragorn." + name, path=path, digest=pins[path])
                for name, path in zip(masks._CORE, pins)]
        loader = SimpleNamespace(source_digests=pins)
        for missing in required:
            partial = [r for r in rows if r["module"] != "aragorn." + missing]
            with self.subTest(missing=missing), patch.object(coordinator, "_custody",
                    return_value=(mask_cases.pin(2), partial, {})), self.assertRaisesRegex(
                        coordinator.PiCoordinatorEntryError, "MASK_SOURCE_NOT_CONSUMED"):
                masks._custody(loader, None, 15)

    def test_three_entrypoints_forward_the_carrier_before_dispatch(self):
        for t, field in ((coordinator_cases.CoordinatorEntryTests, "config_hold"),
                         (broker_cases.PreparationEntryTests, "config_hold"), (mask_cases.EntryTests, "hold")):
            with self.subTest(route=t.__name__):
                case = t()
                try:
                    case.setUp()
                    select(case.plan, getattr(case, "documents", None))
                    case.invoke()
                    holder = getattr(case, field)
                    holder.assert_called_once()
                    self.assertEqual(holder.call_args.kwargs["carrier"], PIN)
                    self.assertNotIn("manifest", holder.call_args.kwargs)
                    self.assertNotIn("configurations", holder.call_args.kwargs)
                    for event in getattr(case, "events", ()):
                        self.assertFalse(isinstance(event, str) and event.startswith("read:" + ROOT + "/"),
                                         "protected configuration was read by ambient path")
                finally:
                    case.doCleanups()

    def test_rejects_downgrade_crossed_refs_and_pins_on_other_deployments(self):
        regular = coordinator_cases.prepared()[0]
        select(regular)
        fixture = mask_cases.EntryTests()
        try:
            fixture.setUp()
            stopped = deepcopy(fixture.plan)
        finally:
            fixture.doCleanups()
        select(stopped)
        for plan, reader in ((regular, lambda p: coordinator._plan(p, p["host_profile_digest"], Path("/controlled/plan"))),
                             (stopped, lambda p: masks._plan(p, p["host_profile_digest"]))):
            reader(deepcopy(plan))
            for mutation in (lambda c: c.pop("carrier"), lambda c: c.update(carrier=None),
                             lambda c: c.update(deployment_path=ROOT + "/other"),
                             lambda c: c.update(deployment_path="/alternate/installed"),
                             lambda c: c["manifest"].update(path=ROOT + "/inputs/configurations.json"),
                             lambda c: c["configurations"].update(path="/controlled/elsewhere.json")):
                bad = deepcopy(plan)
                mutation(bad["service_configuration"])
                with self.assertRaises((ValueError, RuntimeError)):
                    reader(bad)
        for shared in (stopped["capture"]["volume_device"], *stopped["capture"]["backing_devices"]):
            bad = deepcopy(stopped)
            bad["service_configuration"]["carrier"]["device"] = shared
            with self.assertRaises((ValueError, RuntimeError)):
                masks._plan(bad, bad["host_profile_digest"])

    def test_other_deployments_keep_their_independently_pinned_reference_path(self):
        section = coordinator_cases.prepared()[0]["service_configuration"]
        inputs = Mock()
        inputs.ref.side_effect = lambda ref: ("held", ref["path"], ref["digest"])
        args = coordinator._configuration_args(coordinator._configuration_section(section), inputs, 15)
        self.assertNotIn("carrier", args)
        for key in ("manifest", "configurations"):
            self.assertEqual(args[key], ("held", section[key]["path"], args[key + "_digest"]))
        self.assertEqual(inputs.ref.call_count, 2)

    def test_real_held_configuration_reads_fixed_files_and_drops_custody_on_error(self):
        # The existing file holder reads real inert documents. Only guest mount/owner identity is modelled.
        fixture = service_cases.PiServiceConfigurationTests()
        with ExitStack() as scope:
            scope.callback(fixture.doCleanups)
            fixture.setUp()
            mount = fixture.fixture / "manager-carrier"
            mount.mkdir(mode=0o700)
            docs = mount / "inputs"
            docs.mkdir(mode=0o700)
            receipt = fixture.install(destination_parent=mount, deployment_name="installed")
            for filename, body in (("manifest.json", fixture.manifest), ("configurations.json", fixture.configs)):
                path = docs / filename
                path.write_bytes(canonical_json(body))
                path.chmod(0o400)
            scope.enter_context(patch.object(service.carrier_media, "ROOT", mount))
            fd = os.open(mount, service.provision._DIRECTORY)
            scope.callback(os.close, fd)
            medium = Mock(root_fd=fd)
            events = []
            @contextmanager
            def hold(pin, *, deadline):
                self.assertEqual(pin, PIN)
                events.append("entered")
                try:
                    yield medium
                finally:
                    events.append("closed")
            scope.enter_context(patch.object(service.carrier_media, "hold_configuration_carrier", side_effect=hold))
            args = dict(receipt_digest=canonical_digest(receipt), manifest_digest=canonical_digest(fixture.manifest),
                        configurations_digest=canonical_digest(fixture.configs), deadline=time.monotonic()+20, carrier=PIN)
            with service.hold_pi_service_configuration(mount / "installed", **args) as held:
                self.assertEqual(held.configurations, fixture.configs)
                root_fd = held.root_fd
                held.guard()
                self.assertTrue(any(call.kwargs.get("directory_fd") == root_fd for call in medium.guard.call_args_list))
            self.assertEqual(events, ["entered", "closed"])
            with self.assertRaises(RuntimeError):
                _ = held.configurations
            with self.assertRaisesRegex(RuntimeError, "reference pin differs"):
                with service.hold_pi_service_configuration(mount / "installed",
                        **(args | {"configurations_digest": "sha256:" + "f" * 64})):
                    self.fail("a changed reference reached a consumer")
            medium.require_member.side_effect = ValueError("different mount")
            with self.assertRaisesRegex(ValueError, "different mount"):
                with service.hold_pi_service_configuration(mount / "installed", **args):
                    self.fail("foreign file reached a consumer")
            self.assertEqual(events, ["entered", "closed"] * 3)
