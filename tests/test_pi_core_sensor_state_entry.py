"""Nominated read/receipt route only: no Linux operation or managed service is started."""
from contextlib import nullcontext
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase, mock

from aragorn import pi_core_coordinator_entry as entry
from aragorn import pi_core_sensor_state_entry as sensor
from aragorn import pi_core_service_lifecycle as lifecycle
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_coordinator_entry as plans
from tests import test_pi_core_managed_bootstrap as managed


def section():
    return dict(store=str(sensor.custody.STORE), receipt_directory=str(sensor.custody.RECEIPTS),
                attempt_id="f"*32, storage=dict(device="253:7", backing_devices=["259:0"], fs_type="ext4"),
                clock=dict(boot_id="52d599dc-3bca-4641-bf24-533cd2769ed7", clock_id="CLOCK_BOOTTIME",
                           time_namespace_inode=45))


def receipt(ok=True):
    return dict(attempt_id="f"*32, capture_digest=plans.pin("4"), receipt_digest=plans.pin("5"),
                status="RETAINED_SENSOR_STATE_ONLY" if ok else "RETAINED_SENSOR_STATE_INCONSISTENT",
                activation_authorized=False, phase3_exit_eligible=False, sensor_health_verified=False)


def identity():
    return dict(role="sensor", unit="aragorn-pi-sensor.service", invocation_id="a"*32, pid=21,
                start_ticks=75, uid=101, gid=102)


def protected_plan():
    plan, _ = plans.prepared()
    cfg = plan["service_configuration"]
    cfg.update(deployment_path=str(sensor.carrier.ROOT / "installed"),
               carrier=dict(device="259:4", image_sha256="9"*64, image_bytes=4096))
    for name in ("manifest", "configurations"):
        cfg[name]["path"] = str(sensor.carrier.ROOT / "inputs" / (name + ".json"))
    plan[sensor.FIELD] = section()
    return plan


class SensorEntryTests(TestCase):
    def test_only_explicit_managed_unavailable_route_accepts_exact_plan_without_a_pid(self):
        path = Path("/private/plan")
        plan = protected_plan()
        self.assertIs(entry._plan(plan, plan["host_profile_digest"], path, allow_sensor_state=True), plan)
        with self.assertRaises(entry.PiCoordinatorEntryError):
            entry._plan(plan, plan["host_profile_digest"], path)  # shared preparatory caller
        for change in ({"pid": 9}, {"store": "/tmp/private"}, {"clock": None}):
            candidate = {**plan, sensor.FIELD: {**section(), **change}}
            with self.subTest(change=change), self.assertRaises(ValueError):
                entry._plan(candidate, plan["host_profile_digest"], path, allow_sensor_state=True)
        with self.assertRaises(entry.PiCoordinatorEntryError):
            entry._plan(plan | {"mode": "PROTECTED"}, plan["host_profile_digest"], path, allow_sensor_state=True)
        legacy, _ = plans.prepared()
        with self.assertRaisesRegex(entry.PiCoordinatorEntryError, "PROTECTED_CONFIGURATION"):
            entry._plan(legacy | {sensor.FIELD:section()}, plan["host_profile_digest"], path, allow_sensor_state=True)
        plan["service_configuration"]["carrier"]["device"] = section()["storage"]["backing_devices"][0]
        with self.assertRaisesRegex(entry.PiCoordinatorEntryError, "ALIASES_CONFIGURATION"):
            entry._plan(plan, plan["host_profile_digest"], path, allow_sensor_state=True)

    def test_mint_checks_retained_plan_bytes_and_every_actual_consumed_host_module(self):
        plan = protected_plan()
        host = plan["host_profile_digest"]
        path = Path("/private/p")
        pin = canonical_digest(plan)
        inputs = entry._Inputs(120.)
        inputs.guard = mock.Mock()
        inputs.rows = [dict(path=path, pin=pin, raw=canonical_json(plan))]
        rows = [dict(module="aragorn."+n, path="opt/aragorn/src/aragorn/"+n+".py", digest=plans.pin("8"))
                for n in sensor._SOURCES]
        pins = {row["path"]: row["digest"] for row in rows}
        subject = {"host_profile_digest":host, "pid":sensor.os.getpid()}
        def mint():
            return sensor.from_held_plan(inputs, path, plan, pin, host, rows, pins, subject)
        self.assertIs(type(mint()), sensor.SensorStateRequest)
        rows.pop()
        with self.assertRaises(ValueError):
            mint()
        inputs.rows[0]["raw"] = b"{}"
        with self.assertRaises(ValueError):
            mint()

    def test_preflight_checks_actual_carrier_and_prospective_worker_binds_before_start(self):
        case = managed.ManagedBootstrapTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        config = case.config
        carrier_dev = sensor.os.makedev(8, 4)
        evidence_dev = sensor.os.makedev(8, 5)
        service = SimpleNamespace(configurations=case.configuration.configurations, root=sensor.carrier.ROOT / "installed/root",
                                  root_fd=34)
        plan = SimpleNamespace(deadline=125., rows=[], directories=[], guard=mock.Mock())
        def run(cfg):
            launch = {k: (str(v) if isinstance(v, Path) else v) for k in cfg.__dataclass_fields__ for v in (getattr(cfg,k),)}
            binding = dict(launch_digest=canonical_digest(launch), configuration_digest=canonical_digest(service.configurations),
                           deployment_digest=canonical_digest({}), attempt_id=section()["attempt_id"])
            req = sensor.SensorStateRequest(sensor._SEAL, plan, canonical_json(binding), 45, "8:4")
            req.preflight(deployment={}, service_configuration=service, config=cfg,
                          protected_root=case.args["protected_root"], deadline=120.)
            return req
        with mock.patch.object(sensor.os, "fstat", return_value=SimpleNamespace(st_dev=carrier_dev)), \
                mock.patch.object(sensor.custody, "check_sensor_destinations", return_value=((evidence_dev,4),(evidence_dev,5))) as opened:
            self.assertEqual(run(config)._state, "prepared")
            opened.assert_called_once_with(store=sensor.custody.STORE, receipt_directory=sensor.custody.RECEIPTS,
                                           attempt_id=section()["attempt_id"], deadline=120.)
            with self.assertRaisesRegex(ValueError, "overlaps protected inputs"):
                run(replace(config, root_directory=sensor.custody.STORE.parent))
            service.root = Path("/legacy/root")
            with self.assertRaisesRegex(ValueError, "medium differs"):
                run(config)
            opened.assert_called_once()
            service.root = sensor.carrier.ROOT / "installed/root"
            opened.return_value = ((carrier_dev,4),(carrier_dev,5))
            with self.assertRaisesRegex(ValueError, "shares the configuration"):
                run(config)

    def test_actual_managed_caller_stops_before_worker_when_opt_in_fails(self):
        case = managed.ManagedBootstrapTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        req = object.__new__(sensor.SensorStateRequest)
        with mock.patch.object(sensor.SensorStateRequest, "preflight") as preflight:
            case.services.capture_sensor_state.side_effect = ValueError("unstable")
            with self.assertRaisesRegex(ValueError, "unstable"):
                case.run_bootstrap(sensor_state_request=req)
        preflight.assert_called_once()
        case.services.capture_sensor_state.assert_called_once_with(req, deadline=case.services.operation_deadline)
        case.worker.assert_not_called()
        self.assertIn("services-cleanup", case.events)

    def test_read_route_binds_already_owned_sensor_pidfd_peer_and_authenticated_generation(self):
        row = identity()
        s = lifecycle._Service("sensor", row["uid"], row["gid"], Path("/fake"), started=True,
            pid=row["pid"], pidfd=7, start_ticks=row["start_ticks"], invocation=row["invocation_id"],
            immutable_digest=plans.pin("b"), connection=object())
        held = object.__new__(lifecycle.PiServiceLifecycle)
        held.provider_credential = None
        held._active, held._closed = True, False
        held.services = {"sensor": s}
        held._channels = SimpleNamespace(requests_retired=False, _connections=(None, s.connection, None))
        held.identities = {"sensor":dict(uid=s.uid,gid=s.gid)}
        proc = {k:row[k] for k in ("uid","gid","pid","start_ticks","invocation_id")}
        proc.update(cgroup=s.plan.profile.cgroup, unit_properties_digest=s.immutable_digest)
        held._observation = {"trusted_source_startup":{"sensor":dict(status="AUTHENTICATED_TRUSTED_SOURCE_STARTUP", process=proc)}}
        held._bounded = lambda d: d
        held._ownership = held.guard = mock.Mock()
        req = object.__new__(sensor.SensorStateRequest)
        def read(*,identity,guard,deadline):
            self.assertEqual(identity, row)
            self.assertEqual(guard(deadline=deadline), row)
            return receipt()
        with mock.patch.object(lifecycle, "_generation"), mock.patch.object(lifecycle.transport, "require_peer_live"), \
                mock.patch.object(lifecycle.transport, "validate_worker_pidfd") as pidfd, \
                mock.patch.object(sensor.SensorStateRequest, "acquire", side_effect=read) as acquire:
            held.capture_sensor_state(req, deadline=2.)
            self.assertEqual(pidfd.call_args_list, [mock.call(7,21), mock.call(7,21)])
            with self.assertRaises(lifecycle.PiServiceLifecycleError):
                held.capture_sensor_state(req, deadline=2.)
            acquire.assert_called_once()
            held._sensor_state_attempted = False  # separate inert lifetime variant
            proc["invocation_id"] = "d"*32
            with self.assertRaises(lifecycle.PiServiceLifecycleError):
                held.capture_sensor_state(req, deadline=2.)
            acquire.assert_called_once()

    def test_stable_clock_mismatch_retained_once_and_topology_checked_while_publishing(self):
        ident, sec = identity(), section()
        binding = dict(attempt_id=sec["attempt_id"], clock=sec["clock"], storage=sec["storage"],
                       host_profile_digest=plans.pin("1"), plan_digest=plans.pin("2"), deployment_digest=plans.pin("3"),
                       configuration_digest=plans.pin("4"), launch_digest=plans.pin("5"))
        req = sensor.SensorStateRequest(sensor._SEAL, mock.Mock(), canonical_json(binding), 100, "8:4")
        req._state,req._deadline,req._roots = "prepared",60.,((),())
        topo = mock.Mock()
        def retain(**kw):
            kw["topology_guard"]()
            doc = json.loads(kw["record_raw"])
            self.assertEqual({k:doc[k] for k in binding},binding)
            self.assertEqual(doc["identity"], ident)
            return plans.pin("9")
        with mock.patch.object(sensor.observer,"capture_sensor_state",return_value=({}, b"manager\n", b"sensor\n")), \
                mock.patch.object(sensor.observer,"hold_sensor_mount_guard",return_value=nullcontext(topo)), \
                mock.patch.object(sensor.evidence,"verify_sensor_state",return_value={"sensor_read_only_bind_matched": True,
                    "manager":{"pid":100}, "clock":sec["clock"] | {"time_namespace_inode":46}}), \
                mock.patch.object(sensor.custody,"retain_sensor_observation",side_effect=retain) as writer:
            result = req.acquire(identity=ident,guard=lambda **kw:ident,deadline=60.)
            self.assertEqual(result["status"],"RETAINED_SENSOR_STATE_INCONSISTENT")
            self.assertNotIn("view",result)
            with self.assertRaises(ValueError):
                req.acquire(identity=ident,guard=lambda **kw:ident,deadline=60.)
        writer.assert_called_once()
        topo.assert_called_once()

    def test_carrier_check_uses_held_device_and_original_deadline_before_reporting_success(self):
        ident, clock = identity(), section()["clock"]
        wire = (b"manager observation\n", b"sensor observation\n")
        for error, expected in ((None, "RETAINED_SENSOR_STATE_ONLY"),
                                (ValueError("wrong mounted file"), "RETAINED_SENSOR_STATE_INCONSISTENT")):
            req = sensor.SensorStateRequest(sensor._SEAL, mock.Mock(),
                canonical_json(dict(storage=section()["storage"], attempt_id=section()["attempt_id"], clock=clock)),
                100, "8:4")
            req._state, req._deadline = "prepared", 60.
            with (
                self.subTest(expected=expected),
                mock.patch.object(sensor.observer, "capture_sensor_state", return_value=({}, *wire)) as capture,
                mock.patch.object(sensor.evidence, "verify_sensor_state", return_value=dict(
                    sensor_read_only_bind_matched=True, manager=dict(pid=100), clock=clock)),
                mock.patch.object(sensor.evidence, "validate_sensor_configuration_mounts", side_effect=error) as check,
                mock.patch.object(sensor.observer, "hold_sensor_mount_guard", return_value=nullcontext(mock.Mock())),
                mock.patch.object(sensor.custody, "retain_sensor_observation", return_value=plans.pin("9")) as retain,
            ):
                result = req.acquire(identity=ident, guard=lambda **kw: ident, deadline=60.)
                self.assertEqual(result["status"], expected)
                check.assert_called_once_with(*wire, "8:4", deadline=60.)
                capture.assert_called_once()
                self.assertEqual((retain.call_args.kwargs["manager_raw"], retain.call_args.kwargs["sensor_raw"]), wire)
                self.assertIs(result["activation_authorized"], False)

    def test_public_projection_uses_authenticated_generation_and_only_discloses_pins(self):
        path=Path(__file__).resolve().parents[1]/"packaging/pi-core/coordinator.py"
        spec=importlib.util.spec_from_file_location("sensor_public_wrapper",path)
        wrapper=importlib.util.module_from_spec(spec); spec.loader.exec_module(wrapper)
        ident=identity()
        proc={k:v for k,v in ident.items() if k not in ("unit","role")}
        proc["cgroup"]="/system.slice/"+ident["unit"]
        services={"trusted_source_startup":{"sensor":{"process":proc,"status":"AUTHENTICATED_TRUSTED_SOURCE_STARTUP"}},
                  sensor.FIELD:receipt()}
        ob=dict(status="MANAGED_CALL_RETURNED_NOT_QUALIFIED", phase3_exit_eligible=False,owned_inputs_closed=True,
                managed_call_attempted=True, managed_result={"status":"BOOTSTRAP_COMPLETE","services":services})
        public=wrapper._public_observation(ob)[sensor.FIELD]
        self.assertEqual(public, {k:receipt()[k] for k in ("capture_digest","receipt_digest","status")} |
                         {"sensor_identity_digest":canonical_digest(ident)})
        services[sensor.FIELD]["path"]="/private"
        with self.assertRaises(ValueError):
            wrapper._public_observation(ob)
