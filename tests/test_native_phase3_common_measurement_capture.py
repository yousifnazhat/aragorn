"""Inert finite private closure and real retained record composition only.

No historical test method or live producer runs. Public-envelope data and real
blocked/interval data are separate fixtures; neither is presented as a genuine
combined live capture or as final acceptance evidence.
"""

from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_measurement_capture as subject
from aragorn import native_phase3_blocked_create_verify as blocked
from aragorn import native_phase3_ingress_interval_verify as interval
from aragorn import runtime_native_measurement_inputs as prepared_inputs
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_native_phase3_common_attempt_capture as capture_data
from tests import test_native_phase3_blocked_create_verify as blocked_data
from tests import test_native_phase3_common_process_verifier as process_data


class MeasurementPlanData(unittest.TestCase):
    """Only public capture data and its finite test-only private grant source."""

    def setUp(self):
        fixture = capture_data.AttemptCaptureData()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.capture = fixture.capture
        self.public_cas = fixture.reader

    def plan(self, capture=None, **updates):
        return subject.plan_native_common_measurement_inputs(
            self.capture if capture is None else capture,
            **({"public_cas": self.public_cas} | updates),
        )

    def private_store(self, plan):
        store = CAS(self.fixture.planner_fixture.common.root / "finite-private")
        raw = self.fixture.planner_fixture.common.inputs[
            capture_data.inputs.base.preparation.old.live._GRANT
        ]
        self.assertEqual(canonical_digest(json.loads(raw)), plan["grant_digest"])
        blobs = plan["public_blobs"] | {plan["grant_digest"]: raw}
        for pin, content in blobs.items():
            store.put_expected(
                BytesIO(content), expected_digest=pin, max_bytes=len(content)
            )
        return CAS(store.root, read_only=True), raw


class NativeCommonMeasurementPlanTests(MeasurementPlanData):
    def test_plan_missing_set_is_exact_grant_and_real_private_validator_accepts(self):
        with (
            patch.object(
                CAS, "put", side_effect=AssertionError("public planner wrote")
            ),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("public planner wrote")
            ),
            patch("time.clock_gettime_ns", side_effect=AssertionError("planner clock")),
        ):
            plan = self.plan()
        self.assertGreater(len(plan["input_rows"]), 0)
        self.assertLessEqual(len(plan["input_rows"]), 13)
        self.assertEqual(
            {row["digest"] for row in plan["input_rows"]} - set(plan["public_blobs"]),
            {plan["grant_digest"]},
        )
        self.assertNotIn(plan["grant_digest"], plan["public_blobs"])
        installed = {
            target: source
            for source, target in capture_data.inputs.FIXTURE_HELPERS.items()
        } | capture_data.inputs.HELPER_ALIASES
        self.assertEqual(set(plan["installed_sources"]), set(installed))
        for target, source in installed.items():
            content = self.fixture.bound["source_raws"][source]
            self.assertEqual(
                plan["installed_sources"][target],
                {
                    "digest": capture_data.subject._digest(content),
                    "bytes": len(content),
                },
            )
        private, grant = self.private_store(plan)
        self.assertEqual(plan["grant_bytes"], len(grant))
        with (
            patch.object(
                CAS, "put", side_effect=AssertionError("private validator wrote")
            ),
            patch.object(
                CAS,
                "put_expected",
                side_effect=AssertionError("private validator wrote"),
            ),
            patch(
                "time.clock_gettime_ns", side_effect=AssertionError("validator clock")
            ),
        ):
            validated = prepared_inputs.validate_prepared_native_measurement_inputs(
                prepared_raw=plan["prepared_raw"],
                expected_prepared_digest=plan["prepared_digest"],
                expected_binding_digest=plan["binding_digest"],
                expected_broker_source_pins=plan["source_pins"],
                source_cas=private,
            )
        self.assertEqual(
            set(validated["input_blobs"]), {row["digest"] for row in plan["input_rows"]}
        )
        self.assertEqual(validated["input_blobs"][plan["grant_digest"]], grant)

    def test_planner_rejects_missing_retained_public_child_and_writable_store(self):
        with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
            self.plan(public_cas=self.fixture.store)
        missing = self.fixture.built["measurement_prepared_digest"]
        original = CAS.read

        def read(store, pin, **kwargs):
            if pin == missing:
                raise FileNotFoundError("inert missing public preparation")
            return original(store, pin, **kwargs)

        with patch.object(CAS, "read", read):
            with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                self.plan()

    def test_planner_rejects_extra_private_role_and_rebound_prepared_pin(self):
        changes = (
            lambda value: value["guest"]["attempt"]["plan"].update(
                measurement_prepared_digest="sha256:" + "f" * 64
            ),
            lambda value: value["guest"]["attempt"]["public_blob_attempts"][0].update(
                role="private_grant"
            ),
        )
        for change in changes:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                self.plan(value)

    def test_full_consumer_requires_real_private_grant_after_public_replay(self):
        raw = canonical_json(self.capture) + b"\n"
        pin = capture_data.subject._digest(raw)
        self.fixture.retain({pin: raw})
        plan = self.plan()
        missing = CAS(self.fixture.planner_fixture.common.root / "missing-grant")
        for child_pin, content in plan["public_blobs"].items():
            missing.put_expected(
                BytesIO(content), expected_digest=child_pin, max_bytes=len(content)
            )
        with patch.object(
            subject,
            "validate_prepared_native_measurement_inputs",
            wraps=prepared_inputs.validate_prepared_native_measurement_inputs,
        ) as validate:
            with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                subject.verify_native_common_measurement_capture(
                    raw,
                    expected_capture_digest=pin,
                    public_cas=self.public_cas,
                    private_input_cas=CAS(missing.root, read_only=True),
                    expected_worker={
                        "pid": 1,
                        "start_time_ticks": 1,
                        "uid": 1,
                        "gid": 1,
                    },
                    expected_broker_process={
                        "pid": 2,
                        "start_time_ticks": 2,
                        "uid": 2,
                        "gid": 2,
                        "boot_id": "inert",
                        "mount_namespace": "inert",
                    },
                    expected_gateway={"pid": 3, "uid": 3, "gid": 3},
                    expected_sink_accounts={
                        "broker_uid": 2,
                        "broker_gid": 4,
                        "runtime_gid": 1,
                    },
                )
        validate.assert_called_once()

    def test_full_consumer_rejects_public_envelope_observation_doubles_after_real_private_validation(
        self,
    ):
        raw = canonical_json(self.capture) + b"\n"
        pin = capture_data.subject._digest(raw)
        self.fixture.retain({pin: raw})
        private, _ = self.private_store(self.plan())
        with (
            patch.object(
                subject,
                "validate_prepared_native_measurement_inputs",
                wraps=prepared_inputs.validate_prepared_native_measurement_inputs,
            ) as validate,
            patch.object(
                subject.processes,
                "verify_native_common_process_observations",
                wraps=subject.processes.verify_native_common_process_observations,
            ) as process_verify,
            patch.object(
                subject,
                "verify_native_common_measurement_records",
                side_effect=AssertionError("unverified processes reached records"),
            ) as records,
        ):
            with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                subject.verify_native_common_measurement_capture(
                    raw,
                    expected_capture_digest=pin,
                    public_cas=self.public_cas,
                    private_input_cas=private,
                    expected_worker={
                        "pid": 1,
                        "start_time_ticks": 1,
                        "uid": 1,
                        "gid": 1,
                    },
                    expected_broker_process={
                        "pid": 2,
                        "start_time_ticks": 2,
                        "uid": 2,
                        "gid": 2,
                        "boot_id": "inert",
                        "mount_namespace": "inert",
                    },
                    expected_gateway={"pid": 3, "uid": 3, "gid": 3},
                    expected_sink_accounts={
                        "broker_uid": 2,
                        "broker_gid": 4,
                        "runtime_gid": 1,
                    },
                )
        validate.assert_called_once()
        process_verify.assert_called_once()
        records.assert_not_called()

    def test_private_public_stores_must_be_disjoint_not_aliases_or_nested(self):
        plan = self.plan()
        private, _ = self.private_store(plan)
        subject._separate_stores(self.public_cas, private)
        nested = CAS(self.public_cas.root / "nested-private")
        parent_alias = self.public_cas.root.parent / "aliased-parent"
        parent_alias.symlink_to(self.public_cas.root.parent, target_is_directory=True)
        alias = CAS(parent_alias / self.public_cas.root.name, read_only=True)
        for candidate in (self.public_cas, alias, CAS(nested.root, read_only=True)):
            with self.subTest(root=candidate.root):
                with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                    subject._separate_stores(self.public_cas, candidate)
                with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                    subject._separate_stores(candidate, self.public_cas)


class NativeCommonMeasurementProcessExpectationTests(unittest.TestCase):
    """Real process consumer, inert records, explicitly not a full capture."""

    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = CAS(Path(directory.name) / "public")
        self.reader = CAS(store.root, read_only=True)
        identity, observer, pins = process_data._fixture()
        verification = subject.processes.verify_native_common_process_observations(
            identity,
            deepcopy(identity),
            observer,
            deepcopy(observer),
            expected_container_id=process_data.CONTAINER,
            expected_file_digests=pins,
        )
        journal = []
        for role, value in (
            ("identity_before", identity),
            ("identity_after", identity),
            ("process_before", observer),
            ("process_after", observer),
        ):
            raw = canonical_json(value)
            pin = store.put(BytesIO(raw), max_bytes=len(raw))
            journal.append({"role": role, "digest": pin, "bytes": len(raw)})
        self.capture = {
            "guest": {
                "attempt": {
                    "public_blob_attempts": journal,
                    "process_verification": verification,
                }
            }
        }
        self.plan = {
            "request": {
                "container_id": process_data.CONTAINER,
                "expected_file_digests": pins,
                "boot_id": process_data.BOOT,
            }
        }
        self.expectations = {
            "expected_" + role: {
                key: observer["processes"][role]["process"][key]
                for key in (
                    ("pid", "uid", "gid") if role == "gateway" else subject._EPOCH
                )
            }
            for role in ("worker", "gateway", "broker")
        }
        broker = self.expectations.pop("expected_broker")
        broker.update(
            boot_id=process_data.BOOT,
            mount_namespace=f"mnt:[{identity['processes']['broker']['mount_namespace']['inode']}]",
        )
        self.expectations["expected_broker_process"] = broker
        self.expectations["expected_sink_accounts"] = {
            "broker_uid": broker["uid"],
            "runtime_gid": self.expectations["expected_worker"]["gid"],
            # Explicit fixture input, deliberately not inferred from sink bytes.
            "broker_gid": 993,
        }

    def verify(self, *, capture=None, **updates):
        return subject._verify_process_expectations(
            self.capture if capture is None else capture,
            self.plan,
            subject._reader(self.reader),
            **(self.expectations | updates),
        )

    def test_real_process_replay_joins_explicit_expectations_and_retained_result(self):
        result = self.verify()
        self.assertEqual(
            result, self.capture["guest"]["attempt"]["process_verification"]
        )
        self.assertEqual(result["caller_pinned_files"], 28)
        self.assertTrue(
            all(result[key] is False for key in subject.processes.FALSE_FLAGS)
        )

    def test_rebound_caller_process_namespace_accounts_or_asserted_process_result_refused(
        self,
    ):
        changes = (
            ("expected_worker", "pid", 1),
            ("expected_worker", "uid", True),
            ("expected_broker_process", "start_time_ticks", 1),
            ("expected_broker_process", "mount_namespace", "mnt:[1]"),
            (
                "expected_broker_process",
                "boot_id",
                "ffffffff-1111-2222-3333-444444444444",
            ),
            ("expected_gateway", "gid", 1),
            ("expected_sink_accounts", "broker_uid", 1),
            ("expected_sink_accounts", "runtime_gid", 1),
            ("expected_sink_accounts", "broker_gid", True),
        )
        for role, key, value in changes:
            expected = deepcopy(self.expectations[role])
            expected[key] = value
            with self.subTest(role=role, key=key):
                with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
                    self.verify(**{role: expected})
        capture = deepcopy(self.capture)
        capture["guest"]["attempt"]["process_verification"]["caller_pinned_files"] = 1
        with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
            self.verify(capture=capture)


class MeasurementRecordsData(unittest.TestCase):
    """Positive component data; not a forged full public capture or live run."""

    def setUp(self):
        fixture = blocked_data.BlockedCreateData()
        self.addCleanup(fixture.close)
        self.fixture = fixture
        args = fixture.arguments()
        joined, broker = fixture.joined, fixture.joined.broker
        public = broker.evidence

        def record(raw):
            pin = joined.retain(public, raw)
            return {"digest": pin, "bytes": len(raw), "text": raw.decode()}

        work = {
            "status": "OBSERVED",
            "records": {
                name: record(args[name + "_raw"])
                for name in (
                    "driver",
                    "receipt_before",
                    "receipt_after",
                    "sink_before",
                    "sink_after",
                )
            },
        }
        snapshot = {
            "status": "SNAPSHOTTED",
            "records": {
                name: record(args[name + "_raw"])
                for name in (
                    "startup",
                    "ingress",
                    "attempt",
                    "action",
                    "completion",
                )
            },
        }
        journal = []
        clocks = {}
        for name, value in (("before", joined.before), ("after", joined.after)):
            value["processes"]["broker"]["gid"] = broker.process["gid"]
            clocks[name] = canonical_json(value)
            row = record(clocks[name])
            journal.append(
                {
                    "role": "clock_" + name,
                    "digest": row["digest"],
                    "bytes": row["bytes"],
                }
            )
        interval_args = {
            key: value
            for key, value in args.items()
            if key
            in {
                "startup_raw",
                "ingress_raw",
                "attempt_raw",
                "action_raw",
                "expected_record_digests",
                "completion_raw",
                "expected_completion_digest",
                "expected_binding_raw",
                "expected_binding_digest",
                "expected_worker",
                "expected_broker_process",
                "expected_worker_binding_digest",
                "expected_genesis_digest",
                "input_cas",
                "evidence_cas",
            }
        }
        interval_args.update(
            clock_before_raw=clocks["before"],
            clock_after_raw=clocks["after"],
            expected_clock_before_digest=canonical_digest(json.loads(clocks["before"])),
            expected_clock_after_digest=canonical_digest(json.loads(clocks["after"])),
        )
        # Expected producer-report bytes are established by the actual existing
        # pure consumers, never mocked PASS dictionaries or a prior test method.
        verification = {
            "blocked_create": blocked.verify_native_blocked_create(**args),
            "ingress_interval": interval.verify_native_ingress_interval(
                **interval_args
            ),
        }
        verification_record = record(canonical_json(verification))
        journal.append(
            {
                "role": "independent_verification",
                "digest": verification_record["digest"],
                "bytes": verification_record["bytes"],
            }
        )
        work_record, snapshot_record = (
            record(canonical_json(work)),
            record(canonical_json(snapshot)),
        )
        self.capture = {
            "guest": {
                "attempt": {
                    "workload": {"status": "OBSERVED", "digest": work_record["digest"]},
                    "snapshot": {
                        "status": "SNAPSHOTTED",
                        "digest": snapshot_record["digest"],
                    },
                    "public_blob_attempts": journal,
                    "verification": verification,
                }
            }
        }
        self.plan = {
            "binding_raw": args["expected_binding_raw"],
            "binding_digest": args["expected_binding_digest"],
            "source_pins": json.loads(args["expected_binding_raw"])["source_pins"],
            "sink_source_digest": args["expected_sink_source_digest"],
            "request": {
                "container_id": args["expected_container_id"],
                "measurement_binding_digest": args["expected_binding_digest"],
                "expected_file_digests": {
                    "/etc/aragorn/runtime-action-worker.json": args[
                        "expected_worker_binding_digest"
                    ],
                    "/etc/aragorn/runtime-native-tool-genesis.json": args[
                        "expected_genesis_digest"
                    ],
                },
            },
        }
        self.arguments = {
            "capture": self.capture,
            "plan": self.plan,
            "public_cas": args["evidence_cas"],
            "private_input_cas": args["input_cas"],
            **{
                key: args[key]
                for key in (
                    "expected_worker",
                    "expected_broker_process",
                    "expected_gateway",
                    "expected_sink_accounts",
                )
            },
        }


class NativeCommonMeasurementRecordsTests(MeasurementRecordsData):
    def test_real_blocked_and_interval_consumers_replay_without_effects(self):
        with (
            patch.object(CAS, "put", side_effect=AssertionError("replay wrote")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("replay wrote")
            ),
            patch(
                "time.clock_gettime_ns",
                side_effect=AssertionError("replay sampled clock"),
            ),
        ):
            result = subject.verify_native_common_measurement_records(**self.arguments)
        self.assertEqual(result, self.capture["guest"]["attempt"]["verification"])
        self.assertEqual(
            result["blocked_create"]["decision"],
            dict.fromkeys(blocked.FALSE_FLAGS, False),
        )
        self.assertEqual(
            result["ingress_interval"]["decision"],
            dict.fromkeys(interval.FALSE_FLAGS, False),
        )

    def test_record_replay_refuses_rebound_process_and_expected_result(self):
        worker = deepcopy(self.arguments["expected_worker"])
        worker["pid"] += 1
        with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
            subject.verify_native_common_measurement_records(
                **(self.arguments | {"expected_worker": worker})
            )
        value = deepcopy(self.capture)
        value["guest"]["attempt"]["verification"]["blocked_create"]["status"] = (
            "UNVERIFIED"
        )
        with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
            subject.verify_native_common_measurement_records(
                **(self.arguments | {"capture": value})
            )

    def test_record_replay_refuses_missing_clock_or_private_inputs(self):
        value = deepcopy(self.capture)
        value["guest"]["attempt"]["public_blob_attempts"] = [
            row
            for row in value["guest"]["attempt"]["public_blob_attempts"]
            if row["role"] != "clock_after"
        ]
        with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
            subject.verify_native_common_measurement_records(
                **(self.arguments | {"capture": value})
            )
        empty = CAS(self.arguments["private_input_cas"].root.parent / "missing-private")
        with self.assertRaises(subject.NativeCommonMeasurementCaptureError):
            subject.verify_native_common_measurement_records(
                **(
                    self.arguments
                    | {"private_input_cas": CAS(empty.root, read_only=True)}
                )
            )


class NativeCommonMeasurementFullCompositionTests(MeasurementPlanData):
    """One coherent inert deployment; no producer or semantic PASS is mocked."""

    def test_full_capture_replays_real_private_process_and_measurement_consumers(self):
        plan = self.plan()
        private, grant_raw = self.private_store(plan)
        native = self.fixture.planner_fixture.common.inputs
        request, binding = plan["request"], json.loads(plan["binding_raw"])
        identity, observer, old_pins = process_data._fixture()
        replacements = {
            old_pins[path]: pin
            for path, pin in request["expected_file_digests"].items()
        }

        def replace(value):
            if type(value) is dict:
                return {key: replace(item) for key, item in value.items()}
            if type(value) is list:
                return [replace(item) for item in value]
            if type(value) is str:
                return (
                    replacements.get(value, value)
                    .replace(process_data.CONTAINER, request["container_id"])
                    .replace(process_data.BOOT, request["boot_id"])
                    .replace(
                        process_data.BOOT.replace("-", ""),
                        request["boot_id"].replace("-", ""),
                    )
                )
            return value

        identity, observer = replace(identity), replace(observer)
        identity["measured_joins"].update(
            runtime_profile_digest=binding["runtime_profile_digest"],
            declared_runtime_digest_not_whole_tree_measurement=binding[
                "runtime_digest"
            ],
            declared_input_digests_not_cas_readback={
                key: binding[key]
                for key in identity["measured_joins"][
                    "declared_input_digests_not_cas_readback"
                ]
            },
        )
        epochs = {
            role: {
                key: observer["processes"][role]["process"][key]
                for key in subject._EPOCH
            }
            for role in ("worker", "broker", "gateway")
        }
        broker_epoch = epochs["broker"] | {
            "boot_id": request["boot_id"],
            "mount_namespace": f"mnt:[{identity['processes']['broker']['mount_namespace']['inode']}]",
        }
        process_result = subject.processes.verify_native_common_process_observations(
            identity,
            deepcopy(identity),
            observer,
            deepcopy(observer),
            expected_container_id=request["container_id"],
            expected_file_digests=request["expected_file_digests"],
        )

        fixture = blocked_data.BlockedCreateData()
        self.addCleanup(fixture.close)
        joined, broker = fixture.joined, fixture.joined.broker
        broker.inputs, broker.evidence = CAS(private.root), self.fixture.store
        broker.plan.clear()
        broker.plan.update(binding)
        broker.grant.clear()
        broker.grant.update(json.loads(grant_raw))
        broker.path.clear()
        broker.path.update(json.loads(private.read(binding["path_digest"])))
        broker.request.update(
            {key: binding[key] for key in subject.broker._MATCH},
            policy_version=broker.grant["policy_version"],
        )
        profile = json.loads(native[subject.public.base.live._OBSERVATION])[
            "runtime_profile"
        ]
        broker.attribution.update(
            **epochs["worker"],
            profile_digest=binding["runtime_profile_digest"],
            runtime_digest=binding["runtime_digest"],
            active_skill_digest=binding["active_skill_digest"],
            executable_digest=profile["executable_digest"],
            skill_path=profile["skill_path"],
            cgroup=profile["cgroup"],
        )
        broker.process.clear()
        broker.process.update(broker_epoch)
        broker.profiled.update(
            sensor_digest=binding["sensor_digest"],
            runtime_peer={key: epochs["worker"][key] for key in ("pid", "uid", "gid")},
        )
        broker.profiled["measured_action"].update(
            {key: broker.request[key] for key in subject.broker._MEASURED}
        )
        lease = broker.state["claim"]["lease"]
        lease.update(
            {key: binding[key] for key in subject.broker._MATCH},
            grant_digest=binding["grant_digest"],
            runtime_profile_digest=binding["runtime_profile_digest"],
            sensor_digest=binding["sensor_digest"],
            policy_version=broker.grant["policy_version"],
            runtime_attribution_digest=canonical_digest(broker.attribution),
        )
        broker.state["grant_digest"] = binding["grant_digest"]
        broker.receipt["runtime_attribution_digest"] = canonical_digest(
            broker.attribution
        )
        broker.pending["runtime_attribution_digest"] = canonical_digest(
            broker.attribution
        )
        broker.decision.update(
            policy_digest=binding["policy_digest"],
            policy_version=broker.grant["policy_version"],
        )
        joined._rebuild_broker_request()
        joined.worker_binding = json.loads(native[subject._WORKER])
        joined._worker_epoch(epochs["worker"])
        for record in joined.records.values():
            record["worker_binding"] = deepcopy(joined.worker_binding)
            record["worker_binding_digest"] = canonical_digest(joined.worker_binding)
        fixture.gateway = {key: epochs["gateway"][key] for key in ("pid", "uid", "gid")}
        joined.records["ingress"]["body"]["gateway_peer"] = deepcopy(fixture.gateway)
        joined.records["action"]["body"]["action_request"] = deepcopy(broker.request)
        fixture.genesis = json.loads(native[subject._GENESIS])
        fixture.genesis_pin = canonical_digest(fixture.genesis)
        attempt_body = joined.records["attempt"]["body"]
        attempt_body["genesis_digest"] = fixture.genesis_pin
        attempt_body["attempt"].update(
            genesis_digest=fixture.genesis_pin, previous_digest=fixture.genesis_pin
        )
        attempt_body["receipt_state"]["genesis_digest"] = fixture.genesis_pin
        joined._rechain()

        fixture.source_result["broker_result"] = deepcopy(broker.result)
        callback = json.loads(fixture.driver["native_callback"]["result_json"])
        content = json.loads(callback["content"][0]["text"])
        content["result"] = deepcopy(fixture.source_result)
        callback["content"][0]["text"] = canonical_json(content).decode()
        callback["details"]["source_result"] = deepcopy(fixture.source_result)
        fixture.driver["native_callback"]["result_json"] = blocked_data._js(callback)
        result_bytes = fixture.driver["native_callback"]["result_json"].encode()
        projection = {
            "digest": subject.public._digest(result_bytes),
            "bytes": len(result_bytes),
        }
        fixture.driver["native_projection"]["result"] = projection
        fixture.driver["source_result"] = blocked_data._sized(fixture.source_result)
        fixture.driver["container_id"] = request["container_id"]
        fixture.driver["gateway"]["system_info"]["response"]["pid"] = fixture.gateway[
            "pid"
        ]
        terminal = deepcopy(fixture.receipt_after["receipts"][1])
        terminal.update(
            genesis_digest=fixture.genesis_pin,
            previous_digest=canonical_digest(attempt_body["attempt"]),
        )
        terminal["event"].update(
            attempt_digest=canonical_digest(attempt_body["attempt"]),
            result_digest=projection["digest"],
            result_bytes=projection["bytes"],
        )
        fixture.receipt_before = fixture._snapshot([])
        fixture.receipt_after = fixture._snapshot(
            [deepcopy(attempt_body["attempt"]), terminal]
        )
        fixture.accounts.update(
            broker_uid=broker.process["uid"], runtime_gid=joined.worker["gid"]
        )
        sink_source = self.fixture.bound["source_raws"][
            "src/aragorn/native_phase3_denied_create_sink.py"
        ]
        for sink in (fixture.sink_before, fixture.sink_after):
            sink.update(
                container_id=request["container_id"],
                observer_source_digest=plan["sink_source_digest"],
                path_descriptor=deepcopy(broker.path),
                accounts=deepcopy(fixture.accounts),
            )
            source = sink["observer_source"]
            source.update(bytes=len(sink_source), digest=plan["sink_source_digest"])
            source["identity"][6] = len(sink_source)
            for name, group in (
                ("protected", fixture.accounts["runtime_gid"]),
                ("staging", fixture.accounts["broker_gid"]),
            ):
                metadata = sink["directories"][name]["identity"]
                metadata[0:2] = [
                    broker.path["root_device"],
                    broker.path["root_inode"] + (name == "staging"),
                ]
                metadata[3:5] = [broker.process["uid"], group]
        for clock in (joined.before, joined.after):
            clock["boot_id"] = request["boot_id"]
            for role in ("worker", "broker"):
                clock["processes"][role].update(epochs[role])
        args = fixture.arguments() | {
            "expected_container_id": request["container_id"],
            "expected_sink_source_digest": plan["sink_source_digest"],
        }
        clock_raws = {
            name: canonical_json(value)
            for name, value in (("before", joined.before), ("after", joined.after))
        }
        interval_args = {
            key: value
            for key, value in args.items()
            if key
            in {
                "startup_raw",
                "ingress_raw",
                "attempt_raw",
                "action_raw",
                "expected_record_digests",
                "completion_raw",
                "expected_completion_digest",
                "expected_binding_raw",
                "expected_binding_digest",
                "expected_worker",
                "expected_broker_process",
                "expected_worker_binding_digest",
                "expected_genesis_digest",
                "input_cas",
                "evidence_cas",
            }
        }
        interval_args.update(
            **{f"clock_{name}_raw": raw for name, raw in clock_raws.items()},
            **{
                f"expected_clock_{name}_digest": subject.public._digest(raw)
                for name, raw in clock_raws.items()
            },
        )
        for raw in clock_raws.values():
            joined.retain(self.fixture.store, raw)
        verification = {
            "blocked_create": blocked.verify_native_blocked_create(**args),
            "ingress_interval": interval.verify_native_ingress_interval(
                **interval_args
            ),
        }

        capture = deepcopy(self.capture)
        report = capture["guest"]["attempt"]
        journal = report["public_blob_attempts"]

        def document(role, raw, *, replace_role=True):
            pin = joined.retain(self.fixture.store, raw)
            if replace_role:
                journal[:] = [row for row in journal if row["role"] != role]
            journal.append({"role": role, "digest": pin, "bytes": len(raw)})
            return {"digest": pin, "bytes": len(raw), "text": raw.decode()}

        for name, value in (
            ("identity_before", identity),
            ("identity_after", identity),
            ("process_before", observer),
            ("process_after", observer),
        ):
            document(name, canonical_json(value))
        for name, raw in clock_raws.items():
            document("clock_" + name, raw)
        work = json.loads(self.public_cas.read(report["workload"]["digest"]))
        measured = json.loads(self.public_cas.read(report["snapshot"]["digest"]))
        for name in (
            "driver",
            "receipt_before",
            "receipt_after",
            "sink_before",
            "sink_after",
        ):
            work["records"][name] = document("workload_" + name, args[name + "_raw"])
        for name in ("identity_before", "identity_after"):
            work["records"][name] = document(
                "workload_" + name, canonical_json(identity)
            )
        for name in ("startup", "ingress", "attempt", "action", "completion"):
            measured["records"][name] = document(
                "measurement_" + name, args[name + "_raw"]
            )
        measured["records"]["pending"] = document(
            "measurement_pending", canonical_json(broker.pending)
        )
        completion = json.loads(args["completion_raw"])
        evidence = json.loads(self.public_cas.read(completion["evidence_digest"]))
        pins = {
            "evidence": completion["evidence_digest"],
            **{
                name: evidence[name + "_digest"]
                for name in ("consumed_grant_state", "profile_receipt", "broker_result")
            },
            "profiled_submission": canonical_digest(broker.profiled),
        }
        journal[:] = [row for row in journal if row["role"] != "broker_blob"]
        measured["broker_blob_digests"] = pins
        measured["broker_blobs"] = {
            pin: document("broker_blob", self.public_cas.read(pin), replace_role=False)
            for pin in pins.values()
        }
        report["workload"]["digest"] = document("workload", canonical_json(work))[
            "digest"
        ]
        report["snapshot"]["digest"] = document(
            "measurement_snapshot", canonical_json(measured)
        )["digest"]
        report["verification"] = verification
        report["process_verification"] = process_result
        document("independent_verification", canonical_json(verification))
        report["public_blob_digests"] = sorted({row["digest"] for row in journal})
        rows = [
            {"digest": pin, "bytes": len(raw), "text": raw.decode()}
            for pin in report["public_blob_digests"]
            for raw in (self.public_cas.read(pin),)
        ]
        capture["guest"]["public_blobs"] = rows
        order = [row["digest"] for row in rows]
        capture["guest_publication"] = {
            "attempted": list(order),
            "retained": list(order),
            "failed": [],
            "complete": True,
        }
        raw = canonical_json(capture) + b"\n"
        pin = joined.retain(self.fixture.store, raw)
        with (
            patch.object(CAS, "put", side_effect=AssertionError("full replay wrote")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("full replay wrote")
            ),
            patch(
                "time.clock_gettime_ns",
                side_effect=AssertionError("full replay sampled clock"),
            ),
        ):
            result = subject.verify_native_common_measurement_capture(
                raw,
                expected_capture_digest=pin,
                public_cas=self.public_cas,
                private_input_cas=private,
                **{
                    key: args[key]
                    for key in (
                        "expected_worker",
                        "expected_broker_process",
                        "expected_gateway",
                        "expected_sink_accounts",
                    )
                },
            )
        self.assertEqual(
            result["status"], "RETAINED_NATIVE_MEASUREMENT_SEMANTICS_REPLAYED"
        )
        self.assertEqual(result["measurement"], verification)
        self.assertEqual(result["process_joins"], process_result)
        self.assertTrue(result["prepared_private_input_semantics_replayed"])
        self.assertTrue(result["bounded_measurement_consumers_replayed"])
        self.assertFalse(result["independent_full_measurement_replay_complete"])
        self.assertTrue(all(result[key] is False for key in subject.public.FALSE_FLAGS))
        self.assertNotIn(grant_raw.decode(), canonical_json(result).decode())


if __name__ == "__main__":
    unittest.main()
