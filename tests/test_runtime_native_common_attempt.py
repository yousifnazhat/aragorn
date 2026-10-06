"""Inert outer-controller tests, with no service, VM, workload or clock effects.

Orchestration positives use explicit effect doubles. One composition test uses
real pure consumers and existing inert data constructors, not historical tests.
"""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from scripts import runtime_native_common_attempt as subject
from tests import test_native_phase3_blocked_create_verify as blocked_data


CONTAINER = "c" * 64
PIN = "sha256:" + "a" * 64
BOOT = "11111111-1111-4111-8111-111111111111"
DESCRIPTOR = {
    "schema": "aragorn/runtime-protected-path/v1",
    "root_device": 7,
    "root_inode": 42,
    "target_name": "runtime-worker-qualified.txt",
}


def record(value):
    raw = canonical_json(value)
    return {
        "text": raw.decode(),
        "bytes": len(raw),
        "digest": subject.workload._digest(raw),
    }


class NativeCommonAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.evidence, self.plan_store = CAS(root / "evidence"), CAS(root / "plan")
        self.events = []
        self.sources = dict.fromkeys(subject.SOURCE_PATHS, PIN)
        self.common = {
            "case_id": "inert",
            "nonce": "d" * 64,
            "container_id": CONTAINER,
            "implementation_source_raws": {},
        }
        self.inputs = {
            name: b"PRIVATE_SEVEN_WRITER_INPUT" + str(index).encode()
            for index, name in enumerate(
                subject.setup.predecessor.writer_parent.DYNAMIC_PATHS
            )
        }
        self.expected = {
            role: {
                "pid": index + 10,
                "start_time_ticks": index + 100,
                "uid": index + 990,
                "gid": 997,
            }
            for index, role in enumerate(("worker", "broker", "gateway"))
        }
        self.broker = self.expected["broker"] | {
            "boot_id": BOOT,
            "mount_namespace": "mnt:[45]",
        }
        self.accounts = {
            "broker_uid": self.expected["broker"]["uid"],
            "broker_gid": 991,
            "runtime_gid": 997,
        }
        self.request = {
            "container_id": CONTAINER,
            "boot_id": BOOT,
            "measurement_binding_digest": PIN,
            "expected_file_digests": {
                subject.identity.prior._WORKER: PIN,
                subject.identity.prior._GENESIS: PIN,
                "/usr/lib/aragorn/aragorn/runtime_worker_ingress_measurement.py": PIN,
            },
        }
        self.binding = {"schema": "inert-binding"}
        self.built = {
            "report": {"status": "INERT_PLAN"},
            "request_raw": canonical_json(self.request),
            "scheduled_request": {"attempt_id": "selected"},
            "expected_binding_digest": PIN,
            "measurement_prepared_raw": canonical_json({"binding": self.binding}),
            "measurement_prepared_digest": PIN,
            "common_preparation_raw": b"{}",
            "common_preparation_digest": PIN,
            "collection_preparation_raw": b"{}",
            "collection_preparation_digest": PIN,
        }
        driver = {
            "worker_request": {"digest": PIN},
            "source_result": {"document": {"broker_result": {"request_digest": PIN}}},
        }
        self.work = {
            "status": "OBSERVED",
            "records": {
                "driver": record(driver),
                "receipt_before": record({"count": 0}),
                "receipt_after": record({"count": 2}),
                "sink_before": record({"phase": "BEFORE"}),
                "sink_after": record({"phase": "AFTER"}),
            },
        }
        blob = record({"evidence": "public"})
        self.measured = {
            "status": "SNAPSHOTTED",
            "records": {
                name: record({"stage": name})
                for name in (
                    "startup",
                    "ingress",
                    "attempt",
                    "action",
                    "pending",
                    "completion",
                )
            },
            "broker_blobs": {blob["digest"]: blob},
            "broker_blob_digests": {"evidence": blob["digest"]},
        }
        self.hook_failure = None
        self.builder_failure = None
        self.cleanup_error = None
        self.snapshot_error = None
        self.handoff_active = False

    def harness(self, stack):
        def replace(owner, name, **kwargs):
            return stack.enter_context(patch.object(owner, name, **kwargs))

        self.arguments = replace(
            subject, "_arguments", return_value=(self.common, {}, {"files": []})
        )
        self.environment = replace(
            subject.setup.predecessor,
            "_environment",
            side_effect=lambda *_: self.events.append("environment"),
        )
        self.network = replace(
            subject,
            "_network",
            side_effect=lambda: self.events.append("network") or {"entries": ["lo"]},
        )
        self.source_read = replace(
            subject,
            "_source_guard",
            side_effect=lambda *_: self.events.append("source") or {"fixed": PIN},
        )
        self.native = SimpleNamespace(
            _STARTUP_CODE={},
            _sources=Mock(return_value={"installed": PIN}),
            setup_prior=SimpleNamespace(_require_fixture=Mock()),
            response=SimpleNamespace(_identities=Mock()),
        )
        self.native_loader = replace(
            subject.setup.predecessor.package, "_native", return_value=self.native
        )
        replace(subject.setup, "_overrides", return_value={})
        replace(
            subject.setup,
            "_implementation_readback",
            return_value={"implementation": PIN},
        )
        self.unused = replace(
            subject.setup.measurement,
            "require_native_measurement_unused",
            side_effect=lambda: self.events.append("unused"),
        )
        self.ingress = replace(
            subject.setup,
            "_ingress_absent",
            side_effect=lambda: self.events.append("ingress-absent"),
        )
        self.absent = replace(
            subject.workload,
            "_absent",
            side_effect=lambda *_: self.events.append("absent"),
        )

        @contextmanager
        def ancestry(_):
            yield 99, lambda: None

        replace(subject.workload, "_ancestry", side_effect=ancestry)
        self.cas_guard = Mock(side_effect=lambda: self.events.append("cas-guard"))

        @contextmanager
        def stores():
            self.events.append("stores-enter")
            try:
                yield self.evidence, self.plan_store, self.cas_guard
            finally:
                self.events.append("stores-close")

        self.stores = replace(subject, "_stores", side_effect=stores)

        @contextmanager
        def descriptor(_):
            self.events.append("descriptor-enter")
            try:
                yield (
                    canonical_json(DESCRIPTOR),
                    lambda: self.events.append("descriptor-guard"),
                )
            finally:
                self.events.append("descriptor-close")

        replace(subject, "_protected_descriptor", side_effect=descriptor)
        replace(subject.setup.measurement, "_boot_id", return_value=BOOT)
        replace(
            subject.setup,
            "_writer_readback",
            side_effect=lambda _native, inputs: (
                self.events.append("writers")
                or {name: subject.workload._digest(raw) for name, raw in inputs.items()}
            ),
        )

        def build(**kwargs):
            self.events.append("build")
            self.assertEqual(kwargs["provisioning_inputs"], self.inputs)
            self.assertEqual(kwargs["expected_boot_id"], BOOT)
            self.assertEqual(
                kwargs["protected_descriptor_raw"], canonical_json(DESCRIPTOR)
            )
            self.assertEqual(kwargs["payload_raw"], subject._PAYLOAD)
            self.assertEqual(
                set(kwargs["source_pins"]), {"execute", "verify", "identity_reader"}
            )
            self.assertEqual(kwargs["public_blob_attempts"], [])
            # An unknown private fixture blob must never enter the public journal.
            private = b"PRIVATE_PLANNING_GRANT"
            self.private_pin = self.evidence.put(
                BytesIO(private), max_bytes=len(private)
            )
            raw = b'{"public":"plan"}'
            subject._retain(
                self.evidence,
                CAS(self.evidence.root, read_only=True),
                self.cas_guard,
                kwargs["public_blob_attempts"],
                "plan_report",
                raw,
            )
            if self.builder_failure is not None:
                raise self.builder_failure
            return deepcopy(self.built)

        self.build = replace(
            subject.planner, "prepare_native_common_attempt_plan", side_effect=build
        )
        self.handoff_guard = Mock(
            side_effect=lambda: self.events.append("handoff-guard")
        )

        @contextmanager
        def held(**kwargs):
            self.assertEqual(kwargs["provisioning_inputs"], self.inputs)
            self.events.append("handoff-enter")
            self.handoff_active = True
            session = SimpleNamespace(
                report={"status": "HELD"},
                report_raw=b'{"status":"HELD"}',
                request=deepcopy(self.request),
                request_raw=canonical_json(self.request),
                provisioning_raw=b'{"provisioning":"public"}',
                claim_raw=b'{"claim":"permanent"}',
                guard=self.handoff_guard,
            )
            try:
                yield session
            finally:
                self.assertIn("cleanup", self.events)
                self.events.append("handoff-close")
                self.handoff_active = False

        self.handoff = replace(
            subject.handoff, "hold_prepared_native_common_measurement", side_effect=held
        )

        def prepare(native, callback, *, state):
            self.events.append("prepare")
            state["pins_frozen_before_activation"] = True
            state["provisioning_file_digests"] = {
                name: subject.workload._digest(raw) for name, raw in self.inputs.items()
            }
            callback(dict(self.inputs), state)
            self.assertTrue(self.handoff_active)
            self.events.append("activate")
            state["activation_count"] += 1
            if self.hook_failure is not None:
                raise self.hook_failure
            return {"PRIVATE_SETUP_RAW_MUST_NOT_ESCAPE": True}, state

        self.prepare = replace(
            subject.setup.predecessor, "_prepare", side_effect=prepare
        )
        self.identity = replace(
            subject.identity,
            "read_native_common_identity",
            side_effect=lambda **_: (
                self.events.append("identity") or {"identity": "actual-double"}
            ),
        )
        self.process = replace(
            subject.observer,
            "observe_common_processes",
            side_effect=lambda **_: (
                self.events.append("process") or {"process": "independent-double"}
            ),
        )
        replace(
            subject,
            "_expectations",
            return_value=(self.expected, self.broker, self.accounts),
        )

        @contextmanager
        def live(*_):
            self.events.append("live-enter")
            try:
                yield lambda: self.events.append("live-guard")
            finally:
                self.events.append("live-close")

        replace(subject.workload, "_live_processes", side_effect=live)
        self.clock = replace(
            subject.clock,
            "observe_native_common_clock_domain",
            side_effect=lambda **_: (
                self.events.append("clock") or {"clock": "same-process-double"}
            ),
        )
        self.workload = replace(
            subject.workload,
            "run_native_blocked_create_workload",
            side_effect=lambda **_: (
                self.events.append("workload") or deepcopy(self.work)
            ),
        )

        def take_snapshot(**kwargs):
            self.events.append("snapshot")
            self.assertTrue(self.handoff_active)
            if self.snapshot_error is not None:
                raise self.snapshot_error
            return deepcopy(self.measured)

        self.snapshot = replace(
            subject.snapshot,
            "snapshot_native_measurement_evidence",
            side_effect=take_snapshot,
        )
        replace(
            subject.process_verify,
            "verify_native_common_process_observations",
            return_value={"processes": "joined"},
        )
        self.verify = replace(
            subject,
            "_verify",
            return_value={
                "blocked_create": {"qualified": False},
                "ingress_interval": {"metrics": False},
            },
        )

        def cleanup(_):
            self.events.append("cleanup")
            if "handoff-enter" in self.events:
                self.assertTrue(self.handoff_active)
            if self.cleanup_error is not None:
                raise self.cleanup_error
            return {"four": "inactive"}

        self.cleanup = replace(subject.setup, "_cleanup", side_effect=cleanup)

    def run_attempt(self):
        return subject.run_native_common_attempt(
            common_arguments=self.common,
            plan_arguments={},
            expected_setup_digest=PIN,
            expected_source_digests=self.sources,
        )

    def test_first_activation_holds_original_handoff_through_cleanup(self):
        with ExitStack() as stack:
            self.harness(stack)
            result = self.run_attempt()
            self.prepare.assert_called_once()
            self.build.assert_called_once()
            self.workload.assert_called_once()
            self.snapshot.assert_called_once()
            self.cleanup.assert_called_once()
        self.assertEqual(result["status"], "BOUNDED_NATIVE_ATTEMPT_VERIFIED")
        self.assertEqual(result["setup_state"]["activation_count"], 1)
        self.assertEqual(result["callback_count"], 1)
        self.assertEqual(self.events.count("clock"), 2)
        for left, right in (
            ("unused", "stores-enter"),
            ("build", "handoff-enter"),
            ("handoff-enter", "activate"),
            ("activate", "workload"),
            ("workload", "snapshot"),
            ("snapshot", "cleanup"),
            ("cleanup", "handoff-close"),
            ("handoff-close", "stores-close"),
        ):
            self.assertLess(self.events.index(left), self.events.index(right))
        self.assertNotIn(self.private_pin, result["public_blob_digests"])
        self.assertNotIn("PRIVATE_SETUP_RAW", str(result))
        self.assertNotIn("PRIVATE_SEVEN_WRITER", str(result))
        self.assertTrue(all(result[name] is False for name in subject.FALSE_FLAGS))
        for row in result["public_blob_attempts"]:
            raw = self.evidence.read(row["digest"])
            self.assertEqual(len(raw), row["bytes"])

    def test_initial_guards_refuse_without_setup_or_cleanup_mutation(self):
        for target in (
            "environment",
            "network",
            "source_read",
            "unused",
            "ingress",
            "absent",
        ):
            with self.subTest(target=target), ExitStack() as stack:
                self.harness(stack)
                getattr(self, target).side_effect = ValueError("PRIVATE_DIAGNOSTIC")
                result = self.run_attempt()
                self.prepare.assert_not_called()
                self.stores.assert_not_called()
                self.cleanup.assert_not_called()
                if target in ("environment", "network", "source_read"):
                    self.native_loader.assert_not_called()
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn("PRIVATE_DIAGNOSTIC", str(result))

    def test_plan_failure_keeps_known_public_candidates_and_cleans_once(self):
        with ExitStack() as stack:
            self.harness(stack)
            error = ValueError("private builder detail")
            error._native_common_attempt_plan = {"status": "REFUSED"}
            self.builder_failure = error
            result = self.run_attempt()
            self.workload.assert_not_called()
            self.handoff.assert_not_called()
            self.cleanup.assert_called_once()
        self.assertEqual(result["plan"], {"status": "REFUSED"})
        self.assertTrue(result["public_blob_digests"])
        self.assertNotIn(self.private_pin, result["public_blob_digests"])

    def test_activation_failure_closes_handoff_only_after_cleanup(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.hook_failure = ValueError("activation refused")
            result = self.run_attempt()
            self.workload.assert_not_called()
            self.cleanup.assert_called_once()
        self.assertEqual(result["status"], "REFUSED")
        self.assertLess(
            self.events.index("cleanup"), self.events.index("handoff-close")
        )

    def test_handoff_provisioning_failure_never_activates_and_cleans_once(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.handoff.side_effect = ValueError("provisioning refused")
            result = self.run_attempt()
            self.build.assert_called_once()
            self.handoff.assert_called_once()
            self.workload.assert_not_called()
            self.cleanup.assert_called_once()
        self.assertEqual(result["setup_state"]["activation_count"], 0)
        self.assertNotIn("activate", self.events)
        self.assertIn("stores-close", self.events)

    def test_second_preactivation_callback_is_refused_without_replanning(self):
        with ExitStack() as stack:
            self.harness(stack)

            def duplicate(_native, callback, *, state):
                state["pins_frozen_before_activation"] = True
                callback(dict(self.inputs), state)
                callback(dict(self.inputs), state)

            self.prepare.side_effect = duplicate
            result = self.run_attempt()
            self.build.assert_called_once()
            self.handoff.assert_called_once()
            self.workload.assert_not_called()
            self.cleanup.assert_called_once()
        self.assertEqual(result["callback_count"], 2)
        self.assertEqual(result["setup_state"]["activation_count"], 0)
        self.assertEqual(result["status"], "REFUSED")

    def test_workload_interrupt_retains_partial_then_clock_snapshot_and_cleanup(self):
        interruption = KeyboardInterrupt()
        interruption._native_blocked_create_workload = deepcopy(self.work)
        with ExitStack() as stack:
            self.harness(stack)
            self.workload.side_effect = interruption
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.run_attempt()
            self.snapshot.assert_called_once()
            self.cleanup.assert_called_once()
        self.assertIs(raised.exception, interruption)
        result = interruption._native_common_attempt
        self.assertEqual(self.events.count("clock"), 2)
        self.assertIsNotNone(result["workload"]["digest"])
        self.assertIn(
            "measurement_startup",
            {row["role"] for row in result["public_blob_attempts"]},
        )

    def test_snapshot_interrupt_and_report_put_failure_keep_child_records(self):
        interruption = KeyboardInterrupt()
        interruption._native_measurement_evidence_snapshot = deepcopy(self.measured)
        original = subject._retain

        def retain(*args):
            if args[4] == "measurement_snapshot":
                raise ValueError("whole report put refused")
            return original(*args)

        with ExitStack() as stack:
            self.harness(stack)
            self.snapshot_error = interruption
            stack.enter_context(patch.object(subject, "_retain", side_effect=retain))
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.run_attempt()
            self.cleanup.assert_called_once()
        self.assertIs(raised.exception, interruption)
        result = interruption._native_common_attempt
        self.assertIsNone(result["snapshot"]["digest"])
        roles = {row["role"] for row in result["public_blob_attempts"]}
        self.assertTrue(
            {"measurement_startup", "measurement_completion", "broker_blob"} <= roles
        )
        self.assertIn(
            "SNAPSHOT_REPORT_RETENTION_REFUSED", result["postcondition_failures"]
        )

    def test_missing_driver_pins_still_calls_snapshot_once(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.work["status"] = "REFUSED"
            self.work["records"].pop("driver")
            result = self.run_attempt()
            self.snapshot.assert_called_once()
            self.assertIsNone(
                self.snapshot.call_args.kwargs["expected_worker_request_digest"]
            )
            self.assertIsNone(
                self.snapshot.call_args.kwargs["expected_action_request_digest"]
            )
        self.assertEqual(result["status"], "REFUSED")

    def test_second_process_reader_failure_does_not_lose_common_after_read(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.process.side_effect = [
                {"process": "before"},
                ValueError("observer after"),
            ]
            result = self.run_attempt()
        self.assertEqual(result["status"], "REFUSED")
        self.assertIn(
            "identity_after", {row["role"] for row in result["public_blob_attempts"]}
        )
        self.assertIn(
            "INDEPENDENT_PROCESS_AFTER_REFUSED", result["postcondition_failures"]
        )

    def test_cleanup_failure_still_closes_all_contexts_without_retry(self):
        with ExitStack() as stack:
            self.harness(stack)
            self.cleanup_error = ValueError("cleanup failure")
            result = self.run_attempt()
            self.cleanup.assert_called_once()
        self.assertEqual(result["status"], "REFUSED")
        self.assertIn("handoff-close", self.events)
        self.assertIn("descriptor-close", self.events)
        self.assertIn("stores-close", self.events)

    def test_cleanup_time_blob_loss_refuses_after_reading_all_public_candidates(self):
        missing = self.measured["records"]["startup"]["digest"]
        after_cleanup_reads = []
        original_read = CAS.read
        with ExitStack() as stack:
            self.harness(stack)
            original_cleanup = self.cleanup.side_effect

            def cleanup(native):
                states = original_cleanup(native)
                path = self.evidence._sha_root / missing[7:9] / missing[9:]
                path.unlink()  # Only this test's temporary inert CAS fixture.
                return states

            def read(store, pin, **kwargs):
                if "cleanup" in self.events:
                    self.assertTrue(self.handoff_active)
                    self.assertNotIn("stores-close", self.events)
                    after_cleanup_reads.append(pin)
                return original_read(store, pin, **kwargs)

            self.cleanup.side_effect = cleanup
            stack.enter_context(patch.object(CAS, "read", new=read))
            result = self.run_attempt()
            self.cleanup.assert_called_once()
            self.workload.assert_called_once()
            self.snapshot.assert_called_once()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["public_readback_failures"], [missing])
        self.assertEqual(
            after_cleanup_reads,
            [row["digest"] for row in result["public_blob_attempts"]],
        )
        self.assertIn("handoff-close", self.events)
        self.assertIn("stores-close", self.events)

    def test_real_epoch_namespace_expectations_use_actual_readlink_and_stat(self):
        common = {
            "boot_id": BOOT.replace("-", ""),
            "processes": {
                role: {
                    "pid": pin["pid"],
                    "start_time_ticks": pin["start_time_ticks"],
                    "uids": [pin["uid"]] * 4,
                    "gids": [pin["gid"]] * 4,
                }
                for role, pin in self.expected.items()
            },
        }
        common["processes"]["broker"]["mount_namespace"] = {"device": 4, "inode": 45}
        observed = {
            "boot_id": BOOT.replace("-", ""),
            "processes": {
                role: {"process": pin} for role, pin in self.expected.items()
            },
        }
        metadata = SimpleNamespace(st_dev=4, st_ino=45)
        with (
            patch.object(subject.os, "open", return_value=10),
            patch.object(subject.os, "fstat", return_value=metadata),
            patch.object(subject.os, "stat", return_value=metadata),
            patch.object(subject.os, "readlink", return_value="mnt:[45]") as readlink,
            patch.object(subject.os, "close") as close,
            patch.object(
                subject.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=991)
            ),
        ):
            expected, broker, accounts = subject._expectations(common, observed, BOOT)
            self.assertEqual(expected, self.expected)
            self.assertEqual(broker, self.broker)
            self.assertEqual(accounts, self.accounts)
            readlink.assert_called_once_with(
                f"/proc/{self.expected['broker']['pid']}/ns/mnt"
            )
            close.assert_called_once_with(10)

    def test_network_inventory_is_bounded_and_loopback_only(self):
        @contextmanager
        def ancestry(path):
            self.assertEqual(path, "/sys/class/net")
            yield 10, lambda: None

        class Entries:
            def __init__(self, names):
                self.names, self.reads = iter(names), 0

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def __iter__(self):
                return self

            def __next__(self):
                self.reads += 1
                return SimpleNamespace(name=next(self.names))

        for names in (["lo"], [], ["eth0"], ["lo", "eth0", "PRIVATE_EXTRA"]):
            entries = Entries(names)
            with (
                self.subTest(names=names),
                patch.object(subject.workload, "_ancestry", side_effect=ancestry),
                patch.object(subject.os, "scandir", return_value=entries),
                patch.object(
                    subject.workload, "_directory", return_value=[1, 2, 3, 0, 0]
                ),
            ):
                if names == ["lo"]:
                    self.assertEqual(subject._network()["entries"], ["lo"])
                else:
                    with self.assertRaises(subject.NativeCommonAttemptError):
                        subject._network()
                self.assertEqual(entries.reads, 2)

    def test_real_pure_consumers_compose_retained_fixture_and_clock_pair(self):
        data = blocked_data.BlockedCreateData()
        self.addCleanup(data.close)
        args = data.arguments()
        joined, broker = data.joined, data.joined.broker
        # Copy only this test's inert input fixture to a single test CAS, matching
        # the production builder's already validated finite merged input closure.
        for path in broker.inputs._sha_root.glob("*/*"):
            raw = path.read_bytes()
            broker.evidence.put_expected(
                BytesIO(raw),
                expected_digest="sha256:" + path.parent.name + path.name,
                max_bytes=len(raw),
            )
        clocks = {}
        for name, value in (("before", joined.before), ("after", joined.after)):
            value["processes"]["broker"]["gid"] = broker.process["gid"]
            clocks[name] = canonical_json(value)
            broker.evidence.put(BytesIO(clocks[name]), max_bytes=len(clocks[name]))
        work = {
            "records": {
                name: record(json.loads(args[name + "_raw"]))
                for name in (
                    "driver",
                    "receipt_before",
                    "receipt_after",
                    "sink_before",
                    "sink_after",
                )
            }
        }
        measured = {
            "records": {
                name: record(json.loads(args[name + "_raw"]))
                for name in ("startup", "ingress", "attempt", "action", "completion")
            }
        }
        request = {
            "container_id": args["expected_container_id"],
            "measurement_binding_digest": args["expected_binding_digest"],
            "expected_file_digests": {
                subject.identity.prior._WORKER: args["expected_worker_binding_digest"],
                subject.identity.prior._GENESIS: args["expected_genesis_digest"],
            },
        }
        expected = {
            "worker": args["expected_worker"],
            "gateway": args["expected_gateway"],
        }
        sources = {
            subject.workload.SINK_SOURCE_PATH: args["expected_sink_source_digest"]
        }
        with (
            patch.object(CAS, "put", side_effect=AssertionError("consumer wrote")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("consumer wrote")
            ),
        ):
            result = subject._verify(
                work,
                measured,
                clocks,
                expected,
                args["expected_broker_process"],
                args["expected_sink_accounts"],
                request,
                args["expected_binding_raw"],
                sources,
                CAS(broker.evidence.root, read_only=True),
            )
        self.assertEqual(
            result["blocked_create"]["status"],
            "RETAINED_BLOCKED_CREATE_WORKLOAD_JOINS_VERIFIED",
        )
        self.assertFalse(
            result["blocked_create"]["decision"]["blocked_pre_effect_verified"]
        )
        self.assertIn("ingress_interval", result)


if __name__ == "__main__":
    unittest.main()
