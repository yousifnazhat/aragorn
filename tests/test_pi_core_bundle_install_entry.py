"""New managed materialization composition only, not installed/live evidence."""

import copy
import fcntl
import hashlib
from io import BytesIO
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_bundle_install_entry as subject
from aragorn import pi_core_bundle_launch as bundle
from aragorn import runtime_active_skill_lineage_v2 as lineage_v2
from aragorn.acquire import ingest_local
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.runtime_process_profile import runtime_process_profile
from tests.pi_core_policy_fixtures import policy_documents, store_policy_manifest


def pin(char="a"):
    return "sha256:" + char * 64


def fixture():
    documents = {}
    def ref(name, value):
        path = "/var/lib/pi/prepared/" + name + ".json"
        documents[path] = value
        return {"path": path, "digest": canonical_digest(value)}
    _, policy = policy_documents()
    context = {"operation": "install", "policy_digest": policy["admission_policy_digest"],
        "destination": {"root_device": 1, "root_inode": 2, "target_name": "pi"}}
    deployment = {name: pin() for name in subject._DEPLOYMENT_FIELDS}
    deployment.update(policy=canonical_digest(policy), runtime_commit_or_image=pin("5"))
    plan = dict(schema=subject.SCHEMA, host_profile_digest=pin("c"),
        context=ref("context", context), candidate_cas_root="/var/lib/pi/candidate",
        predecessor_cas_root=None, deployment=ref("deployment", deployment),
        launch=ref("launch", {"provider_route_digest": None}), runtime_conformance_digest=pin("6"),
        revocations=ref("revocations", {"schema": "aragorn/protected-install-revocations/v1", "context_ids": []}))
    return plan, documents


class InstallEntryTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.documents = fixture()
        for name in ("os.open", "os.system", "subprocess.run", "subprocess.Popen", "socket.socket",
                     "socket.socketpair", "socket.create_connection"):
            self.enterContext(mock.patch(name, side_effect=AssertionError("no live operations")))
        self.enterContext(mock.patch.object(subject.os, "geteuid", return_value=0))
        self.enterContext(mock.patch.object(subject.os, "getegid", return_value=0))
        self.enterContext(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.enterContext(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))
        self.enterContext(mock.patch.object(subject.time, "time", return_value=1000.75))
        self.source, self.host = object(), object()
        self.custody = self.enterContext(mock.patch.object(subject, "_custody",
            return_value=(pin("c"), [{"module": "retained"}], {"host": "retained"})))
        self.inputs = mock.Mock(cleanup_uncertainty=[])
        self.inputs.read.side_effect = lambda path, expected, maximum: copy.deepcopy(self.plan)
        def read_ref(value):
            document = self.documents[value["path"]]
            subject.coordinator._require(canonical_digest(document) == value["digest"], "changed pinned input")
            return copy.deepcopy(document)
        self.inputs.ref.side_effect = read_ref
        self.enterContext(mock.patch.object(subject.coordinator, "_Inputs", return_value=self.inputs))
        policy_rows, _ = policy_documents()
        def read_policy(digest, *, max_bytes):
            if digest not in policy_rows:
                raise CASError("unretained fixture input")
            raw = canonical_json(policy_rows[digest])
            self.assertLessEqual(len(raw), max_bytes)
            return raw
        self.cas = self.enterContext(mock.patch.object(subject, "CAS", return_value=mock.Mock()))
        self.cas.return_value.read.side_effect = read_policy
        self.launch = self.enterContext(mock.patch.object(subject.coordinator, "_launch", return_value=object()))
        self.views = self.enterContext(mock.patch.object(subject, "_installed_views", return_value=((51, 52), pin("5"))))
        self.readonly = self.enterContext(mock.patch.object(subject.inventory, "_directory"))
        self.destination = mock.Mock(fd=42, cleanup_uncertainty=[])
        self.destination_type = self.enterContext(mock.patch.object(subject, "_Destination", return_value=self.destination))
        self.verify = self.enterContext(mock.patch.object(subject, "verify_protected_install_context_v2",
            return_value=SimpleNamespace(manifest_digest=pin("7"), target_name="pi")))
        self.bounds = self.enterContext(mock.patch.object(subject, "_supported_bundle"))
        self.transaction = {"schema": "aragorn/protected-install-transaction/v1", "context_digest": self.plan["context"]["digest"]}
        self.publish = self.enterContext(mock.patch.object(subject.publisher, "_publish_protected_install_transaction",
            return_value=self.transaction))
        self.readback = self.enterContext(mock.patch.object(subject, "_readback", return_value=pin("b")))

    def invoke(self):
        return subject.run(Path("/var/lib/pi/plan.json"), canonical_digest(self.plan),
            deadline_ns=125_000_000_000, source_loader=self.source, host_custody=self.host)

    def refuse(self, attempted=False):
        with self.assertRaises(subject.PiBundleInstallEntryError) as raised:
            self.invoke()
        self.assertEqual(raised.exception.observation["installation_attempted"], attempted)
        if not attempted:
            self.publish.assert_not_called()
        return raised.exception.observation

    def test_install_calls_existing_publisher_once_with_measured_runtime_and_no_new_authority(self):
        result = self.invoke()
        self.publish.assert_called_once()
        args = self.publish.call_args
        self.assertEqual(args.args[2], 42)
        self.assertEqual(args.kwargs["measured_target_runtime_digest"], pin("5"))
        self.assertEqual(args.kwargs["expected_context_digest"], self.plan["context"]["digest"])
        self.assertEqual(args.kwargs["expected_runtime_conformance_digest"], pin("6"))
        self.assertIsNone(args.kwargs["expected_active_cas"])
        self.cas.assert_called_once_with(Path(self.plan["candidate_cas_root"]), read_only=True)
        self.assertEqual(result["status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")
        self.assertEqual(result["publication_state"], "PUBLISHER_RETURNED")
        self.assertEqual(result["observed_tree_digest"], pin("b"))
        self.assertIs(self.readback.call_args.args[2], self.cas.return_value)
        self.assertIs(self.readback.call_args.args[3], self.verify.return_value)
        self.assertFalse(result["managed_call_attempted"])
        self.assertIsNone(result["managed_result"])
        self.assertFalse(result["phase3_exit_eligible"])
        self.assertTrue(result["owned_inputs_closed"] and result["owned_destination_closed"])
        self.assertIsNot(result["transaction"], self.transaction)

    def test_update_requires_and_passes_readonly_predecessor_cas(self):
        context = self.documents[self.plan["context"]["path"]]
        context["operation"] = "update"
        self.plan["context"]["digest"] = canonical_digest(context)
        self.plan["predecessor_cas_root"] = "/var/lib/pi/predecessor"
        self.invoke()
        self.assertEqual(self.cas.call_args_list, [mock.call(Path("/var/lib/pi/candidate"), read_only=True),
            mock.call(Path("/var/lib/pi/predecessor"), read_only=True)])
        self.assertIs(self.publish.call_args.kwargs["expected_active_cas"], self.cas.return_value)

    def test_update_without_predecessor_refuses(self):
        context = self.documents[self.plan["context"]["path"]]
        context["operation"] = "update"
        self.plan["context"]["digest"] = canonical_digest(context)
        self.refuse()

    def test_install_with_predecessor_refuses(self):
        self.plan["predecessor_cas_root"] = "/var/lib/pi/predecessor"
        self.refuse()

    def test_rollback_refuses_before_mutation(self):
        context = self.documents[self.plan["context"]["path"]]
        context["operation"] = "rollback"
        self.plan["context"]["digest"] = canonical_digest(context)
        self.refuse()

    def test_extra_plan_command_refuses(self):
        self.plan["command"] = "not executed"
        self.refuse()

    def test_host_profile_mismatch_refuses(self):
        self.plan["host_profile_digest"] = pin("d")
        self.refuse()

    def test_missing_deployment_dimension_refuses(self):
        document = self.documents[self.plan["deployment"]["path"]]
        del document["adapter"]
        self.plan["deployment"]["digest"] = canonical_digest(document)
        self.refuse()

    def test_policy_mismatch_refuses(self):
        document = self.documents[self.plan["context"]["path"]]
        document["policy_digest"] = pin("b")
        self.plan["context"]["digest"] = canonical_digest(document)
        self.refuse()

    def test_replaced_reference_bytes_refuse(self):
        self.documents[self.plan["revocations"]["path"]]["context_ids"].append(pin())
        self.refuse()

    def test_revocation_inventory_duplicate_refuses(self):
        document = self.documents[self.plan["revocations"]["path"]]
        document["context_ids"] = [pin(), pin()]
        self.plan["revocations"]["digest"] = canonical_digest(document)
        self.refuse()

    def test_cas_inside_mutating_destination_refuses(self):
        self.plan["candidate_cas_root"] = "/var/lib/aragorn/admitted/cas"
        self.refuse()

    def test_changed_actual_runtime_or_os_refuses(self):
        self.views.side_effect = RuntimeError("actual installed bytes differ")
        self.refuse()

    def test_context_verification_refusal_precedes_publisher(self):
        self.verify.side_effect = ValueError("expired or revoked or non-ALLOW")
        self.refuse()

    def test_unsupported_pi_layout_refuses_before_publisher(self):
        self.bounds.side_effect = ValueError("unsupported script")
        self.refuse()

    def test_busy_root_refuses_without_wait_or_publish(self):
        self.destination.acquire.side_effect = BlockingIOError("active holder")
        result = self.refuse()
        self.destination.acquire.assert_called_once()
        self.assertTrue(result["owned_destination_closed"])

    def test_claim_callback_refreshes_time_without_adopting_new_revocations(self):
        def publish(*args, **kwargs):
            self.assertEqual(kwargs["claim_state_provider"](), (1000, ()))
            return self.transaction
        self.publish.side_effect = publish
        self.invoke()
        self.assertGreaterEqual(self.inputs.guard.call_count, 4)
        self.assertGreaterEqual(self.custody.call_count, 6)

    def test_claim_changed_pin_stays_hold_without_second_effect(self):
        def publish(*args, **kwargs):
            self.documents[self.plan["revocations"]["path"]]["context_ids"].append(pin())
            kwargs["claim_state_provider"]()
        self.publish.side_effect = publish
        result = self.refuse(True)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["publication_state"], "UNKNOWN")
        self.publish.assert_called_once()

    def test_actual_recovery_record_retained_privately(self):
        recovery = {"context_consumed": True, "owned_version": "private"}
        self.publish.side_effect = subject.publisher.ProtectedInstallTransactionError("held", recovery=recovery)
        result = self.refuse(True)
        self.assertEqual(result["recovery"], recovery)
        self.assertIsNot(result["recovery"], recovery)
        self.assertEqual(result["publication_state"], "RECOVERY_RECORD_RETAINED")
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_interrupt_without_recovery_is_unknown_hold(self):
        self.publish.side_effect = KeyboardInterrupt()
        result = self.refuse(True)
        self.assertIsNone(result["recovery"])
        self.assertEqual(result["publication_state"], "UNKNOWN")
        self.assertEqual(result["status"], "CLEANUP_HOLD")

    def test_unserializable_recovery_preserves_original_failure_and_unknown_state(self):
        failure = subject.publisher.ProtectedInstallTransactionError("original failure", recovery={"value": object()})
        self.publish.side_effect = failure
        with self.assertRaises(subject.PiBundleInstallEntryError) as raised:
            self.invoke()
        self.assertIs(raised.exception.__cause__, failure)
        self.assertEqual(raised.exception.observation["publication_state"], "UNKNOWN")
        self.assertEqual(raised.exception.observation["status"], "CLEANUP_HOLD")
        self.assertIsNone(raised.exception.observation["recovery"])

    def test_reacquire_or_active_readback_failure_preserves_transaction(self):
        self.readback.side_effect = BlockingIOError("new owner")
        result = self.refuse(True)
        self.assertEqual(result["transaction"], self.transaction)
        self.assertEqual(result["status"], "CLEANUP_HOLD")
        self.assertEqual(result["publication_state"], "PUBLISHER_RETURNED")
        self.assertIsNone(result["observed_tree_digest"])
        self.readback.assert_called_once()

    def test_post_return_readonly_loss_stays_hold(self):
        def publish(*args, **kwargs):
            self.readonly.side_effect = RuntimeError("readonly mount lost")
            return self.transaction
        self.publish.side_effect = publish
        self.assertEqual(self.refuse(True)["status"], "CLEANUP_HOLD")

    def test_destination_close_failure_never_reports_success_or_retries(self):
        self.destination.close.side_effect = OSError("close outcome uncertain")
        self.destination.cleanup_uncertainty = [{"scope": "DESTINATION_CLOSE", "descriptors": [42]}]
        result = self.refuse(True)
        self.assertEqual(result["failure_stage"], "DESTINATION_CLEANUP")
        self.assertFalse(result["owned_destination_closed"])
        self.destination.close.assert_called_once()

    def test_input_close_failure_preserves_publication(self):
        self.inputs.close.side_effect = OSError("input close uncertain")
        result = self.refuse(True)
        self.assertEqual(result["failure_stage"], "INPUT_CLEANUP")
        self.assertEqual(result["transaction"], self.transaction)
        self.assertFalse(result["owned_inputs_closed"])

    def test_no_publisher_after_source_custody_loss(self):
        self.custody.side_effect = RuntimeError("verified source changed")
        self.refuse()


class InstallBoundsTests(unittest.TestCase):
    def setUp(self):
        self.files = [{"path": "SKILL.md", "size": 4, "digest": pin(), "executable": False}]
        self.loader = self.enterContext(mock.patch.object(subject, "load_verified_retained_manifest",
            return_value={"files": self.files}))
        self.cas = mock.Mock()
        self.cas.read.return_value = b"safe"

    def check(self):
        subject._supported_bundle(self.cas, pin("b"))

    def test_supported_nonexecutable_skill_and_one_directory(self):
        self.files.append({"path": "references/file.txt", "size": 10, "digest": pin("c"), "executable": False})
        self.check()
        self.cas.read.assert_called_once_with(pin(), max_bytes=32 * 1024)

    def test_executable_member_refused(self):
        self.files[0]["executable"] = True
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.check()

    def test_deep_or_multiple_support_directories_refused(self):
        for paths in (("one/two/file",), ("one/a", "two/b")):
            with self.subTest(paths=paths):
                self.loader.return_value = {"files": self.files + [dict(self.files[0], path=path) for path in paths]}
                with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
                    self.check()

    def test_count_or_byte_bound_refused(self):
        for rows in ([dict(self.files[0], path=str(i)) for i in range(65)],
                     [dict(self.files[0], size=1024 * 1024 + 1)]):
            self.loader.return_value = {"files": rows}
            with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
                self.check()

    def test_missing_empty_or_oversized_skill_refused(self):
        for row in (dict(self.files[0], path="other"), dict(self.files[0], size=0), dict(self.files[0], size=32769)):
            self.loader.return_value = {"files": [row]}
            with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
                self.check()

    def test_non_utf8_skill_refused(self):
        self.cas.read.return_value = b"\xffbad"
        with self.assertRaises(UnicodeDecodeError):
            self.check()


class InstalledMeasurementTests(unittest.TestCase):
    def setUp(self):
        self.inputs = mock.Mock()
        self.inputs.directories = [(None, [31], None)]
        self.config = SimpleNamespace(root_directory=Path("/var/lib/pi/os"), runtime_directory=Path("/var/lib/pi/runtime"),
            activation_directory=Path("/var/lib/pi/activations"), root_closure_digest=pin("1"),
            compiled_receipt={"receipt": "pinned"}, compiled_receipt_digest=pin("2"), source_observation=None)
        self.deployment = {"os_profile": pin("1"), "runtime_commit_or_image": pin("3"), "configuration": pin("4")}
        self.manifest = {"files": [{"path": "usr/bin/env", "executable": True}]}
        self.tree = self.enterContext(mock.patch.object(subject.launch, "_tree", return_value=(self.manifest, (), pin("1"))))
        self.runtime = self.enterContext(mock.patch.object(subject.launch, "_runtime_inventory", return_value=pin("3")))
        self.empty = self.enterContext(mock.patch.object(subject.launch, "_require_empty_mountpoints"))
        self.config_digest = self.enterContext(mock.patch.object(subject.launch, "confined_configuration_digest", return_value=pin("4")))
        self.readonly = self.enterContext(mock.patch.object(subject.inventory, "_directory"))

    def check(self):
        return subject._installed_views(self.inputs, self.config, self.deployment)

    def test_actual_held_trees_feed_compiled_inventory_and_deployment_joins(self):
        roots, digest = self.check()
        self.assertEqual(roots, (31, 31))
        self.assertEqual(digest, pin("3"))
        self.runtime.assert_called_once_with(self.manifest, self.config.compiled_receipt, pin("2"))
        self.assertEqual(self.tree.call_count, 2)
        self.assertEqual(self.readonly.call_count, 4)

    def test_runtime_configuration_or_os_mismatch_refuses(self):
        for key in self.deployment:
            with self.subTest(key=key):
                changed = dict(self.deployment, **{key: pin("f")})
                with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
                    subject._installed_views(self.inputs, self.config, changed)

    def test_overlapping_runtime_or_admitted_root_refuses_before_measurement(self):
        self.config.runtime_directory = subject._DESTINATION / "runtime"
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.check()
        self.tree.assert_not_called()

    def test_missing_actual_readonly_view_refuses(self):
        self.readonly.side_effect = RuntimeError("writable actual mount")
        with self.assertRaises(RuntimeError):
            self.check()
        self.tree.assert_not_called()

    def test_source_observation_requires_pinned_gate_artifact(self):
        self.config.source_observation = {"configured": True}
        with mock.patch.object(subject.launch, "_source_gate_artifact", side_effect=RuntimeError("gate differs")) as gate:
            with self.assertRaises(RuntimeError):
                self.check()
        gate.assert_called_once()

    def test_os_credential_free_entrypoint_is_required(self):
        self.manifest["files"].clear()
        with self.assertRaisesRegex(subject.coordinator.PiCoordinatorEntryError, "OS_ENTRYPOINT"):
            self.check()
        self.runtime.assert_not_called()

    def test_source_gate_and_node_pins_join_actual_runtime_inventory(self):
        self.config.source_observation = {"pins": {"gate_digest": pin("a"), "node_digest": pin("b")}}
        self.manifest["files"].append({"path": "node/bin/node", "digest": pin("b")})
        with mock.patch.object(subject.launch, "_source_gate_artifact", return_value={"digest": pin("a")}):
            self.check()
        with mock.patch.object(subject.launch, "_source_gate_artifact", return_value={"digest": pin("f")}):
            with self.assertRaisesRegex(subject.coordinator.PiCoordinatorEntryError, "SOURCE_GATE_BINDING"):
                self.check()


class DestinationCustodyTests(unittest.TestCase):
    def setUp(self):
        self.inputs = mock.Mock()
        self.inputs.directories = [(None, [11], None)]
        self.state = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0,
            st_nlink=2, st_dev=3, st_ino=4)
        self.enterContext(mock.patch.object(subject.os, "open", return_value=12))
        self.enterContext(mock.patch.object(subject.os, "fstat", return_value=self.state))
        self.named = self.enterContext(mock.patch.object(subject.os, "stat", return_value=self.state))
        self.enterContext(mock.patch.object(subject.os, "get_inheritable", return_value=False))
        self.close = self.enterContext(mock.patch.object(subject.os, "close"))
        self.lock = self.enterContext(mock.patch.object(subject.fcntl, "flock"))
        self.holder = subject._Destination(self.inputs, {"root_device": 3, "root_inode": 4, "target_name": "pi"})

    def test_parent_held_and_only_nonblocking_lock_used(self):
        self.holder.acquire()
        self.inputs.hold_directory.assert_called_once_with(subject._DESTINATION.parent)
        self.lock.assert_called_once_with(12, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.holder.close()
        self.close.assert_called_once_with(12)

    def test_named_root_substitution_refused(self):
        self.named.return_value = SimpleNamespace(**{**vars(self.state), "st_ino": 999})
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.holder.acquire()
        self.lock.assert_not_called()
        self.holder.close()

    def test_busy_lock_has_one_attempt_and_preserves_owned_close(self):
        self.lock.side_effect = BlockingIOError()
        with self.assertRaises(BlockingIOError):
            self.holder.acquire()
        self.lock.assert_called_once()
        self.holder.close()

    def test_mutable_root_size_and_time_are_not_false_identity_pins(self):
        self.holder.acquire()
        self.state.st_size, self.state.st_mtime_ns = 900, 999
        self.holder.guard()
        self.holder.close()

    def test_close_failure_keeps_uncertainty_without_retry(self):
        self.holder.acquire()
        self.close.side_effect = OSError("ambiguous")
        with self.assertRaises(OSError):
            self.holder.close()
        self.assertEqual(self.holder.cleanup_uncertainty, [{"scope": "DESTINATION_CLOSE", "descriptors": [12]}])
        with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
            self.holder.close()
        self.close.assert_called_once()


class SourceCustodyTests(unittest.TestCase):
    def test_install_entry_consumption_is_required_in_addition_to_base_caller(self):
        source = SimpleNamespace(source_digests={subject._SOURCE_PATH: pin()})
        row = {"module": subject.__name__, "path": subject._SOURCE_PATH, "digest": pin()}
        with mock.patch.object(subject.coordinator, "_custody", return_value=(pin("c"), [row], {})):
            self.assertEqual(subject._custody(source, object(), 1)[0], pin("c"))
        with mock.patch.object(subject.coordinator, "_custody", return_value=(pin("c"), [], {})):
            with self.assertRaises(subject.coordinator.PiCoordinatorEntryError):
                subject._custody(source, object(), 1)


class ExistingPublisherConsumerTests(unittest.TestCase):
    """Real temporary CAS/publisher/immutable consumer; no worker is launched.

    The independently retained analyzer decision and installed host/view
    custody are inert dependencies. Root ownership is mapped to the fixture's
    current user only in these tests. This is not an admission qualification.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home().resolve(), prefix="aragorn-managed-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.cas = CAS(self.root / "cas")
        self.protected = self.root / "protected"
        self.protected.mkdir(mode=0o700)
        self.uid = os.geteuid()
        self.plan, self.documents = fixture()
        self.plan["candidate_cas_root"] = str(self.root / "cas")
        self.plan["runtime_conformance_digest"] = pin("8")
        self.deployment = self.documents[self.plan["deployment"]["path"]]
        self.policy = store_policy_manifest(self.cas)
        self.deployment.update(runtime_commit_or_image=pin("7"), policy=canonical_digest(self.policy))
        self.plan["deployment"]["digest"] = canonical_digest(self.deployment)
        self.enterContext(mock.patch.object(subject, "_DESTINATION", self.protected))
        self.enterContext(mock.patch.object(subject, "_custody", return_value=(pin("c"), [], {})))
        self.enterContext(mock.patch.object(subject.coordinator, "_launch", return_value=object()))
        self.enterContext(mock.patch.object(subject, "_installed_views", return_value=((), pin("7"))))
        original_require = subject.coordinator._require
        def fixture_root_only(value, reason):
            if reason != "BUNDLE_INSTALL_ROOT_REQUIRED":
                return original_require(value, reason)
        self.enterContext(mock.patch.object(subject.coordinator, "_require", side_effect=fixture_root_only))
        self.enterContext(mock.patch.object(subject.time, "time", return_value=1000.0))
        self.enterContext(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.enterContext(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))
        for name in ("socket.socket", "socket.socketpair", "socket.create_connection", "subprocess.run",
                     "subprocess.Popen", "os.execve", "os.system"):
            self.enterContext(mock.patch(name, side_effect=AssertionError("no process or network operation")))
        owner = self
        class HeldFixtureInputs:
            def __init__(self, deadline):
                self.directories, self.cleanup_uncertainty = [], []
            def read(self, path, expected, maximum):
                owner.assertEqual(expected, canonical_digest(owner.plan))
                return copy.deepcopy(owner.plan)
            def ref(self, reference):
                document = owner.documents[reference["path"]]
                owner.assertEqual(canonical_digest(document), reference["digest"])
                return copy.deepcopy(document)
            def hold_directory(self, path):
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                self.directories.append((path, [fd], None))
            def guard(self):
                pass
            def close(self):
                for _, descriptors, _ in self.directories:
                    os.close(descriptors[0])
                self.directories.clear()
        self.enterContext(mock.patch.object(subject.coordinator, "_Inputs", HeldFixtureInputs))
        def mapped_root(holder):
            self.assertFalse(holder.closed)
            held = os.fstat(holder.fd)
            named = os.stat(self.protected, follow_symlinks=False)
            self.assertEqual((held.st_dev, held.st_ino), holder.expected)
            self.assertEqual((named.st_dev, named.st_ino), holder.expected)
            self.assertEqual(held.st_uid, self.uid)
            self.assertEqual(stat.S_IMODE(held.st_mode), 0o700)
        self.enterContext(mock.patch.object(subject._Destination, "guard", mapped_root))
        self.decision = self.enterContext(mock.patch("aragorn.protected_install_context.verify_decision_v3",
            side_effect=lambda cas, digest, **kwargs: {"verdict": "ALLOW", "manifest_digest": kwargs["expected_manifest_digest"]}))
        original_read = subject.lineage._read_owned_bytes_at
        def owned_read(*args, **kwargs):
            kwargs["expected_uid"] = self.uid
            return original_read(*args, **kwargs)
        self.enterContext(mock.patch.object(subject.lineage, "_read_owned_bytes_at", side_effect=owned_read))
        self.enterContext(mock.patch.object(bundle, "_root"))
        original_open, original_directory = subject.lineage._open_protected_root, subject.lineage._open_directory_at
        self.enterContext(mock.patch.object(subject.lineage, "_open_protected_root",
            side_effect=lambda path, uid: original_open(path, self.uid)))
        self.enterContext(mock.patch.object(subject.lineage, "_open_directory_at",
            side_effect=lambda fd, name, uid, mode, label: original_directory(fd, name, self.uid, mode, label)))
        original_member = bundle._read_owned_bytes_at
        def member(*args, **kwargs):
            kwargs["expected_uid"] = self.uid
            return original_member(*args, **kwargs)
        self.enterContext(mock.patch.object(bundle, "_read_owned_bytes_at", side_effect=member))
        original_hold = lineage_v2.hold_runtime_active_skill_lineage
        def hold(*args, **kwargs):
            kwargs["expected_install_uid"] = self.uid
            return original_hold(*args, **kwargs)
        self.enterContext(mock.patch.object(bundle, "hold_runtime_active_skill_lineage", side_effect=hold))
        self.context = self.candidate("a", b"# Admitted first capability\n")

    def candidate(self, character, content, previous=None):
        source = self.root / ("source-" + character)
        source.mkdir()
        (source / "SKILL.md").write_bytes(content)
        manifest = ingest_local(source, self.cas)
        raw = canonical_json(manifest)
        manifest_digest = self.cas.put(BytesIO(raw), max_bytes=len(raw))
        state = self.protected.stat()
        context = {"schema": "aragorn/protected-install-context/v2",
            "authority": "BROKER_CONTEXT_ONLY_NOT_INSTALLER_AUTHORITY", "context_id": pin(character),
            "status": "active", "expires_at_unix": 1200, "operation": "update" if previous else "install",
            "expected_active": {"context_id": previous["context_id"], "manifest_digest": previous["manifest_digest"]} if previous else None,
            "decision_digest": pin("2"), "manifest_digest": manifest_digest, "artifact_graph_digest": pin("3"),
            "policy_digest": self.policy["admission_policy_digest"], "analyzer_run_receipt_digests": [pin("4")], "analyzer_verifier_digest": pin("5"),
            "artifact_graph_verifier_digest": pin("6"), "target_runtime_digest": pin("7"), "runtime_conformance_digest": pin("8"),
            "destination": {"root_device": state.st_dev, "root_inode": state.st_ino, "target_name": "pi"}}
        self.documents[self.plan["context"]["path"]] = context
        self.plan["context"]["digest"] = canonical_digest(context)
        self.plan["predecessor_cas_root"] = str(self.root / "cas") if previous else None
        return context

    def install(self):
        return subject.run(Path("/var/lib/pi/plan.json"), canonical_digest(self.plan), deadline_ns=125_000_000_000,
                           source_loader=object(), host_custody=object())

    def prepare(self, context, content):
        version = self.protected / ".aragorn-versions/pi" / (context["context_id"][7:] + "-" + context["manifest_digest"][7:])
        profile = runtime_process_profile({"schema": "aragorn/runtime-single-skill-process-profile/v1",
            "authority": "ROOT_PROFILE_PIN_ONLY_NOT_SEMANTIC_CAUSATION_AUTHORITY", "runtime_digest": pin("7"),
            "executable_digest": pin("9"), "cgroup": "/aragorn/pi-fixture", "skill_path": str(version / "SKILL.md")})
        # This test-only input represents separately supplied existing start
        # authority; the install entry never returns or issues a grant.
        grant = {"active_skill_digest": "sha256:" + hashlib.sha256(content).hexdigest(),
            "install_context_digest": canonical_digest(context), "source_manifest_digest": context["manifest_digest"],
            "policy_digest": self.policy["runtime_action_policy_digest"]}
        return bundle.hold_prepared_pi_bundle(CAS(self.root / "cas", read_only=True), context,
            profile=profile, grant=grant, protected_root=self.protected, runtime_conformance_digest=pin("8"),
            deployment=self.deployment, revoked_context_ids=(), now_unix=1000, deadline=125.0)

    def test_existing_publisher_installs_exact_bytes_and_existing_pi_consumer_reads_them(self):
        result = self.install()
        self.assertEqual(result["status"], "INSTALLED_NOT_ACTIVATED_OR_QUALIFIED")
        with self.prepare(self.context, b"# Admitted first capability\n") as prepared:
            self.assertEqual(prepared.system_prompt, "# Admitted first capability\n")
            self.assertEqual(prepared.context_digest, result["transaction"]["context_digest"])
            self.assertEqual(prepared.deployment_digest, result["deployment_digest"])
            self.assertEqual(prepared.policy_digest, self.policy["runtime_action_policy_digest"])
            self.assertNotEqual(prepared.policy_digest, self.context["policy_digest"])
        self.decision.assert_called()
        for call in self.decision.call_args_list:
            self.assertEqual(call.kwargs["expected_policy_digest"], self.policy["admission_policy_digest"])
        self.assertFalse(prepared._lease.active)

    def test_bare_admission_pin_refuses_before_install_or_launch(self):
        self.deployment["policy"] = self.policy["admission_policy_digest"]
        self.plan["deployment"]["digest"] = canonical_digest(self.deployment)
        with self.assertRaises(subject.PiBundleInstallEntryError) as error:
            self.install()
        self.assertFalse(error.exception.observation["installation_attempted"])
        with self.assertRaises(bundle.PiBundleLaunchError), self.prepare(self.context, b"# Admitted first capability\n"):
            self.fail("bare admission policy must not prepare")
        self.decision.assert_not_called()

    def test_update_rejects_stale_start_authority_and_preserves_predecessor(self):
        first = self.install()
        previous = self.context
        current = self.candidate("b", b"# Updated capability\n", previous)
        result = self.install()
        self.assertEqual(result["transaction"]["expected_active"]["context_id"], previous["context_id"])
        with self.assertRaises((bundle.PiBundleLaunchError, subject.lineage.RuntimeActionBrokerError,
                                lineage_v2.RuntimeActionObservationPublisherError)):
            with self.prepare(previous, b"# Admitted first capability\n"):
                self.fail("stale authority must not prepare")
        with self.prepare(current, b"# Updated capability\n") as prepared:
            self.assertEqual(prepared.system_prompt, "# Updated capability\n")
        self.assertEqual((self.protected / first["transaction"]["version_path"] / "SKILL.md").read_bytes(),
                         b"# Admitted first capability\n")

    def test_replay_is_not_retried_or_reported_unconsumed(self):
        self.install()
        with self.assertRaises(subject.PiBundleInstallEntryError) as raised:
            self.install()
        self.assertTrue(raised.exception.observation["installation_attempted"])
        self.assertEqual(raised.exception.observation["status"], "CLEANUP_HOLD")
        self.assertEqual(len(list((self.protected / ".aragorn-install-claims").iterdir())), 1)

    def test_quarantined_candidate_cannot_be_published(self):
        from aragorn.protected_skill_quarantine import publish_quarantine_at
        fd = os.open(self.protected, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            digest = "sha256:" + hashlib.sha256(b"# Admitted first capability\n").hexdigest()
            publish_quarantine_at(fd, digest, pin("9"), expected_uid=self.uid)
        finally:
            os.close(fd)
        with self.assertRaises(subject.PiBundleInstallEntryError):
            self.install()
        self.assertFalse((self.protected / "pi").exists())

    def test_wrong_expected_active_cas_does_not_replace_current_bundle(self):
        self.install()
        self.candidate("b", b"# Updated capability\n", self.context)
        empty = self.root / "empty-cas"
        CAS(empty)
        self.plan["predecessor_cas_root"] = str(empty)
        with self.assertRaises(subject.PiBundleInstallEntryError):
            self.install()
        self.assertEqual((self.protected / "pi/SKILL.md").read_bytes(), b"# Admitted first capability\n")
