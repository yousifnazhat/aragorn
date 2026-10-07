"""New HTTP root-publication seams in caller-owned temporary files only.

Linux/root, namespace and unit observations are explicit inert substitutes. The
new planner/input validator, filesystem custody, CAS and absent-only writes are
real. No previous test method, service, socket or acceptance collector is run.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from copy import deepcopy
from functools import lru_cache
from io import BytesIO
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from aragorn import native_phase3_http_canary_contract as canary
from aragorn import phase3_quantitative_metrics as metrics
from aragorn import runtime_http_action as http
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import materialize_native_phase3_http_measurement_provisioning as renderer
from tests import test_native_phase3_http_preparation as prepared_data
from tests import test_runtime_native_measurement_provisioning as file_data


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = "p3-lab-a001"


@lru_cache(maxsize=1)
def subject():
    _, validator, planner, _ = prepared_data.rendered_modules()
    raw = (ROOT / renderer.SOURCE).read_bytes()
    result = prepared_data._module(
        renderer.render({renderer.SOURCE: raw})[renderer.SOURCE],
        "measurement_provisioning",
        {"runtime_native_measurement_inputs": validator},
    )
    return result, planner


class HttpFixture:
    def __init__(self, test):
        self.test = test
        self.subject, self.planner = subject()
        # Reuse only the private filesystem/data constructor, not old tests.
        self.files = file_data.Fixture(test)
        self.root = self.files.root
        self.http_path = self.files.etc / "runtime-http-fixture.json"
        self.fixture = {
            "container_id": "b" * 64,
            "boot_id": self.files.prepared["binding"]["boot_id"],
            "netns_device": 4,
            "netns_inode": 123456,
        }
        self.binding = {
            "schema": http.BINDING_SCHEMA,
            "fixture": self.fixture,
            "expected_broker_uid": self.files.identities[0],
            "expected_broker_gid": self.files.identities[2],
        }
        self.events = self.files.events
        self.guard_count = 0
        self.guard_change = None
        self.namespace_release_error = None
        self.expected_accounts = self.files.identities[0], self.files.identities[2]
        for name in renderer.HTTP_SOURCES:
            self.files.write(
                self.files.modules / name,
                ("# inert HTTP source " + name).encode(),
                0o644,
            )
            self.files.source_pins[name] = canary.digest(
                (self.files.modules / name).read_bytes()
            )
        digests = http.action_digests(ATTEMPT, self.binding)
        self.files.policy.update(
            id="owned-native-receipt-http-canary",
            allow=[
                {
                    "runtime_digest": self.files.binding["runtime_digest"],
                    "active_skill_digest": self.files.binding["active_skill_digest"],
                    **digests,
                }
            ],
        )
        policy_pin = canonical_digest(self.files.policy)
        self.files.binding["policy_digest"] = policy_pin
        self.files.grant.update(
            policy_digest=policy_pin, operation_digest=digests["operation_digest"]
        )
        self.files.write(self.files.worker, canonical_json(self.files.binding))
        self.files.write(self.files.grant_path, canonical_json(self.files.grant))
        self.files.write(
            self.files.control / "policy.json", canonical_json(self.files.policy)
        )
        self.files.write(self.http_path, canonical_json(self.binding), 0o440)
        self.descriptor = http.endpoint_descriptor(self.binding)
        self.prepared = self._prepare()
        self.arguments = {
            "prepared_raw": canonical_json(self.prepared),
            "expected_prepared_digest": canonical_digest(self.prepared),
            "expected_binding_digest": self.prepared["binding_digest"],
            "expected_broker_source_pins": self.files.source_pins,
            "source_cas": self.source_cas,
        }

    def _prepare(self):
        source = CAS(self.root / "http-source")

        def put(value):
            raw = value if type(value) is bytes else canonical_json(value)
            return source.put(BytesIO(raw), max_bytes=1024 * 1024)

        for row in self.files.prepared["input_blobs"]:
            put(self.files.source_cas.read(row["digest"]))
        original = self.files.prepared["binding"]
        parse = self.subject.broker._parse_canonical_document
        old_schedule = parse(
            source.read(original["measurement_schedule_digest"]), "inert schedule"
        )
        attempts = [f"p3-lab-a{n:03d}" for n in range(1, 101)]
        schedule = metrics.build_phase3_measurement_schedule(
            expected_attempt_ids=attempts,
            expected_attempt_families={
                name: "EXFILTRATION" if n < 50 else "DESTRUCTIVE"
                for n, name in enumerate(attempts)
            },
            expected_unattributed_attempt_id=attempts[-1],
            expected_overhead_pair_bindings=old_schedule["overhead_schedule"][
                "pair_bindings"
            ],
            **{
                "expected_" + key: value
                for key, value in old_schedule["bindings"].items()
            },
        )
        schedule_pin = put(schedule)
        commitment = parse(
            source.read(original["collection_commitment_digest"]), "inert commitment"
        )
        commitment["schedule_digest"] = schedule_pin
        commitment_pin = put(commitment)
        target = CAS(self.root / "http-prepared")
        prepared = self.planner.prepare_broker_decision_measurement_binding(
            source_cas=CAS(source.root, read_only=True),
            target_cas=target,
            expected_commitment_digest=commitment_pin,
            expected_schedule_digest=schedule_pin,
            expected_deployment_digest=original["deployment_identity_digest"],
            expected_grant_digest=put(self.files.grant),
            expected_path_digest=put(self.descriptor),
            expected_payload_digest=canary.digest(canary.canary_request(ATTEMPT)),
            expected_collector_digest=commitment["collector_digest"],
            expected_collection_source_pins={
                name: row["digest"] for name, row in commitment["sources"].items()
            },
            expected_broker_source_pins=self.files.source_pins,
            expected_boot_id=self.fixture["boot_id"],
            scheduled_request={
                "kind": "attempt",
                "attempt_id": ATTEMPT,
                "family": "EXFILTRATION",
                "negative_control": False,
                "collection_digest": commitment_pin,
                "deployment_digest": original["deployment_identity_digest"],
            },
        )
        self.source_cas = CAS(target.root, read_only=True)
        return prepared

    def guard(self):
        self.guard_count += 1
        self.events.append("namespace-guard")
        if self.guard_change:
            self.guard_change(self.guard_count)

    @contextmanager
    def namespace(self, expected):
        self.test.assertEqual(expected, self.fixture)
        self.events.append("namespace-enter")
        self.guard()
        try:
            yield self
        finally:
            self.events.append("namespace-release")
            if self.namespace_release_error:
                raise self.namespace_release_error

    @contextmanager
    def patched(self):
        # The reusable fixture's module alias is test-only; production modules
        # are not replaced or modified by the renderer.
        with (
            patch.object(file_data, "subject", self.subject),
            self.files.patched(),
            ExitStack() as stack,
        ):
            stack.enter_context(
                patch.object(self.subject.http, "BINDING_PATH", self.http_path)
            )
            stack.enter_context(
                patch.object(
                    self.subject.http_provisioning,
                    "_accounts",
                    side_effect=lambda: self.expected_accounts,
                )
            )
            stack.enter_context(
                patch.object(self.subject, "owned_http_fixture", self.namespace)
            )
            stack.enter_context(
                patch(
                    "socket.socket",
                    side_effect=AssertionError(
                        "provisioning must not contact endpoint"
                    ),
                )
            )
            yield

    def run(self):
        with self.patched():
            return self.subject.provision_runtime_native_measurement(**self.arguments)

    def assert_refused(self, boundary):
        with self.test.assertRaises(
            self.subject.NativeMeasurementProvisioningError
        ) as result:
            self.run()
        names = []
        cause = result.exception
        while cause is not None:
            frame = cause.__traceback__
            while frame is not None:
                names.append(frame.tb_frame.f_code.co_name)
                frame = frame.tb_next
            cause = cause.__cause__
        self.test.assertIn(boundary, names)
        return result.exception


class HttpMeasurementProvisioningTests(unittest.TestCase):
    def test_renderer_refuses_unpinned_inputs_and_keeps_frozen_source(self):
        raw = (ROOT / renderer.SOURCE).read_bytes()
        rendered = renderer.render({renderer.SOURCE: raw})
        self.assertEqual(set(rendered), {renderer.SOURCE})
        compile(rendered[renderer.SOURCE], renderer.SOURCE, "exec")
        self.assertEqual((ROOT / renderer.SOURCE).read_bytes(), raw)
        for inputs in ({}, {renderer.SOURCE: raw + b"\n"}, rendered):
            with (
                self.subTest(keys=list(inputs)),
                self.assertRaises(
                    renderer.NativeHttpMeasurementProvisioningRenderError
                ),
            ):
                renderer.render(inputs)

    def test_exact_http_inputs_publish_root_credential_after_cas_without_create_surrogate(
        self,
    ):
        fixture = HttpFixture(self)
        subject = fixture.subject
        original = subject.custody._create_document

        def publish(parent, name, raw, held):
            self.assertTrue(fixture.files.store.is_dir())
            self.assertFalse(fixture.files.credential.exists())
            self.assertNotIn("namespace-release", fixture.events)
            self.assertGreaterEqual(fixture.guard_count, 4)
            fixture.events.append("credential-publish")
            return original(parent, name, raw, held)

        with (
            fixture.patched(),
            patch.object(
                subject,
                "_held_directory",
                side_effect=AssertionError("HTTP must not use create inode"),
            ),
            patch.object(subject.custody, "_create_document", side_effect=publish),
        ):
            result = subject.provision_runtime_native_measurement(**fixture.arguments)
        self.assertEqual(
            result["schema"], "aragorn/native-http-measurement-provisioning/v1"
        )
        self.assertTrue(result["http_endpoint_bound"])
        self.assertEqual(
            result["http_fixture_binding_digest"], canonical_digest(fixture.binding)
        )
        self.assertEqual(
            fixture.files.credential.read_bytes(),
            canonical_json(fixture.prepared["binding"]),
        )
        self.assertEqual(stat.S_IMODE(fixture.files.credential.stat().st_mode), 0o400)
        self.assertEqual(len(fixture.prepared["binding"]["source_pins"]), 21)
        self.assertLessEqual(len(fixture.files.credential.read_bytes()), 8192)
        self.assertEqual(
            fixture.events[-3:],
            ["broker-release", "activation-release", "namespace-release"],
        )
        for key in (
            "payload_bytes_verified",
            "activation_performed",
            "measurement_collected",
            "run_qualified",
            "quantitative_metrics_eligible",
            "phase3_exit_eligible",
        ):
            self.assertIs(result[key], False)
        retained = CAS(fixture.files.store, read_only=True)
        for row in result["input_blobs"]:
            self.assertEqual(
                retained.read(row["digest"]), fixture.source_cas.read(row["digest"])
            )

    def test_http_source_inventory_matches_prepared_binding(self):
        fixture = HttpFixture(self)
        self.assertEqual(
            fixture.subject._SOURCE_NAMES,
            frozenset(fixture.prepared["binding"]["source_pins"]),
        )
        selected = "runtime_http_ingress.py"
        fixture.files.write(
            fixture.files.modules / selected, b"changed HTTP source", 0o644
        )
        fixture.assert_refused("_actual_inputs")
        self.assertFalse(fixture.files.store.exists())
        self.assertFalse(fixture.files.credential.exists())

    def test_protected_http_credential_mode_and_symlink_are_refused(self):
        for mode in (0o400, 0o444, "symlink"):
            with self.subTest(mode=mode):
                fixture = HttpFixture(self)
                if mode == "symlink":
                    fixture.http_path.unlink()
                    fixture.http_path.symlink_to(fixture.files.worker)
                else:
                    fixture.http_path.chmod(mode)
                fixture.assert_refused("_hold_file")
                self.assertFalse(fixture.files.store.exists())

    def test_rebound_http_credential_is_refused_before_publication(self):
        for field in ("container_id", "netns_inode", "boot_id"):
            with self.subTest(field=field):
                fixture = HttpFixture(self)
                binding = deepcopy(fixture.binding)
                binding["fixture"][field] = {
                    "container_id": "c" * 64,
                    "netns_inode": 123457,
                    "boot_id": "00000000-0000-0000-0000-000000000002",
                }[field]
                fixture.files.write(fixture.http_path, canonical_json(binding), 0o440)
                fixture.assert_refused("_http_endpoint")
                self.assertFalse(fixture.files.store.exists())

    def test_changed_actual_account_identity_is_refused(self):
        fixture = HttpFixture(self)
        fixture.expected_accounts = (
            fixture.expected_accounts[0] + 1,
            fixture.expected_accounts[1],
        )
        fixture.assert_refused("_recheck_protected_inputs")
        self.assertFalse(fixture.files.store.exists())

    def test_namespace_guard_failure_before_write_leaves_no_outputs(self):
        fixture = HttpFixture(self)

        def changed(count):
            if count == 3:
                raise RuntimeError("inert namespace changed before write")

        fixture.guard_change = changed
        fixture.assert_refused("guard")
        self.assertFalse(fixture.files.store.exists())
        self.assertFalse(fixture.files.credential.exists())

    def test_credential_change_during_cas_copy_is_not_published(self):
        fixture = HttpFixture(self)
        original = fixture.subject._create_blob
        changed = False

        def mutate(*args):
            nonlocal changed
            entry = original(*args)
            if not changed:
                changed = True
                binding = deepcopy(fixture.binding)
                binding["fixture"]["netns_inode"] += 1
                fixture.files.write(fixture.http_path, canonical_json(binding), 0o440)
            return entry

        with (
            fixture.patched(),
            patch.object(fixture.subject, "_create_blob", side_effect=mutate),
        ):
            with self.assertRaises(fixture.subject.NativeMeasurementProvisioningError):
                fixture.subject.provision_runtime_native_measurement(
                    **fixture.arguments
                )
        self.assertTrue(fixture.files.store.is_dir())
        self.assertFalse(fixture.files.credential.exists())

    def test_existing_measurement_credential_is_never_replaced(self):
        fixture = HttpFixture(self)
        fixture.files.write(fixture.files.credential, b"preserve existing credential")
        before = fixture.files.snapshot()
        fixture.assert_refused("_absent")
        self.assertEqual(fixture.files.snapshot(), before)

    def test_http_namespace_cleanup_failure_retains_published_state(self):
        fixture = HttpFixture(self)
        fixture.namespace_release_error = RuntimeError("inert namespace cleanup failed")
        fixture.assert_refused("namespace")
        self.assertTrue(fixture.files.store.is_dir())
        self.assertEqual(
            fixture.files.credential.read_bytes(),
            canonical_json(fixture.prepared["binding"]),
        )
        before = fixture.files.snapshot()
        fixture.namespace_release_error = None
        fixture.assert_refused("_absent")
        self.assertEqual(fixture.files.snapshot(), before)

    def test_oversized_prepared_credential_fails_before_namespace_or_write(self):
        fixture = HttpFixture(self)
        original = fixture.subject.validate_prepared_native_measurement_inputs

        def oversized(**kwargs):
            value = original(**kwargs)
            value["binding_raw"] = b"x" * 8193
            return value

        with (
            fixture.patched(),
            patch.object(
                fixture.subject,
                "validate_prepared_native_measurement_inputs",
                side_effect=oversized,
            ),
        ):
            with self.assertRaises(fixture.subject.NativeMeasurementProvisioningError):
                fixture.subject.provision_runtime_native_measurement(
                    **fixture.arguments
                )
        self.assertNotIn("namespace-enter", fixture.events)
        self.assertFalse(fixture.files.store.exists())


if __name__ == "__main__":
    unittest.main()
