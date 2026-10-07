"""Inert retained-envelope replay; no live attempt or qualification evidence.

Only existing data constructors are composed. The real pure original planner
produces its public closure under a test clock. Post-attempt observations below
are explicit data doubles: this consumer does not replay their private semantics.
"""

from copy import deepcopy
import hashlib
from io import BytesIO
import json
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from aragorn import native_phase3_common_attempt_capture as subject
from aragorn import native_phase3_common_attempt_inputs as inputs
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from scripts import materialize_runtime_native_blocked_create_driver as driver
from scripts import runtime_native_common_attempt_capture as guest_contract
from tests import test_native_phase3_common_setup_capture as setup_data
from tests import test_runtime_native_common_attempt_plan as plan_data


class AttemptCaptureData(unittest.TestCase):
    """Reusable data constructor, never inherited historical test behavior."""

    def setUp(self):
        outer = setup_data.SetupCaptureData()
        outer.setUp()
        self.addCleanup(outer.doCleanups)
        fixture = plan_data.Fixture(self)
        self.planner_fixture = fixture
        root = Path(__file__).resolve().parents[1]
        sources = {path: (root / path).read_bytes() for path in inputs.SOURCE_PATHS}
        base_arguments = dict(outer.arguments)
        base_arguments.update(
            source_raws={path: sources[path] for path in inputs.base.SOURCE_PATHS},
            implementation_source_raws={
                path: sources[path] for path in inputs.base.IMPLEMENTATION_PATHS
            },
            setup_source_raw=sources[inputs.base.SETUP_SOURCE],
            wrapper_source_raw=sources[inputs.base.WRAPPER_SOURCE],
            host_source_raw=sources[inputs.base.HOST_SOURCE],
        )
        base_bundle = inputs.base.prepare_common_setup_inputs(**base_arguments)
        base_bound = inputs.base.inspect_common_setup_inputs(
            base_bundle["bundle_raw"],
            expected_bundle_digest=base_bundle["bundle_digest"],
        )
        fixture.arguments["common_arguments"] = {
            key: value
            for key, value in base_bound["setup_arguments"].items()
            if key != "expected_setup_digest"
        } | {"container_id": setup_data.data.CONTAINER}
        self.bound = inputs.prepare_common_attempt_inputs(
            setup_bundle_raw=base_bundle["bundle_raw"],
            expected_setup_bundle_digest=base_bundle["bundle_digest"],
            plan_arguments={
                key: fixture.arguments[key] for key in inputs.PLAN_ARGUMENTS
            },
            source_raws={path: sources[path] for path in inputs.EXTRA_SOURCE_PATHS},
        )
        self.built = fixture.build()
        self.store = CAS(fixture.common.root / "public-replay")
        self.reader = CAS(self.store.root, read_only=True)
        self.retain(self.bound["input_blobs"])
        journal = deepcopy(fixture.journal)
        blobs = {row["digest"]: fixture.cas.read(row["digest"]) for row in journal}

        def document(role, value=None, *, raw=None):
            content = canonical_json(value) if raw is None else raw
            pin = subject._digest(content)
            blobs[pin] = content
            journal.append({"role": role, "digest": pin, "bytes": len(content)})
            return pin

        document("request", raw=self.built["request_raw"])
        claim = {
            "schema": "aragorn/native-common-measurement-claim/v1",
            "collection_preparation_digest": self.built[
                "collection_preparation_digest"
            ],
            "common_preparation_digest": self.built["common_preparation_digest"],
            "measurement_prepared_digest": self.built["measurement_prepared_digest"],
            "commitment_digest": self.built["report"]["commitment_digest"],
            "request_digest": subject._digest(
                canonical_json(self.built["scheduled_request"])
            ),
            "common_request_digest": self.built["request_digest"],
            "binding_digest": self.built["binding_digest"],
            "container_id": setup_data.data.CONTAINER,
            "claimed_boottime_ns": 300,
            "state": "PERMANENT_NO_RETRY_CLAIM_NOT_COMPLETION",
        }
        claim_pin = document("claim", claim)
        provision_pin = document("provisioning", {"inert_test_only": "provisioning"})
        handoff = {
            "schema": "aragorn/native-common-measurement-handoff/v1",
            "authority": "LOCAL_ORIGINAL_COMMITMENT_PROVISIONING_NOT_ACTIVATION_OR_MEASUREMENT",
            "status": "INPUTS_PROVISIONED_NOT_ACTIVATED",
            "container_id": setup_data.data.CONTAINER,
            "collection_preparation_digest": self.built[
                "collection_preparation_digest"
            ],
            "common_preparation_digest": self.built["common_preparation_digest"],
            "measurement_prepared_digest": self.built["measurement_prepared_digest"],
            "commitment_digest": self.built["report"]["commitment_digest"],
            "scheduled_request": self.built["scheduled_request"],
            "scheduled_request_digest": claim["request_digest"],
            "binding_digest": self.built["binding_digest"],
            "request_digest": self.built["request_digest"],
            "provisioning_digest": provision_pin,
            "claim_digest": claim_pin,
            "claimed_boottime_ns": 300,
            "decision": dict.fromkeys(plan_data.subject.handoff._FALSE, False),
            "limitations": list(plan_data.subject.handoff.LIMITATIONS),
        }
        document("handoff", handoff)
        work = {"inert_test_only": "workload", "status": "OBSERVED", "records": {}}
        snapshot = {
            "inert_test_only": "snapshot",
            "status": "SNAPSHOTTED",
            "records": {},
            "broker_blob_digests": {},
            "broker_blobs": {},
        }
        verification = {"inert_test_only": "verification"}
        document("independent_verification", verification)
        for role in (
            "identity_before",
            "identity_after",
            "process_before",
            "process_after",
            "clock_before",
            "clock_after",
            "measurement_startup",
            "measurement_ingress",
            "measurement_attempt",
            "measurement_action",
            "measurement_pending",
            "measurement_completion",
            "workload_receipt_before",
            "workload_receipt_after",
            "workload_sink_before",
            "workload_sink_after",
            "workload_driver_input",
            "workload_driver",
            "workload_identity_before",
            "workload_identity_after",
        ):
            pin = document(role, {"inert_test_only": role})
            if role.startswith(("measurement_", "workload_")):
                target = snapshot if role.startswith("measurement_") else work
                target["records"][role.split("_", 1)[1]] = {
                    "text": blobs[pin].decode(),
                    "bytes": len(blobs[pin]),
                    "digest": pin,
                }
        for name in (
            "evidence",
            "consumed_grant_state",
            "profile_receipt",
            "broker_result",
            "profiled_submission",
        ):
            pin = document("broker_blob", {"inert_test_only_broker_role": name})
            snapshot["broker_blob_digests"][name] = pin
            snapshot["broker_blobs"][pin] = {
                "text": blobs[pin].decode(),
                "bytes": len(blobs[pin]),
                "digest": pin,
            }
        work_pin = document("workload", work)
        snapshot_pin = document("measurement_snapshot", snapshot)
        preparation = json.loads(self.built["common_preparation_raw"])
        report = {
            "schema": "aragorn/native-common-attempt/v1",
            "authority": "OWNED_FIRST_ACTIVATION_BOUNDED_ATTEMPT_NOT_HOST_OR_CAMPAIGN_AUTHORITY",
            "status": "BOUNDED_NATIVE_ATTEMPT_VERIFIED",
            "setup_state": {
                "activation_count": 1,
                "pins_frozen_before_activation": True,
                "provisioning_file_digests": preparation["provisioning_file_digests"],
            },
            "callback_count": 1,
            "workload_count": 1,
            "snapshot_count": 1,
            "cleanup_count": 1,
            "public_blob_attempts": journal,
            "public_blob_digests": sorted(blobs),
            "public_readback_failures": [],
            "plan": self.built["report"],
            "handoff": handoff,
            "workload": {"status": "OBSERVED", "digest": work_pin},
            "snapshot": {"status": "SNAPSHOTTED", "digest": snapshot_pin},
            "verification": verification,
            "fixture_stack_cleanup": deepcopy(outer.setup["fixture_stack_cleanup"]),
            "refusal": None,
            "postcondition_failures": [],
            "limitations": list(guest_contract.attempt.LIMITATIONS),
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        }
        for name in (
            "installed_sources",
            "installed_sources_after",
            "writer_readback",
            "writer_readback_after",
        ):
            report[name] = deepcopy(outer.setup[name])
        implementation = {
            target: setup_data._metadata(sources[path], inode=3000 + index)
            for index, (path, target) in enumerate(
                inputs.base.IMPLEMENTATION_PATHS.items()
            )
        }
        implementation[inputs.base.FIXTURE_HELPERS[inputs.base.SETUP_SOURCE]] = (
            setup_data._metadata(sources[inputs.base.SETUP_SOURCE], inode=3100)
        )
        report["implementation_sources"] = implementation
        report["implementation_sources_after"] = deepcopy(implementation)
        inverse = {target: path for path, target in inputs.FIXTURE_HELPERS.items()}
        checked = {
            path: setup_data._metadata(sources[inverse[path]], inode=3200 + index)
            for index, path in enumerate(inputs.ATTEMPT_SOURCE_PATHS)
        }
        report["sources_before"] = checked
        report["sources_after"] = deepcopy(checked)
        report["network_before"] = {"entries": ["lo"], "inert_test_only": True}
        report["network_after"] = deepcopy(report["network_before"])
        report["process_verification"] = {"inert_test_only": True}
        self.retain(blobs)
        rows = [
            {"digest": pin, "bytes": len(raw), "text": raw.decode()}
            for pin, raw in blobs.items()
        ]
        controllers = {
            path: setup_data._metadata(sources[path], inode=3300 + index)
            for index, path in enumerate(
                (inputs.WRAPPER_SOURCE, inputs.CONSUMER_SOURCE)
            )
        }
        guest = {
            "schema": guest_contract.SCHEMA,
            "authority": guest_contract.AUTHORITY,
            "status": "EXPORTED_BOUNDED_ATTEMPT",
            "container_id": setup_data.data.CONTAINER,
            "input_bundle_digest": self.bound["bundle_digest"],
            "attempt": report,
            "public_blobs": rows,
            "export_failures": [],
            "refusal": None,
            "input_bundle_readback": True,
            "controller_sources": controllers,
            "controller_sources_after": deepcopy(controllers),
            "postcondition_failures": [],
            "recovery": {
                "status": "NOT_REQUIRED",
                "claim_metadata": None,
                "public_blob_attempts": [],
                "failures": [],
            },
            "public_export_complete": True,
            "preserve_fixture_for_evidence": False,
            "interrupted": False,
            "limitations": list(guest_contract._LIMITATIONS),
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        }
        outer_names = (
            "build_observation",
            "fixture_image",
            "parent_identity",
            "parent_before",
            "parent_after",
            "runtime_before",
            "runtime_after",
            "container_inspect",
            "cleanup",
        )
        capture = {key: deepcopy(outer.capture[key]) for key in outer_names}
        owner = capture["cleanup"]["owner"]
        name = subject.NAME_PREFIX + owner[:16]
        old_name = capture["cleanup"]["name"]
        # Only replace the fixture name in this inert outer model, preserving
        # the exact ownership, argv, inspect and cleanup joins of its constructor.
        capture = json.loads(json.dumps(capture).replace(old_name, name))
        helpers = {}
        for path, target in inputs.FIXTURE_HELPERS.items():
            raw = sources[path]
            helpers[path] = {
                "path": path,
                "mode": "100644",
                "blob": hashlib.sha1(
                    b"blob " + str(len(raw)).encode() + b"\0" + raw
                ).hexdigest(),
                "bytes": len(raw),
                "digest": subject._digest(raw),
                "installed_path": target,
                "installed_mode": "0444",
            }
        order = [row["digest"] for row in rows]
        capture.update(
            schema=subject.SCHEMA,
            authority=subject.AUTHORITY,
            status="CAPTURED_BOUNDED_ATTEMPT",
            input_bundle_digest=self.bound["bundle_digest"],
            source=json.loads(self.bound["source_raw"]),
            fixture_helpers=helpers,
            fixture_aliases={
                target: dict(helpers[path], installed_path=target)
                for target, path in inputs.HELPER_ALIASES.items()
            },
            fixture_container=setup_data.data.CONTAINER,
            fixture_name=name,
            fixture_owner=owner,
            staged_profile=json.loads(self.bound["stage_raw"]),
            generated_driver=driver.materialize_runtime_native_blocked_create_driver(
                fixture.common.root / "driver"
            ),
            guest=guest,
            guest_recovery=deepcopy(guest["recovery"]),
            guest_publication={
                "attempted": list(order),
                "retained": list(order),
                "failed": [],
                "complete": True,
            },
            cleanup_failure=None,
            refusal=None,
            fixture_creation_attempted=True,
            invocation_started=True,
            fixture_preserved=False,
            cleanup_deferred_reason=None,
            preservation_suspension=None,
            invocation_failure=None,
            postcondition_failures=[],
            independent_capture_replay_complete=False,
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        )
        self.capture = capture

    def retain(self, blobs):
        for pin, raw in blobs.items():
            self.store.put_expected(
                BytesIO(raw), expected_digest=pin, max_bytes=len(raw)
            )

    def verify(self, value=None, **updates):
        raw = canonical_json(self.capture if value is None else value) + b"\n"
        pin = subject._digest(raw)
        self.retain({pin: raw})
        return subject.verify_native_common_attempt_capture(
            raw, **({"expected_capture_digest": pin, "store": self.reader} | updates)
        )


class NativeCommonAttemptCaptureTests(AttemptCaptureData):
    def private_capture(self):
        value = deepcopy(self.capture)
        plan = value["guest"]["attempt"]["plan"]
        prepared = json.loads(self.reader.read(plan["measurement_prepared_digest"]))
        grant = prepared["binding"]["grant_digest"]
        size = next(
            row["bytes"] for row in prepared["input_blobs"] if row["digest"] == grant
        )
        fixture = {
            "container_id": value["fixture_container"],
            "name": value["fixture_name"],
            "owner": value["fixture_owner"],
            "source_commit": value["source"]["commit"],
            "image": value["fixture_image"]["Id"],
            "network_mode": "none",
            "pid": 71,
            "started_at": "2026-10-06T20:10:58.131000000Z",
        }
        source = {
            "digest": grant,
            "bytes": size,
            "identity": [1, 2, stat.S_IFREG | 0o444, 0, 0, 1, size, 3, 4],
        }
        value["private_input_transfer_attempted"] = True
        value["private_measurement_inputs"] = {
            "schema": "aragorn/native-common-measurement-input-retention/v1",
            "authority": "PRIVATE_HOST_CAS_RETENTION_NOT_MEASUREMENT_OR_QUALIFICATION",
            "status": "PRIVATE_INPUTS_RETAINED",
            "container_id": value["fixture_container"],
            "prepared_digest": plan["measurement_prepared_digest"],
            "binding_digest": plan["binding_digest"],
            "grant_digest": grant,
            "grant_bytes": size,
            "input_blobs": prepared["input_blobs"],
            "input_set_digest": subject._digest(
                canonical_json(prepared["input_blobs"])
            ),
            "fixture_before": deepcopy(fixture),
            "fixture_after": deepcopy(fixture),
            "grant_source_before": deepcopy(source),
            "grant_source_after": deepcopy(source),
            "scratch_directory": "/private/inert/native-common-measurement-input-retention",
            "copy_count": 1,
            "input_validation_complete": True,
            "postcondition_failures": [],
            "refusal": None,
            **dict.fromkeys(subject.FALSE_FLAGS, False),
        }
        return value

    def test_optional_private_metadata_joins_without_claiming_private_semantics(self):
        result = self.verify(self.private_capture())
        self.assertTrue(result["public_capture_joins_verified"])
        self.assertFalse(result["private_measurement_input_semantics_replayed"])
        self.assertFalse(result["independent_full_measurement_replay_complete"])
        self.assertTrue(all(result[key] is False for key in subject.FALSE_FLAGS))
        value = deepcopy(self.capture)
        value.update(
            private_input_transfer_attempted=False, private_measurement_inputs=None
        )
        self.assertTrue(self.verify(value)["public_capture_joins_verified"])

    def test_private_metadata_rebinding_partial_or_extra_bytes_are_refused(self):
        mutations = (
            lambda value: value.pop("private_input_transfer_attempted"),
            lambda value: value.update(private_input_transfer_attempted=False),
            lambda value: value["private_measurement_inputs"].update(grant_bytes=1),
            lambda value: value["private_measurement_inputs"].update(
                prepared_digest="sha256:" + "f" * 64
            ),
            lambda value: value["private_measurement_inputs"].update(
                raw_grant="forbidden field"
            ),
            lambda value: value["private_measurement_inputs"].update(
                input_validation_complete=False
            ),
            lambda value: value["private_measurement_inputs"]["fixture_after"].update(
                pid=99
            ),
            lambda value: value["private_measurement_inputs"]["grant_source_after"][
                "identity"
            ].__setitem__(1, 99),
        )
        for mutation in mutations:
            value = self.private_capture()
            mutation(value)
            with self.assertRaises(subject.NativeCommonAttemptCaptureError):
                self.verify(value)

    def test_real_public_plan_replay_is_read_only_and_keeps_claim_ceiling(self):
        raw = canonical_json(self.capture) + b"\n"
        pin = subject._digest(raw)
        self.retain({pin: raw})
        with (
            patch.object(CAS, "put", side_effect=AssertionError("no publication")),
            patch.object(
                CAS, "put_expected", side_effect=AssertionError("no publication")
            ),
            patch.object(
                inputs.base.preparation,
                "_inspect",
                side_effect=AssertionError("no private writer replay"),
            ),
            patch.object(
                plan_data.subject,
                "prepare_native_common_attempt_plan",
                side_effect=AssertionError("no new plan"),
            ),
            patch("time.clock_gettime_ns", side_effect=AssertionError("no clock")),
        ):
            result = subject.verify_native_common_attempt_capture(
                raw, expected_capture_digest=pin, store=self.reader
            )
        self.assertEqual(
            result["status"], "BOUNDED_PUBLIC_ATTEMPT_CAPTURE_REPLAY_VERIFIED"
        )
        self.assertTrue(result["public_capture_joins_verified"])
        for key in (
            *subject.FALSE_FLAGS,
            "private_writer_semantics_replayed",
            "private_measurement_input_semantics_replayed",
            "independent_full_measurement_replay_complete",
        ):
            self.assertIs(result[key], False)
        self.assertEqual(
            result["deployment_digest"],
            json.loads(self.built["common_preparation_raw"])["deployment_digest"],
        )

    def test_partial_counts_claim_escalation_and_unsafe_cleanup_refuse(self):
        changes = (
            lambda value: value.update(status="REFUSED"),
            lambda value: value.update(phase3_exit_eligible=True),
            lambda value: value.update(fixture_preserved=True),
            lambda value: value["guest"].update(public_export_complete=False),
            lambda value: value["guest"]["attempt"].update(callback_count=True),
            lambda value: value["guest"]["attempt"]["setup_state"].update(
                activation_count=2
            ),
            lambda value: value["cleanup"].update(removed_id="f" * 64),
            lambda value: value["guest"]["attempt"]["fixture_stack_cleanup"].popitem(),
        )
        for change in changes:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonAttemptCaptureError):
                self.verify(value)

    def test_missing_changed_unknown_and_unretained_public_children_refuse(self):
        changes = (
            lambda value: value["guest"]["public_blobs"].pop(),
            lambda value: value["guest"]["public_blobs"][0].update(
                text="not the retained bytes"
            ),
            lambda value: value["guest"]["attempt"]["public_blob_attempts"][0].update(
                role="private_grant"
            ),
            lambda value: value["guest_publication"]["retained"].pop(),
            lambda value: value["guest"]["attempt"]["plan"].update(
                binding_digest="sha256:" + "f" * 64
            ),
        )
        for change in changes:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonAttemptCaptureError):
                self.verify(value)
        child = self.capture["guest"]["public_blobs"][-1]["digest"]
        original = CAS.read

        def missing(store, pin, **kwargs):
            if pin == child:
                raise FileNotFoundError("inert missing child")
            return original(store, pin, **kwargs)

        with patch.object(CAS, "read", missing):
            with self.assertRaises(subject.NativeCommonAttemptCaptureError):
                self.verify()

    def test_private_writer_pin_is_refused_even_under_an_allowed_public_role(self):
        raw = next(iter(self.planner_fixture.common.inputs.values()))
        pin = subject._digest(raw)
        self.retain({pin: raw})
        value = deepcopy(self.capture)
        value["guest"]["attempt"]["public_blob_attempts"].append(
            {"role": "broker_blob", "digest": pin, "bytes": len(raw)}
        )
        value["guest"]["attempt"]["public_blob_digests"].append(pin)
        value["guest"]["attempt"]["public_blob_digests"].sort()
        value["guest"]["public_blobs"].append(
            {"digest": pin, "bytes": len(raw), "text": raw.decode()}
        )
        for key in ("attempted", "retained"):
            value["guest_publication"][key].append(pin)
        with self.assertRaisesRegex(
            subject.NativeCommonAttemptCaptureError, "private writer pin exported"
        ):
            self.verify(value)

    def test_helper_alias_stage_and_controller_custody_mutations_refuse(self):
        alias = next(iter(inputs.HELPER_ALIASES))
        changes = (
            lambda value: value["fixture_helpers"][inputs.WRAPPER_SOURCE].update(
                installed_mode="0644"
            ),
            lambda value: value["fixture_aliases"][alias].update(
                digest="sha256:" + "f" * 64
            ),
            lambda value: value["guest"]["controller_sources_after"][
                inputs.CONSUMER_SOURCE
            ]["identity"].__setitem__(1, 9999),
            lambda value: value["staged_profile"]["files"][0].update(mode="0777"),
        )
        for change in changes:
            value = deepcopy(self.capture)
            change(value)
            with self.assertRaises(subject.NativeCommonAttemptCaptureError):
                self.verify(value)

    def test_caller_capture_pin_and_read_only_store_are_required(self):
        with self.assertRaises(subject.NativeCommonAttemptCaptureError):
            self.verify(expected_capture_digest="sha256:" + "f" * 64)
        with self.assertRaisesRegex(
            subject.NativeCommonAttemptCaptureError, "read-only evidence CAS required"
        ):
            self.verify(store=self.store)

    def test_rehashed_handoff_reference_and_embedded_record_mutations_refuse(self):
        def replace_document(value, old_pin, document):
            raw = canonical_json(document)
            pin = subject._digest(raw)
            self.retain({pin: raw})
            report = value["guest"]["attempt"]
            for row in report["public_blob_attempts"]:
                if row["digest"] == old_pin:
                    row.update(digest=pin, bytes=len(raw))
            report["public_blob_digests"] = sorted(
                pin if item == old_pin else item
                for item in report["public_blob_digests"]
            )
            for row in value["guest"]["public_blobs"]:
                if row["digest"] == old_pin:
                    row.update(digest=pin, bytes=len(raw), text=raw.decode())
            for key in ("attempted", "retained"):
                value["guest_publication"][key] = [
                    pin if item == old_pin else item
                    for item in value["guest_publication"][key]
                ]
            return pin

        value = deepcopy(self.capture)
        handoff = value["guest"]["attempt"]["handoff"]
        old_pin = subject._digest(canonical_json(handoff))
        handoff["claim_digest"] = "sha256:" + "f" * 64
        replace_document(value, old_pin, handoff)
        with self.assertRaises(subject.NativeCommonAttemptCaptureError):
            self.verify(value)
        value = deepcopy(self.capture)
        summary = value["guest"]["attempt"]["workload"]
        document = json.loads(self.reader.read(summary["digest"]))
        document["records"]["driver"]["digest"] = "sha256:" + "f" * 64
        summary["digest"] = replace_document(value, summary["digest"], document)
        with self.assertRaises(subject.NativeCommonAttemptCaptureError):
            self.verify(value)


if __name__ == "__main__":
    unittest.main()
