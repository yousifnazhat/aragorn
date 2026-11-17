"""Fixed action sibling storage with inert filesystem/identity fixtures only."""

from dataclasses import replace
import json
import os
import unittest
from unittest import mock

from aragorn import pi_core_provider_evidence as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_evidence as fixtures


class ActionFixture(fixtures.Fixture):
    def setUp(self):
        super().setUp()
        self.provider_index = self.index
        self.index = self.store / ("action-attempt-" + self.activation["activation_id"] + ".jsonl")

    def hold(self, **changes):
        return subject.hold_action_evidence(self.config, changes.pop("control_fd", self.control_fd),
            activation=changes.pop("activation", self.activation), deadline=changes.pop("deadline", 125.0), **changes)

    def provider(self):
        return subject.hold_provider_evidence(self.config, self.control_fd,
            activation=self.activation, deadline=125.0)

    def assert_observation(self, error, status="CLEANUP_HOLD"):
        result = error.pi_action_evidence_observation
        self.assertEqual((result["schema"], result["authority"], result["status"]),
                         (subject.ACTION_SCHEMA, subject.AUTHORITY, status))
        self.assertIs(result["phase3_eligible"], False)
        self.assertFalse(hasattr(error, "pi_provider_evidence_observation"))
        return result


class ActionEvidenceStoreTests(ActionFixture):
    def test_exact_action_schema_kinds_and_ordered_private_references(self):
        kinds = ("REQUEST_FRAME", "REQUEST_CONTEXT", "CHECK", "CURRENT_ATTEMPT", "ACTION_DONE",
                 "SENSOR_DONE", "ACTION_RESULT", "CONTROL_READBACK", "FAILURE")
        self.assertEqual(subject._ACTION_KINDS, frozenset(kinds))
        with self.hold() as owner:
            self.assertIs(type(owner), subject.PiProviderEvidence)
            for ordinal, kind in enumerate(kinds):
                raw = {"actual": ordinal, "private": "not an index payload"}
                ref = owner.retain(kind, raw)
                self.assertEqual(self.blob(ref["digest"]).read_bytes(), canonical_json(raw))
            lines = self.index.read_bytes().splitlines(keepends=True)
            header = json.loads(lines[0])
            self.assertEqual(header, {"schema": "aragorn/pi-core-action-evidence-index/v1",
                "authority": "DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE", "sequence": 0,
                "kind": "HEADER", "activation_id": self.activation["activation_id"],
                "activation_digest": canonical_digest(self.activation)})
            for ordinal, line in enumerate(lines[1:], 1):
                value = json.loads(line)
                self.assertEqual(value["schema"], "aragorn/pi-core-action-evidence-reference/v1")
                self.assertEqual(value["sequence"], ordinal)
                self.assertEqual(value["kind"], kinds[ordinal - 1])
                self.assertEqual(value["previous_prefix_digest"], subject._digest(b"".join(lines[:ordinal])))
            self.assertNotIn(b"not an index payload", self.index.read_bytes())
        self.assertEqual(owner.observation["status"], "CLOSED")
        self.assertTrue(owner.observation["owned_handles_closed"])
        self.assertEqual(owner.observation["schema"], subject.ACTION_SCHEMA)
        self.assertFalse(self.provider_index.exists())

    def test_same_activation_has_disjoint_indexes_and_shared_cas(self):
        value = {"same actual bytes": True}
        with self.provider() as provider, self.hold() as action:
            provider_ref = provider.retain("REQUEST", value)
            provider_before = self.provider_index.read_bytes()
            action_ref = action.retain("REQUEST_FRAME", value)
            self.assertEqual(provider_ref["digest"], action_ref["digest"])
            self.assertEqual(self.provider_index.read_bytes(), provider_before)
            self.assertNotEqual(provider.observation["index_digest"], action.observation["index_digest"])
            self.assertEqual(provider.observation["schema"], subject.SCHEMA)
            self.assertEqual(action.observation["schema"], subject.ACTION_SCHEMA)
        self.assertEqual(self.original_stat(self.blob(action_ref["digest"])).st_nlink, 1)
        self.original_fstat(self.control_fd)

    def test_provider_default_header_and_reference_bytes_are_unchanged(self):
        with self.provider() as owner:
            header_raw = canonical_json({"schema": "aragorn/pi-core-provider-evidence-index/v1",
                "authority": "DURABLE_REFERENCE_PREFIX_ONLY_NOT_COMPLETED_CAPTURE", "sequence": 0,
                "kind": "HEADER", "activation_id": self.activation["activation_id"],
                "activation_digest": canonical_digest(self.activation)}) + b"\n"
            self.assertEqual(self.provider_index.read_bytes(), header_raw)
            ref = owner.retain("REQUEST", {"value": 1})
            expected = {"schema": "aragorn/pi-core-provider-evidence-reference/v1", "sequence": 1,
                "previous_prefix_digest": subject._digest(header_raw), **ref}
            self.assertEqual(self.provider_index.read_bytes(), header_raw + canonical_json(expected) + b"\n")
        self.assertFalse(self.index.exists())

    def test_provider_kind_is_not_an_action_kind(self):
        with self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.hold() as owner:
                owner.retain("SERVICE_PERMIT", {"not action": True})
        self.assertEqual(self.assert_observation(caught.exception)["references"], [])
        self.assertFalse(self.provider_index.exists())

    def test_action_kind_does_not_expand_provider_defaults(self):
        with self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.provider() as owner:
                owner.retain("ACTION_DONE", {"not provider": True})
        self.assertTrue(hasattr(caught.exception, "pi_provider_evidence_observation"))
        self.assertFalse(hasattr(caught.exception, "pi_action_evidence_observation"))
        self.assertFalse(self.index.exists())

    def test_no_namespace_or_mode_argument_is_accepted(self):
        for field in ("namespace", "kind", "action", "index_path"):
            with self.subTest(field=field), self.assertRaises(TypeError):
                self.hold(**{field: "../other"})
        self.assertFalse(self.index.exists())

    def test_action_index_is_never_reopened_and_provider_is_untouched(self):
        with self.hold():
            pass
        action_before = self.index.read_bytes()
        with self.provider():
            pass
        provider_before = self.provider_index.read_bytes()
        with self.assertRaises(FileExistsError) as caught:
            with self.hold():
                self.fail("must not reopen")
        self.assert_observation(caught.exception, "REFUSED")
        self.assertEqual(self.index.read_bytes(), action_before)
        self.assertEqual(self.provider_index.read_bytes(), provider_before)

    def test_symlink_action_index_is_never_followed(self):
        target = self.root / "unrelated"
        target.write_bytes(b"preserve")
        self.index.symlink_to(target)
        with self.assertRaises(FileExistsError):
            with self.hold():
                self.fail("must refuse")
        self.assertTrue(self.index.is_symlink())
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_kind_cannot_choose_path_and_record_must_be_object(self):
        for index, (kind, value) in enumerate((("../other", {}), ("ACTION_DONE", []))):
            activation = fixtures.activation()
            activation.update(activation_id=f"{index + 1:032x}", session_id=f"{index + 1:032x}", run_id=f"{index + 1:032x}")
            with self.subTest(kind=kind), self.assertRaises(subject.PiProviderEvidenceError):
                with self.hold(activation=activation) as owner:
                    owner.retain(kind, value)
            self.assertEqual(owner.observation["references"], [])

    def test_fixed_store_choice_cannot_change_after_open(self):
        with self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.hold() as owner:
                owner._storage = subject._PROVIDER_STORAGE
                owner.retain("REQUEST", {"cross index": True})
        # A mutated owner still cannot write either schema into the other index.
        self.assertEqual(len(self.index.read_bytes().splitlines()), 1)
        self.assertFalse(self.provider_index.exists())
        self.assertEqual(self.assert_observation(caught.exception)["references"], [])

    def test_nonroot_configuration_refuses_without_creating_index(self):
        self.config = replace(self.config, expected_broker_uid=1001)
        with self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.hold():
                self.fail("wrong owner")
        self.assert_observation(caught.exception, "REFUSED")
        self.assertFalse(self.index.exists())

    def test_borrowed_handle_is_preserved_on_success_and_refusal(self):
        with self.hold():
            pass
        self.original_fstat(self.control_fd)
        with self.assertRaises(FileExistsError):
            with self.hold():
                self.fail("no resume")
        self.original_fstat(self.control_fd)

    def test_missing_store_is_not_provisioned(self):
        self.sha.rmdir()
        with self.assertRaises(FileNotFoundError) as caught:
            with self.hold():
                self.fail("missing store")
        self.assert_observation(caught.exception, "REFUSED")
        self.assertFalse(self.sha.exists())

    def test_record_count_bound_is_shared_without_adding_capture_authority(self):
        self.assertEqual((subject._MAX_RECORDS, subject._MAX_RECORD, subject._MAX_INDEX),
                         (64, 4 * 1024 * 1024, 64 * 1024))
        with self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.hold() as owner:
                for index in range(64):
                    owner.retain("CHECK", {"actual": index})
                owner.retain("CHECK", {"actual": 65})
        observation = self.assert_observation(caught.exception)
        self.assertEqual(len(observation["references"]), 64)
        self.assertEqual(len(self.index.read_bytes().splitlines()), 65)

    def test_record_byte_bound_precedes_blob_write(self):
        with mock.patch.object(subject._HeldCAS, "put_expected", side_effect=AssertionError("must not write")) as put:
            with self.assertRaises(subject.PiProviderEvidenceError) as caught:
                with self.hold() as owner:
                    owner.retain("REQUEST_FRAME", {"frame": "x" * subject._MAX_RECORD})
        self.assert_observation(caught.exception)
        put.assert_not_called()

    def test_action_deadline_and_activation_expiry_are_not_renewed(self):
        with self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.hold() as owner:
                self.clock.return_value = self.activation["expires_at_monotonic_ns"]
                owner.retain("ACTION_DONE", {"late": True})
        self.assertEqual(self.assert_observation(caught.exception)["references"], [])

    def test_partial_append_preserves_verified_prefix_and_action_pending_record(self):
        original = os.write
        with self.assertRaises(OSError) as caught:
            with self.hold() as owner:
                previous = owner.observation
                def partial(fd, raw):
                    if fd == owner._index:
                        original(fd, raw[:7])
                        raise OSError("inert partial action append")
                    return original(fd, raw)
                with mock.patch.object(os, "write", side_effect=partial):
                    owner.retain("CURRENT_ATTEMPT", {"attempted": True})
        result = self.assert_observation(caught.exception)
        self.assertEqual(result["index_status"], "UNCONFIRMED")
        self.assertEqual(result["index_digest"], previous["index_digest"])
        self.assertEqual(result["pending_reference"]["kind"], "CURRENT_ATTEMPT")
        self.assertEqual(self.index.stat().st_size, previous["index_bytes"] + 7)
        self.assertEqual(result["references"], [])

    def test_cancellation_preserves_same_error_and_action_reference_prefix(self):
        error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            with self.hold() as owner:
                owner.retain("REQUEST_CONTEXT", {"captured": True})
                raise error
        self.assertIs(caught.exception, error)
        result = self.assert_observation(error, "CLOSED")
        self.assertTrue(result["owned_handles_closed"])
        self.assertEqual(result["references"][0]["kind"], "REQUEST_CONTEXT")

    def test_cas_failure_preserves_same_error_and_unknown_helper_cleanup(self):
        error = OSError("inert action blob failure")
        with mock.patch.object(subject._HeldCAS, "put_expected", side_effect=error) as put:
            with self.assertRaises(OSError) as caught:
                with self.hold() as owner:
                    owner.retain("CONTROL_READBACK", {"captured": True})
        self.assertIs(caught.exception, error)
        result = self.assert_observation(error)
        self.assertFalse(result["owned_handles_closed"])
        self.assertEqual(result["pending_reference"]["kind"], "CONTROL_READBACK")
        put.assert_called_once()

    def test_owned_close_is_one_shot_and_never_closes_borrowed_control(self):
        original, closed, index_fd = os.close, [], None
        def close(fd):
            closed.append(fd)
            original(fd)
            if fd == index_fd:
                raise OSError("inert uncertain action close")
        with mock.patch.object(os, "close", side_effect=close), self.assertRaises(subject.PiProviderEvidenceError) as caught:
            with self.hold() as owner:
                index_fd = owner._index
                owned = list(owner._fds)
        result = self.assert_observation(caught.exception)
        self.assertFalse(result["owned_handles_closed"])
        self.assertEqual(closed.count(index_fd), 1)
        self.assertTrue(set(owned) <= set(closed))
        self.assertNotIn(self.control_fd, closed)

    def test_detached_action_observation_contains_no_raw_payload(self):
        with self.hold() as owner:
            reference = owner.retain("ACTION_RESULT", {"private": "actual worker result"})
            reference["kind"] = "changed"
            detached = owner.observation
            detached["references"].clear()
            self.assertEqual(owner.observation["references"][0]["kind"], "ACTION_RESULT")
            self.assertNotIn(b"actual worker result", canonical_json(owner.observation))


def load_tests(loader, tests, pattern):
    cases = [loader.loadTestsFromTestCase(ActionEvidenceStoreTests)]
    # Only provider checks affected by the fixed sibling format/selector join.
    for name in (
        "test_exact_raw_record_and_ordered_index_are_durable_before_return",
        "test_existing_attempt_index_is_preserved_and_never_resumed",
        "test_unknown_kind_cannot_select_a_path",
        "test_constructor_is_not_a_public_authority_factory",
        "test_closed_owner_cannot_append",
    ):
        cases.append(fixtures.ProviderEvidenceTests(name))
    for name in ("test_body_cancellation_preserves_same_exception_and_storage_prefix",
                 "test_header_failure_is_not_an_empty_successful_attempt"):
        cases.append(fixtures.ProviderEvidenceFailureTests(name))
    return unittest.TestSuite(cases)
