"""Only approval custody checks; every native/filesystem edge is inert."""

import copy
import os
import stat
from dataclasses import replace
from pathlib import Path
from unittest import mock

from aragorn import pi_core_provider_approval as subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_mediation as fixtures


class ProviderApprovalTests(fixtures.InertTests):
    def setUp(self):
        super().setUp()
        self.request = fixtures.request()
        self.activation = fixtures.identity_fixtures.activation()
        values = fixtures.policy_fixtures._fixture()
        pins = {"operation_digest": canonical_digest(subject.mediation._OPERATION),
                "path_digest": canonical_digest(fixtures.route()),
                "payload_digest": canonical_digest(self.request["payload"])}
        values["policy"]["allow"][0].update(pins)
        action = values["request"]
        action.update(pins, policy_digest=canonical_digest(values["policy"]))
        self.intent = {"schema": subject.INTENT_SCHEMA, "route": fixtures.route(), "data_class": "PUBLIC",
            "payload_digest": pins["payload_digest"], "max_requests": 1,
            "request": {key: value for key, value in action.items() if key not in subject._DERIVED}}
        self.activation.update({key: action[key] for key in
                                ("runtime_digest", "active_skill_digest", "policy_digest")})
        root = Path("/var/lib/aragorn/provider-control")
        self.config = subject.broker.RuntimeActionBrokerConfig(root / "broker.sock", root / "instance.lock",
            root / "broker.lock", root, Path("/var/lib/aragorn/output"), Path("/var/lib/aragorn/staging"),
            *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
            0, 1301, 1302, action["runtime_digest"], 1201, 1202)
        self.storage = {"policy.json": values["policy"], "revocations.json": values["revocations"],
            "health.json": values["mediator_health"],
            "state.json": {"schema": "aragorn/runtime-action-broker-state/v2",
                "authority": "BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
                "minimum_revocation_generation": 3, "minimum_mediator_health_epoch": 1,
                "consumed": [], "effect_journal": None},
            "observation.json": {"schema": "aragorn/runtime-action-observation/v1",
                "authority": "SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY", "sequence": 1,
                "sensor_digest": values["policy"]["sensor_digest"], "observed_at_unix": 98,
                "expires_at_unix": 103, "active": values["active"], "measured_action": values["measured_action"]}}
        self.root = fixtures.metadata()
        self.lock = fixtures.metadata(directory=False, inode=11)
        self.lock.st_mode = stat.S_IFREG | 0o600
        self.named = {"broker.lock": self.lock}
        self.fds = {50: self.root, 51: self.lock}
        self.raw = {}
        self.temporary = ".provider-data-approval.inert"
        self.locked = False
        self.stack.enter_context(mock.patch.object(subject.broker, "_validate_config"))  # Platform guard only.
        self.stack.enter_context(mock.patch.object(subject.broker, "_require_protected_ancestry"))
        self.open_root = self.stack.enter_context(mock.patch.object(subject.broker, "_open_protected_directory", return_value=50))
        self.open_lock = self.stack.enter_context(mock.patch.object(subject.broker, "_open_lock_file", return_value=51))
        self.stack.enter_context(mock.patch.object(os, "fstat", side_effect=lambda fd: copy.copy(self.fds[fd])))
        self.stack.enter_context(mock.patch.object(os, "lstat", side_effect=lambda _: copy.copy(self.root)))
        self.stack.enter_context(mock.patch.object(os, "stat", side_effect=self.stat_named))
        self.close = self.stack.enter_context(mock.patch.object(os, "close"))
        self.sync = self.stack.enter_context(mock.patch.object(os, "fsync"))
        self.acquire = self.stack.enter_context(mock.patch.object(subject.broker, "_acquire_lock", side_effect=self.acquire_lock))
        self.unlock = self.stack.enter_context(mock.patch.object(subject.broker.fcntl, "flock", side_effect=self.unlock_lock))
        self.load = self.stack.enter_context(mock.patch.object(subject.broker, "_load_control", side_effect=self.load_control))
        for name in ("_load_state", "_evaluate_snapshot", "_advance_floors", "_commit_state",
                     "publish_runtime_control_document", "_recover_before_listen"):
            self.stack.enter_context(mock.patch.object(subject.broker, name,
                side_effect=AssertionError("approval must not mutate controls or perform recovery")))
        self.create = self.stack.enter_context(mock.patch.object(subject.broker, "create_exclusive_file_at", side_effect=self.create_file))
        self.write = self.stack.enter_context(mock.patch.object(os, "write", side_effect=self.write_file))
        self.link = self.stack.enter_context(mock.patch.object(os, "link", side_effect=self.link_file))
        self.unlink = self.stack.enter_context(mock.patch.object(os, "unlink", side_effect=self.unlink_file))
        self.readback = self.stack.enter_context(mock.patch.object(subject.broker, "_read_owned_bytes_at",
            side_effect=lambda fd, name, **kwargs: bytes(self.raw[name])))

    def stat_named(self, name, **kwargs):
        if name not in self.named:
            raise FileNotFoundError(name)
        return copy.copy(self.named[name])

    def acquire_lock(self, descriptor, deadline):
        self.assertEqual(descriptor, 51)
        self.assertFalse(self.locked)
        self.locked = True

    def unlock_lock(self, descriptor, operation):
        self.assertEqual((descriptor, operation), (51, subject.broker.fcntl.LOCK_UN))
        self.assertTrue(self.locked)
        self.locked = False

    def load_control(self, fd, path, *args):
        self.assertTrue(self.locked)
        return copy.deepcopy(self.storage[path.name])

    def create_file(self, fd, *, prefix, mode):
        self.assertTrue(self.locked)
        self.assertEqual((fd, prefix, mode), (50, ".provider-data-approval.", 0o400))
        self.fds[60] = self.named[self.temporary] = fixtures.metadata(directory=False, inode=12)
        self.raw[self.temporary] = bytearray()
        return self.temporary, 60

    def write_file(self, fd, content):
        self.assertEqual(fd, 60)
        self.raw[self.temporary].extend(content)
        self.fds[60].st_size += len(content)
        return len(content)

    def link_file(self, old, new, **kwargs):
        if new in self.named:
            raise FileExistsError(new)
        self.assertTrue(self.locked)
        self.assertEqual(kwargs, {"src_dir_fd": 50, "dst_dir_fd": 50, "follow_symlinks": False})
        self.named[new] = self.named[old]
        self.named[new].st_nlink += 1
        self.raw[new] = self.raw[old]

    def unlink_file(self, name, **kwargs):
        self.assertEqual((name, kwargs), (self.temporary, {"dir_fd": 50}))
        self.named.pop(name).st_nlink -= 1
        del self.raw[name]

    def hold(self, **options):
        return subject.hold_provider_approval(self.config, intent=options.pop("intent", self.intent),
                                              deadline=options.pop("deadline", 120.0), **options)

    def bind(self, holder, **options):
        return holder.bind(options.pop("request", self.request), options.pop("activation", self.activation),
                           deadline=options.pop("deadline", 120.0), **options)

    def assert_no_publication(self):
        self.create.assert_not_called()
        self.link.assert_not_called()
        self.write.assert_not_called()
        self.unlink.assert_not_called()

    def test_template_excludes_all_activation_derived_ids_and_detaches_intent(self):
        observed = subject.validate_intent(self.intent)
        self.assertEqual(set(observed["request"]), subject._TEMPLATE_FIELDS)
        observed["route"]["model"] = "changed"
        self.assertNotEqual(observed, self.intent)
        self.assertNotIn(b"validation-only", canonical_json(self.intent))

    def test_template_cannot_supply_session_run_tool_or_activation(self):
        for field in (*sorted(subject._DERIVED), "activation_digest"):
            changed = copy.deepcopy(self.intent)
            changed["request"][field] = "forged"
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                subject.validate_intent(changed)

    def test_unknown_intent_and_invalid_data_class_or_boolean_budget_refuse(self):
        for change in ({"extra": True}, {"data_class": []}, {"data_class": "SECRET"}, {"max_requests": True}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                subject.validate_intent({**self.intent, **change})

    def test_request_parser_and_fixed_provider_pins_are_required(self):
        for field, value in (("schema", "wrong"), ("policy_version", True), ("operation_digest", "sha256:" + "f" * 64),
                             ("path_digest", "sha256:" + "f" * 64), ("payload_digest", "sha256:" + "f" * 64)):
            changed = copy.deepcopy(self.intent)
            changed["request"][field] = value
            with self.subTest(field=field), self.assertRaises((ValueError, RuntimeError)):
                subject.validate_intent(changed)

    def test_request_lifetime_is_not_extended_or_repaired(self):
        for expires in (98, 104):
            changed = copy.deepcopy(self.intent)
            changed["request"]["expires_at_unix"] = expires
            with self.subTest(expires=expires), self.assertRaisesRegex(RuntimeError, "LIFETIME"):
                subject.validate_intent(changed)

    def test_hold_and_guard_only_read_existing_controls_under_short_lock(self):
        before = copy.deepcopy(self.storage)
        with self.hold() as holder:
            self.assertIs(holder.config, self.config)
            self.assertEqual(holder.route_digest, canonical_digest(self.intent["route"]))
            self.assertFalse(self.locked)
            holder.guard(deadline=110)
            self.assertFalse(self.locked)
        self.assertEqual(self.storage, before)
        self.assert_no_publication()
        self.assertEqual(self.close.call_args_list, [mock.call(51), mock.call(50)])

    def test_holder_properties_are_read_only(self):
        with self.hold() as holder:
            for field in ("config", "route_digest"):
                with self.subTest(field=field), self.assertRaises(AttributeError):
                    setattr(holder, field, object())

    def test_only_factory_and_active_same_process_root_custody_can_guard(self):
        with self.assertRaisesRegex(RuntimeError, "FACTORY"):
            subject.PiProviderApproval()
        with self.hold() as holder:
            with mock.patch.object(os, "getpid", return_value=1001), self.assertRaises(RuntimeError):
                holder.guard(deadline=110)
            with mock.patch.object(os, "geteuid", return_value=1201), self.assertRaises(RuntimeError):
                holder.guard(deadline=110)
        with self.assertRaisesRegex(RuntimeError, "CUSTODY"):
            holder.guard(deadline=110)

    def test_deadline_cannot_be_extended(self):
        with self.hold(deadline=110) as holder, self.assertRaises(RuntimeError):
            holder.guard(deadline=111)

    def test_expired_or_future_request_refuses_without_renewal(self):
        for now in (97, 103):
            self.wall.return_value = now
            with self.subTest(now=now), self.assertRaisesRegex(RuntimeError, "EXPIRED_OR_FUTURE"):
                with self.hold():
                    self.fail("expired intent entered")
        self.assert_no_publication()

    def test_nonroot_config_and_runtime_mismatch_refuse_before_open(self):
        for config in (replace(self.config, expected_broker_uid=4),
                       replace(self.config, expected_runtime_uid=None),
                       replace(self.config, expected_runtime_digest="sha256:" + "f" * 64)):
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                with subject.hold_provider_approval(config, intent=self.intent, deadline=120):
                    self.fail("invalid config entered")
        self.open_root.assert_not_called()

    def test_reserved_control_names_refuse(self):
        for name in (subject.mediation.APPROVAL_NAME, "provider-activation-forged.json"):
            config = replace(self.config, policy_path=self.config.control_root / name)
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "RESERVED"):
                with subject.hold_provider_approval(config, intent=self.intent, deadline=120):
                    self.fail("reserved path entered")

    def test_existing_approval_is_never_adopted(self):
        self.named[subject.mediation.APPROVAL_NAME] = fixtures.metadata(directory=False, inode=15)
        with self.assertRaises(RuntimeError):
            with self.hold():
                self.fail("existing approval adopted")
        self.assert_no_publication()

    def test_legacy_state_is_not_migrated(self):
        state = self.storage["state.json"]
        state["schema"] = "aragorn/runtime-action-broker-state/v1"
        del state["effect_journal"]
        with self.assertRaisesRegex(RuntimeError, "RECOVERY_REQUIRED"):
            with self.hold():
                self.fail("migration accepted")
        self.assertNotIn("effect_journal", state)
        self.assert_no_publication()

    def test_pending_recovery_or_malformed_state_blocks(self):
        self.storage["state.json"]["effect_journal"] = {"status": "PENDING"}
        with self.assertRaises(RuntimeError):
            with self.hold():
                self.fail("pending state accepted")
        self.assert_no_publication()

    def test_policy_changes_after_hold_block_publication(self):
        with self.hold() as holder:
            self.storage["policy.json"]["id"] = "changed-policy"
            with self.assertRaisesRegex(RuntimeError, "POLICY_MISMATCH"):
                self.bind(holder)
        self.assert_no_publication()

    def test_health_failure_or_rollback_and_revocation_block(self):
        cases = (("health.json", "status", "unhealthy"), ("health.json", "epoch", 0),
                 ("health.json", "expires_at_unix", 100), ("revocations.json", "generation", 2),
                 ("revocations.json", "skill_digests", [self.intent["request"]["active_skill_digest"]]))
        for name, key, value in cases:
            before = copy.deepcopy(self.storage[name])
            self.storage[name][key] = value
            with self.subTest(name=name, key=key), self.assertRaises((ValueError, RuntimeError)):
                with self.hold():
                    self.fail("unready controls accepted")
            self.storage[name] = before
        self.assert_no_publication()

    def test_missing_observation_is_not_synthesized(self):
        del self.storage["observation.json"]
        with self.assertRaises(KeyError):
            with self.hold():
                self.fail("missing observation replaced")
        self.assert_no_publication()

    def test_external_intent_mutation_does_not_change_held_authority(self):
        with self.hold() as holder:
            self.intent["route"]["model"] = "different"
            approval = self.bind(holder)
        self.assertEqual(approval["route"], fixtures.route())

    def test_internal_intent_mutation_is_detected(self):
        with self.hold() as holder:
            holder._intent["max_requests"] = 2
            with self.assertRaisesRegex(RuntimeError, "INTENT_CHANGED"):
                holder.guard(deadline=110)
        self.assert_no_publication()

    def test_named_root_or_lock_substitution_is_detected(self):
        with self.hold() as holder:
            with mock.patch.object(os, "lstat", return_value=fixtures.metadata(inode=99)), self.assertRaises(RuntimeError):
                holder.guard(deadline=110)
            self.named["broker.lock"] = fixtures.metadata(directory=False, inode=99)
            with self.assertRaisesRegex(RuntimeError, "LOCK_CHANGED"):
                holder.guard(deadline=110)
        self.assert_no_publication()

    def test_bind_derives_only_real_ids_and_publishes_existing_approval_schema(self):
        before = copy.deepcopy(self.storage)
        with self.hold() as holder:
            approval = self.bind(holder)
            self.assertEqual(approval["activation_digest"], canonical_digest(self.activation))
            for key, value in self.intent["request"].items():
                self.assertEqual(approval["request"][key], value)
            self.assertEqual(approval["request"]["session_id"], self.activation["activation_id"])
            self.assertEqual(approval["request"]["run_id"], self.activation["activation_id"])
            self.assertEqual(approval["request"]["tool_call_id"], canonical_digest(self.request))
            self.assertEqual(approval["schema"], subject.mediation.APPROVAL_SCHEMA)
            self.assertNotIn(b"validation-only", canonical_json(approval))
            holder.guard(deadline=110)
        self.assertEqual(self.storage, before)
        self.assertEqual(bytes(self.raw[subject.mediation.APPROVAL_NAME]), canonical_json(approval))
        self.assertNotIn(self.temporary, self.named)
        self.assertEqual(self.named[subject.mediation.APPROVAL_NAME].st_nlink, 1)
        self.link.assert_called_once()
        self.unlink.assert_called_once()

    def test_second_bind_refuses_without_republishing(self):
        with self.hold() as holder:
            self.bind(holder)
            with self.assertRaisesRegex(RuntimeError, "ALREADY_ATTEMPTED"):
                self.bind(holder)
        self.link.assert_called_once()

    def test_changed_prompt_or_model_refuses_before_publication(self):
        for key in ("prompt", "model"):
            request = copy.deepcopy(self.request)
            if key == "prompt":
                request["payload"]["messages"][1]["content"] += " changed"
            else:
                request["payload"]["model"]["id"] = "different"
            with self.subTest(key=key), self.hold() as holder:
                with self.assertRaises(RuntimeError):
                    self.bind(holder, request=request)
                with self.assertRaisesRegex(RuntimeError, "ALREADY_ATTEMPTED"):
                    self.bind(holder)
        self.assert_no_publication()

    def test_activation_uid_expiry_or_pins_cannot_be_substituted(self):
        for key, value in (("uid", 999), ("expires_at_monotonic_ns", 100_000_000_000),
                           ("runtime_digest", "sha256:" + "f" * 64),
                           ("policy_digest", "sha256:" + "f" * 64), ("session_id", "b" * 32)):
            activation = {**self.activation, key: value}
            with self.subTest(key=key), self.hold() as holder, self.assertRaises(RuntimeError):
                self.bind(holder, activation=activation)
        self.assert_no_publication()

    def test_preexisting_actual_activation_claim_is_retained_and_refused(self):
        name = subject.mediation._claim_name(self.activation)
        self.named[name] = fixtures.metadata(directory=False, inode=77)
        with self.hold() as holder, self.assertRaises(RuntimeError):
            self.bind(holder)
        self.assertIn(name, self.named)
        self.assert_no_publication()

    def test_guard_survives_legitimate_consumption_without_erasing_claim(self):
        name = subject.mediation._claim_name(self.activation)
        with self.hold() as holder:
            self.bind(holder)
            self.named[name] = fixtures.metadata(directory=False, inode=77)
            self.storage["state.json"]["consumed"] = [{"request_digest": canonical_digest(self.request),
                "observation_digest": canonical_digest(self.storage["observation.json"]), "expires_at_unix": 103}]
            self.storage["state.json"]["minimum_mediator_health_epoch"] = 2
            self.storage["health.json"]["epoch"] = 2
            holder.guard(deadline=110)
        self.assertIn(name, self.named)
        self.assertIn(subject.mediation.APPROVAL_NAME, self.named)

    def test_changed_published_approval_metadata_is_detected(self):
        with self.hold() as holder:
            self.bind(holder)
            self.named[subject.mediation.APPROVAL_NAME].st_mtime_ns += 1
            with self.assertRaisesRegex(RuntimeError, "APPROVAL_CHANGED"):
                holder.guard(deadline=110)
        self.assertIn(subject.mediation.APPROVAL_NAME, self.named)

    def test_changed_published_approval_bytes_are_detected(self):
        with self.hold() as holder:
            self.bind(holder)
            self.raw[subject.mediation.APPROVAL_NAME][0] = ord("[")
            with self.assertRaisesRegex(RuntimeError, "APPROVAL_CHANGED"):
                holder.guard(deadline=110)

    def test_name_substitution_during_readback_is_detected(self):
        with self.hold() as holder:
            self.bind(holder)
            def substituted(fd, name, **kwargs):
                raw = bytes(self.raw[name])
                self.named[name] = copy.copy(self.named[name])
                self.named[name].st_ino = 98
                return raw
            self.readback.side_effect = substituted
            with self.assertRaisesRegex(RuntimeError, "APPROVAL_CHANGED"):
                holder.guard(deadline=110)

    def test_zero_progress_write_retains_failure_and_cannot_retry(self):
        self.write.side_effect = lambda *_: 0
        with self.hold() as holder:
            with self.assertRaisesRegex(RuntimeError, "WRITE_STALLED"):
                self.bind(holder)
            with self.assertRaisesRegex(RuntimeError, "ALREADY_ATTEMPTED"):
                self.bind(holder)
        self.assertIn(self.temporary, self.named)
        self.assertNotIn(subject.mediation.APPROVAL_NAME, self.named)
        self.unlink.assert_not_called()

    def test_partial_write_failure_retains_bytes(self):
        def partial(fd, data):
            self.write_file(fd, data[:7])
            self.write.side_effect = OSError("inert write failure")
            return 7
        self.write.side_effect = partial
        with self.hold() as holder, self.assertRaises(OSError):
            self.bind(holder)
        self.assertEqual(len(self.raw[self.temporary]), 7)
        self.unlink.assert_not_called()
        self.link.assert_not_called()

    def test_temp_fsync_failure_retains_candidate(self):
        self.sync.side_effect = OSError("inert fsync failure")
        with self.hold() as holder, self.assertRaises(OSError):
            self.bind(holder)
        self.assertIn(self.temporary, self.named)
        self.link.assert_not_called()
        self.unlink.assert_not_called()

    def test_absent_only_link_race_never_replaces_or_adopts(self):
        def race(old, new, **kwargs):
            self.named[new] = fixtures.metadata(directory=False, inode=90)
            raise FileExistsError(new)
        self.link.side_effect = race
        with self.hold() as holder, self.assertRaises(FileExistsError):
            self.bind(holder)
        self.assertEqual(self.named[subject.mediation.APPROVAL_NAME].st_ino, 90)
        self.assertIn(self.temporary, self.named)
        self.unlink.assert_not_called()

    def test_ambiguous_post_link_failure_preserves_both_names(self):
        def sync(fd):
            if fd == 50:
                raise OSError("inert directory fsync failure")
        self.sync.side_effect = sync
        with self.hold() as holder, self.assertRaises(OSError):
            self.bind(holder)
        self.assertIn(subject.mediation.APPROVAL_NAME, self.named)
        self.assertIn(self.temporary, self.named)
        self.assertEqual(self.named[subject.mediation.APPROVAL_NAME].st_nlink, 2)
        self.unlink.assert_not_called()

    def test_final_readback_failure_retains_published_approval(self):
        self.readback.side_effect = lambda *_args, **_kwargs: b"changed"
        with self.hold() as holder, self.assertRaisesRegex(RuntimeError, "READBACK_CHANGED"):
            self.bind(holder)
        self.assertIn(subject.mediation.APPROVAL_NAME, self.named)
        self.assertEqual(self.unlink.call_count, 1)

    def test_teardown_does_not_require_fresh_request_authority(self):
        with self.hold() as holder:
            self.bind(holder)
            self.wall.return_value = 500
        self.assertIn(subject.mediation.APPROVAL_NAME, self.named)
        self.assertEqual(self.close.call_args_list, [mock.call(60), mock.call(51), mock.call(50)])

    def test_close_failure_is_reported_without_erasing_approval(self):
        with mock.patch.object(subject.broker, "_release_lock_and_close", return_value=OSError("inert close failure")):
            with self.assertRaisesRegex(RuntimeError, "CLOSE_FAILED"):
                with self.hold() as holder:
                    self.bind(holder)
        self.assertIn(subject.mediation.APPROVAL_NAME, self.named)

    def test_lock_timeout_closes_owned_descriptors_without_writes(self):
        self.acquire.side_effect = subject.broker.RuntimeActionBrokerError("lock timed out")
        with self.assertRaisesRegex(RuntimeError, "timed out"):
            with self.hold():
                self.fail("timed out lock entered")
        self.assertEqual(self.close.call_args_list, [mock.call(51), mock.call(50)])
        self.assert_no_publication()
