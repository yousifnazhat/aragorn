"""Focused boundary/publication checks using inert owned-source transitions only."""

import copy
from pathlib import Path
import unittest
from unittest import mock

from aragorn import pi_core_provider_observation as subject
from aragorn import pi_core_provider_approval as approval_subject
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from tests import test_pi_core_provider_approval as approval_fixtures
from tests import test_pi_core_provider_mediation as fixtures
from tests import test_pi_core_node_source_observer as source_fixtures


def provider_inputs():
    """Actual inert producer output plus compatible acquired identity records.

    These are unit fixtures, not captured deployment or qualification evidence.
    No new passing observation or replacement workload sample is manufactured.
    """
    captured = source_fixtures.build_inert_node_source_capture()
    source = captured["record"]
    activation = fixtures.identity_fixtures.activation()
    activation.update(pid=source["worker"]["pid"], uid=source["worker"]["uid"], gid=source["worker"]["gid"],
        start_time_ticks=source["worker"]["start_ticks"], cgroup=source["worker"]["cgroup"],
        boot_id=source["clock"]["boot_id"], runtime_digest=source["bindings"]["runtime_digest"],
        deployment_digest=source["bindings"]["deployment_digest"], executable_digest=source["bindings"]["node_digest"])
    request = fixtures.request()
    values = fixtures.policy_fixtures._fixture()
    pins = dict(runtime_digest=activation["runtime_digest"], active_skill_digest=activation["active_skill_digest"],
        operation_digest=canonical_digest(subject.mediation._OPERATION), path_digest=canonical_digest(fixtures.route()),
        payload_digest=canonical_digest(request["payload"]))
    values["policy"]["allow"][0].update(pins)
    action = values["request"]
    action.update(pins, session_id=activation["session_id"], run_id=activation["run_id"],
                  tool_call_id=canonical_digest(request), policy_digest=canonical_digest(values["policy"]))
    activation["policy_digest"] = action["policy_digest"]
    approval = dict(schema=subject.mediation.APPROVAL_SCHEMA, authority=subject.mediation.APPROVAL_AUTHORITY,
        activation_digest=canonical_digest(activation), route=fixtures.route(), data_class="PUBLIC",
        payload_digest=pins["payload_digest"], max_requests=1, request=action)
    measured = {key: copy.deepcopy(activation[key]) for key in subject.identity._ATTRIBUTION_FIELDS}
    measured.update(schema=subject.identity.process.ATTRIBUTION_SCHEMA,
        authority=subject.identity.process.ATTRIBUTION_AUTHORITY,
        skill_path="/var/lib/aragorn/admitted/version/SKILL.md")
    lineage = dict(schema=subject.lineage_contract.VERIFIED_LINEAGE_SCHEMA,
        authority=subject.lineage_contract.VERIFIED_LINEAGE_AUTHORITY,
        active_record_digest=activation["active_record_digest"], context_digest=activation["install_context_digest"],
        manifest_digest=activation["source_manifest_digest"], tree_digest=activation["tree_digest"],
        version_path="version", target_name="skill", runtime_skill_path=measured["skill_path"],
        active_skill_digest=activation["active_skill_digest"], root_device=1, root_inode=2,
        active_link_device=1, active_link_inode=3, version_device=1, version_inode=4, skill_device=1, skill_inode=5)
    grant = dict(schema=subject.capability.GRANT_SCHEMA, authority=subject.capability.GRANT_AUTHORITY,
        grant_id="b" * 64, source_manifest_digest=activation["source_manifest_digest"],
        install_context_digest=activation["install_context_digest"], runtime_profile_digest=activation["profile_digest"],
        runtime_digest=activation["runtime_digest"], active_skill_digest=activation["active_skill_digest"],
        sensor_digest=values["policy"]["sensor_digest"], policy_digest=action["policy_digest"], policy_version=1,
        operation_digest=canonical_digest({"schema": "aragorn/runtime-file-operation/v1", "operation": "create"}),
        issued_at_unix=95, expires_at_unix=105, max_actions=1)
    root = Path("/var/lib/aragorn/provider-control")
    config = subject.broker.RuntimeActionBrokerConfig(root / "broker.sock", root / "instance.lock", root / "broker.lock",
        root, Path("/var/lib/aragorn/output"), Path("/var/lib/aragorn/staging"),
        *(root / (name + ".json") for name in ("policy", "revocations", "health", "observation", "state")),
        0, 1301, 1302, activation["runtime_digest"], activation["uid"], activation["gid"])
    values["mediator_health"]["runtime_digest"] = activation["runtime_digest"]
    storage = {"policy.json": values["policy"], "revocations.json": values["revocations"],
        "health.json": values["mediator_health"],
        "state.json": dict(schema="aragorn/runtime-action-broker-state/v2",
            authority="BROKER_STATE_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY", minimum_revocation_generation=3,
            minimum_mediator_health_epoch=1, consumed=[], effect_journal=None),
        "observation.json": dict(schema="aragorn/runtime-action-observation/v1",
            authority="SENSOR_OBSERVATION_ONLY_NOT_EFFECT_AUTHORITY", sequence=1,
            sensor_digest=grant["sensor_digest"], observed_at_unix=98, expires_at_unix=103,
            active=None, measured_action=None)}
    return dict(request=request, activation=activation, approval=approval, measured=measured, lineage=lineage,
        grant=grant, source_capture=source, boundary_boottime_ns=captured["arguments"]["boundary_boottime_ns"],
        now_unix=100, config=config, storage=storage)


class SourceBoundaryTests(fixtures.InertTests):
    def setUp(self):
        super().setUp()
        self.values = provider_inputs()
        self.source = self.values["source_capture"]

    def validate(self, **changes):
        values = {**self.values, **changes}
        return subject.validate_provider_source_capture(values["source_capture"], values["activation"],
            boundary_boottime_ns=values["boundary_boottime_ns"])

    def test_actual_inert_owner_capture_returns_detached_boundary_not_health_authority(self):
        result = self.validate()
        self.assertEqual(set(result), {"challenge", "clock", "boundary_boottime_ns"})
        self.assertEqual(result["challenge"], {key: self.source["events"][-1][key]
                                              for key in ("nonce", "issued_ns", "deadline_ns")})
        self.assertNotEqual(self.source["bindings"]["profile_digest"], self.values["activation"]["profile_digest"])
        result["clock"]["boot_id"] = "changed"
        self.assertNotEqual(result["clock"], self.source["clock"])

    def test_only_node_v2_held_arm64_snapshot_is_accepted(self):
        for key, value in (("schema", "aragorn/pi-core-source-observation/v1"), ("state", "CLOSED"),
                           ("architecture", "linux-x86_64")):
            source = copy.deepcopy(self.source)
            source[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_missing_or_extra_snapshot_fields_refuse(self):
        for extra in (False, True):
            source = copy.deepcopy(self.source)
            if extra:
                source["health_verified"] = True
            else:
                del source["accounting"]
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_foreign_worker_generation_user_group_and_cgroup_refuse(self):
        for key in ("pid", "start_ticks", "uid", "gid", "cgroup"):
            source = copy.deepcopy(self.source)
            source["worker"][key] = "/foreign" if key == "cgroup" else source["worker"][key] + 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_foreign_runtime_deployment_and_node_pins_refuse(self):
        for key in ("runtime_digest", "deployment_digest", "node_digest"):
            source = copy.deepcopy(self.source)
            source["bindings"][key] = "sha256:" + "f" * 64
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_clock_boot_domain_or_missing_namespace_refuses(self):
        for key, value in (("boot_id", "11111111-2222-3333-4444-555555555555"),
                           ("clock_id", "CLOCK_MONOTONIC"), ("time_namespace_inode", 0)):
            source = copy.deepcopy(self.source)
            source["clock"][key] = value
            with self.subTest(key=key), self.assertRaises((RuntimeError, ValueError)):
                self.validate(source_capture=source)

    def test_boundary_freshness_includes_exact_200ms_but_not_more_or_future_capture(self):
        stamp = self.source["events"][-1]["boottime_ns"]
        self.validate(boundary_boottime_ns=stamp + 200_000_000)
        for boundary in (stamp + 200_000_001, stamp - 1, True):
            with self.subTest(boundary=boundary), self.assertRaises(RuntimeError):
                self.validate(boundary_boottime_ns=boundary)

    def test_nonfinal_challenge_or_sequence_loss_refuses(self):
        for mutate in (lambda source: source["events"][-1].update(kind="ALL_STOP"),
                       lambda source: source["events"][1].update(seq=99),
                       lambda source: source["events"][1].update(boottime_ns=0)):
            source = copy.deepcopy(self.source)
            mutate(source)
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_challenge_budget_nonce_and_stopped_proof_refuse(self):
        for key, value in (("deadline_ns", 999999999), ("nonce", "wrong"), ("all_stopped", False),
                           ("tasks", []), ("epoch", 999), ("stops_after", 999), ("stops_before", 999)):
            source = copy.deepcopy(self.source)
            source["events"][-1][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_each_challenged_task_requires_fresh_resume_then_stop(self):
        for kind in ("RESUME", "STOP"):
            source = copy.deepcopy(self.source)
            event = next(event for event in reversed(source["events"]) if event["kind"] == kind)
            event["boottime_ns"] = source["events"][-1]["issued_ns"] - 1
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_duplicate_challenge_nonce_refuses(self):
        source = copy.deepcopy(self.source)
        repeated = copy.deepcopy(source["events"][-1])
        repeated.update(seq=repeated["seq"] + 1, boottime_ns=repeated["boottime_ns"] + 1)
        source["events"].append(repeated)
        source["accounting"]["events_retained"] += 1
        with self.assertRaises(RuntimeError):
            self.validate(source_capture=source, boundary_boottime_ns=repeated["boottime_ns"] + 1)

    def test_missing_changed_or_boolean_loss_accounting_refuses(self):
        for key in self.source["accounting"]:
            source = copy.deepcopy(self.source)
            source["accounting"][key] += 1
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)
        source = copy.deepcopy(self.source)
        source["accounting"]["refusals"] = False
        with self.assertRaises(RuntimeError):
            self.validate(source_capture=source)

    def test_retained_refusal_and_cleanup_are_not_live_health(self):
        for kind in ("REFUSED", "CLEANUP"):
            source = copy.deepcopy(self.source)
            source["events"][0]["kind"] = kind
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_required_source_read_gap_changed_pin_or_partial_delivery_refuses(self):
        for mutate in (lambda event: event.update(offset=1), lambda event: event.update(digest="sha256:" + "f" * 64),
                       lambda event: event.update(path="/not-acquired")):
            source = copy.deepcopy(self.source)
            mutate(next(event for event in source["events"] if event["kind"] == "READ_ENTER"))
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)
        source = copy.deepcopy(self.source)
        next(event for event in source["events"] if event["kind"] == "READ_EXIT")["result"] -= 1
        source["accounting"]["bytes_read"] -= 1
        with self.assertRaisesRegex(RuntimeError, "INCOMPLETE"):
            self.validate(source_capture=source)

    def test_pending_source_read_or_loader_mapping_refuses_even_consistent_counts(self):
        for kind, counter in (("READ_EXIT", "reads_exited"), ("READ_EXIT", "maps_entered")):
            source = copy.deepcopy(self.source)
            if counter == "reads_exited":
                event = next(event for event in source["events"] if event["kind"] == kind)
                event["kind"] = "MAP_ENTER"
                source["accounting"].update(reads_exited=0, pending_reads=1, bytes_read=0, maps_entered=1)
            else:
                source["events"][0]["kind"] = "MAP_ENTER"
                source["accounting"][counter] += 1
            with self.subTest(counter=counter), self.assertRaises(RuntimeError):
                self.validate(source_capture=source)

    def test_ordinary_pending_wait_is_not_misclassified_as_loss(self):
        source = copy.deepcopy(self.source)
        event = next(event for event in reversed(source["events"]) if event["kind"] == "STOP")
        event.update(op="ENTRY", syscall=98)
        source["accounting"]["pending_syscalls"] = 1
        self.validate(source_capture=source)

    def test_classified_pending_io_is_allowed_but_unclassified_read_refuses(self):
        source = copy.deepcopy(self.source)
        stop = next(event for event in reversed(source["events"]) if event["kind"] == "STOP")
        stop.update(op="ENTRY", syscall=63)
        source["accounting"]["pending_syscalls"] = 1
        with self.assertRaisesRegex(RuntimeError, "PENDING_INPUT"):
            self.validate(source_capture=source)
        challenge = source["events"][-1]
        source["events"].insert(-1, dict(seq=challenge["seq"], boottime_ns=challenge["boottime_ns"],
            kind="IO_ENTER", pid=stop["pid"], call_id=stop["seq"]))
        challenge["seq"] += 1
        source["accounting"]["events_retained"] += 1
        source["accounting"]["io_entered"] += 1
        self.validate(source_capture=source)

    def test_orphan_io_accounting_refuses_even_with_matching_declared_count(self):
        source = copy.deepcopy(self.source)
        challenge = source["events"][-1]
        source["events"].insert(-1, dict(seq=challenge["seq"], boottime_ns=challenge["boottime_ns"],
            kind="IO_EXIT", pid=self.values["activation"]["pid"], call_id=999))
        challenge["seq"] += 1
        source["accounting"]["events_retained"] += 1
        source["accounting"]["io_exited"] += 1
        with self.assertRaisesRegex(RuntimeError, "IO_JOIN"):
            self.validate(source_capture=source)

    def test_event_and_record_bounds_are_not_widened(self):
        source = copy.deepcopy(self.source)
        source["events"] = [source["events"][0]] * 4097
        with self.assertRaises(RuntimeError):
            self.validate(source_capture=source)
        source = copy.deepcopy(self.source)
        source["loaders"] = ["x" * (4 * 1024 * 1024)]
        with self.assertRaises(RuntimeError):
            self.validate(source_capture=source)


class PublicationTests(fixtures.InertTests):
    def setUp(self):
        super().setUp()
        self.values = provider_inputs()
        self.storage = self.values.pop("storage")
        self.config = self.values.pop("config")
        self.load = self.stack.enter_context(mock.patch.object(subject.broker, "_load_control",
            side_effect=lambda fd, path, *args: copy.deepcopy(self.storage[path.name])))
        self.write = self.stack.enter_context(mock.patch.object(subject.broker, "_atomic_publish_at",
            side_effect=self.store))
        for name in ("_publish_observed_state_locked", "_commit_state", "_advance_floors", "_evaluate_snapshot"):
            self.stack.enter_context(mock.patch.object(subject.broker, name,
                side_effect=AssertionError("observation must not renew health, change state, or decide")))

    def store(self, fd, name, raw, **kwargs):
        self.assertEqual((fd, name, kwargs), (50, "observation.json", {"expected_uid": 0}))
        self.storage[name] = subject.broker._parse_canonical_document(raw, "test publication")

    def publish(self, **changes):
        return subject.publish_provider_observation(50, self.config, **{**self.values, **changes})

    def test_actual_request_is_published_once_with_unchanged_global_controls(self):
        before = copy.deepcopy(self.storage)
        result = self.publish()
        self.write.assert_called_once()
        self.assertEqual(result, self.storage["observation.json"])
        self.assertEqual(result["sequence"], 2)
        self.assertEqual(result["active"]["tool_call_id"], canonical_digest(self.values["request"]))
        self.assertEqual(result["measured_action"]["payload_digest"], canonical_digest(self.values["request"]["payload"]))
        for name in before.keys() - {"observation.json"}:
            self.assertEqual(self.storage[name], before[name])
        self.assertEqual({call.args[1].name for call in self.load.call_args_list}, {"policy.json", "observation.json"})
        self.assertNotIn("verdict", result)

    def test_existing_active_anchor_is_advanced_without_adopting_its_attribution(self):
        first = self.publish()
        first["active"]["tool_call_id"] = "previous-call"
        first["measured_action"]["tool_call_id"] = "previous-call"
        self.storage["observation.json"] = first
        result = self.publish()
        self.assertEqual(result["sequence"], 3)
        self.assertEqual(result["active"]["tool_call_id"], canonical_digest(self.values["request"]))

    def test_observation_expiry_never_renews_action_or_grant(self):
        grant = copy.deepcopy(self.values["grant"])
        grant["expires_at_unix"] = 101
        result = self.publish(grant=grant)
        self.assertEqual((result["observed_at_unix"], result["expires_at_unix"]), (100, 101))
        self.assertEqual(self.values["approval"]["request"]["expires_at_unix"], 103)

    def test_expired_or_future_action_refuses_before_publication(self):
        for now in (97, 103):
            with self.subTest(now=now), self.assertRaises(RuntimeError):
                self.publish(now_unix=now)
        self.write.assert_not_called()

    def test_changed_payload_route_tool_or_activation_refuses(self):
        for key, value in (("sequence", 2), ("activation_id", "b" * 32), ("route_digest", "sha256:" + "f" * 64)):
            request = copy.deepcopy(self.values["request"])
            request[key] = value
            with self.subTest(key=key), self.assertRaises((RuntimeError, ValueError)):
                self.publish(request=request)
        request = copy.deepcopy(self.values["request"])
        request["payload"]["messages"][1]["content"] += " changed"
        with self.assertRaises(RuntimeError):
            self.publish(request=request)
        self.write.assert_not_called()

    def test_measured_worker_or_mounted_view_substitution_refuses(self):
        for key, value in (("pid", 999), ("profile_digest", "sha256:" + "f" * 64),
                           ("mount_namespace", {"device": 2, "inode": 4})):
            measured = copy.deepcopy(self.values["measured"])
            measured[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.publish(measured=measured)
        self.write.assert_not_called()

    def test_lineage_bytes_version_and_actual_skill_path_remain_bound(self):
        for key in ("context_digest", "manifest_digest", "tree_digest", "active_record_digest", "active_skill_digest",
                    "version_path", "runtime_skill_path", "authority"):
            lineage = copy.deepcopy(self.values["lineage"])
            lineage[key] = "different"
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.publish(lineage=lineage)
        self.write.assert_not_called()

    def test_grant_sensor_runtime_profile_policy_and_install_pins_remain_bound(self):
        for key in ("sensor_digest", "runtime_digest", "runtime_profile_digest", "policy_digest",
                    "source_manifest_digest", "install_context_digest", "active_skill_digest"):
            grant = copy.deepcopy(self.values["grant"])
            grant[key] = "sha256:" + "f" * 64
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.publish(grant=grant)
        self.write.assert_not_called()

    def test_create_grant_is_not_relabelled_as_provider_effect_authority(self):
        before = copy.deepcopy(self.values["grant"])
        self.assertNotEqual(before["operation_digest"], self.values["approval"]["request"]["operation_digest"])
        self.publish()
        self.assertEqual(self.values["grant"], before)

    def test_missing_anchor_is_not_created(self):
        del self.storage["observation.json"]
        with self.assertRaises(KeyError):
            self.publish()
        self.write.assert_not_called()

    def test_corrupt_half_populated_or_foreign_sensor_anchor_refuses(self):
        original = copy.deepcopy(self.storage["observation.json"])
        for change in ({"sequence": 0}, {"active": {}}, {"sensor_digest": "sha256:" + "f" * 64},
                       {"active": {}, "measured_action": {}}):
            self.storage["observation.json"] = {**original, **change}
            with self.subTest(change=change), self.assertRaises((RuntimeError, ValueError)):
                self.publish()
        self.write.assert_not_called()

    def test_changed_policy_or_source_snapshot_cannot_publish(self):
        self.storage["policy.json"]["id"] = "changed"
        with self.assertRaises(RuntimeError):
            self.publish()
        self.write.assert_not_called()
        source = copy.deepcopy(self.values["source_capture"])
        source["state"] = "CLOSED"
        with self.assertRaises(RuntimeError):
            self.publish(source_capture=source)
        self.write.assert_not_called()

    def test_publication_failure_is_not_retried(self):
        failure = OSError("inert publication failure")
        self.write.side_effect = failure
        with self.assertRaises(OSError) as caught:
            self.publish()
        self.assertIs(caught.exception, failure)
        self.write.assert_called_once()

    def test_stale_global_health_is_not_refreshed_by_new_observation(self):
        self.storage["health.json"]["expires_at_unix"] = 100
        before = copy.deepcopy(self.storage["health.json"])
        result = self.publish()
        decision = subject.decision.evaluate_runtime_action(self.values["approval"]["request"], self.storage["policy.json"],
            now_unix=100, active=result["active"], measured_action=result["measured_action"],
            revocations=self.storage["revocations.json"], minimum_revocation_generation=3,
            mediator_health=self.storage["health.json"], minimum_mediator_health_epoch=1)
        self.assertEqual(decision["verdict"], "BLOCK")
        self.assertEqual(self.storage["health.json"], before)


class InactiveApprovalTests(approval_fixtures.ProviderApprovalTests):
    def inactive(self):
        self.storage["observation.json"].update(active=None, measured_action=None)

    def test_fully_inactive_anchor_allows_readiness_and_real_binding_without_health_change(self):
        self.inactive()
        before = copy.deepcopy(self.storage)
        with self.hold() as holder:
            holder.guard(deadline=110)
            bound = self.bind(holder)
        self.assertEqual(bound["request"]["tool_call_id"], canonical_digest(self.request))
        self.assertEqual(self.storage, before)

    def test_each_half_populated_anchor_refuses_without_publication(self):
        original = copy.deepcopy(self.storage["observation.json"])
        for key in ("active", "measured_action"):
            self.storage["observation.json"] = {**original, key: None}
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "PARTIAL"):
                with self.hold():
                    self.fail("half-populated anchor admitted")
        self.assert_no_publication()

    def test_inactive_anchor_sensor_must_match_policy(self):
        self.inactive()
        self.storage["observation.json"]["sensor_digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(RuntimeError, "SENSOR_MISMATCH"):
            with self.hold():
                self.fail("foreign sensor admitted")
        self.assert_no_publication()

    def test_inactive_anchor_does_not_bypass_missing_stale_or_unhealthy_global_health(self):
        self.inactive()
        original = copy.deepcopy(self.storage["health.json"])
        for change in ({"status": "unhealthy"}, {"expires_at_unix": 100}, {"epoch": 0}):
            self.storage["health.json"] = {**original, **change}
            with self.subTest(change=change), self.assertRaises((RuntimeError, ValueError)):
                with self.hold():
                    self.fail("bad health admitted")
        del self.storage["health.json"]
        with self.assertRaises(KeyError):
            with self.hold():
                self.fail("missing health admitted")
        self.assert_no_publication()

    def test_inactive_anchor_does_not_bypass_revocation(self):
        self.inactive()
        self.storage["revocations.json"]["skill_digests"] = [self.intent["request"]["active_skill_digest"]]
        with self.assertRaises(RuntimeError):
            with self.hold():
                self.fail("revoked skill admitted")
        self.assert_no_publication()

    def test_existing_populated_anchor_keeps_structural_validation(self):
        self.storage["observation.json"]["active"]["extra"] = "forged"
        with self.assertRaises((RuntimeError, ValueError)):
            with self.hold():
                self.fail("corrupt active context admitted")
        self.assert_no_publication()


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    for case in (SourceBoundaryTests, PublicationTests, InactiveApprovalTests):
        suite.addTests(case(name) for name in sorted(case.__dict__) if name.startswith("test_"))
    for name in ("test_hold_and_guard_only_read_existing_controls_under_short_lock",
                 "test_missing_observation_is_not_synthesized",
                 "test_bind_derives_only_real_ids_and_publishes_existing_approval_schema"):
        suite.addTest(approval_fixtures.ProviderApprovalTests(name))
    return suite
