"""Inert raw-record fixtures only; no tracing, workers or live health claims."""

from copy import deepcopy
from io import BytesIO
from tempfile import TemporaryDirectory
import unittest

from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from aragorn.pi_core_source_observation_verify import (
    PiSourceObservationVerificationError, verify_pi_source_observation,
)
from tests.test_pi_core_source_observer import build_inert_source_capture


class PiSourceObservationReplayTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cas = CAS(temporary.name)
        self.source = b"abcd"
        source_pin = self.put_raw(self.source)
        self.identity = dict(device=1, inode=3, mode=0o100444, nlink=1, uid=0, gid=0,
                             size=4, mtime_ns=1, ctime_ns=1)
        gate = {**self.identity, "inode": 2, "mode": 0o100555, "size": 1}
        self.sources = [dict(path="/opt/aragorn/worker.mjs", digest=source_pin, identity=dict(self.identity))]
        inventory = {"schema": "aragorn/pi-core-source-inventory/v1", "sources": self.sources}
        inventory_raw = canonical_json(inventory)
        bindings = {key: "sha256:" + f"{index:064x}" for index, key in enumerate(
            ("deployment_digest", "runtime_digest", "gate_digest", "node_digest", "producer_digest"), 1)}
        bindings["source_inventory_digest"] = self.put_raw(inventory_raw)
        worker = dict(pid=101, start_ticks=20, uid=1000, gid=1000, cgroup="/owned.scope",
                      unit="owned.scope", invocation_id="a" * 32)
        clock = dict(boot_id="00000000-0000-0000-0000-000000000001", clock_id="CLOCK_BOOTTIME", time_namespace_inode=22)
        self.challenge = dict(nonce="b" * 64, issued_ns=200, deadline_ns=100_000_200)
        events = [
            dict(kind="ARMED", boottime_ns=100, tasks=[101], options=0x10005f, gate_identity=gate),
            self.stop(110, event=128),
            self.stop(120, op="ENTRY", syscall=221, args=[0, 0, 0, 0, 0, 0]),
            self.stop(130, event=4, event_message=101),
            dict(kind="EXEC", boottime_ns=140, pid=101, digest=bindings["node_digest"]),
            self.stop(150, op="EXIT", result=0, is_error=False),
            self.stop(160, op="ENTRY", syscall=63, args=[8, 4096, 4, 0, 0, 0]),
            dict(kind="READ_ENTER", boottime_ns=170, call_id=1, pid=101, syscall="read", fd=8,
                 offset=0, count=4, path=self.sources[0]["path"], digest=source_pin, identity=dict(self.identity)),
            self.stop(180, op="EXIT", result=4, is_error=False),
            dict(kind="READ_EXIT", boottime_ns=190, call_id=1, pid=101, result=4, is_error=False, identity=dict(self.identity)),
            self.stop(220, event=128),
            dict(kind="CHALLENGE", boottime_ns=230, **self.challenge, stops_before=6, stops_after=7,
                 tasks=[101], all_stopped=True),
        ]
        self.record = dict(schema="aragorn/pi-core-source-observation/v1", architecture="linux-arm64", bindings=bindings,
                           worker=worker, clock=clock, sources=self.sources, state="HELD", events=events, accounting={})
        self.arguments = dict(expected_bindings=deepcopy(bindings), expected_worker=deepcopy(worker),
                              expected_clock=deepcopy(clock), source_inventory_raw=inventory_raw,
                              expected_gate_identity=deepcopy(gate), expected_challenge=dict(self.challenge),
                              boundary_boottime_ns=240, evidence_cas=self.cas)
        self.recount()

    def stop(self, stamp, *, op="NONE", syscall=None, args=None, result=None, is_error=None, event=0, event_message=None):
        return dict(kind="STOP", boottime_ns=stamp, pid=101, status=(event << 16) | ((5 if op == "NONE" else 133) << 8) | 127,
                    op=op, syscall=syscall, args=args, result=result, is_error=is_error, event=event, event_message=event_message)

    def put_raw(self, raw):
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def recount(self):
        events = self.record["events"]
        for seq, event in enumerate(events, 1):
            event["seq"] = seq
        entered = sum(event["kind"] == "READ_ENTER" for event in events)
        exited = sum(event["kind"] == "READ_EXIT" for event in events)
        self.record["accounting"] = dict(
            stops_acquired=sum(event["kind"] == "STOP" for event in events), reads_entered=entered,
            reads_exited=exited, bytes_read=sum(max(0, event["result"]) for event in events if event["kind"] == "READ_EXIT"),
            pending_reads=entered-exited, refusals=sum(event["kind"] == "REFUSED" for event in events), events_retained=len(events))

    def verify(self):
        raw = canonical_json(self.record)
        return verify_pi_source_observation(raw, expected_observation_digest=self.put_raw(raw), **self.arguments)

    def refused(self):
        with self.assertRaises(PiSourceObservationVerificationError):
            self.verify()

    def test_complete_ranges_replay_without_runtime_or_execution_authority(self):
        result = self.verify()
        self.assertEqual(result["status"], "CONSISTENT_SOURCE_READ_COVERAGE")
        self.assertEqual(result["bytes_read"], 4)
        for flag in ("sensor_health_verified", "effect_authorized", "v8_execution_verified", "phase3_qualified", "acquisition_authenticity_verified"):
            self.assertIs(result[flag], False)

    def test_inert_producer_capture_round_trips_through_cas_and_independent_replay(self):
        fixture = build_inert_source_capture()
        for pin, raw in fixture["sources"].items():
            self.assertEqual(self.put_raw(raw), pin)
        self.assertEqual(self.put_raw(fixture["source_inventory_raw"]), fixture["expected_bindings"]["source_inventory_digest"])
        capture = canonical_json(fixture["capture"])
        result = verify_pi_source_observation(
            capture, expected_observation_digest=self.put_raw(capture), evidence_cas=self.cas,
            **{key: fixture[key] for key in ("expected_bindings", "expected_worker", "expected_clock",
                "expected_gate_identity", "expected_challenge", "boundary_boottime_ns", "source_inventory_raw")},
        )
        self.assertEqual(result["status"], "CONSISTENT_SOURCE_READ_COVERAGE")
        self.assertEqual(result["bytes_read"], 3)
        self.assertFalse(result["sensor_health_verified"])

    def test_capture_pin_substitution_is_rejected(self):
        raw = canonical_json(self.record)
        with self.assertRaises(PiSourceObservationVerificationError):
            verify_pi_source_observation(raw, expected_observation_digest="sha256:" + "0" * 64, **self.arguments)

    def test_duplicate_json_keys_are_rejected(self):
        raw = b'{"schema":"a","schema":"a"}'
        with self.assertRaises(PiSourceObservationVerificationError):
            verify_pi_source_observation(raw, expected_observation_digest=self.put_raw(raw), **self.arguments)

    def test_forged_pass_record_is_not_raw_observation(self):
        self.record = {"status": "PASS"}
        self.refused()

    def test_exact_bindings_cannot_be_substituted(self):
        for key in self.record["bindings"]:
            original = self.record["bindings"][key]
            self.record["bindings"][key] = "sha256:" + "0" * 64
            with self.subTest(key=key):
                self.refused()
            self.record["bindings"][key] = original

    def test_worker_pid_and_start_generation_are_joined(self):
        self.record["worker"]["start_ticks"] += 1
        self.refused()

    def test_clock_domain_substitution_is_rejected(self):
        self.record["clock"]["time_namespace_inode"] += 1
        self.refused()

    def test_syscall_decoding_is_arm64_only(self):
        self.record["architecture"] = "linux-x86_64"
        self.refused()

    def test_inventory_must_match_separate_frozen_pin(self):
        self.arguments["source_inventory_raw"] += b" "
        self.refused()

    def test_source_content_must_exist_in_cas(self):
        changed = deepcopy(self.sources)
        changed[0]["digest"] = "sha256:" + "0" * 64
        inventory = canonical_json({"schema": "aragorn/pi-core-source-inventory/v1", "sources": changed})
        pin = self.put_raw(inventory)
        self.arguments["source_inventory_raw"] = inventory
        self.arguments["expected_bindings"]["source_inventory_digest"] = pin
        self.record["bindings"]["source_inventory_digest"] = pin
        self.record["sources"] = changed
        with self.assertRaises(CASError):
            self.verify()

    def test_source_metadata_matches_strict_producer_constraints(self):
        for field, value in (("mode", 0o104444), ("mode", 0o102444), ("mode", 0o101444),
                             ("mode", 0o100644), ("uid", 1), ("gid", 1), ("nlink", 2), ("size", 5)):
            changed = deepcopy(self.sources)
            changed[0]["identity"][field] = value
            raw = canonical_json({"schema": "aragorn/pi-core-source-inventory/v1", "sources": changed})
            pin = self.put_raw(raw)
            self.arguments["source_inventory_raw"] = raw
            self.arguments["expected_bindings"]["source_inventory_digest"] = pin
            self.record["bindings"]["source_inventory_digest"] = pin
            self.record["sources"] = changed
            with self.subTest(field=field, value=value):
                self.refused()

    def test_gate_object_identity_must_match_independent_observation(self):
        self.record["events"][0]["gate_identity"]["inode"] += 1
        self.refused()

    def test_ptrace_options_cannot_omit_exitkill_or_thread_detection(self):
        self.record["events"][0]["options"] = 1
        self.refused()

    def test_trace_must_begin_at_the_armed_stopped_gate(self):
        self.record["events"][1]["event"] = 4
        self.record["events"][1]["status"] = (4 << 16) | (5 << 8) | 127
        self.refused()

    def test_initial_self_stopped_gate_accepts_linux_sigstop19(self):
        self.record["events"][1]["status"] = (128 << 16) | (19 << 8) | 127
        self.assertEqual(self.verify()["status"], "CONSISTENT_SOURCE_READ_COVERAGE")

    def test_later_sigstop_is_not_fresh_interrupt_progress(self):
        self.record["events"][10]["status"] = (128 << 16) | (19 << 8) | 127
        self.refused()

    def test_node_execution_must_follow_kernel_exec_stop(self):
        self.record["events"][3] = self.stop(130, event=128)
        self.recount()
        self.refused()

    def test_node_image_pin_is_exact(self):
        self.record["events"][4]["digest"] = "sha256:" + "0" * 64
        self.refused()

    def test_exec_event_message_must_identify_owned_worker(self):
        self.record["events"][3]["event_message"] = 102
        self.refused()

    def test_failed_exec_exit_cannot_qualify_later_source_reads(self):
        self.record["events"][5].update(result=-2, is_error=True)
        self.refused()

    def test_omitted_exec_record_is_rejected(self):
        self.record["events"].pop(4)
        self.recount()
        self.refused()

    def test_read_requires_actual_entry_stop_arguments(self):
        self.record["events"][6]["args"][0] += 1
        self.refused()

    def test_read_argument_bounds_match_producer(self):
        entry = self.record["events"][7]
        for field, value in (("fd", 1 << 31), ("fd", True), ("count", 16 * 1024 * 1024 + 1),
                             ("count", True), ("offset", 5), ("offset", (1 << 63) - 1)):
            original = entry[field]
            entry[field] = value
            with self.subTest(field=field, value=value):
                self.refused()
            entry[field] = original

    def test_pread_uses_explicit_offset(self):
        self.record["events"][6]["syscall"] = 67
        self.record["events"][7]["syscall"] = "pread64"
        self.assertEqual(self.verify()["bytes_read"], 4)
        self.record["events"][6]["args"][3] = 1
        self.refused()

    def test_short_read_covers_only_returned_bytes(self):
        self.record["events"][8]["result"] = self.record["events"][9]["result"] = 2
        self.recount()
        self.refused()

    def test_two_partial_reads_can_cover_exact_complete_file(self):
        self.record["events"][8]["result"] = self.record["events"][9]["result"] = 2
        source = self.sources[0]
        second = [
            self.stop(191, op="ENTRY", syscall=67, args=[8, 4096, 2, 2, 0, 0]),
            dict(kind="READ_ENTER", boottime_ns=193, call_id=2, pid=101, syscall="pread64", fd=8,
                 offset=2, count=2, path=source["path"], digest=source["digest"], identity=dict(self.identity)),
            self.stop(195, op="EXIT", result=2, is_error=False),
            dict(kind="READ_EXIT", boottime_ns=197, call_id=2, pid=101, result=2, is_error=False, identity=dict(self.identity)),
        ]
        self.record["events"][10:10] = second
        self.record["events"][-1].update(stops_before=8, stops_after=9)
        self.recount()
        result = self.verify()
        self.assertEqual(result["bytes_read"], 4)
        self.assertEqual(result["completed_reads"], 2)

    def test_eof_is_not_positive_progress_or_source_coverage(self):
        self.record["events"][8]["result"] = self.record["events"][9]["result"] = 0
        self.recount()
        self.refused()

    def test_read_error_does_not_cover_requested_bytes(self):
        for index in (8, 9):
            self.record["events"][index].update(result=-4, is_error=True)
        self.recount()
        self.refused()

    def test_source_identity_is_unchanged_through_read_exit(self):
        self.record["events"][9]["identity"]["ctime_ns"] += 1
        self.refused()

    def test_positive_return_cannot_exceed_requested_bytes(self):
        self.record["events"][6]["args"][2] = 3
        self.record["events"][7]["count"] = 3
        self.refused()

    def test_missing_read_entry_cannot_hide_a_source_read(self):
        self.record["events"].pop(7)
        self.recount()
        self.refused()

    def test_orphan_general_syscall_exit_is_rejected(self):
        self.record["events"].insert(10, self.stop(195, op="EXIT", result=0, is_error=False))
        self.recount()
        self.refused()

    def test_duplicate_general_syscall_entry_is_rejected(self):
        self.record["events"].insert(3, self.stop(125, op="ENTRY", syscall=221, args=[0] * 6))
        self.recount()
        self.refused()

    def test_pre_exec_source_reads_are_not_ignored(self):
        self.record["events"][2].update(syscall=63, args=[8, 4096, 4, 0, 0, 0])
        self.refused()

    def test_missing_read_exit_cannot_qualify_accounting(self):
        self.record["events"].pop(9)
        self.recount()
        self.refused()

    def test_duplicated_completion_is_rejected(self):
        self.record["events"].insert(10, deepcopy(self.record["events"][9]))
        self.recount()
        self.refused()

    def test_sequence_gap_is_rejected(self):
        self.record["events"][4]["seq"] += 1
        self.refused()

    def test_event_timestamp_regression_is_rejected(self):
        self.record["events"][4]["boottime_ns"] = 90
        self.refused()

    def test_all_stop_challenge_must_match_nonce_and_exact_task_inventory(self):
        challenge = self.record["events"][-1]
        for key, value in (("nonce", "c" * 64), ("tasks", [101, 102]), ("all_stopped", False)):
            original = challenge[key]
            challenge[key] = value
            with self.subTest(key=key):
                self.refused()
            challenge[key] = original

    def test_challenge_requires_a_new_acquired_stop(self):
        self.record["events"][-1]["stops_before"] = 7
        self.refused()

    def add_second_challenge(self):
        challenge = dict(nonce="c" * 64, issued_ns=300, deadline_ns=100_000_300)
        self.record["events"].extend([
            self.stop(320, event=128),
            dict(kind="CHALLENGE", boottime_ns=330, **challenge, stops_before=7, stops_after=8,
                 tasks=[101], all_stopped=True),
        ])
        self.arguments.update(expected_challenge=challenge, boundary_boottime_ns=340)
        self.recount()

    def test_multiple_challenges_preserve_one_cumulative_capture(self):
        self.add_second_challenge()
        result = self.verify()
        self.assertEqual(result["challenge_count"], 2)
        self.assertEqual(result["completed_reads"], 1)

    def test_prior_challenge_nonce_cannot_be_reused(self):
        self.add_second_challenge()
        self.record["events"][-1]["nonce"] = "b" * 64
        self.arguments["expected_challenge"]["nonce"] = "b" * 64
        self.refused()

    def test_prior_challenge_stop_cannot_be_reused(self):
        self.add_second_challenge()
        self.record["events"].pop(-2)
        self.record["events"][-1].update(stops_before=6, stops_after=7)
        self.recount()
        self.refused()

    def test_prior_challenge_deadline_is_still_checked(self):
        self.add_second_challenge()
        self.record["events"][11]["deadline_ns"] += 1
        self.refused()

    def test_challenge_cannot_relabel_old_stop_as_progress(self):
        self.record["events"][10]["boottime_ns"] = 195
        self.refused()

    def test_prior_syscall_exit_cannot_be_relabelled_challenge_interrupt(self):
        self.record["events"][10] = self.stop(220, op="EXIT", result=0, is_error=False)
        self.recount()
        self.refused()

    def test_challenge_refuses_pending_general_syscall(self):
        self.record["events"].insert(10, self.stop(195, op="ENTRY", syscall=172, args=[0] * 6))
        self.recount()
        self.record["events"][-1].update(stops_before=7, stops_after=8)
        self.refused()

    def test_challenge_deadline_remains_100ms(self):
        self.arguments["expected_challenge"]["deadline_ns"] += 1
        self.record["events"][-1]["deadline_ns"] += 1
        self.refused()

    def test_200ms_age_boundary_is_stale(self):
        self.arguments["boundary_boottime_ns"] = 200_000_230
        self.refused()

    def test_accounting_is_reconstructed_not_trusted(self):
        for key in self.record["accounting"]:
            self.record["accounting"][key] += 1
            with self.subTest(key=key):
                self.refused()
            self.record["accounting"][key] -= 1

    def test_unknown_zero_loss_counter_cannot_extend_contract(self):
        self.record["accounting"]["kernel_lost"] = 0
        self.refused()

    def test_clone_fork_and_unsupported_source_access_are_refused(self):
        for syscall in (65, 69, 286, 76, 77, 75, 71, 285, 425, 426, 427, 281, 220, 435, 117, 277, 270, 271):
            self.record["events"][6]["syscall"] = syscall
            with self.subTest(syscall=syscall):
                self.refused()

    def test_file_backed_mmap_is_explicitly_unsupported(self):
        self.record["events"][6].update(syscall=222, args=[0, 4096, 1, 2, 8, 0])
        self.refused()

    def test_unclassified_syscall_is_not_silently_accepted(self):
        self.record["events"][6]["syscall"] = 64
        self.refused()

    def test_clone_event_is_explicitly_unsupported(self):
        for event in (1, 2, 3):
            self.record["events"][10] = self.stop(220, event=event)
            self.recount()
            with self.subTest(event=event):
                self.refused()

    def test_retained_failure_cannot_be_relabelled_held(self):
        self.record["events"].insert(10, dict(kind="REFUSED", code="UNSUPPORTED_CLONE", boottime_ns=195))
        self.recount()
        self.refused()

    def test_refused_and_closed_capture_states_are_not_qualifying(self):
        for state in ("REFUSED", "CLOSED", "PASS", "UNKNOWN"):
            self.record["state"] = state
            with self.subTest(state=state):
                self.refused()

    def test_boolean_aliases_are_not_integer_accounting(self):
        self.record["accounting"]["reads_entered"] = True
        self.refused()
