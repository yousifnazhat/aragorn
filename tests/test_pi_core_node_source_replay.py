"""Inert raw-record replay, never tracing or live health qualification."""

from copy import deepcopy
from io import BytesIO
from tempfile import TemporaryDirectory
import unittest

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from aragorn.pi_core_node_source_observation_verify import verify_pi_node_source_observation
from aragorn.pi_core_source_observation_verify import PiSourceObservationVerificationError
from tests import test_pi_core_source_observation_verify as legacy
from tests.test_pi_core_node_source_observer import build_inert_node_source_capture


class NodeReplayTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.cas = CAS(temporary.name)
        self.source = dict(path="/opt/aragorn/pi-runtime/pi-core/entrypoint.js", digest=self.put(b"abcd"),
                           identity=self.identity(3, 4), readonly_view=True)
        self.loader = dict(path="/lib/ld-linux-aarch64.so.1", digest=self.put(b"\x7fELF"),
                           identity=self.identity(4, 4, 0o100555), readonly_view=True)
        source_raw = canonical_json(dict(schema="aragorn/pi-core-node-source-inventory/v2", sources=[self.source]))
        loader_raw = canonical_json(dict(schema="aragorn/pi-core-loader-inventory/v1", loaders=[self.loader]))
        pins = {key: "sha256:" + f"{index:064x}" for index, key in enumerate(
            ("gate_digest", "node_digest", "producer_digest", "node_observer_digest"), 1)}
        pins.update(source_inventory_digest=self.put(source_raw), loader_inventory_digest=self.put(loader_raw))
        profile = dict(schema="aragorn/pi-core-node-source-profile/v1", pins=pins,
                       sources=[{key: self.source[key] for key in ("path", "digest")}],
                       required_sources=[self.source["path"]],
                       loader_files=[{key: self.loader[key] for key in ("path", "digest")}])
        profile_raw = canonical_json(profile)
        bindings = {**pins, "profile_digest": self.put(profile_raw),
                    "runtime_digest": "sha256:" + "a" * 64, "deployment_digest": "sha256:" + "b" * 64}
        worker = dict(pid=101, start_ticks=20, uid=1000, gid=1000, cgroup="/owned.scope",
                      unit="owned.scope", invocation_id="a" * 32)
        clock = dict(boot_id="00000000-0000-0000-0000-000000000001", clock_id="CLOCK_BOOTTIME", time_namespace_inode=22)
        gate = self.identity(2, 1, 0o100555)
        self.challenge = dict(nonce="c" * 64, issued_ns=200, deadline_ns=100_000_200)
        events = [
            dict(kind="ARMED", tasks=[101], options=0x10005F, gate_identity=gate),
            self.stop(event=128), self.barrier(1, 2),
            dict(kind="STDIO", epoch=1, descriptors=[dict(fd=fd, rdev=259,
                 identity=dict(device=2, inode=5, mode=0o20666)) for fd in range(3)]),
            self.resume(), self.stop(op="ENTRY", syscall=221, args=[0] * 6),
            self.resume(), self.stop(event=4, event_message=101),
            dict(kind="EXEC", pid=101, digest=bindings["node_digest"]), self.resume(),
            self.stop(op="EXIT", result=0, is_error=False), self.resume(),
            self.stop(op="ENTRY", syscall=67, args=[8, 4096, 4, 0, 0, 0]),
            self.barrier(2, 13),
            dict(kind="READ_ENTER", pid=101, call_id=13, syscall="pread64", fd=8, offset=0, count=4,
                 path=self.source["path"], digest=self.source["digest"], identity=self.source["identity"], epoch=2,
                 iovecs=None), self.resume(), self.stop(op="EXIT", result=4, is_error=False),
            self.barrier(3, 17),
            dict(kind="READ_EXIT", pid=101, call_id=13, result=4, is_error=False,
                 identity=self.source["identity"], epoch=3),
            self.resume(), self.stop(event=128), self.barrier(4, 21),
            dict(kind="CHALLENGE", **self.challenge, epoch=4, tasks=[dict(pid=101, start_ticks=20)],
                 stops_before=6, stops_after=7, all_stopped=True),
        ]
        self.record = dict(schema="aragorn/pi-core-node-source-observation/v2", architecture="linux-arm64",
                           bindings=bindings, worker=worker, clock=clock, sources=[self.source],
                           required_sources=profile["required_sources"], loaders=[self.loader],
                           state="HELD", events=events, accounting={})
        self.arguments = dict(expected_bindings=deepcopy(bindings), expected_worker=deepcopy(worker),
                              expected_clock=deepcopy(clock), expected_gate_identity=deepcopy(gate),
                              expected_profile_raw=profile_raw, source_inventory_raw=source_raw,
                              loader_inventory_raw=loader_raw, expected_root_peer=(9000, 0, 0),
                              expected_root_endpoints=("/run/aragorn/request.sock",),
                              expected_challenge=dict(self.challenge), boundary_boottime_ns=240, evidence_cas=self.cas)
        self.recount()

    @staticmethod
    def identity(inode, size, mode=0o100444):
        return dict(device=1, inode=inode, mode=mode, nlink=1, uid=0, gid=0, size=size, mtime_ns=1, ctime_ns=1)

    @staticmethod
    def stop(*, pid=101, start_ticks=20, op="NONE", syscall=None, args=None,
             result=None, is_error=None, event=0, event_message=None):
        return dict(kind="STOP", pid=pid, start_ticks=start_ticks,
                    status=(event << 16) | ((5 if op == "NONE" else 133) << 8) | 127,
                    op=op, syscall=syscall, args=args, result=result, is_error=is_error,
                    event=event, event_message=event_message)

    @staticmethod
    def resume(pid=101, start_ticks=20):
        return dict(kind="RESUME", pid=pid, start_ticks=start_ticks, request="SYSCALL")

    @staticmethod
    def barrier(epoch, stop_seq):
        return dict(kind="ALL_STOP", epoch=epoch, tasks=[dict(pid=101, start_ticks=20)], stop_seqs=[stop_seq])

    def put(self, raw):
        return self.cas.put(BytesIO(raw), max_bytes=len(raw))

    def recount(self):
        events = self.record["events"]
        for index, event in enumerate(events, 1):
            event["seq"], event["boottime_ns"] = index, index * 10
        counts = lambda kind: sum(event["kind"] == kind for event in events)
        self.record["accounting"] = dict(
            stops_acquired=counts("STOP"), reads_entered=counts("READ_ENTER"), reads_exited=counts("READ_EXIT"),
            bytes_read=sum(max(0, event["result"]) for event in events if event["kind"] == "READ_EXIT"),
            pending_reads=counts("READ_ENTER")-counts("READ_EXIT"), refusals=counts("REFUSED"), events_retained=len(events),
            threads_observed=1+counts("THREAD"), threads_exited=counts("THREAD_EXIT"),
            maps_entered=counts("MAP_ENTER"), maps_exited=counts("MAP_EXIT"),
            io_entered=counts("IO_ENTER"), io_exited=counts("IO_EXIT"), pending_syscalls=0)

    def verify(self):
        raw = canonical_json(self.record)
        return verify_pi_node_source_observation(raw, expected_observation_digest=self.put(raw), **self.arguments)

    def refused(self):
        with self.assertRaises(PiSourceObservationVerificationError):
            self.verify()

    def repin_inventories(self):
        source_raw = canonical_json(dict(schema="aragorn/pi-core-node-source-inventory/v2", sources=self.record["sources"]))
        loader_raw = canonical_json(dict(schema="aragorn/pi-core-loader-inventory/v1", loaders=self.record["loaders"]))
        bindings = self.record["bindings"]
        bindings.update(source_inventory_digest=self.put(source_raw), loader_inventory_digest=self.put(loader_raw))
        profile = dict(schema="aragorn/pi-core-node-source-profile/v1",
                       pins={key: bindings[key] for key in ("gate_digest", "node_digest", "producer_digest",
                             "node_observer_digest", "source_inventory_digest", "loader_inventory_digest")},
                       sources=[{key: row[key] for key in ("path", "digest")} for row in self.record["sources"]],
                       required_sources=self.record["required_sources"],
                       loader_files=[{key: row[key] for key in ("path", "digest")} for row in self.record["loaders"]])
        profile_raw = canonical_json(profile)
        bindings["profile_digest"] = self.put(profile_raw)
        self.arguments.update(source_inventory_raw=source_raw, loader_inventory_raw=loader_raw,
                              expected_profile_raw=profile_raw, expected_bindings=deepcopy(bindings))

    def threaded(self):
        events = deepcopy(self.record["events"][:11])
        def emit(row):
            events.append(row)
            row["seq"] = len(events)
            return row["seq"]
        def barrier(epoch, parent_stop, child_stop=None):
            rows = [dict(pid=101, start_ticks=20)]
            stops = [parent_stop]
            if child_stop is not None:
                rows.append(dict(pid=102, start_ticks=21))
                stops.append(child_stop)
            return emit(dict(kind="ALL_STOP", epoch=epoch, tasks=rows, stop_seqs=stops))
        emit(self.resume())
        clone_entry = emit(self.stop(op="ENTRY", syscall=220, args=[0x50F00, 4096, 0, 0, 0, 0]))
        barrier(2, clone_entry)
        clone_request = emit(dict(kind="CLONE_REQUEST", pid=101, call_id=clone_entry, syscall=220,
                                  flags=0x50F00, clone_args=None, epoch=2))
        emit(self.resume())
        emit(self.stop(event=3, event_message=102))
        emit(dict(kind="THREAD", pid=102, start_ticks=21, parent_pid=101, flags=0x50F00,
                  clone_call_seq=clone_request))
        child_initial = emit(self.stop(pid=102, start_ticks=21, event=128))
        emit(self.resume())
        parent_exit = emit(self.stop(op="EXIT", result=102, is_error=False))
        emit(self.resume(102, 21))
        child_start = emit(self.stop(pid=102, start_ticks=21, op="EXIT", result=0, is_error=False))
        emit(dict(kind="THREAD_START", pid=102, stop_seq=child_start, clone_call_seq=clone_request))
        emit(self.resume(102, 21))
        read_entry = emit(self.stop(pid=102, start_ticks=21, op="ENTRY", syscall=67, args=[8, 4096, 4, 0, 0, 0]))
        barrier(3, parent_exit, read_entry)
        emit(dict(kind="READ_ENTER", pid=102, call_id=read_entry, syscall="pread64", fd=8, offset=0, count=4,
                  path=self.source["path"], digest=self.source["digest"], identity=self.source["identity"], epoch=3,
                  iovecs=None))
        emit(self.resume(102, 21))
        read_exit = emit(self.stop(pid=102, start_ticks=21, op="EXIT", result=4, is_error=False))
        barrier(4, parent_exit, read_exit)
        emit(dict(kind="READ_EXIT", pid=102, call_id=read_entry, result=4, is_error=False,
                  identity=self.source["identity"], epoch=4))
        issued = len(events) * 10 + 1
        before = sum(event["kind"] == "STOP" for event in events)
        emit(self.resume())
        emit(self.resume(102, 21))
        parent_stop = emit(self.stop(event=128))
        child_stop = emit(self.stop(pid=102, start_ticks=21, event=128))
        barrier(5, parent_stop, child_stop)
        self.challenge.update(issued_ns=issued, deadline_ns=issued + 100_000_000)
        emit(dict(kind="CHALLENGE", **self.challenge, epoch=5,
                  tasks=[dict(pid=101, start_ticks=20), dict(pid=102, start_ticks=21)],
                  stops_before=before, stops_after=before+2, all_stopped=True))
        self.record["events"] = events
        self.arguments.update(expected_challenge=dict(self.challenge), boundary_boottime_ns=(len(events)+1)*10)
        self.recount()
        return {"clone_entry": clone_entry, "clone_request": clone_request, "child_initial": child_initial,
                "parent_exit": parent_exit, "read_entry": read_entry, "read_exit": read_exit}

    def event(self, kind):
        return next(row for row in self.record["events"] if row["kind"] == kind)

    def finish(self, events, *, pending=0):
        issued = len(events) * 10 + 1
        before = sum(row["kind"] == "STOP" for row in events)
        epoch = max(row["epoch"] for row in events if row["kind"] == "ALL_STOP") + 1
        events.append(self.resume())
        events.append(self.stop(event=128))
        events.append(self.barrier(epoch, len(events)))
        self.challenge.update(issued_ns=issued, deadline_ns=issued+100_000_000)
        events.append(dict(kind="CHALLENGE", **self.challenge, epoch=epoch,
                           tasks=[dict(pid=101, start_ticks=20)], stops_before=before, stops_after=before+1,
                           all_stopped=True))
        self.record["events"] = events
        self.arguments.update(expected_challenge=dict(self.challenge), boundary_boottime_ns=(len(events)+1)*10)
        self.recount()
        self.record["accounting"]["pending_syscalls"] = pending

    def owned_io(self, *, pending=False, internal=False):
        events = deepcopy(self.record["events"][:19])
        epoch = 4
        channel = dict(kind="root-unix", peer=[9000, 0, 0], endpoint="/run/aragorn/request.sock")
        identity = dict(device=4, inode=40, mode=0o140777)
        if internal:
            events.extend([self.resume(), self.stop(op="ENTRY", syscall=19, args=[0, 0, 0, 0, 0, 0])])
            call = len(events)
            events.append(self.barrier(epoch, call))
            events.extend([self.resume(), self.stop(op="EXIT", result=9, is_error=False)])
            events.append(self.barrier(epoch+1, len(events)))
            identity = dict(device=4, inode=40, mode=0o600)
            events.append(dict(kind="FD_CREATE", pid=101, call_id=call, kind_name="eventfd", epoch=epoch+1,
                               descriptors=[dict(fd=9, identity=identity)]))
            channel = dict(kind="eventfd", created_by=call)
            epoch += 2
        events.extend([self.resume(), self.stop(op="ENTRY", syscall=63, args=[9, 8192, 8, 0, 0, 0])])
        call = len(events)
        events.append(self.barrier(epoch, call))
        events.append(dict(kind="IO_ENTER", pid=101, call_id=call, syscall="read", fd=9, count=8,
                           iovecs=None, channel=channel, identity=identity, epoch=epoch))
        if not pending:
            events.extend([self.resume(), self.stop(op="EXIT", result=8, is_error=False),
                           dict(kind="IO_EXIT", pid=101, call_id=call, result=8, is_error=False, epoch=epoch)])
        self.finish(events, pending=int(pending))

    def loader_mapping(self):
        events = deepcopy(self.record["events"][:19])
        events.extend([self.resume(), self.stop(op="ENTRY", syscall=222, args=[0, 4096, 5, 2, 10, 0])])
        call = len(events)
        events.append(self.barrier(4, call))
        events.append(dict(kind="MAP_ENTER", pid=101, call_id=call, fd=10, offset=0, length=4096,
                           prot=5, flags=2, path=self.loader["path"], digest=self.loader["digest"],
                           identity=self.loader["identity"], epoch=4))
        events.extend([self.resume(), self.stop(op="EXIT", result=8192, is_error=False)])
        events.append(self.barrier(5, len(events)))
        events.append(dict(kind="MAP_EXIT", pid=101, call_id=call, result=8192, is_error=False,
                           identity=self.loader["identity"], epoch=5))
        self.finish(events)

    def aliased_eventfds(self):
        events = deepcopy(self.record["events"][:19])
        identity = dict(device=4, inode=40, mode=0o600)
        origins = []
        epoch = 4
        for fd in (9, 10):
            events.extend([self.resume(), self.stop(op="ENTRY", syscall=19, args=[0]*6)])
            call = len(events)
            origins.append(call)
            events.append(self.barrier(epoch, call))
            events.extend([self.resume(), self.stop(op="EXIT", result=fd, is_error=False)])
            events.append(self.barrier(epoch+1, len(events)))
            events.append(dict(kind="FD_CREATE", pid=101, call_id=call, kind_name="eventfd", epoch=epoch+1,
                               descriptors=[dict(fd=fd, identity=identity)]))
            epoch += 2
        for fd, origin in zip((9, 10), origins):
            events.extend([self.resume(), self.stop(op="ENTRY", syscall=63, args=[fd, 8192, 8, 0, 0, 0])])
            call = len(events)
            events.append(self.barrier(epoch, call))
            events.append(dict(kind="IO_ENTER", pid=101, call_id=call, syscall="read", fd=fd, count=8,
                               iovecs=None, channel=dict(kind="eventfd", created_by=origin),
                               identity=identity, epoch=epoch))
            events.extend([self.resume(), self.stop(op="EXIT", result=8, is_error=False),
                           dict(kind="IO_EXIT", pid=101, call_id=call, result=8, is_error=False, epoch=epoch)])
            epoch += 1
        self.finish(events)
        return origins

    def test_required_file_delivery_is_consistent_but_not_health_or_execution(self):
        result = self.verify()
        self.assertEqual(result["status"], "CONSISTENT_REQUIRED_SOURCE_DELIVERY")
        self.assertEqual(result["required_source_count"], 1)
        for flag in ("acquisition_authenticity_verified", "sensor_health_verified", "effect_authorized",
                     "v8_execution_verified", "phase3_qualified"):
            self.assertIs(result[flag], False)

    def test_independent_thread_source_delivery_joins_parent_and_child_generations(self):
        self.threaded()
        self.assertEqual(self.verify()["threads_observed"], 2)

    def test_actual_inert_producer_records_round_trip_through_independent_replay(self):
        fixture = build_inert_node_source_capture()
        for raw in fixture["blobs"]:
            self.put(raw)
        raw = canonical_json(fixture["record"])
        result = verify_pi_node_source_observation(
            raw, expected_observation_digest=self.put(raw), evidence_cas=self.cas, **fixture["arguments"])
        self.assertEqual(result["bytes_read"], 3)
        self.assertEqual(result["status"], "CONSISTENT_REQUIRED_SOURCE_DELIVERY")
        self.assertFalse(result["sensor_health_verified"])

    def test_source_reads_can_span_vector_elements(self):
        raw, entry = self.record["events"][12], self.event("READ_ENTER")
        raw.update(syscall=65, args=[8, 4096, 2, 0, 0, 0])
        entry.update(syscall="readv", iovecs=(4096).to_bytes(8, "little").hex() + (2).to_bytes(8, "little").hex()
                     + (8192).to_bytes(8, "little").hex() + (2).to_bytes(8, "little").hex())
        self.assertEqual(self.verify()["bytes_read"], 4)

    def test_empty_vector_sum_cannot_claim_four_bytes(self):
        self.event("READ_ENTER")["iovecs"] = "00" * 16
        self.refused()

    def test_pread_offset_must_join_raw_arguments(self):
        self.event("READ_ENTER")["offset"] = 1
        self.refused()

    def test_wrong_read_result_cannot_be_substituted_after_raw_exit(self):
        self.event("READ_EXIT")["result"] = 3
        self.recount()
        self.refused()

    def test_partial_required_source_is_not_complete_delivery(self):
        self.record["events"][16]["result"] = 3
        self.event("READ_EXIT")["result"] = 3
        self.recount()
        self.refused()

    def test_read_error_is_not_source_coverage(self):
        self.record["events"][16].update(result=-13, is_error=True)
        self.event("READ_EXIT").update(result=-13, is_error=True)
        self.recount()
        self.refused()

    def test_source_identity_change_at_exit_is_refused(self):
        self.event("READ_EXIT")["identity"] = {**self.source["identity"], "inode": 55}
        self.refused()

    def test_required_profile_pin_is_caller_held(self):
        self.arguments["expected_profile_raw"] += b" "
        self.refused()

    def test_source_inventory_pin_is_caller_held(self):
        self.arguments["source_inventory_raw"] += b" "
        self.refused()

    def test_changed_record_binding_is_not_promoted_to_expected_pin(self):
        self.record["bindings"]["node_observer_digest"] = "sha256:" + "f" * 64
        self.refused()

    def test_owner_writable_file_on_readonly_view_is_supported(self):
        self.source["identity"]["mode"] = 0o100644
        self.repin_inventories()
        self.assertEqual(self.verify()["bytes_read"], 4)

    def test_claiming_writable_view_is_refused_even_for_readonly_mode(self):
        self.source["readonly_view"] = False
        self.repin_inventories()
        self.refused()

    def test_group_writable_source_is_refused_even_on_readonly_view(self):
        self.source["identity"]["mode"] = 0o100664
        self.repin_inventories()
        self.refused()

    def test_source_alias_in_loader_inventory_is_refused(self):
        self.loader["identity"]["inode"] = self.source["identity"]["inode"]
        self.repin_inventories()
        self.refused()

    def test_record_cannot_remove_caller_required_source(self):
        self.record["required_sources"] = []
        self.refused()

    def test_record_counter_cannot_hide_loss(self):
        self.record["accounting"]["stops_acquired"] -= 1
        self.refused()

    def test_duplicate_raw_sequence_is_refused(self):
        self.record["events"][10]["seq"] = 10
        self.refused()

    def test_all_stop_cannot_reference_a_stale_stop(self):
        self.event("ALL_STOP")["stop_seqs"] = [9]
        self.refused()

    def test_source_exit_requires_fresh_all_stop_epoch(self):
        self.event("READ_EXIT")["epoch"] = 1
        self.refused()

    def test_source_enter_without_held_barrier_is_refused(self):
        self.event("READ_ENTER")["epoch"] = 0
        self.refused()

    def test_double_resume_cannot_create_held_custody(self):
        self.record["events"][5] = self.resume()
        self.recount()
        self.refused()

    def test_thread_generation_change_is_refused(self):
        refs = self.threaded()
        self.record["events"][refs["read_exit"]-1]["start_ticks"] = 22
        self.refused()

    def test_child_requires_matching_parent_clone_request(self):
        self.threaded()
        self.event("THREAD")["clone_call_seq"] -= 1
        self.refused()

    def test_child_cannot_be_a_process_clone(self):
        refs = self.threaded()
        self.record["events"][refs["clone_entry"]-1]["args"][0] = 17
        self.event("CLONE_REQUEST")["flags"] = 17
        self.event("THREAD")["flags"] = 17
        self.refused()

    def test_child_first_exit_needs_thread_start_join(self):
        self.threaded()
        self.event("THREAD_START")["clone_call_seq"] += 1
        self.refused()

    def test_parent_clone_result_cannot_substitute_child_pid(self):
        refs = self.threaded()
        self.record["events"][refs["parent_exit"]-1]["result"] = 103
        self.refused()

    def test_child_missing_from_all_stop_is_refused(self):
        self.threaded()
        barriers = [row for row in self.record["events"] if row["kind"] == "ALL_STOP"]
        barriers[2]["tasks"].pop()
        barriers[2]["stop_seqs"].pop()
        self.refused()

    def test_challenge_requires_progress_from_every_live_tid(self):
        self.threaded()
        self.event("CHALLENGE")["issued_ns"] = 355
        self.event("CHALLENGE")["deadline_ns"] = 100_000_355
        self.arguments["expected_challenge"].update(issued_ns=355, deadline_ns=100_000_355)
        self.refused()

    def test_challenge_cannot_extend_deadline(self):
        self.event("CHALLENGE")["deadline_ns"] += 1
        self.refused()

    def test_unpinned_final_challenge_is_refused(self):
        self.arguments["expected_challenge"]["nonce"] = "d" * 64
        self.refused()

    def test_stale_observation_boundary_is_refused(self):
        self.arguments["boundary_boottime_ns"] = 200_000_231
        self.refused()

    def test_challenge_cannot_claim_all_stopped_without_custody(self):
        self.event("CHALLENGE")["all_stopped"] = False
        self.refused()

    def test_unsupported_event_is_retained_refusal(self):
        self.record["events"][-1]["kind"] = "HEALTHY"
        self.refused()

    def test_extra_claim_field_is_rejected(self):
        self.record["sensor_health_verified"] = True
        self.refused()

    def test_loader_mapping_is_separate_from_required_source_delivery(self):
        self.loader_mapping()
        result = self.verify()
        self.assertEqual((result["bytes_read"], result["loader_mappings"]), (4, 1))

    def test_loader_map_cannot_replace_source_delivery(self):
        self.loader_mapping()
        self.record["events"][16]["result"] = 0
        self.event("READ_EXIT")["result"] = 0
        self.recount()
        self.refused()

    def test_loader_reads_remain_outside_source_byte_accounting(self):
        self.loader_mapping()
        enter, exit = self.event("MAP_ENTER"), self.event("MAP_EXIT")
        call = enter["call_id"]
        self.record["events"][call-1].update(syscall=67, args=[10, 4096, 4, 0, 0, 0])
        enter["kind"] = "LOADER_READ_ENTER"
        for key in ("length", "prot", "flags"):
            del enter[key]
        enter.update(syscall="pread64", count=4, iovecs=None)
        exit.update(kind="LOADER_READ_EXIT", result=4)
        stop = next(row for row in self.record["events"] if row["kind"] == "STOP" and row.get("result") == 8192)
        stop["result"] = 4
        self.recount()
        result = self.verify()
        self.assertEqual((result["bytes_read"], result["loader_mappings"]), (4, 0))

    def test_failed_loader_mapping_is_not_counted_as_mapped(self):
        self.loader_mapping()
        exit = self.event("MAP_EXIT")
        stop = next(row for row in self.record["events"] if row["kind"] == "STOP" and row.get("result") == 8192)
        exit.update(result=-13, is_error=True)
        stop.update(result=-13, is_error=True)
        self.recount()
        result = self.verify()
        self.assertEqual((result["loader_mapping_attempts"], result["loader_mappings"]), (1, 0))

    def test_mapping_a_source_as_a_loader_is_refused(self):
        self.loader_mapping()
        self.event("MAP_ENTER")["path"] = self.source["path"]
        self.refused()

    def test_writable_executable_loader_map_is_refused(self):
        self.loader_mapping()
        self.event("MAP_ENTER")["prot"] = 7
        self.refused()

    def test_owned_root_ipc_does_not_count_as_source_bytes(self):
        self.owned_io()
        self.assertEqual(self.verify()["bytes_read"], 4)

    def test_pending_owned_root_reply_is_accounted_not_relabelled_as_zero(self):
        self.owned_io(pending=True)
        self.assertEqual(self.verify()["bytes_read"], 4)
        self.assertEqual(self.record["accounting"]["pending_syscalls"], 1)

    def test_false_zero_pending_ipc_accounting_is_refused(self):
        self.owned_io(pending=True)
        self.record["accounting"]["pending_syscalls"] = 0
        self.refused()

    def test_root_ipc_peer_must_be_independently_pinned(self):
        self.owned_io()
        self.event("IO_ENTER")["channel"]["peer"][0] = 9001
        self.refused()

    def test_root_ipc_endpoint_must_be_independently_pinned(self):
        self.owned_io()
        self.event("IO_ENTER")["channel"]["endpoint"] = "/run/aragorn/unowned.sock"
        self.refused()

    def test_created_eventfd_has_independent_syscall_and_identity_join(self):
        self.owned_io(internal=True)
        self.assertEqual(self.verify()["bytes_read"], 4)

    def test_eventfd_input_cannot_invent_creation_origin(self):
        self.owned_io(internal=True)
        self.event("IO_ENTER")["channel"]["created_by"] += 1
        self.refused()

    def test_eventfd_creation_cannot_substitute_output_descriptor(self):
        self.owned_io(internal=True)
        self.event("FD_CREATE")["descriptors"][0]["fd"] = 10
        self.refused()

    def test_distinct_eventfd_births_can_share_anon_inode_identity(self):
        self.aliased_eventfds()
        self.assertEqual(self.verify()["bytes_read"], 4)
        self.assertEqual(self.record["accounting"]["io_exited"], 2)

    def test_aliased_eventfd_identity_cannot_supply_an_unrecorded_birth(self):
        origins = self.aliased_eventfds()
        self.event("IO_ENTER")["channel"]["created_by"] = origins[1] + 1
        self.refused()

    def test_stdio_must_be_actual_null_device_identity(self):
        self.event("STDIO")["descriptors"][0]["rdev"] = 0
        self.refused()

    def test_missing_stdio_capture_cannot_resume_gate(self):
        self.event("STDIO")["descriptors"].pop()
        self.refused()

    def test_clone3_thread_bytes_are_independently_decoded(self):
        refs = self.threaded()
        fields = [0x50F00, 0, 0, 0, 0, 4096, 4096, 0, 0, 0, 0]
        self.record["events"][refs["clone_entry"]-1].update(syscall=435, args=[8192, 88, 0, 0, 0, 0])
        self.event("CLONE_REQUEST").update(syscall=435, clone_args=b"".join(x.to_bytes(8, "little") for x in fields).hex())
        self.assertEqual(self.verify()["threads_observed"], 2)

    def test_clone3_capture_cannot_override_return_signal(self):
        refs = self.threaded()
        fields = [0x50F00, 0, 0, 0, 17, 4096, 4096, 0]
        self.record["events"][refs["clone_entry"]-1].update(syscall=435, args=[8192, 64, 0, 0, 0, 0])
        self.event("CLONE_REQUEST").update(syscall=435, clone_args=b"".join(x.to_bytes(8, "little") for x in fields).hex())
        self.refused()

    def test_unknown_raw_syscall_cannot_hide_as_ordinary_work(self):
        self.record["events"][12]["syscall"] = 212
        self.refused()

    def test_pending_source_read_cannot_be_health_snapshot(self):
        events = deepcopy(self.record["events"][:15])
        self.finish(events, pending=1)
        self.refused()

    def test_retired_child_is_joined_to_exit_event_and_terminal_wait(self):
        self.threaded()
        events = deepcopy(self.record["events"][:32])
        events.extend([self.resume(102, 21), self.stop(pid=102, start_ticks=21, op="ENTRY", syscall=93, args=[0]*6),
                       self.resume(102, 21), self.stop(pid=102, start_ticks=21, event=6, event_message=0),
                       dict(kind="RESUME", pid=102, start_ticks=21, request="CONT")])
        terminal = self.stop(pid=102, start_ticks=21)
        terminal["status"] = 0
        events.extend([terminal, dict(kind="THREAD_EXIT", pid=102, start_ticks=21, status=0)])
        self.finish(events)
        result = self.verify()
        self.assertEqual((result["threads_observed"], result["threads_exited"]), (2, 1))


class LegacyEmptySourceTests(unittest.TestCase):
    def empty_fixture(self, *, error):
        value = legacy.PiSourceObservationReplayTests()
        value.setUp()
        self.addCleanup(value.doCleanups)
        row = value.record["sources"][0]
        row["digest"], row["identity"]["size"] = value.put_raw(b""), 0
        inventory = canonical_json(dict(schema="aragorn/pi-core-source-inventory/v1", sources=[row]))
        pin = value.put_raw(inventory)
        value.record["bindings"]["source_inventory_digest"] = pin
        value.arguments["expected_bindings"]["source_inventory_digest"] = pin
        value.arguments["source_inventory_raw"] = inventory
        entry, exit = value.record["events"][7], value.record["events"][9]
        entry.update(digest=row["digest"], identity=deepcopy(row["identity"]), count=1)
        value.record["events"][6]["args"][2] = 1
        exit.update(identity=deepcopy(row["identity"]), result=-13 if error else 0, is_error=error)
        value.record["events"][8].update(result=exit["result"], is_error=error)
        value.recount()
        return value

    def test_existing_v1_empty_source_requires_successful_delivery_attempt(self):
        self.empty_fixture(error=True).refused()

    def test_existing_v1_successful_empty_file_eof_still_qualifies_recorded_delivery(self):
        value = self.empty_fixture(error=False).verify()
        self.assertEqual(value["status"], "CONSISTENT_SOURCE_READ_COVERAGE")
        self.assertEqual(value["bytes_read"], 0)

