"""Inert wire examples for B48 verification only. They are not boot, restoration or acceptance evidence."""
import json
import unittest

from scripts.build_pi_core_linux import BuildError, canonical, sha256
from scripts.verify_pi_core_owner_records import verify_owner_records


UID = "2c137c03-65bd-41ff-8813-d0719b4df791"


def owner_fixture(uid, expected=None, *, base=1000):
    expected = expected if expected is not None else {
        "runner_sha256": "a" * 64, "runner_cdhash": "b" * 40, "disk_sha256": "c" * 64,
        "store_sha256_before": "d" * 64, "policy_sha256_before": "e" * 64,
        **{k: {"dev": 1, "ino": i} for i, k in enumerate(
            ("fixture_identity", "attempt_identity", "disk_identity", "store_identity"), start=1)}}
    raw = b"non-guest parser fixture\x00\r\n\xff"
    graph = {"platform": "generic-arm64-efi", "cpu_count": 2, "memory_bytes": 4294967296,
             "nvme_controllers": 1, "raw_disks": 1, "attachment_read_only": True,
             "serial_output_only": 1, "guest_serial_input": False, "other_devices": 0, "variable_store_bound": True}
    capture = {"schema": "aragorn/bounded-host-serial/v1", "clock": "CLOCK_MONOTONIC_RAW", "raw_file": "serial.raw",
               "status": "eof", "stream_termination": "eof", "attempt_start_ns": base, "record_start_ns": base+1,
               "record_end_ns": base+12, "capture_bytes": len(raw), "capture_sha256": sha256(raw), "sync_verified": True,
               "pipe_eof": True, "boot_observed": False, "phase3_exit_eligible": False}
    events = []
    for t, name, sequence in ((2, "armed", 1), (3, "recorder-armed", None), (6, "start-issued", None),
                              (7, "start-completion-returned", None), (8, "active-observed", 2),
                              (9, "delegate-guest-stop", None), (10, "stopped-observed", 3), (11, "retired", 4)):
        event = {"schema": "aragorn/b47-owner-event/v1", "clock": "CLOCK_MONOTONIC_RAW", "attempt_uuid": uid,
                 "event": name, "monotonic_ns": base+t}
        if sequence is not None:
            event.update(schema="pi-core-vz-stop-event/v1", sequence=sequence)
        events.append(event)
    owner = {"schema": "aragorn/pi-core-vm-owner/v1", "attempt_uuid": uid, "status": "stopped-observed",
             "events": events, "capture": capture, "start_issued": True, "complete": True, "stopped_observed": True,
             "journal_sealed": True, "recorder_joined": True, "supervision_lost": False, "boot_observed": False,
             "phase3_exit_eligible": False}
    terminal = {"schema": "aragorn/b47-bound-owner-terminal/v1", "attempt_uuid": uid, "phase3_exit_eligible": False,
                "owner": owner, "graph": graph, "runner": {k: expected[k] for k in ("runner_sha256", "runner_cdhash")},
                **{k: v for k, v in expected.items() if k not in ("runner_sha256", "runner_cdhash")}}
    return ({"owner-terminal.json": canonical(terminal), "serial.raw": raw,
             "owner-events.jsonl": b"".join(canonical(e) + b"\n" for e in events)}, expected)


class OwnerRecords(unittest.TestCase):
    def setUp(self):
        self.files, self.expected = owner_fixture(UID)
        self.terminal = json.loads(self.files["owner-terminal.json"])

    def verify(self, **changes):
        return verify_owner_records(UID, dict(self.files, **changes), self.expected)

    def reject_terminal(self, where, field, value, *, both=False):
        doc = json.loads(self.files["owner-terminal.json"])
        target = doc
        for part in where:
            target = target[part]
        target[field] = value
        f = {"owner-terminal.json": canonical(doc)}
        if both:
            f["owner-events.jsonl"] = b"".join(canonical(e)+b"\n" for e in doc["owner"]["events"])
        with self.subTest(where=where, field=field, value=value), self.assertRaises(BuildError):
            self.verify(**f)

    def test_raw_bound_normal_path_only_returns_joinable_times(self):
        got = self.verify()
        self.assertEqual(got, {"attempt_uuid": UID, "attempt_start_ns": 1000, "record_start_ns": 1001,
                               "observer_armed_ns": 1002, "recorder_armed_ns": 1003, "start_issued_ns": 1006,
                               "active_observed_ns": 1008, "stopped_observed_ns": 1010, "retired_ns": 1011,
                               "record_end_ns": 1012})

    def test_terminal_must_match_external_digests_and_distinct_filesystem_identities(self):
        for k in self.expected:
            if k == "runner_cdhash" or k.endswith("sha256") or k.endswith("sha256_before"):
                alternative = "0" * len(self.expected[k])
            else:
                alternative = self.expected[k] | {"ino": 99}
            with self.subTest(k=k), self.assertRaises(BuildError):
                verify_owner_records(UID, self.files, self.expected | {k: alternative})
        self.reject_terminal(("graph",), "nvme_controllers", True)
        self.reject_terminal(("graph",), "variable_store_bound", False)
        self.reject_terminal(("disk_identity",), "dev", True)
        self.reject_terminal((), "attempt_uuid", "wrong")
        files, inputs = owner_fixture(UID, self.expected | {"store_identity": self.expected["disk_identity"]})
        with self.assertRaises(BuildError):
            verify_owner_records(UID, files, inputs)

    def test_event_order_sequence_and_explicit_loss_not_hidden_by_terminal_booleans(self):
        for i, name in ((0, "recorder-armed"), (1, "armed"), (3, "start-completion-error"), (4, "control-eof"),
                        (5, "delegate-stop-error"), (6, "force-completion-returned"), (7, "supervision-lost")):
            self.reject_terminal(("owner", "events", i), "event", name, both=True)
        for k, wrong in (("sequence", True), ("attempt_uuid", "other"), ("clock", "CLOCK_REALTIME"),
                         ("monotonic_ns", 1009), ("schema", "aragorn/b47-owner-event/v1")):
            self.reject_terminal(("owner", "events", 0), k, wrong, both=True)
        for k, wrong in (("stopped_observed", False), ("supervision_lost", True), ("complete", 1),
                         ("journal_sealed", False), ("recorder_joined", False), ("boot_observed", True)):
            self.reject_terminal(("owner",), k, wrong)

    def test_serial_bytes_bounds_eof_and_clock(self):
        for raw in (b"", self.files["serial.raw"][:-1], bytes(len(self.files["serial.raw"])), b"z" * (8 << 20)):
            with self.subTest(raw_len=len(raw)), self.assertRaises(BuildError):
                self.verify(**{"serial.raw": raw})
        for k, wrong in (("capture_bytes", True), ("capture_sha256", "c"*64), ("clock", "CLOCK_MONOTONIC"),
                         ("raw_file", "../serial.raw"), ("status", "limit"), ("pipe_eof", False),
                         ("record_start_ns", 1004), ("record_end_ns", 1009), ("record_end_ns", 180000001000),
                         ("sync_verified", False), ("phase3_exit_eligible", True)):
            self.reject_terminal(("owner", "capture"), k, wrong)

    def test_truncated_oversized_noncanonical_or_disagreeing_journals(self):
        wire = self.files["owner-events.jsonl"]
        for corrupt in (wire[:-1], wire + b"\n", wire + wire, wire.replace(b"1002", b"1001", 1),
                        b" "*2048 + wire, wire.replace(b'"sequence":1', b'"sequence":1,"sequence":1', 1)):
            with self.subTest(size=len(corrupt)), self.assertRaises(BuildError):
                self.verify(**{"owner-events.jsonl": corrupt})
        data = self.files["owner-terminal.json"]
        for other in (data.replace(b'"complete":true', b'"complete":false,"complete":true'),
                      data.replace(b'"cpu_count":2', b'"cpu_count":2.0'), b"[]", b"\xff", b" "*32769, b"null"):
            with self.subTest(size=len(other)), self.assertRaises(BuildError):
                self.verify(**{"owner-terminal.json": other})
