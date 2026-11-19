"""Wire-format examples for the offline reader only. No process, reservation, VM or qualification."""
import json
import unittest

from scripts.build_pi_core_linux import BuildError, canonical
from scripts.verify_pi_core_owner_watchdog import verify_watchdog_records


UID = "d876acea-5fac-42c8-bd1b-95eefd1e956a"


def watchdog_files(uid, owner=None):
    """Small test-only example; never an input for readiness or live evidence."""
    t = max(1, owner["attempt_start_ns"]-10) if owner else 100
    ready = owner["recorder_armed_ns"] if owner else None
    queued = owner["start_issued_ns"]+1 if owner else None
    end = owner["record_end_ns"]+10 if owner else t+100
    limits = [t+seconds*10**9 for seconds in (180,195,210)]
    ids = {"schema":"aragorn/b46-owned-host-watchdog/v1", "attempt_uuid":uid, "clock":"CLOCK_MONOTONIC_RAW"}
    start = dict(ids, reserved_raw_ns=max(1,t-1), disposition="reserved-before-spawn")
    row = dict(ids, child_pid=27215, child_reaped=True, child_returncode=0 if owner else 78, outcome="child-exited",
               exit_observed_raw_ns=end, start_raw_ns=t, effective_deadlines_raw_ns=limits,
               run_deadline_raw_ns=limits[0], graceful_deadline_raw_ns=limits[1], force_deadline_raw_ns=limits[2],
               interrupted=False, interrupt_signal=None, host_kill_requested=False, host_kill_raw_ns=None,
               graceful=None, force=None, vm_stopped_verified=False,
               owner_arm={"status":"queued" if owner else "not-granted","ready_raw_ns":ready,"queued_raw_ns":queued})
    files = {"watchdog.json":canonical(row), "watchdog.json.started":canonical(start)}
    if owner:
        files["watchdog.json.owner-arm"] = canonical(dict(
            ids, schema="aragorn/b47-owned-child-arm-decision/v1", child_pid=27215,
            run_deadline_raw_ns=limits[0], ready_raw_ns=ready, disposition="decision-not-delivery"))
    else:
        files["refusal.stderr"] = b"B47 held: no approved boot attempt\n"
    return files


def replace_fields(files, name, **changes):
    return {**files, name:canonical(dict(json.loads(files[name]), **changes))}


class WatchdogReader(unittest.TestCase):
    def setUp(self):
        self.owner = dict(attempt_uuid=UID, attempt_start_ns=100, observer_armed_ns=111, record_start_ns=112,
                          recorder_armed_ns=113, start_issued_ns=130, active_observed_ns=141,
                          stopped_observed_ns=150, retired_ns=161, record_end_ns=170)

    def test_complete_pair_allows_send_timestamp_after_native_start(self):
        row = verify_watchdog_records(UID, watchdog_files(UID, self.owner), self.owner)
        self.assertEqual(row["disposition"], "consistent-supervised-transcript")
        self.assertGreater(row["queued_raw_ns"], self.owner["start_issued_ns"])

    def test_held_refusal_requires_exact_stderr_and_no_arm_or_effect(self):
        files = watchdog_files(UID)
        self.assertEqual(verify_watchdog_records(UID, files)["disposition"], "consistent-held-refusal")
        alt = replace_fields(files, "watchdog.json", owner_arm=dict(status="peer-eof", ready_raw_ns=None, queued_raw_ns=None))
        self.assertEqual(verify_watchdog_records(UID, alt)["disposition"], "consistent-held-refusal")
        for item in ("watchdog.json.owner-arm", "watchdog.json.graceful", "watchdog.json.force",
                     "watchdog.json.kill", "owner-terminal.json", "refusal.stderr"):
            with self.subTest(item=item), self.assertRaises(BuildError):
                verify_watchdog_records(UID, {**files, item:b"unmatched bytes"})

    def test_missing_decision_foreign_pid_or_uid_and_forged_grant_refused(self):
        files = watchdog_files(UID, self.owner)
        name = "watchdog.json.owner-arm"
        for changes in (dict(child_pid=27216), dict(ready_raw_ns=999), dict(attempt_uuid="other"),
                        dict(clock="wall"), dict(disposition="delivered")):
            with self.subTest(changes=changes), self.assertRaises(BuildError):
                verify_watchdog_records(UID, replace_fields(files, name, **changes), self.owner)
        files.pop(name)
        with self.assertRaises(BuildError):
            verify_watchdog_records(UID, files, self.owner)

    def test_abnormal_or_ill_typed_terminal_cannot_attest_normal_child_exit(self):
        files = watchdog_files(UID, self.owner)
        for changes in (dict(child_reaped=1),dict(child_returncode=False),dict(interrupted=True),
                        dict(host_kill_requested=True),dict(vm_stopped_verified=True),dict(force={"sent":True}),
                        dict(outcome="child-exited-after-deadline"),dict(effective_deadlines_raw_ns=[1, 2, 3]),
                        dict(graceful_deadline_raw_ns=27),dict(start_raw_ns=True),dict(extra="ignored"),
                        dict(exit_observed_raw_ns=self.owner["record_end_ns"]-1)):
            with self.subTest(changes=changes), self.assertRaises(BuildError):
                verify_watchdog_records(UID, replace_fields(files, "watchdog.json", **changes), self.owner)

    def test_malformed_duplicate_oversized_or_truncated_reservation_is_rejected(self):
        files = watchdog_files(UID)
        name = "watchdog.json.started"
        valid = files[name]
        for bad in (valid[:-1], valid+b" ", b'{"clock":"CLOCK_MONOTONIC_RAW",'+valid[1:],
                    b" "*65537, b"{}", b"[]", b"\xff", b"["*2000 + b"]"*2000):
            with self.subTest(size=len(bad)), self.assertRaises(BuildError):
                verify_watchdog_records(UID, {**files, name:bad})

    def test_owner_ready_start_and_host_exit_times_must_join(self):
        files = watchdog_files(UID, self.owner)
        for changes in (dict(attempt_uuid="different"), dict(recorder_armed_ns=114), dict(start_issued_ns=112),
                        dict(retired_ns=180), dict(attempt_start_ns=89),dict(record_start_ns=None)):
            with self.subTest(changes=changes), self.assertRaises(BuildError):
                verify_watchdog_records(UID, files, dict(self.owner, **changes))
