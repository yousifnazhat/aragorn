"""Failure boundaries specific to selecting the pilot reader on the protected caller."""
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import replace
from unittest import TestCase, mock

from aragorn import pi_core_pilot_output_observer as output
from aragorn.oci_worker_protocol import canonical_json
from scripts.pi_core_pilot_output_observer import hold_pilot_output as offline_reader
from tests import test_pi_core_pilot_output_wiring as ordering


class ProtectedReadbackGuardTests(TestCase):
    def setUp(self):
        self.case = ordering.wiring.fixture(self, ordering.PilotOutputWiringTests)

    def test_changed_nominated_task_consumes_request_and_refuses_before_any_file_read(self):
        self.assertIs(output.hold_pilot_output, offline_reader)
        c = self.case
        plan = c.f.f.plan
        start = json.loads(plan.start_bytes)
        edited = replace(plan, start_bytes=canonical_json({**start, "task": start["task"].rstrip()}))
        with mock.patch.object(output, "hold_pilot_output") as reader:
            for candidate, reason in [(edited, "PILOT_INPUT"), (plan, "REQUEST_SPENT")]:
                with self.assertRaisesRegex(ValueError, reason):
                    with c.output.hold(activation=c.activation, plan=candidate, deadline=110):
                        self.fail("reader armed")
            reader.assert_not_called()

    def test_inner_file_close_uncertainty_prevents_release_and_holds_cleanup(self):
        c = self.case
        os_close = os.close
        failed = []
        def uncertain(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                os_close(fd)  # simulate a close that may have taken effect
                failed.append(fd)
                raise OSError("close outcome unknown")
            os_close(fd)
        with mock.patch.object(output.os, "close", side_effect=uncertain):
            report = c.run_worker()
        self.assertEqual(len(failed), 1)
        self.assertEqual(report["cleanup"]["status"], "CLEANUP_HOLD")
        self.assertIs(report["cleanup"]["pilot_output_close_unconfirmed"], True)
        self.assertNotIn("pilot_output_observation", report)
        self.assertNotIn("RELEASE", c.events)
        self.assertEqual(c.events.count("cleanup"), 1)

    def test_read_finishing_at_shortened_work_deadline_is_not_published(self):
        c = self.case
        observed = output.hold_pilot_output
        @contextmanager
        def clock_crosses_limit(*args, **kwargs):
            with observed(*args, **kwargs) as read:
                def last_read():
                    value = read()
                    # The outer operation budget still has time, but the exchange
                    # must not substitute that budget for its protected interval.
                    output.time.monotonic.return_value = c.f.r.read_bootstrap_result.call_args.args[1]
                    return value
                yield last_read
        with mock.patch.object(output, "hold_pilot_output", side_effect=clock_crosses_limit):
            report = c.run_worker()
        self.assertNotIn("pilot_output_observation", report)
        self.assertNotEqual(report["status"], "BOOTSTRAP_COMPLETE")
        self.assertNotIn("RELEASE", c.events)
        self.assertEqual(c.events.count("read"), 1)
