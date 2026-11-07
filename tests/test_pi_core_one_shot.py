"""Focused clean one-shot Pi completion, never live effect evidence."""

import json
import subprocess
import unittest

from tests import test_pi_core_worker as offline


class PiCoreOneShotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse exact dependency and executable checks, not prior test cases.
        offline.PiCoreWorkerTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        offline.PiCoreWorkerTests.tearDownClass.__func__(cls)

    def case(self, name):
        if name not in self.fixtures:
            completed = subprocess.run([str(offline._NODE), "--no-warnings",
                str(offline._ROOT / "tests/fixtures/pi_core_one_shot_offline.ts"), name],
                cwd=offline._ROOT, env=self.environment, capture_output=True, timeout=8, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", errors="replace"))
            self.assertLessEqual(len(completed.stdout), 2 * 1024 * 1024)
            value = json.loads(completed.stdout)
            self.assertEqual(value["selected"], name)
            self.assertEqual(value["nodeVersion"], offline._NODE_VERSION)
            self.assertEqual(value["fixture"], "REAL_PI_ONE_SHOT_MOCKED_TRANSPORTS_NOT_EFFECT_AUTHORITY")
            self.assertEqual(value["liveIO"], [])
            self.fixtures[name] = value
        return self.fixtures[name]

    def stopped(self, name, reason, relay_calls):
        value = self.case(name)
        self.assertIsNone(value["error"])
        self.assertEqual(value["report"]["status"], "STOPPED")
        self.assertEqual(value["report"]["stopReason"], reason)
        self.assertLessEqual(value["providerCalls"], 1)
        self.assertEqual(value["relayCalls"], relay_calls)
        return value

    def completed(self, name):
        value = self.case(name)
        self.assertIsNone(value["error"])
        report = value["report"]
        self.assertEqual(report["status"], "COMPLETED")
        self.assertIsNone(report["stopReason"])
        self.assertEqual(report["authority"], "ADAPTER_CORRELATION_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY")
        self.assertTrue(report["agentSettled"])
        self.assertTrue(report["transcriptComplete"])
        self.assertEqual((value["providerCalls"], value["relayCalls"]), (1, 1))
        self.assertEqual((report["providerCalls"], report["toolCalls"]), (1, 1))
        self.assertEqual((value["providerAborts"], value["toolAborts"]), (0, 0))
        self.assertEqual(report["results"][0]["sourceResult"], value["replies"][0])
        tool_results = [row for row in report["messages"] if row["role"] == "toolResult"]
        self.assertEqual(len(tool_results), 1)
        self.assertFalse(tool_results[0]["isError"])
        self.assertEqual(tool_results[0]["details"], report["results"][0])
        self.assertEqual(report["messages"][-1]["role"], "toolResult")
        return value

    def test_opt_in_completes_without_abort_continuation_or_reply_rewriting(self):
        self.completed("completed")

    def test_protected_entry_selects_exact_one_shot_completion(self):
        value = self.completed("protectedEntry")
        self.assertEqual(value["requests"][0]["session_id"], "a" * 32)

    def test_default_turn_limit_behavior_is_unchanged(self):
        self.stopped("default", "TURN_LIMIT", 1)

    def test_block_remains_stopped_and_preserves_refusal(self):
        value = self.stopped("blocked", "BROKER_BLOCKED", 1)
        self.assertEqual(value["report"]["results"][0]["sourceResult"], value["replies"][0])

    def test_indeterminate_reply_is_never_promoted(self):
        value = self.stopped("indeterminate", "RELAY_INDETERMINATE", 1)
        self.assertEqual(value["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_not_submitted_reply_is_never_promoted(self):
        self.stopped("notSubmitted", "RELAY_NOT_SUBMITTED", 1)

    def test_malformed_reply_remains_uncertain_without_retry(self):
        self.stopped("malformed", "INVALID_OR_UNCERTAIN_RELAY_RESULT", 1)

    def test_wrong_request_digest_remains_uncertain(self):
        self.stopped("wrongDigest", "INVALID_OR_UNCERTAIN_RELAY_RESULT", 1)

    def test_unclassified_relay_failure_remains_uncertain(self):
        value = self.stopped("relayFailure", "INVALID_OR_UNCERTAIN_RELAY_RESULT", 1)
        self.assertEqual(value["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_caller_cancellation_is_not_clean_completion(self):
        value = self.stopped("callerAbort", "ABORTED", 1)
        self.assertFalse(value["report"]["agentSettled"])
        self.assertEqual(value["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_deadline_keeps_inflight_effect_indeterminate(self):
        value = self.stopped("relayDeadline", "DEADLINE_EXCEEDED", 1)
        self.assertFalse(value["report"]["agentSettled"])
        self.assertEqual(value["report"]["results"][0]["transportStatus"], "INDETERMINATE")

    def test_preaborted_run_has_no_callbacks(self):
        value = self.stopped("preAborted", "ABORTED", 0)
        self.assertEqual(value["providerCalls"], 0)

    def test_provider_failure_has_no_tool_or_retry(self):
        self.stopped("providerFailure", "PROVIDER_FAILED", 0)

    def test_provider_abort_is_not_relabelled_completion(self):
        self.stopped("providerAborted", "PROVIDER_ABORTED", 0)

    def test_two_tool_batch_is_rejected_before_first_relay(self):
        self.stopped("twoCalls", "TOOL_CALL_LIMIT", 0)

    def test_invalid_opt_in_or_widened_limits_refuse_before_callbacks(self):
        for name in ("invalidOption", "invalidTurns", "invalidTools"):
            with self.subTest(name=name):
                value = self.case(name)
                self.assertIsNone(value["report"])
                self.assertIsNotNone(value["error"])
                self.assertEqual((value["providerCalls"], value["relayCalls"]), (0, 0))

    def test_text_only_report_remains_correlation_not_effect_proof(self):
        value = self.case("textOnly")
        self.assertIsNone(value["error"])
        self.assertEqual(value["report"]["status"], "COMPLETED")
        self.assertEqual(value["report"]["results"], [])
        self.assertEqual((value["providerCalls"], value["relayCalls"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
