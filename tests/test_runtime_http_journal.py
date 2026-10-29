"""HTTP journal checks with its own 16-byte nonce, not a capability lease nonce.

The original capability stage retained 24 passing non-journal checks. Keeping
this fixture separate permits only the four affected journal checks to run.
"""

from __future__ import annotations

import copy
import types
import unittest
from unittest.mock import patch

from scripts import materialize_runtime_http_capability as renderer
from scripts import stage_runtime_phase3_ingress_profile as predecessor
from test_runtime_http_capability import fixture, result_for


class HttpJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inherited, replacements = predecessor._verified_payloads()
        original = {
            name: raw for name, _mode, raw in (inherited | replacements).values()
        }
        cls.rendered = renderer._render(renderer._JOURNAL, original[renderer._JOURNAL])

    def setUp(self):
        self.binding, self.submission, _grant = fixture()
        self.result = result_for(self.binding, self.submission)
        self.journal = types.ModuleType("aragorn._http_journal_test")
        self.journal.__package__ = "aragorn"
        # Only the exact pinned and reversibly rendered local source is run.
        exec(compile(self.rendered, renderer._JOURNAL, "exec"), self.journal.__dict__)  # noqa: S102
        self.nonce = self.enterContext(
            patch.object(self.journal.secrets, "token_hex", return_value="d" * 32)
        )
        self.socket = self.enterContext(
            patch.object(
                self.journal.socket, "socket", side_effect=AssertionError("live socket")
            )
        )
        self.addCleanup(self.socket.assert_not_called)

    def journal_event(self, result, *, role="broker"):
        records = []

        @self.journal.endpoint(role)
        def observe():
            self.journal.note("action_request", self.submission["request_digest"])
            self.journal.note("broker_result", result)

        with patch.object(
            self.journal,
            "emit_journal_event",
            side_effect=lambda event: records.append(copy.deepcopy(event)),
        ):
            observe()
        self.nonce.assert_called_with(16)
        self.assertEqual(records[-1]["attempt_id"], "d" * 32)
        return records[-1]

    def test_http_sent_journal_is_versioned_and_schema_bound(self):
        event = self.journal_event(self.result)
        self.assertEqual(event["schema"], "aragorn/runtime-endpoint-journal-event/v3")
        self.assertEqual(event["result_kind"], "VALIDATED_BROKER_RESULT")
        self.assertEqual(event["effect_status"], "SENT")
        self.assertTrue(self.journal._valid_event(event))

    def test_http_journal_does_not_accept_create_schema_sent_or_http_created(self):
        self.assertTrue(self.journal._valid_event(self.journal_event(self.result)))
        for changes in (
            {"schema": "aragorn/runtime-action-broker-result/v1"},
            {"effect_status": "CREATED"},
            {"authority": "WRONG"},
        ):
            event = self.journal_event({**self.result, **changes})
            self.assertEqual(event["result_kind"], "NONE")
            self.assertIsNone(event["effect_status"])

    def test_http_journal_validation_rejects_old_schema_and_sensor_authority(self):
        event = self.journal_event(self.result)
        self.assertTrue(self.journal._valid_event(event))
        self.assertFalse(
            self.journal._valid_event(
                {**event, "schema": "aragorn/runtime-endpoint-journal-event/v2"}
            )
        )
        self.assertFalse(self.journal._valid_event({**event, "role": "sensor"}))

    def test_successor_journal_keeps_create_and_block_states_distinct(self):
        create = {
            "schema": "aragorn/runtime-action-broker-result/v1",
            "authority": "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
            "request_digest": self.submission["request_digest"],
            "verdict": "ALLOW",
            "effect_status": "CREATED",
        }
        event = self.journal_event(create)
        self.assertEqual(event["effect_status"], "CREATED")
        self.assertTrue(self.journal._valid_event(event))
        block = self.journal_event(
            result_for(self.binding, self.submission, blocked=True)
        )
        self.assertEqual(block["effect_status"], "NOT_PERFORMED")
        self.assertTrue(self.journal._valid_event(block))


if __name__ == "__main__":
    unittest.main()
