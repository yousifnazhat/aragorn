"""Inert callback checks; fake marks are never retained as measured samples."""

import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from aragorn import native_phase3_workload_json_sum as producer
from aragorn import native_phase3_workload_json_sum_verify as consumer
from aragorn import phase3_reference_tasks as tasks
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


class JsonSumCallbackTests(unittest.TestCase):
    def setUp(self):
        self.descriptor = tasks.describe_tasks(
            Path(tasks.__file__).read_bytes()
        )["BENIGN_JSON_SUM"]
        self.request = {
            "kind": "task", "mode": "baseline", "pair_id": "p3-lab-p001",
            "task_digest": canonical_digest(self.descriptor),
            "input_digest": self.descriptor["input"]["digest"],
            "host_profile_digest": "sha256:" + "1" * 64,
            "collection_digest": "sha256:" + "2" * 64,
            "deployment_digest": "sha256:" + "3" * 64,
        }
        self.boundaries = {"TASK_ACCEPTED": 10, "TASK_COMPLETED": 20}

    def execute(self, request=None, mark=None):
        with patch.object(producer.sys, "platform", "linux"), patch.object(
            producer.time, "CLOCK_BOOTTIME", 7, create=True
        ):
            return producer.execute(
                self.request if request is None else request,
                self.boundaries.__getitem__ if mark is None else mark,
            )

    def test_real_task_once_between_marks_for_both_modes(self):
        original = tasks.execute_reference_task
        for mode in ("baseline", "instrumented"):
            request = {**self.request, "mode": mode}
            events = []

            def mark(name):
                events.append(name)
                return self.boundaries[name]

            def task(*args):
                events.append("EXECUTE")
                return original(*args)

            with patch.object(tasks, "execute_reference_task", side_effect=task) as call:
                raw = self.execute(request, mark)
            call.assert_called_once_with(
                "BENIGN_JSON_SUM", b'{"values":[1,2,3,4,5,6,7]}\n'
            )
            self.assertEqual(events, ["TASK_ACCEPTED", "EXECUTE", "TASK_COMPLETED"])
            with patch.object(tasks, "execute_reference_task", side_effect=AssertionError):
                verified = consumer.verify(raw, request, self.boundaries)
            self.assertEqual(verified["semantics"], {"completed": True})
            self.assertEqual(verified["request_digest"], canonical_digest(request))

    def test_bad_requests_refuse_before_marks_or_execution(self):
        variants = [
            {**self.request, "kind": "attempt"},
            {**self.request, "mode": "unknown"},
            {**self.request, "pair_id": "../escape"},
            {**self.request, "task_digest": "sha256:" + "4" * 64},
            {**self.request, "input_digest": "sha256:" + "4" * 64},
            {**self.request, "host_profile_digest": True},
            {**self.request, "extra": 1},
        ]
        for request in variants:
            with self.subTest(request=request), patch.object(
                tasks, "execute_reference_task", side_effect=AssertionError
            ) as call:
                with self.assertRaises(ValueError):
                    self.execute(request, lambda _: self.fail("unexpected mark"))
                call.assert_not_called()

    def test_nonlinux_and_failed_task_never_complete(self):
        with patch.object(producer.sys, "platform", "darwin"):
            with self.assertRaisesRegex(ValueError, "LINUX_BOOTTIME"):
                producer.execute(self.request, lambda _: self.fail("unexpected mark"))
        events = []
        with patch.object(tasks, "execute_reference_task", side_effect=RuntimeError("task")):
            with self.assertRaisesRegex(RuntimeError, "task"):
                self.execute(mark=lambda name: events.append(name) or 10)
        self.assertEqual(events, ["TASK_ACCEPTED"])

    def test_consumer_rejects_forged_output_flags_source_and_bindings(self):
        raw = self.execute()
        receipt = json.loads(raw)
        mutations = [
            ("observation", "result", "output", "sum", 29),
            ("observation", "result", "paired_measurement_eligible", True),
            ("observation", "task", "module_source_digest", "sha256:" + "4" * 64),
            ("boundaries", "TASK_COMPLETED", 21),
            ("deployment_digest", "sha256:" + "4" * 64),
        ]
        for *path, value in mutations:
            altered = copy.deepcopy(receipt)
            node = altered
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                consumer.verify(canonical_json(altered), self.request, self.boundaries)
        for key, value in (
            ("mode", "instrumented"), ("pair_id", "p3-lab-p002"),
            ("host_profile_digest", "sha256:" + "4" * 64),
            ("collection_digest", "sha256:" + "4" * 64),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                consumer.verify(raw, {**self.request, key: value}, self.boundaries)

    def test_bad_clock_values_are_not_coerced_or_replaced(self):
        raw = self.execute()
        for start, end in ((True, 20), (10, 10), (20, 10), (-1, 20), (10, 2**63)):
            boundaries = {"TASK_ACCEPTED": start, "TASK_COMPLETED": end}
            with self.subTest(boundaries=boundaries):
                with self.assertRaises(ValueError):
                    self.execute(mark=boundaries.__getitem__)
                with self.assertRaises(ValueError):
                    consumer.verify(raw, self.request, boundaries)

    def test_noncanonical_malformed_and_duplicate_receipts_refuse(self):
        raw = self.execute()
        for invalid in (
            b"", b"x" * 65537, b"null", b"[]", b"{}", b"\xff",
            b'{"schema":1,"schema":2}', raw + b"\n",
            raw.replace(b'"sum":28', b'"sum":28.0'),
            raw.replace(b'"sum":28', b'"sum":NaN'),
        ):
            with self.subTest(invalid=invalid[:60]), self.assertRaises(ValueError):
                consumer.verify(invalid, self.request, self.boundaries)
