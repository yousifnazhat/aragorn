"""Offline regressions; one timing-only projection is from an owned capture.

Synthetic envelopes around that projection are not retained raw vendor events;
neither they nor the remaining synthetic cases assert acquisition authority.
"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from aragorn import runtime_tetragon_process as subject

ROOT = Path(__file__).resolve().parents[1]
_NAMESPACE_SOURCE = '// SPDX-License-Identifier: Apache-2.0\n// Copyright Authors of Tetragon\n\npackage consts\n\nconst MetricsNamespace = "tetragon"\n\nvar (\n\tExamplePolicyLabel   = "example-tracingpolicy"\n\tExampleKprobeLabel   = "example_kprobe"\n\tExampleSyscallLabel  = "example_syscall"\n\tExampleNamespace     = "example-namespace"\n\tExampleWorkload      = "example-workload"\n\tExamplePod           = "example-pod"\n\tExampleBinary        = "example-binary"\n\tExampleNodeName      = "example-node-name"\n\tExampleProcessLabels = []string{ExampleNamespace, ExampleWorkload, ExamplePod, ExampleBinary, ExampleNodeName}\n)\n'.encode(
    "ascii"
)


def _process(
    pid: int, *, parent: str = "", start: str = "2026-09-13T00:00:01Z"
) -> dict:
    result = {
        "exec_id": f"opaque-vendor-exec-{pid}",
        "pid": pid,
        "uid": 992,
        "start_time": start,
        "binary": "/usr/bin/true",
        "arguments": "",
        "docker": "a" * 15,
        "flags": "execve",
        "refcnt": 1,
        "ns": {"pid": {"inum": 4001}, "cgroup": {"inum": 4002}},
    }
    if parent:
        result["parent_exec_id"] = parent
    return result


def _events() -> list[dict]:
    parent = _process(100, start="2026-09-13T00:00:00Z")
    process = _process(101, parent=parent["exec_id"])
    return [
        {
            "process_exec": {"process": process, "parent": parent},
            "node_name": "synthetic-node",
            "time": "2026-09-13T00:00:02Z",
        },
        {
            "process_exit": {
                "process": copy.deepcopy(process),
                "parent": copy.deepcopy(parent),
                "status": 0,
                "time": "2026-09-13T00:00:03Z",
            },
            "node_name": "synthetic-node",
            "time": "2026-09-13T00:00:03.000000001Z",
        },
    ]


def _raw(events: list[dict]) -> bytes:
    # Whitespace/order are intentionally not Aragorn canonical JSON.
    return b"".join(json.dumps(e, ensure_ascii=False).encode() + b"\n" for e in events)


def _window(raw: bytes) -> dict:
    return {
        "schema": "aragorn/tetragon-reported-window/v1",
        "origin": "SYNTHETIC_TEST",
        "profile": subject.PROFILE,
        "producer_instance_before": "b" * 64,
        "producer_instance_after": "b" * 64,
        "node_name": "synthetic-node",
        "opened_at": "2026-09-13T00:00:00Z",
        "closed_at": "2026-09-13T00:00:04Z",
        "reader_ready_before_window": True,
        "reader_reached_eof": True,
        "producer_quiesced": True,
        "final_status_collected": True,
        "collector_restarts": 0,
        "reader_drops": 0,
        "reader_errors": 0,
        "metrics_before": dict.fromkeys(subject.LOSS_METRICS, 0),
        "metrics_after": dict.fromkeys(subject.LOSS_METRICS, 0),
        "raw_digest": subject._digest(raw),
        "raw_bytes": len(raw),
    }


class TetragonProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lock = (
            ROOT / "benchmark/tetragon-candidate-source-v1.lock.json"
        ).read_bytes()

    def normalize(self, events=None, *, raw=None, window=None):
        if raw is None:
            raw = _raw(_events() if events is None else events)
        return subject.normalize_process_capture(
            raw,
            source_lock=self.lock,
            window=_window(raw) if window is None else window,
        )

    def test_exact_selected_upstream_lock_and_drift(self) -> None:
        for raw in (None, bytearray(self.lock), b"", b"x" * (32 * 1024 + 1)):
            with (
                mock.patch.object(
                    subject,
                    "_digest",
                    side_effect=AssertionError("unbounded lock was hashed"),
                ) as hashed,
                self.assertRaises(subject.TetragonProcessError),
            ):
                subject.verify_source_lock(raw)
            hashed.assert_not_called()
        doc = subject.verify_source_lock(self.lock)
        self.assertEqual(doc["commit"], "1de2ed8ebea18e56257dc59597aa13bf8f0e471e")
        self.assertEqual(len(doc["files"]), 19)
        self.assertTrue(
            {
                "bpf/process/bpf_execve_event.c",
                "pkg/grpc/exec/exec.go",
                "pkg/ktime/ktime.go",
                "pkg/ktime/ktime_linux.go",
                "pkg/process/process.go",
            }.issubset({item["path"] for item in doc["files"]})
        )
        self.assertFalse(doc["verification"]["release_image_signature_verified"])
        self.assertIsNone(doc["verification"]["release_image_digest"])
        self.assertFalse(doc["verification"]["local_tag_signature_verified"])
        subject.verify_upstream_source_file(
            self.lock, "pkg/metrics/consts/consts.go", _NAMESPACE_SOURCE
        )
        for record in doc["files"]:
            with (
                self.subTest(source=record["path"]),
                self.assertRaises(subject.TetragonProcessError),
            ):
                subject.verify_upstream_source_file(
                    self.lock, record["path"], b"X" * record["bytes"]
                )
        for raw in (
            self.lock[:-1],
            b" " + self.lock,
            self.lock.replace(b"v1.7.0", b"v1.8.0"),
        ):
            with self.assertRaises(subject.TetragonProcessError):
                subject.verify_source_lock(raw)
        for sources in (
            {},
            {"extra": b"x"},
            {item["path"]: b"X" * item["bytes"] for item in doc["files"]},
        ):
            with self.assertRaises(subject.TetragonProcessError):
                subject.verify_upstream_source_files(self.lock, sources)
        for content in (bytearray(_NAMESPACE_SOURCE), _NAMESPACE_SOURCE[:-1], b""):
            with self.assertRaises(subject.TetragonProcessError):
                subject.verify_upstream_source_file(
                    self.lock, "pkg/metrics/consts/consts.go", content
                )
        with self.assertRaises(subject.TetragonProcessError):
            subject.verify_upstream_source_file(self.lock, "unknown", _NAMESPACE_SOURCE)

    def test_positive_is_synthetic_selected_records_without_authority(self) -> None:
        raw = _raw(_events())
        result = self.normalize(raw=raw)
        self.assertEqual(result["input_origin"], "SYNTHETIC_TEST")
        self.assertEqual(result["event_count"], 2)
        self.assertEqual(result["raw_digest"], subject._digest(raw))
        for key in subject._CEILINGS:
            self.assertIs(result[key], False)
        for event in result["events"]:
            self.assertTrue(
                all(
                    value is None for value in event["unavailable_attribution"].values()
                )
            )
        p = result["events"][0]["vendor_record"]["process_exec"]["process"]
        self.assertEqual(p["pid"], 101)
        self.assertEqual(p["docker"], "a" * 15)
        self.assertEqual(p["ns"]["cgroup"], {"inum": 4002})
        # Returned mutable content is independent of caller input and later calls.
        result["events"][0]["vendor_record"]["node_name"] = "changed"
        self.assertEqual(
            self.normalize()["events"][0]["vendor_record"]["node_name"],
            "synthetic-node",
        )

    def test_lexical_framing_byte_limits_and_unknown_variants(self) -> None:
        raw = _raw(_events())
        bad = [
            b"",
            raw[:-1],
            raw.replace(b"\n", b"\r\n"),
            b"\n" + raw,
            b"\xff\n",
            b"null\n",
            b"{}\n",
            b'{"x":0,"x":0}\n',
            b'{"x":1.0}\n',
            b'{"x":NaN}\n',
            b'{"x":"\\u0000"}\n',
            b" " * subject.MAX_CAPTURE_BYTES + b"\n",
            b" " * subject.MAX_RECORD_BYTES + raw,
        ]
        for value in bad:
            with (
                self.subTest(raw=value[:50]),
                self.assertRaises(subject.TetragonProcessError),
            ):
                self.normalize(raw=value)
        for variant in (
            "process_kprobe",
            "process_tracepoint",
            "process_throttle",
            "rate_limit_info",
            "processExec",
            "test",
        ):
            value = _events()[0]
            value[variant] = value.pop("process_exec")
            with (
                self.subTest(variant=variant),
                self.assertRaises(subject.TetragonProcessError),
            ):
                self.normalize([value])
        for change in (
            lambda e: e.update(process_exit={}),
            lambda e: e.update(extra=1),
            lambda e: e.update(aggregation_info={"count": "2"}),
            lambda e: e.update(node_labels={"x": "y"}),
        ):
            event = _events()[0]
            change(event)
            with self.assertRaises(subject.TetragonProcessError):
                self.normalize([event])

    def test_process_types_optional_fields_and_truthful_unavailable_values(
        self,
    ) -> None:
        changes = {
            "pid": [True, 0, -1, "101", 1 << 32],
            "uid": [False, -1, 1 << 32],
            "tid": [False, 0],
            "refcnt": [False, -1],
            "exec_id": ["", None, "x" * 1025],
            "docker": ["a" * 64, "a" * 14, "g" * 15],
            "arguments": [None, "x" * 16385],
            "start_time": [
                "2026-02-30T00:00:00Z",
                "2026-09-13T00:00:00.1Z",
                "2026-09-13T00:00:00+00:00",
            ],
            "ns": [
                {"cgroup": {"inum": True}},
                {"mnt": {"inum": 0}},
                {"pid": {"inum": 3, "is_host": 1}},
                {"unknown": {"inum": 3}},
            ],
            "in_init_tree": [1, "true"],
            "cap": [{}],
            "process_credentials": [{}],
            "pod": [{}],
            "environment_variables": [[]],
            "executable_digest": ["sha256:" + "a" * 64],
        }
        for field, values in changes.items():
            for value in values:
                event = _events()[0]
                event["process_exec"]["process"][field] = value
                with (
                    self.subTest(field=field, value=value),
                    self.assertRaises(subject.TetragonProcessError),
                ):
                    self.normalize([event])
        for flags in ("procFS", "unknown", "truncArgs", "miss", "execve"):
            event = _events()[0]
            p = event["process_exec"]["process"]
            p["flags"] = flags
            p["uid"] = 0  # Root is representable telemetry, not authorized effect.
            result = self.normalize([event])
            self.assertFalse(result["continuous_coverage_verified"])
            self.assertEqual(
                result["events"][0]["execution_origin"],
                "UNVERIFIED_VENDOR_RECORD_NOT_PROVEN_LIVE_EXEC",
            )

    def test_ancestry_identity_and_reported_window_conflicts(self) -> None:
        for mutate in (
            lambda e: e[0]["process_exec"]["process"].update(parent_exec_id="other"),
            lambda e: e[0]["process_exec"]["parent"].update(
                parent_exec_id="opaque-vendor-exec-101"
            ),
            lambda e: e[0]["process_exec"].update(
                ancestors=[copy.deepcopy(e[0]["process_exec"]["parent"])]
            ),
            lambda e: e[0]["process_exec"].update(ancestors=[{}] * 33),
            lambda e: e[1]["process_exit"]["process"].update(pid=102),
            lambda e: e[1]["process_exit"]["process"].update(
                exec_id="conflicting-alias"
            ),
            lambda e: e[0]["process_exec"]["process"].update(
                start_time="2026-09-13T00:00:03Z"
            ),
            lambda e: e[1]["process_exit"].update(status=False),
            lambda e: e[0].update(node_name="wrong-node"),
            lambda e: e[0].update(time="2026-09-13T00:00:05Z"),
        ):
            events = _events()
            mutate(events)
            with self.assertRaises(subject.TetragonProcessError):
                self.normalize(events)
        # Event delivery may be reordered. No total producer ordering is invented.
        self.assertEqual(self.normalize(list(reversed(_events())))["event_count"], 2)
        event = _events()[0]
        del event["process_exec"]["parent"]
        result = self.normalize([event])
        self.assertFalse(result["runtime_attribution_verified"])

        # Each record has no ancestor array, but their parent edges form one
        # long cross-record chain. The collection bound must not become O(n^2).
        count = 1024
        chain = [
            {
                "process_exec": {
                    "process": _process(
                        2000 + i,
                        parent=f"opaque-vendor-exec-{2001 + i}"
                        if i + 1 < count
                        else "",
                    )
                },
                "node_name": "synthetic-node",
                "time": "2026-09-13T00:00:02Z",
            }
            for i in range(count)
        ]
        self.assertEqual(self.normalize(chain)["event_count"], count)
        chain[-1]["process_exec"]["process"]["parent_exec_id"] = (
            "opaque-vendor-exec-2000"
        )
        with self.assertRaisesRegex(
            subject.TetragonProcessError, "cyclic vendor ancestry"
        ):
            self.normalize(chain)

        # Deterministic work accounting avoids a machine-dependent time limit.
        # String subclasses instrument only this internal graph-helper test;
        # the public raw-JSON path above always supplies ordinary strings.
        hash_calls = 0

        class CountedKey(str):
            def __hash__(self):
                nonlocal hash_calls
                hash_calls += 1
                return super().__hash__()

        keys = [CountedKey(f"counted-{i}") for i in range(count)]
        processes = [
            {
                "exec_id": key,
                "pid": i + 1,
                "start_time": "2026-09-13T00:00:01Z",
                "parent_exec_id": keys[i + 1] if i + 1 < count else "",
            }
            for i, key in enumerate(keys)
        ]
        subject._identities(processes)
        self.assertLess(hash_calls, 40 * count)

    def test_observed_timestamp_projection_and_unverified_wall_order(self) -> None:
        # Exact PID/timestamp projection of six records in owned observation
        # 189925B sha256:3f64362ab12391e5d44c7ce781e4963c8b37262707ec89095d83e719d1bf17de.
        # Its 47343B NDJSON digest is
        # sha256:bfd3a0f1789e2fc8d0d51439b80b4c2ccc345e36ea09683bb5094e2d5ad66ebb.
        # No arguments or other raw records are copied. The envelopes/exec IDs
        # below are explicitly synthetic, not a live capture or window proof.
        rows = (
            (4873, "012648982", "012648941", "012741732", "012741690"),
            (4878, "371091035", "371090951", "371179450", "371179368"),
            (4883, "655008108", "655008025", "655101816", "655101691"),
        )
        events = []
        for pid, start, executed, exited, outer_exit in rows:
            stamps = [
                f"2026-09-13T08:18:05.{part}Z"
                for part in (start, executed, exited, outer_exit)
            ]
            process = _process(pid, start=stamps[0])
            for kind, outer, body_time in (
                ("process_exec", stamps[1], None),
                ("process_exit", stamps[3], stamps[2]),
            ):
                body = {"process": copy.deepcopy(process)}
                if body_time is not None:
                    body.update(time=body_time, status=0)
                event = {kind: body, "time": outer, "node_name": "synthetic-node"}
                raw = _raw([event])
                result = subject._event(raw)
                self.assertEqual(result["vendor_record"], event)
                self.assertEqual(result["raw_digest"], subject._digest(raw))
                self.assertEqual(result["raw_bytes"], len(raw))
                self.assertIs(result["wall_time_ordering_verified"], False)
                events.append(event)
        subject._identities(
            [
                e[next(k for k in e if k.startswith("process_"))]["process"]
                for e in events
            ]
        )
        self.assertEqual(len(events), 6)

        # No guessed nanosecond tolerance: independently converted parent,
        # ancestor, process, and exit times may also reflect wall-clock steps.
        for field in ("process", "parent", "ancestor", "exit"):
            event = _events()[1]
            body = event["process_exit"]
            if field == "exit":
                body["time"] = "2026-09-14T00:00:00Z"
            elif field == "ancestor":
                body["ancestors"] = [_process(99, start="2026-09-14T00:00:00Z")]
            else:
                body[field]["start_time"] = "2026-09-14T00:00:00Z"
            result = self.normalize([event])
            self.assertIs(result["wall_time_ordering_verified"], False)
            self.assertEqual(result["events"][0]["vendor_record"], event)

        for field in ("outer", "start", "exit"):
            for invalid in ("2026-02-30T00:00:00Z", "2026-09-13T00:00:00.1Z", True):
                event = copy.deepcopy(events[1])
                if field == "outer":
                    event["time"] = invalid
                elif field == "start":
                    event["process_exit"]["process"]["start_time"] = invalid
                else:
                    event["process_exit"]["time"] = invalid
                with (
                    self.subTest(field=field, invalid=invalid),
                    self.assertRaises(subject.TetragonProcessError),
                ):
                    subject._event(_raw([event]))

        # The actual capture's missing BPF metric and reader exit 1/EOF cannot
        # be represented as a successful zero-error complete reported window.
        raw = _raw(events)
        for failure in ("missing-bpf", "reader-error"):
            window = _window(raw)
            window.update(
                opened_at="2026-09-13T08:18:00Z", closed_at="2026-09-13T08:19:00Z"
            )
            if failure == "missing-bpf":
                for phase in ("metrics_before", "metrics_after"):
                    window[phase].pop("tetragon_bpf_missed_events_total")
            else:
                window["reader_errors"] = 1
            with (
                self.subTest(failure=failure),
                self.assertRaises(subject.TetragonProcessError),
            ):
                self.normalize(raw=raw, window=window)

    def test_loss_restart_or_incomplete_window_fails_closed(self) -> None:
        raw = _raw(_events())
        changes = {
            "origin": ["LIVE_VERIFIED", None, {}],
            "profile": ["anything"],
            "producer_instance_after": ["c" * 64],
            "producer_instance_before": ["bad"],
            "raw_digest": ["sha256:" + "0" * 64],
            "raw_bytes": [True, len(raw) - 1],
            "opened_at": ["2026-09-13T00:00:04Z"],
            "reader_ready_before_window": [False, 1],
            "reader_reached_eof": [False, 1],
            "producer_quiesced": [False],
            "final_status_collected": [False],
            "collector_restarts": [1, True],
            "reader_drops": [1, True],
            "reader_errors": [1, True],
        }
        for field, values in changes.items():
            for value in values:
                window = _window(raw)
                window[field] = value
                with (
                    self.subTest(field=field),
                    self.assertRaises(subject.TetragonProcessError),
                ):
                    self.normalize(raw=raw, window=window)
        for phase in ("metrics_before", "metrics_after"):
            for metric in subject.LOSS_METRICS:
                for value in (1, True, "0", -1):
                    window = _window(raw)
                    window[phase][metric] = value
                    with (
                        self.subTest(phase=phase, metric=metric),
                        self.assertRaises(subject.TetragonProcessError),
                    ):
                        self.normalize(raw=raw, window=window)
            window = _window(raw)
            window[phase].pop(subject.LOSS_METRICS[0])
            with self.assertRaises(subject.TetragonProcessError):
                self.normalize(raw=raw, window=window)

    def test_no_raw_attribution_or_count_promotes_to_completeness(self) -> None:
        raw = _raw(_events())
        for field, value in (
            ("run_conformance_eligible", True),
            ("expected_event_count", 2),
            ("full_container_id", "a" * 64),
            ("metrics_verified", True),
        ):
            window = _window(raw)
            window[field] = value
            with self.assertRaises(subject.TetragonProcessError):
                self.normalize(raw=raw, window=window)
        # Omitting an event cannot be discovered by this unauthenticated format.
        # The remaining selection is accepted only with completeness still false.
        result = self.normalize(_events()[:1])
        self.assertEqual(result["event_count"], 1)
        self.assertFalse(result["delivery_completeness_verified"])
        self.assertFalse(result["producer_authenticity_verified"])
        self.assertFalse(result["phase3_eligible"])


if __name__ == "__main__":
    unittest.main()
