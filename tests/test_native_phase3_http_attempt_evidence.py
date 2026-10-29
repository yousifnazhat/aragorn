"""Inert HTTP export/replay composition checks; not retained live evidence."""

import ast
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from scripts import materialize_native_phase3_http_attempt_evidence as subject
from aragorn import native_phase3_http_collection_verify as http
from aragorn.oci_worker_protocol import canonical_json

ROOT = Path(__file__).resolve().parents[1]


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def load_function(raw, name, namespace):
    tree = ast.parse(raw)
    node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    exec(
        compile(
            ast.Module(body=[node], type_ignores=[]), "<inert-http-evidence>", "exec"
        ),
        namespace,
    )
    return namespace[name]


class HttpAttemptEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = {name: (ROOT / name).read_bytes() for name in subject.INPUTS}
        cls.rendered = subject.render(cls.original)

    def test_exact_four_outputs_are_deterministic_python(self):
        self.assertEqual(self.rendered, subject.render(self.original))
        self.assertEqual(set(self.rendered), set(subject.INPUTS))
        for name, raw in self.rendered.items():
            self.assertNotEqual(raw, self.original[name])
            ast.parse(raw)
        self.assertNotIn(
            b"blocked.verify_native_blocked_create", self.rendered[subject.MEASUREMENT]
        )
        self.assertNotIn(
            b"interval.verify_native_ingress_interval",
            self.rendered[subject.MEASUREMENT],
        )
        self.assertIn(
            b'"BOUNDED_NATIVE_HTTP_ATTEMPT_VERIFIED"', self.rendered[subject.GUEST]
        )
        self.assertIn(
            b"expected_http_fixture=_http_fixture(container)",
            self.rendered[subject.GUEST],
        )

    def test_changed_frozen_input_is_refused(self):
        for name in self.original:
            altered = self.original | {name: self.original[name] + b"\n"}
            with (
                self.subTest(name=name),
                self.assertRaises(subject.NativeHttpAttemptEvidenceRenderError),
            ):
                subject.render(altered)

    def test_staged_driver_requires_fixed_metadata_and_matching_stage_row(self):
        expected = {
            "schema": "aragorn/native-http-staged-driver/v1",
            "path": "/opt/aragorn/native-http-attempt-driver-v1.mjs",
            "mode": "0444",
            "bytes": 24,
            "digest": "sha256:" + "a" * 64,
            "stage_owned": True,
        }
        verify = load_function(
            self.rendered[subject.PUBLIC],
            "_generated_driver",
            {
                "_require": require,
                "inputs": SimpleNamespace(
                    HTTP_DRIVER_REPORT=expected, MAX_BUNDLE=2**20
                ),
                "base": SimpleNamespace(_parse=lambda raw, _limit: json.loads(raw)),
            },
        )
        row = {key: expected[key] for key in ("path", "mode", "bytes", "digest")}
        bound = {"stage_raw": canonical_json({"files": [row]})}
        verify(expected, bound)
        with self.assertRaises(ValueError):
            verify(expected | {"stage_owned": False}, bound)
        with self.assertRaises(ValueError):
            verify(
                expected,
                {
                    "stage_raw": canonical_json(
                        {"files": [row | {"digest": "sha256:" + "b" * 64}]}
                    )
                },
            )

    def test_public_export_accepts_only_exact_new_roles(self):
        tree = ast.parse(self.rendered[subject.GUEST])
        roles_node = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "_PUBLIC_ROLES"
                for target in node.targets
            )
        )
        namespace = {
            "_require": require,
            "_pin": lambda value: (
                isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
            ),
            "MAX_PUBLIC_BLOBS": 256,
            "MAX_PUBLIC_BLOB": 2**24,
            "MAX_PUBLIC_TOTAL": 2**25,
        }
        exec(
            compile(
                ast.Module(body=[roles_node], type_ignores=[]), "<inert-roles>", "exec"
            ),
            namespace,
        )
        candidate = load_function(
            self.rendered[subject.GUEST], "_candidates", namespace
        )
        for name in subject.READINESS_ROLES:
            self.assertEqual(
                candidate([{"role": name, "digest": "sha256:" + "a" * 64, "bytes": 4}]),
                [{"digest": "sha256:" + "a" * 64, "bytes": 4}],
            )
        with self.assertRaises(ValueError):
            candidate(
                [{"role": "private_grant", "digest": "sha256:" + "a" * 64, "bytes": 4}]
            )

    def replay_fixture(self):
        """Only composition is mocked; existing raw semantic consumers are not rerun."""
        blobs = {}

        def retain(value):
            raw = canonical_json(value)
            blobs[digest(raw)] = raw
            return {"text": raw.decode(), "bytes": len(raw), "digest": digest(raw)}

        fixture = {
            "container_id": "d" * 64,
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "netns_device": 4,
            "netns_inode": 4321,
        }
        binding = {
            "schema": "aragorn/runtime-http-fixture-binding/v1",
            "fixture": fixture,
            "expected_broker_uid": 995,
            "expected_broker_gid": 997,
        }
        nonce = "e" * 32
        readiness = {
            "request": {
                "schema": "aragorn/runtime-http-readiness-input/v1",
                "readiness_nonce": nonce,
                "fixture_binding_digest": digest(canonical_json(binding)),
                "timeout_ms": 500,
            },
            "claim": {"claim": "inert"},
            "result": {"interval": {"finished_ns": 10}},
            "sink": {"sink": "readiness"},
            "listener_witness": {"observed_boottime_ns": 11},
        }
        sink = {"fixture": fixture, "process": {"pid": 20}}
        ready_sink = {"fixture": fixture, "process": {"pid": 21}}
        ready_result, listener_result = (
            {"roundtrip": "checked"},
            {"listener": "checked"},
        )
        gateway = {"pid": 60, "uid": 996, "gid": 997}
        http_result = {"http": "checked", "ingress": {"gateway_peer": gateway}}
        verification = {
            "http_collection": http_result,
            "broker_readiness": {
                "round_trip": ready_result,
                "listener": listener_result,
            },
        }
        rows = {}
        for role, value in {
            "http_fixture_binding": binding,
            "http_sink_identity": sink,
            "readiness_sink_identity": ready_sink,
            "clock_before": {"clock": "before"},
            "clock_after": {"clock": "after"},
            "independent_verification": verification,
            **{"readiness_" + name: value for name, value in readiness.items()},
        }.items():
            rows[role] = retain(value)
        work = {
            "records": {
                name: retain({"record": name})
                for name in ("driver", "sink", "terminal")
            }
        }
        measured = {
            "records": {
                name: retain({"record": name})
                for name in (
                    "startup",
                    "ingress",
                    "attempt",
                    "action",
                    "pending",
                    "completion",
                )
            }
        }
        ready_report = {
            name: {
                "document": value,
                "digest": rows["readiness_" + name]["digest"],
                "bytes": rows["readiness_" + name]["bytes"],
            }
            for name, value in readiness.items()
        }
        ready_report.update(
            cleanup_complete=True,
            verification=ready_result,
            listener_verification=listener_result,
        )
        report = {
            "workload": {"digest": retain(work)["digest"]},
            "snapshot": {"digest": retain(measured)["digest"]},
            "broker_readiness": ready_report,
            "verification": verification,
            "public_blob_attempts": [
                {"role": role, "digest": row["digest"]} for role, row in rows.items()
            ],
        }
        native = Mock(return_value=http_result)
        ready = Mock(return_value=ready_result)
        listener = Mock(return_value=listener_result)
        namespace = {
            "_require": require,
            "_reader": lambda _store: lambda pin, *_args: blobs[pin],
            "_separate_stores": lambda *_args: None,
            "canonical_json": canonical_json,
            "NativeCommonMeasurementCaptureError": ValueError,
            "_EPOCH": ("pid", "start_time_ticks", "uid", "gid"),
            "_HTTP_FIXTURE": "/etc/aragorn/runtime-http-fixture.json",
            "_WORKER": "worker",
            "_GENESIS": "genesis",
            "public": SimpleNamespace(
                MAX_PUBLIC_BLOB=2**24,
                _digest=digest,
                base=SimpleNamespace(_parse=lambda raw, _limit: json.loads(raw)),
            ),
            "http": SimpleNamespace(
                fixture_binding=http.fixture_binding,
                verify_native_http_collection=native,
            ),
            "readiness_verify": SimpleNamespace(verify_broker_readiness=ready),
            "listener": SimpleNamespace(verify_listener_witness=listener),
        }
        load_function(self.rendered[subject.MEASUREMENT], "_role", namespace)
        replay = load_function(
            self.rendered[subject.MEASUREMENT],
            "verify_native_common_measurement_records",
            namespace,
        )
        request = {
            "expected_file_digests": {
                "worker": "sha256:" + "b" * 64,
                "genesis": "sha256:" + "c" * 64,
                "/etc/aragorn/runtime-http-fixture.json": rows["http_fixture_binding"][
                    "digest"
                ],
                "/etc/aragorn/runtime-http-readiness.json": rows["readiness_request"][
                    "digest"
                ],
            }
        }
        arguments = {
            "capture": {"guest": {"attempt": report}},
            "plan": {
                "request": request,
                "binding_raw": b"{}",
                "binding_digest": digest(b"{}"),
                "fixture_binding_raw": canonical_json(binding),
            },
            "public_cas": object(),
            "private_input_cas": object(),
            "expected_worker": {"pid": 30},
            "expected_broker_process": {
                "pid": 40,
                "start_time_ticks": 50,
                "uid": 995,
                "gid": 997,
            },
            "expected_gateway": gateway,
            "expected_sink_accounts": {},
            "expected_http_sink_identity": sink,
            "expected_readiness_sink_identity": ready_sink,
        }
        return SimpleNamespace(
            replay=replay,
            arguments=arguments,
            native=native,
            ready=ready,
            listener=listener,
            report=report,
            blobs=blobs,
            rows=rows,
            measured=measured,
        )

    def test_replay_forwards_exact_private_public_sources_and_native_stamps(self):
        data = self.replay_fixture()
        self.assertEqual(data.replay(**data.arguments), data.report["verification"])
        self.assertEqual(data.native.call_count, 1)
        self.assertEqual(data.ready.call_count, 1)
        self.assertEqual(data.listener.call_count, 1)
        arguments = data.native.call_args.kwargs
        self.assertIs(arguments["input_cas"], data.arguments["private_input_cas"])
        self.assertIs(arguments["evidence_cas"], data.arguments["public_cas"])
        self.assertEqual(
            set(arguments["ingress_raws"]), {"startup", "ingress", "attempt", "action"}
        )
        self.assertEqual(
            arguments["clock_before_raw"], canonical_json({"clock": "before"})
        )
        self.assertEqual(
            arguments["expected_sink_identity"],
            data.arguments["expected_http_sink_identity"],
        )

    def test_sink_identity_cannot_be_rebound_from_observer_output(self):
        data = self.replay_fixture()
        with self.assertRaises(ValueError):
            data.replay(
                **(data.arguments | {"expected_http_sink_identity": {"pid": 999}})
            )
        data.native.assert_not_called()

    def test_independent_gateway_epoch_cannot_be_replaced_by_same_account_peer(self):
        data = self.replay_fixture()
        gateway = data.arguments["expected_gateway"] | {"pid": 999}
        with self.assertRaises(ValueError):
            data.replay(**(data.arguments | {"expected_gateway": gateway}))

    def test_listener_must_follow_readiness_and_cleanup_must_complete(self):
        for change in ("clock", "cleanup"):
            data = self.replay_fixture()
            if change == "clock":
                value = {"observed_boottime_ns": 9}
                raw = canonical_json(value)
                pin = digest(raw)
                data.blobs[pin] = raw
                for row in data.report["public_blob_attempts"]:
                    if row["role"] == "readiness_listener_witness":
                        row["digest"] = pin
            else:
                data.report["broker_readiness"]["cleanup_complete"] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                data.replay(**data.arguments)
            data.native.assert_not_called()

    def test_changed_measurement_bytes_fail_before_native_consumer(self):
        data = self.replay_fixture()
        altered = deepcopy(data.measured)
        altered["records"]["completion"]["text"] = '{"record":"changed"}'
        raw = canonical_json(altered)
        pin = digest(raw)
        data.blobs[pin] = raw
        data.report["snapshot"]["digest"] = pin
        with self.assertRaises(ValueError):
            data.replay(**data.arguments)
        data.native.assert_not_called()

    def test_unfinished_or_unexported_readiness_preserves_fixture(self):
        complete = load_function(
            self.rendered[subject.GUEST],
            "_readiness_export_complete",
            {
                "_require": require,
                "canonical_json": canonical_json,
                "_IDENTITY": SimpleNamespace(_digest=digest),
            },
        )
        data = self.replay_fixture()
        report = data.report
        report["broker_readiness"].update(status="OBSERVED", cleanup_errors=[])
        raw = canonical_json(report["broker_readiness"])
        data.blobs[digest(raw)] = raw
        report["public_blob_attempts"].append(
            {"role": "broker_readiness", "digest": digest(raw)}
        )
        result = {
            "attempt": report,
            "public_blobs": [
                {"digest": pin, "text": raw.decode("utf-8")}
                for pin, raw in data.blobs.items()
            ],
        }
        self.assertTrue(complete(result))
        report["broker_readiness"]["status"] = "REFUSED"
        self.assertFalse(complete(result))
        report["broker_readiness"]["status"] = "OBSERVED"
        sink_pin = report["broker_readiness"]["sink"]["digest"]
        result["public_blobs"] = [
            row for row in result["public_blobs"] if row["digest"] != sink_pin
        ]
        self.assertFalse(complete(result))
