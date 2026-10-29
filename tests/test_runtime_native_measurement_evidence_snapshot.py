"""Inert record composition and held-file checks, not a native capture."""

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
from scripts import runtime_native_measurement_evidence_snapshot as subject
from tests.test_native_phase3_ingress_interval_verify import JoinedData


CONTAINER = "c" * 64
PIN = "sha256:" + "f" * 64


class SnapshotData:
    """Data-only predecessor construction; no historical tests are inherited."""

    def __init__(self):
        self.joined = JoinedData()
        self.sources = {
            subject.SOURCE_PATH: b"# inert snapshot source\n",
            subject.WORKER_HELPER: b"# inert worker helper\n",
            subject.BROKER_HELPER: b"# inert effective broker helper\n",
        }
        self.joined.broker.plan["source_pins"][
            "runtime_broker_decision_measurement.py"
        ] = subject.protected._digest(self.sources[subject.BROKER_HELPER])
        self.arguments = self.joined.arguments()
        a, j = self.arguments, self.joined
        self.files = dict(self.sources)
        self.files.update(
            {
                subject.WORKER_ROOT + "/" + stage + ".json": a[stage + "_raw"]
                for stage in subject.worker.STAGES
            }
        )
        self.files[subject.CONTROL + "/" + subject._CONTROL_NAMES["pending"]] = (
            canonical_json(j.broker.pending)
        )
        self.files[subject.CONTROL + "/" + subject._CONTROL_NAMES["completion"]] = a[
            "completion_raw"
        ]
        completion = subject._parse(a["completion_raw"])
        evidence_raw = j.broker.evidence.read(
            completion["evidence_digest"], max_bytes=subject._LIMIT
        )
        evidence = subject._parse(evidence_raw)
        self.pins = {
            "evidence": completion["evidence_digest"],
            **{name: evidence[field] for name, field in subject._BROKER_FIELDS.items()},
            "profiled_submission": evidence["pending"]["submission_digest"],
        }
        for pin in self.pins.values():
            self.files[self.blob_path(pin)] = j.broker.evidence.read(
                pin, max_bytes=subject._LIMIT
            )
        self.kwargs = {
            "expected_container_id": CONTAINER,
            "expected_worker": a["expected_worker"],
            "expected_broker_process": a["expected_broker_process"],
            "expected_worker_binding_digest": a["expected_worker_binding_digest"],
            "expected_genesis_digest": a["expected_genesis_digest"],
            "expected_measurement_binding_raw": a["expected_binding_raw"],
            "expected_measurement_binding_digest": a["expected_binding_digest"],
            "expected_worker_request_digest": canonical_digest(
                j.records["ingress"]["body"]["worker_request"]
            ),
            "expected_action_request_digest": canonical_digest(j.broker.request),
            "expected_source_digest": subject.protected._digest(
                self.sources[subject.SOURCE_PATH]
            ),
            "expected_worker_helper_digest": subject.protected._digest(
                self.sources[subject.WORKER_HELPER]
            ),
        }

    @staticmethod
    def blob_path(pin):
        return subject.EVIDENCE + "/blobs/sha256/" + pin[7:9] + "/" + pin[9:]

    def close(self):
        self.joined.close()


class InertCustody:
    """Fake custody/process boundary, real canonical bytes and pure consumers."""

    def __init__(self, data):
        self.data, self.partial_reads, self.calls = data, {}, []
        self.final_called = self.closed = False
        self.postguard_path = None
        self.interrupt_path = None
        self.final_failure = False

    def hold(self, path):
        self.calls.append(("hold", path))
        return 1

    def read(self, path, uid, gid, mode, limit):
        self.calls.append(("read", path, uid, gid, mode, limit))
        if path == self.interrupt_path:
            raise KeyboardInterrupt()
        raw = self.data.files[path]
        if not 0 < len(raw) <= limit:
            raise ValueError("inert read bound")
        self.partial_reads[path] = raw
        if path == self.postguard_path:
            raise ValueError("inert post-read guard refusal")
        return raw

    def worker_inventory(self):
        self.calls.append(("inventory", subject.WORKER_ROOT))
        expected = {
            subject.WORKER_ROOT + "/" + stage + ".json"
            for stage in subject.worker.STAGES
        }
        actual = {
            path
            for path in self.data.files
            if path.startswith(subject.WORKER_ROOT + "/")
        }
        if expected != actual:
            raise ValueError("inert inventory refusal")

    def final_readbacks(self, failures):
        self.final_called = True
        if self.final_failure:
            failures.append("INERT_FINAL_READBACK_REFUSED")
        return None

    def close(self, failures):
        self.closed = True
        return None


class NativeMeasurementEvidenceSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.data = SnapshotData()
        self.addCleanup(self.data.close)
        self.custody = InertCustody(self.data)

    @contextmanager
    def inert(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(subject, "_environment"))
            stack.enter_context(patch.object(subject, "_accounts"))
            guard = stack.enter_context(
                patch.object(
                    subject,
                    "_guard",
                    return_value=self.data.joined.records["startup"]["time_namespace"],
                )
            )
            stack.enter_context(
                patch.object(
                    subject.protected, "_open_pidfd", side_effect=(1001, 1002, 1003)
                )
            )
            close = stack.enter_context(patch.object(subject.os, "close"))
            stack.enter_context(
                patch.object(subject, "_Custody", return_value=self.custody)
            )
            # This snapshot must not instantiate/read any input CAS, even though
            # the data constructor used inert CAS fixtures before entering here.
            stack.enter_context(
                patch.object(
                    CAS, "read", side_effect=AssertionError("unexpected CAS access")
                )
            )
            stack.enter_context(
                patch.object(
                    CAS, "put", side_effect=AssertionError("unexpected CAS write")
                )
            )
            yield guard, close

    def run_snapshot(self, **changes):
        with self.inert():
            return subject.snapshot_native_measurement_evidence(
                **{**self.data.kwargs, **changes}
            )

    def test_fixed_complete_public_closure_runs_real_pure_joins_without_private_store(
        self,
    ):
        result = self.run_snapshot()
        self.assertEqual(result["status"], "SNAPSHOTTED")
        self.assertEqual(
            set(result["records"]), {*subject.worker.STAGES, "pending", "completion"}
        )
        self.assertEqual(result["broker_blob_digests"], self.data.pins)
        self.assertEqual(len(result["broker_blobs"]), 5)
        self.assertEqual(
            result["public_joins"],
            {
                "worker_ingress_records_joined": True,
                "public_effective_receipt_records_joined": True,
                "private_input_closure_verified": False,
            },
        )
        self.assertTrue(all(result[flag] is False for flag in subject.FALSE_FLAGS))
        self.assertTrue(self.custody.final_called and self.custody.closed)
        paths = [row[1] for row in self.custody.calls if row[0] == "read"]
        self.assertEqual(set(paths), set(self.data.files))
        self.assertFalse(
            any(
                "decision-measurement-inputs" in path or "grant.json" in path
                for path in paths
            )
        )

    def test_missing_driver_pins_keep_public_records_but_never_pass(self):
        result = self.run_snapshot(
            expected_worker_request_digest=None, expected_action_request_digest=None
        )
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(len(result["records"]), 6)
        self.assertEqual(len(result["broker_blobs"]), 5)
        self.assertIsNone(result["public_joins"])
        self.assertEqual(result["failures"][0]["phase"], "PUBLIC_JOINS")

    def test_missing_record_does_not_prevent_other_public_reads_or_cleanup(self):
        del self.data.files[subject.WORKER_ROOT + "/ingress.json"]
        result = self.run_snapshot()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(
            set(result["records"]), {"startup", "action", "pending", "completion"}
        )
        self.assertEqual(result["unclassified_reads"][0]["role"], "attempt")
        self.assertEqual(len(result["broker_blobs"]), 5)
        self.assertTrue(self.custody.final_called and self.custody.closed)

    def test_successful_bytes_survive_post_read_directory_refusal(self):
        self.custody.postguard_path = subject.WORKER_ROOT + "/attempt.json"
        result = self.run_snapshot()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(
            result["records"]["attempt"]["text"].encode(),
            self.data.arguments["attempt_raw"],
        )
        self.assertIn("action", result["records"])
        self.assertEqual(len(result["broker_blobs"]), 5)

    def test_v1_completion_and_arbitrary_digest_path_are_not_followed(self):
        path = subject.CONTROL + "/" + subject._CONTROL_NAMES["completion"]
        original = self.data.files[path]
        for value in (
            "aragorn/runtime-broker-decision-measurement-complete/v1",
            "../../decision-measurement-inputs",
        ):
            completion = subject._parse(original)
            if value.endswith("/v1"):
                completion["schema"] = value
            else:
                completion["evidence_digest"] = value
            self.data.files[path] = canonical_json(completion)
            self.custody.calls.clear()
            with self.subTest(value=value):
                result = self.run_snapshot()
                self.assertEqual(result["status"], "REFUSED")
                self.assertEqual(result["broker_blobs"], {})
                self.assertFalse(
                    any(
                        row[0] == "read" and row[1].startswith(subject.EVIDENCE + "/")
                        for row in self.custody.calls
                    )
                )

    def test_caller_request_or_process_expectation_substitution_refuses(self):
        result = self.run_snapshot(expected_action_request_digest=PIN)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["failures"][0]["phase"], "PUBLIC_JOINS")
        # Caller process expectation is coherent/canonical but not the retained
        # broker's actual asserted epoch. The public binding joins must reject it.
        other = {
            **self.data.kwargs["expected_broker_process"],
            "start_time_ticks": 9999,
        }
        result = self.run_snapshot(expected_broker_process=other)
        self.assertEqual(result["status"], "REFUSED")
        self.assertIsNone(result["public_joins"])

    def test_bad_blob_does_not_suppress_independent_sibling_reads(self):
        broken = self.data.blob_path(self.data.pins["consumed_grant_state"])
        self.data.files[broken] = b'{"tampered":true}'
        result = self.run_snapshot()
        self.assertEqual(result["status"], "REFUSED")
        self.assertNotIn(self.data.pins["consumed_grant_state"], result["broker_blobs"])
        self.assertEqual(
            set(result["broker_blob_digests"]),
            {"evidence", "profile_receipt", "broker_result", "profiled_submission"},
        )

    def test_final_failure_and_interruption_preserve_partial_evidence(self):
        self.custody.final_failure = True
        result = self.run_snapshot()
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(len(result["records"]), 6)
        self.assertTrue(result["postcondition_failures"])
        self.custody.final_failure = False
        self.custody.partial_reads.clear()
        self.custody.interrupt_path = subject.WORKER_ROOT + "/ingress.json"
        with self.inert() as (_, close), self.assertRaises(KeyboardInterrupt) as caught:
            subject.snapshot_native_measurement_evidence(**self.data.kwargs)
        retained = caught.exception._native_measurement_evidence_snapshot
        self.assertEqual(retained["status"], "REFUSED")
        self.assertIn("startup", retained["records"])
        self.assertIn("completion", retained["records"])
        self.assertTrue(self.custody.final_called and self.custody.closed)
        self.assertEqual(close.call_count, 3)

    def test_constructor_refusal_closes_root_fd_and_preserves_primary(self):
        wrong = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0, st_gid=0)
        with (
            patch.object(subject.os, "open", return_value=88),
            patch.object(subject.os, "fstat", return_value=wrong),
            patch.object(
                subject.os, "close", side_effect=OSError("private close")
            ) as close,
        ):
            with self.assertRaisesRegex(
                subject.NativeMeasurementEvidenceSnapshotError, "ROOT_CUSTODY_REFUSED"
            ) as caught:
                subject._Custody({}, {})
        close.assert_called_once_with(88)
        self.assertEqual(
            caught.exception._snapshot_cleanup_failures,
            ("ROOT_DESCRIPTOR_CLOSE_REFUSED",),
        )

    def test_rehashed_public_pointer_never_exports_grant_shaped_bytes(self):
        raw = canonical_json(
            {
                "schema": "aragorn/runtime-capability-grant/v1",
                "private_marker": "MUST_NOT_EXPORT",
            }
        )
        pin = subject.protected._digest(raw)
        self.data.files[self.data.blob_path(pin)] = raw
        evidence = subject._parse(
            self.data.files[self.data.blob_path(self.data.pins["evidence"])]
        )
        evidence["consumed_grant_state_digest"] = pin
        evidence_raw = canonical_json(evidence)
        evidence_pin = subject.protected._digest(evidence_raw)
        self.data.files[self.data.blob_path(evidence_pin)] = evidence_raw
        path = subject.CONTROL + "/" + subject._CONTROL_NAMES["completion"]
        completion = subject._parse(self.data.files[path])
        completion["evidence_digest"] = evidence_pin
        self.data.files[path] = canonical_json(completion)
        result = self.run_snapshot()
        self.assertEqual(result["status"], "REFUSED")
        self.assertNotIn(pin, result["broker_blobs"])
        self.assertNotIn("MUST_NOT_EXPORT", canonical_json(result).decode())
        self.assertIn(
            {"role": "consumed_grant_state", "bytes": len(raw), "digest": pin},
            result["unclassified_reads"],
        )
        self.assertIn("profiled_submission", result["broker_blob_digests"])

    def test_rehashed_nested_public_fields_cannot_export_arbitrary_objects(self):
        original = dict(self.data.files)
        for name in (
            "profiled_submission",
            "state_measured_action",
            "state_attribution",
        ):
            self.data.files = dict(original)
            role = (
                "profiled_submission"
                if name == "profiled_submission"
                else "consumed_grant_state"
            )
            value = subject._parse(original[self.data.blob_path(self.data.pins[role])])
            if role == "profiled_submission":
                value["measured_action"]["session_id"] = {
                    "private": "PRIVATE_NESTED_MARKER"
                }
            else:
                claim = value["claim"]["profile_claim"]
                field = (
                    "measured_action"
                    if name == "state_measured_action"
                    else "runtime_attribution"
                )
                claim["profile_pending"][field]["private"] = "PRIVATE_NESTED_MARKER"
                claim[field + "_digest"] = canonical_digest(
                    claim["profile_pending"][field]
                )
                if field == "runtime_attribution":
                    claim["profile_pending"][field + "_digest"] = claim[
                        field + "_digest"
                    ]
                    value["claim"]["lease"][field + "_digest"] = claim[
                        field + "_digest"
                    ]
                    lease_pin = canonical_digest(value["claim"]["lease"])
                    value["claim"]["lease_digest"] = claim["lease_digest"] = lease_pin
                    value["result"]["lease_digest"] = lease_pin
                    value["result"]["profile_result"]["lease_digest"] = lease_pin
                # Existing state parsing alone accepts this nested extension.
                subject.effective.v4._state(
                    value, self.data.joined.broker.plan["grant_digest"]
                )
            raw = canonical_json(value)
            pin = subject.protected._digest(raw)
            self.data.files[self.data.blob_path(pin)] = raw
            evidence = subject._parse(
                original[self.data.blob_path(self.data.pins["evidence"])]
            )
            if role == "profiled_submission":
                evidence["pending"]["submission_digest"] = pin
            else:
                evidence["consumed_grant_state_digest"] = pin
            pending_raw = canonical_json(evidence["pending"])
            self.data.files[
                subject.CONTROL + "/" + subject._CONTROL_NAMES["pending"]
            ] = pending_raw
            evidence_raw = canonical_json(evidence)
            evidence_pin = subject.protected._digest(evidence_raw)
            self.data.files[self.data.blob_path(evidence_pin)] = evidence_raw
            completion_path = (
                subject.CONTROL + "/" + subject._CONTROL_NAMES["completion"]
            )
            completion = subject._parse(original[completion_path])
            completion.update(
                pending_digest=subject.protected._digest(pending_raw),
                evidence_digest=evidence_pin,
            )
            self.data.files[completion_path] = canonical_json(completion)
            with self.subTest(name=name):
                result = self.run_snapshot()
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn(pin, result["broker_blobs"])
                self.assertNotIn(
                    "PRIVATE_NESTED_MARKER", canonical_json(result).decode()
                )
                self.assertIn(
                    {"role": role, "bytes": len(raw), "digest": pin},
                    result["unclassified_reads"],
                )

    def test_unclassified_named_and_nested_records_export_metadata_only(self):
        for nested in (False, True):
            value = {"schema": "private-input", "secret": "PRIVATE_MARKER"}
            if nested:
                value = subject._parse(
                    self.data.arguments["startup_raw"], subject.worker.MAX_RECORD_BYTES
                )
                value["body"] = {"private": "PRIVATE_MARKER"}
            raw = canonical_json(value)
            self.data.files[subject.WORKER_ROOT + "/startup.json"] = raw
            with self.subTest(nested=nested):
                result = self.run_snapshot()
                self.assertEqual(result["status"], "REFUSED")
                self.assertNotIn("startup", result["records"])
                self.assertNotIn("PRIVATE_MARKER", canonical_json(result).decode())
                self.assertIn(
                    {
                        "role": "startup",
                        "bytes": len(raw),
                        "digest": subject.protected._digest(raw),
                    },
                    result["unclassified_reads"],
                )
                self.assertIn("completion", result["records"])

    def test_real_file_reader_is_nofollow_bounded_and_retains_postguard_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            os.chown(root, os.geteuid(), os.getegid())
            path = root / "record.json"
            path.write_bytes(b'{"public":true}')
            path.chmod(0o400)
            fd = os.open(root, subject._FLAGS)
            self.addCleanup(os.close, fd)
            custody = subject._Custody.__new__(subject._Custody)
            custody.root, custody.reads, custody.partial_reads = fd, [], {}
            custody.nodes, custody.fds = {}, []
            with patch.object(
                custody, "guard", side_effect=[None, ValueError("postguard")]
            ):
                with self.assertRaisesRegex(ValueError, "postguard"):
                    custody.read("/record.json", os.geteuid(), os.getegid(), 0o400, 64)
            self.assertEqual(custody.partial_reads["/record.json"], b'{"public":true}')
            self.assertEqual(len(custody.reads), 1)
            path.chmod(0o600)
            with self.assertRaises(Exception):
                custody.read("/record.json", os.geteuid(), os.getegid(), 0o400, 64)
            path.unlink()
            os.mkfifo(path, 0o400)
            with self.assertRaises(Exception):
                custody.read("/record.json", os.geteuid(), os.getegid(), 0o400, 64)
            path.unlink()
            path.symlink_to(root / "not-read")
            with self.assertRaises(OSError):
                custody.read("/record.json", os.geteuid(), os.getegid(), 0o400, 64)


if __name__ == "__main__":
    unittest.main()
