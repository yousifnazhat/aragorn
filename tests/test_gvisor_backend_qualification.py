from __future__ import annotations

import copy
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn import gvisor_backend_qualification as qualification
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json


class GVisorBackendQualificationTests(unittest.TestCase):
    def test_exact_three_run_receipt_verifies_and_closes_over_every_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))

            raw, loaded = qualification.load_gvisor_backend_qualification_lock(
                fixture["lock_path"]
            )
            self.assertEqual(raw, canonical_json(fixture["lock"]))
            self.assertEqual(loaded, fixture["lock"])
            verified = qualification.verify_gvisor_backend_qualification(
                fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
            )
            self.assertEqual(verified, fixture["receipt"])
            closure = qualification.derive_gvisor_backend_qualification_closure(
                fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
            )
            self.assertEqual(set(closure), fixture["digests"])
            self.assertEqual(
                closure,
                {
                    digest: len(fixture["cas"].read(digest))
                    for digest in sorted(fixture["digests"])
                },
            )

            root = Path(__file__).parents[1]
            lock_schema = json.loads(
                (root / "schema/gvisor-backend-qualification-lock-v1.schema.json")
                .read_text(encoding="utf-8")
            )
            receipt_schema = json.loads(
                (root / "schema/gvisor-backend-qualification-receipt-v1.schema.json")
                .read_text(encoding="utf-8")
            )
            self.assertEqual(
                lock_schema["properties"]["controls"]["const"],
                qualification._CONTROL_IDS,
            )
            self.assertEqual(
                receipt_schema["properties"]["authority"]["const"],
                qualification.RECEIPT_AUTHORITY,
            )

    def test_unknown_fields_and_repeated_ids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            changed = copy.deepcopy(fixture["receipt"])
            changed["unknown"] = True
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "missing or unknown fields",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][1]["run_id"] = changed["runs"][0]["run_id"]
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "repeats a run or container ID",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

            changed_lock = fixture["lock"] | {"unknown": True}
            fixture["lock_path"].write_bytes(canonical_json(changed_lock))
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "missing or unknown fields",
            ):
                qualification.load_gvisor_backend_qualification_lock(
                    fixture["lock_path"]
                )

    def test_missing_control_digest_drift_and_failed_cleanup_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))

            controls = json.loads(
                fixture["cas"].read(fixture["control_digests"][0])
            )
            controls["controls"].pop()
            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][0]["control_evidence_digest"] = _put(
                fixture, controls
            )
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "control evidence is incomplete",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

            other_runtime = _put(fixture, b"other runtime lock")
            drifted_pins = fixture["pins"] | {
                "expected_runtime_lock_digest": other_runtime
            }
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "runtime lock digest drifted",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], fixture["receipt_digest"], **drifted_pins
                )

            cleanup = json.loads(
                fixture["cas"].read(fixture["cleanup_digests"][0])
            )
            cleanup["container_absent"] = False
            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][0]["cleanup_evidence_digest"] = _put(
                fixture, cleanup
            )
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "cleanup did not complete",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

    def test_cas_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            digest = fixture["control_digests"][0]
            hexadecimal = digest.removeprefix("sha256:")
            blob = (
                fixture["cas"].root
                / "blobs"
                / "sha256"
                / hexadecimal[:2]
                / hexadecimal[2:]
            )
            blob.chmod(0o600)
            blob.write_bytes(b"{}")

            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "blob failed digest verification",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"],
                    fixture["receipt_digest"],
                    **fixture["pins"],
                )


def _fixture(root: Path) -> dict:
    cas = CAS(root / "cas")
    fixture = {"cas": cas, "digests": set()}
    runtime_lock_digest = _put(fixture, b"runtime-lock-v1")
    probe_digest = _put(fixture, b"exact-linux-arm64-probe")
    implementation_digest = _put(fixture, b"qualification-verifier")
    lock = {
        "schema": qualification.LOCK_SCHEMA,
        "authority": qualification.LOCK_AUTHORITY,
        "profile": qualification.PROFILE,
        "runs": 3,
        "runtime_lock_digest": runtime_lock_digest,
        "probe_digest": probe_digest,
        "controls": qualification._CONTROL_IDS,
    }
    lock_digest = _put(fixture, lock)
    lock_path = root / "qualification-lock.json"
    lock_path.write_bytes(canonical_json(lock))

    runs = []
    control_digests = []
    cleanup_digests = []
    for sequence in range(1, 4):
        run_id = f"{sequence:032x}"
        container_id = f"{sequence:064x}"
        run_request_digest = _put(
            fixture,
            {
                "schema": qualification.RUN_REQUEST_SCHEMA,
                "lock_digest": lock_digest,
                "runtime_lock_digest": runtime_lock_digest,
                "implementation_digest": implementation_digest,
                "probe_digest": probe_digest,
                "run_id": run_id,
            },
        )
        artifacts = {
            field: _put(fixture, f"{run_id}:{field}".encode("ascii"))
            for field in qualification._ARTIFACT_FIELDS
        }
        controls = [
            {
                "control_id": control_id,
                "observed": copy.deepcopy(expected),
            }
            for control_id, expected in qualification._CONTROL_EXPECTATIONS
        ]
        control_digest = _put(
            fixture,
            {
                "schema": qualification.CONTROL_EVIDENCE_SCHEMA,
                "lock_digest": lock_digest,
                "runtime_lock_digest": runtime_lock_digest,
                "probe_digest": probe_digest,
                "run_id": run_id,
                "container_id": container_id,
                "controls": controls,
                "artifacts": artifacts,
            },
        )
        cleanup_digest = _put(
            fixture,
            {
                "schema": qualification.CLEANUP_EVIDENCE_SCHEMA,
                "lock_digest": lock_digest,
                "run_id": run_id,
                "container_id": container_id,
                "container_absent": True,
                "trace_files_absent": True,
                "host_sentinels_unchanged": True,
                "sinks_closed": True,
            },
        )
        control_digests.append(control_digest)
        cleanup_digests.append(cleanup_digest)
        runs.append(
            {
                "run_id": run_id,
                "container_id": container_id,
                "run_request_digest": run_request_digest,
                "control_evidence_digest": control_digest,
                "cleanup_evidence_digest": cleanup_digest,
            }
        )
    receipt = {
        "schema": qualification.RECEIPT_SCHEMA,
        "authority": qualification.RECEIPT_AUTHORITY,
        "profile": qualification.PROFILE,
        "status": "PASS",
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "probe_digest": probe_digest,
        "implementation_digest": implementation_digest,
        "runs": runs,
    }
    receipt_digest = _put(fixture, receipt)
    fixture.update(
        {
            "lock": lock,
            "lock_path": lock_path,
            "receipt": receipt,
            "receipt_digest": receipt_digest,
            "control_digests": control_digests,
            "cleanup_digests": cleanup_digests,
            "pins": {
                "expected_lock_digest": lock_digest,
                "expected_runtime_lock_digest": runtime_lock_digest,
                "expected_implementation_digest": implementation_digest,
            },
        }
    )
    return fixture


def _put(fixture: dict, value: object) -> str:
    raw = value if isinstance(value, bytes) else canonical_json(value)
    digest = fixture["cas"].put(BytesIO(raw), max_bytes=2 * 1024 * 1024)
    fixture["digests"].add(digest)
    return digest


if __name__ == "__main__":
    unittest.main()
