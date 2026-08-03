from __future__ import annotations

import copy
import json
import struct
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn import gvisor_remote_trace_capture as capture
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json


class GVisorRemoteTraceCaptureTests(unittest.TestCase):
    def test_exact_init_time_zero_drop_raw_capture_verifies_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))

            receipt = capture.verify_gvisor_remote_trace_capture(
                fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
            )
            self.assertEqual(receipt, fixture["receipt"])
            closure = capture.derive_gvisor_remote_trace_capture_closure(
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

            schema = json.loads(
                (
                    Path(__file__).parents[1]
                    / "schema/gvisor-remote-trace-capture-receipt-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                schema["properties"]["authority"]["const"], capture.AUTHORITY
            )

    def test_dynamic_or_loss_tolerant_session_config_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary), ignore_setup_error=True)
            with self.assertRaisesRegex(
                capture.GVisorRemoteTraceCaptureError,
                "remote sink profile changed",
            ):
                capture.verify_gvisor_remote_trace_capture(
                    fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            pins = fixture["pins"] | {
                "expected_runtime_lock_digest": _put(fixture, b"other runtime")
            }
            with self.assertRaisesRegex(
                capture.GVisorRemoteTraceCaptureError,
                "runtime_lock_digest drifted",
            ):
                capture.verify_gvisor_remote_trace_capture(
                    fixture["cas"], fixture["receipt_digest"], **pins
                )

    def test_drops_missing_anchor_and_unclosed_lifecycle_fail_closed(self) -> None:
        variants = (
            ({"dropped_count": 1}, "reports drops"),
            ({"include_container_start": False}, "container/start anchor"),
            ({"final_drops": 1}, "final status"),
            ({"closed_lifecycle": False}, "lifecycle is incomplete"),
        )
        for options, error in variants:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                fixture = _fixture(Path(temporary), **options)
                with self.assertRaisesRegex(
                    capture.GVisorRemoteTraceCaptureError, error
                ):
                    capture.verify_gvisor_remote_trace_capture(
                        fixture["cas"],
                        fixture["receipt_digest"],
                        **fixture["pins"],
                    )

    def test_unknown_receipt_field_and_cas_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            changed = copy.deepcopy(fixture["receipt"])
            changed["unknown"] = True
            with self.assertRaisesRegex(
                capture.GVisorRemoteTraceCaptureError,
                "missing or unknown fields",
            ):
                capture.verify_gvisor_remote_trace_capture(
                    fixture["cas"], _put(fixture, changed), **fixture["pins"]
                )

            digest = fixture["frame_digests"][0]
            hexadecimal = digest.removeprefix("sha256:")
            blob = (
                fixture["cas"].root
                / "blobs"
                / "sha256"
                / hexadecimal[:2]
                / hexadecimal[2:]
            )
            blob.chmod(0o600)
            blob.write_bytes(b"tampered")
            with self.assertRaisesRegex(
                capture.GVisorRemoteTraceCaptureError,
                "blob failed digest verification",
            ):
                capture.verify_gvisor_remote_trace_capture(
                    fixture["cas"],
                    fixture["receipt_digest"],
                    **fixture["pins"],
                )


def _fixture(
    root: Path,
    *,
    ignore_setup_error: bool = False,
    dropped_count: int = 0,
    include_container_start: bool = True,
    final_drops: int = 0,
    closed_lifecycle: bool = True,
) -> dict:
    fixture = {"cas": CAS(root / "cas"), "digests": set()}
    runtime_lock_digest = _put(fixture, b"runtime-lock")
    monitor_implementation_digest = _put(fixture, b"monitor-implementation")
    workload_receipt_digest = _put(fixture, b"workload-receipt")
    session_config = {
        "trace_session": {
            "name": capture.SESSION_NAME,
            "points": [
                {
                    "name": "container/start",
                    "optional_fields": [],
                    "context_fields": ["container_id"],
                },
                {
                    "name": "syscall/execve/enter",
                    "optional_fields": [],
                    "context_fields": ["container_id", "process_name"],
                },
            ],
            "ignore_missing": False,
            "sinks": [
                {
                    "name": "remote",
                    "config": {"endpoint": capture.SOCKET_ENDPOINT},
                    "ignore_setup_error": ignore_setup_error,
                }
            ],
        }
    }
    session_config_digest = _put(fixture, session_config)
    run_id = "1" * 32
    sandbox_id = "2" * 64
    container_id = "3" * 64
    events = list(capture._LIFECYCLE_EVENTS)
    if not closed_lifecycle:
        events.pop()
    lifecycle_digest = _put(
        fixture,
        {
            "schema": capture.LIFECYCLE_SCHEMA,
            "run_id": run_id,
            "sandbox_id": sandbox_id,
            "container_id": container_id,
            "session_config_digest": session_config_digest,
            "monitor_implementation_digest": monitor_implementation_digest,
            "workload_receipt_digest": workload_receipt_digest,
            "events": events,
        },
    )
    handshake_digest = _put(fixture, b"\x08\x01")
    final_session_status_digest = _put(
        fixture,
        (
            "SESSIONS (1)\n"
            '"Default"\n'
            f'        Sink: "remote", dropped: {final_drops}\n'
        ).encode("ascii"),
    )
    message_types = [1 if include_container_start else 11, 11]
    frames = []
    frame_digests = []
    raw_frame_bytes = 0
    for sequence, message_type in enumerate(message_types):
        raw = struct.pack("<HHI", 8, message_type, dropped_count) + bytes(
            (sequence + 1,)
        )
        digest = _put(fixture, raw)
        frame_digests.append(digest)
        raw_frame_bytes += len(raw)
        frames.append(
            {
                "sequence": sequence,
                "digest": digest,
                "size": len(raw),
                "message_type": message_type,
                "dropped_count": dropped_count,
            }
        )
    frame_manifest_digest = _put(
        fixture,
        {
            "schema": capture.FRAME_MANIFEST_SCHEMA,
            "run_id": run_id,
            "sandbox_id": sandbox_id,
            "container_id": container_id,
            "session_config_digest": session_config_digest,
            "frames": frames,
        },
    )
    receipt = {
        "schema": capture.SCHEMA,
        "authority": capture.AUTHORITY,
        "profile": capture.PROFILE,
        "status": "RECORDED",
        "run_id": run_id,
        "sandbox_id": sandbox_id,
        "container_id": container_id,
        "runtime_lock_digest": runtime_lock_digest,
        "session_config_digest": session_config_digest,
        "monitor_implementation_digest": monitor_implementation_digest,
        "workload_receipt_digest": workload_receipt_digest,
        "lifecycle_digest": lifecycle_digest,
        "sentry_handshake_digest": handshake_digest,
        "monitor_handshake_digest": handshake_digest,
        "final_session_status_digest": final_session_status_digest,
        "frame_manifest_digest": frame_manifest_digest,
        "frame_count": len(frames),
        "raw_frame_bytes": raw_frame_bytes,
    }
    receipt_digest = _put(fixture, receipt)
    fixture.update(
        {
            "receipt": receipt,
            "receipt_digest": receipt_digest,
            "frame_digests": frame_digests,
            "pins": {
                "expected_runtime_lock_digest": runtime_lock_digest,
                "expected_session_config_digest": session_config_digest,
                "expected_monitor_implementation_digest": (
                    monitor_implementation_digest
                ),
                "expected_workload_receipt_digest": workload_receipt_digest,
            },
        }
    )
    return fixture


def _put(fixture: dict, value: object) -> str:
    raw = value if isinstance(value, bytes) else canonical_json(value)
    digest = fixture["cas"].put(BytesIO(raw), max_bytes=16 * 1024 * 1024)
    fixture["digests"].add(digest)
    return digest


if __name__ == "__main__":
    unittest.main()
