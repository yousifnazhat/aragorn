from __future__ import annotations

import importlib.util
import struct
import sys
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "phase2_exit_gate.py"
_CONTAINER_ID = "a" * 64
_HEADER = struct.Struct("<HHI")


def _load_gate():
    spec = importlib.util.spec_from_file_location("_phase2_exit_gate_test", _SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Phase 2 exit gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate()


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _int(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _bytes(field: int, value: bytes | str) -> bytes:
    raw = value.encode() if isinstance(value, str) else value
    return _varint((field << 3) | 2) + _varint(len(raw)) + raw


def _context(timestamp: int, container_id: str = _CONTAINER_ID) -> bytes:
    return b"".join(
        (
            _int(1, timestamp),
            _int(2, 10),
            _int(4, 10),
            _bytes(6, container_id),
            _bytes(9, "sleep"),
        )
    )


def _payload(
    message_type: int,
    timestamp: int,
    *,
    is_exit: bool = False,
    container_id: str = _CONTAINER_ID,
) -> bytes:
    fields = [_bytes(1, _context(timestamp, container_id))]
    if is_exit:
        fields.append(_bytes(2, b""))
    if message_type == 1:
        fields.extend(
            (
                _bytes(2, _CONTAINER_ID),
                _bytes(3, "sleep"),
                _bytes(4, "/bin/sleep"),
                _bytes(4, "30"),
                _bytes(5, "PATH=/bin"),
                _bytes(5, f"HOSTNAME={_CONTAINER_ID[:12]}"),
                _bytes(5, "ARAGORN_SCENARIO=scenario-a"),
            )
        )
    elif message_type == 2:
        fields.extend(_int(field, 10) for field in range(3, 7))
    elif message_type == 7:
        fields.extend((_int(3, 56), _int(4, 0), _bytes(6, "/etc/ld.so.cache")))
    elif message_type == 11:
        fields.extend((_int(3, 221), _bytes(6, "/bin/sleep"), _bytes(7, "sleep")))
    elif message_type == 34:
        fields.extend((_int(3, 64), _int(4, 1), _int(6, 1)))
    return b"".join(fields)


def _frame(
    message_type: int,
    timestamp: int,
    *,
    is_exit: bool = False,
    container_id: str = _CONTAINER_ID,
) -> bytes:
    return _HEADER.pack(_HEADER.size, message_type, 0) + _payload(
        message_type,
        timestamp,
        is_exit=is_exit,
        container_id=container_id,
    )


def _valid_frames() -> list[bytes]:
    return [
        _frame(1, 1),
        _frame(2, 2),
        _frame(7, 3),
        _frame(7, 4, is_exit=True),
        _frame(11, 5),
        _frame(11, 6, is_exit=True),
        _frame(34, 7),
        _frame(34, 8, is_exit=True),
        _frame(5, 9),
    ]


class Phase2ExitCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cas = gate.CAS(Path(self.temporary.name) / "cas")

    def _receipt(self, frames: list[bytes]) -> dict[str, object]:
        items = []
        for frame in frames:
            digest = self.cas.put(BytesIO(frame), max_bytes=len(frame))
            items.append({"digest": digest, "size": len(frame)})
        manifest = gate.canonical_json({"frames": items})
        manifest_digest = self.cas.put(BytesIO(manifest), max_bytes=len(manifest))
        return {
            "container_id": _CONTAINER_ID,
            "frame_count": len(frames),
            "frame_manifest_digest": manifest_digest,
            "raw_frame_bytes": sum(map(len, frames)),
        }

    def _decode(self, frames: list[bytes]):
        return gate._decode_capture(
            self.cas,
            self._receipt(frames),
            scenario="scenario-a",
        )

    def test_decodes_exact_configured_point_profile(self) -> None:
        counts = self._decode(_valid_frames())

        self.assertEqual(set(counts), set(gate.REQUIRED_POINTS))
        self.assertTrue(all(counts[point] == 1 for point in gate.REQUIRED_POINTS))

    def test_missing_point_is_visible_and_dangling_pair_is_rejected(self) -> None:
        without_clone = _valid_frames()
        without_clone.pop(1)
        self.assertNotIn("sentry/clone", self._decode(without_clone))

        dangling_open = _valid_frames()
        dangling_open.pop(3)
        with self.assertRaisesRegex(gate.Phase2ExitGateError, "dangling syscalls"):
            self._decode(dangling_open)

    def test_rejects_context_mismatch_and_timestamp_regression(self) -> None:
        cases = {
            "container": (1, _frame(2, 2, container_id="b" * 64)),
            "timestamp": (1, _frame(2, 1)),
        }
        for label, (index, replacement) in cases.items():
            with self.subTest(label=label):
                frames = _valid_frames()
                frames[index] = replacement
                with self.assertRaisesRegex(
                    gate.Phase2ExitGateError,
                    "context changed or is unordered",
                ):
                    self._decode(frames)

    def test_rejects_nonminimal_protobuf_varint(self) -> None:
        frames = _valid_frames()
        header, payload = frames[0][: _HEADER.size], frames[0][_HEADER.size :]
        self.assertEqual(payload[0], 0x0A)
        frames[0] = header + b"\x8a\x00" + payload[1:]

        with self.assertRaisesRegex(gate.Phase2ExitGateError, "varint is not minimal"):
            self._decode(frames)


if __name__ == "__main__":
    unittest.main()
