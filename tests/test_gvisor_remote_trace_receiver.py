from __future__ import annotations

import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Self
from unittest import mock

from aragorn import gvisor_remote_trace_receiver as receiver


class _Connection:
    def __init__(self, packets: list[bytes]) -> None:
        self.packets = packets
        self.sent: list[bytes] = []

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_error: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        if timeout <= 0:
            raise AssertionError("timeout must remain positive")

    def recv(self, maximum: int) -> bytes:
        return self.packets.pop(0)[:maximum] if self.packets else b""

    def send(self, packet: bytes) -> int:
        self.sent.append(packet)
        return len(packet)


class _Listener:
    def __init__(
        self,
        connection: _Connection,
        *,
        accept_error: BaseException | None = None,
    ) -> None:
        self.connection = connection
        self.accept_error = accept_error
        self.accept_count = 0
        self.closed = False

    def bind(self, path: str) -> None:
        Path(path).touch(exist_ok=False)

    def listen(self, backlog: int) -> None:
        if backlog != 1:
            raise AssertionError("receiver must accept one connection")

    def settimeout(self, timeout: float) -> None:
        if timeout <= 0:
            raise AssertionError("timeout must remain positive")

    def accept(self) -> tuple[_Connection, None]:
        self.accept_count += 1
        if self.accept_error is not None:
            raise self.accept_error
        return self.connection, None

    def close(self) -> None:
        self.closed = True


class GVisorRemoteTraceReceiverTests(unittest.TestCase):
    def test_one_bounded_v1_seqpacket_session_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            receiver.GVisorRemoteTraceReceiverError,
            "absolute root-owned path",
        ):
            receiver.receive_gvisor_remote_trace("events.sock")

        with tempfile.TemporaryDirectory() as temporary:
            socket_path = Path(temporary) / "events.sock"

            def exchange(
                frames: tuple[bytes, ...],
                *,
                handshake: bytes = receiver.V1_HANDSHAKE,
                max_frame_bytes: int = 16,
                max_total_bytes: int = 32,
                max_frames: int = 2,
            ) -> tuple[dict[str, object], _Connection]:
                connection = _Connection([handshake, *frames, b""])
                listener = _Listener(connection)
                outcome: dict[str, object] = {}
                with (
                    mock.patch.object(receiver, "_validate_socket_path"),
                    mock.patch.object(receiver, "_verify_bound_socket"),
                    mock.patch.object(
                        receiver.socket,
                        "socket",
                        return_value=listener,
                    ) as socket_factory,
                ):
                    ready = threading.Event()
                    connected = threading.Event()
                    handshake_complete = threading.Event()
                    try:
                        outcome["result"] = receiver.receive_gvisor_remote_trace(
                            socket_path,
                            timeout_seconds=1,
                            max_frame_bytes=max_frame_bytes,
                            max_total_bytes=max_total_bytes,
                            max_frames=max_frames,
                            ready_event=ready,
                            connected_event=connected,
                            handshake_event=handshake_complete,
                        )
                    except receiver.GVisorRemoteTraceReceiverError as exc:
                        outcome["error"] = exc
                socket_factory.assert_called_once_with(
                    socket.AF_UNIX,
                    socket.SOCK_SEQPACKET,
                )
                self.assertEqual(listener.accept_count, 1)
                self.assertTrue(listener.closed)
                self.assertFalse(socket_path.exists())
                self.assertTrue(ready.is_set())
                self.assertEqual(connected.is_set(), listener.accept_error is None)
                self.assertEqual(
                    handshake_complete.is_set(),
                    handshake == receiver.V1_HANDSHAKE,
                )
                return outcome, connection

            frames = (
                struct.pack("<HHI", 8, 1, 0) + b"a",
                struct.pack("<HHI", 8, 11, 0) + b"b",
            )
            outcome, connection = exchange(frames)
            self.assertEqual(connection.sent, [receiver.V1_HANDSHAKE])
            self.assertEqual(
                outcome["result"],
                receiver.GVisorRemoteTraceResult(
                    sentry_handshake=receiver.V1_HANDSHAKE,
                    monitor_handshake=receiver.V1_HANDSHAKE,
                    frames=frames,
                    frame_count=2,
                    raw_frame_bytes=sum(map(len, frames)),
                ),
            )

            failures = (
                ({"handshake": b"\x08\x02"}, "sentry handshake"),
                ({"frames": (struct.pack("<HHI", 7, 1, 0),)}, "header size"),
                ({"frames": (struct.pack("<HHI", 8, 1, 1),)}, "dropped"),
                (
                    {
                        "frames": (struct.pack("<HHI", 8, 1, 0) + b"x",),
                        "max_frame_bytes": 8,
                    },
                    "frame exceeds",
                ),
                ({"frames": frames, "max_frames": 1}, "frame count"),
                ({"frames": frames, "max_total_bytes": 17}, "total limit"),
            )
            for options, error in failures:
                with self.subTest(error=error):
                    outcome, _connection = exchange(
                        options.get("frames", ()),
                        **{
                            name: value
                            for name, value in options.items()
                            if name != "frames"
                        },
                    )
                    self.assertRegex(str(outcome["error"]), error)

            listener = _Listener(_Connection([]), accept_error=TimeoutError())
            with (
                mock.patch.object(receiver, "_validate_socket_path"),
                mock.patch.object(receiver, "_verify_bound_socket"),
                mock.patch.object(receiver.socket, "socket", return_value=listener),
                self.assertRaisesRegex(
                    receiver.GVisorRemoteTraceReceiverError,
                    "timed out",
                ),
            ):
                receiver.receive_gvisor_remote_trace(
                    socket_path,
                    timeout_seconds=0.01,
                    max_frame_bytes=16,
                    max_total_bytes=32,
                    max_frames=2,
                )
            self.assertTrue(listener.closed)
            self.assertFalse(socket_path.exists())


if __name__ == "__main__":
    unittest.main()
