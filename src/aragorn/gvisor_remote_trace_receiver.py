"""Receive one bounded raw gVisor remote seccheck session."""

from __future__ import annotations

import os
import socket
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .gvisor_remote_trace_capture import _HEADER as _FRAME_HEADER
from .gvisor_remote_trace_capture import _MAX_FRAME_BYTES as MAX_FRAME_BYTES
from .gvisor_remote_trace_capture import _MAX_FRAMES as MAX_FRAMES
from .gvisor_remote_trace_capture import _MAX_RAW_BYTES as MAX_TOTAL_BYTES

V1_HANDSHAKE = b"\x08\x01"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 300.0


class GVisorRemoteTraceReceiverError(RuntimeError):
    """The bounded remote seccheck transport failed closed."""


@dataclass(frozen=True, slots=True)
class GVisorRemoteTraceResult:
    """Raw transport bytes only; this carries no lifecycle authority."""

    sentry_handshake: bytes
    monitor_handshake: bytes
    frames: tuple[bytes, ...]
    frame_count: int
    raw_frame_bytes: int


def receive_gvisor_remote_trace(
    socket_path: str | os.PathLike[str],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_frame_bytes: int = MAX_FRAME_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
    max_frames: int = MAX_FRAMES,
    ready_event: threading.Event | None = None,
    handshake_event: threading.Event | None = None,
) -> GVisorRemoteTraceResult:
    """Accept one v1 SOCK_SEQPACKET session and retain its raw frames."""

    path = Path(socket_path)
    _validate_limits(
        timeout_seconds=timeout_seconds,
        max_frame_bytes=max_frame_bytes,
        max_total_bytes=max_total_bytes,
        max_frames=max_frames,
    )
    _validate_socket_path(path)
    deadline = time.monotonic() + timeout_seconds
    listener: socket.socket | None = None
    bound = False
    try:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        listener.bind(os.fspath(path))
        bound = True
        os.chmod(path, 0o600, follow_symlinks=False)
        listener.listen(1)
        _verify_bound_socket(path)
        if ready_event is not None:
            ready_event.set()
        _set_timeout(listener, deadline)
        connection, _address = listener.accept()
        listener.close()
        with connection:
            sentry_handshake = _receive_packet(
                connection,
                len(V1_HANDSHAKE) + 1,
                deadline,
            )
            if sentry_handshake != V1_HANDSHAKE:
                raise GVisorRemoteTraceReceiverError(
                    "gVisor remote trace v1 sentry handshake changed"
                )
            _set_timeout(connection, deadline)
            if connection.send(V1_HANDSHAKE) != len(V1_HANDSHAKE):
                raise GVisorRemoteTraceReceiverError(
                    "gVisor remote trace v1 monitor handshake was incomplete"
                )
            if handshake_event is not None:
                handshake_event.set()

            frames: list[bytes] = []
            total = 0
            while frame := _receive_packet(
                connection,
                max_frame_bytes + 1,
                deadline,
            ):
                if len(frame) > max_frame_bytes:
                    raise GVisorRemoteTraceReceiverError(
                        "gVisor remote trace frame exceeds its byte limit"
                    )
                if len(frame) < _FRAME_HEADER.size:
                    raise GVisorRemoteTraceReceiverError(
                        "gVisor remote trace frame header is truncated"
                    )
                header_size, _message_type, dropped_count = _FRAME_HEADER.unpack_from(
                    frame
                )
                if header_size != _FRAME_HEADER.size:
                    raise GVisorRemoteTraceReceiverError(
                        "gVisor remote trace frame header size changed"
                    )
                if dropped_count:
                    raise GVisorRemoteTraceReceiverError(
                        "gVisor remote trace frame reports dropped messages"
                    )
                if len(frames) >= max_frames:
                    raise GVisorRemoteTraceReceiverError(
                        "gVisor remote trace frame count exceeds its limit"
                    )
                total += len(frame)
                if total > max_total_bytes:
                    raise GVisorRemoteTraceReceiverError(
                        "gVisor remote trace raw bytes exceed their total limit"
                    )
                frames.append(frame)
        return GVisorRemoteTraceResult(
            sentry_handshake=sentry_handshake,
            monitor_handshake=V1_HANDSHAKE,
            frames=tuple(frames),
            frame_count=len(frames),
            raw_frame_bytes=total,
        )
    except GVisorRemoteTraceReceiverError:
        raise
    except TimeoutError as exc:
        raise GVisorRemoteTraceReceiverError(
            "gVisor remote trace receive timed out"
        ) from exc
    except OSError as exc:
        raise GVisorRemoteTraceReceiverError(
            f"cannot receive gVisor remote trace: {exc}"
        ) from exc
    finally:
        if listener is not None:
            listener.close()
        if bound:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def _receive_packet(connection: socket.socket, maximum: int, deadline: float) -> bytes:
    _set_timeout(connection, deadline)
    return connection.recv(maximum)


def _set_timeout(connection: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    connection.settimeout(remaining)


def _validate_limits(
    *,
    timeout_seconds: float,
    max_frame_bytes: int,
    max_total_bytes: int,
    max_frames: int,
) -> None:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS
        or type(max_frame_bytes) is not int
        or not _FRAME_HEADER.size <= max_frame_bytes <= MAX_FRAME_BYTES
        or type(max_total_bytes) is not int
        or not _FRAME_HEADER.size <= max_total_bytes <= MAX_TOTAL_BYTES
        or type(max_frames) is not int
        or not 1 <= max_frames <= MAX_FRAMES
    ):
        raise GVisorRemoteTraceReceiverError(
            "gVisor remote trace receiver limits are invalid"
        )


def _validate_socket_path(path: Path) -> None:
    if os.geteuid() != 0 or not path.is_absolute() or ".." in path.parts:
        raise GVisorRemoteTraceReceiverError(
            "gVisor remote trace socket requires an absolute root-owned path"
        )
    current = path.parent
    while True:
        try:
            parent = current.lstat()
        except OSError as exc:
            raise GVisorRemoteTraceReceiverError(
                f"cannot inspect gVisor remote trace socket ancestry: {exc}"
            ) from exc
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022
        ):
            raise GVisorRemoteTraceReceiverError(
                "gVisor remote trace socket ancestry is not root-owned and protected"
            )
        if current.parent == current:
            break
        current = current.parent
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise GVisorRemoteTraceReceiverError(
            f"cannot inspect gVisor remote trace socket path: {exc}"
        ) from exc
    raise GVisorRemoteTraceReceiverError(
        "gVisor remote trace socket path already exists"
    )


def _verify_bound_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GVisorRemoteTraceReceiverError(
            f"cannot inspect bound gVisor remote trace socket: {exc}"
        ) from exc
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise GVisorRemoteTraceReceiverError(
            "bound gVisor remote trace socket is not root-owned and protected"
        )
