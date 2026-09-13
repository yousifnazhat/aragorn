from __future__ import annotations

import copy
import fcntl
import os
import socket
import tempfile
import time
import unittest
from unittest import mock

from aragorn import runtime_endpoint_journal as subject
from aragorn.oci_worker_protocol import canonical_json


class RuntimeEndpointJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        # Exercise the Linux-only producer's logic without a live systemd host.
        self.native_linux = subject.sys.platform == "linux"
        platform = mock.patch.object(subject.sys, "platform", "linux")
        platform.start()
        self.addCleanup(platform.stop)

    def test_existing_unix_stream_one_line_flags_and_descriptor_survive(self) -> None:
        sender, receiver = socket.socketpair()
        default_timeout = socket.getdefaulttimeout()
        try:
            before = fcntl.fcntl(sender, fcntl.F_GETFL)
            document = subject._new("worker")
            self.assertTrue(
                subject.emit_journal_event(document, descriptor=sender.fileno())
            )
            self.assertEqual(receiver.recv(8192), canonical_json(document) + b"\n")
            self.assertEqual(fcntl.fcntl(sender, fcntl.F_GETFL), before)
            sender.sendall(b"still-open")
            self.assertEqual(receiver.recv(32), b"still-open")
            for changed_timeout in (0.25, 0):
                socket.setdefaulttimeout(changed_timeout)
                with mock.patch.object(subject.os, "dup") as duplicate:
                    self.assertFalse(
                        subject.emit_journal_event(document, descriptor=sender.fileno())
                    )
                    duplicate.assert_not_called()
                self.assertEqual(fcntl.fcntl(sender, fcntl.F_GETFL), before)
        finally:
            socket.setdefaulttimeout(default_timeout)
            sender.close()
            receiver.close()

    def test_unsupported_descriptors_never_write_or_change_flags(self) -> None:
        with (
            mock.patch.object(subject.sys, "platform", "darwin"),
            mock.patch.object(subject.os, "dup") as duplicate,
        ):
            self.assertFalse(subject.emit_journal_event(subject._new("worker")))
            duplicate.assert_not_called()
        read_fd, write_fd = os.pipe()
        datagram, peer = socket.socketpair(type=socket.SOCK_DGRAM)
        inet = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with tempfile.TemporaryFile() as regular:
            try:
                for descriptor in (
                    write_fd,
                    regular.fileno(),
                    datagram.fileno(),
                    inet.fileno(),
                    -1,
                    True,
                ):
                    with self.subTest(descriptor=descriptor):
                        self.assertFalse(
                            subject.emit_journal_event(
                                subject._new("sensor"), descriptor=descriptor
                            )
                        )
                self.assertEqual(regular.tell(), 0)
                self.assertTrue(os.get_blocking(write_fd))
            finally:
                os.close(read_fd)
                os.close(write_fd)
                datagram.close()
                peer.close()
                inet.close()

    def test_full_broken_partial_outputs_are_bounded_and_duplicates_closed(
        self,
    ) -> None:
        sender, receiver = socket.socketpair()
        duplicates = []
        original_dup = os.dup

        def duplicate(fd):
            result = original_dup(fd)
            duplicates.append(result)
            return result

        try:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            # This flag change is test-owned; the producer never toggles it.
            sender.setblocking(False)
            while True:
                try:
                    sender.send(b"x" * 4096, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    break
            if self.native_linux:
                # On the real target kernel, prove MSG_DONTWAIT is sufficient
                # even when the full shared open-file description is blocking.
                sender.setblocking(True)
            before = fcntl.fcntl(sender, fcntl.F_GETFL)
            started = time.monotonic()
            with mock.patch.object(subject.os, "dup", side_effect=duplicate):
                self.assertFalse(
                    subject.emit_journal_event(
                        subject._new("broker"), descriptor=sender.fileno()
                    )
                )
                receiver.close()
                self.assertFalse(
                    subject.emit_journal_event(
                        subject._new("broker"), descriptor=sender.fileno()
                    )
                )
            self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(fcntl.fcntl(sender, fcntl.F_GETFL), before)
            for descriptor in duplicates:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            sender.close()
            receiver.close()

        sender, receiver = socket.socketpair()
        real_socket = socket.socket
        held = []

        def partial(*, fileno):
            stream = real_socket(fileno=fileno)
            held.append(stream)
            proxy = mock.Mock(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
            proxy.getpeername.side_effect = stream.getpeername
            proxy.send.side_effect = lambda raw, flags: len(raw) - 1
            proxy.close.side_effect = stream.close
            return proxy

        try:
            with mock.patch.object(subject.socket, "socket", side_effect=partial):
                self.assertFalse(
                    subject.emit_journal_event(
                        subject._new("worker"), descriptor=sender.fileno()
                    )
                )
            self.assertEqual(held[0].fileno(), -1)
            sender.sendall(b"original-open")
            self.assertEqual(receiver.recv(32), b"original-open")
        finally:
            sender.close()
            receiver.close()

    def test_exact_projection_refuses_extra_secrets_and_malformed_types(self) -> None:
        for mutate in (
            lambda item: item.update(payload="secret"),
            lambda item: item.update(error="credential=secret"),
            lambda item: item.update(peer={"pid": True, "uid": 1, "gid": 1}),
            lambda item: item.update(attempt_id="secret\n"),
            lambda item: item.update(worker_request_digest="sha256:" + "A" * 64),
            lambda item: item.update(action_request_digest="sha256:" + "1" * 64),
            lambda item: item.update(result_kind="VALIDATED_BROKER_RESULT"),
        ):
            with self.subTest(mutate=mutate):
                document = subject._new("worker")
                mutate(document)
                with mock.patch.object(subject.os, "dup") as duplicate:
                    self.assertFalse(subject.emit_journal_event(document))
                    duplicate.assert_not_called()

    def test_projection_does_not_retain_request_text_and_preserves_exception(
        self,
    ) -> None:
        records = []
        original = ValueError("secret exception")

        @subject.endpoint("worker")
        def handler():
            subject.note("peer", (123, 4, 5))
            subject.note("peer_expected")
            subject.note("frame")
            subject.note("worker_request", {"content": "secret payload"})
            subject.note("action_document", {"request": {"content": "secret payload"}})
            subject.note("submit")
            raise original

        with (
            mock.patch.object(
                subject,
                "emit_journal_event",
                side_effect=lambda item: records.append(copy.deepcopy(item)),
            ),
            self.assertRaises(ValueError) as caught,
        ):
            handler()
        self.assertIs(caught.exception, original)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["attempt_id"], records[1]["attempt_id"])
        self.assertEqual(records[1]["outcome"], "INDETERMINATE")
        self.assertEqual(records[1]["request_state"], "VALIDATED")
        self.assertNotIn(b"secret", canonical_json(records))
        self.assertTrue(all(subject._valid_event(item) for item in records))
        self.assertIsNone(subject._CURRENT.get())

    def test_emission_and_context_reset_failure_never_mask_return_or_exception(
        self,
    ) -> None:
        original_context = subject._CURRENT
        original = RuntimeError("original core error")
        token = None

        def set_context(value):
            nonlocal token
            token = original_context.set(value)
            return token

        @subject.endpoint("worker")
        def handler(raises):
            if raises:
                raise original
            return 73

        for failure in (OSError("broken output"), KeyboardInterrupt()):
            for raises in (False, True):
                proxy = mock.Mock()
                proxy.set.side_effect = set_context
                proxy.get.side_effect = original_context.get
                proxy.reset.side_effect = RuntimeError("reset failure")
                try:
                    with (
                        mock.patch.object(subject, "_CURRENT", proxy),
                        mock.patch.object(
                            subject, "emit_journal_event", side_effect=failure
                        ),
                    ):
                        if raises:
                            with self.assertRaises(RuntimeError) as caught:
                                handler(True)
                            self.assertIs(caught.exception, original)
                        else:
                            self.assertEqual(handler(False), 73)
                finally:
                    if token is not None:
                        original_context.reset(token)
                        token = None


if __name__ == "__main__":
    unittest.main()
