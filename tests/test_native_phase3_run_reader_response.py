"""Mocked syscall/provider checks only; no sockets, processes or live proc reads."""

import base64
from contextlib import ExitStack
import json
import select
import socket
import struct
import unittest
from unittest.mock import Mock, patch

from aragorn import native_phase3_run_reader_response as leaf
from aragorn.native_phase3_run_acquisition import project_acquisition
from aragorn.native_phase3_run_acquisition_verify import verify_acquisition
from aragorn.native_phase3_run_progress import evaluate_progress
from test_native_phase3_run_acquisition import fixture, encode, digest, OTHER


def stat_bytes(pid, ticks):
    return (f"{pid} (reader (loop) name) " + " ".join(["S"] + ["0"] * 18 + [str(ticks)]) + "\n").encode()


def status_bytes(uid, gid):
    return (f"Uid:\t{uid} {uid} {uid} {uid}\nGid:\t{gid} {gid} {gid} {gid}\n"
            "CapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapBnd:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n").encode()


class Harness:
    def __init__(self):
        self.records, self.pins = fixture()
        self.now = 110
        self.response_changes = {}
        self.raw_response = None
        self.sender = (101, 997, 997)
        self.controls = None
        self.flags = 0
        self.socket_timeout = 0.0
        self.inheritable = False
        self.options = {socket.SO_TYPE: socket.SOCK_SEQPACKET, leaf._PASSCRED: 1, leaf._PASSPIDFD: 0}
        self.peer = (101, 997, 997)
        self.prequeued = False
        self.timeout = False
        self.poll_error = None
        self.send_actions = []
        self.receive_actions = []
        self.read_mutation = lambda path, raw: raw
        self.retained = []
        self.calls = []
        self.connection = Mock()
        self.connection.family = socket.AF_UNIX
        self.connection.fileno.return_value = 700
        self.connection.gettimeout.side_effect = lambda: self.socket_timeout
        self.connection.get_inheritable.side_effect = lambda: self.inheritable
        self.connection.getsockopt.side_effect = self.getsockopt
        self.connection.send.side_effect = self.send
        self.connection.recvmsg.side_effect = self.receive
        self.claim = Mock(side_effect=lambda raw: raw)
        self.retain = Mock(side_effect=self.retention)

    def getsockopt(self, level, option, *args):
        if option == leaf._PEERCRED:
            return leaf._UCREDS.pack(*self.peer)
        return self.options[option]

    def stamp(self):
        self.now += 1
        return self.now

    def read(self, path, maximum):
        path = str(path)
        self.calls.append(("read", path))
        if path == "/proc/self/fdinfo/701":
            raw = b"Pid:\t101\n"
        elif path == "/proc/sys/kernel/random/boot_id":
            raw = (self.records["epoch"]["process"]["boot_id"] + "\n").encode()
        else:
            pid = int(path.split("/")[2])
            if path.endswith("/stat"):
                raw = stat_bytes(pid, 12 if pid == 101 else 33)
            else:
                raw = status_bytes(997, 997) if pid == 101 else status_bytes(501, 501)
        return self.read_mutation(path, raw)

    def send(self, raw, flags):
        self.calls.append(("send", raw, flags))
        self.send_started = self.now
        if self.send_actions:
            action = self.send_actions.pop(0)
            if isinstance(action, BaseException):
                raise action
            return action
        return len(raw)

    def receive(self, *args):
        self.calls.append(("recvmsg", args))
        if self.receive_actions:
            raise self.receive_actions.pop(0)
        response = {
            "schema": "aragorn/native-phase3-run-reader-response/v1",
            "epoch_digest": self.pins["epoch"], "challenge_digest": self.pins["challenge"],
            "request_digest": self.pins["request"], "sequence_after": 5,
            "ack_ns": self.send_started, **self.response_changes,
        }
        controls = self.controls if self.controls is not None else [(socket.SOL_SOCKET, leaf._CREDENTIALS, leaf._UCREDS.pack(*self.sender))]
        return self.raw_response if self.raw_response is not None else encode(response), controls, self.flags, None

    def poller(self):
        harness = self

        class Poll:
            def __init__(self):
                self.registrations = []

            def register(self, fd, flags):
                self.registrations.append((fd, flags))

            def poll(self, timeout):
                if timeout == 0:
                    return [(700, select.POLLIN)] if harness.prequeued else []
                if harness.poll_error is not None:
                    return harness.poll_error
                event = select.POLLOUT if self.registrations[0][1] & select.POLLOUT else select.POLLIN
                if harness.timeout and event == select.POLLIN:
                    harness.now = harness.records["challenge"]["deadline_ns"]
                    return []
                return [(700, event)]

        return Poll()

    def retention(self, raw, *, expected_digest):
        self.retained.append(raw)
        return {"digest": expected_digest, "bytes": len(raw)}

    def __enter__(self):
        self.stack = ExitStack()
        replacements = (
            (leaf.sys, "platform", "linux"),
            (leaf.os, "getpid", Mock(return_value=5000)),
            (leaf.os, "geteuid", Mock(return_value=501)),
            (leaf.os, "getegid", Mock(return_value=501)),
            (leaf.threading, "get_native_id", Mock(return_value=5000)),
            (leaf.clock, "_stamp", Mock(side_effect=self.stamp)),
            (leaf.clock, "_namespace", Mock(return_value={"device": 1, "inode": 99})),
            (leaf.process, "_read_virtual_file", Mock(side_effect=self.read)),
            (leaf.process, "open_peer_pidfd", Mock(return_value=701)),
            (leaf.process, "require_live_pidfd", Mock()),
            (leaf.select, "poll", Mock(side_effect=self.poller)),
            (leaf.os, "open", Mock(side_effect=[901, 902])),
            (leaf.os, "close", Mock()),
        )
        for obj, name, replacement in replacements:
            self.stack.enter_context(patch.object(obj, name, replacement))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def run(self, **changes):
        arguments = {"epoch_raw": encode(self.records["epoch"]), "challenge_raw": encode(self.records["challenge"]),
                     "bindings": self.pins, "connection_epoch": "d" * 64, "consume_once": self.claim, "retain": self.retain}
        arguments.update(changes)
        return leaf.acquire_reader_response(self.connection, **arguments)


class ReaderResponseTests(unittest.TestCase):
    def refusal(self, h, **args):
        with self.assertRaises(leaf.ReaderResponseError) as caught:
            h.run(**args)
        error = caught.exception
        self.assertLessEqual(len(error.partial_evidence), 131072)
        self.assertIs(json.loads(error.partial_evidence)["effect_authorized"], False)
        h.connection.close.assert_not_called()
        h.connection.settimeout.assert_not_called()
        h.connection.setblocking.assert_not_called()
        return error

    def test_acquires_and_retains_actual_readbacks_then_joins_independently(self):
        with Harness() as h:
            reader = h.run()
            h.claim.assert_called_once()
            h.retain.assert_called_once()
            leaf.process.open_peer_pidfd.assert_called_once_with(h.connection, 101)
            self.assertEqual([call.args[0] for call in leaf.os.close.call_args_list], [902, 901, 701])
            self.assertGreater(leaf.process.require_live_pidfd.call_count, 10)
            self.assertEqual(reader["status"], "ACK")
            evidence = json.loads(h.retained[0])
            self.assertEqual(base64.b64decode(evidence["before_reader_stat_before_base64"]), stat_bytes(101, 12))
            self.assertEqual(base64.b64decode(evidence["after_reader_status_base64"]), status_bytes(997, 997))
            self.assertLess(reader["ack_ns"], evidence["send_finished_ns"])
            self.assertEqual(reader["ack_ns"], evidence["send_started_ns"])
            self.assertEqual(h.connection.recvmsg.call_args.args, (4097, 4096, socket.MSG_DONTWAIT | leaf._CLOEXEC))
            self.assertEqual(h.connection.send.call_args.args[1], socket.MSG_DONTWAIT | leaf._NOSIGNAL)
            self.assertEqual(evidence["send_call_flags"], h.connection.send.call_args.args[1])
            self.assertEqual(evidence["recvmsg_call_flags"], h.connection.recvmsg.call_args.args[2])
            self.assertEqual(evidence["receive_flags"], h.flags)
            h.records["reader"] = reader
            h.records["loss"]["after"] = None
            h.records["submission"].update(intent=True, custody="PARTIAL")
            raw = encode(h.records)
            window = project_acquisition(raw, bindings=h.pins)
            self.assertIsNone(json.loads(window)["loss_after"])
            decision = evaluate_progress(window, expected_epoch=h.pins["epoch"], expected_challenge=h.pins["challenge"])
            self.assertEqual(decision["disposition"], "INDETERMINATE")
            result = verify_acquisition(raw, window, decision, bindings=h.pins, expected_raw_digest=digest(raw))
            self.assertIs(result["acquisition_authenticity_verified"], False)

    def test_socket_preflight_refuses_before_claim_without_mode_mutation(self):
        cases = (("socket_timeout", None), ("socket_timeout", 0.1), ("inheritable", True),
                 ("peer", (999, 997, 997)), ("peer", (101, 998, 997)))
        for name, value in cases:
            with self.subTest(name=name, value=value), Harness() as h:
                setattr(h, name, value)
                self.refusal(h)
                h.claim.assert_not_called()
                h.connection.send.assert_not_called()
        for option, value in ((socket.SO_TYPE, socket.SOCK_STREAM), (leaf._PASSCRED, 0), (leaf._PASSPIDFD, 1)):
            with self.subTest(option=option), Harness() as h:
                h.options[option] = value
                self.refusal(h)
                h.claim.assert_not_called()

    def test_sender_must_match_even_while_original_peer_is_alive(self):
        for sender in ((102, 997, 997), (101, 998, 997), (101, 997, 998)):
            with self.subTest(sender=sender), Harness() as h:
                h.sender = sender
                self.refusal(h)
                h.connection.recvmsg.assert_called_once()

    def test_ancillary_fds_close_before_refusal_even_on_truncation(self):
        for kind in (socket.SCM_RIGHTS, leaf._PIDFD):
            with self.subTest(kind=kind), Harness() as h:
                h.controls = [(socket.SOL_SOCKET, kind, struct.pack("ii", 810, 811))]
                h.flags = socket.MSG_CTRUNC
                error = self.refusal(h)
                self.assertIn("ancillary refused", str(error.original_failure))
                self.assertEqual([c.args[0] for c in leaf.os.close.call_args_list], [810, 811, 902, 901, 701])
                self.assertIn("controls", json.loads(error.partial_evidence))

    def test_ancillary_rejection_never_closes_unknown_integers(self):
        for controls in ([], [(socket.SOL_SOCKET, leaf._CREDENTIALS, b"short")],
                         [(999, 999, struct.pack("i", 810))],
                         [(socket.SOL_SOCKET, leaf._CREDENTIALS, leaf._UCREDS.pack(101, 997, 997))] * 2):
            with self.subTest(controls=controls), Harness() as h:
                h.controls = controls
                self.refusal(h)
                self.assertEqual([c.args[0] for c in leaf.os.close.call_args_list], [902, 901, 701])

    def test_claim_is_single_use_and_failed_or_partial_readback_never_sends(self):
        for result in (b"partial", RuntimeError("claim exists"), KeyboardInterrupt()):
            with self.subTest(result=result), Harness() as h:
                h.claim.side_effect = result if isinstance(result, BaseException) else lambda raw: result
                error = self.refusal(h)
                h.claim.assert_called_once()
                h.connection.send.assert_not_called()
                self.assertTrue(json.loads(error.partial_evidence)["claim_attempted"])
                self.assertFalse(json.loads(error.partial_evidence)["claim_confirmed"])
                if type(result) is bytes:
                    self.assertEqual(base64.b64decode(json.loads(error.partial_evidence)["claim_readback_base64"]), result)

    def test_prequeued_or_expired_inputs_do_not_consume(self):
        for case in ("prequeued", "expired"):
            with self.subTest(case=case), Harness() as h:
                if case == "prequeued":
                    h.prequeued = True
                else:
                    h.now = 200
                self.refusal(h)
                h.claim.assert_not_called()

    def test_send_eagain_waits_but_short_or_interrupted_send_never_retries(self):
        with Harness() as h:
            h.send_actions = [BlockingIOError()]
            self.assertEqual(h.run()["status"], "ACK")
            self.assertEqual(h.connection.send.call_count, 2)
            h.claim.assert_called_once()
        for action in (1, InterruptedError(), KeyboardInterrupt()):
            with self.subTest(action=action), Harness() as h:
                h.send_actions = [action]
                error = self.refusal(h)
                h.connection.send.assert_called_once()
                h.claim.assert_called_once()
                h.connection.recvmsg.assert_not_called()
                evidence = json.loads(error.partial_evidence)
                self.assertEqual(evidence["send_call_flags"], socket.MSG_DONTWAIT | leaf._NOSIGNAL)
                self.assertNotIn("recvmsg_call_flags", evidence)

    def test_receive_wait_retries_keep_budget_and_timeout_has_no_invented_ack(self):
        with Harness() as h:
            h.receive_actions = [BlockingIOError()]
            self.assertEqual(h.run()["status"], "ACK")
            h.claim.assert_called_once()
            h.connection.send.assert_called_once()
        with Harness() as h:
            h.receive_actions = [InterruptedError()]
            error = self.refusal(h)
            h.claim.assert_called_once()
            h.connection.recvmsg.assert_called_once()
            evidence = json.loads(error.partial_evidence)
            self.assertEqual(evidence["send_call_flags"], socket.MSG_DONTWAIT | leaf._NOSIGNAL)
            self.assertEqual(evidence["recvmsg_call_flags"], socket.MSG_DONTWAIT | leaf._CLOEXEC)
            self.assertNotIn("receive_flags", evidence)
        with Harness() as h:
            h.timeout = True
            reader = h.run()
            self.assertEqual(reader["status"], "TIMEOUT")
            self.assertEqual(reader["sequence_after"], 4)
            self.assertIsNone(reader["ack_ns"])
            self.assertIsNone(reader["received_ns"])
            h.connection.recvmsg.assert_not_called()

    def test_pidfd_poll_and_readback_discontinuities_refuse(self):
        for events in ([(701, select.POLLIN)], [(700, select.POLLHUP)], [(700, select.POLLERR)]):
            with self.subTest(events=events), Harness() as h:
                h.poll_error = events
                self.refusal(h)
        with Harness() as h:
            leaf.process.open_peer_pidfd.side_effect = ValueError("wrong socket PIDFD")
            self.refusal(h)
            h.claim.assert_not_called()
        for path, raw in (("/proc/self/fdinfo/701", b"Pid:\t999\n"),
                          ("/proc/101/stat", stat_bytes(101, 999)),
                          ("/proc/sys/kernel/random/boot_id", b"different\n")):
            with self.subTest(path=path), Harness() as h:
                h.read_mutation = lambda p, original: raw if p == path else original
                self.refusal(h)
                h.claim.assert_not_called()
        with Harness() as h:
            leaf.clock._namespace.return_value = {"device": 1, "inode": 100}
            self.refusal(h)

    def test_raw_stat_and_status_parsers_refuse_malformed_or_privileged_state(self):
        malformed = (
            ("/proc/101/stat", b"101 (truncated) S 0\n"),
            ("/proc/101/stat", stat_bytes(999, 12)),
            ("/proc/101/status", status_bytes(997, 997) + b"Uid: 997 997 997 997\n"),
            ("/proc/101/status", status_bytes(997, 997).replace(b"CapEff:\t0\n", b"")),
            ("/proc/101/status", status_bytes(997, 997).replace(b"CapBnd:\t0", b"CapBnd:\t1")),
            ("/proc/101/status", status_bytes(997, 997).replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0")),
            ("/proc/101/status", status_bytes(997, 997).replace(b"997 997 997 997", b"997 0 997 997", 1)),
            ("/proc/101/status", status_bytes(997, 997).replace(b"CapAmb:\t0", b"CapAmb:\txyz")),
            ("/proc/101/status", b"\xff"),
        )
        for path, raw in malformed:
            with self.subTest(raw=raw), Harness() as h:
                h.read_mutation = lambda p, original: raw if p == path else original
                error = self.refusal(h)
                self.assertIn(base64.b64encode(raw).decode(), error.partial_evidence.decode())
                h.claim.assert_not_called()

    def test_ack_framing_pins_and_chronology_refuse(self):
        for changes in ({"ack_ns": 100}, {"ack_ns": 200}, {"ack_ns": True},
                        {"sequence_after": 4}, {"epoch_digest": OTHER}, {"challenge_digest": OTHER},
                        {"request_digest": OTHER}, {"extra": 0}, {"schema": "other"}):
            with self.subTest(changes=changes), Harness() as h:
                h.response_changes = changes
                self.refusal(h)
        for raw in (b"", b" " * 4097, b"[]", b"\xff", b'{"schema":0,"schema":1}'):
            with self.subTest(raw=raw[:30]), Harness() as h:
                h.raw_response = raw
                self.refusal(h)
        with Harness() as h:
            h.flags = socket.MSG_TRUNC
            self.refusal(h)

    def test_late_receive_final_readback_and_rollback_refuse(self):
        with Harness() as h:
            original_receive = h.receive
            def late_receive(*args):
                result = original_receive(*args)
                h.now = 200
                return result
            h.connection.recvmsg.side_effect = late_receive
            self.refusal(h)
        with Harness() as h:
            def delay(path, raw):
                if h.connection.recvmsg.called:
                    h.now = 200
                return raw
            h.read_mutation = delay
            self.refusal(h)
        with Harness() as h:
            leaf.clock._stamp.side_effect = [111, 110]
            self.refusal(h)

    def test_primary_error_survives_cleanup_and_retention_failures(self):
        with Harness() as h:
            primary = RuntimeError("send refused")
            h.send_actions = [primary]
            leaf.os.close.side_effect = OSError("close failed")
            h.retain.side_effect = OSError("retention failed")
            error = self.refusal(h)
            self.assertIs(error.original_failure, primary)
            self.assertEqual(len(error.cleanup_failures), 3)
            self.assertIsInstance(error.retention_failure, OSError)
            h.retain.assert_called_once()
        with Harness() as h:
            leaf.os.close.side_effect = OSError("close failed")
            self.refusal(h)
            self.assertEqual(json.loads(h.retained[0])["status"], "REFUSED")

    def test_retention_ack_must_be_exact_and_is_never_retried(self):
        for result in ({"digest": OTHER, "bytes": 0}, {"digest": OTHER}, None, KeyboardInterrupt()):
            with self.subTest(result=result), Harness() as h:
                h.retain.side_effect = result if isinstance(result, BaseException) else lambda *args, **kwargs: result
                self.assertIsNotNone(self.refusal(h).retention_failure)
                h.retain.assert_called_once()
                h.claim.assert_called_once()

    def test_input_mutation_and_evidence_capacity_refuse_without_claim(self):
        for args in ({"challenge_raw": b"{}"}, {"connection_epoch": "bad"},
                     {"epoch_raw": b" " * 32769}, {"challenge_raw": b"[" * 1500 + b"]" * 1500}):
            with self.subTest(args=args), Harness() as h:
                self.refusal(h, **args)
                h.claim.assert_not_called()
        with Harness() as h:
            h.read_mutation = lambda path, raw: raw + b"\n" * 16000 if path.endswith("/status") else raw
            error = self.refusal(h)
            self.assertIn("overflow", json.loads(error.partial_evidence))

    def test_changed_post_claim_socket_and_timeout_pending_packet_refuse(self):
        with Harness() as h:
            def claim(raw):
                h.socket_timeout = 0.5
                return raw
            h.claim.side_effect = claim
            self.refusal(h)
            h.connection.send.assert_not_called()
        with Harness() as h:
            h.timeout = True
            original_poller = h.poller
            def poller():
                item = original_poller()
                poll = item.poll
                def call(timeout):
                    result = poll(timeout)
                    if timeout != 0:
                        h.prequeued = True
                    return result
                item.poll = call
                return item
            leaf.select.poll.side_effect = poller
            self.refusal(h)
