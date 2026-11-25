"""Inert, caller-owned transport. No sockets, Linux services or actual measurements."""
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from time import monotonic
from unittest import TestCase, mock

from aragorn import phase3_reference_tasks as fixed, pi_core_task_reference as reference, pi_core_task_service as service
from aragorn import pi_core_task_copy_observation as observation, native_phase3_workload_copy_readback as legacy_copy
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


class TaskServiceTests(TestCase):
    def ticket(self, task, mode):
        desc = fixed.describe_tasks(Path(reference.__file__).read_bytes())[task]
        req = dict(kind="task", pair_id="pair-1", mode=mode, task_digest=canonical_digest(desc),
                   input_digest=desc["input"]["digest"], host_profile_digest=canonical_digest("host"),
                   collection_digest=canonical_digest("schedule"), deployment_digest=canonical_digest("deployment"))
        return dict(schema="aragorn/pi-core-task-ticket/v1", request=req, environment_digest=canonical_digest(mode),
                    clock=dict(clock_id="CLOCK_BOOTTIME", boot_id="12345678-1234-1234-1234-123456789abc", time_namespace_inode=99),
                    pi_peer=[101, 1200, 1200], service_peer=[102, 1300, 1300], manager_peer=[103, 0, 0])

    def roundtrip(self, task="BENIGN_JSON_SUM", mode="baseline", change=None, copy_observation=None, prepare=None,
                  collector_mark=None, pi_route=None, early_response=None):
        ticket = self.ticket(task, mode)
        req = ticket["request"]
        directory_fd = None
        if prepare:
            copy_observation, directory_fd = prepare(ticket)
        handed, kept, events = {}, [], []
        self.last_events = events
        @contextmanager
        def edge(connection, *_args):
            yield lambda: None
        def write(connection, message, deadline):
            events.append("send:" + connection)
            handed[connection] = deepcopy(message)
        def call_service(incoming, deadline):
            self.assertNotIn("pi-forwarded", handed)
            handed["pi-forwarded"] = deepcopy(incoming)
            service.serve_one(ticket, canonical_digest(ticket), pi="from-pi", witness="to-manager",
                              guard=lambda: ticket["environment_digest"], deadline=deadline,
                              copy_directory_fd=directory_fd)
            return handed["from-pi"]
        def read(connection, deadline):
            if connection == "from-pi":
                return handed["pi-forwarded"] | ({"ticket_digest": canonical_digest("other")} if change == "request" else {})
            if connection == "pi":
                if early_response is not None:
                    events.append("untrusted-early-answer")
                    return deepcopy(early_response)
                if pi_route:
                    return pi_route(handed["pi"], lambda incoming: call_service(incoming, deadline))
                response = call_service(handed["pi"], deadline)
                if change == "nonce-mismatch":
                    return response | {"service_nonce":"a"*64}
                return response | {"service_nonce":"invalid"} if change == "nonce-invalid" else response
            if connection == "witness":
                if early_response is not None:
                    call_service(handed["pi"], deadline)
                events.append("read:service-witness")
                if change == "nonce-invalid":
                    return handed["to-manager"] | {"service_nonce":"invalid"}
                return handed["to-manager"] | ({"request_digest": canonical_digest("other")} if change == "witness" else {})
            raise AssertionError(connection)
        def mark(name):
            events.append(name)
            return collector_mark(name) if collector_mark is not None else {"TASK_ACCEPTED": 123, "TASK_COMPLETED": 456}[name]
        def retain(raw):
            kept.append(json.loads(raw))
            return canonical_digest(kept[-1]) if change != "retain" else canonical_digest("unretained")
        with mock.patch.object(service, "_edge", edge), mock.patch.object(service, "_write", write), \
                mock.patch.object(service, "_read", read):
            raw = service.measure_via_pi(req, mark, ticket=ticket, ticket_pin=canonical_digest(ticket),
                pi="pi", witness="witness", deadline=monotonic()+10, guard=lambda: (canonical_digest("other") if change == "mode"
                                                                      else ticket["environment_digest"]),
                retain=retain, copy_observation=copy_observation)
        self.assertEqual(kept[0]["service_response"], kept[0]["pi_response"])
        self.assertEqual(kept[0]["receipt_digest"], canonical_digest(json.loads(raw)))
        self.assertEqual(kept[0]["request_digest"], canonical_digest(req))
        self.assertEqual(kept[0]["ticket_digest"], canonical_digest(ticket))
        self.last_sidecar, self.last_ticket = kept[0], ticket
        return json.loads(raw), events

    def copy_roundtrip(self, mode="baseline", collector_mark=None, pi_route=None):
        with ExitStack() as stack:
            root = stack.enter_context(TemporaryDirectory())
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, directory_fd)
            # Translate only uid/gid in this fabricated guest view. The directory/file
            # identities, permissions, actual bytes, FD operations and readback are real.
            uid, gid = 1300, 1300
            class Meta:
                st_uid, st_gid = uid, gid
                def __init__(self, st): self.st = st
                def __getattr__(self, name): return getattr(self.st, name)
            class GuestOS:
                def __getattr__(self, name): return getattr(os, name)
                def getuid(self): return uid
                def geteuid(self): return uid
                def getegid(self): return gid
                def fstat(self, fd): return Meta(os.fstat(fd))
                def stat(self, *a, **kw): return Meta(os.stat(*a, **kw))
            for module in (fixed, reference, legacy_copy):
                stack.enter_context(mock.patch.object(module, "os", GuestOS()))
            identity = observation._identity
            stack.enter_context(mock.patch.object(observation, "_identity", side_effect=lambda st: identity(Meta(st))))
            stack.enter_context(mock.patch.object(observation, "_hold_process", return_value=nullcontext(7)))
            stack.enter_context(mock.patch.object(observation, "_guest_edge"))
            stack.enter_context(mock.patch.object(observation, "_same_mount"))
            def prepare(ticket):
                req_pin = canonical_digest(ticket["request"])
                d = fixed._identity(Meta(os.fstat(directory_fd)))
                guest = dict(unit="aragorn-pi-task.service", invocation_id="1"*32, pid=102, start_ticks=21,
                             uid=uid, gid=gid, boot_id=ticket["clock"]["boot_id"], observer_mount_ns=12,
                             service_mount_ns=13, time_ns=99, observer_mount_id=50, service_mount_id=52)
                fixture = dict(schema="aragorn/pi-core-task-copy-fixture/v1", request_digest=req_pin, guest=guest, directory_identity=d)
                ticket["copy"] = dict(directory_identity=d, fixture_digest=canonical_digest(fixture))
                return observation.ManagedCopyObserver(directory_fd=directory_fd, service_directory_fd=9,
                    request_digest=req_pin, guest=guest, directory_identity=d), directory_fd
            receipt, events = self.roundtrip("BENIGN_COPY_READBACK", mode, prepare=prepare,
                                            collector_mark=collector_mark, pi_route=pi_route)
            on_disk = (Path(root)/"allowed-copy.txt").read_bytes()
            self.assertEqual(on_disk, fixed.reference_inputs()["allowed_copy_text"])
            self.assertEqual(bytes.fromhex(self.last_sidecar["copy_observation"]["content_hex"]), on_disk)
            return receipt, events

    def test_copy_service_bytes_are_independently_read_in_both_modes(self):
        for mode in ("baseline", "instrumented"):
            with self.subTest(mode=mode):
                receipt, _events = self.copy_roundtrip(mode)
                self.assertEqual(receipt["observation"]["retained_file"]["identity"], self.last_sidecar["copy_observation"]["file_identity"])

    def test_three_reviewed_computations_use_same_roundtrip_in_both_modes(self):
        for mode in ("baseline", "instrumented"):
            for task in ("BENIGN_JSON_SUM", "BENIGN_LINE_COUNT", "BENIGN_SHA256"):
                with self.subTest(task=task, mode=mode):
                    result, events = self.roundtrip(task, mode)
                    self.assertEqual(result["observation"]["result"]["template_id"], task)
                    self.assertEqual(result["boundaries"], {"TASK_ACCEPTED":123, "TASK_COMPLETED":456})
                    self.assertLess(events.index("TASK_ACCEPTED"), events.index("send:pi"))
                    self.assertLess(events.index("send:from-pi"), events.index("TASK_COMPLETED"))
                    self.assertNotIn("TASK_ACCEPTED", events[events.index("TASK_ACCEPTED")+1:])

    def test_substituted_request_witness_or_environment_refuses(self):
        for which in ("request", "witness", "mode", "retain"):
            with self.subTest(which=which), self.assertRaises(ValueError):
                self.roundtrip(change=which)

    def test_both_complete_returns_precede_end_mark_even_with_an_early_pi_frame(self):
        self.roundtrip()
        reply = self.last_sidecar["pi_response"]
        self.assertLess(self.last_events.index("read:service-witness"), self.last_events.index("TASK_COMPLETED"))
        # Deliberately predict the nonce in this timing-only fixture: even identical
        # Pi bytes cannot end the interval until the service has actually finished.
        with mock.patch.object(secrets, "token_hex", return_value=reply["service_nonce"]):
            self.roundtrip(early_response=reply)
        events = self.last_events
        self.assertLess(events.index("untrusted-early-answer"), events.index("send:from-pi"))
        self.assertLess(events.index("read:service-witness"), events.index("TASK_COMPLETED"))

    def test_nonce_issued_from_entropy_after_task_once_per_execution(self):
        order = []
        original = reference.execute_reference_task
        def work(*args, **kwargs):
            out = original(*args, **kwargs)
            order.append("done")
            return out
        def entropy(n):
            self.assertEqual(n, 32)
            order.append("nonce")
            return ("b" if order.count("nonce") == 1 else "c")*64
        with mock.patch.object(reference, "execute_reference_task", side_effect=work), \
                mock.patch.object(secrets, "token_hex", side_effect=entropy):
            for expected in ("b"*64,"c"*64):
                raw, _ = self.roundtrip()
                self.assertNotIn("service_nonce", raw)
                self.assertEqual(self.last_sidecar["service_response"]["service_nonce"], expected)
                self.assertEqual(self.last_sidecar["pi_response"]["service_nonce"], expected)
        self.assertEqual(order, ["done","nonce","done","nonce"])

    def test_stale_mismatched_or_invalid_nonce_never_retains_a_result(self):
        self.roundtrip()
        stale = self.last_sidecar["pi_response"]
        for options in (dict(early_response=stale), dict(change="nonce-mismatch"), dict(change="nonce-invalid")):
            with self.subTest(options=tuple(options)), self.assertRaises(ValueError):
                self.roundtrip(**options)

    def test_copy_without_independent_guest_observer_refuses_before_service(self):
        with self.assertRaisesRegex(ValueError, "COPY_OBSERVER"):
            self.roundtrip("BENIGN_COPY_READBACK")
