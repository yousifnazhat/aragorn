"""New source-startup protocol checks on inert sockets and captured processes.

No service, source loader, target interpreter, live capture or provider executes.
The loader's separate tests cover same-byte loading; these checks cover its
authenticated startup join and the affected lifecycle/entry callers only.
"""

import copy
from contextlib import ExitStack
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest import mock

from aragorn import pi_core_service_entry as entry
from aragorn import pi_core_service_lifecycle as subject
from aragorn.oci_worker_protocol import canonical_digest
from tests import test_pi_core_service_entry as entry_fixture
from tests import test_pi_core_service_lifecycle as lifecycle_fixture


def records(role="action"):
    names = ["aragorn", "aragorn.pi_core_service_entry", subject.provision.ROLES[role]["module"]]
    return [{"module": name, "path": subject.provision.IMPORT_ROOT + "/" + name.replace(".", "/") +
             ("/__init__.py" if name == "aragorn" else ".py"), "digest": "sha256:" + str(index + 1) * 64}
            for index, name in enumerate(names)]


def inventory():
    result = {row["path"]: row["digest"] for role in subject.ROLES for row in records(role)}
    result[subject._SOURCE_LOADER] = "sha256:" + "f" * 64
    return result


def challenge(role="action"):
    return {"schema": entry.SOURCE_STARTUP_SCHEMA, "kind": "CHALLENGE", "role": role,
        "nonce": "a" * 64, "runtime_closure_digest": "sha256:" + "b" * 64,
        "binding_digest": "sha256:" + "c" * 64, "source_inventory_digest": canonical_digest(inventory())}


class SourceInventoryTests(unittest.TestCase):
    def test_each_role_accepts_only_real_startup_subset(self):
        for role in subject.ROLES:
            rows = records(role)
            self.assertEqual(subject._consumed_sources(rows, inventory(), role), rows)
            self.assertLess(len(rows), len(inventory()))

    def test_empty_unbounded_or_nonlist_records_refuse(self):
        for value in ([], {}, tuple(records()), records() * 172):
            with self.subTest(value=type(value)), self.assertRaises(subject.PiServiceLifecycleError):
                subject._consumed_sources(value, inventory(), "action")

    def test_unknown_or_missing_record_fields_refuse(self):
        for changed in ({**records()[0], "loaded": True}, {"module": "aragorn"}):
            with self.assertRaises(subject.PiServiceLifecycleError):
                subject._consumed_sources([changed, *records()[1:]], inventory(), "action")

    def test_wrong_type_module_path_or_digest_refuses(self):
        for field in ("module", "path", "digest"):
            rows = records()
            rows[0][field] = None
            with self.assertRaises(subject.PiServiceLifecycleError):
                subject._consumed_sources(rows, inventory(), "action")

    def test_duplicate_module_or_path_refuses(self):
        for changed in (records()[0], {**records()[1], "module": "aragorn.other"}):
            with self.assertRaises(subject.PiServiceLifecycleError):
                subject._consumed_sources([*records(), changed], inventory(), "action")

    def test_unlisted_wrong_pin_or_wrong_module_path_refuses(self):
        for field, value in (("digest", "sha256:" + "0" * 64),
                             ("path", "tmp/aragorn/__init__.py"), ("module", "other"),
                             ("module", "aragorn.fake")):
            rows = records()
            rows[0][field] = value
            with self.assertRaises(subject.PiServiceLifecycleError):
                subject._consumed_sources(rows, inventory(), "action")

    def test_missing_package_entry_or_role_handler_refuses(self):
        for index in range(3):
            rows = records()
            del rows[index]
            with self.assertRaises(subject.PiServiceLifecycleError):
                subject._consumed_sources(rows, inventory(), "action")


class EntrySourceTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(entry.time, "monotonic", return_value=100.0))
        class Loader:
            source_digests = inventory()
            snapshot = mock.Mock(return_value=records())
        self.loader = Loader()
        bootstrap = ModuleType("_aragorn_pi_service_source")
        bootstrap.PiServiceSourceLoader = Loader
        self.stack.enter_context(mock.patch.dict(sys.modules,
            {"_aragorn_pi_service_source": bootstrap}))
        self.sent = []
        self.response = challenge()
        self.ack_changes = {}
        self.receive = self.stack.enter_context(mock.patch.object(entry.channel, "receive_authenticated_packet",
            side_effect=self.reply))
        self.send = self.stack.enter_context(mock.patch.object(entry.channel, "send_authenticated_packet",
            side_effect=lambda connection, message, deadline, **kwargs: self.sent.append(copy.deepcopy(message))))

    def reply(self, *_args, **_kwargs):
        if not self.sent:
            return copy.deepcopy(self.response), ()
        base = {key: value for key, value in self.sent[0].items() if key not in {"kind", "sources"}}
        return {**base, "kind": "ACCEPTED", **self.ack_changes}, ()

    def run_handshake(self):
        return entry._source_handshake(object(), "action", 9000, 110.0, self.loader)

    def test_exact_report_requires_ack_and_rechecks_loader(self):
        self.run_handshake()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["kind"], "CONSUMED")
        self.assertEqual(self.sent[0]["sources_digest"], canonical_digest(records()))
        self.assertEqual(self.loader.snapshot.call_count, 2)
        for call in self.receive.call_args_list:
            self.assertEqual(call.args[1], (9000, 0, 0))
            self.assertEqual(call.kwargs, {"expected_rights": 0, "max_bytes": 65536})

    def test_plain_loader_substitute_refuses_before_receive(self):
        self.loader = SimpleNamespace(source_digests=inventory(), snapshot=lambda: records())
        with self.assertRaises(entry.PiServiceEntryError): self.run_handshake()
        self.receive.assert_not_called()

    def test_missing_bootstrap_identity_refuses_before_receive(self):
        with mock.patch.dict(sys.modules, {"_aragorn_pi_service_source": None}):
            with self.assertRaises(entry.PiServiceEntryError): self.run_handshake()
        self.receive.assert_not_called()

    def test_wrong_role_kind_schema_inventory_or_pin_refuses_before_send(self):
        cases = (("role", "provider"), ("kind", "ACCEPTED"), ("schema", "v0"),
                 ("nonce", "x" * 64), ("runtime_closure_digest", "bad"),
                 ("binding_digest", None), ("source_inventory_digest", "sha256:" + "0" * 64))
        for field, value in cases:
            self.response = {**challenge(), field: value}
            with self.subTest(field=field), self.assertRaises(entry.PiServiceEntryError): self.run_handshake()
        self.send.assert_not_called()

    def test_extra_challenge_fields_refuse(self):
        self.response["retry"] = True
        with self.assertRaises(entry.PiServiceEntryError): self.run_handshake()
        self.send.assert_not_called()

    def test_loader_failure_never_sends_receipt(self):
        self.loader.snapshot.side_effect = ValueError("source changed")
        with self.assertRaises(ValueError): self.run_handshake()
        self.send.assert_not_called()

    def test_missing_or_substituted_ack_refuses(self):
        self.ack_changes = {"nonce": "b" * 64}
        with self.assertRaises(entry.PiServiceEntryError): self.run_handshake()
        self.assertEqual(len(self.sent), 1)

    def test_source_change_during_ack_refuses(self):
        self.loader.snapshot.side_effect = [records(), records("provider")]
        with self.assertRaises(entry.PiServiceEntryError): self.run_handshake()

    def test_receive_failure_is_not_retried(self):
        self.receive.side_effect = TimeoutError("inert missing packet")
        with self.assertRaises(TimeoutError): self.run_handshake()
        self.receive.assert_called_once()
        self.send.assert_not_called()

    def test_send_failure_is_not_retried(self):
        self.send.side_effect = OSError("inert short write")
        with self.assertRaises(OSError): self.run_handshake()
        self.send.assert_called_once()
        self.receive.assert_called_once()


class LifecycleSourceTests(lifecycle_fixture.PiServiceLifecycleTests):
    def setUp(self):
        super().setUp()
        self.runtime.binding["source_digests"] = inventory()
        self.runtime.observation.update({"runtime_closure_digest": "sha256:" + "b" * 64,
            "binding_digest": "sha256:" + "c" * 64, "receipt_digest": "sha256:" + "d" * 64})
        self.stack.enter_context(mock.patch.object(subject.secrets, "token_hex", return_value="a" * 64))
        self.source_guard = self.stack.enter_context(mock.patch.object(subject.transport, "guard_channel", return_value=999))
        self.live = self.stack.enter_context(mock.patch.object(subject.transport, "require_peer_live"))
        self.source_sent, self.receipt_change = [], lambda value: value
        self.source_send = self.stack.enter_context(mock.patch.object(subject.transport, "send_authenticated_packet",
            side_effect=self.source_message))
        self.source_receive = self.stack.enter_context(mock.patch.object(subject.transport, "receive_authenticated_packet",
            side_effect=self.source_reply))

    def source_message(self, connection, message, deadline, **kwargs):
        self.assertEqual(deadline, 120.0)
        self.assertEqual(kwargs, {"max_bytes": 65536})
        self.source_sent.append(copy.deepcopy(message))
        self.events.append(message["kind"] + "-" + message["role"])

    def source_reply(self, connection, peer, deadline, **kwargs):
        self.assertEqual(connection.peer, peer)
        self.assertEqual(deadline, 120.0)
        self.assertEqual(kwargs, {"expected_rights": 0, "max_bytes": 65536})
        latest = self.source_sent[-1]
        rows = records(latest["role"])
        receipt = {**latest, "kind": "CONSUMED", "sources": rows, "sources_digest": canonical_digest(rows)}
        return self.receipt_change(receipt), ()

    def test_receipts_join_exact_captured_process_and_precede_readiness(self):
        with self.hold() as held:
            observed = held.observation["trusted_source_startup"]
            self.assertEqual(set(observed), set(subject.ROLES))
            self.assertLess(self.events.index("ACCEPTED-action"), self.events.index("action-LISTEN"))
            self.assertLess(self.events.index("ACCEPTED-provider"), self.events.index("channels-held"))
            for role, row in observed.items():
                service = held.services[role]
                self.assertEqual(row["status"], "AUTHENTICATED_TRUSTED_SOURCE_STARTUP")
                self.assertEqual(row["process"]["pid"], service.pid)
                self.assertEqual(row["process"]["invocation_id"], service.invocation)
                self.assertEqual(row["receipt_digest"], canonical_digest(row["receipt"]))
            self.assertFalse(held.observation["loaded_code_verified"])
            self.assertFalse(held.observation["phase3_exit_eligible"])
        self.assertEqual(self.source_receive.call_count, 3)
        self.assertEqual(self.close_fd.call_args_list.count(mock.call(999)), 3)

    def test_legacy_image_refuses_before_any_service_start(self):
        del self.runtime.binding["source_digests"]
        with self.assertRaisesRegex(subject.PiServiceLifecycleError, "verified-source"):
            with self.hold(): pass
        self.command.assert_not_called()
        self.assertNotIn("prepare", self.events)

    def test_missing_loader_source_refuses_before_start(self):
        self.runtime.binding["source_digests"].pop(subject._SOURCE_LOADER)
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.command.assert_not_called()

    def test_wrong_receipt_binding_never_acks_or_starts_sensor(self):
        self.receipt_change = lambda value: {**value, "nonce": "b" * 64}
        with self.assertRaises(subject.PiServiceLifecycleError) as raised:
            with self.hold(): pass
        self.assertEqual([item["kind"] for item in self.source_sent], ["CHALLENGE"])
        self.assertNotIn("capture-sensor", self.events)
        observed = raised.exception.pi_service_lifecycle_observation["trusted_source_startup"]["action"]
        self.assertEqual(observed["status"], "INCOMPLETE")
        self.assertEqual(observed["challenge"], self.source_sent[0])
        self.assertEqual(observed["receipt"]["nonce"], "b" * 64)
        self.assertEqual(observed["receipt_digest"], canonical_digest(observed["receipt"]))
        self.assertIn(mock.call(999), self.close_fd.call_args_list)

    def test_changed_source_receipt_cannot_become_handler_authority(self):
        def substitute(value):
            value["sources"][0]["digest"] = "sha256:" + "0" * 64
            value["sources_digest"] = canonical_digest(value["sources"])
            return value
        self.receipt_change = substitute
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.assertEqual(len(self.source_sent), 1)
        self.channels.assert_not_called()

    def test_wrong_record_digest_refuses(self):
        self.receipt_change = lambda value: {**value, "sources_digest": "sha256:" + "0" * 64}
        with self.assertRaises(subject.PiServiceLifecycleError):
            with self.hold(): pass
        self.assertEqual(len(self.source_sent), 1)

    def test_timeout_or_fd_rejection_is_not_retried(self):
        self.source_receive.side_effect = subject.transport.PiIdentityHandoffError("packet refused")
        with self.assertRaises(subject.transport.PiIdentityHandoffError) as raised:
            with self.hold(): pass
        self.source_receive.assert_called_once()
        self.assertEqual(len(self.source_sent), 1)
        self.assertNotIn("capture-sensor", self.events)
        observed = raised.exception.pi_service_lifecycle_observation["trusted_source_startup"]["action"]
        self.assertEqual(observed["status"], "INCOMPLETE")
        self.assertEqual(observed["challenge"], self.source_sent[0])
        self.assertNotIn("receipt", observed)

    def test_challenge_send_failure_retains_challenge_before_attempt(self):
        self.source_send.side_effect = OSError("inert uncertain send")
        with self.assertRaises(OSError) as raised:
            with self.hold(): pass
        observed = raised.exception.pi_service_lifecycle_observation["trusted_source_startup"]["action"]
        self.assertEqual(observed["status"], "INCOMPLETE")
        self.assertEqual(observed["challenge"], challenge())
        self.assertEqual(observed["process"]["pid"], 8001)
        self.assertNotIn("receipt", observed)
        self.source_send.assert_called_once()
        self.source_receive.assert_not_called()

    def test_ack_failure_leaves_incomplete_observation(self):
        def fail_ack(connection, message, deadline, **kwargs):
            self.source_message(connection, message, deadline, **kwargs)
            if message["kind"] == "ACCEPTED": raise OSError("inert uncertain acknowledgement")
        self.source_send.side_effect = fail_ack
        with self.assertRaises(OSError) as raised:
            with self.hold(): pass
        observed = raised.exception.pi_service_lifecycle_observation["trusted_source_startup"]["action"]
        self.assertEqual(observed["status"], "INCOMPLETE")
        self.assertEqual(observed["challenge"], self.source_sent[0])
        self.assertEqual(observed["receipt"]["kind"], "CONSUMED")
        self.assertEqual(observed["receipt_digest"], canonical_digest(observed["receipt"]))
        self.assertEqual(len(self.source_sent), 2)
        self.channels.assert_not_called()

    def test_input_change_before_ack_refuses(self):
        def changed(value):
            self.runtime.guard.side_effect = ValueError("held image changed")
            return value
        self.receipt_change = changed
        with self.assertRaises(ValueError):
            with self.hold(): pass
        self.assertEqual(len(self.source_sent), 1)

    def test_startup_is_one_shot_even_after_incomplete_receive(self):
        held = self.instance()
        self.prepare_service(held)
        item = held.services["action"]
        self.capture_service(item, 120.0)
        item.connection = item.listener.accepted
        self.source_receive.side_effect = TimeoutError("inert timeout")
        with self.assertRaises(TimeoutError): held._source_startup(item)
        with self.assertRaises(subject.PiServiceLifecycleError): held._source_startup(item)
        self.source_receive.assert_called_once()

    def test_passive_listener_allows_bounded_held_source_descriptors(self):
        held = self.instance()
        item = held.services["action"]
        self.capture_service(item, 120.0)
        directory = lifecycle_fixture.metadata(500, lifecycle_fixture.stat.S_IFDIR | 0o750, 1201, 1301)
        endpoint = lifecycle_fixture.metadata(888, lifecycle_fixture.stat.S_IFSOCK | 0o660, 1201, 1301)
        raw = b"Num RefCount Protocol Flags Type St Inode Path\n0: 2 0 00010000 0001 01 987 /proc/self/fd/12/sensor.sock\n"
        names = [str(value) for value in range(1, 100)]
        with mock.patch.object(subject.process, "_read_virtual_file", return_value=raw), \
             mock.patch.object(subject.os, "listdir", return_value=names), \
             mock.patch.object(subject.os, "readlink", side_effect=lambda path: "socket:[987]" if path.endswith("/13") else "/pinned/source.py"), \
             mock.patch.object(subject.os, "stat", side_effect=lambda path, **kwargs: directory if str(path).startswith("/proc/") else endpoint):
            self.assertEqual(self.real_listener(item, 501, subject.broker._directory_identity(directory), 120.0),
                             subject.broker._file_identity(endpoint))

    def test_passive_listener_still_rejects_excess_source_descriptors(self):
        held = self.instance()
        item = held.services["action"]
        self.capture_service(item, 120.0)
        with mock.patch.object(subject.process, "_read_virtual_file", return_value=b"header\n"), \
             mock.patch.object(subject.os, "stat", side_effect=FileNotFoundError), \
             mock.patch.object(subject.os, "listdir", return_value=[str(value) for value in range(subject._MAX_SERVICE_FDS + 1)]):
            with self.assertRaisesRegex(subject.PiServiceLifecycleError, "inventory exceeds"):
                self.real_listener(item, 501, (), 120.0)


class EntryCallerTests(entry_fixture.PiServiceEntryTests):
    def test_source_handshake_precedes_role_handler_and_listener(self):
        loader = object()
        def exchanged(*args):
            self.assertIs(args[-1], loader)
            self.action.assert_not_called()
            self.assertFalse(any(event[0] == "bind" for event in self.events))
        with mock.patch.object(entry, "_source_handshake", side_effect=exchanged) as exchange:
            entry.run("action", ["9000", "105000000000"], source_loader=loader)
        exchange.assert_called_once()
        self.action.assert_called_once()

    def test_handshake_refusal_never_reaches_handler_or_listener(self):
        with mock.patch.object(entry, "_source_handshake", side_effect=entry.PiServiceEntryError("refused")), \
             self.assertRaises(entry.PiServiceEntryError):
            entry.run("action", ["9000", "105000000000"], source_loader=object())
        self.action.assert_not_called()
        self.assertFalse(any(event[0] == "bind" for event in self.events))
        self.assertTrue(all(item.closed for item in self.sockets))

    def test_main_forwards_exact_loader(self):
        loader = object()
        with mock.patch.object(entry, "run") as run:
            self.assertEqual(entry.main("action", ["9000", "105000000000"], source_loader=loader), 0)
        run.assert_called_once_with("action", ["9000", "105000000000"], source_loader=loader)


def load_tests(_loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (SourceInventoryTests, EntrySourceTests, LifecycleSourceTests, EntryCallerTests):
        for name in sorted(cls.__dict__):
            if name.startswith("test_"): suite.addTest(cls(name))
    # Only affected existing caller/lifetime checks, not the historical suites.
    for name in ("test_fixed_start_order_passive_readiness_and_owned_channel_withdrawal",
                 "test_wrong_postexec_peer_refuses_before_sensor_start",
                 "test_listener_readiness_failure_never_starts_sensor",
                 "test_service_exit_during_body_cannot_become_success_after_clean_stop",
                 "test_channel_withdrawal_failure_never_becomes_verified_cleanup"):
        suite.addTest(LifecycleSourceTests(name))
    for name in ("test_action_dispatches_one_existing_handler_and_cleans_owned_listener",
                 "test_sensor_dispatches_real_adoption_wrapper_with_direct_stream",
                 "test_provider_dispatches_exact_handler_without_reading_credentials"):
        suite.addTest(EntryCallerTests(name))
    return suite
