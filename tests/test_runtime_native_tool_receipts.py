from __future__ import annotations

import copy
import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aragorn import runtime_native_tool_receipts as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json

_D = "sha256:" + "1" * 64


class Fixture:
    """Test-only operator provisioning; the production core has no initializer."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(mode=0o700)
        self.genesis = {
            "schema": "aragorn/native-tool-receipt-genesis/v1",
            "authority": "ROOT_PROVISIONED_WORKER_RECEIPT_STREAM_NOT_RUN_AUTHORITY",
            "stream_id": _D,
            "worker_uid": os.geteuid(),
            "worker_gid": os.getegid(),
            "runtime_digest": _D,
            "policy_digest": _D,
            "policy_version": 1,
        }
        self.expected = canonical_digest(self.genesis)
        self.state = {
            "schema": "aragorn/native-tool-receipt-state/v1",
            "authority": subject._RETAINED_AUTHORITY,
            "genesis_digest": self.expected,
            "receipts": [],
        }
        self.write("genesis.json", canonical_json(self.genesis), 0o400)
        self.write("state.json", canonical_json(self.state), 0o400)
        self.write("receipt.lock", b"", 0o600)
        CAS(root / "cas")

    def write(self, name: str, raw: bytes, mode: int = 0o400):
        target = self.root / name
        if target.exists():
            target.chmod(0o600)
        target.write_bytes(raw)
        target.chmod(mode)

    def open(self):
        return subject.NativeToolReceiptStore(self.root, self.expected)

    def attempt(self, number=1, tool="read"):
        return {
            "schema": "aragorn/native-tool-attempt/v1",
            "authority": subject._AUTHORITY,
            "tool_name": tool,
            "session_id": "session-one",
            "run_id": "run-one",
            "session_key_digest": _D,
            "tool_call_digest": canonical_digest(number),
            "params_digest": _D,
            "params_bytes": 17,
            "worker_request_digest": _D if tool == "aragorn_runtime_create" else None,
        }

    def terminal(self, attempt, ack, outcome="RETURNED"):
        return {
            "schema": "aragorn/native-tool-terminal/v1",
            "authority": subject._AUTHORITY,
            "tool_name": attempt["tool_name"],
            **{name: attempt[name] for name in subject._CORRELATION},
            "attempt_digest": ack["receipt_digest"],
            "outcome": outcome,
            "result_digest": _D if outcome == "RETURNED" else None,
            "result_bytes": 23 if outcome == "RETURNED" else None,
            "error_code": None
            if outcome == "RETURNED"
            else "ABORTED"
            if outcome == "CANCELLED"
            else "NATIVE_ERROR",
        }


class NativeToolReceiptTests(unittest.TestCase):
    def test_inventory_iteration_is_bounded_and_always_closed(self):
        class Entries:
            def __init__(self, names):
                self.names = names
                self.consumed = 0
                self.closed = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.closed = True

            def __iter__(self):
                for name in self.names:
                    self.consumed += 1
                    yield SimpleNamespace(name=name)

        for names, expected, consumed, valid in (
            (("a", "b"), {"a", "b"}, 2, True),
            (("a", "other"), {"a", "b"}, 2, False),
            (("a", "b", "extra", "never-read"), {"a", "b"}, 3, False),
            (("extra", "never-read"), set(), 1, False),
        ):
            entries = Entries(names)
            with (
                self.subTest(names=names),
                mock.patch.object(subject.os, "scandir", return_value=entries) as scan,
            ):
                if valid:
                    subject._inventory(42, expected)
                else:
                    with self.assertRaises(subject.NativeToolReceiptFatal):
                        subject._inventory(42, expected)
                scan.assert_called_once_with(42)
                self.assertEqual(entries.consumed, consumed)
                self.assertTrue(entries.closed)

    def test_read_create_roundtrip_replay_and_restart_have_no_effect_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary).resolve() / "receipts")
            store = fixture.open()
            for number, tool in enumerate(("read", "aragorn_runtime_create"), 1):
                attempt = fixture.attempt(number, tool)
                ack = store.retain_attempt(attempt)
                self.assertEqual(ack["status"], "ATTEMPT_RECORDED_EXECUTE_ONCE")
                self.assertEqual(ack["sequence"], number * 2 - 1)
                self.assertEqual(ack["event_digest"], canonical_digest(attempt))
                self.assertIs(ack["effect_authorized"], False)
                self.assertIs(ack["run_qualified"], False)
                self.assertEqual(
                    store.retain_attempt(attempt)["status"],
                    "ALREADY_RECORDED_DO_NOT_EXECUTE",
                )
                with self.assertRaises(subject.NativeToolReceiptRejected):
                    store.retain_attempt(fixture.attempt(number + 100))
                with self.assertRaises(subject.NativeToolReceiptFatal):
                    fixture.open()  # An unmatched attempt is not startup-safe.
                terminal = fixture.terminal(attempt, ack)
                completed = store.retain_terminal(terminal)
                self.assertEqual(completed["sequence"], number * 2)
                self.assertEqual(completed["status"], "TERMINAL_RECORDED")
                self.assertEqual(
                    store.retain_terminal(terminal)["status"],
                    "TERMINAL_ALREADY_RECORDED",
                )
                store = fixture.open()
                self.assertEqual(
                    store.retain_attempt(attempt)["status"],
                    "ALREADY_RECORDED_DO_NOT_EXECUTE",
                )
            raw = (fixture.root / "state.json").read_bytes()
            state = subject.broker._parse_canonical_document(raw, "test")
            self.assertEqual(len(state["receipts"]), 4)
            previous = fixture.expected
            for sequence, digest in enumerate(state["receipts"], 1):
                record = subject.broker._parse_canonical_document(
                    CAS(fixture.root / "cas", read_only=True).read(digest), "test"
                )
                self.assertEqual(
                    (record["sequence"], record["previous_digest"]),
                    (sequence, previous),
                )
                previous = digest

    def test_strict_requests_and_terminal_correlations_never_retain_raw_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary).resolve() / "receipts")
            store = fixture.open()
            mutations = (
                ("tool_name", "write"),
                ("tool_name", []),
                ("params_bytes", True),
                ("params_bytes", -1),
                ("params_digest", "sha256:" + "A" * 64),
                ("run_id", ""),
                ("session_key_digest", None),
                ("worker_request_digest", _D),
                ("raw_params", "secret raw content"),
                ("authority", "ALLOW"),
            )
            original = (fixture.root / "state.json").read_bytes()
            for key, value in mutations:
                candidate = fixture.attempt()
                candidate[key] = value
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(subject.NativeToolReceiptRejected),
                ):
                    store.retain_attempt(candidate)
            self.assertEqual((fixture.root / "state.json").read_bytes(), original)
            for number, outcome in enumerate(("RETURNED", "RAISED", "CANCELLED"), 1):
                attempt = fixture.attempt(number)
                ack = store.retain_attempt(attempt)
                for key, value in (
                    ("run_id", "other"),
                    ("session_id", "other"),
                    ("session_key_digest", "sha256:" + "2" * 64),
                    ("tool_call_digest", _D),
                    ("attempt_digest", _D),
                    ("tool_name", "aragorn_runtime_create"),
                    ("result_bytes", True),
                    ("error_code", "secret raw exception"),
                ):
                    terminal = fixture.terminal(attempt, ack, outcome)
                    terminal[key] = value
                    with (
                        self.subTest(outcome=outcome, key=key),
                        self.assertRaises(subject.NativeToolReceiptRejected),
                    ):
                        store.retain_terminal(terminal)
                store.retain_terminal(fixture.terminal(attempt, ack, outcome))
            for path in (fixture.root / "cas").rglob("*"):
                if path.is_file():
                    self.assertNotIn(b"secret raw", path.read_bytes())

    def test_no_self_initialization_and_exact_actual_uid_gid_custody(self):
        for mutation in (
            "absent",
            "genesis",
            "expected",
            "uid",
            "gid",
            "root-mode",
            "state-mode",
            "fifo-lock",
            "symlink-state",
            "hardlink-state",
            "missing-cas",
            "extra",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary).resolve()
                fixture = Fixture(root / "receipts")
                if mutation == "absent":
                    with self.assertRaises(subject.NativeToolReceiptFatal):
                        subject.NativeToolReceiptStore(
                            root / "absent", fixture.expected
                        )
                    self.assertFalse((root / "absent").exists())
                    continue
                if mutation == "genesis":
                    fixture.write("genesis.json", b"{}")
                elif mutation == "expected":
                    fixture.expected = _D
                elif mutation in {"uid", "gid"}:
                    fixture.genesis["worker_" + mutation] += 1
                    fixture.expected = canonical_digest(fixture.genesis)
                    fixture.write("genesis.json", canonical_json(fixture.genesis))
                    fixture.state["genesis_digest"] = fixture.expected
                    fixture.write("state.json", canonical_json(fixture.state))
                elif mutation == "root-mode":
                    fixture.root.chmod(0o750)
                elif mutation == "state-mode":
                    (fixture.root / "state.json").chmod(0o600)
                elif mutation == "fifo-lock":
                    (fixture.root / "receipt.lock").unlink()
                    os.mkfifo(fixture.root / "receipt.lock", 0o600)
                elif mutation == "symlink-state":
                    (fixture.root / "state.json").unlink()
                    (fixture.root / "state.json").symlink_to(
                        fixture.root / "genesis.json"
                    )
                elif mutation == "hardlink-state":
                    os.link(fixture.root / "state.json", root / "external")
                elif mutation == "missing-cas":
                    (fixture.root / "cas/blobs/sha256").rmdir()
                else:
                    fixture.write("extra", b"extra")
                with self.assertRaises(subject.NativeToolReceiptFatal):
                    fixture.open()

    def test_retention_failures_are_fatal_and_never_return_an_execute_ack(self):
        for phase in (
            "cas-before",
            "cas-after",
            "state-before",
            "state-after",
            "final-sync",
            "cleanup",
            "interrupt",
        ):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary).resolve() / "receipts")
                store = fixture.open()
                put = subject.CAS.put_expected
                publish = subject.broker._atomic_publish_at
                audit = store._audit_cas
                release = subject.broker._release_lock_and_close

                def failed_put(cas, *args, phase=phase, put=put, **kwargs):
                    if phase == "cas-after":
                        put(cas, *args, **kwargs)
                    raise OSError("CAS publication failure")

                def failed_publish(*args, phase=phase, publish=publish, **kwargs):
                    if phase == "state-after":
                        publish(*args, **kwargs)
                    if phase == "interrupt":
                        raise KeyboardInterrupt()
                    raise OSError("state publication failure")

                def failed_sync(*args, audit=audit, **kwargs):
                    audit(*args, **kwargs)
                    if kwargs.get("sync"):
                        raise OSError("final synchronization failure")

                def failed_cleanup(*args, release=release):
                    release(*args)
                    return OSError("close failure")

                if phase.startswith("cas"):
                    patch = mock.patch.object(subject.CAS, "put_expected", failed_put)
                elif phase == "final-sync":
                    patch = mock.patch.object(store, "_audit_cas", failed_sync)
                elif phase == "cleanup":
                    patch = mock.patch.object(
                        subject.broker, "_release_lock_and_close", failed_cleanup
                    )
                else:
                    patch = mock.patch.object(
                        subject.broker, "_atomic_publish_at", failed_publish
                    )
                with patch, self.assertRaises(subject.NativeToolReceiptFatal):
                    store.retain_attempt(fixture.attempt())
                with self.assertRaises(subject.NativeToolReceiptFatal):
                    store.retain_attempt(fixture.attempt())
                if phase != "cas-before":
                    with self.assertRaises(subject.NativeToolReceiptFatal):
                        fixture.open()  # Orphaned CAS or unresolved attempt stays fail-stop.

    def test_state_rollback_corruption_and_rebound_lock_halt_the_live_store(self):
        for mutation in (
            "rollback",
            "sequence",
            "boolean-sequence",
            "previous",
            "orphan",
            "lock-rebound",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                fixture = Fixture(Path(temporary).resolve() / "receipts")
                store = fixture.open()
                attempt = fixture.attempt()
                ack = store.retain_attempt(attempt)
                store.retain_terminal(fixture.terminal(attempt, ack))
                if mutation == "rollback":
                    fixture.write("state.json", canonical_json(fixture.state))
                elif mutation == "lock-rebound":
                    (fixture.root / "receipt.lock").unlink()
                    fixture.write("receipt.lock", b"", 0o600)
                else:
                    cas = CAS(fixture.root / "cas")
                    if mutation == "orphan":
                        cas.put(BytesIO(b"orphan"), max_bytes=6)
                    else:
                        state = subject.broker._parse_canonical_document(
                            (fixture.root / "state.json").read_bytes(), "test"
                        )
                        first, second = [
                            subject.broker._parse_canonical_document(
                                cas.read(digest), "test"
                            )
                            for digest in state["receipts"]
                        ]
                        first[
                            "previous_digest" if mutation == "previous" else "sequence"
                        ] = (
                            _D
                            if mutation == "previous"
                            else True
                            if mutation == "boolean-sequence"
                            else 7
                        )
                        first_digest = canonical_digest(first)
                        second["previous_digest"] = first_digest
                        second["event"]["attempt_digest"] = first_digest
                        # Rebind every digest and remove obsolete blobs: rejection
                        # must come from sequence/chain semantics, not inventory.
                        for digest in state["receipts"]:
                            path = (
                                fixture.root
                                / "cas/blobs/sha256"
                                / digest[7:9]
                                / digest[9:]
                            )
                            path.unlink()
                            if not any(path.parent.iterdir()):
                                path.parent.rmdir()
                        state["receipts"] = [
                            cas.put(BytesIO(canonical_json(item)), max_bytes=4096)
                            for item in (first, second)
                        ]
                        fixture.write("state.json", canonical_json(state))
                        with self.assertRaises(subject.NativeToolReceiptFatal):
                            fixture.open()
                with self.assertRaises(subject.NativeToolReceiptFatal):
                    store.retain_attempt(fixture.attempt(2))
                with self.assertRaises(subject.NativeToolReceiptFatal):
                    store.retain_attempt(fixture.attempt(2))

    def test_fixed_capacity_conflicting_replays_and_terminal_delivery_uncertainty(self):
        self.assertEqual(subject._MAX_CALLS, 512)
        self.assertLess(
            len(canonical_json({"receipts": [_D] * 1024})) + 512,
            subject._MAX_STATE_BYTES,
        )
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary).resolve() / "receipts")
            store = fixture.open()
            attempt = fixture.attempt()
            with mock.patch.object(subject, "_MAX_CALLS", 1):
                ack = store.retain_attempt(attempt)
                conflict = copy.deepcopy(attempt)
                conflict["params_bytes"] += 1
                with self.assertRaises(subject.NativeToolReceiptRejected):
                    store.retain_attempt(conflict)
                terminal = fixture.terminal(attempt, ack)
                store.retain_terminal(terminal)
                conflict = copy.deepcopy(terminal)
                conflict["result_bytes"] += 1
                with self.assertRaises(subject.NativeToolReceiptRejected):
                    store.retain_terminal(conflict)
                with self.assertRaises(subject.NativeToolReceiptRejected):
                    store.retain_attempt(fixture.attempt(2))
                self.assertEqual(
                    store.retain_attempt(attempt)["status"],
                    "ALREADY_RECORDED_DO_NOT_EXECUTE",
                )
            store = fixture.open()
            attempt = fixture.attempt(2)
            ack = store.retain_attempt(attempt)
            terminal = fixture.terminal(attempt, ack)
            publish = subject.broker._atomic_publish_at

            def committed_then_failed(*args, **kwargs):
                publish(*args, **kwargs)
                raise OSError("return path lost after commit")

            with (
                mock.patch.object(
                    subject.broker, "_atomic_publish_at", committed_then_failed
                ),
                self.assertRaises(subject.NativeToolReceiptFatal),
            ):
                store.retain_terminal(terminal)
            recovered = fixture.open()
            self.assertEqual(
                recovered.retain_terminal(terminal)["status"],
                "TERMINAL_ALREADY_RECORDED",
            )
            self.assertEqual(
                recovered.retain_attempt(attempt)["status"],
                "ALREADY_RECORDED_DO_NOT_EXECUTE",
            )


if __name__ == "__main__":
    unittest.main()
