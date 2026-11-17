"""Focused protected-store checks using temporary files, never provider work.

Root metadata is mapped to the fixture's current user. No test result establishes
actual root custody, provider execution, raw-network capture or qualification.
"""

import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from aragorn import pi_core_provider_evidence as subject
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_digest, canonical_json


def pin(character="a"):
    return "sha256:" + character * 64


def activation():
    value = {"schema": subject.identity.ACTIVATION_SCHEMA, "authority": subject.identity.ACTIVATION_AUTHORITY,
        "activation_id": "a" * 32, "session_id": "a" * 32, "run_id": "a" * 32,
        "pid": 123, "uid": 1001, "gid": 1001, "start_time_ticks": 12,
        "mount_namespace": {"device": 1, "inode": 2}, "cgroup": "/aragorn/pi-worker",
        "boot_id": "00000000-0000-0000-0000-000000000000", "expires_at_monotonic_ns": 130_000_000_000}
    value.update({name: pin() for name in subject.identity._PINS})
    return value


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home().resolve(), prefix="aragorn-provider-evidence-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "control"
        self.control.mkdir(mode=0o700)
        self.store = self.control / "provider-evidence"
        CAS(self.store)
        self.sha = self.store / "blobs/sha256"
        self.control_fd = os.open(self.control, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.addCleanup(os.close, self.control_fd)
        self.config = subject.broker.RuntimeActionBrokerConfig(
            **{name: self.control / name for name in ("socket_path", "instance_lock_path", "lock_path",
                "policy_path", "revocations_path", "health_path", "observation_path", "state_path")},
            control_root=self.control, protected_root=self.root / "effects", staging_root=self.root / "staging",
            expected_broker_uid=0, expected_peer_uid=1002, expected_peer_gid=1002,
            expected_runtime_digest=pin(), expected_runtime_uid=1001, expected_runtime_gid=1001)
        self.activation = activation()
        self.index = self.store / ("attempt-" + self.activation["activation_id"] + ".jsonl")
        for name in ("socket.socket", "socket.socketpair", "socket.create_connection", "subprocess.Popen",
                     "subprocess.run", "os.execve", "os.system"):
            self.enterContext(mock.patch(name, side_effect=AssertionError("no service or network operation")))
        self.enterContext(mock.patch.object(subject.os, "geteuid", return_value=0))
        self.enterContext(mock.patch.object(subject.os, "getegid", return_value=0))
        self.enterContext(mock.patch.object(subject.time, "monotonic", return_value=100.0))
        self.clock = self.enterContext(mock.patch.object(subject.time, "monotonic_ns", return_value=100_000_000_000))
        self.validate_config = self.enterContext(mock.patch.object(subject.broker, "_validate_config"))
        self.original_stat, self.original_fstat, self.original_lstat = os.stat, os.fstat, os.lstat
        def mapped(function):
            def read(*args, **kwargs):
                result = function(*args, **kwargs)
                fields = {name: getattr(result, name) for name in dir(result) if name.startswith("st_")}
                fields.update(st_uid=0, st_gid=0)
                return SimpleNamespace(**fields)
            return read
        self.enterContext(mock.patch.object(subject.os, "stat", side_effect=mapped(self.original_stat)))
        self.enterContext(mock.patch.object(subject.os, "fstat", side_effect=mapped(self.original_fstat)))
        self.enterContext(mock.patch.object(subject.os, "lstat", side_effect=mapped(self.original_lstat)))

    def hold(self, **changes):
        return subject.hold_provider_evidence(self.config, changes.pop("control_fd", self.control_fd),
            activation=changes.pop("activation", self.activation), deadline=changes.pop("deadline", 125.0), **changes)

    def blob(self, digest):
        return self.sha / digest[7:9] / digest[9:]

    def assert_cause_observation(self, error, status="CLEANUP_HOLD"):
        observed = error.pi_provider_evidence_observation
        self.assertEqual(observed["schema"], subject.SCHEMA)
        self.assertEqual(observed["status"], status)
        self.assertFalse(observed["phase3_eligible"])
        return observed


class ProviderEvidenceTests(Fixture):
    def test_exact_raw_record_and_ordered_index_are_durable_before_return(self):
        value = {"fabricated": [2, 3], "text": "private record"}
        with self.hold() as owner:
            header_raw = self.index.read_bytes()
            ref = owner.retain("REQUEST", value)
            expected = canonical_json(value)
            self.assertEqual(ref, {"kind": "REQUEST", "digest": canonical_digest(value), "bytes": len(expected)})
            self.assertEqual(self.blob(ref["digest"]).read_bytes(), expected)
            lines = self.index.read_bytes().splitlines()
            self.assertEqual(len(lines), 2)
            header, reference = map(json.loads, lines)
            self.assertEqual(header["activation_digest"], canonical_digest(self.activation))
            self.assertEqual(reference["sequence"], 1)
            self.assertEqual(reference["previous_prefix_digest"], subject._digest(header_raw))
            self.assertEqual({key: reference[key] for key in ref}, ref)
            self.assertNotIn(b"private record", self.index.read_bytes())
            self.assertEqual(owner.observation["index_digest"], subject._digest(self.index.read_bytes()))
            self.assertEqual(owner.observation["index_status"], "DURABLE_PREFIX")
        self.assertEqual(owner.observation["status"], "CLOSED")
        self.assertIsNone(owner.observation["pending_reference"])
        self.assertTrue(owner.observation["owned_handles_closed"])
        self.assertFalse(owner.observation["phase3_eligible"])
        self.assertEqual(list(self.sha.glob(".aragorn-put-*")), [])

    def test_observation_and_returned_references_are_detached_and_redacted(self):
        with self.hold() as owner:
            ref = owner.retain("APPROVAL", {"text": "never public"})
            ref["kind"] = "changed"
            public = owner.observation
            public["references"].clear()
            self.assertEqual(owner.observation["references"][0]["kind"], "APPROVAL")
            self.assertNotIn(b"never public", canonical_json(owner.observation))

    def test_same_blob_deduplicates_but_each_actual_reference_is_ordered(self):
        with self.hold() as owner:
            first = owner.retain("REQUEST", {"same": True})
            second = owner.retain("FAILURE", {"same": True})
            self.assertEqual(first["digest"], second["digest"])
            self.assertEqual(len(owner.observation["references"]), 2)
            lines = [json.loads(line) for line in self.index.read_bytes().splitlines()]
            self.assertEqual([line["sequence"] for line in lines], [0, 1, 2])
            raw_prefix = b"\n".join(self.index.read_bytes().splitlines()[:2]) + b"\n"
            self.assertEqual(lines[2]["previous_prefix_digest"], subject._digest(raw_prefix))
        self.assertEqual(self.original_stat(self.blob(first["digest"])).st_nlink, 1)

    def test_existing_blob_is_explicitly_fsynced_and_read_back(self):
        value = {"existing": "same bytes"}
        with self.hold() as owner:
            ref = owner.retain("REQUEST", value)
            original_fsync = os.fsync
            seen = []
            def fsync(fd):
                seen.append((self.original_fstat(fd).st_dev, self.original_fstat(fd).st_ino))
                return original_fsync(fd)
            with mock.patch.object(subject.os, "fsync", side_effect=fsync):
                owner.retain("FAILURE", value)
            info = self.original_stat(self.blob(ref["digest"]))
            self.assertIn((info.st_dev, info.st_ino), seen)

    def test_borrowed_control_descriptor_remains_open(self):
        with self.hold():
            pass
        self.assertEqual(self.original_fstat(self.control_fd).st_ino, self.original_stat(self.control).st_ino)

    def test_store_initialization_does_not_create_any_directory(self):
        with mock.patch.object(subject.os, "mkdir", side_effect=AssertionError("no provisioning")) as mkdir:
            with self.hold():
                pass
        mkdir.assert_not_called()

    def test_missing_store_is_not_created(self):
        (self.sha).rmdir()
        (self.store / "blobs").rmdir()
        self.store.rmdir()
        with self.assertRaises(FileNotFoundError) as raised:
            with self.hold():
                self.fail("missing store must refuse")
        observed = self.assert_cause_observation(raised.exception, "REFUSED")
        self.assertTrue(observed["owned_handles_closed"])
        self.assertFalse(self.store.exists())

    def test_missing_sha_directory_is_not_provisioned(self):
        self.sha.rmdir()
        with self.assertRaises(FileNotFoundError):
            with self.hold():
                self.fail("missing internal directory must refuse")
        self.assertFalse(self.sha.exists())

    def test_symlink_store_refuses_without_following(self):
        self.store.rename(self.control / "retained-store")
        self.store.symlink_to(self.control / "retained-store", target_is_directory=True)
        with self.assertRaises(OSError):
            with self.hold():
                self.fail("symlink must refuse")
        self.assertFalse((self.control / "retained-store" / self.index.name).exists())

    def test_nonprivate_store_refuses_before_attempt_index(self):
        self.store.chmod(0o755)
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold():
                self.fail("nonprivate store must refuse")
        self.assertFalse(self.index.exists())

    def test_store_owner_change_refuses_before_retention(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                original_fstat = subject.os.fstat
                def wrong_owner(fd):
                    value = original_fstat(fd)
                    if fd == owner._root:
                        value.st_uid = 999
                    return value
                with mock.patch.object(subject.os, "fstat", side_effect=wrong_owner):
                    owner.retain("REQUEST", {"refused": True})
        self.assertEqual(owner.observation["references"], [])

    def test_existing_attempt_index_is_preserved_and_never_resumed(self):
        with self.hold():
            pass
        previous = self.index.read_bytes()
        with self.assertRaises(FileExistsError) as raised:
            with self.hold():
                self.fail("attempt must not resume")
        self.assert_cause_observation(raised.exception, "REFUSED")
        self.assertEqual(self.index.read_bytes(), previous)

    def test_named_store_replacement_refuses_and_preserves_original(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                self.store.rename(self.control / "original-store")
                CAS(self.store)
                owner.retain("REQUEST", {"not": "retained"})
        self.assertEqual(owner.observation["status"], "CLEANUP_HOLD")
        self.assertTrue((self.control / "original-store" / self.index.name).exists())
        self.assertFalse(self.index.exists())

    def test_named_control_replacement_refuses_without_closing_borrowed_handle(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                self.control.rename(self.root / "original-control")
                self.control.mkdir(mode=0o700)
                owner.retain("REQUEST", {"refused": True})
        self.original_fstat(self.control_fd)

    def test_index_prefix_tampering_is_not_rewritten(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                self.index.chmod(0o600)
                with self.index.open("ab") as output:
                    output.write(b"foreign\n")
                self.index.chmod(0o400)
                owner.retain("REQUEST", {"actual": True})
        self.assertTrue(self.index.read_bytes().endswith(b"foreign\n"))
        self.assertEqual(owner.observation["references"], [])

    def test_unknown_kind_cannot_select_a_path(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                owner.retain("../key", {"value": 1})
        self.assertEqual(owner.observation["references"], [])
        self.assertEqual(list(self.sha.iterdir()), [])

    def test_nonobject_record_and_noncanonical_value_refuse(self):
        for index, value in enumerate(([], {"value": float("nan")}, {"value": object()})):
            candidate = activation()
            candidate.update(activation_id=f"{index + 1:032x}", session_id=f"{index + 1:032x}", run_id=f"{index + 1:032x}")
            with self.subTest(index=index), self.assertRaises((RuntimeError, TypeError, ValueError)):
                with self.hold(activation=candidate) as owner:
                    owner.retain("REQUEST", value)

    def test_record_size_bound_precedes_any_blob_write(self):
        with mock.patch.object(subject._HeldCAS, "put_expected", side_effect=AssertionError("must not write")) as put:
            with self.assertRaises(subject.PiProviderEvidenceError):
                with self.hold() as owner:
                    owner.retain("REQUEST", {"value": "x" * subject._MAX_RECORD})
        put.assert_not_called()

    def test_record_count_is_bounded_at_64(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                for index in range(64):
                    owner.retain("DECISION", {"record": index})
                self.assertEqual(len(owner.observation["references"]), 64)
                owner.retain("DECISION", {"record": 65})
        self.assertEqual(len(self.index.read_bytes().splitlines()), 65)

    def test_original_deadline_and_activation_expiry_are_not_extended(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                self.clock.return_value = self.activation["expires_at_monotonic_ns"]
                owner.retain("REQUEST", {"late": True})
        self.assertEqual(owner.observation["references"], [])

    def test_deadline_beyond_actual_activation_refuses_before_store(self):
        candidate = activation()
        candidate["expires_at_monotonic_ns"] = 120_000_000_000
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold(activation=candidate):
                self.fail("extended deadline must refuse")
        self.assertFalse(self.index.exists())

    def test_original_caller_deadline_expiry_refuses_without_widening(self):
        with self.assertRaises(RuntimeError):
            with self.hold() as owner:
                with mock.patch.object(subject.time, "monotonic", return_value=126.0):
                    owner.retain("REQUEST", {"late": True})
        self.assertEqual(owner.observation["references"], [])

    def test_invalid_activation_cannot_choose_attempt_filename(self):
        candidate = activation()
        candidate["activation_id"] = "../escape"
        with self.assertRaises(RuntimeError):
            with self.hold(activation=candidate):
                self.fail("invalid identity must refuse")
        self.assertFalse(self.index.exists())

    def test_constructor_is_not_a_public_authority_factory(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            subject.PiProviderEvidence()

    def test_closed_owner_cannot_append(self):
        with self.hold() as owner:
            pass
        previous = self.index.read_bytes()
        with self.assertRaises(subject.PiProviderEvidenceError):
            owner.retain("REQUEST", {"late": True})
        self.assertEqual(self.index.read_bytes(), previous)


class ProviderEvidenceFailureTests(Fixture):
    def test_corrupt_existing_digest_is_not_overwritten_or_indexed(self):
        value = {"expected": "raw"}
        digest = canonical_digest(value)
        self.blob(digest).parent.mkdir(mode=0o700)
        self.blob(digest).write_bytes(b"different")
        self.blob(digest).chmod(0o444)
        from aragorn.cas import CASError
        with self.assertRaises(CASError):
            with self.hold() as owner:
                owner.retain("REQUEST", value)
        self.assertEqual(self.blob(digest).read_bytes(), b"different")
        self.assertEqual(owner.observation["references"], [])

    def test_cas_temporary_unlink_failure_is_observed_not_erased(self):
        original_unlink = os.unlink
        def refuse_temp(path, *args, **kwargs):
            if str(path).startswith(".aragorn-put-"):
                raise OSError("inert unlink failure")
            return original_unlink(path, *args, **kwargs)
        with self.assertRaises(subject.PiProviderEvidenceError) as raised:
            with self.hold() as owner:
                with mock.patch.object(subject.os, "unlink", side_effect=refuse_temp):
                    owner.retain("REQUEST", {"raw": "retained even though temporary remains"})
        observed = self.assert_cause_observation(raised.exception)
        self.assertEqual(len(list(self.sha.glob(".aragorn-put-*"))), 1)
        self.assertEqual(len(observed["references"]), 0)
        self.assertIn({"stage": "CAS", "reason": "TEMPORARY_CLEANUP_UNCONFIRMED"}, observed["uncertainty"])

    def test_raw_readback_failure_does_not_append_reference_or_retry(self):
        with self.assertRaises(OSError) as raised:
            with self.hold() as owner:
                with mock.patch.object(subject._HeldCAS, "read", side_effect=OSError("inert readback")) as read:
                    owner.retain("REQUEST", {"actual": "raw"})
        observed = self.assert_cause_observation(raised.exception)
        read.assert_called_once()
        self.assertFalse(observed["owned_handles_closed"])
        self.assertEqual(observed["references"], [])
        self.assertEqual(len(self.index.read_bytes().splitlines()), 1)
        self.assertEqual(observed["pending_reference"], {"kind": "REQUEST", "digest": canonical_digest({"actual": "raw"}),
            "bytes": len(canonical_json({"actual": "raw"}))})

    def test_cas_write_exception_preserves_unknown_helper_cleanup(self):
        with self.assertRaises(OSError) as raised:
            with self.hold() as owner:
                with mock.patch.object(subject._HeldCAS, "put_expected", side_effect=OSError("inert put")) as put:
                    owner.retain("REQUEST", {"actual": 1})
        observed = self.assert_cause_observation(raised.exception)
        put.assert_called_once()
        self.assertFalse(observed["owned_handles_closed"])
        self.assertIn({"stage": "CAS_WRITE", "reason": "HELPER_HANDLES_UNCONFIRMED"}, observed["uncertainty"])

    def test_partial_reference_append_is_retained_with_previous_verified_prefix(self):
        original_write = os.write
        with self.assertRaises(OSError) as raised:
            with self.hold() as owner:
                previous = owner.observation
                def partial(fd, raw):
                    if fd == owner._index:
                        original_write(fd, raw[:5])
                        raise OSError("inert interrupted append")
                    return original_write(fd, raw)
                with mock.patch.object(subject.os, "write", side_effect=partial):
                    owner.retain("REQUEST", {"raw": "still durable"})
        observed = self.assert_cause_observation(raised.exception)
        self.assertEqual(observed["index_status"], "UNCONFIRMED")
        self.assertEqual(observed["index_digest"], previous["index_digest"])
        self.assertEqual(observed["index_bytes"], previous["index_bytes"])
        self.assertEqual(self.index.stat().st_size, previous["index_bytes"] + 5)
        self.assertEqual(observed["references"], [])
        self.assertEqual(observed["pending_reference"]["kind"], "REQUEST")

    def test_index_fsync_failure_never_promotes_appended_reference(self):
        original_fsync = os.fsync
        with self.assertRaises(OSError) as raised:
            with self.hold() as owner:
                def fsync(fd):
                    if fd == owner._index:
                        raise OSError("inert index durability")
                    return original_fsync(fd)
                with mock.patch.object(subject.os, "fsync", side_effect=fsync):
                    owner.retain("REQUEST", {"raw": "durable but index unconfirmed"})
        observed = self.assert_cause_observation(raised.exception)
        self.assertEqual(observed["index_status"], "UNCONFIRMED")
        self.assertEqual(observed["references"], [])

    def test_blob_fsync_failure_leaves_unindexed_blob(self):
        original_fsync = os.fsync
        with self.assertRaises(OSError):
            with self.hold() as owner:
                put_complete = False
                original_put = owner._cas.put_expected
                def put(*args, **kwargs):
                    nonlocal put_complete
                    result = original_put(*args, **kwargs)
                    put_complete = True
                    return result
                def fsync(fd):
                    metadata = self.original_fstat(fd)
                    if put_complete and stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) == 0o444:
                        raise OSError("inert blob durability")
                    return original_fsync(fd)
                with mock.patch.object(owner._cas, "put_expected", side_effect=put), \
                     mock.patch.object(subject.os, "fsync", side_effect=fsync):
                    owner.retain("REQUEST", {"raw": 1})
        self.assertEqual(owner.observation["references"], [])

    def test_borrowed_control_is_not_closed_when_index_creation_fails(self):
        self.index.write_bytes(b"preexisting")
        self.index.chmod(0o400)
        with self.assertRaises(FileExistsError):
            with self.hold():
                self.fail("existing index must refuse")
        self.original_fstat(self.control_fd)
        self.assertEqual(self.index.read_bytes(), b"preexisting")

    def test_close_failure_is_attempted_once_with_other_owned_closes_continuing(self):
        original_close = os.close
        closed = []
        index_fd = None
        def close(fd):
            closed.append(fd)
            if fd == index_fd:
                original_close(fd)
                raise OSError("closed but outcome unconfirmed")
            return original_close(fd)
        with self.assertRaises(subject.PiProviderEvidenceError) as raised:
            with mock.patch.object(subject.os, "close", side_effect=close):
                with self.hold() as owner:
                    index_fd = owner._index
                    owned = list(owner._fds)
        observed = self.assert_cause_observation(raised.exception)
        self.assertFalse(observed["owned_handles_closed"])
        self.assertEqual(closed.count(index_fd), 1)
        self.assertTrue(set(owned) <= set(closed))
        self.assertNotIn(self.control_fd, closed)

    def test_body_cancellation_preserves_same_exception_and_storage_prefix(self):
        failure = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as raised:
            with self.hold() as owner:
                owner.retain("REQUEST", {"before": "cancellation"})
                raise failure
        self.assertIs(raised.exception, failure)
        observed = raised.exception.pi_provider_evidence_observation
        self.assertEqual(observed["status"], "CLOSED")
        self.assertTrue(observed["owned_handles_closed"])
        self.assertEqual(len(observed["references"]), 1)

    def test_swallowed_retain_failure_cannot_be_returned_as_success(self):
        with self.assertRaises(subject.PiProviderEvidenceError):
            with self.hold() as owner:
                try:
                    owner.retain("INVALID", {"value": True})
                except subject.PiProviderEvidenceError:
                    pass
        self.assertEqual(owner.observation["status"], "CLEANUP_HOLD")

    def test_header_failure_is_not_an_empty_successful_attempt(self):
        with mock.patch.object(subject.provision.provision, "_write_all", side_effect=OSError("header write")):
            with self.assertRaises(OSError) as raised:
                with self.hold():
                    self.fail("failed header must not yield")
        observed = self.assert_cause_observation(raised.exception)
        self.assertEqual(observed["index_status"], "UNCONFIRMED")
        self.assertIsNone(observed["index_digest"])
        self.assertTrue(self.index.exists())


def load_tests(loader, tests, pattern):
    """Select only this new focused suite, never imported historical cases."""
    return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in
                              (ProviderEvidenceTests, ProviderEvidenceFailureTests))
