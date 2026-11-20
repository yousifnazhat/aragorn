"""B56: inert original scratch files and a real temporary CAS, never a live fixture."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from aragorn import native_phase3_workload_copy_portable as portable
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_digest, canonical_json
import test_native_phase3_workload_copy_readback as legacy


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class PortableCopyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = legacy.CopyReadbackTests()
        self.fixture.setUp()
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.store = CAS(self.root / "retained")

    def acquire(self, request, *, context=None):
        if context is None:
            with self.fixture.scratch() as (directory, ctx, _):
                result = self.acquire(request, context=ctx)
            self.assertFalse(directory.exists())
            return result
        raw = self.fixture.execute(context, request)
        pin = portable.observe_and_retain(raw, request, self.fixture.boundaries, evidence_cas=self.store, **context)
        expected = {k: v for k, v in context.items() if k != "copy_directory_fd"}
        return raw, pin, expected

    def replay(self, raw, request, pin, expected, *, store=None):
        return portable.verify_portable(raw, request, self.fixture.boundaries, evidence_cas=(
            CAS(self.store.root, read_only=True) if store is None else store), expected_observation_digest=pin, **expected)

    def test_relocated_read_only_replay_consumes_three_original_blobs_after_fixture_removal(self):
        request = self.fixture.request
        raw, pin, expected = self.acquire(request)
        moved = self.root / "portable"
        self.store.root.rename(moved)
        ro = CAS(moved, read_only=True)
        observation = json.loads(ro.read(pin))
        self.assertEqual((pin, observation["receipt_digest"], observation["content_digest"]),
                         (canonical_digest(observation), digest(raw), digest(legacy.INPUT)))
        self.assertEqual((ro.read(observation["receipt_digest"]), ro.read(observation["content_digest"])),
                         (raw, legacy.INPUT))
        self.assertEqual(observation["directory_identity"], expected["expected_copy_directory_identity"])
        with patch.object(legacy.consumer, "observe_copy", side_effect=AssertionError("fixture reopened")), \
                patch.object(legacy.tasks, "execute_reference_task", side_effect=AssertionError("task repeated")), \
                patch.object(CAS, "put_expected", side_effect=AssertionError("replay wrote")):
            self.assertEqual(self.replay(raw, request, pin, expected, store=ro),
                             {"receipt_digest": digest(raw), "request_digest": canonical_digest(request),
                              "deployment_digest": request["deployment_digest"], "semantics": {"completed": True}})

    def test_mixed_observation_pair_mode_and_independent_context_are_rejected(self):
        baseline = self.fixture.request
        instrumented = dict(baseline, mode="instrumented")
        with self.fixture.scratch() as (_, c1, _), self.fixture.scratch() as (_, c2, _):
            raw, pin, expected = self.acquire(baseline, context=c1)
            other_raw, other_pin, other_expected = self.acquire(instrumented, context=c2)
        for args in ((raw, baseline, other_pin, expected), (other_raw, baseline, pin, expected),
                     (raw, instrumented, pin, expected), (raw, dict(baseline, pair_id="other-pair"), pin, expected),
                     (raw, baseline, pin, other_expected),
                     (raw, baseline, pin, dict(expected, expected_fixture={**legacy.FIXTURE, "netns_inode": 99}))):
            with self.subTest(pin=args[2], request=args[1]), self.assertRaises((ValueError, CASError)):
                self.replay(*args)
        self.assertTrue(self.replay(other_raw, instrumented, other_pin, other_expected)["semantics"]["completed"])

    def test_bytes_substituted_in_portable_store_and_wrong_store_modes_are_rejected(self):
        request = self.fixture.request
        raw, pin, expected = self.acquire(request)
        with self.assertRaises(ValueError):
            self.replay(raw, request, pin, expected, store=self.store)
        with patch.object(legacy.consumer, "observe_copy", side_effect=AssertionError("read-only capture")), \
                self.assertRaisesRegex(ValueError, "WRITABLE_CAS_REQUIRED"):
            portable.observe_and_retain(raw, request, self.fixture.boundaries,
                                        evidence_cas=CAS(self.store.root, read_only=True), copy_directory_fd=-1, **expected)
        observation = self.store.read(pin)
        for content in (raw, legacy.INPUT, observation):
            hex_digest = digest(content)[7:]
            blob = self.store.root / "blobs/sha256" / hex_digest[:2] / hex_digest[2:]
            # Replace only this test-owned content, keeping the hash-addressed name unchanged.
            blob.chmod(0o600)
            blob.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
            blob.chmod(0o444)
            with self.subTest(blob=hex_digest), self.assertRaises((ValueError, CASError)):
                self.replay(raw, request, pin, expected)
            blob.chmod(0o600)
            blob.write_bytes(content)
            blob.chmod(0o444)
        forged = json.loads(raw)
        forged["observation"]["result"]["output"]["readback_equal"] = False
        with self.assertRaises((ValueError, CASError)):
            self.replay(canonical_json(forged), request, pin, expected)

    def test_final_guard_or_close_failure_publishes_no_evidence_and_never_retries(self):
        original_close = os.close
        def broken_close(fd):
            original_close(fd)
            raise OSError("injected close uncertainty")
        for problem in ("guard", "close"):
            with self.subTest(failure=problem), self.fixture.scratch() as (directory, context, held):
                raw = self.fixture.execute(context)
                if problem == "guard":
                    fault = patch.object(held, "guard", side_effect=[None, OSError("guard changed"), None])
                else:
                    fault = patch.object(legacy.consumer.os, "close", side_effect=broken_close)
                with fault, patch.object(legacy.tasks, "execute_reference_task", side_effect=AssertionError("task repeated")), \
                        self.assertRaises((OSError, ValueError)):
                    portable.observe_and_retain(raw, self.fixture.request, self.fixture.boundaries,
                                                evidence_cas=self.store, **context)
                self.assertFalse(any(p.is_file() for p in self.store.root.rglob("*")))
                self.assertEqual((directory / "allowed-copy.txt").read_bytes(), legacy.INPUT)
                os.fstat(context["copy_directory_fd"])


def load_tests(loader, tests, pattern):
    affected = (
        "test_both_modes_delegate_once_between_marks_and_preserve_caller_fd", "test_consumer_is_independent_and_rejects_forged_output",
        "test_same_bytes_inode_replacement_refuses", "test_directory_and_fixture_final_guard_changes_refuse",
        "test_content_short_extra_and_post_read_metadata_changes_refuse", "test_close_failure_refuses_and_preserves_primary_error_and_caller_fd",
        "test_invalid_marks_canonical_bytes_and_boolean_metadata_refuse", "test_symlink_hardlink_and_nonregular_retention_refuse",
        "test_pair_mode_and_independent_directory_context_cannot_be_swapped",
    )
    tests.addTests(legacy.CopyReadbackTests(name) for name in affected)
    return tests
