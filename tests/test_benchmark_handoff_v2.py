from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn import benchmark_handoff_v2
from aragorn.benchmark_handoff_v2 import (
    HandoffError,
    build_handoff_manifest,
    export_declared_byte_transport as export_handoff,
    handoff_manifest_digest,
    import_declared_byte_transport as import_handoff,
    validate_handoff_manifest,
)
from aragorn.cas import CAS, CASError
from aragorn.oci_worker_protocol import canonical_json


class BenchmarkHandoffV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.source_cas = CAS(self.root / "source")

    def test_manifest_is_canonical_bounded_and_exact(self) -> None:
        first = self._put(self.source_cas, b"first")
        second = self._put(self.source_cas, b"second")
        manifest = build_handoff_manifest(
            kind="worker_input",
            root_digest=first,
            blobs={second: 6, first: 5},
        )

        self.assertEqual(
            [item["digest"] for item in manifest["blobs"]],
            sorted((first, second)),
        )
        self.assertEqual(manifest["total_bytes"], 11)
        self.assertEqual(
            handoff_manifest_digest(manifest),
            "sha256:" + hashlib.sha256(canonical_json(manifest)).hexdigest(),
        )
        validate_handoff_manifest(manifest)

        mutations = []
        unknown = deepcopy(manifest)
        unknown["unknown"] = True
        mutations.append(("unknown", unknown))
        wrong_kind = deepcopy(manifest)
        wrong_kind["kind"] = "arbitrary"
        mutations.append(("kind", wrong_kind))
        missing_root = deepcopy(manifest)
        missing_root["root_digest"] = "sha256:" + "f" * 64
        mutations.append(("root_digest", missing_root))
        unsorted = deepcopy(manifest)
        unsorted["blobs"].reverse()
        mutations.append(("sorted", unsorted))
        repeated = deepcopy(manifest)
        repeated["blobs"].insert(1, deepcopy(repeated["blobs"][0]))
        repeated["total_bytes"] += repeated["blobs"][0]["size"]
        mutations.append(("repeats", repeated))
        wrong_total = deepcopy(manifest)
        wrong_total["total_bytes"] += 1
        mutations.append(("total_bytes", wrong_total))
        boolean_size = deepcopy(manifest)
        boolean_size["blobs"][0]["size"] = True
        mutations.append(("size", boolean_size))
        for label, mutation in mutations:
            with self.subTest(label=label), self.assertRaises(HandoffError):
                validate_handoff_manifest(mutation)

        with self.assertRaises(HandoffError):
            build_handoff_manifest(
                kind="worker_input",
                root_digest=first,
                blobs={first: 5, 1: 2},  # type: ignore[dict-item]
            )

        bounded = {
            "sha256:" + "1" * 64: 128 * 1024 * 1024,
            "sha256:" + "2" * 64: 128 * 1024 * 1024,
            "sha256:" + "3" * 64: 32 * 1024 * 1024,
        }
        maximum_input = build_handoff_manifest(
            kind="worker_input",
            root_digest="sha256:" + "1" * 64,
            blobs=bounded,
        )
        self.assertEqual(maximum_input["total_bytes"], 288 * 1024 * 1024)
        with self.assertRaisesRegex(HandoffError, "total_bytes"):
            build_handoff_manifest(
                kind="worker_input",
                root_digest="sha256:" + "1" * 64,
                blobs={
                    **bounded,
                    "sha256:" + "4" * 64: 1,
                },
            )

    def test_export_and_import_rehash_exact_bytes_into_another_cas(self) -> None:
        payloads = (b"root request", b"", b"subject bytes")
        digests = [self._put(self.source_cas, payload) for payload in payloads]
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=digests[0],
            blobs={
                digest: len(payload)
                for digest, payload in zip(digests, payloads, strict=True)
            },
        )
        bundle = self.root / "bundle"

        exported_digest = export_handoff(self.source_cas, manifest, bundle)

        self.assertEqual(exported_digest, handoff_manifest_digest(manifest))
        self.assertEqual(
            (bundle / "manifest.json").read_bytes(),
            canonical_json(manifest),
        )
        self.assertEqual(
            stat.S_IMODE(os.lstat(bundle / "manifest.json").st_mode),
            0o444,
        )
        self.assertEqual(
            set(path.name for path in (bundle / "blobs").iterdir()),
            {digest.removeprefix("sha256:") for digest in digests},
        )
        self.assertEqual(stat.S_IMODE(os.lstat(bundle).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(bundle / "blobs").st_mode), 0o700)

        # A production transport copies this private bundle into a
        # receiver-owned snapshot. This unit test exercises the byte format and
        # importer under one UID; the distinct-principal exercise remains an
        # external Phase 0 gate.
        destination = CAS(self.root / "destination")
        imported = import_handoff(
            bundle,
            destination,
            expected_manifest_digest=exported_digest,
            expected_kind="worker_output",
            expected_root_digest=digests[0],
        )

        self.assertEqual(imported, manifest)
        for digest, payload in zip(digests, payloads, strict=True):
            self.assertEqual(destination.read(digest), payload)
        self.assertEqual(
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=exported_digest,
                expected_kind="worker_output",
                expected_root_digest=digests[0],
            ),
            manifest,
        )

    def test_import_rejects_manifest_expectation_and_blob_tampering(self) -> None:
        original = b"root-data"
        root_digest = self._put(self.source_cas, original)
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: len(original)},
        )
        bundle = self.root / "bundle"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)

        with self.assertRaisesRegex(HandoffError, "manifest digest"):
            import_handoff(
                bundle,
                CAS(self.root / "wrong-manifest"),
                expected_manifest_digest="sha256:" + "f" * 64,
                expected_kind="worker_output",
                expected_root_digest=root_digest,
            )
        with self.assertRaisesRegex(HandoffError, "kind"):
            import_handoff(
                bundle,
                CAS(self.root / "wrong-kind"),
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_input",
                expected_root_digest=root_digest,
            )
        with self.assertRaisesRegex(HandoffError, "root digest"):
            import_handoff(
                bundle,
                CAS(self.root / "wrong-root"),
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_output",
                expected_root_digest="sha256:" + "e" * 64,
            )

        blob = bundle / "blobs" / root_digest.removeprefix("sha256:")
        blob.chmod(0o644)
        blob.write_bytes(b"evil-data")
        blob.chmod(0o444)
        substituted_digest = "sha256:" + hashlib.sha256(b"evil-data").hexdigest()
        destination = CAS(self.root / "tampered")
        with self.assertRaisesRegex(HandoffError, "digest does not match"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_output",
                expected_root_digest=root_digest,
            )
        with self.assertRaises(CASError):
            destination.verify(root_digest)
        with self.assertRaises(CASError):
            destination.verify(substituted_digest)
        self.assertEqual(
            list(destination.root.glob(".aragorn-handoff-import-*")),
            [],
        )

    def test_import_rejects_ambiguous_bundle_structure(self) -> None:
        cases = (
            "extra",
            "missing",
            "wrong-size",
            "symlink",
            "hardlink",
            "noncanonical",
            "duplicate-key",
            "overlap",
        )
        for case in cases:
            with self.subTest(case=case):
                source = CAS(self.root / f"source-{case}")
                root_digest = self._put(source, b"root")
                manifest = build_handoff_manifest(
                    kind="worker_output",
                    root_digest=root_digest,
                    blobs={root_digest: 4},
                )
                bundle = self.root / f"bundle-{case}"
                manifest_digest = export_handoff(source, manifest, bundle)
                blob = bundle / "blobs" / root_digest.removeprefix("sha256:")
                destination = CAS(
                    bundle / "destination"
                    if case == "overlap"
                    else self.root / f"destination-{case}"
                )

                if case == "extra":
                    (bundle / "blobs" / "extra").write_bytes(b"x")
                    message = "exact manifest"
                elif case == "missing":
                    blob.unlink()
                    message = "exact manifest"
                elif case == "wrong-size":
                    blob.chmod(0o644)
                    blob.write_bytes(b"roots")
                    blob.chmod(0o444)
                    message = "size does not match"
                elif case == "symlink":
                    outside = self.root / "outside-symlink"
                    outside.write_bytes(b"root")
                    blob.unlink()
                    blob.symlink_to(outside)
                    message = "cannot import handoff"
                elif case == "hardlink":
                    outside = self.root / "outside-hardlink"
                    outside.write_bytes(b"root")
                    blob.unlink()
                    os.link(outside, blob)
                    message = "singly linked"
                elif case == "noncanonical":
                    raw = json.dumps(manifest, indent=2).encode("ascii")
                    manifest_path = bundle / "manifest.json"
                    manifest_path.chmod(0o644)
                    manifest_path.write_bytes(raw)
                    manifest_path.chmod(0o444)
                    manifest_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
                    message = "canonical JSON"
                elif case == "duplicate-key":
                    raw = (
                        b'{"schema":"aragorn/benchmark-cas-handoff/v1",'
                        b'"schema":"aragorn/benchmark-cas-handoff/v1"}'
                    )
                    manifest_path = bundle / "manifest.json"
                    manifest_path.chmod(0o644)
                    manifest_path.write_bytes(raw)
                    manifest_path.chmod(0o444)
                    manifest_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
                    message = "duplicate"
                else:
                    message = "must not overlap"

                with self.assertRaisesRegex(HandoffError, message):
                    import_handoff(
                        bundle,
                        destination,
                        expected_manifest_digest=manifest_digest,
                        expected_kind="worker_output",
                        expected_root_digest=root_digest,
                    )

    def test_import_rejects_bundle_nested_below_destination_cas(self) -> None:
        root_digest = self._put(self.source_cas, b"root")
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 4},
        )
        destination = CAS(self.root / "destination-containing-bundle")
        bundle = destination.root / "incoming"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)

        with self.assertRaisesRegex(HandoffError, "must not overlap"):
            import_handoff(
                bundle,
                destination,
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_output",
                expected_root_digest=root_digest,
            )

    def test_descriptor_overlap_check_survives_source_rename(self) -> None:
        root_digest = self._put(self.source_cas, b"root")
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 4},
        )
        bundle = self.root / "bundle-renamed-during-open"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)
        destination = CAS(self.root / "destination-rename")
        moved_bundle = destination.root / "incoming"
        original_open = benchmark_handoff_v2._open_bundle_root

        def open_then_move(source):
            descriptor = original_open(source)
            bundle.rename(moved_bundle)
            return descriptor

        with mock.patch.object(
            benchmark_handoff_v2,
            "_open_bundle_root",
            side_effect=open_then_move,
        ):
            with self.assertRaisesRegex(HandoffError, "must not overlap"):
                import_handoff(
                    bundle,
                    destination,
                    expected_manifest_digest=manifest_digest,
                    expected_kind="worker_output",
                    expected_root_digest=root_digest,
                )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_import_rejects_special_blob_without_blocking(self) -> None:
        root_digest = self._put(self.source_cas, b"root")
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 4},
        )
        bundle = self.root / "bundle-fifo"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)
        blob = bundle / "blobs" / root_digest.removeprefix("sha256:")
        blob.unlink()
        os.mkfifo(blob)

        with self.assertRaisesRegex(HandoffError, "singly linked regular file"):
            import_handoff(
                bundle,
                CAS(self.root / "destination-fifo"),
                expected_manifest_digest=manifest_digest,
                expected_kind="worker_output",
                expected_root_digest=root_digest,
            )

    def test_import_detects_a_blob_changed_during_rehash(self) -> None:
        root_digest = self._put(self.source_cas, b"stable")
        companion_digest = self._put(self.source_cas, b"companion")
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 6, companion_digest: 9},
        )
        bundle = self.root / "bundle-changing"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)
        blob = bundle / "blobs" / root_digest.removeprefix("sha256:")
        destination = CAS(self.root / "destination-changing")
        original_stage = benchmark_handoff_v2._stage_blob
        staged = 0

        def mutate_after_copy(directory_fd, digest, size, staging_fd):
            nonlocal staged
            result = original_stage(directory_fd, digest, size, staging_fd)
            staged += 1
            if staged == len(manifest["blobs"]):
                blob.chmod(0o644)
                blob.write_bytes(b"stable")
                blob.chmod(0o444)
            return result

        with mock.patch.object(
            benchmark_handoff_v2,
            "_stage_blob",
            side_effect=mutate_after_copy,
        ):
            with self.assertRaisesRegex(HandoffError, "changed while imported"):
                import_handoff(
                    bundle,
                    destination,
                    expected_manifest_digest=manifest_digest,
                    expected_kind="worker_output",
                    expected_root_digest=root_digest,
                )
        for digest in (root_digest, companion_digest):
            with self.assertRaises(CASError):
                destination.verify(digest)
        self.assertEqual(
            list(destination.root.glob(".aragorn-handoff-import-*")),
            [],
        )

    def test_import_detects_manifest_change_during_blob_rehash(self) -> None:
        root_digest = self._put(self.source_cas, b"stable")
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 6},
        )
        bundle = self.root / "bundle-changing-manifest"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)
        manifest_path = bundle / "manifest.json"
        destination = CAS(self.root / "destination-manifest")
        original_stage = benchmark_handoff_v2._stage_blob

        def mutate_manifest_after_copy(directory_fd, digest, size, staging_fd):
            result = original_stage(directory_fd, digest, size, staging_fd)
            raw = manifest_path.read_bytes().replace(
                b"worker_output",
                b"worker_outpuX",
            )
            manifest_path.chmod(0o644)
            manifest_path.write_bytes(raw)
            manifest_path.chmod(0o444)
            return result

        with mock.patch.object(
            benchmark_handoff_v2,
            "_stage_blob",
            side_effect=mutate_manifest_after_copy,
        ):
            with self.assertRaisesRegex(HandoffError, "manifest changed"):
                import_handoff(
                    bundle,
                    destination,
                    expected_manifest_digest=manifest_digest,
                    expected_kind="worker_output",
                    expected_root_digest=root_digest,
                )
        with self.assertRaises(CASError):
            destination.verify(root_digest)
        self.assertEqual(
            list(destination.root.glob(".aragorn-handoff-import-*")),
            [],
        )

    def test_operational_commit_failure_never_publishes_root_first(self) -> None:
        root_digest = self._put(self.source_cas, b"root")
        companion_digest = self._put(self.source_cas, b"companion")
        manifest = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 4, companion_digest: 9},
        )
        bundle = self.root / "bundle-commit-failure"
        manifest_digest = export_handoff(self.source_cas, manifest, bundle)
        destination = CAS(self.root / "destination-commit-failure")
        original_put_expected = destination.put_expected
        calls = 0

        def fail_root_commit(stream, *, expected_digest, max_bytes):
            nonlocal calls
            calls += 1
            if calls == len(manifest["blobs"]):
                raise CASError("simulated receiver CAS failure")
            return original_put_expected(
                stream,
                expected_digest=expected_digest,
                max_bytes=max_bytes,
            )

        with mock.patch.object(
            destination,
            "put_expected",
            side_effect=fail_root_commit,
        ):
            with self.assertRaisesRegex(HandoffError, "simulated receiver CAS failure"):
                import_handoff(
                    bundle,
                    destination,
                    expected_manifest_digest=manifest_digest,
                    expected_kind="worker_output",
                    expected_root_digest=root_digest,
                )

        with self.assertRaises(CASError):
            destination.verify(root_digest)
        destination.verify(companion_digest)

    def test_export_is_fresh_bounded_and_cleans_failed_staging(self) -> None:
        root_digest = self._put(self.source_cas, b"root")
        wrong_size = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 3},
        )
        rejected = self.root / "rejected"
        with self.assertRaisesRegex(HandoffError, "cannot export"):
            export_handoff(self.source_cas, wrong_size, rejected)
        self.assertFalse(os.path.lexists(rejected))
        self.assertEqual(
            list(self.root.glob(".aragorn-handoff-*")),
            [],
        )

        valid = build_handoff_manifest(
            kind="worker_output",
            root_digest=root_digest,
            blobs={root_digest: 4},
        )
        destination = self.root / "existing"
        export_handoff(self.source_cas, valid, destination)
        with self.assertRaisesRegex(HandoffError, "already exists"):
            export_handoff(self.source_cas, valid, destination)

    @staticmethod
    def _put(cas: CAS, content: bytes) -> str:
        return cas.put(BytesIO(content), max_bytes=len(content))


if __name__ == "__main__":
    unittest.main()
