"""Owned inert files, real publisher and post-lock readback, no runtime activation."""

import os
import unittest
from unittest import mock

from aragorn.oci_worker_protocol import canonical_json
from tests import test_pi_core_bundle_install_entry as previous

subject = previous.subject


class PostpublicationTests(previous.ExistingPublisherConsumerTests):
    def after_publish(self, change):
        publish = subject.publisher._publish_protected_install_transaction
        def changed(*args, **kwargs):
            result = publish(*args, **kwargs)
            return change(result) or result
        return self.enterContext(mock.patch.object(subject.publisher, "_publish_protected_install_transaction",
                                                   side_effect=changed))

    def held_failure(self):
        with self.assertRaises(subject.PiBundleInstallEntryError) as error:
            self.install()
        row = error.exception.observation
        self.assertTrue(row["installation_attempted"])
        self.assertEqual((row["publication_state"], row["status"]), ("PUBLISHER_RETURNED", "CLEANUP_HOLD"))
        self.assertIsNone(row["observed_tree_digest"])
        self.assertFalse(row["phase3_exit_eligible"])
        return row

    def test_measures_actual_install_and_distinct_update_against_each_approved_cas_manifest(self):
        first = self.install()
        old = subject.load_verified_retained_manifest(self.cas, self.context["manifest_digest"])
        self.assertEqual(first["observed_tree_digest"], old["tree_digest"])
        next_context = self.candidate("b", b"# Independently approved update\n", self.context)
        update = self.install()
        new = subject.load_verified_retained_manifest(self.cas, next_context["manifest_digest"])
        self.assertEqual(update["observed_tree_digest"], new["tree_digest"])
        self.assertNotEqual(first["observed_tree_digest"], update["observed_tree_digest"])
        self.assertFalse(update["managed_call_attempted"])

    def test_matching_size_and_mode_do_not_promote_changed_bytes(self):
        def change(result):
            path = self.protected / result["version_path"] / "SKILL.md"
            self.changed_bytes = b"X" * path.stat().st_size
            path.chmod(0o644)
            path.write_bytes(self.changed_bytes)
            path.chmod(0o444)
        published = self.after_publish(change)
        row = self.held_failure()
        self.assertEqual((self.protected / row["transaction"]["version_path"] / "SKILL.md").read_bytes(), self.changed_bytes)
        published.assert_called_once()

    def test_approved_content_in_writable_file_is_not_immutable(self):
        def change(result):
            (self.protected / result["version_path"] / "SKILL.md").chmod(0o644)
        self.after_publish(change)
        row = self.held_failure()
        self.assertEqual((self.protected / row["transaction"]["version_path"] / "SKILL.md").stat().st_mode & 0o777, 0o644)

    def test_substituted_pointer_is_never_repaired(self):
        def change(result):
            active = self.protected / self.context["destination"]["target_name"]
            active.unlink()
            active.symlink_to("unrelated-version")
        published = self.after_publish(change)
        row = self.held_failure()
        self.assertEqual(os.readlink(self.protected / self.context["destination"]["target_name"]), "unrelated-version")
        self.assertTrue((self.protected / row["transaction"]["version_path"] / "SKILL.md").is_file())
        published.assert_called_once()

    def test_publisher_and_active_record_agreeing_do_not_override_verified_context(self):
        def change(result):
            record = self.protected / subject.lineage.ACTIVE_RUNTIME_RECORD
            altered = result | {"context_digest": previous.pin("f")}
            document = subject.lineage.parse_active_runtime_record(record.read_bytes()) | {"transaction": altered}
            record.chmod(0o644)
            record.write_bytes(canonical_json(document))
            record.chmod(0o444)
            return altered
        published = self.after_publish(change)
        row = self.held_failure()
        self.assertEqual(row["transaction"]["context_digest"], previous.pin("f"))
        self.assertNotEqual(row["transaction"]["context_digest"], row["context_digest"])
        published.assert_called_once()

    def test_replaced_version_name_after_hash_does_not_validate_a_different_inode(self):
        original = subject.publisher.legacy._verify_version_tree
        def rebind(cas, digest, parent_fd, version):
            measured = original(cas, digest, parent_fd, version)
            os.rename(version, "retained-original", src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.mkdir(version, mode=0o555, dir_fd=parent_fd)
            return measured
        # Only change the readback helper after the real publisher has returned.
        def change(result):
            self.enterContext(mock.patch.object(subject.publisher.legacy, "_verify_version_tree", side_effect=rebind))
        published = self.after_publish(change)
        row = self.held_failure()
        path = self.protected / row["transaction"]["version_path"]
        self.assertTrue((path.parent / "retained-original" / "SKILL.md").is_file())
        self.assertEqual(list(path.iterdir()), [])
        published.assert_called_once()

    def test_uncertain_readback_close_retains_publish_without_repeat_or_positive_measurement(self):
        original_close, original_open = os.close, subject.lineage._open_directory_at
        held, attempted = [], []
        def capture(*args):
            fd = original_open(*args)
            if args[-1] == "managed published directory":
                held.append(fd)
            return fd
        def uncertain(fd):
            original_close(fd)
            if held and fd == held[0] and not attempted:
                attempted.append(fd)
                raise OSError("uncertain readback close")
        self.enterContext(mock.patch.object(subject.lineage, "_open_directory_at", side_effect=capture))
        self.enterContext(mock.patch.object(os, "close", side_effect=uncertain))
        row = self.held_failure()
        self.assertEqual(attempted, held[:1])
        self.assertEqual(row["input_cleanup_uncertainty"], [{"scope": "POSTPUBLICATION_DIRECTORY_CLOSE",
                                                           "descriptors": attempted}])
        self.assertTrue((self.protected / row["transaction"]["version_path"] / "SKILL.md").exists())


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite(PostpublicationTests(name) for name in sorted(PostpublicationTests.__dict__)
                               if name.startswith("test_"))
    for name in ("test_install_calls_existing_publisher_once_with_measured_runtime_and_no_new_authority",
                 "test_reacquire_or_active_readback_failure_preserves_transaction",
                 "test_destination_close_failure_never_reports_success_or_retries",
                 "test_input_close_failure_preserves_publication"):
        suite.addTest(previous.InstallEntryTests(name))
    return suite
