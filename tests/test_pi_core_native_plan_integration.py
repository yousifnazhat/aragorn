"""Only newly affected native-plan guards; no old suite or process execution."""

from pathlib import Path
import dataclasses
import unittest
from unittest import mock

from aragorn import pi_core_confined_launch as confined
import test_pi_core_confined_launch as fixtures


class NativePlanIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.config = fixtures.configuration()
        self.profile = fixtures.profile_for(self.config)
        self.prepared = fixtures.prepared_for(self.profile)

    def test_bundle_destination_is_created_in_private_readonly_tmpfs(self):
        _, argv = confined._systemd_plan(self.config, self.prepared, self.profile)
        self.assertIn("--property=TemporaryFileSystem=/var/lib/aragorn/admitted:ro", argv)
        bundle = str(self.prepared.skill_path.parent)
        self.assertIn(f"--property=BindReadOnlyPaths={bundle}:{bundle}", argv)
        self.assertNotIn("--property=BindReadOnlyPaths=/var/lib/aragorn/admitted", argv)

    def test_stdio_and_host_log_sockets_are_disconnected(self):
        _, argv = confined._systemd_plan(self.config, self.prepared, self.profile)
        for property in ("StandardInput=null", "StandardOutput=null", "StandardError=null",
                         "BindLogSockets=no", "LogNamespace="):
            self.assertIn("--property=" + property, argv)

    def test_shared_memory_hugepage_and_pty_paths_are_masked(self):
        _, argv = confined._systemd_plan(self.config, self.prepared, self.profile)
        self.assertIn("--property=InaccessiblePaths=-" + self.config.relay["workerSocketPath"] +
                      " -/dev/shm -/dev/hugepages -/dev/pts", argv)

    def test_relay_mask_rejects_whitespace_and_systemd_specifiers(self):
        for path in ("/run/relay with spaces", "/run/%h", "/run/relay:other", "/run/relay\npath"):
            config = dataclasses.replace(self.config, relay={**self.config.relay, "workerSocketPath": path})
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "relay socket path"):
                confined._start(config, self.prepared)

    def test_no_alternate_admitted_root_can_reach_admission(self):
        with mock.patch.object(confined.os, "geteuid", return_value=0), \
             mock.patch.object(confined.time, "monotonic", return_value=10), \
             mock.patch.object(confined, "hold_prepared_pi_bundle") as admission:
            with self.assertRaisesRegex(ValueError, "fixed admitted root"):
                with confined.hold_confined_pi_launch_plan(object(), {},
                        profile=self.profile, grant={}, protected_root=Path("/alternate/admitted"),
                        runtime_conformance_digest=fixtures.digest(), deployment={},
                        revoked_context_ids=(), now_unix=1, deadline=20, config=self.config):
                    self.fail("guard yielded a plan")
            admission.assert_not_called()

    def test_fixed_admitted_root_keeps_existing_admission_caller(self):
        pins = {"os_profile": self.config.root_closure_digest,
                "configuration": confined.confined_configuration_digest(self.config),
                "runtime_commit_or_image": self.profile.runtime_digest}
        with mock.patch.object(confined.os, "geteuid", return_value=0), \
             mock.patch.object(confined.time, "monotonic", return_value=10), \
             mock.patch.object(confined, "hold_prepared_pi_bundle", side_effect=RuntimeError("inert admission boundary")) as admission:
            with self.assertRaisesRegex(RuntimeError, "inert admission boundary"):
                with confined.hold_confined_pi_launch_plan(object(), {},
                        profile=self.profile, grant={}, protected_root=Path("/var/lib/aragorn/admitted"),
                        runtime_conformance_digest=fixtures.digest(), deployment=pins,
                        revoked_context_ids=(), now_unix=1, deadline=20, config=self.config):
                    self.fail("guard yielded a plan")
            admission.assert_called_once()

    def test_fixed_empty_mountpoints_accept_without_mutating_manifest(self):
        manifest = {"files": [{"path": "usr/bin/env"}]}
        confined._require_empty_mountpoints(manifest, confined._EMPTY_MOUNTPOINTS)
        self.assertEqual(manifest, {"files": [{"path": "usr/bin/env"}]})

    def test_missing_mountpoint_refuses(self):
        for missing in confined._EMPTY_MOUNTPOINTS:
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "empty fixed mountpoint"):
                confined._require_empty_mountpoints({"files": []},
                    tuple(name for name in confined._EMPTY_MOUNTPOINTS if name != missing))

    def test_mountpoint_file_or_hidden_payload_refuses(self):
        for mountpoint in confined._EMPTY_MOUNTPOINTS:
            for path in (mountpoint, mountpoint + "/hidden"):
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "empty fixed mountpoint"):
                    confined._require_empty_mountpoints({"files": [{"path": path}]}, confined._EMPTY_MOUNTPOINTS)

    def test_mountpoint_descendant_directory_refuses(self):
        for mountpoint in confined._EMPTY_MOUNTPOINTS:
            with self.subTest(mountpoint=mountpoint), self.assertRaisesRegex(ValueError, "empty fixed mountpoint"):
                confined._require_empty_mountpoints({"files": []}, (*confined._EMPTY_MOUNTPOINTS, mountpoint + "/child"))


if __name__ == "__main__":
    unittest.main()
