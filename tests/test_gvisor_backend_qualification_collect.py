from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aragorn import gvisor_backend_qualification_collect as collector
from aragorn.cas import CAS
from aragorn.gvisor_backend_qualification import (
    _ARTIFACT_FIELDS,
    _CONTROL_EXPECTATIONS,
    _PROFILE_FIELDS,
    CLEANUP_EVIDENCE_SCHEMA,
    CONTROL_EVIDENCE_SCHEMA,
    RUN_REQUEST_SCHEMA,
)


class GVisorBackendQualificationCollectorTests(unittest.TestCase):
    def test_profile_is_the_single_read_only_probe_mount_envelope(self) -> None:
        run_id = "1" * 32
        canary_lock = collector._canary_lock(collector.CANARY_LOCK.read_bytes())
        profile = collector._qualification_profile(canary_lock, run_id, 4321)

        self.assertEqual(
            profile["command"],
            ["/bin/sh", "/aragorn-qualification/probe-v1.sh"],
        )
        self.assertEqual(
            profile["environment"],
            [
                "PATH=/bin",
                f"ARAGORN_RUN_ID={run_id}",
                "ARAGORN_HOST_PID=4321",
            ],
        )
        self.assertEqual(profile["network_mode"], "none")
        self.assertTrue(profile["read_only"])
        self.assertEqual(profile["cap_drop"], ["ALL"])
        self.assertEqual(profile["security_opt"], ["no-new-privileges=true"])
        for field in _PROFILE_FIELDS:
            self.assertEqual(profile[field], canary_lock["canary"][field])
        self.assertEqual(
            profile["tmpfs"],
            {
                "destination": "/tmp",
                "options": "rw,noexec,nosuid,nodev,size=1048576",
            },
        )
        probe = collector.PROBE.read_text(encoding="ascii")
        self.assertIn("input_path=/aragorn-qualification/input\n", probe)

    def test_fresh_run_ids_are_unique_sorted_and_retry_collisions(self) -> None:
        values = ["2" * 32, "2" * 32, "3" * 32, "1" * 32]
        with mock.patch.object(collector.secrets, "token_hex", side_effect=values):
            self.assertEqual(
                collector._fresh_run_ids(),
                ("1" * 32, "2" * 32, "3" * 32),
            )

    def test_retain_run_binds_every_artifact_and_cleanup_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            run_id = "1" * 32
            container_id = "2" * 64
            shared = {
                "runner_identity_post": b"runner-post",
                "runner_identity_pre": b"runner-pre",
                "runtime_registration": b"runtime-registration",
            }
            per_run = {
                field: f"{run_id}:{field}".encode("ascii")
                for field in _ARTIFACT_FIELDS - set(shared)
            }
            per_run["probe_stdout"] = b"probe-transcript"
            capture = collector._RunCapture(
                run_id=run_id,
                container_id=container_id,
                controls=[
                    {"control_id": control_id, "observed": expected}
                    for control_id, expected in _CONTROL_EXPECTATIONS
                ],
                artifacts=per_run,
            )
            pins = {
                "lock_digest": f"sha256:{'a' * 64}",
                "runtime_lock_digest": f"sha256:{'b' * 64}",
                "implementation_digest": f"sha256:{'c' * 64}",
                "probe_digest": f"sha256:{'d' * 64}",
            }

            retained = collector._retain_run(
                cas, capture, shared_artifacts=shared, **pins
            )
            request = json.loads(cas.read(retained["run_request_digest"]))
            controls = json.loads(cas.read(retained["control_evidence_digest"]))
            cleanup = json.loads(cas.read(retained["cleanup_evidence_digest"]))

            self.assertEqual(request["schema"], RUN_REQUEST_SCHEMA)
            self.assertEqual(request["run_id"], run_id)
            self.assertEqual(controls["schema"], CONTROL_EVIDENCE_SCHEMA)
            self.assertEqual(set(controls["artifacts"]), _ARTIFACT_FIELDS)
            self.assertIn("container_cleanup", controls["artifacts"])
            self.assertIn("container_processes", controls["artifacts"])
            self.assertEqual(
                cleanup,
                {
                    "schema": CLEANUP_EVIDENCE_SCHEMA,
                    "lock_digest": pins["lock_digest"],
                    "run_id": run_id,
                    "container_id": container_id,
                    "container_absent": True,
                    "trace_files_absent": True,
                    "host_sentinels_unchanged": True,
                    "sinks_closed": True,
                },
            )

    def test_coordination_lock_rejects_conflict_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "qualification.lock"
            descriptor = collector._open_coordination_lock(path)
            try:
                with self.assertRaisesRegex(
                    collector.GVisorBackendQualificationCollectionError,
                    "another gVisor capture is active",
                ):
                    collector._open_coordination_lock(path)
            finally:
                collector.os.close(descriptor)

            target = root / "target"
            target.write_bytes(b"")
            target.chmod(0o600)
            symlink = root / "symlink.lock"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(
                collector.GVisorBackendQualificationCollectionError,
                "cannot open gVisor coordination lock",
            ):
                collector._open_coordination_lock(symlink)

    def test_non_linux_or_non_root_fails_before_collection(self) -> None:
        with (
            mock.patch.object(collector.sys, "platform", "darwin"),
            mock.patch.object(collector.os, "geteuid", return_value=0),
            self.assertRaisesRegex(
                collector.GVisorBackendQualificationCollectionError,
                "requires Linux root",
            ),
        ):
            collector._require_collector_host()
        with (
            mock.patch.object(collector.sys, "platform", "linux"),
            mock.patch.object(collector.os, "geteuid", return_value=501),
            self.assertRaisesRegex(
                collector.GVisorBackendQualificationCollectionError,
                "requires Linux root",
            ),
        ):
            collector._require_collector_host()

    def test_process_identity_allows_dynamic_stat_fields_only(self) -> None:
        process_id = 4321
        marker = f"Aragorn-host-process-{'1' * 32}"

        def process_stat(state: str, start_ticks: int, user_ticks: int) -> bytes:
            fields = [state, *("0" for _ in range(10)), str(user_ticks)]
            fields.extend("0" for _ in range(7))
            fields.append(str(start_ticks))
            return (
                f"{process_id} (sleep) ".encode("ascii")
                + " ".join(fields).encode("ascii")
            )

        before = process_stat("R", 987654, 1)
        after = process_stat("S", 987654, 2)
        cmdline = f"{marker}\0{30}\0".encode("ascii")
        with mock.patch.object(
            collector.Path,
            "read_bytes",
            side_effect=(before, cmdline, after),
        ):
            self.assertEqual(collector._process_identity(process_id, marker), 987654)

        replaced = process_stat("S", 987655, 2)
        with (
            mock.patch.object(
                collector.Path,
                "read_bytes",
                side_effect=(before, cmdline, replaced),
            ),
            self.assertRaisesRegex(
                collector.GVisorBackendQualificationCollectionError,
                "process identity changed",
            ),
        ):
            collector._process_identity(process_id, marker)


if __name__ == "__main__":
    unittest.main()
