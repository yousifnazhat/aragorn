from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

from aragorn import gvisor_backend_qualification as qualification
from aragorn import gvisor_runtime as runtime
from aragorn.cas import CAS
from aragorn.gvisor_backend_probe import HOST_SNAPSHOT_SCHEMA
from aragorn.oci_worker_protocol import canonical_json
from tests import test_gvisor_runtime as runtime_support


class GVisorBackendQualificationTests(unittest.TestCase):
    def test_exact_three_run_receipt_verifies_and_closes_over_every_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))

            raw, loaded = qualification.load_gvisor_backend_qualification_lock(
                fixture["lock_path"]
            )
            self.assertEqual(raw, canonical_json(fixture["lock"]))
            self.assertEqual(loaded, fixture["lock"])
            verified = qualification.verify_gvisor_backend_qualification(
                fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
            )
            self.assertEqual(verified, fixture["receipt"])
            closure = qualification.derive_gvisor_backend_qualification_closure(
                fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
            )
            self.assertEqual(set(closure), fixture["digests"])
            self.assertIn(fixture["lock"]["canary_lock_digest"], closure)
            self.assertIn(fixture["lock"]["daemon_config_digest"], closure)
            self.assertEqual(
                closure,
                {
                    digest: len(fixture["cas"].read(digest))
                    for digest in sorted(fixture["digests"])
                },
            )

            root = Path(__file__).parents[1]
            lock_schema = json.loads(
                (
                    root / "schema/gvisor-backend-qualification-lock-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            receipt_schema = json.loads(
                (
                    root / "schema/gvisor-backend-qualification-receipt-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                lock_schema["properties"]["controls"]["const"],
                qualification._CONTROL_IDS,
            )
            self.assertEqual(set(lock_schema["required"]), qualification._LOCK_FIELDS)
            self.assertEqual(
                receipt_schema["properties"]["authority"]["const"],
                qualification.RECEIPT_AUTHORITY,
            )

    def test_unknown_fields_and_repeated_ids_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            changed = copy.deepcopy(fixture["receipt"])
            changed["unknown"] = True
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "missing or unknown fields",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][1]["run_id"] = changed["runs"][0]["run_id"]
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "repeats a run or container ID",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

            changed_lock = fixture["lock"] | {"unknown": True}
            fixture["lock_path"].write_bytes(canonical_json(changed_lock))
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "missing or unknown fields",
            ):
                qualification.load_gvisor_backend_qualification_lock(
                    fixture["lock_path"]
                )

    def test_missing_control_digest_drift_and_failed_cleanup_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))

            controls = json.loads(fixture["cas"].read(fixture["control_digests"][0]))
            controls["controls"].pop()
            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][0]["control_evidence_digest"] = _put(fixture, controls)
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "control evidence is incomplete",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

            other_runtime = _put(fixture, b"other runtime lock")
            drifted_pins = fixture["pins"] | {
                "expected_runtime_lock_digest": other_runtime
            }
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "runtime lock digest drifted",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], fixture["receipt_digest"], **drifted_pins
                )

            cleanup = json.loads(fixture["cas"].read(fixture["cleanup_digests"][0]))
            cleanup["container_absent"] = False
            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][0]["cleanup_evidence_digest"] = _put(fixture, cleanup)
            digest = _put(fixture, changed)
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "cleanup did not complete",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], digest, **fixture["pins"]
                )

    def test_cas_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            digest = fixture["control_digests"][0]
            hexadecimal = digest.removeprefix("sha256:")
            blob = (
                fixture["cas"].root
                / "blobs"
                / "sha256"
                / hexadecimal[:2]
                / hexadecimal[2:]
            )
            blob.chmod(0o600)
            blob.write_bytes(b"{}")

            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "blob failed digest verification",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"],
                    fixture["receipt_digest"],
                    **fixture["pins"],
                )

    def test_asserted_control_cannot_override_probe_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            evidence = json.loads(fixture["cas"].read(fixture["control_digests"][0]))
            transcript = fixture["cas"].read(evidence["artifacts"]["probe_stdout"])
            changed_transcript = transcript.replace(
                b"tcp_loopback_match=1\n",
                b"tcp_loopback_match=0\n",
            )
            changed_digest = _put(fixture, changed_transcript)
            evidence["artifacts"]["probe_stdout"] = changed_digest
            changed = copy.deepcopy(fixture["receipt"])
            changed["runs"][0]["control_evidence_digest"] = _put(fixture, evidence)

            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "control failed: tcp-sink-positive-control",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], _put(fixture, changed), **fixture["pins"]
                )

    def test_forged_live_container_profile_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            live = json.loads(
                fixture["cas"].read(
                    fixture["artifact_digests"][0]["container_live_inspect"]
                )
            )
            live[0]["Config"]["User"] = "0:0"

            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "container configuration changed",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"],
                    _replace_artifact(fixture, "container_live_inspect", live),
                    **fixture["pins"],
                )

    def test_missing_implementation_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            source_digest = fixture["implementation_files"]["analyze.py"]
            _blob_path(fixture["cas"], source_digest).unlink()

            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "cannot verify gVisor backend qualification implementation",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"], fixture["receipt_digest"], **fixture["pins"]
                )

    def test_process_and_cleanup_artifact_tampering_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            processes = json.loads(
                fixture["cas"].read(
                    fixture["artifact_digests"][0]["container_processes"]
                )
            )
            processes["processes"][1]["pid"] += 1
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "process relationship changed",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"],
                    _replace_artifact(fixture, "container_processes", processes),
                    **fixture["pins"],
                )

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _fixture(Path(temporary))
            cleanup = json.loads(
                fixture["cas"].read(fixture["artifact_digests"][0]["container_cleanup"])
            )
            cleanup["absent"] = False
            with self.assertRaisesRegex(
                qualification.GVisorBackendQualificationError,
                "container cleanup observation changed",
            ):
                qualification.verify_gvisor_backend_qualification(
                    fixture["cas"],
                    _replace_artifact(fixture, "container_cleanup", cleanup),
                    **fixture["pins"],
                )

    def test_canary_runtime_argument_drift_fails_closed(self) -> None:
        for replacement in ([], ["--network=host"], ["--network=none"] * 2):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                fixture = _fixture(Path(temporary))
                processes = json.loads(
                    fixture["cas"].read(
                        fixture["artifact_digests"][0]["container_processes"]
                    )
                )
                argv = processes["processes"][1]["argv"]
                index = argv.index("--network=none")
                argv[index : index + 1] = replacement
                with self.assertRaisesRegex(
                    qualification.GVisorBackendQualificationError,
                    "runtime process identity changed",
                ):
                    qualification.verify_gvisor_backend_qualification(
                        fixture["cas"],
                        _replace_artifact(fixture, "container_processes", processes),
                        **fixture["pins"],
                    )

    def test_probe_setup_failures_do_not_count_as_denials(self) -> None:
        for original, replacement, error in (
            (b"tmpfs_chmod_rc=0\n", b"tmpfs_chmod_rc=1\n", "precondition"),
            (b"mount_rc=1\n", b"mount_rc=127\n", "did not execute"),
        ):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                fixture = _fixture(Path(temporary))
                evidence = json.loads(
                    fixture["cas"].read(fixture["control_digests"][0])
                )
                transcript = fixture["cas"].read(
                    evidence["artifacts"]["probe_stdout"]
                )
                evidence["artifacts"]["probe_stdout"] = _put(
                    fixture, transcript.replace(original, replacement)
                )
                receipt = copy.deepcopy(fixture["receipt"])
                receipt["runs"][0]["control_evidence_digest"] = _put(
                    fixture, evidence
                )
                with self.assertRaisesRegex(
                    qualification.GVisorBackendQualificationError, error
                ):
                    qualification.verify_gvisor_backend_qualification(
                        fixture["cas"], _put(fixture, receipt), **fixture["pins"]
                    )


def _fixture(root: Path) -> dict:
    cas = CAS(root / "cas")
    fixture = {"cas": cas, "digests": set()}
    runtime_raw = runtime.LOCK.read_bytes()
    runtime_lock = runtime._runtime_lock(runtime_raw)
    runtime_lock_digest = _put(fixture, runtime_raw)
    canary_raw = runtime.CANARY_LOCK.read_bytes()
    canary_lock = runtime._canary_lock(canary_raw)
    canary_lock_digest = _put(fixture, canary_raw)
    daemon_config_digest = _put(
        fixture,
        {
            "runtimes": {
                canary_lock["runtime"]["name"]: {
                    "path": canary_lock["runtime"]["path"],
                    "runtimeArgs": canary_lock["runtime"]["arguments"],
                }
            }
        },
    )
    probe_digest = _put(
        fixture,
        (
            Path(__file__).parents[1]
            / "benchmark/fixtures/gvisor-backend-qualification/probe-v1.sh"
        ).read_bytes(),
    )
    implementation_files = {
        module: _put(fixture, f"pinned qualification {module}\n".encode())
        for module in qualification.IMPLEMENTATION_MODULES
    }
    implementation_digest = _put(
        fixture,
        {
            "schema": qualification.IMPLEMENTATION_SCHEMA,
            "files": implementation_files,
        },
    )
    lock = {
        "schema": qualification.LOCK_SCHEMA,
        "authority": qualification.LOCK_AUTHORITY,
        "profile": qualification.PROFILE,
        "runs": 3,
        "runtime_lock_digest": runtime_lock_digest,
        "canary_lock_digest": canary_lock_digest,
        "daemon_config_digest": daemon_config_digest,
        "probe_digest": probe_digest,
        "controls": qualification._CONTROL_IDS,
    }
    lock_digest = _put(fixture, lock)
    lock_path = root / "qualification-lock.json"
    lock_path.write_bytes(canonical_json(lock))

    installed_binaries = [
        runtime_support._metadata(
            item["path"],
            item["digest"],
            inode=(
                10 if item["path"] == runtime_lock["runtime"]["path"] else 20 + index
            ),
        )
        for index, item in enumerate(runtime_lock["binaries"])
    ]
    shared_artifacts = {
        field: _put(fixture, raw)
        for field, raw in {
            "runtime_version": runtime_lock["runtime"]["version_output"].encode(),
            "installed_binaries": canonical_json(installed_binaries),
            "runtime_registration": canonical_json(
                {
                    "path": canary_lock["runtime"]["path"],
                    "runtimeArgs": canary_lock["runtime"]["arguments"],
                    "status": {},
                }
            ),
            "docker_executable": canonical_json(
                runtime_support._metadata(
                    "/usr/bin/docker", "sha256:" + "e" * 64, inode=30
                )
            ),
            "helper_implementations": canonical_json(
                [
                    {
                        "module": module,
                        "file": runtime_support._metadata(
                            f"/opt/aragorn/src/aragorn/{module}",
                            implementation_files[module],
                            inode=40 + index,
                        ),
                    }
                    for index, module in enumerate(qualification.HELPER_MODULES)
                ]
            ),
            "runner_identity_pre": runtime_support._runner(),
            "runner_identity_post": runtime_support._runner(),
            "image_inspect": canonical_json(
                [
                    {
                        "Id": runtime_lock["image"]["digest"],
                        "RepoDigests": [runtime_lock["image"]["repo_digest"]],
                        "Os": runtime_lock["image"]["os"],
                        "Architecture": runtime_lock["image"]["architecture"],
                    }
                ]
            ),
        }.items()
    }
    runs = []
    control_digests = []
    cleanup_digests = []
    artifact_digests = []
    for sequence in range(1, 4):
        run_id = f"{sequence:032x}"
        container_id = f"{sequence:064x}"
        run_request_digest = _put(
            fixture,
            {
                "schema": qualification.RUN_REQUEST_SCHEMA,
                "lock_digest": lock_digest,
                "runtime_lock_digest": runtime_lock_digest,
                "implementation_digest": implementation_digest,
                "probe_digest": probe_digest,
                "run_id": run_id,
            },
        )
        host_pid = 1000 + sequence
        probe_stdout = _probe_transcript(run_id, host_pid)
        probe_stdout_digest = _put(fixture, probe_stdout)
        host_snapshot_digest = _put(fixture, _host_snapshot(run_id, host_pid))
        profile = qualification._qualification_profile(canary_lock, run_id, host_pid)
        source = f"/run/aragorn-gvisor-qualification-{run_id}-fixture"
        artifacts = dict(shared_artifacts)
        artifacts.update(
            {
                "container_cleanup": _put(
                    fixture,
                    {
                        "schema": runtime.CANARY_CLEANUP_SCHEMA,
                        "container_id": container_id,
                        "absent": True,
                    },
                ),
                "container_live_inspect": _put(
                    fixture,
                    _qualification_container(
                        runtime_lock,
                        canary_lock,
                        profile,
                        run_id,
                        container_id,
                        source,
                        "live",
                    ),
                ),
                "container_post_inspect": _put(
                    fixture,
                    _qualification_container(
                        runtime_lock,
                        canary_lock,
                        profile,
                        run_id,
                        container_id,
                        source,
                        "postrun",
                    ),
                ),
                "container_pre_inspect": _put(
                    fixture,
                    _qualification_container(
                        runtime_lock,
                        canary_lock,
                        profile,
                        run_id,
                        container_id,
                        source,
                        "prestart",
                    ),
                ),
                "container_processes": _put(
                    fixture,
                    _qualification_processes(
                        runtime_lock, canary_lock, container_id
                    ),
                ),
                "host_sentinel_post": host_snapshot_digest,
                "host_sentinel_pre": host_snapshot_digest,
                "probe_stderr": _put(fixture, b""),
                "probe_stdout": probe_stdout_digest,
            }
        )
        if set(artifacts) != qualification._ARTIFACT_FIELDS:
            raise AssertionError("test artifact inventory drifted")
        controls = [
            {
                "control_id": control_id,
                "observed": copy.deepcopy(expected),
            }
            for control_id, expected in qualification._CONTROL_EXPECTATIONS
        ]
        control_digest = _put(
            fixture,
            {
                "schema": qualification.CONTROL_EVIDENCE_SCHEMA,
                "lock_digest": lock_digest,
                "runtime_lock_digest": runtime_lock_digest,
                "probe_digest": probe_digest,
                "run_id": run_id,
                "container_id": container_id,
                "controls": controls,
                "artifacts": artifacts,
            },
        )
        cleanup_digest = _put(
            fixture,
            {
                "schema": qualification.CLEANUP_EVIDENCE_SCHEMA,
                "lock_digest": lock_digest,
                "run_id": run_id,
                "container_id": container_id,
                "container_absent": True,
                "trace_files_absent": True,
                "host_sentinels_unchanged": True,
                "sinks_closed": True,
            },
        )
        control_digests.append(control_digest)
        cleanup_digests.append(cleanup_digest)
        artifact_digests.append(artifacts)
        runs.append(
            {
                "run_id": run_id,
                "container_id": container_id,
                "run_request_digest": run_request_digest,
                "control_evidence_digest": control_digest,
                "cleanup_evidence_digest": cleanup_digest,
            }
        )
    receipt = {
        "schema": qualification.RECEIPT_SCHEMA,
        "authority": qualification.RECEIPT_AUTHORITY,
        "profile": qualification.PROFILE,
        "status": "PASS",
        "lock_digest": lock_digest,
        "runtime_lock_digest": runtime_lock_digest,
        "probe_digest": probe_digest,
        "implementation_digest": implementation_digest,
        "runs": runs,
    }
    receipt_digest = _put(fixture, receipt)
    fixture.update(
        {
            "lock": lock,
            "lock_path": lock_path,
            "receipt": receipt,
            "receipt_digest": receipt_digest,
            "control_digests": control_digests,
            "cleanup_digests": cleanup_digests,
            "artifact_digests": artifact_digests,
            "implementation_files": implementation_files,
            "pins": {
                "expected_lock_digest": lock_digest,
                "expected_runtime_lock_digest": runtime_lock_digest,
                "expected_implementation_digest": implementation_digest,
            },
        }
    )
    return fixture


def _qualification_container(
    runtime_lock: dict,
    canary_lock: dict,
    profile: dict,
    run_id: str,
    container_id: str,
    source: str,
    phase: str,
) -> list[dict]:
    container = runtime_support._container(runtime_lock, phase)
    container["Id"] = container_id
    container["Path"] = profile["command"][0]
    container["Args"] = profile["command"][1:]
    container["Config"].update(
        {
            "Cmd": profile["command"],
            "User": profile["user"],
            "Env": profile["environment"],
            "Labels": {qualification._RUN_LABEL: run_id},
        }
    )
    container["HostConfig"].update(
        {
            "Runtime": canary_lock["runtime"]["name"],
            "NetworkMode": profile["network_mode"],
            "ReadonlyRootfs": profile["read_only"],
            "CapDrop": profile["cap_drop"],
            "SecurityOpt": profile["security_opt"],
            "PidsLimit": profile["pids_limit"],
            "Memory": profile["memory_bytes"],
            "MemorySwap": profile["memory_swap_bytes"],
            "NanoCpus": profile["nano_cpus"],
            "Ulimits": [
                {
                    "Name": "nofile",
                    "Hard": profile["nofile_hard"],
                    "Soft": profile["nofile_soft"],
                }
            ],
            "Tmpfs": {profile["tmpfs"]["destination"]: profile["tmpfs"]["options"]},
            "Mounts": [
                {
                    "Type": "bind",
                    "Source": source,
                    "Target": qualification._MOUNT_DESTINATION,
                    "ReadOnly": True,
                }
            ],
        }
    )
    container["Mounts"] = [
        {
            "Type": "bind",
            "Source": source,
            "Destination": qualification._MOUNT_DESTINATION,
            "Mode": "ro",
            "RW": False,
            "Propagation": "rprivate",
        }
    ]
    return [container]


def _qualification_processes(
    runtime_lock: dict, canary_lock: dict, container_id: str
) -> dict:
    processes = json.loads(runtime_support._processes(runtime_lock))
    for process in processes["processes"]:
        if process["role"] in {"gofer", "sandbox"}:
            process["argv"][1:3] = canary_lock["runtime"]["arguments"]
        process["argv"] = [
            container_id if value == runtime_support._CONTAINER_ID else value
            for value in process["argv"]
        ]
    return processes


def _replace_artifact(fixture: dict, field: str, value: object) -> str:
    evidence = json.loads(fixture["cas"].read(fixture["control_digests"][0]))
    evidence["artifacts"][field] = _put(fixture, value)
    receipt = copy.deepcopy(fixture["receipt"])
    receipt["runs"][0]["control_evidence_digest"] = _put(fixture, evidence)
    return _put(fixture, receipt)


def _blob_path(cas: CAS, digest: str) -> Path:
    hexadecimal = digest.removeprefix("sha256:")
    return cas.root / "blobs" / "sha256" / hexadecimal[:2] / hexadecimal[2:]


def _put(fixture: dict, value: object) -> str:
    raw = value if isinstance(value, bytes) else canonical_json(value)
    digest = fixture["cas"].put(BytesIO(raw), max_bytes=2 * 1024 * 1024)
    fixture["digests"].add(digest)
    return digest


def _probe_transcript(run_id: str, host_pid: int) -> bytes:
    fields = (
        "schema=aragorn/gvisor-backend-qualification-probe-transcript/v1",
        f"run_id={run_id}",
        f"host_pid={host_pid}",
        "uid=65534",
        "gid=65534",
        "supplementary_gids=",
        "no_new_privileges=1",
        "cap_inheritable=0000000000000000",
        "cap_permitted=0000000000000000",
        "cap_effective=0000000000000000",
        "cap_bounding=0000000000000000",
        "cap_ambient=0000000000000000",
        "tmpfs_write_rc=0",
        "tmpfs_read_match=1",
        "tmpfs_removed=1",
        "tcp_loopback_send_rc=0",
        "tcp_loopback_listener_rc=0",
        "tcp_loopback_match=1",
        "udp_loopback_send_rc=0",
        "udp_loopback_listener_rc=143",
        "udp_loopback_match=1",
        "host_file_visible=0",
        "host_process_visible=0",
        "non_loopback_interfaces=0",
        "ipv4_routes=0",
        "tcp_egress_send_rc=1",
        "udp_egress_send_rc=1",
        "rootfs_write_rc=1",
        "rootfs_artifact_present=0",
        "input_read_match=1",
        "input_write_rc=1",
        "input_rename_rc=1",
        "input_unlink_rc=1",
        "input_post_match=1",
        "tmpfs_script_write_rc=0",
        "tmpfs_chmod_rc=0",
        "tmpfs_exec_rc=126",
        "mount_rc=1",
        "unshare_rc=1",
        "mknod_rc=1",
        "setuid_rc=1",
        "setgid_rc=1",
    )
    return ("\n".join(fields) + "\n").encode("ascii")


def _host_snapshot(run_id: str, host_pid: int) -> dict[str, object]:
    return {
        "schema": HOST_SNAPSHOT_SCHEMA,
        "run_id": run_id,
        "host_file_digest": _raw_digest(f"Aragorn-host-file-{run_id}"),
        "input_digest": _raw_digest(f"Aragorn-input-{run_id}"),
        "process_id": host_pid,
        "process_start_ticks": host_pid + 1000,
        "process_marker_digest": _raw_digest(f"Aragorn-host-process-{run_id}"),
    }


def _raw_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('ascii')).hexdigest()}"


if __name__ == "__main__":
    unittest.main()
