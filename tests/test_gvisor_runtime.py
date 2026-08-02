from __future__ import annotations

import copy
import hashlib
import json
import tarfile
import tempfile
import unittest
from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
from unittest import mock

from aragorn import gvisor_runtime as runtime
from aragorn.benchmark_handoff_v2 import (
    build_handoff_manifest,
    import_declared_byte_transport,
)
from aragorn.cas import CAS
from aragorn.oci_worker_protocol import canonical_json
from tests import test_docker_identity as identity_support

_CONTAINER_ID = "a" * 64
_RUN_ID = "c" * 32
_CAPTURED_AT = "2026-08-02T17:00:00Z"
_IMPLEMENTATION_SOURCES = {
    module: f"pinned {module}\n".encode() for module in runtime._IMPLEMENTATION_MODULES
}
_IMPLEMENTATION_FILES = {
    module: "sha256:" + hashlib.sha256(raw).hexdigest()
    for module, raw in _IMPLEMENTATION_SOURCES.items()
}
_IMPLEMENTATION_MANIFEST = canonical_json(
    {
        "schema": runtime.IMPLEMENTATION_SCHEMA,
        "files": _IMPLEMENTATION_FILES,
    }
)
_IMPLEMENTATION_DIGEST = (
    "sha256:" + hashlib.sha256(_IMPLEMENTATION_MANIFEST).hexdigest()
)
_LIVE_RECEIPT_DIGEST = (
    "sha256:1a26267fdaeee1ad458db98c88733e5b210460daa3d31fb143dc85fc39492d29"
)
_LIVE_HANDOFF_DIGEST = (
    "sha256:125898f127d08f7afa36f4ff63dcdb75bf99b7a6deda63765923436eb6f5baf3"
)
_LIVE_CANARY_RECEIPT_DIGEST = (
    "sha256:8e520d91b4782e806e7e28a5892e90f1be41dc5785d09cecb699dc42c0d040d0"
)
_LIVE_CANARY_HANDOFF_DIGEST = (
    "sha256:8053b7d191f9ad779de8b3b52060860af6fd2ff423fed058eed2e282a536e6f4"
)
_LIVE_CANARY_IMPLEMENTATION_DIGEST = (
    "sha256:bb60beb32bb620b1025dcdf5fdc874819d4e08b894285b79e1e883846f8bc79d"
)
_LIVE_CANARY_LOCK_DIGEST = (
    "sha256:70556d2b8ae0d30f199f5bd6d7df2c1df11071a9b61120954f9b76f6870839ed"
)
_LIVE_CANARY_ARCHIVE_SHA256 = (
    "abc8bd333047ab02511cba63ae06e08e90a627d8665fb6994bebeac582bf5bf9"
)
_LIVE_CANARY_RUN_ID = "7838a22fbd2de49b6f833443ca60f45e"


def _canary_trace(
    container_id: str = _CONTAINER_ID,
    *,
    artifact: bool = False,
) -> bytes:
    _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
    _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
    profile = (
        runtime._artifact_profile(canary_lock) if artifact else canary_lock["canary"]
    )
    command = profile["command"]
    go_command = ", ".join(json.dumps(value) for value in command)
    environment = json.dumps(
        [
            f"HOSTNAME={container_id[:12]}",
            "SHLVL=1",
            "HOME=/home",
            "PATH=/bin",
            "PWD=/",
        ],
        separators=(", ", ": "),
    )
    target = runtime._ARTIFACT_TARGET if artifact else profile["token_path"]
    execute = (
        f'0xbbb /bin/sha256sum, 0xccc ["/bin/sha256sum", "{target}"], '
        f"0xddd {environment}"
    )
    read = f"AT_FDCWD /, 0xeee {target}, O_RDONLY|0x0, 0o0"
    syscalls = []
    if not artifact:
        write = f"AT_FDCWD /, 0xaaa {target}, O_WRONLY|O_CREAT|O_TRUNC, 0o666"
        syscalls.extend(
            (
                f"strace.go:570] [   1:   1] sh E openat({write})",
                f"strace.go:608] [   1:   1] sh X openat({write}) = 3 (0x3) (2.1µs)",
            )
        )
    syscalls.extend(
        (
            f"strace.go:567] [   2:   2] sh E execve({execute})",
            f"strace.go:605] [   2:   2] sh X execve({execute}) = 0 (0x0) (3µs)",
            f"strace.go:570] [   2:   2] sha256sum E openat({read})",
            f"strace.go:608] [   2:   2] sha256sum X openat({read}) = 3 (0x3) (2.6µs)",
        )
    )
    messages = [
        (
            "cli.go:276] Version release-"
            f"{runtime_lock['release']['version']}, go1.test, arm64, 2 CPUs, linux, "
            "PID 1, PPID 0, UID 65534, GID 65534"
        ),
        (
            "cli.go:278] Args: [runsc-sandbox --network=none boot "
            f"--bundle=/runtime/{container_id} {container_id}]"
        ),
        "config.go:533] Platform: systrap",
        "config.go:535] FileAccess: exclusive / Directfs: false / Overlay: root:self",
        "config.go:536] Network: none",
        (
            "config.go:539] Debug: true. Strace: true, max size: 256, "
            "syscalls: openat,execve"
        ),
        f"kernel.go:1293] EXEC: []string{{{go_command}}}",
        *syscalls,
        "cli.go:316] Exiting with status: 0",
    ]
    return b"".join(
        json.dumps(
            {
                "msg": message,
                "level": "info",
                "time": "2026-08-02T14:00:00.000001-04:00",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
        for message in messages
    )


_LIVE_IMPLEMENTATION_DIGEST = (
    "sha256:92594d82e743616019846bcb5af94def01cb7637f967722efa8422ed50e9178c"
)
_LIVE_LOCK_DIGEST = (
    "sha256:f56bfc3e06e26e682c609d51811edf341d3f688b67f13104883265f515efe602"
)


def _json(value: object, *, indent: int | None = None) -> bytes:
    return json.dumps(
        value, indent=indent, separators=None if indent else (",", ":")
    ).encode()


def _metadata(path: str, digest: str, *, inode: int) -> dict[str, object]:
    return {
        "path": path,
        "digest": digest,
        "device": 1,
        "inode": inode,
        "mode": 0o755,
        "uid": 0,
        "gid": 0,
        "size": 1024,
        "mtime_ns": 1,
        "ctime_ns": 1,
    }


def _daemon() -> bytes:
    return _json(
        {
            "exec-opts": ["native.cgroupdriver=cgroupfs"],
            "features": {"buildkit": True, "containerd-snapshotter": True},
            "runtimes": {
                "runsc-systrap": {
                    "path": "/usr/local/bin/runsc",
                    "runtimeArgs": ["--platform=systrap", "--directfs=false"],
                }
            },
        },
        indent=4,
    )


def _container(lock: dict[str, object], phase: str) -> dict[str, object]:
    image = lock["image"]
    smoke = lock["smoke"]
    assert isinstance(image, dict) and isinstance(smoke, dict)
    state = {
        "prestart": {
            "Status": "created",
            "Running": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "Error": "",
        },
        "live": {
            "Status": "running",
            "Running": True,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 44,
            "ExitCode": 0,
            "Error": "",
        },
        "postrun": {
            "Status": "exited",
            "Running": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "Error": "",
        },
    }[phase]
    return {
        "Id": _CONTAINER_ID,
        "Created": "2026-08-02T16:42:38Z",
        "Image": image["digest"],
        "Path": smoke["command"][0],
        "Args": smoke["command"][1:],
        "Platform": "linux",
        "ImageManifestDescriptor": {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": image["digest"],
            "platform": {
                "architecture": image["architecture"],
                "os": image["os"],
                "variant": image["variant"],
            },
        },
        "Config": {
            "Image": image["reference"],
            "Cmd": smoke["command"],
            "User": smoke["user"],
            "Env": smoke["environment"],
            "Volumes": None,
            "Entrypoint": None,
            "Labels": {"aragorn.runtime-smoke.run_id": _RUN_ID},
        },
        "HostConfig": {
            "Runtime": "runsc-systrap",
            "NetworkMode": smoke["network_mode"],
            "ReadonlyRootfs": smoke["read_only"],
            "CapDrop": smoke["cap_drop"],
            "SecurityOpt": smoke["security_opt"],
            "PidsLimit": smoke["pids_limit"],
            "Memory": smoke["memory_bytes"],
            "MemorySwap": smoke["memory_swap_bytes"],
            "NanoCpus": smoke["nano_cpus"],
            "Ulimits": [
                {
                    "Name": "nofile",
                    "Hard": smoke["nofile_hard"],
                    "Soft": smoke["nofile_soft"],
                }
            ],
            "Privileged": False,
            "CapAdd": None,
            "Devices": [],
            "DeviceRequests": None,
            "PublishAllPorts": False,
            "PortBindings": {},
            "Binds": None,
            "VolumesFrom": None,
            "Links": None,
            "ExtraHosts": None,
            "Dns": None,
            "DnsOptions": [],
            "DnsSearch": [],
            "GroupAdd": None,
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "PidMode": "",
            "UTSMode": "",
            "UsernsMode": "",
        },
        "Mounts": [],
        "NetworkSettings": {"Ports": {}, "Networks": {"none": {}}},
        "State": state,
    }


def _artifact_container(
    runtime_lock: dict[str, object],
    canary_lock: dict[str, object],
    phase: str,
    source: str,
) -> dict[str, object]:
    container = _container(runtime_lock, phase)
    profile = runtime._artifact_profile(canary_lock)
    container["Path"] = profile["command"][0]
    container["Args"] = profile["command"][1:]
    config = container["Config"]
    host = container["HostConfig"]
    assert isinstance(config, dict) and isinstance(host, dict)
    config["Cmd"] = profile["command"]
    config["User"] = profile["user"]
    config["Env"] = profile["environment"]
    config["Labels"] = {"aragorn.acquired-artifact.run_id": _RUN_ID}
    host.update(
        {
            "Runtime": "runsc-systrap-canary",
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
                    "Target": runtime._ARTIFACT_TARGET,
                    "ReadOnly": True,
                }
            ],
        }
    )
    container["Mounts"] = [
        {
            "Type": "bind",
            "Source": source,
            "Destination": runtime._ARTIFACT_TARGET,
            "Mode": "ro",
            "RW": False,
            "Propagation": "rprivate",
        }
    ]
    return container


def _runner() -> bytes:
    return canonical_json(
        {
            "context": identity_support.context("unix:///var/run/docker.sock"),
            "version": identity_support.version(),
            "info": identity_support.info(),
        }
    )


def _processes(lock: dict[str, object]) -> bytes:
    binaries = lock["binaries"]
    assert isinstance(binaries, list)
    runsc_digest = next(
        item["digest"] for item in binaries if item["path"] == "/usr/local/bin/runsc"
    )
    runsc = _metadata("/usr/local/bin/runsc", runsc_digest, inode=10)
    shim = _metadata("/usr/bin/containerd-shim-runc-v2", "sha256:" + "d" * 64, inode=11)
    return canonical_json(
        {
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "processes": [
                {
                    "role": "gofer",
                    "pid": 40,
                    "ppid": 30,
                    "starttime": 100,
                    "uids": [0, 0, 0, 0],
                    "gids": [0, 0, 0, 0],
                    "argv": [
                        "runsc-gofer",
                        "--platform=systrap",
                        "--directfs=false",
                        "gofer",
                        _CONTAINER_ID,
                    ],
                    "exe": runsc,
                },
                {
                    "role": "sandbox",
                    "pid": 44,
                    "ppid": 30,
                    "starttime": 101,
                    "uids": [65534, 65534, 65534, 65534],
                    "gids": [65534, 65534, 65534, 65534],
                    "argv": [
                        "runsc-sandbox",
                        "--platform=systrap",
                        "--directfs=false",
                        "boot",
                        _CONTAINER_ID,
                    ],
                    "exe": runsc,
                },
                {
                    "role": "shim",
                    "pid": 30,
                    "ppid": 1,
                    "starttime": 99,
                    "uids": [0, 0, 0, 0],
                    "gids": [0, 0, 0, 0],
                    "argv": [
                        "/usr/bin/containerd-shim-runc-v2",
                        "-namespace",
                        "moby",
                        "-id",
                        _CONTAINER_ID,
                    ],
                    "exe": shim,
                },
            ],
        }
    )


def _evidence(lock: dict[str, object]) -> dict[str, bytes]:
    image = lock["image"]
    binaries = lock["binaries"]
    runtime_lock = lock["runtime"]
    assert isinstance(image, dict)
    assert isinstance(binaries, list)
    assert isinstance(runtime_lock, dict)
    return {
        "runtime_version": runtime_lock["version_output"].encode(),
        "installed_binaries": canonical_json(
            [
                _metadata(
                    item["path"],
                    item["digest"],
                    inode=10 if item["path"] == runtime_lock["path"] else index + 1,
                )
                for index, item in enumerate(binaries)
            ]
        ),
        "daemon_config": _daemon(),
        "runtime_registration": _json(
            {
                "path": runtime_lock["path"],
                "runtimeArgs": runtime_lock["arguments"],
                "status": {},
            }
        ),
        "docker_executable": canonical_json(
            _metadata("/usr/bin/docker", "sha256:" + "e" * 64, inode=20)
        ),
        "helper_implementations": canonical_json(
            [
                {
                    "module": module,
                    "file": _metadata(
                        f"/opt/aragorn/src/aragorn/{module}",
                        _IMPLEMENTATION_FILES[module],
                        inode=30 + index,
                    ),
                }
                for index, module in enumerate(runtime._HELPER_MODULES, start=1)
            ]
        ),
        "runner_pre": _runner(),
        "runner_post": _runner(),
        "image_inspect": _json(
            [
                {
                    "Id": image["digest"],
                    "RepoDigests": [image["repo_digest"]],
                    "Os": image["os"],
                    "Architecture": image["architecture"],
                }
            ]
        ),
        "container_pre_inspect": _json([_container(lock, "prestart")]),
        "container_live_inspect": _json([_container(lock, "live")]),
        "container_processes": _processes(lock),
        "container_stdout": b"",
        "container_stderr": b"",
        "container_post_inspect": _json([_container(lock, "postrun")]),
    }


def _put_fixture_receipt(
    cas: CAS,
    evidence: dict[str, bytes],
    *,
    lock_raw: bytes,
    run_id: str = _RUN_ID,
    captured_at: str = _CAPTURED_AT,
) -> str:
    lock = runtime._runtime_lock(lock_raw)
    runtime._verify_evidence(
        lock,
        evidence,
        run_id=run_id,
        implementation_files=_IMPLEMENTATION_FILES,
    )
    implementation_digest = cas.put(
        BytesIO(_IMPLEMENTATION_MANIFEST),
        max_bytes=runtime._MAX_IMPLEMENTATION_MANIFEST_BYTES,
    )
    for module, raw in _IMPLEMENTATION_SOURCES.items():
        cas.put_expected(
            BytesIO(raw),
            expected_digest=_IMPLEMENTATION_FILES[module],
            max_bytes=runtime._MAX_IMPLEMENTATION_SOURCE_BYTES,
        )
    lock_digest = cas.put(BytesIO(lock_raw), max_bytes=runtime._MAX_LOCK_BYTES)
    evidence_digests = {
        name: cas.put(BytesIO(raw), max_bytes=runtime._EVIDENCE_LIMITS[name])
        for name, raw in sorted(evidence.items())
    }
    return cas.put(
        BytesIO(
            canonical_json(
                {
                    "schema": runtime.SCHEMA,
                    "authority": runtime.AUTHORITY,
                    "lock_digest": lock_digest,
                    "implementation_digest": implementation_digest,
                    "run_id": run_id,
                    "captured_at": captured_at,
                    "evidence": evidence_digests,
                    "status": "PASS",
                }
            )
        ),
        max_bytes=runtime._MAX_RECEIPT_BYTES,
    )


class GVisorRuntimeTests(unittest.TestCase):
    def test_checked_in_live_smoke_closure_imports_and_replays(self) -> None:
        root = Path(__file__).parents[1]
        archive = (
            root
            / "benchmark"
            / "evidence"
            / "phase2-gvisor-runtime-smoke-b86096ddeed564a5938ae9dc1819c7a8-2026-08-02.tar.gz"
        )
        checked_in_receipt = (
            root
            / "benchmark"
            / "receipts"
            / "phase2-gvisor-runtime-smoke-b86096ddeed564a5938ae9dc1819c7a8-2026-08-02.json"
        ).read_bytes()
        self.assertEqual(
            "9c05312c54e098556ed37dc4bb9f907ae7059d7937ef9fae458ec38f39045e6d",
            hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            handoff = Path(temporary) / "handoff"
            handoff.mkdir(mode=0o700)
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(handoff, filter="data")
            cas = CAS(Path(temporary) / "cas")
            import_declared_byte_transport(
                handoff,
                cas,
                expected_manifest_digest=_LIVE_HANDOFF_DIGEST,
                expected_kind="runtime_evidence",
                expected_root_digest=_LIVE_RECEIPT_DIGEST,
            )
            receipt = runtime.verify_gvisor_runtime_smoke(
                cas,
                _LIVE_RECEIPT_DIGEST,
                expected_lock_digest=_LIVE_LOCK_DIGEST,
                expected_verifier_implementation_digest=(_LIVE_IMPLEMENTATION_DIGEST),
            )
            self.assertEqual(cas.read(_LIVE_RECEIPT_DIGEST), checked_in_receipt)
            self.assertEqual(receipt["run_id"], "b86096ddeed564a5938ae9dc1819c7a8")

    def test_checked_in_live_canary_closure_imports_and_replays(self) -> None:
        root = Path(__file__).parents[1]
        stem = f"phase2-gvisor-detonation-canary-{_LIVE_CANARY_RUN_ID}-2026-08-02"
        archive = root / "benchmark" / "evidence" / f"{stem}.tar.gz"
        checked_in_receipt = (
            root / "benchmark" / "receipts" / f"{stem}.json"
        ).read_bytes()
        self.assertEqual(
            _LIVE_CANARY_ARCHIVE_SHA256,
            hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as temporary:
            handoff = Path(temporary) / "handoff"
            handoff.mkdir(mode=0o700)
            with tarfile.open(archive, "r:gz") as bundle:
                bundle.extractall(handoff, filter="data")
            cas = CAS(Path(temporary) / "cas")
            imported = import_declared_byte_transport(
                handoff,
                cas,
                expected_manifest_digest=_LIVE_CANARY_HANDOFF_DIGEST,
                expected_kind="runtime_evidence",
                expected_root_digest=_LIVE_CANARY_RECEIPT_DIGEST,
            )
            closure = runtime.derive_gvisor_detonation_canary_closure(
                cas,
                _LIVE_CANARY_RECEIPT_DIGEST,
                expected_lock_digest=_LIVE_CANARY_LOCK_DIGEST,
                expected_verifier_implementation_digest=(
                    _LIVE_CANARY_IMPLEMENTATION_DIGEST
                ),
            )
            self.assertEqual(
                {item["digest"]: item["size"] for item in imported["blobs"]},
                closure,
            )
            self.assertEqual(cas.read(_LIVE_CANARY_RECEIPT_DIGEST), checked_in_receipt)
            receipt = json.loads(checked_in_receipt)
            self.assertEqual(receipt["run_id"], _LIVE_CANARY_RUN_ID)
            self.assertEqual(receipt["status"], "RECORDED")

    def test_runtime_path_smoke_replays_and_fails_closed_on_drift(self) -> None:
        lock_raw, lock = runtime.load_gvisor_runtime_lock()
        evidence = _evidence(lock)
        self.assertEqual(
            "sha256:" + hashlib.sha256(evidence["daemon_config"]).hexdigest(),
            lock["daemon_config_digest"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cas"
            cas = CAS(root)
            receipt_digest = _put_fixture_receipt(
                cas,
                evidence,
                lock_raw=lock_raw,
            )
            lock_digest = "sha256:" + hashlib.sha256(lock_raw).hexdigest()
            receipt = runtime.verify_gvisor_runtime_smoke(
                cas,
                receipt_digest,
                expected_lock_digest=lock_digest,
                expected_verifier_implementation_digest=_IMPLEMENTATION_DIGEST,
            )
            self.assertEqual(receipt["authority"], runtime.AUTHORITY)
            self.assertEqual(receipt["status"], "PASS")
            closure = runtime.derive_gvisor_runtime_smoke_closure(
                cas,
                receipt_digest,
                expected_lock_digest=lock_digest,
                expected_verifier_implementation_digest=_IMPLEMENTATION_DIGEST,
            )
            self.assertEqual(closure[receipt_digest], len(cas.read(receipt_digest)))
            self.assertLessEqual(len(closure), 26)
            handoff = build_handoff_manifest(
                kind="runtime_evidence",
                root_digest=receipt_digest,
                blobs=closure,
            )
            self.assertEqual(handoff["total_bytes"], sum(closure.values()))

            changed = copy.deepcopy(evidence)
            live = json.loads(changed["container_live_inspect"])
            live[0]["HostConfig"]["Runtime"] = "runc"
            changed["container_live_inspect"] = _json(live)
            with self.assertRaises(runtime.GVisorRuntimeError):
                _put_fixture_receipt(
                    cas,
                    changed,
                    lock_raw=lock_raw,
                )

            post_runner = json.loads(evidence["runner_post"])
            post_runner["info"]["ID"] = "other-daemon"
            changed = evidence | {"runner_post": canonical_json(post_runner)}
            with self.assertRaises(runtime.GVisorRuntimeError):
                _put_fixture_receipt(
                    cas,
                    changed,
                    lock_raw=lock_raw,
                )

            helpers = json.loads(evidence["helper_implementations"])
            helpers[0]["file"]["digest"] = "sha256:" + "0" * 64
            changed = evidence | {"helper_implementations": canonical_json(helpers)}
            with self.assertRaises(runtime.GVisorRuntimeError):
                _put_fixture_receipt(cas, changed, lock_raw=lock_raw)

            processes = json.loads(evidence["container_processes"])
            processes["processes"][0]["exe"]["inode"] += 1
            changed = evidence | {"container_processes": canonical_json(processes)}
            with self.assertRaises(runtime.GVisorRuntimeError):
                _put_fixture_receipt(cas, changed, lock_raw=lock_raw)

            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime.verify_gvisor_runtime_smoke(
                    cas,
                    receipt_digest,
                    expected_lock_digest="sha256:" + "f" * 64,
                    expected_verifier_implementation_digest=_IMPLEMENTATION_DIGEST,
                )

            forged = dict(json.loads(cas.read(receipt_digest)))
            forged["authority"] = "ISOLATION_AUTHORITY"
            forged_digest = cas.put(
                BytesIO(canonical_json(forged)), max_bytes=64 * 1024
            )
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime.verify_gvisor_runtime_smoke(
                    cas,
                    forged_digest,
                    expected_lock_digest=lock_digest,
                    expected_verifier_implementation_digest=_IMPLEMENTATION_DIGEST,
                )

    def test_canary_trace_is_strictly_paired_and_normalized(self) -> None:
        _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
        _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
        trace = _canary_trace()
        self.assertEqual(
            runtime._parse_canary_trace(
                trace, runtime_lock, canary_lock, _CONTAINER_ID
            ),
            tuple(
                canonical_json(event)
                for event in canary_lock["canary"]["source_events"]
            ),
        )

        mutations = (
            trace.replace(b"Network: none", b"Network: sandbox", 1),
            trace.replace(b"O_RDONLY|0x0", b"O_RDONLY|O_CLOEXEC", 1),
            trace.replace(b"= 0 (0x0)", b"= -1 errno=1", 1),
            trace.replace(
                b"cli.go:316] Exiting with status: 0",
                b"cli.go:316] Exiting with status: 1",
                1,
            ),
            trace.replace(b"sha256sum X openat", b"sha256sum E openat", 1),
            trace[:-1],
        )
        for changed in mutations:
            with (
                self.subTest(changed=hashlib.sha256(changed).hexdigest()),
                self.assertRaises(runtime.GVisorRuntimeError),
            ):
                runtime._parse_canary_trace(
                    changed, runtime_lock, canary_lock, _CONTAINER_ID
                )

    def test_acquired_artifact_profile_is_bound_and_normalized(self) -> None:
        _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
        _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
        artifact = runtime._AcquiredArtifact(
            quarantine_receipt_digest="sha256:" + "1" * 64,
            gateway_profile_digest="sha256:" + "2" * 64,
            source_closure_digest="sha256:" + "3" * 64,
            manifest_digest="sha256:" + "4" * 64,
            tree_digest="sha256:" + "5" * 64,
            entrypoint_digest="sha256:" + "6" * 64,
            entrypoint_size=80,
            materialized_path=Path("/run/aragorn-gvisor-artifact/run.sh"),
        )
        expected_events = tuple(
            canonical_json(event)
            for event in runtime._artifact_profile(canary_lock)["source_events"]
        )
        self.assertEqual(
            runtime._parse_artifact_trace(
                _canary_trace(artifact=True),
                runtime_lock,
                canary_lock,
                _CONTAINER_ID,
            ),
            expected_events,
        )
        bind = {
            "source": str(artifact.materialized_path),
            "destination": runtime._ARTIFACT_TARGET,
        }
        self.assertEqual(
            runtime._verify_detonation_container(
                runtime_lock,
                canary_lock,
                _artifact_container(
                    runtime_lock,
                    canary_lock,
                    "prestart",
                    bind["source"],
                ),
                phase="prestart",
                run_id=_RUN_ID,
                artifact=artifact,
                bind_mount=bind,
            ),
            _CONTAINER_ID,
        )
        request = json.loads(
            runtime._artifact_run_request(
                runtime_lock,
                canary_lock,
                artifact,
                run_id=_RUN_ID,
                container_id=_CONTAINER_ID,
                implementation_digest="sha256:" + "7" * 64,
            )
        )
        self.assertEqual(request["subject_digest"], artifact.tree_digest)
        self.assertEqual(request["input_manifest_digest"], artifact.manifest_digest)
        self.assertEqual(request["input_tree_digest"], artifact.tree_digest)
        self.assertEqual(request["command"], ["/bin/sh", runtime._ARTIFACT_TARGET])
        self.assertEqual(
            request["mount"],
            {"destination": runtime._ARTIFACT_TARGET, "read_only": True},
        )

        writable = _artifact_container(
            runtime_lock,
            canary_lock,
            "prestart",
            bind["source"],
        )
        writable["HostConfig"]["Mounts"][0]["ReadOnly"] = False
        with self.assertRaises(runtime.GVisorRuntimeError):
            runtime._verify_detonation_container(
                runtime_lock,
                canary_lock,
                writable,
                phase="prestart",
                run_id=_RUN_ID,
                artifact=artifact,
                bind_mount=bind,
            )

    def test_acquired_artifact_pins_fail_before_runtime_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source-cas"
            writable_source = CAS(source_root)
            fixture = (
                Path(__file__).parents[1]
                / "benchmark"
                / "fixtures"
                / "phase2-inert-detonation"
            )
            files = []
            for path in sorted(item for item in fixture.iterdir() if item.is_file()):
                raw = path.read_bytes()
                digest = writable_source.put(BytesIO(raw), max_bytes=len(raw))
                files.append(
                    {
                        "path": path.name,
                        "size": len(raw),
                        "digest": digest,
                        "git_blob_sha1": hashlib.sha1(
                            f"blob {len(raw)}\0".encode("ascii") + raw
                        ).hexdigest(),
                        "executable": path.name == "run.sh",
                    }
                )
            tree_files = [
                {key: item[key] for key in ("path", "size", "digest", "executable")}
                for item in files
            ]
            tree_digest = (
                "sha256:" + hashlib.sha256(canonical_json(tree_files)).hexdigest()
            )
            self.assertEqual(tree_digest, runtime._ARTIFACT_TREE_DIGEST)
            manifest = {
                "schema": "aragorn/github-manifest/v1",
                "source": {
                    "kind": "github_commit",
                    "host": "github.com",
                    "owner": "yousifnazhat",
                    "repository": "agent-skill-inert-fixture",
                    "commit": "a" * 40,
                    "repository_hash_algorithm": "sha1",
                    "commit_tree": "b" * 40,
                    "skill_path": ".",
                    "skill_tree": "c" * 40,
                    "api_version": "2026-03-10",
                },
                "tree_digest": tree_digest,
                "files": files,
                "closure": {"scope": "source_tree", "status": "complete"},
            }
            for change in ("source", "tree", "entrypoint"):
                changed_manifest = copy.deepcopy(manifest)
                if change == "source":
                    changed_manifest["source"]["owner"] = "other"
                elif change == "tree":
                    changed_manifest["tree_digest"] = "sha256:" + "0" * 64
                else:
                    next(
                        item
                        for item in changed_manifest["files"]
                        if item["path"] == "run.sh"
                    )["digest"] = "sha256:" + "0" * 64
                with (
                    self.subTest(fixed_profile_change=change),
                    self.assertRaises(runtime.GVisorRuntimeError),
                ):
                    runtime._fixed_artifact_entrypoint(changed_manifest)
            raw_manifest = canonical_json(manifest)
            manifest_digest = writable_source.put(
                BytesIO(raw_manifest),
                max_bytes=len(raw_manifest),
            )
            source = CAS(source_root, read_only=True)
            output = CAS(root / "output-cas")
            materialized = root / "materialized"
            materialized.mkdir(mode=0o700)
            quarantine_digest = "sha256:" + "d" * 64
            gateway_digest = "sha256:" + "e" * 64
            source_closure_digest = "sha256:" + "f" * 64
            entrypoint_digest = next(
                item["digest"] for item in files if item["path"] == "run.sh"
            )
            self.assertEqual(entrypoint_digest, runtime._ARTIFACT_ENTRYPOINT_DIGEST)
            expected = {
                "expected_manifest_digest": manifest_digest,
                "expected_gateway_profile_digest": gateway_digest,
            }
            arguments = {
                "expected_quarantine_receipt_digest": quarantine_digest,
                "expected_manifest_digest": manifest_digest,
                "expected_tree_digest": tree_digest,
                "expected_gateway_profile_digest": gateway_digest,
                "expected_entrypoint_digest": entrypoint_digest,
                "expected_lock_digest": "sha256:" + "1" * 64,
                "expected_verifier_implementation_digest": "sha256:" + "2" * 64,
            }

            def verify(_cas: CAS, receipt: str, **pins: str) -> dict[str, object]:
                if receipt != quarantine_digest or pins != expected:
                    raise ValueError("wrong caller-held acquisition pin")
                return {
                    "tree_digest": tree_digest,
                    "source_closure_digest": source_closure_digest,
                }

            def closure(_cas: CAS, receipt: str, **pins: str) -> dict[str, int]:
                verify(_cas, receipt, **pins)
                return {
                    manifest_digest: len(raw_manifest),
                    **{item["digest"]: item["size"] for item in files},
                }

            with (
                mock.patch(
                    "aragorn.github_quarantine_receipt."
                    "verify_github_quarantine_receipt",
                    side_effect=verify,
                ),
                mock.patch(
                    "aragorn.github_quarantine_receipt."
                    "derive_github_quarantine_closure",
                    side_effect=closure,
                ),
                mock.patch.object(
                    runtime.tempfile,
                    "TemporaryDirectory",
                    return_value=nullcontext(str(materialized)),
                ),
                mock.patch.object(
                    runtime,
                    "_collect_gvisor_detonation",
                    return_value="sha256:" + "9" * 64,
                ) as collect,
            ):
                observed = runtime.collect_gvisor_acquired_artifact(
                    output,
                    source,
                    **arguments,
                )
                self.assertEqual(observed, "sha256:" + "9" * 64)
                artifact = collect.call_args.kwargs["artifact"]
                self.assertEqual(artifact.manifest_digest, manifest_digest)
                self.assertEqual(artifact.tree_digest, tree_digest)
                self.assertEqual(artifact.entrypoint_digest, entrypoint_digest)
                self.assertEqual(
                    artifact.source_closure_digest,
                    source_closure_digest,
                )

                for changed in (
                    {"expected_quarantine_receipt_digest": "sha256:" + "0" * 64},
                    {"expected_manifest_digest": "sha256:" + "0" * 64},
                    {"expected_tree_digest": "sha256:" + "0" * 64},
                    {"expected_gateway_profile_digest": "sha256:" + "0" * 64},
                    {"expected_entrypoint_digest": "sha256:" + "0" * 64},
                ):
                    collect.reset_mock()
                    with (
                        self.subTest(changed=next(iter(changed))),
                        self.assertRaises(runtime.GVisorRuntimeError),
                    ):
                        runtime.collect_gvisor_acquired_artifact(
                            output,
                            source,
                            **(arguments | changed),
                        )
                    collect.assert_not_called()

            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime.collect_gvisor_acquired_artifact(
                    output,
                    writable_source,
                    **arguments,
                )

            nested_output = CAS(source_root / "nested-output")
            nested_source_root = output.root / "nested-source"
            CAS(nested_source_root)
            nested_source = CAS(nested_source_root, read_only=True)
            for unsafe_output, unsafe_source in (
                (nested_output, source),
                (output, nested_source),
            ):
                with self.assertRaises(runtime.GVisorRuntimeError):
                    runtime.collect_gvisor_acquired_artifact(
                        unsafe_output,
                        unsafe_source,
                        **arguments,
                    )

    def test_container_cleanup_error_fails_closed(self) -> None:
        with (
            mock.patch.object(
                runtime,
                "_cleanup_container",
                return_value="container still exists",
            ),
            self.assertRaisesRegex(
                runtime.GVisorRuntimeError,
                "Docker canary cleanup failed: container still exists",
            ),
        ):
            runtime._cleanup_container_strict(
                Path("/usr/bin/docker"),
                "aragorn-gvisor-artifact-test",
                {},
                label="Docker canary",
            )

    def test_public_collector_does_not_accept_caller_evidence(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaises(TypeError),
        ):
            runtime.collect_gvisor_runtime_smoke(  # type: ignore[call-arg]
                CAS(Path(temporary) / "cas"),
                evidence={},
                expected_lock_digest="sha256:" + "a" * 64,
                expected_verifier_implementation_digest="sha256:" + "b" * 64,
            )

        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schema"
                / "gvisor-runtime-smoke-receipt-v1.schema.json"
            ).read_text()
        )
        self.assertEqual(schema["properties"]["authority"]["const"], runtime.AUTHORITY)


if __name__ == "__main__":
    unittest.main()
