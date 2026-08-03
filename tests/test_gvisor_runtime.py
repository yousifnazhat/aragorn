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
from aragorn.detonation_observation import (
    retain_detonation_capability_diff,
    retain_detonation_observation,
)
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
_LIVE_ARTIFACT_RUN_ID = "4147e7ee2b15c6ada9832112122225f4"
_LIVE_ARTIFACT_RECEIPT_DIGEST = (
    "sha256:b44239596290137d43d76dd834cf5f81937e264bdfbd497d8a52070527f5aedf"
)
_LIVE_ARTIFACT_HANDOFF_DIGEST = (
    "sha256:5314c6d62f16b4a00a14578d4e733404b4b146f8aa346a497303311bf052f089"
)
_LIVE_ARTIFACT_ARCHIVE_SHA256 = (
    "07d7225a99b4f6da836ccbb2d41b8333513560e710c34bc5280b6cf07b7b564b"
)
_BOUNDED_LIVE_ARTIFACT_RUN_ID = "a34474048ae9cdd792c2d2c37c9cb4c0"
_BOUNDED_LIVE_ARTIFACT_RECEIPT_DIGEST = (
    "sha256:d15eefc95e5355b44561d31e7c3594e8af66820b6a1375bf4850ca9c120ae141"
)
_BOUNDED_LIVE_ARTIFACT_HANDOFF_DIGEST = (
    "sha256:fd03ae3d7b41d3556a8eea222fde9a72a829015fddb6c96c33ae9711d876d80f"
)
_BOUNDED_LIVE_ARTIFACT_ARCHIVE_SHA256 = (
    "f439cf58c099e45bb74aab719b7922653da8212d149237d8c8b6a317d4dca2ec"
)
_BOUNDED_LIVE_ARTIFACT_IMPLEMENTATION_DIGEST = (
    "sha256:0091293a77b61270f73778cbbbf382e2e4770c48d10e43d80d5789e8e8e1434d"
)
_LIVE_ARTIFACT_V2_RUN_ID = "e55ef93d8538c50c94dee1c25899faf0"
_LIVE_ARTIFACT_V2_RECEIPT_DIGEST = (
    "sha256:e0529d77157210e7957dea3d87691951b9b68d9e49eaee57879035494e328b57"
)
_LIVE_ARTIFACT_V2_HANDOFF_DIGEST = (
    "sha256:d7c9fcbdacf8019ca7f124798da228c1ad73c9cf78e4a6743c854bdd6ca9e596"
)
_LIVE_ARTIFACT_V2_ARCHIVE_SHA256 = (
    "dcd37b03dedebe869e5984c124f7838c7b4e7db6c7f38f02a5e5e8d25365a8e3"
)
_LIVE_ARTIFACT_V2_IMPLEMENTATION_DIGEST = (
    "sha256:322010616fe6750a8f37a57a68ea1d6b77883eacd5e7503b14bd4aa69429d1b8"
)
_LIVE_ARTIFACT_PINS = {
    "expected_quarantine_receipt_digest": (
        "sha256:295b14aff90d6daddac8e435f54863cbe7133d910aa05243d9579f92b41fc475"
    ),
    "expected_manifest_digest": (
        "sha256:aa2952790d95fabbdfcbe97ded12e9802f382097bc9441af1400f3068fdde1bd"
    ),
    "expected_tree_digest": runtime._ARTIFACT_TREE_DIGEST,
    "expected_gateway_profile_digest": (
        "sha256:b15767734e21048d2c25c94b0dede208618a0b0640c4819750a3bfb6f85477fc"
    ),
    "expected_entrypoint_digest": runtime._ARTIFACT_ENTRYPOINT_DIGEST,
    "expected_lock_digest": _LIVE_CANARY_LOCK_DIGEST,
    "expected_verifier_implementation_digest": (
        "sha256:9642904785f64fcf42f8edb5cb3023deb4eb6cbef15819bc6afd58f3b29fe585"
    ),
}


def _canary_trace(
    container_id: str = _CONTAINER_ID,
    *,
    artifact: bool = False,
    artifact_profile: runtime._AcquiredArtifact | None = None,
    extra_syscalls: tuple[str, ...] = (),
) -> bytes:
    _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
    _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
    profile = (
        runtime._artifact_profile(canary_lock, artifact_profile)
        if artifact
        else canary_lock["canary"]
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
    if artifact_profile and artifact_profile.execution_profile:
        script_read = read.replace("O_RDONLY|0x0", "O_RDONLY|O_CLOEXEC")
        shell_execute = (
            f'0x111 /bin/sh, 0x222 ["/bin/sh", "{target}"], '
            f"0x333 {environment}"
        )
        syscalls.extend(
            (
                f"strace.go:567] [   3:   3] sh E execve({shell_execute})",
                f"strace.go:605] [   3:   3] sh X execve({shell_execute}) = 0 (0x0) (3µs)",
                f"strace.go:570] [   3:   3] sh E openat({script_read})",
                f"strace.go:608] [   3:   3] sh X openat({script_read}) = 3 (0x3) (2.6µs)",
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
        *extra_syscalls,
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
    artifact: runtime._AcquiredArtifact | None = None,
) -> dict[str, object]:
    container = _container(runtime_lock, phase)
    profile = runtime._artifact_profile(canary_lock, artifact)
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

    def test_checked_in_live_acquired_artifact_imports_and_replays(self) -> None:
        root = Path(__file__).parents[1]
        cases = (
            (
                f"phase2-gvisor-acquired-artifact-{_LIVE_ARTIFACT_RUN_ID}-2026-08-02",
                _LIVE_ARTIFACT_RUN_ID,
                _LIVE_ARTIFACT_RECEIPT_DIGEST,
                _LIVE_ARTIFACT_HANDOFF_DIGEST,
                _LIVE_ARTIFACT_ARCHIVE_SHA256,
                _LIVE_ARTIFACT_PINS["expected_verifier_implementation_digest"],
                None,
            ),
            (
                (
                    "phase2-gvisor-acquired-artifact-"
                    f"{_BOUNDED_LIVE_ARTIFACT_RUN_ID}-2026-08-02"
                ),
                _BOUNDED_LIVE_ARTIFACT_RUN_ID,
                _BOUNDED_LIVE_ARTIFACT_RECEIPT_DIGEST,
                _BOUNDED_LIVE_ARTIFACT_HANDOFF_DIGEST,
                _BOUNDED_LIVE_ARTIFACT_ARCHIVE_SHA256,
                _BOUNDED_LIVE_ARTIFACT_IMPLEMENTATION_DIGEST,
                None,
            ),
            (
                (
                    "phase2-gvisor-acquired-artifact-v2-"
                    f"{_LIVE_ARTIFACT_V2_RUN_ID}-2026-08-02"
                ),
                _LIVE_ARTIFACT_V2_RUN_ID,
                _LIVE_ARTIFACT_V2_RECEIPT_DIGEST,
                _LIVE_ARTIFACT_V2_HANDOFF_DIGEST,
                _LIVE_ARTIFACT_V2_ARCHIVE_SHA256,
                _LIVE_ARTIFACT_V2_IMPLEMENTATION_DIGEST,
                runtime.ARTIFACT_NORMALIZATION_PROFILE,
            ),
        )
        for case in cases:
            (
                stem,
                run_id,
                receipt_digest,
                handoff_digest,
                archive_sha256,
                implementation,
                normalization_profile,
            ) = case
            with self.subTest(run_id=run_id):
                archive = root / "benchmark" / "evidence" / f"{stem}.tar.gz"
                checked_in_receipt = (
                    root / "benchmark" / "receipts" / f"{stem}.json"
                ).read_bytes()
                self.assertEqual(
                    archive_sha256,
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
                        expected_manifest_digest=handoff_digest,
                        expected_kind="runtime_evidence",
                        expected_root_digest=receipt_digest,
                    )
                    pins = _LIVE_ARTIFACT_PINS | {
                        "expected_verifier_implementation_digest": implementation
                    }
                    profile_pin = (
                        {"expected_normalization_profile": normalization_profile}
                        if normalization_profile is not None
                        else {}
                    )
                    closure = runtime.derive_gvisor_acquired_artifact_closure(
                        cas,
                        receipt_digest,
                        **pins,
                        **profile_pin,
                    )
                    self.assertEqual(
                        {
                            item["digest"]: item["size"]
                            for item in imported["blobs"]
                        },
                        closure,
                    )
                    self.assertEqual(cas.read(receipt_digest), checked_in_receipt)
                    receipt = runtime.verify_gvisor_acquired_artifact(
                        cas,
                        receipt_digest,
                        **pins,
                        **profile_pin,
                    )
                    self.assertEqual(receipt["run_id"], run_id)
                    self.assertEqual(receipt["status"], "RECORDED")
                    if normalization_profile is not None:
                        self.assertEqual(receipt["schema"], runtime.ARTIFACT_SCHEMA_V2)
                        self.assertEqual(
                            receipt["normalization_profile"], normalization_profile
                        )
                        for action in (
                            runtime.verify_gvisor_acquired_artifact,
                            runtime.derive_gvisor_acquired_artifact_closure,
                        ):
                            with self.assertRaises(runtime.GVisorRuntimeError):
                                action(cas, receipt_digest, **pins)
                            with self.assertRaises(runtime.GVisorRuntimeError):
                                action(
                                    cas,
                                    receipt_digest,
                                    **pins,
                                    expected_normalization_profile=(
                                        runtime.ARTIFACT_NORMALIZATION_PROFILE
                                    ),
                                    expected_execution_profile=(
                                        runtime.ARTIFACT_EXECUTION_PROFILE
                                    ),
                                    expected_entrypoint_path="run.sh",
                                    expected_declared_capabilities=[],
                                )
                    if run_id == _BOUNDED_LIVE_ARTIFACT_RUN_ID:
                        with self.assertRaises(runtime.GVisorRuntimeError):
                            runtime.verify_gvisor_acquired_artifact(
                                cas,
                                receipt_digest,
                                **pins,
                                expected_normalization_profile=(
                                    runtime.ARTIFACT_NORMALIZATION_PROFILE
                                ),
                            )
                        canary_lock = runtime._canary_lock(
                            cas.read(receipt["lock_digest"])
                        )
                        runtime_lock = runtime._runtime_lock(
                            cas.read(receipt["runtime_lock_digest"])
                        )
                        log_manifest = json.loads(
                            cas.read(receipt["evidence"]["backend_log_manifest"])
                        )
                        boot_digest = next(
                            item["file"]["digest"]
                            for item in log_manifest["files"]
                            if item["command"] == "boot"
                        )
                        boot = cas.read(
                            boot_digest,
                            max_bytes=canary_lock["trace"]["max_log_bytes"],
                        )
                        events = runtime._parse_artifact_trace(
                            boot,
                            runtime_lock,
                            canary_lock,
                            json.loads(
                                cas.read(
                                    receipt["evidence"]["container_pre_inspect"]
                                )
                            )[0]["Id"],
                            normalization_profile=(
                                runtime.ARTIFACT_NORMALIZATION_PROFILE
                            ),
                        )
                        expected = tuple(
                            sorted(
                                canonical_json(
                                    {
                                        "schema": (
                                            "aragorn/detonation-source-event/v1"
                                        ),
                                        "operation": operation,
                                        "detail": detail,
                                    }
                                )
                                for operation, detail in (
                                    (
                                        "file-open-read",
                                        "gvisor-json-strace:openat:read:/aragorn-input/run.sh",
                                    ),
                                    (
                                        "file-open-read",
                                        "gvisor-json-strace:openat:read:/lib/libc.so.6",
                                    ),
                                    (
                                        "file-open-read",
                                        "gvisor-json-strace:openat:read:/lib/libm.so.6",
                                    ),
                                    (
                                        "file-open-read",
                                        "gvisor-json-strace:openat:read:/lib/libresolv.so.2",
                                    ),
                                    (
                                        "file-open-write",
                                        "gvisor-json-strace:openat:write:/dev/null",
                                    ),
                                    (
                                        "process-exec",
                                        "gvisor-json-strace:execve:/bin/sha256sum",
                                    ),
                                    (
                                        "process-exec",
                                        "gvisor-json-strace:execve:/bin/sleep",
                                    ),
                                )
                            )
                        )
                        self.assertEqual(events, expected)
                        self.assertEqual(events, tuple(sorted(set(events))))
                        self.assertEqual(boot.count(b" = -1 errno="), 9)
                        normalized = b"\n".join(events)
                        for failed_only in (
                            b"/etc/ld.so.cache",
                            b"/lib/aarch64-linux-gnu/libm.so.6",
                            b"/usr/lib/aarch64-linux-gnu/libm.so.6",
                        ):
                            self.assertNotIn(failed_only, normalized)

    def test_v3_acquired_artifact_round_trips_and_binds_caller_pins(self) -> None:
        root = Path(__file__).parents[1]
        archive = (
            root
            / "benchmark"
            / "evidence"
            / (
                "phase2-gvisor-acquired-artifact-v2-"
                f"{_LIVE_ARTIFACT_V2_RUN_ID}-2026-08-02.tar.gz"
            )
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
                expected_manifest_digest=_LIVE_ARTIFACT_V2_HANDOFF_DIGEST,
                expected_kind="runtime_evidence",
                expected_root_digest=_LIVE_ARTIFACT_V2_RECEIPT_DIGEST,
            )
            historical = json.loads(cas.read(_LIVE_ARTIFACT_V2_RECEIPT_DIGEST))
            evidence = {
                name: cas.read(digest)
                for name, digest in historical["evidence"].items()
            }
            source = json.loads(evidence["artifact_source"])
            canary_lock = runtime._canary_lock(
                cas.read(historical["lock_digest"])
            )
            runtime_lock = runtime._runtime_lock(
                cas.read(historical["runtime_lock_digest"])
            )
            artifact = runtime._AcquiredArtifact(
                quarantine_receipt_digest=historical[
                    "quarantine_receipt_digest"
                ],
                gateway_profile_digest=historical["gateway_profile_digest"],
                source_closure_digest=historical["source_closure_digest"],
                manifest_digest=historical["input_manifest_digest"],
                tree_digest=historical["input_tree_digest"],
                entrypoint_path=historical["entrypoint"]["path"],
                entrypoint_digest=historical["entrypoint"]["digest"],
                entrypoint_size=historical["entrypoint"]["size"],
                execution_profile=runtime.ARTIFACT_EXECUTION_PROFILE,
                declared_capabilities=("file-read", "process-exec"),
                materialized_path=Path(source["path"]),
            )
            profile = runtime._artifact_profile(canary_lock, artifact)
            for name in (
                "container_pre_inspect",
                "container_live_inspect",
                "container_post_inspect",
            ):
                document = json.loads(evidence[name])
                document[0]["Path"] = profile["command"][0]
                document[0]["Args"] = profile["command"][1:]
                document[0]["Config"]["Cmd"] = profile["command"]
                evidence[name] = canonical_json(document)

            implementation_files = {}
            for module in runtime._ARTIFACT_IMPLEMENTATION_MODULES:
                raw = (root / "src" / "aragorn" / module).read_bytes()
                implementation_files[module] = cas.put(
                    BytesIO(raw),
                    max_bytes=runtime._MAX_IMPLEMENTATION_SOURCE_BYTES,
                )
            implementation_digest = cas.put(
                BytesIO(
                    canonical_json(
                        {
                            "schema": runtime.ARTIFACT_IMPLEMENTATION_SCHEMA,
                            "files": implementation_files,
                        }
                    )
                ),
                max_bytes=runtime._MAX_IMPLEMENTATION_MANIFEST_BYTES,
            )
            helpers = json.loads(evidence["helper_implementations"])
            for item in helpers:
                item["file"]["digest"] = implementation_files[item["module"]]
            evidence["helper_implementations"] = canonical_json(helpers)

            log_manifest = json.loads(evidence["backend_log_manifest"])
            container_id = log_manifest["container_id"]
            boot = _canary_trace(
                container_id,
                artifact=True,
                artifact_profile=artifact,
            )
            boot_digest = cas.put(
                BytesIO(boot),
                max_bytes=canary_lock["trace"]["max_log_bytes"],
            )
            boot_entry = next(
                item for item in log_manifest["files"] if item["command"] == "boot"
            )
            boot_entry["file"]["digest"] = boot_digest
            boot_entry["file"]["size"] = len(boot)
            evidence["backend_log_manifest"] = canonical_json(log_manifest)

            normalization_profile = runtime.ARTIFACT_NORMALIZATION_PROFILE
            source_events = runtime._parse_artifact_trace(
                boot,
                runtime_lock,
                canary_lock,
                container_id,
                normalization_profile=normalization_profile,
                artifact=artifact,
            )
            run_request_digest = cas.put(
                BytesIO(
                    runtime._artifact_run_request(
                        runtime_lock,
                        canary_lock,
                        artifact,
                        run_id=historical["run_id"],
                        container_id=container_id,
                        implementation_digest=implementation_digest,
                        normalization_profile=normalization_profile,
                    )
                ),
                max_bytes=runtime._MAX_CANARY_RUN_REQUEST_BYTES,
            )
            identity = runtime._artifact_identity(
                artifact,
                run_request_digest,
                implementation_digest,
            )
            observation_bindings = {}
            for source_event in source_events:
                observation_digest = retain_detonation_observation(
                    cas,
                    source_event,
                    **identity,
                )
                observation_bindings[observation_digest] = runtime._raw_digest(
                    source_event
                )
            capability_diff_receipt_digest = retain_detonation_capability_diff(
                cas,
                observation_bindings,
                **identity,
                declared_capabilities=artifact.declared_capabilities,
            )
            receipt = {
                "schema": runtime.ARTIFACT_SCHEMA_V3,
                "authority": runtime.ARTIFACT_AUTHORITY_V3,
                "lock_digest": historical["lock_digest"],
                "runtime_lock_digest": historical["runtime_lock_digest"],
                "implementation_digest": implementation_digest,
                "run_id": historical["run_id"],
                "captured_at": historical["captured_at"],
                **identity,
                "capability_diff_receipt_digest": (
                    capability_diff_receipt_digest
                ),
                "evidence": {
                    name: cas.put(
                        BytesIO(raw),
                        max_bytes=runtime._ARTIFACT_EVIDENCE_LIMITS[name],
                    )
                    for name, raw in sorted(evidence.items())
                },
                "status": "RECORDED",
                "quarantine_receipt_digest": artifact.quarantine_receipt_digest,
                "gateway_profile_digest": artifact.gateway_profile_digest,
                "source_closure_digest": artifact.source_closure_digest,
                "entrypoint": runtime._artifact_entrypoint(artifact),
                "normalization_profile": normalization_profile,
                "execution_profile": artifact.execution_profile,
            }
            receipt_digest = cas.put(
                BytesIO(canonical_json(receipt)),
                max_bytes=runtime._MAX_RECEIPT_BYTES,
            )
            pins = {
                "expected_quarantine_receipt_digest": (
                    artifact.quarantine_receipt_digest
                ),
                "expected_manifest_digest": artifact.manifest_digest,
                "expected_tree_digest": artifact.tree_digest,
                "expected_gateway_profile_digest": artifact.gateway_profile_digest,
                "expected_entrypoint_digest": artifact.entrypoint_digest,
                "expected_lock_digest": historical["lock_digest"],
                "expected_verifier_implementation_digest": implementation_digest,
                "expected_normalization_profile": normalization_profile,
                "expected_execution_profile": artifact.execution_profile,
                "expected_entrypoint_path": artifact.entrypoint_path,
                "expected_declared_capabilities": artifact.declared_capabilities,
            }
            verified = runtime.verify_gvisor_acquired_artifact(
                cas,
                receipt_digest,
                **pins,
            )
            self.assertEqual(verified, receipt)
            closure = runtime.derive_gvisor_acquired_artifact_closure(
                cas,
                receipt_digest,
                **pins,
            )
            self.assertEqual(
                closure,
                {
                    digest: len(cas.read(digest, max_bytes=size))
                    for digest, size in closure.items()
                },
            )

            for changed in (
                {"expected_entrypoint_path": "other.sh"},
                {"expected_execution_profile": "other/v1"},
                {"expected_declared_capabilities": ("file-read",)},
            ):
                for action in (
                    runtime.verify_gvisor_acquired_artifact,
                    runtime.derive_gvisor_acquired_artifact_closure,
                ):
                    with self.assertRaises(runtime.GVisorRuntimeError):
                        action(cas, receipt_digest, **(pins | changed))
            without_capabilities = dict(pins)
            without_capabilities.pop("expected_declared_capabilities")
            for action in (
                runtime.verify_gvisor_acquired_artifact,
                runtime.derive_gvisor_acquired_artifact_closure,
            ):
                with self.assertRaises(runtime.GVisorRuntimeError):
                    action(cas, receipt_digest, **without_capabilities)

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
            entrypoint_path=runtime._ARTIFACT_ENTRYPOINT,
            entrypoint_digest="sha256:" + "6" * 64,
            entrypoint_size=80,
            execution_profile=None,
            declared_capabilities=(),
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
        expected_v2_events = tuple(
            sorted(
                canonical_json(event)
                for event in (
                    {
                        "schema": "aragorn/detonation-source-event/v1",
                        "operation": "file-open-read",
                        "detail": (
                            "gvisor-json-strace:openat:read:"
                            + runtime._ARTIFACT_TARGET
                        ),
                    },
                    {
                        "schema": "aragorn/detonation-source-event/v1",
                        "operation": "process-exec",
                        "detail": "gvisor-json-strace:execve:/bin/sha256sum",
                    },
                )
            )
        )
        self.assertEqual(
            runtime._parse_artifact_trace(
                _canary_trace(artifact=True),
                runtime_lock,
                canary_lock,
                _CONTAINER_ID,
                normalization_profile=runtime.ARTIFACT_NORMALIZATION_PROFILE,
            ),
            expected_v2_events,
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
        self.assertEqual(request["schema"], runtime.ARTIFACT_RUN_REQUEST_SCHEMA)
        self.assertNotIn("normalization_profile", request)
        request_v2 = json.loads(
            runtime._artifact_run_request(
                runtime_lock,
                canary_lock,
                artifact,
                run_id=_RUN_ID,
                container_id=_CONTAINER_ID,
                implementation_digest="sha256:" + "7" * 64,
                normalization_profile=runtime.ARTIFACT_NORMALIZATION_PROFILE,
            )
        )
        self.assertEqual(request_v2["schema"], runtime.ARTIFACT_RUN_REQUEST_SCHEMA_V2)
        self.assertEqual(
            request_v2["normalization_profile"],
            runtime.ARTIFACT_NORMALIZATION_PROFILE,
        )
        generalized = runtime._AcquiredArtifact(
            quarantine_receipt_digest=artifact.quarantine_receipt_digest,
            gateway_profile_digest=artifact.gateway_profile_digest,
            source_closure_digest=artifact.source_closure_digest,
            manifest_digest=artifact.manifest_digest,
            tree_digest=artifact.tree_digest,
            entrypoint_path="scripts/check.sh",
            entrypoint_digest=artifact.entrypoint_digest,
            entrypoint_size=artifact.entrypoint_size,
            execution_profile=runtime.ARTIFACT_EXECUTION_PROFILE,
            declared_capabilities=("file-read", "process-exec"),
            materialized_path=artifact.materialized_path,
        )
        generalized_profile = runtime._artifact_profile(canary_lock, generalized)
        self.assertEqual(
            generalized_profile["command"], list(runtime._ARTIFACT_WRAPPER_COMMAND)
        )
        self.assertEqual(
            generalized_profile["declared_capabilities"],
            ["file-read", "process-exec"],
        )
        request_v3 = json.loads(
            runtime._artifact_run_request(
                runtime_lock,
                canary_lock,
                generalized,
                run_id=_RUN_ID,
                container_id=_CONTAINER_ID,
                implementation_digest="sha256:" + "7" * 64,
                normalization_profile=runtime.ARTIFACT_NORMALIZATION_PROFILE,
            )
        )
        self.assertEqual(request_v3["schema"], runtime.ARTIFACT_RUN_REQUEST_SCHEMA_V3)
        self.assertEqual(
            request_v3["execution_profile"], runtime.ARTIFACT_EXECUTION_PROFILE
        )
        self.assertEqual(request_v3["entrypoint"]["path"], "scripts/check.sh")
        self.assertEqual(request_v3["command"], list(runtime._ARTIFACT_WRAPPER_COMMAND))
        self.assertEqual(
            request_v3["declared_capabilities"],
            ["file-read", "process-exec"],
        )
        generalized_bind = {
            "source": str(generalized.materialized_path),
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
                    generalized_bind["source"],
                    generalized,
                ),
                phase="prestart",
                run_id=_RUN_ID,
                artifact=generalized,
                bind_mount=generalized_bind,
            ),
            _CONTAINER_ID,
        )
        generalized_trace = _canary_trace(
            artifact=True,
            artifact_profile=generalized,
        )
        expected_v3_events = tuple(
            sorted(
                (*expected_v2_events, canonical_json(
                    {
                        "schema": "aragorn/detonation-source-event/v1",
                        "operation": "process-exec",
                        "detail": "gvisor-json-strace:execve:/bin/sh",
                    }
                ))
            )
        )
        self.assertEqual(
            runtime._parse_artifact_trace(
                generalized_trace,
                runtime_lock,
                canary_lock,
                _CONTAINER_ID,
                normalization_profile=runtime.ARTIFACT_NORMALIZATION_PROFILE,
                artifact=generalized,
            ),
            expected_v3_events,
        )
        changed_traces = []
        changed_traces.append(
            generalized_trace.replace(
                b"O_RDONLY|O_CLOEXEC",
                b"O_RDWR|O_CLOEXEC",
            )
        )
        for process in (b"other",):
            changed_traces.append(
                generalized_trace.replace(
                    b"[   3:   3] sh E execve",
                    b"[   3:   3] " + process + b" E execve",
                ).replace(
                    b"[   3:   3] sh X execve",
                    b"[   3:   3] " + process + b" X execve",
                )
            )
            changed_traces.append(
                generalized_trace.replace(
                    b"[   3:   3] sh E openat",
                    b"[   3:   3] " + process + b" E openat",
                ).replace(
                    b"[   3:   3] sh X openat",
                    b"[   3:   3] " + process + b" X openat",
                )
            )
        lines = generalized_trace.splitlines(keepends=True)
        changed_traces.append(
            b"".join(
                line.replace(b"HOME=/home", b"HOME=/attacker")
                if b"[   3:   3]" in line and b"execve" in line
                else line
                for line in lines
            )
        )
        exec_lines = [
            index
            for index, line in enumerate(lines)
            if b"[   3:   3]" in line and b"execve" in line
        ]
        read_lines = [
            index
            for index, line in enumerate(lines)
            if b"[   3:   3]" in line and b"openat" in line
        ]
        reordered = list(lines)
        for exec_index, read_index in zip(exec_lines, read_lines, strict=True):
            reordered[exec_index], reordered[read_index] = (
                reordered[read_index],
                reordered[exec_index],
            )
        changed_traces.append(b"".join(reordered))
        overlapped = list(lines)
        hash_read_exit = next(
            index
            for index, line in enumerate(overlapped)
            if b"[   2:   2] sha256sum X openat" in line
        )
        script_exec_entry = next(
            index
            for index, line in enumerate(overlapped)
            if b"[   3:   3] sh E execve" in line
        )
        overlapped[hash_read_exit], overlapped[script_exec_entry] = (
            overlapped[script_exec_entry],
            overlapped[hash_read_exit],
        )
        changed_traces.append(b"".join(overlapped))
        for changed in changed_traces:
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._parse_artifact_trace(
                    changed,
                    runtime_lock,
                    canary_lock,
                    _CONTAINER_ID,
                    normalization_profile=runtime.ARTIFACT_NORMALIZATION_PROFILE,
                    artifact=generalized,
                )
        with self.assertRaises(runtime.GVisorRuntimeError):
            runtime._artifact_run_request(
                runtime_lock,
                canary_lock,
                generalized,
                run_id=_RUN_ID,
                container_id=_CONTAINER_ID,
                implementation_digest="sha256:" + "7" * 64,
            )
        with self.assertRaises(runtime.GVisorRuntimeError):
            runtime._artifact_run_request(
                runtime_lock,
                canary_lock,
                artifact,
                run_id=_RUN_ID,
                container_id=_CONTAINER_ID,
                implementation_digest="sha256:" + "7" * 64,
                normalization_profile="other/v1",
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

    def test_acquired_artifact_v2_normalization_is_fail_closed(self) -> None:
        _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
        _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
        profile = runtime.ARTIFACT_NORMALIZATION_PROFILE
        baseline = runtime._parse_artifact_trace(
            _canary_trace(artifact=True),
            runtime_lock,
            canary_lock,
            _CONTAINER_ID,
            normalization_profile=profile,
        )
        failed = (
            "strace.go:570] [   8:   8] sh E openat(unparsed-open)",
            (
                "strace.go:608] [   8:   8] sh X openat(unparsed-open) "
                "= -1 errno=2 (no such file or directory) (2.1µs)"
            ),
            "strace.go:567] [   9:   9] sh E execve(unparsed-exec)",
            (
                "strace.go:605] [   9:   9] sh X execve(unparsed-exec) "
                "= -1 errno=2 (no such file or directory) (2.1µs)"
            ),
        )
        self.assertEqual(
            runtime._parse_artifact_trace(
                _canary_trace(artifact=True, extra_syscalls=failed),
                runtime_lock,
                canary_lock,
                _CONTAINER_ID,
                normalization_profile=profile,
            ),
            baseline,
        )

        malformed_outcomes = (
            (
                "strace.go:570] [   8:   8] sh E openat(unparsed-open)",
                (
                    "strace.go:608] [   8:   8] sh X openat(unparsed-open) "
                    "= 3 (0x3) (2.1µs)"
                ),
            ),
            (
                "strace.go:567] [   9:   9] sh E execve(unparsed-exec)",
                (
                    "strace.go:605] [   9:   9] sh X execve(unparsed-exec) "
                    "= 0 (0x0) (2.1µs)"
                ),
            ),
            (
                "strace.go:570] [  10:  10] sh E openat(unparsed-open)",
                (
                    "strace.go:608] [  10:  10] sh X openat(unparsed-open) "
                    "= -0 errno=0 (not a valid failure) (2.1µs)"
                ),
            ),
        )
        for malformed in malformed_outcomes:
            with (
                self.subTest(malformed=malformed[0]),
                self.assertRaises(runtime.GVisorRuntimeError),
            ):
                runtime._parse_artifact_trace(
                    _canary_trace(artifact=True, extra_syscalls=malformed),
                    runtime_lock,
                    canary_lock,
                    _CONTAINER_ID,
                    normalization_profile=profile,
                )

        read_write = (
            (
                "strace.go:570] [  10:  10] sh E openat(AT_FDCWD /, "
                "0xabc /tmp/read-write, O_RDWR|O_CLOEXEC, 0o0)"
            ),
            (
                "strace.go:608] [  10:  10] sh X openat(AT_FDCWD /, "
                "0xabc /tmp/read-write, O_RDWR|O_CLOEXEC, 0o0) "
                "= 3 (0x3) (2.1µs)"
            ),
        )
        read_write_events = runtime._parse_artifact_trace(
            _canary_trace(artifact=True, extra_syscalls=read_write),
            runtime_lock,
            canary_lock,
            _CONTAINER_ID,
            normalization_profile=profile,
        )
        decoded = [json.loads(event) for event in read_write_events]
        self.assertIn(
            {
                "schema": "aragorn/detonation-source-event/v1",
                "operation": "file-open-read",
                "detail": "gvisor-json-strace:openat:read:/tmp/read-write",
            },
            decoded,
        )
        self.assertIn(
            {
                "schema": "aragorn/detonation-source-event/v1",
                "operation": "file-open-write",
                "detail": "gvisor-json-strace:openat:write:/tmp/read-write",
            },
            decoded,
        )

        trace = _canary_trace(artifact=True)
        without_exec_anchor = trace.replace(b"/bin/sha256sum", b"/bin/sleep")
        without_read_anchor = trace.replace(
            b"sha256sum E openat", b"other E openat", 1
        ).replace(b"sha256sum X openat", b"other X openat", 1)
        for changed in (without_exec_anchor, without_read_anchor):
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._parse_artifact_trace(
                    changed,
                    runtime_lock,
                    canary_lock,
                    _CONTAINER_ID,
                    normalization_profile=profile,
                )

    def test_bounded_artifact_profile_rejects_unsafe_entrypoints(self) -> None:
        digest = "sha256:" + "1" * 64
        tree = "sha256:" + "2" * 64
        entrypoint = {
            "path": "scripts/check.sh",
            "size": 20,
            "digest": digest,
            "executable": True,
        }
        manifest = {
            "schema": "aragorn/github-manifest/v1",
            "tree_digest": tree,
            "files": [entrypoint],
        }
        self.assertEqual(
            runtime._pinned_artifact_entrypoint(
                manifest,
                expected_tree_digest=tree,
                expected_path="scripts/check.sh",
                expected_digest=digest,
            ),
            entrypoint,
        )
        variants = []
        for field, value in (
            ("digest", "sha256:" + "3" * 64),
            ("executable", False),
            ("size", 0),
            ("size", runtime._MAX_ARTIFACT_BYTES + 1),
        ):
            changed = copy.deepcopy(manifest)
            changed["files"][0][field] = value
            variants.append(changed)
        duplicate = copy.deepcopy(manifest)
        duplicate["files"].append(copy.deepcopy(entrypoint))
        variants.append(duplicate)
        for changed in variants:
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._pinned_artifact_entrypoint(
                    changed,
                    expected_tree_digest=tree,
                    expected_path="scripts/check.sh",
                    expected_digest=digest,
                )
        for path in (None, "../check.sh", "/check.sh", "scripts\\check.sh", ""):
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._pinned_artifact_entrypoint(
                    manifest,
                    expected_tree_digest=tree,
                    expected_path=path,
                    expected_digest=digest,
                )

        script = b"#!/bin/sh\n/bin/true\n"
        runtime._verify_artifact_script(script, expected_size=len(script))
        for raw, size in (
            (b"/bin/true\n", 10),
            (b"#!/bin/sh\n/bin/true\x00\n", 23),
            (b"#!/bin/sh\r\n/bin/true\n", 21),
            (b"#!/bin/sh\n\xff\n", 12),
            (script, len(script) + 1),
        ):
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._verify_artifact_script(raw, expected_size=size)

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
            manifest = copy.deepcopy(manifest)
            manifest["source"].update(
                {
                    "owner": "second-owner",
                    "repository": "second-inert-fixture",
                    "skill_path": "nested-skill",
                }
            )
            script = b"#!/bin/sh\n/bin/true\n"
            entrypoint = next(
                item for item in manifest["files"] if item["path"] == "run.sh"
            )
            entrypoint.update(
                {
                    "path": "scripts/check.sh",
                    "size": len(script),
                    "digest": writable_source.put(
                        BytesIO(script), max_bytes=len(script)
                    ),
                    "git_blob_sha1": hashlib.sha1(
                        f"blob {len(script)}\0".encode("ascii") + script
                    ).hexdigest(),
                }
            )
            files = manifest["files"]
            tree_files = [
                {key: item[key] for key in ("path", "size", "digest", "executable")}
                for item in files
            ]
            tree_digest = (
                "sha256:" + hashlib.sha256(canonical_json(tree_files)).hexdigest()
            )
            self.assertNotEqual(tree_digest, runtime._ARTIFACT_TREE_DIGEST)
            manifest["tree_digest"] = tree_digest
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
            entrypoint_digest = entrypoint["digest"]
            self.assertNotEqual(entrypoint_digest, runtime._ARTIFACT_ENTRYPOINT_DIGEST)
            expected = {
                "expected_manifest_digest": manifest_digest,
                "expected_gateway_profile_digest": gateway_digest,
            }
            arguments = {
                "expected_quarantine_receipt_digest": quarantine_digest,
                "expected_manifest_digest": manifest_digest,
                "expected_tree_digest": tree_digest,
                "expected_gateway_profile_digest": gateway_digest,
                "expected_entrypoint_path": "scripts/check.sh",
                "expected_entrypoint_digest": entrypoint_digest,
                "expected_declared_capabilities": [],
                "expected_execution_profile": runtime.ARTIFACT_EXECUTION_PROFILE,
                "expected_lock_digest": "sha256:" + "1" * 64,
                "expected_verifier_implementation_digest": "sha256:" + "2" * 64,
                "normalization_profile": runtime.ARTIFACT_NORMALIZATION_PROFILE,
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
                self.assertEqual(
                    collect.call_args.kwargs["artifact_normalization_profile"],
                    runtime.ARTIFACT_NORMALIZATION_PROFILE,
                )
                artifact = collect.call_args.kwargs["artifact"]
                self.assertEqual(artifact.manifest_digest, manifest_digest)
                self.assertEqual(artifact.tree_digest, tree_digest)
                self.assertEqual(artifact.entrypoint_path, "scripts/check.sh")
                self.assertEqual(artifact.entrypoint_digest, entrypoint_digest)
                self.assertEqual(
                    artifact.execution_profile,
                    runtime.ARTIFACT_EXECUTION_PROFILE,
                )
                self.assertEqual(artifact.declared_capabilities, ())
                self.assertEqual(
                    artifact.source_closure_digest,
                    source_closure_digest,
                )
                collect.reset_mock()
                with self.assertRaises(runtime.GVisorRuntimeError):
                    runtime.collect_gvisor_acquired_artifact(
                        output,
                        source,
                        **(arguments | {"normalization_profile": "other/v1"}),
                    )
                collect.assert_not_called()

                for changed in (
                    {"normalization_profile": None},
                    {"expected_execution_profile": None},
                    {"expected_execution_profile": "other/v1"},
                    {"expected_entrypoint_path": "../scripts/check.sh"},
                    {"expected_declared_capabilities": ["unknown"]},
                ):
                    collect.reset_mock()
                    with (
                        self.subTest(profile_change=next(iter(changed))),
                        self.assertRaises(runtime.GVisorRuntimeError),
                    ):
                        runtime.collect_gvisor_acquired_artifact(
                            output,
                            source,
                            **(arguments | changed),
                        )
                    collect.assert_not_called()

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

    def test_canary_trace_store_requires_bounded_headroom(self) -> None:
        _raw, lock = runtime.load_gvisor_detonation_canary_lock()
        directory = Path(lock["trace"]["directory"])
        metadata = mock.Mock(
            st_mode=runtime.stat.S_IFDIR | 0o700,
            st_uid=0,
        )
        filesystem = runtime.os.statvfs_result(
            (4096, 4096, 2048, 1536, 1280, 32, 28, 5, 0, 255)
        )
        with (
            mock.patch.object(runtime, "_verify_protected_path"),
            mock.patch.object(
                runtime.os,
                "stat",
                return_value=mock.Mock(st_dev=9, st_ino=11),
            ),
            mock.patch.object(runtime.Path, "lstat", return_value=metadata),
            mock.patch.object(
                runtime,
                "_require_bounded_tmpfs_mount",
                return_value=filesystem,
            ) as require,
        ):
            self.assertEqual(
                runtime._canary_log_directory(lock, require_headroom=True),
                directory,
            )
        require.assert_called_once_with(
            directory,
            maximum_bytes=8 * 1024 * 1024,
            maximum_inodes=32,
            label="gVisor canary trace store",
        )

        for insufficient in (
            runtime.os.statvfs_result(
                (4096, 4096, 2048, 1536, 1279, 32, 28, 5, 0, 255)
            ),
            runtime.os.statvfs_result(
                (4096, 4096, 2048, 1536, 1280, 32, 28, 4, 0, 255)
            ),
        ):
            with (
                self.subTest(insufficient=insufficient),
                mock.patch.object(runtime, "_verify_protected_path"),
                mock.patch.object(
                    runtime.os,
                    "stat",
                    return_value=mock.Mock(st_dev=9, st_ino=11),
                ),
                mock.patch.object(runtime.Path, "lstat", return_value=metadata),
                mock.patch.object(
                    runtime,
                    "_require_bounded_tmpfs_mount",
                    return_value=insufficient,
                ),
                self.assertRaisesRegex(
                    runtime.GVisorRuntimeError, "lacks bounded run headroom"
                ),
            ):
                runtime._canary_log_directory(lock, require_headroom=True)

        with (
            mock.patch.object(
                runtime.os,
                "stat",
                side_effect=(
                    mock.Mock(st_dev=9, st_ino=11),
                    mock.Mock(st_dev=9, st_ino=12),
                ),
            ),
            self.assertRaisesRegex(
                runtime.GVisorRuntimeError, "outside the host mount namespace"
            ),
        ):
            runtime._require_host_mount_namespace()

    def test_canary_log_cleanup_removes_only_current_container(self) -> None:
        _raw, lock = runtime.load_gvisor_detonation_canary_lock()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            current = (
                f"{_CONTAINER_ID}.{_CONTAINER_ID}.boot.jsonl",
                f"{_CONTAINER_ID}.{_CONTAINER_ID}.delete.jsonl",
            )
            other_id = "b" * 64
            other = directory / f"{other_id}.{other_id}.boot.jsonl"
            for name in current:
                (directory / name).write_bytes(b"trace\n")
            other.write_bytes(b"other\n")

            with mock.patch.object(
                runtime, "_canary_log_directory", return_value=directory
            ):
                runtime._cleanup_canary_logs_strict(lock, _CONTAINER_ID)

            self.assertFalse(any((directory / name).exists() for name in current))
            self.assertEqual(other.read_bytes(), b"other\n")

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
