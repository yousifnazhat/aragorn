from __future__ import annotations

import copy
import hashlib
import json
import tarfile
import tempfile
import unittest
from contextlib import nullcontext
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
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
_LIVE_ARTIFACT_V3_RUN_ID = "0b6ec3ea4b469e9f0ad26728a8711ecf"
_LIVE_ARTIFACT_V3_RECEIPT_DIGEST = (
    "sha256:4356104a711f75c297f5d86706ba3e192abbc514f1963d9ebbcb150375e9f90d"
)
_LIVE_ARTIFACT_V3_HANDOFF_DIGEST = (
    "sha256:95cb6426f5ae702b00096f486b43c561546e7eb0e32a9e7bb536a0937a14a46f"
)
_LIVE_ARTIFACT_V3_ARCHIVE_SHA256 = (
    "8d7f563646bd20faaef25be81b511b130455c1bceaf8a7fbbd9c90d135d3a944"
)
_LIVE_ARTIFACT_V3_IMPLEMENTATION_DIGEST = (
    "sha256:7f93a227e53b893061be6f1c74d503881a7d26b06fc7990946ca419b18831d27"
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
_LIVE_ARTIFACT_V3_PINS = {
    "expected_quarantine_receipt_digest": (
        "sha256:094c9b4541a02e046df6e15a789026f255df2b803f9482e72c9ce7ed6c63ea1a"
    ),
    "expected_manifest_digest": (
        "sha256:5bf379b9493eafc2841d619622a38677c968350f1bceadaa5acb00b6b6a43ad3"
    ),
    "expected_tree_digest": (
        "sha256:34e32015fc62a024af75ca59e2a273b6884e496dabaaf3eb9fb00883e27c447f"
    ),
    "expected_gateway_profile_digest": (
        "sha256:485557f9dcd31329c9ec769fc89e81d2ca2c969b747f1316c1144058faadf798"
    ),
    "expected_entrypoint_digest": (
        "sha256:d03f305f503fd161eca9916a781aa060708ec12fe64d83660e4a56c5e7643894"
    ),
    "expected_lock_digest": _LIVE_CANARY_LOCK_DIGEST,
    "expected_verifier_implementation_digest": (
        _LIVE_ARTIFACT_V3_IMPLEMENTATION_DIGEST
    ),
    "expected_normalization_profile": runtime.ARTIFACT_NORMALIZATION_PROFILE,
    "expected_execution_profile": runtime.ARTIFACT_EXECUTION_PROFILE,
    "expected_entrypoint_path": "scripts/check.sh",
    "expected_declared_capabilities": ("file-read", "process-exec"),
}


def _canary_trace(
    container_id: str = _CONTAINER_ID,
    *,
    artifact: bool = False,
    artifact_profile: runtime._AcquiredArtifact | None = None,
    pre_entrypoint_syscalls: tuple[str, ...] = (),
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
    environment_values = [
        f"HOSTNAME={container_id[:12]}",
        "SHLVL=1",
        "HOME=/home",
        "PATH=/bin",
        "PWD=/",
    ]
    if artifact_profile is not None and artifact_profile.scenario_id is not None:
        environment_values.append(
            f"{runtime.ARTIFACT_SCENARIO_ENVIRONMENT}="
            f"{artifact_profile.scenario_id}"
        )
    environment = json.dumps(environment_values, separators=(", ", ": "))
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
        syscalls.extend(pre_entrypoint_syscalls)
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
    def test_lock_reader_ignores_atime_but_rejects_identity_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            raw = runtime.LOCK.read_bytes()
            path.write_bytes(raw)
            metadata = path.stat()
            fields = {
                name: getattr(metadata, name)
                for name in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            }
            before = SimpleNamespace(**fields, st_atime_ns=1)
            after_atime = SimpleNamespace(**fields, st_atime_ns=2)
            with mock.patch.object(
                runtime.os, "fstat", side_effect=(before, after_atime)
            ):
                self.assertEqual(runtime._read_lock(path, "test"), raw)

            after_change = SimpleNamespace(
                **{**fields, "st_mtime_ns": fields["st_mtime_ns"] + 1},
                st_atime_ns=2,
            )
            with (
                mock.patch.object(
                    runtime.os, "fstat", side_effect=(before, after_change)
                ),
                self.assertRaisesRegex(
                    runtime.GVisorRuntimeError, "lock changed while read"
                ),
            ):
                runtime._read_lock(path, "test")

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
                _LIVE_ARTIFACT_PINS,
                runtime.ARTIFACT_SCHEMA,
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
                _LIVE_ARTIFACT_PINS
                | {
                    "expected_verifier_implementation_digest": (
                        _BOUNDED_LIVE_ARTIFACT_IMPLEMENTATION_DIGEST
                    )
                },
                runtime.ARTIFACT_SCHEMA,
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
                _LIVE_ARTIFACT_PINS
                | {
                    "expected_verifier_implementation_digest": (
                        _LIVE_ARTIFACT_V2_IMPLEMENTATION_DIGEST
                    ),
                    "expected_normalization_profile": (
                        runtime.ARTIFACT_NORMALIZATION_PROFILE
                    ),
                },
                runtime.ARTIFACT_SCHEMA_V2,
            ),
            (
                (
                    "phase2-gvisor-acquired-artifact-v3-"
                    f"{_LIVE_ARTIFACT_V3_RUN_ID}-2026-08-02"
                ),
                _LIVE_ARTIFACT_V3_RUN_ID,
                _LIVE_ARTIFACT_V3_RECEIPT_DIGEST,
                _LIVE_ARTIFACT_V3_HANDOFF_DIGEST,
                _LIVE_ARTIFACT_V3_ARCHIVE_SHA256,
                _LIVE_ARTIFACT_V3_PINS,
                runtime.ARTIFACT_SCHEMA_V3,
            ),
        )
        for case in cases:
            (
                stem,
                run_id,
                receipt_digest,
                handoff_digest,
                archive_sha256,
                pins,
                expected_schema,
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
                    closure = runtime.derive_gvisor_acquired_artifact_closure(
                        cas,
                        receipt_digest,
                        **pins,
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
                    )
                    self.assertEqual(receipt["run_id"], run_id)
                    self.assertEqual(receipt["status"], "RECORDED")
                    self.assertEqual(receipt["schema"], expected_schema)
                    if expected_schema == runtime.ARTIFACT_SCHEMA_V2:
                        self.assertEqual(
                            receipt["normalization_profile"],
                            pins["expected_normalization_profile"],
                        )
                        v1_pins = dict(pins)
                        v1_pins.pop("expected_normalization_profile")
                        for action in (
                            runtime.verify_gvisor_acquired_artifact,
                            runtime.derive_gvisor_acquired_artifact_closure,
                        ):
                            with self.assertRaises(runtime.GVisorRuntimeError):
                                action(cas, receipt_digest, **v1_pins)
                            with self.assertRaises(runtime.GVisorRuntimeError):
                                action(
                                    cas,
                                    receipt_digest,
                                    **(
                                        pins
                                        | {
                                            "expected_execution_profile": (
                                                runtime.ARTIFACT_EXECUTION_PROFILE
                                            ),
                                            "expected_entrypoint_path": "run.sh",
                                            "expected_declared_capabilities": (),
                                        }
                                    ),
                                )
                    if expected_schema == runtime.ARTIFACT_SCHEMA_V3:
                        capability_receipt = json.loads(
                            cas.read(receipt["capability_diff_receipt_digest"])
                        )
                        capability_diff = json.loads(
                            cas.read(capability_receipt["capability_diff_digest"])
                        )
                        self.assertEqual(
                            capability_diff["matched_capabilities"],
                            ["file-read", "process-exec"],
                        )
                        self.assertEqual(
                            capability_diff["undeclared_observed_capabilities"],
                            ["file-write"],
                        )
                        execution_pins = {
                            "expected_execution_profile",
                            "expected_entrypoint_path",
                            "expected_declared_capabilities",
                        }
                        for removed in (
                            execution_pins | {"expected_normalization_profile"},
                            execution_pins,
                        ):
                            legacy_pins = {
                                key: value
                                for key, value in pins.items()
                                if key not in removed
                            }
                            for action in (
                                runtime.verify_gvisor_acquired_artifact,
                                runtime.derive_gvisor_acquired_artifact_closure,
                            ):
                                with self.assertRaises(runtime.GVisorRuntimeError):
                                    action(cas, receipt_digest, **legacy_pins)
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

    def test_v4_and_v5_acquired_artifact_bind_attributed_replay(self) -> None:
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
                entrypoint_executable=historical["entrypoint"]["executable"],
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

            normalization_profile = runtime.ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE
            attributed = runtime._parse_attributed_artifact_trace(
                boot,
                runtime_lock,
                canary_lock,
                container_id,
                artifact=artifact,
            )
            source_events = attributed.subject_source_events
            attribution_manifest_digest = cas.put(
                BytesIO(attributed.manifest),
                max_bytes=runtime._MAX_ATTRIBUTION_MANIFEST_BYTES,
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
            self.assertEqual(
                json.loads(cas.read(run_request_digest))["schema"],
                runtime.ARTIFACT_RUN_REQUEST_SCHEMA_V4,
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
                "schema": runtime.ARTIFACT_SCHEMA_V4,
                "authority": runtime.ARTIFACT_AUTHORITY_V4,
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
                "attribution_manifest_digest": attribution_manifest_digest,
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
            self.assertEqual(
                cas.read(receipt["attribution_manifest_digest"]),
                attributed.manifest,
            )
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
            self.assertIn(attribution_manifest_digest, closure)
            changed_receipt = receipt | {
                "attribution_manifest_digest": cas.put(
                    BytesIO(b"{}"),
                    max_bytes=runtime._MAX_ATTRIBUTION_MANIFEST_BYTES,
                )
            }
            changed_receipt_digest = cas.put(
                BytesIO(canonical_json(changed_receipt)),
                max_bytes=runtime._MAX_RECEIPT_BYTES,
            )
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime.verify_gvisor_acquired_artifact(
                    cas, changed_receipt_digest, **pins
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

            scenario = replace(
                artifact,
                execution_profile=runtime.ARTIFACT_EXECUTION_PROFILE_V2,
                scenario_id="primary",
            )
            scenario_evidence = dict(evidence)
            scenario_profile = runtime._artifact_profile(canary_lock, scenario)
            for name in (
                "container_pre_inspect",
                "container_live_inspect",
                "container_post_inspect",
            ):
                document = json.loads(scenario_evidence[name])
                document[0]["Config"]["Env"] = scenario_profile["environment"]
                scenario_evidence[name] = canonical_json(document)
            scenario_log_manifest = json.loads(
                scenario_evidence["backend_log_manifest"]
            )
            scenario_boot = _canary_trace(
                container_id,
                artifact=True,
                artifact_profile=scenario,
            )
            scenario_boot_digest = cas.put(
                BytesIO(scenario_boot),
                max_bytes=canary_lock["trace"]["max_log_bytes"],
            )
            scenario_boot_entry = next(
                item
                for item in scenario_log_manifest["files"]
                if item["command"] == "boot"
            )
            scenario_boot_entry["file"]["digest"] = scenario_boot_digest
            scenario_boot_entry["file"]["size"] = len(scenario_boot)
            scenario_evidence["backend_log_manifest"] = canonical_json(
                scenario_log_manifest
            )
            scenario_attributed = runtime._parse_attributed_artifact_trace(
                scenario_boot,
                runtime_lock,
                canary_lock,
                container_id,
                artifact=scenario,
            )
            scenario_attribution_digest = cas.put(
                BytesIO(scenario_attributed.manifest),
                max_bytes=runtime._MAX_ATTRIBUTION_MANIFEST_BYTES,
            )
            scenario_run_request_digest = cas.put(
                BytesIO(
                    runtime._artifact_run_request(
                        runtime_lock,
                        canary_lock,
                        scenario,
                        run_id=historical["run_id"],
                        container_id=container_id,
                        implementation_digest=implementation_digest,
                        normalization_profile=normalization_profile,
                    )
                ),
                max_bytes=runtime._MAX_CANARY_RUN_REQUEST_BYTES,
            )
            self.assertEqual(
                json.loads(cas.read(scenario_run_request_digest))["schema"],
                runtime.ARTIFACT_RUN_REQUEST_SCHEMA_V5,
            )
            scenario_identity = runtime._artifact_identity(
                scenario,
                scenario_run_request_digest,
                implementation_digest,
            )
            scenario_observations = {}
            for source_event in scenario_attributed.subject_source_events:
                observation_digest = retain_detonation_observation(
                    cas,
                    source_event,
                    **scenario_identity,
                )
                scenario_observations[observation_digest] = runtime._raw_digest(
                    source_event
                )
            scenario_diff_digest = retain_detonation_capability_diff(
                cas,
                scenario_observations,
                **scenario_identity,
                declared_capabilities=scenario.declared_capabilities,
            )
            scenario_receipt = receipt | {
                "schema": runtime.ARTIFACT_SCHEMA_V5,
                "authority": runtime.ARTIFACT_AUTHORITY_V5,
                **scenario_identity,
                "capability_diff_receipt_digest": scenario_diff_digest,
                "evidence": {
                    name: cas.put(
                        BytesIO(raw),
                        max_bytes=runtime._ARTIFACT_EVIDENCE_LIMITS[name],
                    )
                    for name, raw in sorted(scenario_evidence.items())
                },
                "execution_profile": runtime.ARTIFACT_EXECUTION_PROFILE_V2,
                "scenario_id": "primary",
                "attribution_manifest_digest": scenario_attribution_digest,
            }
            scenario_receipt_digest = cas.put(
                BytesIO(canonical_json(scenario_receipt)),
                max_bytes=runtime._MAX_RECEIPT_BYTES,
            )
            scenario_pins = pins | {
                "expected_execution_profile": (
                    runtime.ARTIFACT_EXECUTION_PROFILE_V2
                ),
                "expected_scenario_id": "primary",
            }
            self.assertEqual(
                runtime.verify_gvisor_acquired_artifact(
                    cas,
                    scenario_receipt_digest,
                    **scenario_pins,
                ),
                scenario_receipt,
            )
            scenario_closure = runtime.derive_gvisor_acquired_artifact_closure(
                cas,
                scenario_receipt_digest,
                **scenario_pins,
            )
            self.assertIn(scenario_attribution_digest, scenario_closure)
            for changed in (
                {"expected_scenario_id": None},
                {"expected_scenario_id": "alternate"},
            ):
                for action in (
                    runtime.verify_gvisor_acquired_artifact,
                    runtime.derive_gvisor_acquired_artifact_closure,
                ):
                    with self.assertRaises(runtime.GVisorRuntimeError):
                        action(
                            cas,
                            scenario_receipt_digest,
                            **(scenario_pins | changed),
                        )

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

    def test_canary_log_accepts_adjacent_complete_records_only(self) -> None:
        _raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
        trace = _canary_trace()
        lines = trace.splitlines(keepends=True)
        joined = b"".join(line[:-1] for line in lines) + b"\n"
        doubled = lines[0][:-1] + lines[1] + b"\n" + b"".join(lines[2:])
        expected = runtime._canary_log_records(trace, canary_lock, "boot")
        for raw in (joined, doubled):
            self.assertEqual(
                runtime._canary_log_records(raw, canary_lock, "boot"), expected
            )
        for separator in (b" ", b"garbage"):
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._canary_log_records(
                    lines[0][:-1] + separator + b"".join(lines[1:]),
                    canary_lock,
                    "boot",
                )
        invalid_json = (
            lines[0].replace(b'"msg":', b'"msg":"duplicate","msg":', 1),
            lines[0].replace(b'"level":"info"', b'"level":NaN', 1),
        )
        for raw in invalid_json:
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._canary_log_records(raw, canary_lock, "boot")

        short_record = copy.deepcopy(canary_lock)
        short_record["trace"]["max_line_bytes"] = len(lines[0]) - 2
        too_few_records = copy.deepcopy(canary_lock)
        too_few_records["trace"]["max_log_lines"] = len(lines) - 1
        for lock in (short_record, too_few_records):
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._canary_log_records(joined, lock, "boot")

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
            entrypoint_executable=True,
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
            entrypoint_executable=True,
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
        for flags in (
            b"O_RDWR|O_CLOEXEC",
            b"O_RDONLY|O_TRUNC",
            b"O_RDONLY|O_CREAT",
            b"O_RDONLY|O_PATH",
            b"O_RDONLY|O_UNKNOWN",
        ):
            changed_traces.append(
                generalized_trace.replace(b"O_RDONLY|O_CLOEXEC", flags)
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

        scenario = replace(
            generalized,
            execution_profile=runtime.ARTIFACT_EXECUTION_PROFILE_V2,
            scenario_id="primary",
        )
        scenario_profile = runtime._artifact_profile(canary_lock, scenario)
        self.assertEqual(
            scenario_profile["environment"],
            ["PATH=/bin", "ARAGORN_SCENARIO=primary"],
        )
        self.assertEqual(
            runtime._artifact_profile(
                canary_lock,
                replace(scenario, scenario_id="alternate"),
            )["environment"],
            ["PATH=/bin", "ARAGORN_SCENARIO=alternate"],
        )
        create_arguments = runtime._create_arguments(
            image="busybox@sha256:" + "8" * 64,
            profile=scenario_profile,
            runtime="runsc-systrap-canary",
            container_name="aragorn-scenario",
            run_label="aragorn.acquired-artifact.run_id=" + _RUN_ID,
        )
        self.assertEqual(
            [
                create_arguments[index + 1]
                for index, value in enumerate(create_arguments)
                if value == "--env"
            ],
            scenario_profile["environment"],
        )
        request_v5 = json.loads(
            runtime._artifact_run_request(
                runtime_lock,
                canary_lock,
                scenario,
                run_id=_RUN_ID,
                container_id=_CONTAINER_ID,
                implementation_digest="sha256:" + "7" * 64,
                normalization_profile=(
                    runtime.ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE
                ),
            )
        )
        self.assertEqual(
            request_v5["schema"], runtime.ARTIFACT_RUN_REQUEST_SCHEMA_V5
        )
        self.assertEqual(request_v5["scenario_id"], "primary")
        scenario_trace = _canary_trace(artifact=True, artifact_profile=scenario)
        runtime._parse_attributed_artifact_trace(
            scenario_trace,
            runtime_lock,
            canary_lock,
            _CONTAINER_ID,
            artifact=scenario,
        )
        self.assertTrue(
            runtime._artifact_exec_environment(
                [
                    "ARAGORN_SCENARIO=primary",
                    "PWD=/",
                    "PATH=/bin",
                    "HOME=/home",
                    "SHLVL=1",
                    f"HOSTNAME={_CONTAINER_ID[:12]}",
                ],
                _CONTAINER_ID,
                scenario_id="primary",
            )
        )
        with self.assertRaises(runtime.GVisorRuntimeError):
            runtime._parse_attributed_artifact_trace(
                scenario_trace.replace(
                    b"ARAGORN_SCENARIO=primary",
                    b"ARAGORN_SCENARIO=alternate",
                ),
                runtime_lock,
                canary_lock,
                _CONTAINER_ID,
                artifact=scenario,
            )
        for changed in (
            replace(scenario, scenario_id="other"),
            replace(generalized, scenario_id="primary"),
        ):
            with self.assertRaises(runtime.GVisorRuntimeError):
                runtime._artifact_profile(canary_lock, changed)

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

    def test_attributed_script_excludes_non_subject_events_from_diff(self) -> None:
        _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
        _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
        artifact = runtime._AcquiredArtifact(
            quarantine_receipt_digest="sha256:" + "1" * 64,
            gateway_profile_digest="sha256:" + "2" * 64,
            source_closure_digest="sha256:" + "3" * 64,
            manifest_digest="sha256:" + "4" * 64,
            tree_digest="sha256:" + "5" * 64,
            entrypoint_path="scripts/check.sh",
            entrypoint_digest="sha256:" + "6" * 64,
            entrypoint_size=80,
            entrypoint_executable=True,
            execution_profile=runtime.ARTIFACT_EXECUTION_PROFILE,
            declared_capabilities=("file-read", "process-exec"),
            materialized_path=Path("/run/aragorn-gvisor-artifact/run.sh"),
        )
        null_write = "AT_FDCWD /, 0x444 /dev/null, O_WRONLY, 0o0"
        unknown_write = "AT_FDCWD /, 0x555 /tmp/other, O_WRONLY, 0o0"
        attributed = runtime._parse_attributed_artifact_trace(
            _canary_trace(
                artifact=True,
                artifact_profile=artifact,
                pre_entrypoint_syscalls=(
                    f"strace.go:571] [   2:   2] sh E openat({null_write})",
                    (
                        f"strace.go:609] [   2:   2] sh X openat({null_write}) "
                        "= 3 (0x3) (2.1µs)"
                    ),
                ),
                extra_syscalls=(
                    f"strace.go:572] [   4:   4] other E openat({unknown_write})",
                    (
                        f"strace.go:610] [   4:   4] other X openat({unknown_write}) "
                        "= 3 (0x3) (2.1µs)"
                    ),
                ),
            ),
            runtime_lock,
            canary_lock,
            _CONTAINER_ID,
            artifact=artifact,
        )
        manifest = json.loads(attributed.manifest)
        self.assertEqual(attributed.manifest, canonical_json(manifest))
        self.assertEqual(manifest["schema"], runtime.ARTIFACT_ATTRIBUTION_SCHEMA)
        self.assertEqual(
            manifest["normalization_profile"],
            runtime.ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE,
        )
        self.assertEqual(
            [event["sequence"] for event in manifest["events"]],
            list(range(len(manifest["events"]))),
        )
        self.assertEqual(
            [(event["scope"], event["tgid"], event["tid"]) for event in manifest["events"] if event["operation"] == "file-open-write"],
            [("harness", 2, 2), ("unknown", 4, 4)],
        )
        subject = [
            event for event in manifest["events"] if event["scope"] == "subject"
        ]
        entrypoint = [
            event for event in manifest["events"] if event["scope"] == "entrypoint"
        ]
        self.assertEqual(len(entrypoint), 1)
        self.assertEqual(entrypoint[0]["operation"], "process-exec")
        self.assertTrue(subject)
        self.assertTrue(
            all(
                (event["tgid"], event["tid"])
                == (manifest["boundary"]["tgid"], manifest["boundary"]["tid"])
                and event["entered_record"]
                > manifest["boundary"]["exited_record"]
                for event in subject
            )
        )

        identity = {
            "subject_digest": artifact.tree_digest,
            "input_manifest_digest": artifact.manifest_digest,
            "input_tree_digest": artifact.tree_digest,
            "run_request_digest": "sha256:" + "7" * 64,
            "normalizer_implementation_digest": "sha256:" + "8" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            cas = CAS(Path(temporary) / "cas")
            bindings = {}
            for source_event in attributed.subject_source_events:
                observation = retain_detonation_observation(
                    cas, source_event, **identity
                )
                bindings[observation] = (
                    "sha256:" + hashlib.sha256(source_event).hexdigest()
                )
            receipt = json.loads(
                cas.read(
                    retain_detonation_capability_diff(
                        cas,
                        bindings,
                        **identity,
                        declared_capabilities=artifact.declared_capabilities,
                    )
                )
            )
            capability_diff = json.loads(cas.read(receipt["capability_diff_digest"]))
        self.assertEqual(
            capability_diff["matched_capabilities"],
            ["file-read"],
        )
        self.assertEqual(
            capability_diff["declared_not_observed_capabilities"],
            ["process-exec"],
        )
        self.assertEqual(capability_diff["undeclared_observed_capabilities"], [])

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
        non_executable = copy.deepcopy(manifest)
        non_executable["files"][0]["executable"] = False
        self.assertFalse(
            runtime._pinned_artifact_entrypoint(
                non_executable,
                expected_tree_digest=tree,
                expected_path="scripts/check.sh",
                expected_digest=digest,
                expected_executable=None,
            )["executable"]
        )
        with self.assertRaises(runtime.GVisorRuntimeError):
            runtime._pinned_artifact_entrypoint(
                non_executable,
                expected_tree_digest=tree,
                expected_path="scripts/check.sh",
                expected_digest=digest,
                expected_executable=True,
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
                self.assertTrue(artifact.entrypoint_executable)
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

                entrypoint["executable"] = False
                tree_files = [
                    {
                        key: item[key]
                        for key in ("path", "size", "digest", "executable")
                    }
                    for item in files
                ]
                tree_digest = (
                    "sha256:" + hashlib.sha256(canonical_json(tree_files)).hexdigest()
                )
                manifest["tree_digest"] = tree_digest
                raw_manifest = canonical_json(manifest)
                manifest_digest = writable_source.put(
                    BytesIO(raw_manifest),
                    max_bytes=len(raw_manifest),
                )
                expected["expected_manifest_digest"] = manifest_digest
                attributed_arguments = arguments | {
                    "expected_manifest_digest": manifest_digest,
                    "expected_tree_digest": tree_digest,
                    "normalization_profile": (
                        runtime.ARTIFACT_ATTRIBUTED_NORMALIZATION_PROFILE
                    ),
                }
                collect.reset_mock()
                with self.assertRaises(runtime.GVisorRuntimeError):
                    runtime.collect_gvisor_acquired_artifact(
                        output,
                        source,
                        **(
                            attributed_arguments
                            | {
                                "normalization_profile": (
                                    runtime.ARTIFACT_NORMALIZATION_PROFILE
                                )
                            }
                        ),
                    )
                collect.assert_not_called()
                (materialized / "entrypoint").unlink()
                observed = runtime.collect_gvisor_acquired_artifact(
                    output,
                    source,
                    **attributed_arguments,
                )
                self.assertEqual(observed, "sha256:" + "9" * 64)
                attributed_artifact = collect.call_args.kwargs["artifact"]
                self.assertFalse(attributed_artifact.entrypoint_executable)
                self.assertFalse(
                    runtime._artifact_entrypoint(attributed_artifact)["executable"]
                )

                (materialized / "entrypoint").unlink()
                scenario_arguments = attributed_arguments | {
                    "expected_execution_profile": (
                        runtime.ARTIFACT_EXECUTION_PROFILE_V2
                    ),
                    "expected_scenario_id": "primary",
                }
                observed = runtime.collect_gvisor_acquired_artifact(
                    output,
                    source,
                    **scenario_arguments,
                )
                self.assertEqual(observed, "sha256:" + "9" * 64)
                scenario_artifact = collect.call_args.kwargs["artifact"]
                self.assertEqual(
                    scenario_artifact.execution_profile,
                    runtime.ARTIFACT_EXECUTION_PROFILE_V2,
                )
                self.assertEqual(scenario_artifact.scenario_id, "primary")
                for changed in (
                    {"expected_scenario_id": None},
                    {"expected_scenario_id": "other"},
                ):
                    collect.reset_mock()
                    with self.assertRaises(runtime.GVisorRuntimeError):
                        runtime.collect_gvisor_acquired_artifact(
                            output,
                            source,
                            **(scenario_arguments | changed),
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
