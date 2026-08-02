from __future__ import annotations

import copy
import hashlib
import json
import tarfile
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

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


def _canary_trace(container_id: str = _CONTAINER_ID) -> bytes:
    _runtime_raw, runtime_lock = runtime.load_gvisor_runtime_lock()
    _canary_raw, canary_lock = runtime.load_gvisor_detonation_canary_lock()
    command = canary_lock["canary"]["command"]
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
    token = canary_lock["canary"]["token_path"]
    write = f"AT_FDCWD /, 0xaaa {token}, O_WRONLY|O_CREAT|O_TRUNC, 0o666"
    execute = (
        f'0xbbb /bin/sha256sum, 0xccc ["/bin/sha256sum", "{token}"], '
        f"0xddd {environment}"
    )
    read = f"AT_FDCWD /, 0xeee {token}, O_RDONLY|0x0, 0o0"
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
        f"strace.go:570] [   1:   1] sh E openat({write})",
        f"strace.go:608] [   1:   1] sh X openat({write}) = 3 (0x3) (2.1µs)",
        f"strace.go:567] [   2:   2] sh E execve({execute})",
        f"strace.go:605] [   2:   2] sh X execve({execute}) = 0 (0x0) (3µs)",
        f"strace.go:570] [   2:   2] sha256sum E openat({read})",
        (f"strace.go:608] [   2:   2] sha256sum X openat({read}) = 3 (0x3) (2.6µs)"),
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
