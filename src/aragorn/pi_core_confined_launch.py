"""Guarded Pi confinement plan and authenticated bootstrap composition.

This module does NOT start systemd, create sockets, mount a root, stop a process,
or remove activation records. The separate native supervisor owns trusted
MainPID/InvocationID custody, exclusive socket ownership, and cleanup attempts.
A plan is not an installed OS closure or permission to execute its argv.
Bootstrap observations deliberately cannot establish effects, RUN, or cleanup.
"""

from __future__ import annotations

import json
import math
import os
import re
import socket
import stat
import struct
import time
from collections.abc import Callable, Collection, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import runtime_active_skill_lineage as lineage
from .acquire import inventory_open_directory
from .cas import CAS
from .oci_worker_protocol import canonical_digest, canonical_json
from .pi_core_bundle_launch import (
    PreparedPiBundle, bind_pi_worker_activation, hold_prepared_pi_bundle,
)
from .runtime_action_broker import (
    _parse_canonical_document, _receive_exact, _require_digest, _send_frame,
)
from .runtime_process_profile import RuntimeProcessProfile

_ID = re.compile(r"[a-f0-9]{32}\Z")
_UNIT = re.compile(r"aragorn-pi-[a-f0-9]{32}\.service\Z")
_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")
_MAX_FRAME = 64 * 1024
_BOOTSTRAP = "/run/aragorn-pi-bootstrap/bootstrap.sock"
_RUNTIME = "/opt/aragorn/pi-runtime"
_ADMITTED = Path("/var/lib/aragorn/admitted")
_EMPTY_MOUNTPOINTS = ("dev", "proc", "sys", "tmp", "var/tmp",
                     "opt/aragorn/pi-runtime", "run/aragorn-pi-bootstrap",
                     "var/lib/aragorn/admitted")
_RESULT_AUTHORITY = "BOOTSTRAP_STATUS_ONLY_NOT_EFFECT_OR_RUN_AUTHORITY"


class PiConfinedLaunchError(ValueError):
    """The confinement plan or bootstrap contract is not safe to consume."""


@dataclass(frozen=True, slots=True)
class PiConfinedLaunchConfig:
    root_directory: Path
    root_closure_digest: str
    runtime_directory: Path
    compiled_receipt: Mapping
    compiled_receipt_digest: str
    activation_directory: Path
    worker_uid: int
    worker_gid: int
    task: str
    model: Mapping
    limits: Mapping
    relay: Mapping


@dataclass(slots=True)
class _PlanLease:
    active: bool = True
    exchange_attempted: bool = False


@dataclass(frozen=True, slots=True)
class PiConfinedLaunchPlan:
    prepared: PreparedPiBundle
    profile: RuntimeProcessProfile
    worker_uid: int
    worker_gid: int
    unit_name: str
    systemd_run_argv: tuple[str, ...]
    activation_path: Path
    start_bytes: bytes
    deadline: float
    root_closure_digest: str
    runtime_inventory_digest: str
    _lease: _PlanLease = field(repr=False, compare=False)
    authority: str = "GUARDED_PLAN_ONLY_NOT_NATIVE_LAUNCH_OR_CONFINEMENT_PROOF"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PiConfinedLaunchError(message)


def _uint(value: object, minimum: int, maximum: int, label: str) -> None:
    _require(type(value) is int and minimum <= value <= maximum, f"invalid {label}")


def _text(value: object, maximum: int, label: str) -> None:
    try:
        valid = type(value) is str and 0 < len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    _require(valid, f"invalid {label}")


def _exact(value: object, fields: set[str], label: str) -> None:
    _require(isinstance(value, Mapping) and set(value) == fields, f"invalid {label} fields")


def _path(value: object, label: str) -> None:
    _require(isinstance(value, Path) and value.is_absolute() and
             _PATH.fullmatch(str(value)) is not None and
             str(value) != "/" and ".." not in value.parts and
             str(value) == os.path.normpath(str(value)), f"invalid {label} path")


def _deadline(deadline: float) -> None:
    now = time.monotonic()
    _require(type(deadline) in (float, int) and math.isfinite(deadline) and
             now < deadline <= now + 30, "original Pi deadline expired or invalid")


def _start(config: PiConfinedLaunchConfig, prepared: PreparedPiBundle) -> bytes:
    _require(_ID.fullmatch(prepared.activation_id) is not None, "invalid activation ID")
    _text(prepared.system_prompt, 32 * 1024, "system prompt")
    _text(config.task, 32 * 1024, "task")
    _exact(config.limits, {"maxTurns", "maxToolCalls", "maxRunMs"}, "limits")
    for name in ("maxTurns", "maxToolCalls"):
        _uint(config.limits[name], 1, 8, name)
    _uint(config.limits["maxRunMs"], 1, 30_000, "maxRunMs")
    _exact(config.model, {"id", "name", "api", "provider", "baseUrl", "reasoning",
                         "input", "cost", "contextWindow", "maxTokens"}, "model")
    for name in ("id", "name", "api", "provider", "baseUrl"):
        _text(config.model[name], 2048, name)
    _require(type(config.model["reasoning"]) is bool and
             config.model["input"] == ["text"], "only an explicit text model is supported")
    _uint(config.model["contextWindow"], 1, 10_000_000, "contextWindow")
    _uint(config.model["maxTokens"], 1, 1_000_000, "maxTokens")
    _exact(config.model["cost"], {"input", "output", "cacheRead", "cacheWrite"}, "cost")
    for value in config.model["cost"].values():
        _uint(value, 0, 2**53 - 1, "canonical model cost")
    _exact(config.relay, {"expectedGatewayGid", "expectedGatewayUid",
                          "expectedWorkerUid", "workerSocketPath"}, "relay")
    for name in ("expectedGatewayGid", "expectedGatewayUid", "expectedWorkerUid"):
        _uint(config.relay[name], 1, 0xffffffff, name)
    _require(config.relay["expectedGatewayUid"] == config.worker_uid and
             config.relay["expectedGatewayGid"] == config.worker_gid and
             config.relay["expectedWorkerUid"] != config.worker_uid,
             "relay gateway must join the confined worker identity")
    _text(config.relay["workerSocketPath"], 4096, "relay socket")
    socket_path = config.relay["workerSocketPath"]
    _require(_PATH.fullmatch(socket_path) is not None and
             all(part not in ("", ".", "..") for part in socket_path.split("/")[1:]) and
             socket_path != _BOOTSTRAP, "invalid relay socket path")
    raw = canonical_json({
        "schema": "aragorn/pi-core-bootstrap-start/v1",
        "activation_id": prepared.activation_id, "system_prompt": prepared.system_prompt,
        "task": config.task, "model": config.model, "limits": config.limits,
        "relay": config.relay, "provider_status": "UNAVAILABLE",
    })
    _require(len(raw) <= _MAX_FRAME, "bootstrap START exceeds frame limit")
    return raw


def confined_configuration_digest(config: PiConfinedLaunchConfig) -> str:
    """Pin protected launcher expectations, not evidence of installed custody."""
    _require(type(config) is PiConfinedLaunchConfig, "invalid launch configuration")
    return canonical_digest({
        "schema": "aragorn/pi-core-confined-configuration/v1",
        "root_directory": str(config.root_directory),
        "root_closure_digest": config.root_closure_digest,
        "runtime_directory": str(config.runtime_directory),
        "compiled_receipt_digest": config.compiled_receipt_digest,
        "activation_directory": str(config.activation_directory),
        "worker_uid": config.worker_uid, "worker_gid": config.worker_gid,
        "task": config.task, "model": config.model, "limits": config.limits,
        "relay": config.relay, "provider_status": "UNAVAILABLE",
    })


def _tree(directory_fd: int) -> tuple[dict, tuple[str, ...], str]:
    """Complete bounded bytes plus root-owned immutable descendant metadata."""
    manifest, directories = inventory_open_directory(directory_fd, max_depth=32,
        max_files=30_000, max_file_size=256 * 1024 * 1024,
        max_total_bytes=512 * 1024 * 1024)
    # Inventory already refuses links/special nodes and detects concurrent
    # mutation. Reopen only descriptor-relative protected directories; workers
    # cannot write or replace any member after this measurement.
    def parent(parts: list[str]) -> int:
        descriptor = os.dup(directory_fd)
        try:
            for part in parts:
                child = lineage._open_directory_at(descriptor, part, 0, 0o555, "Pi immutable directory")
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    for name in directories:
        descriptor = parent(name.split("/"))
        os.close(descriptor)
    for entry in manifest["files"]:
        parts = entry["path"].split("/")
        descriptor = parent(parts[:-1])
        try:
            observed = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            mode = 0o555 if entry["executable"] else 0o444
            _require(stat.S_ISREG(observed.st_mode) and observed.st_uid == 0 and
                     observed.st_nlink == 1 and stat.S_IMODE(observed.st_mode) == mode,
                     "Pi installed member is not root-owned and immutable")
        finally:
            os.close(descriptor)
    closure = canonical_digest({"schema": "aragorn/pi-core-protected-tree/v1",
        "files": manifest["files"], "directories": list(directories)})
    return manifest, directories, closure


def _runtime_inventory(manifest: Mapping, receipt: Mapping, receipt_digest: str) -> str:
    _require(canonical_digest(receipt) == receipt_digest, "compiled receipt pin mismatch")
    _require(receipt.get("schema") == "aragorn/pi-core-linux-build/v1" and
             receipt.get("status") == "COMPILED_NOT_DEPLOYED_OR_OS_QUALIFIED" and
             receipt.get("target") == "linux-arm64-glibc" and
             receipt.get("node_version") == "24.22.2" and
             receipt.get("typescript_version") == "7.0.2" and
             receipt.get("runtime_executed") is False and
             receipt.get("install_scripts_executed") is False,
             "unsupported compiled deployment receipt")
    inventory = [{"path": entry["path"], "kind": "file", "bytes": entry["size"],
                  "sha256": entry["digest"][7:]} for entry in manifest["files"]]
    digest = canonical_digest(inventory)
    _require(inventory == receipt.get("deployment_inventory") and
             digest == "sha256:" + str(receipt.get("deployment_tree_sha256")),
             "compiled inventory differs from installed bytes")
    files = {entry["path"]: entry for entry in manifest["files"]}
    required = {"node/bin/node", "pi-core/worker.js", "pi-core/entrypoint.js",
                "pi-core/package.json", "openclaw/aragorn-runtime-action-worker/index.js",
                "openclaw/aragorn-runtime-action-worker/package.json"}
    _require(required.issubset(files) and files["node/bin/node"]["executable"] and
             any(name.startswith("pi-core/node_modules/") for name in files),
             "compiled runtime layout is incomplete")
    return digest


def _systemd_plan(config: PiConfinedLaunchConfig, prepared: PreparedPiBundle,
                  profile: RuntimeProcessProfile) -> tuple[str, tuple[str, ...]]:
    # The protected supervisor must choose a fresh unit identifier BEFORE
    # preparing the process profile. It differs from the admission activation.
    unit = profile.cgroup.removeprefix("/system.slice/")
    _require(_UNIT.fullmatch(unit) is not None and profile.cgroup == "/system.slice/" + unit,
             "profile must name one fresh dedicated system service cgroup")
    _path(prepared.skill_path, "immutable skill")
    bundle = str(prepared.skill_path.parent)
    properties = (
        "Type=exec", "Restart=no", "KillMode=control-group", "SendSIGKILL=yes",
        "Delegate=no", "NoNewPrivileges=yes", "CapabilityBoundingSet=",
        "AmbientCapabilities=", "SupplementaryGroups=", "UMask=0077",
        "PrivateDevices=yes", "PrivateIPC=yes", "PrivateMounts=yes",
        "PrivateNetwork=yes", "PrivateTmp=yes", "ProtectSystem=strict",
        "ProtectHome=yes", "ProtectControlGroups=yes", "ProtectKernelModules=yes",
        "ProtectKernelTunables=yes", "ProtectKernelLogs=yes", "ProtectClock=yes",
        "ProtectHostname=yes", "ProtectProc=invisible", "ProcSubset=pid",
        "RestrictAddressFamilies=AF_UNIX", "RestrictSUIDSGID=yes", "LockPersonality=yes",
        "SystemCallArchitectures=native", "RestrictNamespaces=yes", "TasksMax=64",
        "MemoryMax=1G", "RuntimeMaxSec=30", "TimeoutStopSec=5",
        "StandardInput=null", "StandardOutput=null", "StandardError=null",
        "BindLogSockets=no", "LogNamespace=",
        "User=" + str(config.worker_uid), "Group=" + str(config.worker_gid),
        "RootDirectory=" + str(config.root_directory),
        # Per-context destination paths are created inside this private tmpfs,
        # never by mutating the pinned OS tree. Only this version is exposed.
        "TemporaryFileSystem=" + str(_ADMITTED) + ":ro",
        "WorkingDirectory=" + bundle,
        "BindReadOnlyPaths=" + str(config.runtime_directory) + ":" + _RUNTIME,
        "BindReadOnlyPaths=" + bundle + ":" + bundle,
        "BindReadOnlyPaths=/run/aragorn-pi-bootstrap:/run/aragorn-pi-bootstrap",
        # Neither the legacy action relay nor host credentials are mounted.
        # Explicitly mask the configured endpoint even if an OS closure contains it.
        # PrivateDevices still projects shared-memory/hugepage endpoints from
        # the host. This bootstrap has no POSIX-shm, hugepage or PTY authority.
        "InaccessiblePaths=-" + config.relay["workerSocketPath"] +
        " -/dev/shm -/dev/hugepages -/dev/pts",
    )
    argv = ("/usr/bin/systemd-run", "--quiet", "--no-block", "--unit=" + unit,
            *("--property=" + value for value in properties), "--",
            "/usr/bin/env", "-i", "HOME=/nonexistent", "PATH=" + _RUNTIME + "/node/bin",
            _RUNTIME + "/node/bin/node", _RUNTIME + "/pi-core/entrypoint.js")
    return unit, argv


def _require_empty_mountpoints(manifest: Mapping, directories: tuple[str, ...]) -> None:
    for mountpoint in _EMPTY_MOUNTPOINTS:
        _require(mountpoint in directories and
                 not any(entry["path"] == mountpoint or entry["path"].startswith(mountpoint + "/")
                         for entry in manifest["files"]) and
                 not any(name.startswith(mountpoint + "/") for name in directories),
                 "protected OS closure lacks an empty fixed mountpoint")


@contextmanager
def hold_confined_pi_launch_plan(
    cas: CAS, context: Mapping, *, profile: RuntimeProcessProfile, grant: Mapping,
    protected_root: Path, runtime_conformance_digest: str, deployment: Mapping,
    revoked_context_ids: Collection[str], now_unix: int, deadline: float,
    config: PiConfinedLaunchConfig,
) -> Iterator[PiConfinedLaunchPlan]:
    """Hold admission and installed descriptors for an inert confinement plan.

    Does not provision anything. Missing OS closure or installed protected files
    fail before a plan is yielded. Executing the argv requires a separate native
    supervisor; there is intentionally no launch facade or injected spawn hook.
    """
    _require(os.geteuid() == 0, "confined Pi planning requires the protected supervisor")
    _deadline(deadline)
    _require(type(config) is PiConfinedLaunchConfig, "invalid launch configuration")
    for name in ("root_directory", "runtime_directory", "activation_directory"):
        _path(getattr(config, name), name)
    _path(protected_root, "admitted bundle root")
    _require(protected_root == _ADMITTED, "native Pi profile requires the fixed admitted root")
    roots = (config.root_directory, config.runtime_directory, config.activation_directory)
    all_roots = (*roots, protected_root)
    _require(all(not a.is_relative_to(b) for a in all_roots for b in all_roots if a != b) and
             len(set(all_roots)) == 4, "Pi control, runtime, OS, and admitted roots overlap")
    _uint(config.worker_uid, 1, 0xffffffff, "worker UID")
    _uint(config.worker_gid, 1, 0xffffffff, "worker GID")
    _require_digest(config.root_closure_digest, "OS root closure")
    _require_digest(config.compiled_receipt_digest, "compiled receipt")
    # Snapshot mutable objects once; they may not redefine the trusted closure
    # after admission. Task/model are data and never become command arguments.
    config = PiConfinedLaunchConfig(**{
        **{name: getattr(config, name) for name in config.__dataclass_fields__},
        **{name: json.loads(canonical_json(getattr(config, name)))
           for name in ("compiled_receipt", "model", "limits", "relay")},
    })
    pins = json.loads(canonical_json(deployment))
    _require(pins.get("os_profile") == config.root_closure_digest and
             pins.get("configuration") == confined_configuration_digest(config),
             "OS root and launcher configuration are not deployment-bound")
    descriptors: list[int] = []
    lease = _PlanLease()
    try:
        with hold_prepared_pi_bundle(cas, context, profile=profile, grant=grant,
                protected_root=protected_root, runtime_conformance_digest=runtime_conformance_digest,
                deployment=pins, revoked_context_ids=revoked_context_ids, now_unix=now_unix,
                deadline=deadline) as prepared:
            start = _start(config, prepared)
            for root in roots:
                descriptors.append(lineage._open_protected_root(root, 0))
            os_manifest, os_directories, os_digest = _tree(descriptors[0])
            runtime_manifest, _, _ = _tree(descriptors[1])
            _require(os_digest == config.root_closure_digest, "protected OS closure differs")
            _require_empty_mountpoints(os_manifest, os_directories)
            os_files = {entry["path"]: entry for entry in os_manifest["files"]}
            _require("usr/bin/env" in os_files and os_files["usr/bin/env"]["executable"],
                     "pinned OS closure lacks the credential-free env entrypoint")
            runtime_digest = _runtime_inventory(runtime_manifest, config.compiled_receipt,
                                                config.compiled_receipt_digest)
            node = next(entry for entry in runtime_manifest["files"] if entry["path"] == "node/bin/node")
            _require(runtime_digest == profile.runtime_digest == pins["runtime_commit_or_image"] and
                     node["digest"] == profile.executable_digest,
                     "compiled runtime and Node executable are not process-profile-bound")
            unit, argv = _systemd_plan(config, prepared, profile)
            _deadline(deadline)
            yield PiConfinedLaunchPlan(prepared, profile, config.worker_uid, config.worker_gid,
                unit, argv, config.activation_directory / (prepared.activation_id + ".json"),
                start, deadline, os_digest, runtime_digest, lease)
    finally:
        lease.active = False
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _read_bootstrap(connection: socket.socket, deadline: float) -> dict:
    # Existing _read_frame requires EOF; this multi-turn channel deliberately
    # reuses its bounded receiver/parser without requiring EOF after HELLO.
    (length,) = struct.unpack("!I", _receive_exact(connection, 4, deadline))
    _require(0 < length <= _MAX_FRAME, "invalid bootstrap frame size")
    raw = _receive_exact(connection, length, deadline)
    return _parse_canonical_document(raw, "Pi bootstrap")


def exchange_prepared_pi_bootstrap(plan: PiConfinedLaunchPlan,
                                  connection: socket.socket, *, expected_pid: int,
                                  on_activation: Callable[[dict], None] | None = None,
                                  on_before_release: Callable[[], None] | None = None) -> dict:
    """Bind an already-launched child and exchange only provider-unavailable status.

    Caller must supply its trusted MainPID and the accepted post-exec socket;
    bind_pi_worker_activation authenticates peer credentials/PIDFD/profile. The
    caller retains process ownership and MUST subsequently withdraw the exact
    published activation and verify process/unit cleanup. This function never
    claims either cleanup or delivery of model/effect work, including on error.
    A failed bind/exchange cannot be retried with this plan. The optional local
    supervisor callback takes custody of the published document before START;
    it is never supplied by the worker or serialized onto the channel.
    """
    _require(os.geteuid() == 0, "Pi bootstrap requires the protected supervisor")
    _require(type(plan) is PiConfinedLaunchPlan and plan._lease.active and
             not plan._lease.exchange_attempted, "Pi launch plan is inactive or already consumed")
    _require(on_activation is None or callable(on_activation), "invalid local activation observer")
    _require(on_before_release is None or callable(on_before_release), "invalid local prerelease observer")
    plan._lease.exchange_attempted = True
    _uint(expected_pid, 1, 0xffffffff, "trusted child PID")
    _deadline(plan.deadline)
    _require(plan.prepared._lease.active and
             time.monotonic_ns() < plan.prepared.expires_at_monotonic_ns,
             "Pi admitted preparation is no longer active")
    deadline = min(plan.deadline, plan.prepared.expires_at_monotonic_ns / 1_000_000_000)
    hello = _read_bootstrap(connection, deadline)
    _exact(hello, {"schema", "worker_nonce"}, "HELLO")
    _require(hello["schema"] == "aragorn/pi-core-bootstrap-hello/v1" and
             type(hello["worker_nonce"]) is str and _ID.fullmatch(hello["worker_nonce"]) is not None,
             "invalid Pi bootstrap HELLO")
    activation = bind_pi_worker_activation(plan.prepared, connection, expected_pid=expected_pid,
        expected_uid=plan.worker_uid, expected_gid=plan.worker_gid, profile=plan.profile,
        activation_path=plan.activation_path)
    if on_activation is not None:
        on_activation(json.loads(canonical_json(activation)))
    _send_frame(connection, plan.start_bytes, deadline)
    result = _read_bootstrap(connection, deadline)
    expected = {"schema": "aragorn/pi-core-bootstrap-result/v1",
                "activation_id": plan.prepared.activation_id,
                "status": "PROVIDER_UNAVAILABLE", "authority": _RESULT_AUTHORITY}
    _require(result == expected, "unexpected Pi bootstrap result; no effect authority is supported")
    # Protected identity registration must be revoked while the authenticated
    # worker is still alive, before RELEASE permits its expected exit.
    if on_before_release is not None:
        on_before_release()
    _send_frame(connection, canonical_json({"schema": "aragorn/pi-core-bootstrap-release/v1",
        "activation_id": plan.prepared.activation_id}), deadline)
    return {"schema": "aragorn/pi-core-bootstrap-observation/v1", "authority": _RESULT_AUTHORITY,
            "activation_digest": canonical_digest(activation), "result": result,
            "release_sent": True, "process_exit_observed": False,
            "activation_withdrawn": False, "native_cleanup_verified": False}
