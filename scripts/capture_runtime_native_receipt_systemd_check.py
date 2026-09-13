"""Capture one owned native read/create fixture; never deploy on the host."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_quarantine_systemd_check as previous
from scripts import stage_runtime_native_receipt_profile as stage

existing = previous.existing
acquisition = existing.existing.acquisition
snapshot = existing.parent_snapshot
_IMAGE = existing._IMAGE
_VOLUME = "aragorn-native-cache-runtime-79ed6eb-v1"
# Expected provisioning policy, not a previously retained volume-inspect claim.
_VOLUME_POLICY = {
    "Name": _VOLUME,
    "Driver": "local",
    "Scope": "local",
    "Options": None,
    "Labels": {"dev.aragorn.capture-owner": "native-cache-build-79ed6eb-v1"},
}
_BUILD = (
    "benchmark/evidence/phase3-native-tool-runtime-build-development-v2-2026-09-13.json"
)
_BUILD_PIN = (
    40591,
    "sha256:a1d302431804f760299e1bcbd16aa269214ce0f35e2b8996c9f0cd3d03658877",
)
_CHECKER = "scripts/runtime_native_receipt_systemd_check.py"
_FILES = {
    **previous._FILES,
    "scripts/runtime_endpoint_journal_systemd_check.py": "/opt/aragorn/runtime_endpoint_journal_systemd_check.py",
    _CHECKER: "/opt/aragorn/runtime-native-receipt-systemd-check.py",
    "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs": "/opt/aragorn/native-receipt-read-create-driver-v1.mjs",
}
_DIRECTORY_HANDOFF = r"""
directories=json.loads(sys.argv[3])
copied_owner=json.loads(sys.argv[4])
expected_dirs={str(p) for v in expected.values() if v['installed_path'].startswith('/usr/') for p in Path(v['installed_path']).parents if p!=Path('/')}
if type(copied_owner) is not list or len(copied_owner)!=2 or any(type(n) is not int or not 0<=n<=0xffffffff for n in copied_owner):
 raise RuntimeError('invalid copied directory owner')
if type(directories) is not list or len(directories)!=13 or len(set(directories))!=13 or set(directories)!=expected_dirs:
 raise RuntimeError('staged directory inventory changed')
fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
identity=lambda s: tuple(getattr(s,k) for k in fields)
held=[]; parents={}; final=[]
try:
 for name in ['/',*sorted(directories,key=lambda n:(len(Path(n).parts),n))]:
  p=Path(name)
  if not p.is_absolute() or str(p)!=name or '..' in p.parts:
   raise RuntimeError('noncanonical staged directory')
  parent=None if name=='/' else parents[str(p.parent)]
  leaf='/' if name=='/' else p.name
  before=os.stat(leaf,dir_fd=parent,follow_symlinks=False)
  if not stat.S_ISDIR(before.st_mode) or stat.S_IMODE(before.st_mode)!=0o755 or (before.st_uid,before.st_gid) not in ((0,0),tuple(copied_owner)) or (name=='/' and (before.st_uid,before.st_gid)!=(0,0)):
   raise RuntimeError('staged directory custody changed')
  fd=os.open(leaf,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  held.append(fd); parents[name]=fd
  if identity(before)!=identity(os.fstat(fd)):
   raise RuntimeError('staged directory changed before handoff')
  if name!='/': os.fchown(fd,0,0)
  after=os.fstat(fd)
  if (after.st_uid,after.st_gid)!=(0,0) or any(getattr(before,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns')):
   raise RuntimeError('staged directory handoff changed identity')
  os.fsync(fd)
  final.append((parent,leaf,fd,identity(after)))
 for parent,leaf,fd,expected_identity in final:
  if identity(os.fstat(fd))!=expected_identity or identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False))!=expected_identity:
   raise RuntimeError('staged directory changed after handoff')
finally:
 close_error=None
 for fd in reversed(held):
  try: os.close(fd)
  except OSError as exc: close_error=close_error or exc
 if close_error is not None: raise RuntimeError('staged directory cleanup failed') from close_error
"""
_DIRECTORY_ANCHOR = "for item in expected.values():\n"
if previous._VERIFY.count(_DIRECTORY_ANCHOR) != 1:
    raise RuntimeError("fixed file verifier anchor changed")
_VERIFY = (
    previous._VERIFY.replace(_DIRECTORY_ANCHOR, _DIRECTORY_HANDOFF + _DIRECTORY_ANCHOR)
    + r"""
client=Path('/usr/lib/aragorn/openclaw/aragorn-runtime-native-tool-client')
expected_names={Path(v['installed_path']).name for v in expected.values() if Path(v['installed_path']).parent==client}
if not expected_names or {p.name for p in client.iterdir()}!=expected_names:
 raise RuntimeError('native client directory inventory changed')
"""
)


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _inspect(kind: str, identity: str) -> dict[str, Any]:
    raw = existing._docker(kind, "inspect", identity)
    items = acquisition._load_json(b'{"items":' + raw + b"}", "native inspect")["items"]
    _expect(
        type(items) is list and len(items) == 1 and type(items[0]) is dict,
        "native inspect inventory changed",
    )
    return items[0]


def _build_binding(commit: str) -> dict[str, Any]:
    identity = acquisition._tree_file(commit, Path(_BUILD))
    _expect(
        (identity["bytes"], identity["digest"]) == _BUILD_PIN, "build record changed"
    )
    with (_ROOT / _BUILD).open("rb") as stream:
        raw = stream.read(_BUILD_PIN[0] + 1)
    _expect((len(raw), acquisition._digest(raw)) == _BUILD_PIN, "build bytes changed")
    record = acquisition._load_json(raw, "native build record")
    _expect(
        raw == acquisition._canonical(record) + b"\n"
        and record["runtime_volume"] == _VOLUME
        and record["runtime_measurement"]["before"]
        == record["runtime_measurement"]["after"]
        == record["final_runtime_measurement"]["tree"]
        == stage._RUNTIME_TREE
        and all(value is False for value in record["proof_limits"].values()),
        "native build/runtime binding changed",
    )
    return identity


def _runtime_program() -> str:
    # Reuse the verified helper import only, never the old runtime/contract pins.
    program = snapshot._program()
    anchor = "const stat = s =>"
    _expect(program.count(anchor) == 1, "snapshot helper import anchor changed")
    return (
        program.split(anchor)[0]
        + """
const runtime_tree_before = runtimeTree('/runtime');
const runtime_tree_after = runtimeTree('/runtime');
console.log(JSON.stringify({helper,mount,runtime_tree_before,runtime_tree_after}));
"""
    )


def _validate_runtime(content: dict[str, Any]) -> None:
    _expect(
        set(content) == {"helper", "mount", "runtime_tree_before", "runtime_tree_after"}
        and content["helper"] == acquisition._helper_input()[1]
        and acquisition._canonical(content["runtime_tree_before"])
        == acquisition._canonical(content["runtime_tree_after"])
        == acquisition._canonical(stage._RUNTIME_TREE),
        "new runtime identity changed",
    )
    mount = content["mount"]
    _expect(
        mount["path"] == "/runtime"
        and mount["ready"] is True
        and mount["read_only"] is True
        and mount["explicit"] is True
        and mount["error"] is None
        and len(mount["records"]) == 1
        and mount["records"][0]["mount_point"] == "/runtime"
        and mount["records"][0]["root"] == f"/docker/volumes/{_VOLUME}/_data"
        and "ro" in mount["records"][0]["mount_options"]
        and "rw" not in mount["records"][0]["mount_options"],
        "new runtime read-only mount changed",
    )


def _snapshot_runtime() -> dict[str, Any]:
    volume = _inspect("volume", _VOLUME)
    _expect(
        {key: volume.get(key) for key in _VOLUME_POLICY} == _VOLUME_POLICY,
        "new runtime volume does not meet expected provisioning policy",
    )
    users = ["ps", "--filter", f"volume={_VOLUME}", "--format", "{{.ID}}"]
    _expect(
        not existing._docker(*users).strip(), "new runtime already has a running user"
    )
    owner = secrets.token_hex(32)
    name = "aragorn-native-runtime-snapshot-" + owner[:32]
    argv = [
        "run",
        "--rm",
        "--name",
        name,
        "--pull=never",
        "--label",
        "dev.aragorn.snapshot-owner=" + owner,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
        "--pids-limit=32",
        "--memory=512m",
        "--env",
        "NODE_OPTIONS=",
        "--env",
        "NODE_PATH=",
        "--mount",
        f"type=volume,src={_VOLUME},dst=/runtime,readonly",
        "--entrypoint",
        "/usr/local/bin/node",
        _IMAGE,
        "--input-type=module",
        "-e",
        _runtime_program(),
    ]
    try:
        raw = existing._docker(*argv)
        content = acquisition._load_json(raw, "new runtime snapshot")
        _validate_runtime(content)
    finally:
        cleanup = snapshot._cleanup_snapshot(name, owner, _IMAGE)
    _expect(
        cleanup["container_name_absent"] is True
        and not existing._docker(*users).strip()
        and _inspect("volume", _VOLUME) == volume,
        "new runtime snapshot cleanup or volume custody changed",
    )
    return {
        "volume_inspect": volume,
        "volume_expected_policy": dict(_VOLUME_POLICY),
        "command": [*acquisition._DOCKER, *argv],
        "stdout": {
            "bytes": len(raw),
            "digest": acquisition._digest(raw),
            "base64": base64.b64encode(raw).decode("ascii"),
        },
        "content": content,
        "cleanup": cleanup,
        "running_users_before": [],
        "running_users_after": [],
        "limitations": [
            "POINT_IN_TIME_READ_ONLY_MEASUREMENT_NOT_EXCLUSIVE_VOLUME_LEASE",
            "TREE_DOES_NOT_COVER_DIRECTORY_CUSTODY_OR_EXTERNAL_SYMLINK_REFERENTS",
            "LOCAL_DOCKER_STATE_AND_BUILD_REPORT_NOT_INDEPENDENTLY_ATTESTED",
        ],
    }


def _create_arguments(name: str, owner: str, commit: str) -> list[str]:
    return [
        "create",
        "--name",
        name,
        "--pull=never",
        "--privileged",
        "--cgroupns=host",
        "--network=none",
        "--security-opt",
        "label=disable",
        "--label",
        "dev.aragorn.snapshot-owner=" + owner,
        "--label",
        "dev.aragorn.source-commit=" + commit,
        "--tmpfs",
        "/run:rw,nosuid,nodev,noexec,mode=755",
        "--tmpfs",
        "/run/lock:rw,nosuid,nodev,noexec,mode=755",
        "-v",
        "/sys/fs/cgroup:/sys/fs/cgroup:rw",
        "--mount",
        f"type=volume,src={_VOLUME},dst=/runtime,readonly",
        _IMAGE,
    ]


def _verify_fixture(
    item: dict, container: str, name: str, owner: str, commit: str
) -> None:
    expected = {
        "NetworkMode": "none",
        "Privileged": True,
        "CgroupnsMode": "host",
        "Binds": ["/sys/fs/cgroup:/sys/fs/cgroup:rw"],
        "Mounts": [
            {
                "Type": "volume",
                "Source": _VOLUME,
                "Target": "/runtime",
                "ReadOnly": True,
            }
        ],
        "Tmpfs": {
            "/run": "rw,nosuid,nodev,noexec,mode=755",
            "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
        },
        "SecurityOpt": ["label=disable"],
        "IpcMode": "private",
        "UsernsMode": "",
        "Runtime": "runc",
    }
    mounts = {mount["Destination"]: mount for mount in item["Mounts"]}
    _expect(
        item["Id"] == container
        and item["Name"] == "/" + name
        and item["Image"] == item["Config"]["Image"] == _IMAGE
        and item["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == owner
        and item["Config"]["Labels"]["dev.aragorn.source-commit"] == commit
        and acquisition._canonical({key: item["HostConfig"][key] for key in expected})
        == acquisition._canonical(expected)
        and len(mounts) == len(item["Mounts"])
        and set(mounts) == {"/runtime", "/sys/fs/cgroup"}
        and mounts["/runtime"]["Type"] == "volume"
        and mounts["/runtime"]["Name"] == _VOLUME
        and mounts["/runtime"]["RW"] is False
        and mounts["/sys/fs/cgroup"]["Type"] == "bind"
        and mounts["/sys/fs/cgroup"]["Source"] == "/sys/fs/cgroup"
        and mounts["/sys/fs/cgroup"]["RW"] is True,
        "owned native fixture identity or isolation changed",
    )


def _capture() -> dict[str, Any]:
    source = existing.existing._source_identity()
    build = _build_binding(source["commit"])
    helpers = {
        path: {
            **acquisition._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0444",
        }
        for path, target in _FILES.items()
    }
    parent = existing.campaign.current_v3_parent_identity()
    before = snapshot.snapshot_parent(parent)
    image = _inspect("image", _IMAGE)
    layers = before["image_inspect"]["RootFS"]["Layers"]
    _expect(
        image["Id"] == _IMAGE
        and image["RootFS"]["Type"] == "layers"
        and image["RootFS"]["Layers"][: len(layers)] == layers
        and len(image["RootFS"]["Layers"]) > len(layers),
        "native fixture is not the pinned child of the unchanged V3 parent",
    )
    runtime_before = _snapshot_runtime()
    owner = secrets.token_hex(32)
    name = "aragorn-native-receipt-check-" + owner[:16]
    with TemporaryDirectory(prefix="aragorn-native-receipt-stage-") as temporary:
        output = Path(temporary).resolve() / "stage"
        manifest = stage.stage_runtime_native_receipt_profile(output)
        _expect(
            manifest["schema"] == stage._SCHEMA
            and manifest["authority"] == stage._AUTHORITY
            and len(manifest["files"]) == 60
            and len(manifest["source_inputs"]) == 72
            and len(manifest["new_dependencies"]) == 15
            and manifest["required_runtime_not_included"]["tree"] == stage._RUNTIME_TREE
            and all(
                manifest[key] is False
                for key in (
                    "root_deployment",
                    "phase3_qualification",
                    "run_qualification",
                    "native_receipt_profile_deployed",
                    "receipt_state_provisioned",
                    "native_hook_reachability",
                    "native_causation_verified",
                    "mandatory_capture",
                )
            ),
            "native stage inventory or authority changed",
        )
        original, replacements = stage._verified_payloads()
        stage.base._audit_tree(output, original | replacements)
        payloads = {
            item["path"]: {
                "installed_path": item["path"],
                "installed_mode": item["mode"],
                "bytes": item["bytes"],
                "digest": item["digest"],
            }
            for item in manifest["files"]
        }
        _expect(len(payloads) == 60, "native stage destinations are not unique")
        started = existing.existing._now()
        try:
            container = (
                existing._docker(*_create_arguments(name, owner, source["commit"]))
                .decode("ascii")
                .strip()
            )
            _expect(
                re.fullmatch(r"[0-9a-f]{64}", container) is not None,
                "invalid created container id",
            )
            inspected = _inspect("container", container)
            _verify_fixture(inspected, container, name, owner, source["commit"])
            # The fully audited tree includes the new client directory. Individual
            # file copies cannot create that destination in the frozen child.
            existing._docker("cp", str(output) + "/.", container + ":/")
            stage.base._audit_tree(output, original | replacements)
            for path, target in _FILES.items():
                existing._docker("cp", str(_ROOT / path), container + ":" + target)
            existing._docker("start", container)
            existing._docker(
                "exec",
                container,
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                "-c",
                _VERIFY,
                json.dumps(payloads | helpers),
                container,
                json.dumps(manifest["directories"]),
                json.dumps([os.geteuid(), os.getegid()]),
            )
            argv = [
                "exec",
                container,
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                _FILES[_CHECKER],
                container,
            ]
            raw = previous._journal_check(argv)
            observation = acquisition._load_json(raw, "native fixture observation")
            _expect(
                raw == acquisition._canonical(observation) + b"\n"
                and observation["schema"]
                == "aragorn/runtime-native-receipt-systemd-integration-observation/v1"
                and observation["fixture_container"] == container
                and observation["status"] == "OBSERVED"
                and observation["phase3_eligible"] is False
                and observation["run_conformance_eligible"] is False,
                "native fixture observation or proof ceiling changed",
            )
        finally:
            cleanup = snapshot._cleanup_snapshot(name, owner, _IMAGE)
        _expect(
            cleanup["container_name_absent"] is True
            and cleanup["removed_id_absent"] is True,
            "owned native fixture cleanup is unconfirmed",
        )
    runtime_after = _snapshot_runtime()
    after = snapshot.snapshot_parent(parent)
    _expect(previous._parent_unchanged(before, after), "frozen parent changed")
    _expect(
        runtime_before["volume_inspect"] == runtime_after["volume_inspect"],
        "new runtime volume changed",
    )
    _expect(
        existing.existing._source_identity() == source, "source changed during capture"
    )
    return {
        "schema": "aragorn/runtime-native-receipt-systemd-capture/v1",
        "authority": "LOCAL_SUCCESSOR_FIXTURE_NOT_RUN_OR_PHASE3_QUALIFICATION",
        "status": "OBSERVED",
        "source": source,
        "build_observation": build,
        "staged_profile": manifest,
        "fixture_helpers": helpers,
        "parent_identity": parent,
        "parent_before": before,
        "parent_after": after,
        "runtime_before": runtime_before,
        "runtime_after": runtime_after,
        "fixture_image": image,
        "fixture_container": container,
        "container_inspect": inspected,
        "invocation": {
            "argv": [*acquisition._DOCKER, *argv],
            "started_at": started,
            "completed_at": existing.existing._now(),
        },
        "observation": observation,
        "cleanup": cleanup,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
        "production_activation_eligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0].startswith("--"):
        print(
            "usage: capture_runtime_native_receipt_systemd_check ABSENT_OUTPUT_JSON",
            file=sys.stderr,
        )
        return 64
    output = Path(arguments[0])
    _expect(
        output.is_absolute() and not os.path.lexists(output),
        "output must be absent and absolute",
    )
    raw = acquisition._canonical(_capture()) + b"\n"
    acquisition._write_output(output, raw)
    print(
        json.dumps(
            {
                "status": "OBSERVED",
                "path": str(output),
                "digest": acquisition._digest(raw),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
