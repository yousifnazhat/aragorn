"""Capture one owned successor startup/quarantine fixture, never a host deployment."""

from __future__ import annotations

import json
import os
import secrets
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from scripts import capture_runtime_response_systemd_check as existing
from scripts import stage_runtime_endpoint_journal_profile as journal_stage
from scripts import stage_runtime_quarantine_profile as stage

campaign = existing.campaign
_IMAGE = existing._IMAGE
_FILES = {
    "scripts/runtime_quarantine_systemd_check.py": "/opt/aragorn/runtime-quarantine-systemd-check.py",
    "scripts/runtime_response_systemd_check.py": "/opt/aragorn/runtime_response_systemd_check.py",
}
_JOURNAL_FILES = {
    **_FILES,
    "scripts/runtime_endpoint_journal_systemd_check.py": "/opt/aragorn/runtime-endpoint-journal-systemd-check.py",
}
_VERIFY = r"""import hashlib,json,os,re,stat,sys,time
from pathlib import Path
expected=json.loads(sys.argv[1]); container=sys.argv[2]
if re.fullmatch('[0-9a-f]{64}',container) is None or os.geteuid()!=0:
 raise RuntimeError('invalid owned fixture identity')
if Path('/proc/1/cgroup').read_text().splitlines()!=['0::/docker/'+container+'/init.scope']:
 raise RuntimeError('not the exact owned Docker systemd fixture')
for item in expected.values():
 p=Path(item['installed_path'])
 if p.resolve(strict=True)!=p: raise RuntimeError('noncanonical staged destination')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd)
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=item['bytes']:
   raise RuntimeError('staged destination metadata changed')
  raw=os.read(fd,item['bytes']+1)
  if len(raw)!=item['bytes'] or 'sha256:'+hashlib.sha256(raw).hexdigest()!=item['digest']:
   raise RuntimeError('staged destination bytes changed')
  os.fchown(fd,0,0); os.fchmod(fd,int(item['installed_mode'],8))
  a=os.fstat(fd)
  os.lseek(fd,0,os.SEEK_SET); reread=os.read(fd,item['bytes']+1)
  b=os.fstat(fd); n=p.lstat()
  fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  if reread!=raw or any(getattr(a,k)!=getattr(b,k) or getattr(b,k)!=getattr(n,k) for k in fields) or a.st_uid!=0 or a.st_gid!=0 or stat.S_IMODE(a.st_mode)!=int(item['installed_mode'],8) or a.st_nlink!=1:
   raise RuntimeError('staged destination custody changed')
 finally: os.close(fd)
deadline=time.monotonic()+20
while not (Path('/run/systemd/private').exists() and Path('/run/aragorn-protected-install').is_dir()):
 if time.monotonic()>deadline: raise RuntimeError('fixture systemd startup timed out')
 time.sleep(.1)
"""


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _parent_unchanged(before: dict, after: dict) -> bool:
    return (
        before["image_inspect"] == after["image_inspect"]
        and before["volume_inspect"] == after["volume_inspect"]
        and before["content"]["runtime_tree_before"]
        == after["content"]["runtime_tree_after"]
        and {
            name: item["content_base64"]
            for name, item in before["content"]["contract_files"].items()
        }
        == {
            name: item["content_base64"]
            for name, item in after["content"]["contract_files"].items()
        }
    )


def _journal_check(argv: list[str]) -> bytes:
    """Preserve the frozen runner's checks, but retain its safe diagnostic limit."""
    acquisition = existing.existing.acquisition
    original_run = acquisition.subprocess.run
    completed = None

    def run(*args: Any, **kwargs: Any) -> Any:
        nonlocal completed
        completed = original_run(*args, **kwargs)
        return completed

    try:
        # Replace only this module binding, never the shared subprocess module.
        with patch.object(acquisition, "subprocess", SimpleNamespace(run=run)):
            return existing._docker(*argv)
    except acquisition.CaptureError as exc:
        if (
            completed is not None
            and len(completed.stdout) <= 2 * 1024 * 1024
            and 0 < len(completed.stderr) <= 16384
        ):
            raise acquisition.CaptureError(
                "journal fixture command failed: "
                + completed.stderr.decode("utf-8", "replace")
            ) from exc
        raise


def _capture(*, endpoint_journal: bool = False) -> dict[str, Any]:
    _expect(type(endpoint_journal) is bool, "fixture selection must be boolean")
    profile = "endpoint-journal" if endpoint_journal else "quarantine"
    files = _JOURNAL_FILES if endpoint_journal else _FILES
    checker = (
        "scripts/runtime_endpoint_journal_systemd_check.py"
        if endpoint_journal
        else "scripts/runtime_quarantine_systemd_check.py"
    )
    file_count = 55 if endpoint_journal else 54
    source = existing.existing._source_identity()
    helpers = {
        path: {
            **existing.existing.acquisition._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0444",
        }
        for path, target in files.items()
    }
    parent = campaign.current_v3_parent_identity()
    before = existing.parent_snapshot.snapshot_parent(parent)
    child_image = json.loads(existing._docker("image", "inspect", _IMAGE))[0]
    parent_image = json.loads(existing._docker("image", "inspect", parent["image_id"]))[
        0
    ]
    layers = parent_image["RootFS"]["Layers"]
    _expect(
        child_image["Id"] == _IMAGE
        and child_image["RootFS"]["Layers"][: len(layers)] == layers
        and len(child_image["RootFS"]["Layers"]) > len(layers),
        "successor fixture is not an extension of the frozen V3 image",
    )
    owner = secrets.token_hex(32)
    name = f"aragorn-runtime-{profile}-check-" + owner[:16]
    with TemporaryDirectory(prefix=f"aragorn-runtime-{profile}-stage-") as temporary:
        output = Path(temporary).resolve() / "stage"
        manifest = (
            journal_stage.stage_runtime_endpoint_journal_profile(output)
            if endpoint_journal
            else stage.stage_runtime_quarantine_profile(output)
        )
        _expect(
            len(manifest["files"]) == file_count
            and len(manifest["base_inputs"]) == 47
            and len(manifest["new_dependencies"]) == (10 if endpoint_journal else 9)
            and manifest["root_deployment"] is False
            and manifest["phase3_qualification"] is False,
            "successor stage inventory or authority changed",
        )
        if endpoint_journal:
            _expect(
                len(manifest["source_inputs"]) == 62
                and manifest["runtime_journal_deployed"] is False
                and manifest["durable_event_retention"] is False
                and manifest["run_qualification"] is False,
                "journal stage inputs or authority changed",
            )
        payloads = {
            item["path"]: {
                "installed_path": item["path"],
                "installed_mode": item["mode"],
                "bytes": item["bytes"],
                "digest": item["digest"],
            }
            for item in manifest["files"]
        }
        _expect(len(payloads) == file_count, "successor destinations are not unique")
        started = existing.existing._now()
        try:
            container = (
                existing._docker(
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
                    "dev.aragorn.source-commit=" + source["commit"],
                    "--tmpfs",
                    "/run:rw,nosuid,nodev,noexec,mode=755",
                    "--tmpfs",
                    "/run/lock:rw,nosuid,nodev,noexec,mode=755",
                    "-v",
                    "/sys/fs/cgroup:/sys/fs/cgroup:rw",
                    "--mount",
                    f"type=volume,src={parent['runtime_volume']},dst=/runtime,readonly",
                    _IMAGE,
                )
                .decode("ascii")
                .strip()
            )
            _expect(
                len(container) == 64
                and all(c in "0123456789abcdef" for c in container),
                "created container id is invalid",
            )
            inspected = json.loads(existing._docker("container", "inspect", container))[
                0
            ]
            runtime_mounts = [
                item
                for item in inspected["Mounts"]
                if item["Destination"] == "/runtime"
            ]
            _expect(
                inspected["Id"] == container
                and inspected["Name"] == "/" + name
                and inspected["Image"] == _IMAGE
                and inspected["Config"]["Image"] == _IMAGE
                and inspected["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == owner
                and inspected["Config"]["Labels"]["dev.aragorn.source-commit"]
                == source["commit"]
                and inspected["HostConfig"]["NetworkMode"] == "none"
                and inspected["HostConfig"]["Privileged"] is True
                and inspected["HostConfig"]["CgroupnsMode"] == "host"
                and inspected["HostConfig"]["Binds"]
                == ["/sys/fs/cgroup:/sys/fs/cgroup:rw"]
                and inspected["HostConfig"]["Mounts"]
                == [
                    {
                        "Type": "volume",
                        "Source": parent["runtime_volume"],
                        "Target": "/runtime",
                        "ReadOnly": True,
                    }
                ]
                and inspected["HostConfig"]["Tmpfs"]
                == {
                    "/run": "rw,nosuid,nodev,noexec,mode=755",
                    "/run/lock": "rw,nosuid,nodev,noexec,mode=755",
                }
                and inspected["HostConfig"]["SecurityOpt"] == ["label=disable"]
                and inspected["HostConfig"]["IpcMode"] == "private"
                and inspected["HostConfig"]["UsernsMode"] == ""
                and inspected["HostConfig"]["Runtime"] == "runc"
                and len(runtime_mounts) == 1
                and runtime_mounts[0].get("Name") == parent["runtime_volume"]
                and runtime_mounts[0]["RW"] is False,
                "created successor fixture identity or isolation changed",
            )
            for path in payloads:
                existing._docker(
                    "cp", str(output / path.removeprefix("/")), container + ":" + path
                )
            for path, target in files.items():
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
            )
            argv = [
                "exec",
                container,
                "/usr/bin/python3.12",
                "-I",
                "-S",
                "-B",
                files[checker],
                container,
            ]
            raw = _journal_check(argv) if endpoint_journal else existing._docker(*argv)
            observation = json.loads(raw)
            _expect(
                raw == campaign._canonical(observation) + b"\n"
                and observation["schema"]
                == f"aragorn/runtime-{profile}-systemd-integration-observation/v1"
                and observation["fixture_container"] == container
                and observation["status"] == "OBSERVED"
                and observation["phase3_eligible"] is False
                and observation["run_conformance_eligible"] is False,
                "successor fixture observation or ceiling changed",
            )
        finally:
            cleanup = existing.parent_snapshot._cleanup_snapshot(name, owner, _IMAGE)
        _expect(
            cleanup["container_name_absent"] is True
            and cleanup["removed_id_absent"] is True,
            "owned successor fixture cleanup is unconfirmed",
        )
    after = existing.parent_snapshot.snapshot_parent(parent)
    _expect(_parent_unchanged(before, after), "frozen parent changed")
    _expect(
        existing.existing._source_identity() == source, "source changed during check"
    )
    return {
        "schema": f"aragorn/runtime-{profile}-systemd-capture/v1",
        "authority": "LOCAL_SUCCESSOR_FIXTURE_NOT_RUN_OR_PHASE3_QUALIFICATION",
        "status": "OBSERVED",
        "source": source,
        "staged_profile": manifest,
        "fixture_helpers": helpers,
        "parent_identity": parent,
        "parent_before": before,
        "parent_after": after,
        "fixture_image": _IMAGE,
        "fixture_container": container,
        "invocation": {
            "argv": [*existing.existing.acquisition._DOCKER, *argv],
            "started_at": started,
            "completed_at": existing.existing._now(),
        },
        "observation": observation,
        "cleanup": cleanup,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    endpoint_journal = len(arguments) == 2 and arguments[0] == "--endpoint-journal"
    if endpoint_journal:
        arguments = arguments[1:]
    if len(arguments) != 1 or arguments[0].startswith("--"):
        print(
            "usage: capture_runtime_quarantine_systemd_check [--endpoint-journal] ABSENT_OUTPUT_JSON",
            file=sys.stderr,
        )
        return 64
    output = Path(arguments[0])
    _expect(
        output.is_absolute() and not os.path.lexists(output),
        "output must be absent and absolute",
    )
    result = _capture(endpoint_journal=True) if endpoint_journal else _capture()
    raw = campaign._canonical(result)
    with output.open("xb") as stream:
        stream.write(raw)
    print(
        json.dumps(
            {
                "status": result["status"],
                "path": str(output),
                "digest": campaign._digest(raw),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
