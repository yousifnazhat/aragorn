"""Run the fixed response check in one owned, disposable V3 Linux fixture."""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(_ROOT), str(_ROOT / "src")]

from aragorn import admission_openclaw_final_v3_campaign as campaign
from scripts import capture_openclaw_final_v3_det01_campaign as existing
from scripts import openclaw_final_v3_parent_snapshot as parent_snapshot

_IMAGE = "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17"
_OVERLAY = {
    "src/aragorn/cas.py": "/usr/lib/aragorn/aragorn/cas.py",
    "src/aragorn/runtime_response_service.py": "/usr/lib/aragorn/aragorn/runtime_response_service.py",
    "packaging/libexec/aragorn-runtime-response-service.py": "/usr/libexec/aragorn/aragorn-runtime-response-service.py",
    "scripts/runtime_response_systemd_check.py": "/opt/aragorn/runtime-response-systemd-check.py",
    "scripts/prepare_runtime_response_systemd_check.py": "/opt/aragorn/prepare_runtime_response_systemd_check.py",
}


def _expect(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def _docker(*arguments: str) -> bytes:
    return existing.acquisition._run([*existing.acquisition._DOCKER, *arguments])


def _capture() -> dict[str, Any]:
    source = existing._source_identity()
    overlays = {
        path: {
            **existing.acquisition._tree_file(source["commit"], Path(path)),
            "installed_path": target,
            "installed_mode": "0644" if path == "src/aragorn/cas.py" else "0444",
        }
        for path, target in _OVERLAY.items()
    }
    parent = campaign.current_v3_parent_identity()
    before = parent_snapshot.snapshot_parent(parent)
    child_image = json.loads(_docker("image", "inspect", _IMAGE))[0]
    parent_image = json.loads(_docker("image", "inspect", parent["image_id"]))[0]
    layers = parent_image["RootFS"]["Layers"]
    _expect(
        child_image["Id"] == _IMAGE
        and child_image["RootFS"]["Layers"][: len(layers)] == layers
        and len(child_image["RootFS"]["Layers"]) > len(layers),
        "response fixture is not an extension of the frozen V3 image",
    )
    owner = secrets.token_hex(32)
    name = "aragorn-runtime-response-check-" + owner[:16]
    started = existing._now()
    try:
        container = (
            _docker(
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
        inspected = json.loads(_docker("container", "inspect", container))[0]
        _expect(
            inspected["Id"] == container
            and inspected["Name"] == "/" + name
            and inspected["Image"] == _IMAGE
            and inspected["Config"]["Labels"]["dev.aragorn.snapshot-owner"] == owner
            and inspected["HostConfig"]["NetworkMode"] == "none"
            and any(
                m["Destination"] == "/runtime"
                and m["Name"] == parent["runtime_volume"]
                and m["RW"] is False
                for m in inspected["Mounts"]
            ),
            "created fixture identity or isolation changed",
        )
        for path, target in _OVERLAY.items():
            _docker("cp", str(_ROOT / path), container + ":" + target)
        _docker("start", container)
        # Only response/check files and their exact CAS dependency are overlaid.
        # The frozen V3 worker, activator, configuration and runtime are unchanged.
        verify = """
import hashlib,json,os,stat,sys,time
from pathlib import Path
expected=json.loads(sys.argv[1])
for item in expected.values():
 p=Path(item['installed_path']); os.chown(p,0,0); os.chmod(p,int(item['installed_mode'],8))
 s=p.lstat(); raw=p.read_bytes()
 if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_gid!=0 or stat.S_IMODE(s.st_mode)!=int(item['installed_mode'],8) or s.st_nlink!=1 or len(raw)!=item['bytes'] or 'sha256:'+hashlib.sha256(raw).hexdigest()!=item['digest']:
  raise RuntimeError('response overlay changed')
deadline=time.monotonic()+20
while not (Path('/run/systemd/private').exists() and Path('/run/aragorn-protected-install').is_dir()):
 if time.monotonic()>deadline: raise RuntimeError('systemd startup timed out')
 time.sleep(.1)
"""
        _docker(
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            "-c",
            verify,
            json.dumps(overlays),
        )
        argv = [
            "exec",
            container,
            "/usr/bin/python3.12",
            "-I",
            "-S",
            "-B",
            _OVERLAY["scripts/prepare_runtime_response_systemd_check.py"],
        ]
        raw = _docker(*argv)
        observation = json.loads(raw)
        _expect(
            raw == campaign._canonical(observation) + b"\n"
            and observation["check"]["status"] == "OBSERVED"
            and observation["check"]["phase3_eligible"] is False
            and observation["check"]["run_conformance_eligible"] is False,
            "response integration observation ceiling changed",
        )
    finally:
        cleanup = parent_snapshot._cleanup_snapshot(name, owner, _IMAGE)
    after = parent_snapshot.snapshot_parent(parent)
    _expect(
        before["image_inspect"] == after["image_inspect"]
        and before["volume_inspect"] == after["volume_inspect"]
        and before["content"]["runtime_tree_before"]
        == after["content"]["runtime_tree_after"]
        and {
            k: v["content_base64"]
            for k, v in before["content"]["contract_files"].items()
        }
        == {
            k: v["content_base64"]
            for k, v in after["content"]["contract_files"].items()
        },
        "frozen parent changed",
    )
    _expect(existing._source_identity() == source, "source changed during check")
    return {
        "schema": "aragorn/runtime-response-systemd-capture/v1",
        "authority": "LOCAL_INTEGRATION_CAPTURE_NOT_PHASE3_QUALIFICATION",
        "status": "OBSERVED",
        "source": source,
        "response_overlay": overlays,
        "parent_identity": parent,
        "parent_before": before,
        "parent_after": after,
        "fixture_image": _IMAGE,
        "fixture_container": container,
        "invocation": {
            "argv": [*existing.acquisition._DOCKER, *argv],
            "started_at": started,
            "completed_at": existing._now(),
        },
        "observation": observation,
        "cleanup": cleanup,
        "phase3_eligible": False,
        "run_conformance_eligible": False,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1:
        print(
            "usage: capture_runtime_response_systemd_check OUTPUT_JSON", file=sys.stderr
        )
        return 64
    output = Path(arguments[0])
    if output.exists() or output.is_symlink():
        raise RuntimeError("output already exists")
    result = _capture()
    with output.open("xb") as stream:
        stream.write(campaign._canonical(result))
    print(
        json.dumps(
            {
                "status": result["status"],
                "path": str(output),
                "digest": campaign._digest(output.read_bytes()),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
