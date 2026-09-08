"""Read the frozen V3 parent and runtime without executing native modules."""

from __future__ import annotations

import base64
import json
import re
import secrets
from typing import Any

from aragorn import admission_openclaw_final_v3_campaign as campaign
from scripts import capture_openclaw_final_v3_core_updater_modules as acquisition

_CONTRACT_FILES = {
    "configuration": (
        "protected-final-combined-config-v3.json",
        2160,
        "sha256:2855474d8b709654fb8902c0dc69ec1f0a3a378518ec23bfb12c1eb9630824ab",
    ),
    "profile": (
        "protected-final-combined-profile-v3.json",
        5302,
        "sha256:3229bd747088199d8bae074bbc27a415169fa21f86462408434ecdb43c5b2a6c",
    ),
    "runtime_lock": (
        "protected-final-combined-runtime-v3.lock.json",
        7620,
        "sha256:3bbcc6568cf713f9e534f84f7a92e313b5aa357065759bd01b5f24a594fb5822",
    ),
}
_SOURCE_ROOT = "/src/benchmark/admission/openclaw-v2026.7.1/"


def _expect(value: bool, message: str) -> None:
    if not value:
        raise campaign.CampaignContractError("V3 parent snapshot " + message)


def _program() -> str:
    raw, helper = acquisition._helper_input()
    files = {
        name: {"path": _SOURCE_ROOT + filename, "bytes": size, "digest": digest}
        for name, (filename, size, digest) in _CONTRACT_FILES.items()
    }
    return f"""
import * as fs from 'node:fs';
import {{createHash}} from 'node:crypto';
const sha = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const helper = {json.dumps(helper)};
const helperRaw = Buffer.from({json.dumps(base64.b64encode(raw).decode("ascii"))}, 'base64');
if (helperRaw.length !== helper.bytes || sha(helperRaw) !== helper.digest)
  throw new Error('helper input changed');
const source = helperRaw.toString('utf8');
if (source.split(helper.transformation.from).length !== 2) throw new Error('helper SELF changed');
const transformed = source.replace(helper.transformation.from,helper.transformation.to);
const body = text => text.split('export function runtimeTree(')[1].split('\\nfunction decodeMountInfoPath(')[0];
if (Buffer.byteLength(transformed) !== helper.transformed_bytes ||
    sha(Buffer.from(transformed)) !== helper.transformed_digest || body(source) !== body(transformed))
  throw new Error('helper transform changed');
const {{runtimeTree,mountObservation}} = await import('data:text/javascript;base64,' + Buffer.from(transformed).toString('base64'));
const mount = mountObservation('/runtime');
if (!mount.ready || !mount.read_only) throw new Error('runtime mount changed');
const stat = s => ({{device:s.dev,inode:s.ino,uid:s.uid,gid:s.gid,mode:(s.mode & 0o7777).toString(8).padStart(4,'0'),
  nlink:s.nlink,type:s.isFile()?'file':'other',size:s.size}});
function read(expected) {{
  const before = stat(fs.lstatSync(expected.path));
  if (before.type !== 'file' || before.nlink !== 1 || before.uid !== 0 || before.gid !== 0 ||
      before.mode !== '0444' || before.size !== expected.bytes) throw new Error('contract custody changed');
  const fd = fs.openSync(expected.path,fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {{
    if (JSON.stringify(before) !== JSON.stringify(stat(fs.fstatSync(fd)))) throw new Error('contract file changed');
    const bytes = fs.readFileSync(fd), after = stat(fs.fstatSync(fd));
    if (JSON.stringify(before) !== JSON.stringify(after) ||
        JSON.stringify(before) !== JSON.stringify(stat(fs.lstatSync(expected.path))) ||
        bytes.length !== expected.bytes || sha(bytes) !== expected.digest) throw new Error('contract bytes changed');
    return {{...expected,content_base64:bytes.toString('base64'),stat_before:before,stat_after:after}};
  }} finally {{ fs.closeSync(fd); }}
}}
const runtime_tree_before = runtimeTree('/runtime');
const contract_files = Object.fromEntries(Object.entries({json.dumps(files)}).map(([name, expected]) => [name,read(expected)]));
const runtime_tree_after = runtimeTree('/runtime');
console.log(JSON.stringify({{helper,mount,runtime_tree_before,runtime_tree_after,contract_files}}));
"""


def _command(parent: dict[str, str], *, container_name: str, owner: str) -> list[str]:
    return [
        *acquisition._DOCKER,
        "run",
        "--rm",
        "--name",
        container_name,
        "--label",
        f"dev.aragorn.snapshot-owner={owner}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "32",
        "--memory",
        "512m",
        "--env",
        "NODE_OPTIONS=",
        "--env",
        "NODE_PATH=",
        "--mount",
        f"type=volume,src={parent['runtime_volume']},dst=/runtime,readonly",
        "--entrypoint",
        "/usr/local/bin/node",
        parent["image_id"],
        "--input-type=module",
        "-e",
        _program(),
    ]


def _cleanup_snapshot(container_name: str, owner: str, image: str) -> dict[str, Any]:
    """Remove only this snapshot's container and verify daemon-side absence."""
    commands = []

    def run(arguments: list[str]) -> bytes:
        command = [*acquisition._DOCKER, *arguments]
        raw = acquisition._run(command)
        commands.append(
            {"argv": command, "stdout": raw.decode("utf-8"), "exit_code": 0}
        )
        return raw

    def listed_ids(selector: str) -> list[str]:
        raw = run(
            [
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                selector,
                "--format",
                "{{.ID}}",
            ]
        )
        values = raw.decode("ascii").splitlines()
        _expect(
            all(re.fullmatch(r"[0-9a-f]{64}", item) for item in values)
            and len(set(values)) == len(values),
            "cleanup container inventory changed",
        )
        return values

    by_name = f"name=^/{container_name}$"
    found = listed_ids(by_name)
    _expect(len(found) <= 1, "cleanup container name is ambiguous")
    removed = None
    owned = None
    if found:
        raw = run(["container", "inspect", found[0]])
        parsed = acquisition._load_json(
            b'{"items":' + raw + b"}", "snapshot cleanup inspect"
        )["items"]
        _expect(
            type(parsed) is list and len(parsed) == 1 and type(parsed[0]) is dict,
            "cleanup inspect inventory changed",
        )
        current = parsed[0]
        _expect(
            current["Id"] == found[0]
            and current["Name"] == "/" + container_name
            and current["Image"] == image
            and current["Config"]["Image"] == image
            and current["Config"].get("Labels", {}).get("dev.aragorn.snapshot-owner")
            == owner,
            "refuses to remove an unowned container",
        )
        owned = {
            "id": current["Id"],
            "name": current["Name"],
            "image": current["Image"],
            "owner": owner,
        }
        run(["container", "rm", "--force", current["Id"]])
        removed = current["Id"]
    _expect(
        bool(run(["info", "--format", "{{.ServerVersion}}"]).strip()),
        "cleanup daemon is unavailable",
    )
    _expect(not listed_ids(by_name), "container name remained after cleanup")
    if removed is not None:
        _expect(not listed_ids("id=" + removed), "container ID remained after cleanup")
    return {
        "name": container_name,
        "owner": owner,
        "image": image,
        "owned_container": owned,
        "removed_id": removed,
        "daemon_reachable": True,
        "container_name_absent": True,
        "removed_id_absent": True if removed else None,
        "commands": commands,
    }


def _validate_content(content: dict[str, Any], parent: dict[str, str]) -> None:
    parent = campaign._parent_identity(parent)
    _expect(
        set(content)
        == {
            "helper",
            "mount",
            "runtime_tree_before",
            "runtime_tree_after",
            "contract_files",
        },
        "content fields changed",
    )
    _expect(
        content["helper"] == acquisition._helper_input()[1], "helper provenance changed"
    )
    _expect(
        content["runtime_tree_before"]
        == content["runtime_tree_after"]
        == acquisition._RUNTIME_TREE
        and content["runtime_tree_before"]["tree_digest"]
        == parent["runtime_tree_digest"],
        "full runtime tree changed",
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
        and "ro" in mount["records"][0]["mount_options"]
        and "rw" not in mount["records"][0]["mount_options"],
        "read-only mount changed",
    )
    _expect(
        set(content["contract_files"]) == set(_CONTRACT_FILES),
        "contract inventory changed",
    )
    for name, (filename, size, digest) in _CONTRACT_FILES.items():
        record = content["contract_files"][name]
        _expect(
            set(record)
            == {
                "path",
                "bytes",
                "digest",
                "content_base64",
                "stat_before",
                "stat_after",
            }
            and record["path"] == _SOURCE_ROOT + filename
            and type(record["bytes"]) is int
            and record["bytes"] == size
            and record["digest"] == digest,
            "contract identity changed",
        )
        raw = base64.b64decode(record["content_base64"], validate=True)
        _expect(
            len(raw) == size
            and acquisition._digest(raw) == digest
            and base64.b64encode(raw).decode("ascii") == record["content_base64"],
            "contract bytes changed",
        )
        document = acquisition._load_json(raw, "parent contract")
        canonical = acquisition._canonical(document)
        _expect(
            raw == canonical + b"\n"
            and acquisition._digest(canonical) == parent[name + "_canonical_digest"],
            "canonical contract digest changed",
        )
        metadata = record["stat_before"]
        _expect(
            metadata == record["stat_after"]
            and set(metadata)
            == {"device", "inode", "uid", "gid", "mode", "nlink", "type", "size"}
            and all(
                type(metadata[key]) is int
                for key in ("device", "inode", "uid", "gid", "nlink", "size")
            )
            and metadata["device"] > 0
            and metadata["inode"] > 0
            and (
                metadata["uid"],
                metadata["gid"],
                metadata["mode"],
                metadata["nlink"],
                metadata["type"],
                metadata["size"],
            )
            == (0, 0, "0444", 1, "file", size),
            "contract metadata changed",
        )


def snapshot_parent(parent: dict[str, Any]) -> dict[str, Any]:
    """Return one point-in-time snapshot; do not grant campaign eligibility."""
    parent = campaign._parent_identity(parent)

    def inspect(kind: str, identity: str) -> dict[str, Any]:
        raw = acquisition._run([*acquisition._DOCKER, kind, "inspect", identity])
        parsed = acquisition._load_json(b'{"items":' + raw + b"}", "Docker inspect")[
            "items"
        ]
        _expect(
            type(parsed) is list and len(parsed) == 1 and type(parsed[0]) is dict,
            "inspect inventory changed",
        )
        return parsed[0]

    image = inspect("image", parent["image_id"])
    volume = inspect("volume", parent["runtime_volume"])
    _expect(
        image["Id"] == parent["image_id"]
        and image["RootFS"]["Type"] == "layers"
        and type(image["RootFS"]["Layers"]) is list
        and bool(image["RootFS"]["Layers"]),
        "immutable image identity changed",
    )
    _expect(
        {key: volume.get(key) for key in acquisition._EXPECTED_VOLUME}
        == acquisition._EXPECTED_VOLUME,
        "runtime volume identity changed",
    )
    users = [
        *acquisition._DOCKER,
        "ps",
        "--filter",
        f"volume={parent['runtime_volume']}",
        "--format",
        "{{.ID}}",
    ]
    _expect(
        not acquisition._run(users).strip(),
        "runtime has a running user before snapshot",
    )
    owner = secrets.token_hex(32)
    container_name = "aragorn-v3-parent-snapshot-" + owner[:32]
    command = _command(parent, container_name=container_name, owner=owner)
    try:
        raw = acquisition._run(command)
        content = acquisition._load_json(raw, "parent snapshot")
        _validate_content(content, parent)
    finally:
        cleanup = _cleanup_snapshot(container_name, owner, parent["image_id"])
    _expect(
        not acquisition._run(users).strip(), "runtime has a running user after snapshot"
    )
    _expect(
        inspect("volume", parent["runtime_volume"]) == volume,
        "volume changed during snapshot",
    )
    return {
        "schema": "aragorn/openclaw-final-v3-parent-snapshot/v1",
        "authority": "POINT_IN_TIME_LOCAL_READ_ONLY_SNAPSHOT_NOT_CAMPAIGN_OR_QUALIFICATION_AUTHORITY",
        "parent": parent,
        "image_inspect": image,
        "volume_inspect": volume,
        "command": command,
        "cleanup": cleanup,
        "stdout": {
            "bytes": len(raw),
            "digest": acquisition._digest(raw),
            "base64": base64.b64encode(raw).decode("ascii"),
        },
        "content": content,
        "running_users_command": users,
        "running_users_before": [],
        "running_users_after": [],
        "limitations": [
            "LOCAL_DOCKER_STATE_NOT_INDEPENDENTLY_ATTESTED",
            "POINT_IN_TIME_SNAPSHOT_NOT_EXCLUSIVE_RUNTIME_VOLUME_LEASE",
            "NO_NATIVE_MODULE_EXECUTION_OR_CAMPAIGN_QUALIFICATION",
        ],
    }
