"""Acquire pinned native call-site bytes without executing the selected modules."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from scripts import (
    capture_openclaw_final_combined_v2_session_snapshot_closure as shared,
)

CaptureError = shared.CaptureError
_canonical = shared._canonical
_digest = shared._digest
_load_json = shared._load_json
_SCRIPT_PATH = Path("scripts") / Path(__file__).name
_SHARED_PATH = Path("scripts/capture_openclaw_final_combined_v2_session_snapshot_closure.py")
_HELPER_PATH = Path("benchmark/admission/openclaw-v2026.7.1/protected-observation-v1.mjs")
_HELPER = "/acquisition/protected-observation-v1.mjs"
_HELPER_IDENTITY = {"bytes": 13609, "digest": "sha256:44ee65e2014e44681d2efe2b2fa76abbede7c6eaf7719aecb104e4be441d635b"}
_SCHEMA = "aragorn/openclaw-final-v3-core-updater-compiled-module-acquisition/v1"
_ROUTE = "ADM-02/update/core-updater-plugin-replacement"
_ROUTE_EVIDENCE_PATH = Path("benchmark/evidence/runtime-action-worker-final-combined-v3-route-core-updater-plugin-replacement-systemd-p3-final-2026-09-03.json")
_ROUTE_EVIDENCE_IDENTITY = {"bytes": 598667, "digest": "sha256:4718a3bdaf5c9474e301ff8d825332a804119cc69a17888bc9fdbffba396dabc"}
_ROUTE_SOURCE_COMMIT = "05192ef62e26a067bc8ef72b0c9d3d7d2813b201"
_ROUTE_RETENTION_COMMIT = "4e72fa6278a4625fa7cda5735a3eff7f9271a8ce"
_ROUTE_RETENTION_BLOB = "6ab96ff90f54cadb1647a84cfc9ac2ca1a7337e8"
_IMAGE = "sha256:1c75f0c37070aa5b702e134e6e6c830690f596891ce0f4fa389ea7515300ea17"
_VOLUME = shared._VOLUME
_RUNTIME_TREE = shared._RUNTIME_TREE
_DOCKER = ["docker", "--context", "colima-aragorn-bakeoff"]
_DIST = "/runtime/lib/node_modules/openclaw/dist/"
_MODULE_IDENTITIES = {
    _DIST + name: {"bytes": size, "digest": "sha256:" + digest}
    for name, size, digest in (
        ("installed-plugin-index-records-NrU3hnwq.js", 4686, "5500445dcd66876952758eec91019a3c4dcc4a852498f956022828f0f867d21f"),
        ("diagnostic-events-JZsXee1S.js", 22651, "fa576a8a2881ff61f0f6bd67a289af6442c61f37b364a2e7923955348ed19994"),
        ("update-cli-DBeOm5kS.js", 162369, "4883052d157512a0d1f8f5f60ca61efff8b80eaa11bd9e2745e36f172dc41309"),
        ("update-CM1QhIWo.js", 70855, "7c74e15d9f9ecc8eca90f069619e346c793cb3b2a0ca502c05e89d9a6bf59597"),
        ("git-install-B1_qr0Ru.js", 13036, "3ef38e48d69d2e8f3c580e99e081882db17cae5825d193435f32b2c26325ad82"),
        ("install-security-scan-BSpTdhul.js", 2432, "79a3bb57e52b78b469a5ed609f5415004e03eaaa0a524d2697e43f46cc8fe43e"),
        ("install-security-scan.runtime.js", 61, "d24aec6df26f4027686a309cefe206f8e635e1a4a5a2e3918c8c3e4a268b2e6d"),
        ("install-security-scan.runtime-CMin9jbx.js", 39967, "49efcd394780b9b65338e41121b1e14be6c4297aa3af232eb64d947364122f35"),
        ("install-policy-yA6T1vUH.js", 20773, "fe85c45bb33191131662b161be2daf66270fa4f538cefbc807b16661cd9884e1"),
        ("install-BzCFXkWy.js", 87117, "c0418807ee6a26e09b1cd878e5d68f87cdfe882786903449bde4ec1ec9c1da45"),
    )
}
_PATHS = tuple(_MODULE_IDENTITIES)
_EXPECTED_VOLUME = {
    "CreatedAt": "2026-08-13T11:52:43-04:00", "Driver": "local",
    "Labels": {
        "io.aragorn.phase": "phase3-final", "io.aragorn.role": "installed-runtime",
        "io.aragorn.source-commit": "7fa98d8e21b6d5937f25a7f19445ff683bb980bf",
        "io.aragorn.source-tree": "dd5ac3991f6dbce8b6e630e3e43644f64bc71d44",
    },
    "Name": _VOLUME, "Options": None, "Scope": "local",
}


def _run(arguments: list[str]) -> bytes:
    result = subprocess.run(arguments, capture_output=True, check=False, timeout=120)
    if len(result.stdout) > 2 * 1024 * 1024 or len(result.stderr) > 16384:
        raise CaptureError("acquisition command output exceeded limit")
    if result.returncode or result.stderr:
        raise CaptureError(f"acquisition command failed: {result.stderr.decode('utf-8', 'replace')[:1024]}")
    return result.stdout


def _tree_file(commit: str, path: Path) -> dict[str, Any]:
    entry = shared._git(["ls-tree", "-z", "--full-name", commit, "--", path.as_posix()])
    if not entry.endswith(b"\0") or entry.count(b"\0") != 1:
        raise CaptureError(f"signed tree entry changed: {path}")
    metadata, returned = entry[:-1].split(b"\t", 1)
    mode, kind, blob = metadata.decode("ascii").split(" ")
    expected_mode = "100755" if path == _SHARED_PATH else "100644"
    raw = shared._git(["cat-file", "blob", blob])
    if (mode, kind, returned.decode()) != (expected_mode, "blob", path.as_posix()) or raw != (_ROOT / path).read_bytes():
        raise CaptureError(f"working file differs from signed tree: {path}")
    return {"path": path.as_posix(), "bytes": len(raw), "digest": _digest(raw), "blob": blob, "mode": mode}


def _source_identity() -> dict[str, Any]:
    if (Path(shared._git(["rev-parse", "--show-toplevel"]).decode().strip()).resolve() != _ROOT
        or shared._git(["rev-parse", "--show-object-format"]).strip() != b"sha1"
        or shared._git(["status", "--porcelain=v1", "--untracked-files=all"])):
        raise CaptureError("acquisition requires the exact clean repository")
    commit = shared._git(["rev-parse", "HEAD"]).decode().strip()
    for signed in (commit, _ROUTE_SOURCE_COMMIT, _ROUTE_RETENTION_COMMIT):
        shared._verify_signature(signed)
    shared._git(["merge-base", "--is-ancestor", _ROUTE_RETENTION_COMMIT, commit])
    route = _tree_file(_ROUTE_RETENTION_COMMIT, _ROUTE_EVIDENCE_PATH)
    if route["blob"] != _ROUTE_RETENTION_BLOB:
        raise CaptureError("original route retention blob changed")
    return {
        "commit": commit,
        "parent": shared._git(["rev-parse", "HEAD^"]).decode().strip(),
        "tree": shared._git(["rev-parse", "HEAD^{tree}"]).decode().strip(),
        "signature": {"key": shared._SIGNING_KEY, "signer": "yousif.snazhat@gmail.com", "status": "GOOD_LOCAL_VERIFICATION"},
        "files": {
            "acquisition": _tree_file(commit, _SCRIPT_PATH),
            "acquisition_helpers": _tree_file(commit, _SHARED_PATH),
            "runtime_tree_helper": _tree_file(commit, _HELPER_PATH),
            "route_evidence": route,
        },
    }


def _route_evidence() -> tuple[dict[str, Any], dict[str, Any]]:
    raw = (_ROOT / _ROUTE_EVIDENCE_PATH).read_bytes()
    shared._verify_identity(raw, _ROUTE_EVIDENCE_IDENTITY, "original route evidence")
    evidence = _load_json(raw, "original route evidence")
    harness = evidence["composition"]["action"]["harness"]["document"]
    bindings = evidence["composition"]["bindings"]
    if (_canonical(evidence) + b"\n" != raw or evidence["route_id"] != _ROUTE
        or evidence["decision"]["route_observation_status"] != "OBSERVED"
        or harness["source_commit"] != _ROUTE_SOURCE_COMMIT or harness["image_id"] != _IMAGE
        or bindings["runtime_volume"] != _VOLUME
        or bindings["runtime_digest"] != _RUNTIME_TREE["tree_digest"]
        or evidence["composition"]["action"]["runtime"]["tree"] != _RUNTIME_TREE):
        raise CaptureError("original route runtime binding changed")
    preflight = evidence["route_observation"]["document"]["core_updater_preflight"]
    observed = [preflight["installed_index"]["writer_module"], preflight["trusted_policy_audit"]["diagnostic_module"]]
    return evidence, {item["path"]: item for item in observed}


def _helper_input() -> tuple[bytes, dict[str, Any]]:
    raw = (_ROOT / _HELPER_PATH).read_bytes()
    shared._verify_identity(raw, _HELPER_IDENTITY, "runtime tree helper")
    old = b"const SELF = fileURLToPath(import.meta.url);"
    new = f"const SELF = {json.dumps(_HELPER)};".encode("ascii")
    if raw.count(old) != 1:
        raise CaptureError("runtime tree helper SELF binding changed")
    transformed = raw.replace(old, new)
    start = b"export function runtimeTree("
    end = b"\nfunction decodeMountInfoPath("
    if (raw.count(start) != 1 or raw.count(end) != 1
        or raw.split(start)[1].split(end)[0] != transformed.split(start)[1].split(end)[0]):
        raise CaptureError("runtime tree helper function changed")
    return raw, {"path": _HELPER, **_HELPER_IDENTITY, "transport": "inline_base64_data_url",
                 "transformation": {"from": old.decode(), "to": new.decode(), "count": 1},
                 "transformed_bytes": len(transformed), "transformed_digest": _digest(transformed),
                 "runtime_tree_function_unchanged": True}


def _program() -> str:
    # Only the pinned observation helper is imported; selected native modules are bytes.
    helper_raw, helper_record = _helper_input()
    return f"""
import * as fs from 'node:fs';
import {{createHash}} from 'node:crypto';
const paths = {json.dumps(_PATHS)};
const expected = {json.dumps(_MODULE_IDENTITIES)};
const helper = {json.dumps(helper_record)};
const helperRaw = Buffer.from({json.dumps(base64.b64encode(helper_raw).decode('ascii'))},'base64');
const sha = raw => 'sha256:' + createHash('sha256').update(raw).digest('hex');
const stat = (s, path) => ({{path,device:s.dev,inode:s.ino,uid:s.uid,gid:s.gid,
  mode:(s.mode & 0o7777).toString(8).padStart(4,'0'),nlink:s.nlink,size:s.size,
  type:s.isFile()?'file':'other'}});
function read(path, expectedIdentity) {{
  const before = stat(fs.lstatSync(path),path);
  if (before.type !== 'file' || before.nlink !== 1 || before.size !== expectedIdentity.bytes)
    throw new Error('file custody changed: ' + path);
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {{
    if (JSON.stringify(stat(fs.fstatSync(fd),path)) !== JSON.stringify(before))
      throw new Error('file changed before read: ' + path);
    const raw = fs.readFileSync(fd);
    const after = stat(fs.fstatSync(fd),path);
    if (JSON.stringify(before) !== JSON.stringify(after) ||
        JSON.stringify(before) !== JSON.stringify(stat(fs.lstatSync(path),path)) ||
        raw.length !== expectedIdentity.bytes || sha(raw) !== expectedIdentity.digest)
      throw new Error('file changed during read: ' + path);
    return {{path,bytes:raw.length,digest:sha(raw),content_base64:raw.toString('base64'),stat_before:before,stat_after:after}};
  }} finally {{ fs.closeSync(fd); }}
}}
if (helperRaw.length !== helper.bytes || sha(helperRaw) !== helper.digest)
  throw new Error('inline runtime helper input changed');
const helperText = helperRaw.toString('utf8');
if (helperText.split(helper.transformation.from).length !== 2)
  throw new Error('runtime helper SELF replacement count changed');
const transformed = helperText.replace(helper.transformation.from,helper.transformation.to);
const functionBody = text => text.split('export function runtimeTree(')[1].split('\\nfunction decodeMountInfoPath(')[0];
if (Buffer.byteLength(transformed) !== helper.transformed_bytes ||
    sha(Buffer.from(transformed)) !== helper.transformed_digest ||
    functionBody(helperText) !== functionBody(transformed))
  throw new Error('runtime helper function changed');
const helperUrl = 'data:text/javascript;base64,' + Buffer.from(transformed).toString('base64');
const {{runtimeTree,mountObservation}} = await import(helperUrl);
const mounts = [mountObservation('/runtime')];
if (!mounts.every(m => m.ready === true)) throw new Error('read-only mounts changed');
const runtime_tree_before = runtimeTree('/runtime');
const module_files = paths.map(path => read(path,expected[path]));
const runtime_tree_after = runtimeTree('/runtime');
console.log(JSON.stringify({{runtime_tree_before,runtime_tree_after,module_files,runtime_tree_helper:helper,mounts}}));
"""


def _command() -> list[str]:
    return [*_DOCKER, "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "32", "--memory", "512m",
            "--env", "NODE_OPTIONS=", "--env", "NODE_PATH=",
            "--mount", f"type=volume,src={_VOLUME},dst=/runtime,readonly",
            "--entrypoint", "/usr/local/bin/node", _IMAGE, "--input-type=module", "-e", _program()]


def _validate_live(live: dict[str, Any], observed: dict[str, Any]) -> None:
    if (set(live) != {"runtime_tree_before", "runtime_tree_after", "module_files", "runtime_tree_helper", "mounts"}
        or live["runtime_tree_before"] != _RUNTIME_TREE or live["runtime_tree_after"] != _RUNTIME_TREE):
        raise CaptureError("live full runtime tree changed")
    records = live["module_files"]
    if not isinstance(records, list) or [item.get("path") for item in records] != list(_PATHS):
        raise CaptureError("selected module inventory changed")
    inodes: set[int] = set()
    devices: set[int] = set()
    for record in records:
        path = record["path"]
        expected = _MODULE_IDENTITIES[path]
        if set(record) != {"path", "bytes", "digest", "content_base64", "stat_before", "stat_after"}:
            raise CaptureError("selected module record changed")
        raw = base64.b64decode(record["content_base64"], validate=True)
        shared._verify_identity(raw, expected, path)
        metadata = record["stat_before"]
        if (type(record["bytes"]) is not int or record["bytes"] != len(raw) or record["digest"] != _digest(raw)
            or record["content_base64"] != base64.b64encode(raw).decode("ascii")
            or metadata != record["stat_after"]
            or set(metadata) != {"device", "gid", "inode", "mode", "nlink", "path", "size", "type", "uid"}
            or any(type(metadata[key]) is not int for key in ("device", "gid", "inode", "nlink", "size", "uid"))
            or (metadata["gid"], metadata["mode"], metadata["nlink"], metadata["path"], metadata["size"], metadata["type"], metadata["uid"])
                != (0, "0644", 1, path, len(raw), "file", 0)
            or metadata["device"] <= 0 or metadata["inode"] <= 0 or metadata["inode"] in inodes):
            raise CaptureError("selected module custody changed")
        inodes.add(metadata["inode"])
        devices.add(metadata["device"])
        if path in observed and {key: observed[path][key] for key in ("path", "bytes", "digest")} != {"path": path, **expected}:
            raise CaptureError("selected module differs from original route")
        record["observed_in_original_route"] = path in observed
    if len(devices) != 1 or set(observed) != set(_PATHS[:2]):
        raise CaptureError("selected module runtime binding changed")
    if live["runtime_tree_helper"] != _helper_input()[1]:
        raise CaptureError("runtime tree helper changed")
    if (not isinstance(live["mounts"], list) or len(live["mounts"]) != 1
        or [item["path"] for item in live["mounts"]] != ["/runtime"]
        or any(item["ready"] is not True or item["read_only"] is not True for item in live["mounts"])):
        raise CaptureError("read-only acquisition mounts changed")


def _live_acquisition(observed: dict[str, Any]) -> dict[str, Any]:
    def inspect(arguments: list[str]) -> dict[str, Any]:
        value = json.loads(_run([*_DOCKER, *arguments]), object_pairs_hook=shared._no_duplicates)
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise CaptureError("Docker inspect shape changed")
        return value[0]

    image = inspect(["image", "inspect", _IMAGE])
    volume = inspect(["volume", "inspect", _VOLUME])
    if image.get("Id") != _IMAGE:
        raise CaptureError("acquisition image changed")
    if {key: volume.get(key) for key in _EXPECTED_VOLUME} != _EXPECTED_VOLUME:
        raise CaptureError("runtime volume changed")
    users = [*_DOCKER, "ps", "--filter", f"volume={_VOLUME}", "--format", "{{.ID}}"]
    if _run(users).strip():
        raise CaptureError("runtime volume has a running user")
    command = _command()
    live = _load_json(_run(command), "live module acquisition")
    _validate_live(live, observed)
    if _run(users).strip() or inspect(["volume", "inspect", _VOLUME]) != volume:
        raise CaptureError("runtime volume changed during acquisition")
    return {**live,
        "image": {"id": _IMAGE, "inspect_canonical_digest": _digest(_canonical(image))},
        "volume": {**_EXPECTED_VOLUME, "inspect_canonical_digest": _digest(_canonical(volume))},
        "commands": {"acquisition": command, "volume_users_before": users, "volume_users_after": users},
        "running_volume_users_before": [], "running_volume_users_after": [],
    }


def _containment() -> dict[str, Any]:
    return {"capabilities_dropped": ["ALL"], "network_mode": "none", "no_new_privileges": True,
            "read_only_root_filesystem": True, "runtime_mount": {"source": _VOLUME, "destination": "/runtime", "mode": "ro"},
            "helper_input": {"source": _HELPER_PATH.as_posix(), "transport": "inline_base64_data_url",
                             "digest": _HELPER_IDENTITY["digest"], "bytes": _HELPER_IDENTITY["bytes"]},
            "selected_modules_executed": False}


def capture() -> dict[str, Any]:
    source = _source_identity()
    shared._verify_identity((_ROOT / _HELPER_PATH).read_bytes(), _HELPER_IDENTITY, "runtime tree helper")
    evidence, observed = _route_evidence()
    live = _live_acquisition(observed)
    if _source_identity() != source:
        raise CaptureError("signed acquisition source changed during acquisition")
    return {
        "schema": _SCHEMA,
        "authority": "SIGNED_SOURCE_BOUND_READ_ONLY_MODULE_ACQUISITION_NOT_ROUTE_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY",
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": source,
        "original_route": {"route_id": _ROUTE, "recorded_at": evidence["recorded_at"], "capture_image_id": _IMAGE,
            "evidence": {"path": _ROUTE_EVIDENCE_PATH.as_posix(), **_ROUTE_EVIDENCE_IDENTITY},
            "source_commit": _ROUTE_SOURCE_COMMIT, "retention_commit": _ROUTE_RETENTION_COMMIT},
        "containment": _containment(),
        "acquisition": live,
        "decision": {"status": "NATIVE_CALL_SITE_BYTES_ACQUIRED_ROUTE_REMAINS_NOT_TESTED", **{key: False for key in shared._ELIGIBILITY_KEYS}},
        "limitations": ["POST_ROUTE_READ_ONLY_ACQUISITION_BOUND_BY_IDENTICAL_FULL_RUNTIME_TREE",
            "TEN_SELECTED_NATIVE_CALL_SITE_MODULES_NOT_FULL_TRANSITIVE_IMPORT_CLOSURE",
            "LOCAL_DOCKER_VOLUME_NOT_INDEPENDENTLY_ATTESTED",
            "NO_NATIVE_ROUTE_EXECUTION_OR_REPLAY_DURING_ACQUISITION",
            "NO_ROUTE_ADMISSION_RUN_PHASE3_EDR_INSTALLER_OR_RELEASE_AUTHORITY"],
    }


def _write_output(path: Path, raw: bytes) -> None:
    if not path.is_absolute():
        raise CaptureError("output path must be absolute")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output = Path(arguments[1]) if len(arguments) == 2 and arguments[0] == "--output" else None
    if arguments and output is None:
        print(f"usage: python3 {Path(__file__).name} [--output ABSENT_ABSOLUTE_PATH]", file=sys.stderr)
        return 64
    try:
        if output is not None and (not output.is_absolute() or os.path.lexists(output)):
            raise CaptureError("output must be an absent absolute path")
        os.chdir(_ROOT)
        raw = _canonical(capture()) + b"\n"
        if output is not None:
            _write_output(output, raw)
    except (CaptureError, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"core-updater module acquisition failed closed: {exc}", file=sys.stderr)
        return 2
    if output is None:
        sys.stdout.buffer.write(raw)
    else:
        print(json.dumps({"path": str(output), "bytes": len(raw), "digest": _digest(raw)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
