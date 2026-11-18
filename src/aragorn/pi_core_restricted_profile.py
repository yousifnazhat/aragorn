"""Fixed release identities, not a switch granting runtime or provider authority."""
from __future__ import annotations

import hashlib
import json

PREFIX = "/opt/aragorn/pi-runtime/"
GATE_PATH = PREFIX + "observer/source-gate"
ENTRY_PATH = PREFIX + "pi-core/entrypoint.js"
NODE_ARGV = (PREFIX + "node/bin/node", "--disallow-code-generation-from-strings", ENTRY_PATH)
RUNTIME_SCHEMA = "aragorn/pi-core-bundled-linux-build/v1"
PROFILE_SCHEMA = "aragorn/pi-core-node-source-profile/v2"
PLAN_SCHEMA = "aragorn/pi-core-source-plan/v2"
GATE_SCHEMA = "aragorn/pi-core-source-gate-build/v2"
BUNDLE_SHA256 = "0806d07ae9110eaa1d98d97b49d4ee305deaf95b82c0c0b61ca905f24bf73c44"
META_SHA256 = "aaeac376685027df4780ad5e8c5f8628e6d76134e61a9ebaab347b759ca73bac"
BUNDLE_RECEIPT_SHA256 = "c6eb0f9483aacdfc1c5cb3a726bd51026014342f37a303c0b65c06f7ae3d3d65"
NODE_SHA256 = "b4855de8c4781130b722ceaec9718fed77cca3eed2e5cfc5455e267c0b9ee3b0"
PACKAGE_SHA256 = "f913fc41b0e32167b11c7253db4ec4a63080b4bfd3e6b6aa7d4b97863f348bab"
GATE_SHA256 = "7bbb6d6ad10732747f8145abc51b9732598bb0e926acd82f14196469ec316620"
GATE_BYTES = 2152
GATE_RECEIPT_SHA256 = "f150270e1c8bf1e9fc3c06a4cd55c8579e7d7e993ee4af31b8cfe7a58ae324c6"
RUNTIME_DIGEST = "sha256:5629ad71c1665dcf2da51fabae3969e4e9ed84db6a648dbdfebbdb52492a4e9e"


def _require(ok, reason):
    if not ok:
        raise ValueError("restricted Pi profile: " + reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def validate_gate(gate_build):
    _require(len(GATE_SHA256) == len(GATE_RECEIPT_SHA256) == 64 and type(gate_build) is dict and
             set(gate_build) == {"schema", "target", "source_sha256", "elf_sha256", "compiler_sha256",
                 "build_command_sha256", "node_argv", "runtime_executed", "receipt_digest"}, "gate receipt fields")
    raw = canonical({k: v for k, v in gate_build.items() if k != "receipt_digest"}) + b"\n"
    _require(gate_build["schema"] == GATE_SCHEMA and gate_build["target"] == "linux-arm64-static" and
             gate_build["runtime_executed"] is False and gate_build["node_argv"] == list(NODE_ARGV) and
             gate_build["elf_sha256"] == GATE_SHA256 and hashlib.sha256(raw).hexdigest() == GATE_RECEIPT_SHA256 and
             gate_build["receipt_digest"] == "sha256:" + GATE_RECEIPT_SHA256, "unapproved gate/argv")


def uses_restricted_inputs(value):
    if not isinstance(value, dict):
        return False
    pins = value.get("pins", value.get("bindings", {}))
    known = ("sha256:" + BUNDLE_SHA256, "sha256:" + GATE_SHA256)
    return ((isinstance(pins, dict) and (pins.get("gate_digest") in known or pins.get("runtime_digest") == RUNTIME_DIGEST))
            or any(isinstance(row, dict) and row.get("digest") in known
                   for key in ("sources", "loader_files", "loaders", "files") if isinstance(value.get(key), list)
                   for row in value[key]))


def validate_profile(value):
    _require(type(value) is dict and value.get("schema") == PROFILE_SCHEMA and type(value.get("pins")) is dict,
             "source profile version")
    pins = value["pins"]
    _require(pins.get("gate_digest") == "sha256:" + GATE_SHA256 and
             pins.get("node_digest") == "sha256:" + NODE_SHA256 and len(GATE_SHA256) == 64, "source profile gate/node")
    _require(all(type(value.get(k)) is list for k in ("sources", "loader_files", "required_sources")),
             "source inventory")
    expected = {ENTRY_PATH: "sha256:" + BUNDLE_SHA256, PREFIX + "pi-core/package.json": "sha256:" + PACKAGE_SHA256,
                NODE_ARGV[0]: "sha256:" + NODE_SHA256, GATE_PATH: "sha256:" + GATE_SHA256}
    for field in ("sources", "loader_files"):
        for row in value[field]:
            _require(type(row) is dict and type(row.get("path")) is str, "source row")
            name, pin = row["path"], row.get("digest")
            if name.startswith(PREFIX):
                _require(name in expected and expected[name] == pin and (name != ENTRY_PATH or field == "sources"),
                         "incorrect runtime inventory member")
            _require(pin != expected[ENTRY_PATH] or name == ENTRY_PATH, "aliased bundle")
    _require(sum(row == {"path": ENTRY_PATH, "digest": expected[ENTRY_PATH]} for row in value["sources"]) == 1
             and ENTRY_PATH in value["required_sources"], "bundle delivery must be required")


def expected_files():
    _require(GATE_BYTES > 0 and len(GATE_SHA256) == 64, "gate unavailable")
    return [{"path": name, "size": n, "digest": "sha256:" + pin, "executable": executable}
            for name, n, pin, executable in (
                ("node/bin/node", 123378856, NODE_SHA256, True),
                ("observer/source-gate", GATE_BYTES, GATE_SHA256, True),
                ("pi-core/entrypoint.js", 755592, BUNDLE_SHA256, False),
                ("pi-core/package.json", 436, PACKAGE_SHA256, False))]


def runtime_receipt(gate_build):
    validate_gate(gate_build)
    rows = [{"path": r["path"], "kind": "file", "bytes": r["size"], "sha256": r["digest"][7:]}
            for r in expected_files()]
    _require(digest(rows) == RUNTIME_DIGEST, "runtime inventory differs from the release")
    return {"schema": RUNTIME_SCHEMA, "target": "linux-arm64-glibc", "node_version": "24.22.2",
            "status": "ASSEMBLED_NOT_DEPLOYED_OR_OS_QUALIFIED", "runtime_executed": False,
            "deployment_inventory": rows, "deployment_tree_sha256": digest(rows)[7:],
            "inputs": {"source_gate": gate_build, "worker_build_receipt_sha256": BUNDLE_RECEIPT_SHA256,
                       "worker_metadata_sha256": META_SHA256}}


def validate_runtime(receipt, manifest, receipt_digest):
    _require(type(receipt) is dict and type(receipt.get("inputs")) is dict, "runtime receipt")
    expected = runtime_receipt(receipt["inputs"].get("source_gate"))
    _require(canonical(receipt) == canonical(expected) and receipt_digest == digest(expected), "runtime receipt mismatch")
    _require(type(manifest) is dict and canonical(manifest.get("files")) == canonical(expected_files()),
             "installed file bytes, modes or names differ")
    return "sha256:" + expected["deployment_tree_sha256"]
