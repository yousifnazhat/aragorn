"""Select exact B105 worker and observer bytes without inventing installed identities."""

import json
import os

from aragorn import pi_core_restricted_profile as fixed
from aragorn import pi_core_source_inventory_prepare as inventory
from scripts import prepare_pi_core_b105_payload as b105
from scripts.build_pi_core_linux import canonical, require, sha256


BASE = b105.OUT
OUT = BASE.with_name("Aragorn-B106-Offline")
PRIOR_PLAN = b105.split.worker.PLAN_PIN
PRIOR_PATH = b105.split.PRIOR / "worker-source-plan.json"
PLAN_PIN = "a97e19440e7576edd52039334e9969e3681d8b9280f4eabd1f03aa9da1876e0f"
WORKER_ROWS_PIN = "26c5d0d1b43ef688845db21fcd3e9c9ce600078389ba2f2c469dc9ba4fa0ace9"
_OBSERVERS = {
    "producer_digest": "/opt/aragorn/src/aragorn/pi_core_source_observer.py",
    "node_observer_digest": "/opt/aragorn/src/aragorn/pi_core_node_source_observer.py",
}


def project():
    """Return the reviewed plan, offline binding receipt and exact staged rows to read."""
    read = b105.image.read
    base = json.loads(read(BASE / "payload.json", b105.PAYLOAD_PIN, 2 << 20))
    outcome = json.loads(read(BASE / "outcome.json", b105.OUTCOME_PIN, 64 << 10))
    require(base["schema"] == b105.split.SCHEMA and outcome["payload_sha256"] == b105.PAYLOAD_PIN and
            outcome["installed_identity_verified"] is outcome["activation_performed"] is False,
            "B105 completed offline layout required")
    payload = b105.split._index(base["entries"])
    worker_roots = (b105.split.worker.RUNTIME_ROOT, b105.split.worker.OS_ROOT)
    worker_rows = [r for path, r in sorted(payload.items()) if any(
        path == root or path.startswith(root + "/") for root in worker_roots)]
    require(len(worker_rows) == 37 and sha256(canonical(worker_rows)) == WORKER_ROWS_PIN,
            "B105 split worker differs from the independently reviewed B64 layout")

    def document(path, name):
        pin = b105.sources.PINS[name]
        require(payload[path]["sha256"] == pin, "B105 inventory row differs")
        return json.loads(read(BASE / "root" / path[1:], pin, 2 << 20))

    host = {r["path"]: r for r in document(b105.image.PROFILE, "coordinator-host.json")["files"]}
    service = {r["path"]: r for r in document(b105.managed._M, "manifest.json")["files"]}
    binding = document(b105.managed._B, "runtime-binding.json")["source_digests"]
    prior = read(PRIOR_PATH, PRIOR_PLAN, 65536)
    plan = inventory._plan(prior, "sha256:" + PRIOR_PLAN)
    require(plan["schema"] == fixed.PLAN_SCHEMA, "restricted B63 source plan required")
    rows = {}

    def select(path, digest, mode, size=None):
        row = payload[path]
        require(row["type"] == "file" and row["mode"] == mode and row["sha256"] == digest[7:] and
                0 < row["size"] <= 128 << 20 and (size is None or row["size"] == size),
                "B105 staged file row differs: " + path)
        require(path not in rows, "B105 source role path reused")
        rows[path] = row

    runtime = {fixed.PREFIX + r["path"]: r for r in fixed.expected_files()}
    require({r["path"]: r["digest"] for r in plan["sources"]} == {
        path: r["digest"] for path, r in runtime.items() if not r["executable"]}, "B105 source declarations differ")
    for name, r in runtime.items():
        select(b105.split.worker.RUNTIME_ROOT + "/" + name.removeprefix(fixed.PREFIX),
               r["digest"], 0o555 if r["executable"] else 0o444, r["size"])
    for r in plan["loader_files"]:
        path = b105.split.worker.OS_ROOT + r["path"]
        select(path, r["digest"], payload[path]["mode"])

    for key, path in _OBSERVERS.items():
        source = host[path]
        installed = service[path[1:]]
        require(source["digest"] == binding[path[1:]] == installed["digest"] and
                source["size"] == installed["size"] and installed["executable"] is False,
                "B105 manager and service observer inputs differ")
        require((source["digest"] == plan["pins"][key]) == (key == "producer_digest"),
                "expected only the Node observer source revision to change")
        select(path, source["digest"], 0o444, source["size"])
        select(b105.prior.TREE + path, source["digest"], 0o444, source["size"])
        plan["pins"][key] = source["digest"]
    raw = canonical(plan)
    source_pin = "sha256:" + PLAN_PIN
    inventory._plan(raw, source_pin)
    receipt = dict(schema="aragorn/pi-core-b106-worker-observer-binding/v1",
        authority="OFFLINE_CONTENT_INTENT_ONLY_NOT_INSTALLATION_CONSUMPTION_OR_LAUNCH",
        payload_digest="sha256:" + b105.PAYLOAD_PIN, payload_outcome_digest="sha256:" + b105.OUTCOME_PIN,
        host_profile_digest="sha256:" + b105.sources.PINS["coordinator-host.json"],
        service_manifest_digest="sha256:" + b105.sources.PINS["manifest.json"],
        service_runtime_binding_digest="sha256:" + b105.sources.PINS["runtime-binding.json"],
        predecessor_source_plan_digest="sha256:" + PRIOR_PLAN, source_plan_digest=source_pin,
        worker_runtime_digest=fixed.RUNTIME_DIGEST, worker_payload_rows_digest="sha256:" + WORKER_ROWS_PIN,
        source_rows=len(plan["sources"]),
        loader_rows=len(plan["loader_files"]), staged_files=len(rows), installed_identity_verified=False,
        worker_consumption_verified=False, activation_authorized=False, phase3_exit_eligible=False)
    return raw, receipt, rows


def _read_rows(root, rows):
    for path, row in rows.items():
        data = b105.prior._retained(root, path[1:], row)
        require(len(data) == row["size"] and sha256(data) == row["sha256"], "B105 file bytes differ: " + path)


def prepare():
    require(not os.path.lexists(OUT), "output already present; no adoption, overwrite or retry")
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe private staging parent")
    raw, outcome, rows = project()
    _read_rows(BASE / "root", rows)
    OUT.mkdir(mode=0o700)
    for name, data in (("worker-source-plan.json", raw), ("outcome.json", canonical(outcome))):
        b105.image.new(OUT / name, data)
        require(b105.image.read(OUT / name, sha256(data), 65536) == data, "B106 binding readback differs")
    b105.managed._sync_directory(OUT)
    b105.managed._sync_directory(parent)
    return outcome


if __name__ == "__main__":
    print(json.dumps(prepare(), sort_keys=True))
