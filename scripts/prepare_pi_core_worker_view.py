"""Project retained worker bytes into the inventory namespace; never mount or install them."""
from aragorn.pi_core_confined_launch import _require_empty_mountpoints
from scripts import prepare_pi_core_restricted_worker_inventory as worker
from scripts.prepare_pi_core_restricted_worker_inventory import fixed, retained


ROOT = worker.ROOT
CHECKPOINT = "packaging/pi-core/restricted-inventory-checkpoint-v1.json"
CHECKPOINT_SHA256 = "bf2fecd4c7e22020d09def1fb4cbf5bd7a0c792141f86c8649153cecc53154d5"
PLAN = retained.BASE / "restricted-inventory-b37/worker-source-plan.json"
RUNTIME_DIRS = ("node", "node/bin", "observer", "pi-core")


def worker_members(root=ROOT):
    """Return relative directories, file bytes/modes, and the exact retained v2 source plan."""
    checkpoint = worker._document(root / CHECKPOINT, CHECKPOINT_SHA256)
    plan_raw = retained.read(root / PLAN, 65536)
    pin = checkpoint["source_plan_digest"]
    retained.require("sha256:" + retained.sha(plan_raw) == pin, "retained worker plan bytes differ")
    plan = worker.installed._plan(plan_raw, pin)
    retained.require(plan_raw == fixed.canonical(retained.audit._json(retained.read(root / worker.PLAN, 65536))),
                     "worker plan differs from reviewed catalog")

    os_pin = worker._document(root / worker.OS, worker.OS_PIN)
    os_receipt = root / os_pin["receipt_local_path"]
    os_record = worker._document(os_receipt, os_pin["receipt_file_sha256"])
    tree = os_record["protected_tree"]
    retained.require(tree == os_pin["protected_tree"] and
                     fixed.digest(tree) == os_record["closure_digest"] == os_pin["closure_digest"] and
                     os_record["node_digest"] == os_pin["node_digest"] == plan["pins"]["node_digest"],
                     "worker OS closure differs")

    runtime = worker._document(root / worker.RUNTIME, worker.RUNTIME_PIN)
    base = root / runtime["output"]
    records = {name: worker._document(base / name, digest) for name, digest in runtime["files"].items()}
    manifest = records["manifest.json"]
    digest = fixed.validate_runtime(records["build-receipt.json"], manifest, runtime["canonical_receipt_digest"])
    retained.require(digest == fixed.RUNTIME_DIGEST == runtime["runtime_digest"] ==
                     records["outcome.json"]["runtime_tree_digest"] == checkpoint["runtime_digest"],
                     "worker runtime closure differs")

    # The base OS must keep this empty for the launcher's read-only bind; only the projection is merged.
    mount = fixed.PREFIX.strip("/")
    _require_empty_mountpoints(tree, tuple(tree["directories"]))
    directories = set(tree["directories"])
    directories.update(mount + "/" + name for name in RUNTIME_DIRS)
    files, pins = {}, {}
    for src, dirs, rows, prefix in ((os_receipt.parent / "root", tree["directories"], tree["files"], ""),
                                    (base / "deployment", RUNTIME_DIRS, manifest["files"], mount + "/")):
        data = worker._staged_bytes(src, dirs, rows)
        for row in rows:
            name = prefix + row["path"]
            files[name] = (data[row["path"]], 0o555 if row["executable"] else 0o444)
            pins["/" + name] = row["digest"]
    expected = {fixed.GATE_PATH: plan["pins"]["gate_digest"], fixed.NODE_ARGV[0]: plan["pins"]["node_digest"]}
    expected.update((r["path"], r["digest"]) for r in plan["sources"] + plan["loader_files"])
    retained.require(all(pins.get(name) == digest for name, digest in expected.items()),
                     "worker view does not supply the pinned inventory")
    return directories, files, plan_raw
