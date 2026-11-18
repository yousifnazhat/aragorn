"""Prepare content intent from retained bytes, not an installed view or observed loads."""
import os
from pathlib import Path
import stat

from aragorn import pi_core_restricted_profile as fixed
from aragorn import pi_core_source_inventory_prepare as installed
from scripts import prepare_pi_core_os_root as elf
from scripts import prepare_pi_core_restricted_host_sources as host
from scripts import prepare_pi_core_restricted_runtime as retained

ROOT = retained.ROOT
PLAN = Path("packaging/pi-core/restricted-worker-inventory-v1.json")
RUNTIME = Path("packaging/pi-core/restricted-runtime-artifact-v1.json")
OS = Path("packaging/pi-core/os-artifact-v1.json")
RUNTIME_PIN = "23cac7e0553e5de1e380b366b140bdda6f8f3569b77868c9865ad742927f3889"
OS_PIN = "42e8f202436c0606c479b7718791bbfb6c6a11b35e820d1bff6a9c03c981b53b"


def _document(path, sha):
    raw = retained.read(path, 1 << 20)
    retained.require(retained.sha(raw) == sha, "retained document differs: " + path.name)
    return retained.audit._json(raw)


def _staged_bytes(root, directories, files):
    # Developer-owned staging directories may be private and writable. Pin bytes
    # and namespace; never promote their metadata to immutable installed identity.
    children = {"": set(), **{name: set() for name in directories}}
    for name in [*directories, *(r["path"] for r in files)]:
        parent, _, leaf = name.rpartition("/")
        retained.require(elf.relative(name) == name and parent in children, "incomplete staged namespace")
        children[parent].add(leaf)

    def snapshot():
        states = {}
        for name, names in children.items():
            p = retained.plain(root / name)
            st = p.lstat()
            retained.require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
                             not st.st_mode & 0o7022 and {child.name for child in p.iterdir()} == names,
                             "staged directory or file set differs: " + name)
            states[name] = (st.st_dev, st.st_ino, st.st_mode, st.st_ctime_ns, st.st_mtime_ns)
        return states

    before = snapshot()
    data, states = {}, {}
    for row in files:
        name = row["path"]
        path = root / name
        mode = 0o555 if row["executable"] else 0o444
        st = retained.plain(path).lstat()
        retained.require(stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == mode and st.st_nlink == 1 and
                         st.st_size == row["size"] and 0 < st.st_size <= 128 << 20, "staged member metadata differs")
        data[name] = retained.read(path, row["size"])
        retained.require("sha256:" + retained.sha(data[name]) == row["digest"], "staged member digest differs: " + name)
        states[name] = (st.st_dev, st.st_ino, st.st_ctime_ns, st.st_mtime_ns)
    retained.require(snapshot() == before, "staged namespace changed")
    for name, expected in states.items():
        st = retained.plain(root / name).lstat()
        retained.require((st.st_dev, st.st_ino, st.st_ctime_ns, st.st_mtime_ns) == expected, "staged member changed")
    return data


def _node_loaders(node, os_data, receipt):
    tree = elf.ImageTree()
    for row in receipt["protected_tree"]["files"]:
        tree.entries[row["path"]] = {"kind": "file", "mode": 0o555 if row["executable"] else 0o444,
                                     "raw": os_data[row["path"]]}
    selected, edges = elf.closed_elf_inventory(tree, node)
    # source_path is an OCI layer origin, not a path in the flattened staging root.
    def projection(rows):
        return [tuple(row[k] for k in ("requester", "kind", "requested", "path", "digest")) for row in rows]
    retained.require(set(selected) == set(os_data) and projection(edges) == projection(receipt["elf_dependencies"]),
                     "declared ELF dependency graph differs")
    pending, reachable = ["@compiled-node"], set()
    while pending:
        parent = pending.pop()
        for row in edges:
            if row["requester"] == parent and row["path"] not in reachable:
                reachable.add(row["path"])
                pending.append(row["path"])
    return [dict(path="/" + name, digest=elf.pin(os_data[name])) for name in sorted(reachable)]


def _plan(host_rows, loaders, reviewed):
    by_path = {row["path"]: row["digest"] for row in host_rows}
    required = ("/opt/aragorn/src/aragorn/pi_core_source_observer.py",
                "/opt/aragorn/src/aragorn/pi_core_node_source_observer.py")
    retained.require(len(by_path) == len(host_rows) and all(k in by_path for k in required),
                     "missing or duplicate host observer pin")
    plan = dict(schema=fixed.PLAN_SCHEMA, pins=dict(gate_digest="sha256:" + fixed.GATE_SHA256,
        node_digest="sha256:" + fixed.NODE_SHA256, producer_digest=by_path[required[0]],
        node_observer_digest=by_path[required[1]]), required_sources=[fixed.ENTRY_PATH], sources=[
        dict(path=fixed.ENTRY_PATH, digest="sha256:" + fixed.BUNDLE_SHA256),
        dict(path=fixed.PREFIX + "pi-core/package.json", digest="sha256:" + fixed.PACKAGE_SHA256)], loader_files=loaders)
    retained.require(plan == reviewed, "selected plan differs from reviewed worker inventory")
    raw = fixed.canonical(plan)
    installed._plan(raw, fixed.digest(plan))
    return raw


def prepare_worker_inventory(root=ROOT):
    """Return verified host rows and exact no-LF v2 source-plan bytes. No writes."""
    root = retained.plain(Path(root))
    host_rows = host.prepare_host_sources(root=root)
    checkpoint = _document(root / RUNTIME, RUNTIME_PIN)
    location = root / checkpoint["output"]
    records = {key: _document(location / key, pin) for key, pin in checkpoint["files"].items()}
    manifest = records["manifest.json"]
    runtime = fixed.validate_runtime(records["build-receipt.json"], manifest, checkpoint["canonical_receipt_digest"])
    retained.require(runtime == fixed.RUNTIME_DIGEST == checkpoint["runtime_digest"] ==
                     records["outcome.json"]["runtime_tree_digest"], "wrong retained runtime")
    runtime_data = _staged_bytes(location / "deployment", ["node", "node/bin", "observer", "pi-core"], manifest["files"])

    os_pin = _document(root / OS, OS_PIN)
    os_path = root / os_pin["receipt_local_path"]
    receipt = _document(os_path, os_pin["receipt_file_sha256"])
    protected = receipt["protected_tree"]
    retained.require(receipt["node_digest"] == "sha256:" + fixed.NODE_SHA256 == os_pin["node_digest"] and
                     fixed.digest(protected) == receipt["closure_digest"] == os_pin["closure_digest"] and
                     protected == os_pin["protected_tree"], "retained Node and OS closure differ")
    os_data = _staged_bytes(os_path.parent / "root", protected["directories"], protected["files"])
    loaders = _node_loaders(runtime_data["node/bin/node"], os_data, receipt)
    reviewed = retained.audit._json(retained.read(root / PLAN, 65536))
    return host_rows, _plan(host_rows, loaders, reviewed)
