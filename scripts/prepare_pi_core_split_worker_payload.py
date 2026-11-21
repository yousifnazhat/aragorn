"""Read the fixed B53 reference archive into the two distinct trees used by the native launcher."""
import io
import json
import tarfile

from aragorn import pi_core_confined_launch as launch
from scripts import prepare_pi_core_worker_filesystem as b53
from scripts import prepare_pi_core_worker_view as view
from scripts.build_pi_core_linux import ROOT, require, sha256


OS_ROOT = "/var/lib/aragorn/pi-os"
RUNTIME_ROOT = "/var/lib/aragorn/pi-runtime"
MOUNT = view.fixed.PREFIX.strip("/")
B53_RECEIPT = "97a7339d3b1d5bce33b5398df8ef7ffee7fe1a193cd042aed018218810c02ca7"
HOST_PIN = "31457b9d0f3bd75693f4ca80bd59705c1e402976c02604c30462a8dcf51d1683"
PLAN_PIN = "2f61a4a6bb4f4dc6f5554435fe3825a3390990af759e9cb9826bf18fcaea90ec"


def _split(raw, archive_pin, os_tree, runtime_manifest):
    require(sha256(raw) == archive_pin, "B53 worker archive differs")
    launch._require_empty_mountpoints(os_tree, tuple(os_tree["directories"]))
    rows, members, contents = {}, {}, {}
    for root, prefix, directories, files in (
            (OS_ROOT, "", os_tree["directories"], os_tree["files"]),
            (RUNTIME_ROOT, MOUNT + "/", view.RUNTIME_DIRS, runtime_manifest["files"])):
        # _open_protected_root and B3 provisioning require owner-write on each outer root.
        rows[root] = dict(path=root, type="dir", uid=0, gid=0, mode=0o755)
        for name in directories:
            path = root + "/" + name
            members[prefix + name] = path
            rows[path] = dict(path=path, type="dir", uid=0, gid=0, mode=0o555)
        for r in files:
            name = r["path"]
            path = root + "/" + name
            members[prefix + name] = path
            rows[path] = dict(path=path, type="file", uid=0, gid=0, mode=0o555 if r["executable"] else 0o444,
                              size=r["size"], sha256=r["digest"].removeprefix("sha256:"))
    # Only look up complete trusted names. Never extract a pathname from the tar to disk.
    expected = iter(sorted(members))
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            require(member.name == next(expected, None), "unexpected or missing worker archive member")
            path = members[member.name]
            row = rows[path]
            directory = row["type"] == "dir"
            require(member.type == (tarfile.DIRTYPE if directory else tarfile.REGTYPE) and
                    member.mode == row["mode"] and member.uid == member.gid == 0 and
                    member.size == row.get("size", 0), "worker archive member metadata differs")
            if not directory:
                with archive.extractfile(member) as stream:
                    data = stream.read(row["size"] + 1)
                require(len(data) == row["size"] and sha256(data) == row["sha256"], "worker file digest differs")
                contents[path] = data
    require(next(expected, None) is None, "worker archive ended early")
    return {"entries": [rows[p] for p in sorted(rows)]}, contents


def prepare(host_profile_raw, plan_raw):
    require(sha256(host_profile_raw) == HOST_PIN and sha256(plan_raw) == PLAN_PIN, "B63 host or worker plan differs")
    plan = view.worker.installed._plan(plan_raw, "sha256:" + PLAN_PIN)
    host = {r["path"]: r["digest"] for r in json.loads(host_profile_raw)["files"]}
    for key, name in (("producer_digest", "pi_core_source_observer"), ("node_observer_digest", "pi_core_node_source_observer")):
        require(plan["pins"][key] == host["/opt/aragorn/src/aragorn/" + name + ".py"], "host observer and worker plan differ")

    receipt = view.worker._document(b53.OUT / "outcome.json", B53_RECEIPT)
    os_record = view.worker._document(ROOT / view.worker.OS, view.worker.OS_PIN)
    tree = os_record["protected_tree"]
    require(view.fixed.digest(tree) == os_record["closure_digest"], "invalid OS closure")
    catalog = view.worker._document(ROOT / view.worker.RUNTIME, view.worker.RUNTIME_PIN)
    def document(name):
        return view.worker._document(ROOT / catalog["output"] / name, catalog["files"][name])
    manifest, compiled = document("manifest.json"), document("build-receipt.json")
    receipt_pin = catalog["canonical_receipt_digest"]
    runtime_pin = launch._runtime_inventory(manifest, compiled, receipt_pin)
    require(runtime_pin == catalog["runtime_digest"] == receipt["runtime_digest"] == view.fixed.RUNTIME_DIGEST,
            "worker runtime build or archive receipt differs")
    require(launch._source_gate_artifact(manifest, compiled)["digest"] == plan["pins"]["gate_digest"] and
            os_record["node_digest"] == plan["pins"]["node_digest"], "worker gate or Node pin differs")
    original = view.worker.installed._plan(view.retained.read(b53.OUT / "worker-source-plan.json", 65536),
                                         "sha256:" + receipt["source_plan_sha256"])
    original["pins"]["node_observer_digest"] = plan["pins"]["node_observer_digest"]
    require(original == plan, "B53 worker intent changed beyond B60 observer replacement")
    archive_pin = receipt["archives"]["worker-view.tar"]
    projection, files = _split(view.retained.read(b53.OUT / "worker-view.tar", b53.LIMIT), archive_pin, tree, manifest)
    expected = {r["path"]: r["digest"] for r in plan["sources"] + plan["loader_files"]}
    expected.update({view.fixed.GATE_PATH: plan["pins"]["gate_digest"], view.fixed.NODE_ARGV[0]: plan["pins"]["node_digest"]})
    projected = {r["path"]: "sha256:" + r["sha256"] for r in projection["entries"] if r["type"] == "file"}
    for path, pin in expected.items():
        target = RUNTIME_ROOT + "/" + path[len(view.fixed.PREFIX):] if path.startswith(view.fixed.PREFIX) else OS_ROOT + path
        require(projected.get(target) == pin, "split member differs from B63 worker observation plan")
    binding = dict(os_root=OS_ROOT, runtime_root=RUNTIME_ROOT, os_closure_digest=os_record["closure_digest"],
                   runtime_digest=runtime_pin, compiled_receipt_digest=receipt_pin, worker_source_plan_digest="sha256:" + PLAN_PIN,
                   worker_archive_sha256=archive_pin, b53_receipt_sha256=B53_RECEIPT)
    return projection, files, binding
