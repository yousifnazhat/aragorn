"""Project retained worker bytes into the inventory namespace; never mount or install them."""
from aragorn.pi_core_confined_launch import _require_empty_mountpoints
from scripts import prepare_pi_core_restricted_worker_inventory as worker
from scripts.prepare_pi_core_restricted_worker_inventory import fixed, retained


ROOT = worker.ROOT
CHECKPOINT = "packaging/pi-core/restricted-inventory-checkpoint-v1.json"
CHECKPOINT_SHA256 = "bf2fecd4c7e22020d09def1fb4cbf5bd7a0c792141f86c8649153cecc53154d5"
PLAN = retained.BASE / "restricted-inventory-b37/worker-source-plan.json"
RUNTIME_DIRS = ("node", "node/bin", "observer", "pi-core")
VIEW_CHECKPOINT = "packaging/pi-core/worker-view-runtime-checkpoint-v1.json"
VIEW_CHECKPOINT_SHA256 = "eff2e329aeafd7e5c7963050b53304886d463d5b325041ca1a49292795e6242b"


def _reviewed_plan(root):
    checkpoint = worker._document(root / CHECKPOINT, CHECKPOINT_SHA256)
    plan_raw = retained.read(root / PLAN, 65536)
    pin = checkpoint["source_plan_digest"]
    retained.require("sha256:" + retained.sha(plan_raw) == pin, "retained worker plan bytes differ")
    plan = worker.installed._plan(plan_raw, pin)
    retained.require(plan_raw == fixed.canonical(retained.audit._json(retained.read(root / worker.PLAN, 65536))),
                     "worker plan differs from reviewed catalog")
    return checkpoint, plan, plan_raw


def _os_closure(root, plan):
    os_pin = worker._document(root / worker.OS, worker.OS_PIN)
    os_receipt = root / os_pin["receipt_local_path"]
    os_record = worker._document(os_receipt, os_pin["receipt_file_sha256"])
    tree = os_record["protected_tree"]
    retained.require(tree == os_pin["protected_tree"] and
                     fixed.digest(tree) == os_record["closure_digest"] == os_pin["closure_digest"] and
                     os_record["node_digest"] == os_pin["node_digest"] == plan["pins"]["node_digest"],
                     "worker OS closure differs")
    return os_receipt, tree


def worker_members(root=ROOT):
    """Return relative directories, file bytes/modes, and the exact retained v2 source plan."""
    checkpoint, plan, plan_raw = _reviewed_plan(root)
    os_receipt, tree = _os_closure(root, plan)

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


def candidate_content_inventory(*, root=ROOT):
    """Read only pinned metadata; report intended modes/content, not installed files or observed loads."""
    from scripts import prepare_pi_core_worker_view_runtime as candidate

    checkpoint, plan, _ = _reviewed_plan(root)
    _, os_tree = _os_closure(root, plan)
    b36 = worker._document(root / worker.RUNTIME, worker.RUNTIME_PIN)
    gate = worker._document(root / candidate.GATE_CHECKPOINT, candidate.GATE_CHECKPOINT_SHA)
    cp = worker._document(root / VIEW_CHECKPOINT, VIEW_CHECKPOINT_SHA256)
    retained.require(cp['schema'] == 'aragorn/pi-core-worker-view-runtime-checkpoint/v1' and
                     cp['output'] == str(candidate.OUTPUT) and set(cp['files']) == {'manifest.json','candidate-receipt.json'} and
                     all(cp[k] is False for k in ('target_executed','launch_authorized','phase3_exit_eligible')),
                     'unexpected candidate checkpoint')
    docs = {name: worker._document(root / candidate.OUTPUT / name, pin) for name,pin in cp['files'].items()}
    manifest, receipt = docs['manifest.json'], docs['candidate-receipt.json']
    retained.require(b36['runtime_digest'] == checkpoint['runtime_digest'] == fixed.RUNTIME_DIGEST and
                     b36['canonical_receipt_digest'] == candidate.PREVIOUS_RECEIPT and
                     plan['pins']['gate_digest'] == 'sha256:' + fixed.GATE_SHA256 and
                     gate['files']['build-receipt.json'] == candidate.GATE_RECEIPT[7:] and
                     gate['runtime_executed'] is gate['phase3_exit_eligible'] is False,
                     'unexpected predecessor or fixed-view gate')
    # Native launch still requires the original B36 gate. This is a separate candidate, never a successor source plan.
    gate_sha = gate['files']['source-gate']
    files = manifest['files']
    expected = [dict(r, digest='sha256:' + gate_sha, size=4232) if r['path'] == candidate.MEMBER else r
                for r in fixed.expected_files()]
    retained.require(manifest['schema'] == 'aragorn/manifest/v1' and
                     manifest['closure'] == {'scope':'source_tree','status':'complete'} and
                     fixed.canonical(files) == fixed.canonical(expected) and
                     fixed.digest(files) == manifest['tree_digest'], 'candidate file set, modes, sizes or tree differ')
    tree = fixed.digest([dict(path=r['path'], kind='file', bytes=r['size'], sha256=r['digest'][7:]) for r in files])
    exact = dict(schema=candidate.SCHEMA, status='STAGED_CANDIDATE_ONLY', replaced_member=candidate.MEMBER,
                 predecessor_checkpoint_sha256=worker.RUNTIME_PIN, predecessor_receipt_digest=candidate.PREVIOUS_RECEIPT,
                 predecessor_runtime_digest=fixed.RUNTIME_DIGEST, gate_checkpoint_sha256=candidate.GATE_CHECKPOINT_SHA,
                 gate_receipt_digest=candidate.GATE_RECEIPT, gate_elf_sha256=gate_sha, manifest_sha256=cp['files']['manifest.json'],
                 candidate_tree_digest=tree, installed=False, target_executed=False, launch_authorized=False, phase3_exit_eligible=False)
    retained.require(fixed.canonical(receipt) == fixed.canonical(exact) and cp['candidate_tree_digest'] == tree != fixed.RUNTIME_DIGEST,
                     'candidate receipt, gate provenance or projected tree differs')

    def row(prefix, r):
        return dict(path=prefix + r['path'], size=r['size'], digest=r['digest'], mode=0o555 if r['executable'] else 0o444)

    runtime = [row(fixed.PREFIX, r) for r in files]
    contents = {r['path']:r['digest'] for r in runtime}
    retained.require(contents[fixed.NODE_ARGV[0]] == plan['pins']['node_digest'] and
                     all(contents.get(r['path']) == r['digest'] for r in plan['sources']), 'unchanged worker sources differ')
    by_path = {'/' + r['path']:r for r in os_tree['files']}
    loaders = [row('/', by_path[r['path']]) for r in sorted(plan['loader_files'], key=lambda r:r['path'])]
    retained.require(len(loaders) == checkpoint['worker_loader_paths'] == 8 and
                     {r['path']:r['digest'] for r in loaders} == {r['path']:r['digest'] for r in plan['loader_files']},
                     'unchanged Node loader inventory differs')
    return dict(schema='aragorn/pi-core-worker-view-content-candidate/v1',
                candidate_receipt_digest='sha256:' + cp['files']['candidate-receipt.json'],
                candidate_manifest_digest='sha256:' + cp['files']['manifest.json'], candidate_tree_digest=tree,
                predecessor_plan_digest=checkpoint['source_plan_digest'], gate_receipt_digest=candidate.GATE_RECEIPT,
                runtime_files=runtime, node_loaders=loaders, installed_view_observed=False, target_executed=False,
                launch_authorized=False, phase3_exit_eligible=False)
