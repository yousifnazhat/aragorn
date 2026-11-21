"""Merge B62's protected caller into the retained B60 delta, offline; never install or boot."""
import json
import os
from pathlib import Path

from scripts import prepare_pi_core_b62_host_sources as sources
from scripts import prepare_pi_core_immutable_payload as image
from scripts.build_pi_core_linux import canonical, require, sha256
from scripts.prepare_pi_core_coordinator_host import host_contract


PRIOR = Path.home() / "Library/Application Support/Aragorn-B60-Offline"
OUT = PRIOR.parent / "Aragorn-B63-Offline"
REVIEW = image.ROOT / "packaging/pi-core/mask-host-successor-b63.json"
BASE_MANIFEST = "3cd63c0accffb9c42eb99f89056e19e3f65bbeb36ff7b17f62c5592a8335e8ce"
PRIOR_OUTCOME = "d71ecec97ecbcaeb1e7108244a284193aca8f97259461016d47e28a88596d7c0"
NAMES = ("coordinator-host.json", "payload.json", "worker-source-plan.json", "helper-inputs.json")


def _delta(base, target):
    """Minimal changed files plus their original directories. This successor deletes no path."""
    old = {r["path"]: r for r in base["entries"]}
    new = {r["path"]: r for r in target["entries"]}
    require(len(old) == len(base["entries"]) and len(new) == len(target["entries"]) and old.keys() <= new.keys(),
            "duplicate or removed payload path")
    different = {p for p in new if old.get(p) != new[p]}
    selected = set(different)
    for p in different:
        r = new[p]
        path = Path(p)
        require(str(path) == p and path.anchor == "/" and p != "/" and ".." not in path.parts and
                r["type"] == "file" and r["uid"] == r["gid"] == 0 and
                r["mode"] == (0o400 if p == image.PROFILE else 0o444) and
                (p not in old or all(old[p][k] == r[k] for k in ("type", "uid", "gid", "mode"))),
                "unexpected change to payload metadata or directory")
        for parent in path.parents:
            if parent != Path("/"):
                name = str(parent)
                require(name in old and old[name] == new[name] and old[name]["type"] == "dir",
                        "payload entry outside original directories")
                selected.add(name)
    return {"entries": [new[p] for p in sorted(selected)]}


def project(products, rows):
    require("sha256:" + sha256(canonical(rows)) == sources.ROWS_DIGEST, "unreviewed host sources")
    profile = host_contract._document(products["coordinator-host.json"])
    by_path = {r["path"]: r for r in profile["files"]}
    changes = {r["path"]: r for r in rows if by_path.get(r["path"]) != r}
    require(set(changes) == set(sources.CHANGED), "host change set differs from reviewed four paths")
    profile["files"] = sorted((by_path | changes).values(), key=lambda r: Path(r["path"]))
    host_contract._profile(profile)
    profile_raw = canonical(profile)
    prior_payload = json.loads(products["payload.json"])
    files = {r["path"]: r for r in prior_payload["entries"]}
    for path, row in changes.items():
        expected = dict(path=path, type="file", uid=0, gid=0, mode=0o444)
        if path in by_path:
            require(files.get(path) == dict(expected, size=by_path[path]["size"],
                    sha256=by_path[path]["digest"][7:]), "host and physical predecessor disagree")
        else:
            require(path not in files, "new host source collides with prior payload")
        files[path] = dict(expected, size=row["size"], sha256=row["digest"][7:])
    pro = files[image.PROFILE]
    require(pro["sha256"] == sha256(products["coordinator-host.json"]), "prior profile not in physical payload")
    files[image.PROFILE] = dict(pro, size=len(profile_raw), sha256=sha256(profile_raw))
    payload = dict(prior_payload, entries=[files[p] for p in sorted(files)])
    return {**products, "coordinator-host.json": profile_raw, "payload.json": canonical(payload)}


def _publish(delta, contents, products, outcome):
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe private staging parent")
    OUT.mkdir(mode=0o700)
    root = OUT / "changed-files"
    root.mkdir(mode=0o700)
    for row in delta["entries"]:
        target = root / row["path"][1:]
        if row["type"] == "dir":
            target.mkdir()
            target.chmod(row["mode"])
        else:
            image.new(target, contents[row["path"]], row["mode"])
    image.check_physical(root, delta)
    for name, raw in (*products.items(), ("outcome.json", canonical(outcome))):
        image.new(OUT / name, raw)
        require(image.read(OUT / name, sha256(raw), len(raw)) == raw, "publication readback differs")


def prepare():
    require(not os.path.lexists(OUT), "output already present; do not resume or replace it")
    outcome = json.loads(image.read(PRIOR / "outcome.json", PRIOR_OUTCOME, 8192))
    prior_products = {n: image.read(PRIOR / n, outcome["retained_files"][n], 2 << 20) for n in NAMES}
    base = json.loads(image.read(image.WORK / "payload.json", BASE_MANIFEST, 2 << 20))
    b60 = json.loads(prior_products["payload.json"])
    retained = PRIOR / "changed-files"
    image.check_physical(retained, _delta(base, b60))
    rows, repo_bytes = sources.prepare_host_sources()
    products = project(prior_products, rows)
    reviewed = json.loads(image.regular_bytes(REVIEW, 8192))
    pins = {n: sha256(raw) for n, raw in products.items()}
    require(reviewed["schema"] == "aragorn/pi-core-protected-capture-host-inputs/v1"
            and reviewed["source_revision"] == sources.REVISION and reviewed["files"] == pins,
            "successor projection does not match independently reviewed pins")
    delta = _delta(base, json.loads(products["payload.json"]))
    contents = {}
    for r in delta["entries"]:
        if r["type"] != "file":
            continue
        path = r["path"]
        if path == image.PROFILE:
            raw = products["coordinator-host.json"]
        elif path in sources.CHANGED:
            raw = repo_bytes[path]
        else:
            raw = image.read(retained / path[1:], r["sha256"], r["size"])
            require(raw == repo_bytes[path], "carried physical file differs from signed source")
        require(len(raw) == r["size"] and sha256(raw) == r["sha256"], "physical delta bytes disagree")
        contents[path] = raw
    result = dict(schema="aragorn/pi-core-protected-capture-host-payload/v1",
                  source_revision=sources.REVISION, source_tree=sources.TREE, source_rows_digest=sources.ROWS_DIGEST,
                  base_manifest_sha256=BASE_MANIFEST, prior_outcome_sha256=PRIOR_OUTCOME,
                  host_files=len(json.loads(products["coordinator-host.json"])["files"]),
                  changed_payload_files=len(contents), retained_files=pins,
                  image_assembled=False, installed_identity_verified=False, phase3_exit_eligible=False)
    _publish(delta, contents, products, result)
    return result
