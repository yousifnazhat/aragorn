"""Prepare only the B59 changes to the immutable host payload. Never mount or install it."""
import json
import os
from pathlib import Path

from aragorn import pi_core_source_inventory_prepare as inventory
from scripts import prepare_pi_core_immutable_payload as image
from scripts import prepare_pi_core_mask_host_sources as sources
from scripts import verify_pi_core_mask_guest_inputs as guest
from scripts.prepare_pi_core_coordinator_host import host_contract
from scripts.build_pi_core_linux import canonical, require, sha256


OUT = Path.home() / "Library/Application Support/Aragorn-B60-Offline"
PLAN = OUT.parent / "Aragorn-B53-Offline/worker-source-plan.json"
PRIOR_PLAN = "305679f5a4891465d0820e2f2adfb3402e60b9d50489c1ccd93bb6ea8bd66ac4"
PRIOR_PROFILE = "ab3a3a5ab3f10125e37523d28969bfcb3f6e709dbb16042be445ee9a30f79dcf"
PRIOR_MANIFEST = "3cd63c0accffb9c42eb99f89056e19e3f65bbeb36ff7b17f62c5592a8335e8ce"
REVIEW = image.ROOT / "packaging/pi-core/mask-host-successor-b60.json"
PREFIX = "/opt/aragorn/src/aragorn/"


def project(profile_raw, manifest_raw, plan_raw, rows):
    require((sha256(profile_raw), sha256(manifest_raw), sha256(plan_raw)) ==
            (PRIOR_PROFILE, PRIOR_MANIFEST, PRIOR_PLAN), "foreign immutable host, payload or worker predecessor")
    require("sha256:" + sha256(canonical(rows)) == sources.ROWS_DIGEST, "foreign observer source projection")
    profile = host_contract._document(profile_raw)
    by_path = {row["path"]: row for row in profile["files"]}
    changes = {row["path"]: row for row in rows if by_path.get(row["path"]) != row}
    require(changes and all(name.startswith(PREFIX) and name.endswith(".py") for name in changes),
            "successor changed the wrapper or non-Python host file")
    profile["files"] = sorted((by_path | changes).values(), key=lambda r: Path(r["path"]))
    host_contract._profile(profile)
    profile_raw = canonical(profile)
    manifest = json.loads(manifest_raw)
    physical = {r["path"]: r for r in manifest["entries"]}
    delta = {}
    files = {**changes, image.PROFILE: dict(size=len(profile_raw), digest="sha256:" + sha256(profile_raw))}
    for name, row in files.items():
        parent = physical[str(Path(name).parent)]
        mode = 0o400 if name == image.PROFILE else 0o444
        prior = physical.get(name)
        require(parent["type"] == "dir" and (prior is None or
                (prior["type"], prior["uid"], prior["gid"], prior["mode"]) == ("file", 0, 0, mode)),
                "unexpected target layout")
        physical[name] = delta[name] = dict(type="file", uid=0, gid=0, mode=mode, path=name,
                                            size=row["size"], sha256=row["digest"][7:])
        for directory in Path(name).parents:
            if directory != Path("/"):
                delta[str(directory)] = physical[str(directory)]
    manifest["entries"] = [physical[n] for n in sorted(physical)]
    plan = inventory._plan(plan_raw, "sha256:" + PRIOR_PLAN)
    observer = PREFIX + "pi_core_node_source_observer.py"
    require(plan["pins"]["node_observer_digest"] == by_path[observer]["digest"], "stale observer plan")
    plan["pins"]["node_observer_digest"] = changes[observer]["digest"]
    plan_raw = canonical(plan)
    inventory._plan(plan_raw, "sha256:" + sha256(plan_raw))
    return profile_raw, canonical(manifest), plan_raw, {"entries": [delta[p] for p in sorted(delta)]}


def prepare():
    reviewed = json.loads(image.regular_bytes(REVIEW, 8192))
    rows = sources.prepare_host_sources()
    profile, manifest, plan, delta = project(
        image.read(image.WORK / "coordinator-host.json", PRIOR_PROFILE, 2 << 20),
        image.read(image.WORK / "payload.json", PRIOR_MANIFEST, 2 << 20),
        image.read(PLAN, PRIOR_PLAN, 65536), rows)
    products = {"coordinator-host.json": profile, "payload.json": manifest, "worker-source-plan.json": plan}
    require(reviewed["files"] == {n: sha256(v) for n, v in products.items()}
            and reviewed["source_revision"] == sources.REVISION, "successor differs from reviewed projections")
    payloads = {}
    for r in delta["entries"]:
        if r["type"] == "file":
            name = r["path"]
            payloads[name] = profile if name == image.PROFILE else image.read(
                image.ROOT / name.removeprefix("/opt/aragorn/"), r["sha256"], r["size"])
    helper = sources.helper_bytes(payloads[PREFIX + "pi_core_mask_probe.py"])
    runtime = guest.verify_guest_inputs(payload_dir=image.WORK, helper_source=helper.decode("ascii"))
    parsed = json.loads(profile)
    interpreter = next(r for r in parsed["files"] if r["path"] == parsed["python_executable"])
    require(runtime["helper_digest"] == sources.PROBE_DIGEST and runtime["interpreter_digest"] == interpreter["digest"]
            and runtime["host_profile_digest"] == "sha256:" + PRIOR_PROFILE, "helper and host refer to different inputs")
    # Publish once, outside the managed checkout. Partial output is retained, never adopted.
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe output parent")
    OUT.mkdir(mode=0o700)
    root = OUT / "changed-files"
    root.mkdir(mode=0o700)
    for r in delta["entries"]:
        target = root / r["path"][1:]
        if r["type"] == "dir":
            target.mkdir()
            target.chmod(r["mode"])
        else:
            image.new(target, payloads[r["path"]], r["mode"])
    image.check_physical(root, delta)
    products["helper-inputs.json"] = canonical(runtime)
    for name, data in products.items():
        image.new(OUT / name, data)
        require(image.read(OUT / name, sha256(data), len(data)) == data, "retained metadata differs")
    result = dict(schema="aragorn/pi-core-mask-host-successor-preparation/v1",
                  source_revision=sources.REVISION, source_tree=sources.TREE,
                  host_files=len(parsed["files"]), changed_payload_files=len(payloads),
                  source_rows_digest=sources.ROWS_DIGEST, helper_digest=sources.PROBE_DIGEST,
                  interpreter_digest=runtime["interpreter_digest"], retained_files={n: sha256(v) for n,v in products.items()},
                  image_assembled=False, installed_identity_verified=False, phase3_exit_eligible=False)
    image.new(OUT / "outcome.json", canonical(result))
    require(image.read(OUT / "outcome.json", sha256(canonical(result)), 16384) == canonical(result),
            "retained outcome differs")
    return result
