"""Prepare the full B69 managed guest payload from B65 and signed B68 sources. No guest execution."""
import json
import os
from pathlib import Path

from scripts import prepare_pi_core_b69_sources as sources
from scripts import prepare_pi_core_service_successor as prior
from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.prepare_pi_core_coordinator_host import host_contract


split, image = prior.split, prior.split.image
BASE = prior.OUT
OUT = BASE.parent / "Aragorn-B69-Offline"
BASE_OUTCOME = "9eb990a693dc3e9e8ab9927ac04458383549b938cd831766cd94ee3203d3db4d"
BASE_PAYLOAD = "156c94630eec1fe9285e8732fd7574c14f2fd9926aa3dd6d0e5f95cb408ceb51"
REVISION = "0910f1d1c5710cb7730002ac5d974803e14e2431"
TREE = "e45cb0c200f3ba9c1201c2b301a371a892f3d15e"
REVIEW = ROOT / "packaging/pi-core/managed-payload-b69.json"
REVIEW_SHA256 = "478c9ed1c64959a85ceccf36b21e054a0253702abc2433b87853bc72a60b4b2c"
_SRC = "/opt/aragorn/src/aragorn/"
_WRAPPER = "/opt/aragorn/bin/coordinator.py"
_M, _B = (prior.REFS + "/" + name for name in prior.PIN_DOCS)
_R = prior.DEPLOY + "/" + prior.service.RECEIPT


def _file(p, raw, mode):
    return dict(path=p, type="file", uid=0, gid=0, mode=mode, size=len(raw), sha256=sha256(raw))


def _profile(raw, code):
    profile = host_contract._document(raw)
    host_contract._profile(profile)
    rows = {r["path"]: r for r in profile["files"]}
    old_sources = {p for p in rows if p.startswith(_SRC) or p == _WRAPPER}
    require(old_sources <= code.keys() and all(p == _WRAPPER or (p.startswith(_SRC) and p.endswith(".py"))
            for p in code), "foreign or missing trusted host source")
    for p, buf in code.items():
        rows[p] = dict(path=p, digest=prior._pin(buf), size=len(buf))
    updated = dict(profile, files=sorted(rows.values(), key=lambda r: Path(r["path"])))
    host_contract._profile(updated)
    return canonical(updated)


def _original_names(absent, original):
    # Added leaves share existing admitted parents. Never mask an original guest object or symlink.
    ancestors = {str(parent) for name in absent for parent in Path(name).parents}
    require(absent and absent.isdisjoint(ancestors), "ambiguous new source names")
    for row in original:
        p = row["path"]
        require(p not in absent, "new source would replace an original guest object")
        if p in ancestors:
            require(row["type"] == "D" and row["uid"] == row["gid"] == 0 and
                    not row["mode"] & 0o022 and row["xattrs"] == [], "unsafe original guest ancestor")


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare():
    require(not os.path.lexists(OUT), "output already present; no adoption, overwrite or retry")
    b65 = json.loads(image.read(BASE / "outcome.json", BASE_OUTCOME, 16384))
    require(b65["payload_sha256"] == BASE_PAYLOAD, "foreign B65 payload")
    base = json.loads(image.read(BASE / "payload.json", BASE_PAYLOAD, 2 << 20))
    require(base["schema"] == split.SCHEMA, "incorrect guest format")
    old = split._index(base["entries"])

    def retained(p):
        row = old[p]
        buf = prior._retained(BASE / "root", p[1:], row)
        require(_file(p, buf, row["mode"]) == row, "retained bytes do not match B65")
        return buf

    host, manifest, binding = (retained(p) for p in (image.PROFILE, _M, _B))
    old_section = b65["service_runtime"]
    require(old_section == dict(deployment_path=prior.DEPLOY, receipt_digest=prior._pin(retained(_R)),
                                manifest=dict(path=_M, digest=prior._pin(manifest)),
                                runtime_binding=dict(path=_B, digest=prior._pin(binding))),
            "B65 service caller refs differ")
    hcode, scode, evidence = sources.prepare(host, manifest, binding)
    require(evidence["source_revision"] == REVISION and evidence["source_tree"] == TREE,
            "unreviewed source tree")
    profile = _profile(host, hcode)
    updated, docs = prior.service_inputs(json.loads(manifest), json.loads(binding), scode)
    for p, buf in scode.items():
        if p.startswith(prior.service.SOURCE_ROOT + "/"):
            require(hcode.get("/" + p) == buf, "host and service copies of a trusted module differ")

    # Compose only the known service subtree from the validated manifest. Keep everything else.
    host_rows = {p:r for p,r in old.items() if not any(p == prefix or p.startswith(prefix + "/")
                 for prefix in (prior.DEPLOY, prior.REFS))}
    overrides = {**hcode, image.PROFILE: profile, **{prior.TREE + "/" + p: b for p,b in scode.items()}, **docs}
    for p, buf in {**hcode, image.PROFILE: profile}.items():
        host_rows[p] = _file(p, buf, 0o400 if p == image.PROFILE else 0o444)
    payload = prior.compose(dict(base, entries=list(host_rows.values())), updated, docs)
    rows = split._index(payload["entries"])
    changes = {p for p,r in rows.items() if old.get(p) != r}
    require(old.keys() <= rows.keys() and changes <= overrides.keys() and all(
            rows[p]["type"] == "file" and (p not in old or
                all(old[p][k] == rows[p][k] for k in ("type","uid","gid","mode")))
            for p in changes), "would remove, re-mode or replace an unrelated guest object")
    require(not {p for p in changes if any(Path(p).is_relative_to(r) for r in split.WORKER_ROOTS)} and
            changes.isdisjoint({_SRC + name + ".py" for name in ("pi_core_source_observer", "pi_core_node_source_observer")}),
            "B64 worker or its two source-plan producer bindings would change")
    added = rows.keys() - old.keys()
    orig = image.read(prior.original._INVENTORY, prior.original._PIN, 64 << 20)
    _original_names(added, (json.loads(line) for line in orig.splitlines()))
    encoded = canonical(payload)
    pins = dict(schema="aragorn/pi-core-managed-payload/v1", payload_sha256=sha256(encoded),
                host_profile_sha256=sha256(profile), manifest_sha256=sha256(docs[_M]),
                binding_sha256=sha256(docs[_B]), layout_receipt_sha256=sha256(docs[_R]))
    require(json.loads(image.read(REVIEW, REVIEW_SHA256, 8192)) == pins, "independent assembly pins differ")
    result = dict(**{k:v for k,v in pins.items() if k != "schema"}, schema="aragorn/pi-core-managed-guest-inputs/v1",
                  b65_outcome_sha256=BASE_OUTCOME, b65_payload_sha256=BASE_PAYLOAD, entries=len(rows),
                  changed_files=len(changes), added_files=len(added), host_files=len(json.loads(profile)["files"]),
                  service_files=len(updated["files"]), source_evidence=evidence,
                  service_runtime=dict(deployment_path=prior.DEPLOY, receipt_digest=prior._pin(docs[_R]),
                       manifest=dict(path=_M, digest=prior._pin(docs[_M])),
                       runtime_binding=dict(path=_B, digest=prior._pin(docs[_B]))),
                  image_assembled=False, installed_identity_verified=False, activation_performed=False,
                  phase3_exit_eligible=False)
    require((result["entries"], result["host_files"], result["service_files"], result["changed_files"],
             result["added_files"]) == (1764, 806, 793, 20, 4), "independent assembly counts differ")
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe private staging parent")
    OUT.mkdir(mode=0o700)
    root = OUT / "root"
    split._stage(root, payload, lambda row: overrides[row["path"]] if row["path"] in changes else
                prior._retained(BASE / "root", row["path"][1:], row))
    # _stage hash-reads every emitted file and verifies namespaces/modes. Sync the directory
    # entries as well, before exposing any completion marker; never adopt partial attempts.
    for r in reversed(payload["entries"]):
        if r["type"] == "dir":
            _sync_directory(root / r["path"][1:])
    _sync_directory(root)
    image.new(OUT / "payload.json", encoded)
    require(image.read(OUT / "payload.json", pins["payload_sha256"], 2 << 20) == encoded, "payload readback differs")
    outcome = canonical(result)
    image.new(OUT / "pending.json", outcome)
    require(image.read(OUT / "pending.json", sha256(outcome), 65536) == outcome and
            set(os.listdir(OUT)) == {"root","payload.json","pending.json"}, "incomplete staged metadata")
    _sync_directory(OUT)
    os.link(OUT / "pending.json", OUT / "outcome.json", follow_symlinks=False)
    (OUT / "pending.json").unlink()
    _sync_directory(OUT)
    _sync_directory(parent)
    require(image.read(OUT / "outcome.json", sha256(outcome), 65536) == outcome, "outcome readback differs")
    return result
