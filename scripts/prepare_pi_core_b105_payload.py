"""Stage the B104 inventories in the retained B75 guest layout; never build media or boot."""

import json
import os

from scripts import prepare_pi_core_b104_sources as sources
from scripts import prepare_pi_core_b69_payload as managed
from scripts import prepare_pi_core_b69_sources as git_sources
from scripts.build_pi_core_linux import canonical, require, sha256


BASE = sources.OUT.with_name("Aragorn-B75-Offline")
OUT = sources.OUT.with_name("Aragorn-B105-Offline")
BASE_OUTCOME = "dd7546345df15e772d9a0865b725280213c05f0d280f63afe1e429b6d6594d53"
BASE_PAYLOAD = "91b41ff45ade64e691a95e95abf72611ba7ca27c1b146136e7b9079c876e7c31"
PAYLOAD_PIN = "b60330aef3582e9d52ed59001b0bd16d6d973549b0d18812934c8f53e739c81f"
OUTCOME_PIN = "c9c53a68840e9a3d4d4be3f0fc731a0fc83235ad550288ba5fafab30bdbf3798"
REVIEW = managed.ROOT / "packaging/pi-core/managed-payload-b105.json"
REVIEW_PIN = "e5b7d65838743cb84bd28f650b70bd377470f1c19083b59d5bffa2ed2471245b"

prior, split, image = managed.prior, managed.split, managed.image
_DOCS = {
    image.PROFILE: "coordinator-host.json", managed._M: "manifest.json",
    managed._B: "runtime-binding.json", managed._R: "service-runtime-receipt.json",
}
_ADDED = {"/opt/aragorn/src/aragorn/pi_core_" + n + ".py" for n in (
    "owned_socket_directories", "state_backing_leaf", "state_dm_mapping", "state_luks_headers",
)}


def project():
    """Return the pinned payload, exact changed file bytes and outcome without writing."""
    docs = {p: image.read(sources.OUT / name, sources.PINS[name], 2 << 20) for p, name in _DOCS.items()}
    previous = json.loads(image.read(BASE / "outcome.json", BASE_OUTCOME, 16384))
    base = json.loads(image.read(BASE / "payload.json", BASE_PAYLOAD, 2 << 20))
    require(previous["schema"] == "aragorn/pi-core-managed-guest-inputs/v1"
            and previous["payload_sha256"] == BASE_PAYLOAD and base["schema"] == split.SCHEMA,
            "foreign B75 payload or outcome")
    original = split._index(base["entries"])

    def retained(p):
        row = original[p]
        return image.read(BASE / "root" / p[1:], row["sha256"], row["size"])

    host_code, service_code, evidence = git_sources._prepare(*sources.original_inventories(),
        review_path=sources.REVIEW, review_pin=sources.REVIEW_PIN, revision=sources.REVISION, tree=sources.TREE)
    manifest, service_docs = prior.service_inputs(json.loads(retained(managed._M)),
        json.loads(retained(managed._B)), service_code)
    require(docs == {image.PROFILE: managed._profile(retained(image.PROFILE), host_code), **service_docs},
            "B104 inventory bytes differ from the signed common source projection")

    host = {p: row for p, row in original.items() if not any(p == root or p.startswith(root + "/")
                                                           for root in (prior.DEPLOY, prior.REFS))}
    for p, raw in {**host_code, image.PROFILE: docs[image.PROFILE]}.items():
        host[p] = managed._file(p, raw, 0o400 if p == image.PROFILE else 0o444)
    payload = prior.compose(dict(base, entries=list(host.values())), manifest, service_docs)
    rows = split._index(payload["entries"])
    changes = {p for p, row in rows.items() if original.get(p) != row}
    added = rows.keys() - original.keys()
    overrides = {**host_code, **docs, **{prior.TREE + "/" + p: b for p, b in service_code.items()}}
    require(original.keys() <= rows.keys() and added == _ADDED | {prior.TREE + p for p in _ADDED}
            and changes <= overrides.keys() and all(rows[p]["type"] == "file" and (
                p in added or all(original[p][k] == rows[p][k] for k in ("type", "mode", "uid", "gid"))) for p in changes),
            "new payload removes, remodes or replaces an unrelated guest object")
    original_names = image.read(prior.original._INVENTORY, prior.original._PIN, 64 << 20)
    managed._original_names(added, (json.loads(line) for line in original_names.splitlines()))

    pins = dict(payload_sha256=sha256(canonical(payload)), host_profile_sha256=sha256(docs[image.PROFILE]),
        manifest_sha256=sha256(docs[managed._M]), binding_sha256=sha256(docs[managed._B]),
        layout_receipt_sha256=sha256(docs[managed._R]))
    require(pins["payload_sha256"] == PAYLOAD_PIN and json.loads(image.read(REVIEW, REVIEW_PIN, 8192)) ==
            dict(schema="aragorn/pi-core-managed-payload/v1", **pins), "independent B105 assembly pins differ")
    outcome = dict(schema="aragorn/pi-core-managed-guest-inputs/v1", **pins,
        b75_outcome_sha256=BASE_OUTCOME, b75_payload_sha256=BASE_PAYLOAD,
        entries=len(rows), changed_files=len(changes), added_files=len(added),
        host_files=len(json.loads(docs[image.PROFILE])["files"]), service_files=len(manifest["files"]),
        source_evidence=evidence, service_runtime=dict(deployment_path=prior.DEPLOY,
            receipt_digest=prior._pin(docs[managed._R]), manifest=dict(path=managed._M, digest=prior._pin(docs[managed._M])),
            runtime_binding=dict(path=managed._B, digest=prior._pin(docs[managed._B]))),
        image_assembled=False, installed_identity_verified=False, activation_performed=False, phase3_exit_eligible=False)
    require(sha256(canonical(outcome)) == OUTCOME_PIN, "independent B105 outcome pin differs")
    return payload, {p: overrides[p] for p in changes}, outcome


def prepare():
    require(not os.path.lexists(OUT), "output already present; no adoption, overwrite or retry")
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe private staging parent")
    payload, changes, outcome = project()
    OUT.mkdir(mode=0o700)
    root = OUT / "root"
    split._stage(root, payload, lambda row: changes[row["path"]] if row["path"] in changes else
                 prior._retained(BASE / "root", row["path"][1:], row))
    for row in reversed(payload["entries"]):
        if row["type"] == "dir":
            managed._sync_directory(root / row["path"][1:])
    managed._sync_directory(root)
    for name, doc, pin in (("payload.json", payload, PAYLOAD_PIN), ("pending.json", outcome, OUTCOME_PIN)):
        raw = canonical(doc)
        image.new(OUT / name, raw)
        require(image.read(OUT / name, pin, 2 << 20) == raw, "B105 metadata readback differs")
    require(set(os.listdir(OUT)) == {"root", "payload.json", "pending.json"}, "incomplete staging")
    managed._sync_directory(OUT)
    os.link(OUT / "pending.json", OUT / "outcome.json", follow_symlinks=False)
    (OUT / "pending.json").unlink()
    managed._sync_directory(OUT)
    managed._sync_directory(parent)
    require(image.read(OUT / "outcome.json", OUTCOME_PIN, 16384) == canonical(outcome), "B105 outcome readback differs")
    return outcome


if __name__ == "__main__":
    print(json.dumps(prepare(), sort_keys=True))
