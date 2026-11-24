"""Select the signed B110 host-only change; carry forward B109 service code without rendering it."""
import json

from scripts import prepare_pi_core_b69_sources as signed
from scripts import prepare_pi_core_b109_payload as b109


REVISION = "2aba715e7bd90f0309891686c791b2b438785f58"
TREE = "1e6f099c8df6da83b39c00c9650899b34867f64c"
REVIEW = signed.ROOT / "packaging/pi-core/managed-sources-b111.json"
REVIEW_PIN = "sha256:b7cbfab3077843d4edc02a267b5b2a19023e63d96d9583b9c86db69e1188f0e4"
_WRAPPER = signed.host.WRAPPER
_SRC = signed.host.PREFIX + "aragorn/"
_MODULES = {_SRC + name + ".py" for name in ("pi_core_pilot_output_custody", "pi_core_pilot_retention_entry")}


def prepare(host_raw, manifest_raw, binding_raw):
    review = signed.previous._document(REVIEW, REVIEW_PIN)
    pin, require = signed.image.pin, signed.image.require
    require((review["signed_revision"], review["signed_tree"]) == (REVISION, TREE), "wrong B111 donor")
    profile, manifest, binding = (signed._prior(raw, review[key]) for raw, key in (
        (host_raw, "prior_host_profile_digest"), (manifest_raw, "prior_service_manifest_digest"),
        (binding_raw, "prior_service_binding_digest")))
    old = {r["path"]: r for r in profile["files"] if r["path"] == _WRAPPER or r["path"].startswith(_SRC)}
    delta = review["host_changes"]
    require(delta.keys() == {_WRAPPER, *_MODULES} and _WRAPPER in old and old[_WRAPPER] != delta[_WRAPPER]
            and _MODULES.isdisjoint(old), "not the reviewed host-only change")
    rows = old | delta
    require(len(rows) == review["host_count"] and pin(signed.canonical([rows[p] for p in sorted(rows)])) ==
            review["host_rows_digest"], "wrong B111 host source inventory")
    names = {p: "packaging/pi-core/coordinator.py" if p == _WRAPPER else p.removeprefix("/opt/aragorn/") for p in rows}
    blobs = signed._objects({name: rows[p]["digest"] for p, name in names.items()}, revision=REVISION, tree=TREE)
    host = {p: blobs[name] for p, name in names.items()}
    require(all(p == row["path"] and len(host[p]) == row["size"] for p, row in rows.items()), "wrong host row")
    signed.host._project_imports(host)  # The new route and both modules must be reachable from the wrapper.

    # All B109 service modules already have signed, byte-identical host copies. No
    # B110 host addition may enter the service binding. Read the already-rendered
    # wrappers from the pinned predecessor, not a new template or workstation file.
    previous = json.loads(b109.b105.image.read(b109.OUT / "outcome.json", b109.OUTCOME_PIN, 16384))
    evidence = previous["source_evidence"].copy()
    service = {p: host["/" + p] for p in binding["source_digests"]}
    require(all("/" + p not in delta and pin(raw) == binding["source_digests"][p] for p, raw in service.items()),
            "service sources differ from B109")
    files = {r["path"]: r for r in manifest["files"]}
    for name, wrapper in binding["wrappers"].items():
        p = wrapper["path"]
        r = files[p]
        require(r["executable"] is True and r["digest"] == wrapper["digest"] ==
                evidence["rendered_wrapper_digests"][name + ".py"], "foreign retained service wrapper")
        raw = b109.b105.prior._retained(b109.OUT / "root", b109.b105.prior.TREE[1:] + "/" + p,
                                         {"mode": 0o555, "size": r["size"]})
        require(len(raw) == r["size"] and pin(raw) == r["digest"], "retained service wrapper bytes differ")
        service[p] = raw
    evidence.update(host_count=len(host), host_rows_digest=review["host_rows_digest"], host_delta_count=len(delta),
                    service_delta_count=0, source_revision=REVISION, source_tree=TREE, source_signer=signed.SIGNER)
    return host, service, evidence
