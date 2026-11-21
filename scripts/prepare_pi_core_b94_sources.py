"""Stage only the four managed deployment inventories. No worker plan, guest, device or service."""
import json
import os
from pathlib import Path

from scripts import prepare_pi_core_b69_payload as managed
from scripts import prepare_pi_core_b69_sources as prior


REVISION = "0aa14e486199b33b84e03bf62ae46c6ca790feaf"
TREE = "82435c0e59ed43d6170ebc6d891241e7c7bacee6"
REVIEW = prior.ROOT / "packaging/pi-core/managed-sources-b94.json"
REVIEW_PIN = "sha256:bb95c830adf7e4f33eb8c3d77c419146942d5552fa403053588b4eec6b2207c0"
BASE = managed.OUT.parent / "Aragorn-B75-Offline" / "root"
OUT = managed.OUT.parent / "Aragorn-B94-Offline"
# Independently projected from the B75 originals and the signed B93 tree.
PINS = {
    "coordinator-host.json": "54c72bbecbc1144c95265c4a3760f7dd3932094837f3253f8b43e78ad631c0f8",
    "manifest.json": "344013ad935d60a5702d6f549fbdfca052b6eaa387b706f34299a78f6d1fe635",
    "runtime-binding.json": "1cb3df496a22751155be118d2eb3c82f96fb425ec873e0b28dbcd6aca5e01c58",
    "service-runtime-receipt.json": "5ea98d30d51c9c6d41c09a80962c2d203f46b75da7416bed8c720d05345fec8f",
}


def prepare(host_raw, manifest_raw, binding_raw):
    return prior._prepare(host_raw, manifest_raw, binding_raw, review_path=REVIEW, review_pin=REVIEW_PIN,
                          revision=REVISION, tree=TREE)


def retain_inventories(host_raw, manifest_raw, binding_raw, host_code, service_code):
    parent = OUT.parent
    managed.require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
                    and not parent.stat().st_mode & 0o022, "unsafe staging parent")
    managed.require(not os.path.lexists(OUT), "output already present; no adoption, overwrite or retry")
    _, service_docs = managed.prior.service_inputs(json.loads(manifest_raw), json.loads(binding_raw), service_code)
    docs = {Path(p).name: raw for p, raw in service_docs.items()}
    docs["coordinator-host.json"] = managed._profile(host_raw, host_code)
    managed.require({name: managed.sha256(raw) for name, raw in docs.items()} == PINS,
                    "managed inventories differ from independent pins")
    OUT.mkdir(mode=0o700)
    for name, raw in docs.items():
        managed.image.new(OUT / name, raw)
        managed.image.read(OUT / name, PINS[name], 2 << 20)
    managed.require(set(os.listdir(OUT)) == set(PINS), "unexpected retained inventory")
    managed._sync_directory(OUT)
    managed._sync_directory(parent)
    return dict(PINS)


def original_inventories():
    review = prior.previous._document(REVIEW, REVIEW_PIN)
    return [managed.image.read(BASE / path[1:], review[key].removeprefix("sha256:"), 2 << 20)
            for path, key in ((managed.image.PROFILE, "prior_host_profile_digest"),
                              (managed._M, "prior_service_manifest_digest"),
                              (managed._B, "prior_service_binding_digest"))]


def main():
    originals = original_inventories()
    host, service, _ = prepare(*originals)
    print(json.dumps(retain_inventories(*originals, host, service), sort_keys=True))


if __name__ == "__main__":
    main()
