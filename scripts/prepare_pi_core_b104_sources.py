"""Prepare new protected inventory documents from B94 and signed B103 source bytes only."""

import json
import os
from pathlib import Path

from scripts import prepare_pi_core_b69_payload as managed
from scripts import prepare_pi_core_b69_sources as sources
from scripts import prepare_pi_core_b94_sources as prior


REVISION = "f4d78b03aa798d7265cd785a6a1de76d630de232"
TREE = "a785ebdd10e9d57e618b67d39bac1f07325be37e"
REVIEW = sources.ROOT / "packaging/pi-core/managed-sources-b104.json"
REVIEW_PIN = "sha256:068784dba511dd95030fc266378d7760362df5f59227979dbd7b946193f1d152"
OUT = prior.OUT.with_name("Aragorn-B104-Offline")
_INPUTS = ("coordinator-host.json", "manifest.json", "runtime-binding.json")
# Independent projection of the original B94 rows plus the exact signed changes.
PINS = {
    "coordinator-host.json": "70d6998fc0b50512cb0583261fd1ca633a3aedef24ca68fa0db73b2b0a20ae87",
    "manifest.json": "deef4f046aaff76a486e327f75e98e8b9ef4a4daa5d4ecbaed8620edc97f69c0",
    "runtime-binding.json": "76fd1f597cc65b9bc98a30d2d470bb27938f92253aff0b1df6770db9bf2dd240",
    "service-runtime-receipt.json": "d7bb0b594df97eb7ba53e3bac535308e33da3b4ca2feff99a97fde17ecc927b0",
}


def original_inventories():
    return tuple(managed.image.read(prior.OUT / name, prior.PINS[name], 2 << 20) for name in _INPUTS)


def prepare(host_raw, manifest_raw, binding_raw):
    host_code, service_code, _ = sources._prepare(host_raw, manifest_raw, binding_raw, review_path=REVIEW,
                                                 review_pin=REVIEW_PIN, revision=REVISION, tree=TREE)
    _, service_docs = managed.prior.service_inputs(json.loads(manifest_raw), json.loads(binding_raw), service_code)
    docs = {Path(p).name: raw for p, raw in service_docs.items()}
    docs["coordinator-host.json"] = managed._profile(host_raw, host_code)
    managed.require({name: managed.sha256(raw) for name, raw in docs.items()} == PINS,
                    "managed inventories differ from independent pins")
    return docs


def retain():
    parent = OUT.parent
    managed.require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
                    and not parent.stat().st_mode & 0o022, "unsafe staging parent")
    managed.require(not os.path.lexists(OUT), "output already present; no adoption, overwrite or retry")
    docs = prepare(*original_inventories())
    OUT.mkdir(mode=0o700)
    for name, raw in docs.items():
        managed.image.new(OUT / name, raw)
        managed.image.read(OUT / name, PINS[name], 2 << 20)
    managed.require(set(os.listdir(OUT)) == set(PINS), "unexpected retained inventory")
    managed._sync_directory(OUT)
    managed._sync_directory(parent)
    return dict(PINS)


if __name__ == "__main__":
    print(json.dumps(retain(), sort_keys=True))
