"""Check the B105 offline evidence inputs; never create a plan, grant or evidence row."""

import json
from pathlib import Path
import sys

from aragorn.cas import CAS, CASError
from scripts.prepare_pi_core_immutable_payload import PROFILE, ROOT, read, require


_SUPPORT = Path.home() / "Library/Application Support"
_B104 = _SUPPORT / "Aragorn-B104-Offline"
_B105 = _SUPPORT / "Aragorn-B105-Offline"
_ADMISSION = _SUPPORT / "Aragorn-B97-Offline/admission-cas"
_CATALOG = ROOT / "packaging/pi-core/managed-evidence-inputs-b105.json"
CATALOG_PIN = "418b0af14419bdfde7e80911b91d1f03362707cf37d3e8aac6ca700f80550224"
_REFS = "/etc/aragorn/service-runtime-inputs/"
_SERVICE = "/var/lib/aragorn/pi-service-runtime"
_INVENTORIES = {"coordinator-host.json": PROFILE, "manifest.json": _REFS + "manifest.json",
                "runtime-binding.json": _REFS + "runtime-binding.json",
                "service-runtime-receipt.json": _SERVICE + "/service-runtime-receipt.json"}


def verify_evidence_inputs(*, payload_dir=None):
    catalog = json.loads(read(_CATALOG, CATALOG_PIN, 16 << 10))
    require(catalog["schema"] == "aragorn/pi-core-b105-evidence-inputs/v1" and
            catalog["authority"] == "OFFLINE_INPUT_PINS_ONLY_NOT_DEPLOYMENT_OR_PILOT_AUTHORITY" and
            catalog["activation_authorized"] is catalog["phase3_exit_eligible"] is False and
            all(pin is None for pin in catalog["held_nominations"].values()), "B105 evidence holds differ")

    directory = _B105 if payload_dir is None else payload_dir
    pins = catalog["payload"]
    payload = json.loads(read(directory / "payload.json", pins["payload.json"][7:], 2 << 20))
    outcome = json.loads(read(directory / "outcome.json", pins["outcome.json"][7:], 64 << 10))
    require(outcome["payload_sha256"] == pins["payload.json"][7:] and
            all(outcome[key] is False for key in ("image_assembled", "installed_identity_verified",
                                                  "activation_performed", "phase3_exit_eligible")),
            "B105 outcome is not the offline layout")
    rows = {row["path"]: row for row in payload["entries"]}
    inventory = catalog["protected_inventories"]
    for name, guest_path in _INVENTORIES.items():
        pin = inventory[name][7:]
        require(rows[guest_path]["sha256"] == pin, "B105 and B104 inventory bindings differ")
        read(_B104 / name, pin, 2 << 20)
        read(directory / "root" / guest_path[1:], pin, 2 << 20)
    require(outcome["service_runtime"] == {
        "deployment_path": _SERVICE, "receipt_digest": inventory["service-runtime-receipt.json"],
        **{key: {"path": _INVENTORIES[name], "digest": inventory[name]}
           for key, name in (("manifest", "manifest.json"), ("runtime_binding", "runtime-binding.json"))},
    }, "B105 service caller references differ")
    for guest_path, pin in catalog["worker_payload_rows"].items():
        require(rows[guest_path]["sha256"] == pin[7:], "B105 worker row differs")

    candidate = catalog["candidate"]
    public = ROOT / "benchmark/pi-core-pilot-v1"
    review = json.loads(read(public / "review.json", candidate["review_digest"][7:], 8192))
    read(public / "task.txt", candidate["task_digest"][7:], 4096)
    skill = read(public / "candidate/SKILL.md", candidate["skill_digest"][7:], 4096)
    require(review["status"] == "PROPOSED_INPUTS_ONLY" and
            all(review[k] == candidate[k] for k in ("skill_digest", "task_digest", "tree_digest")),
            "B105 public candidate inputs differ")
    require(_ADMISSION.resolve(strict=True) == _ADMISSION, "linked B97 evidence store")
    archive = CAS(_ADMISSION, read_only=True)
    manifest = json.loads(archive.read(candidate["manifest_digest"], max_bytes=4096))
    graph = json.loads(archive.read(candidate["artifact_graph_digest"], max_bytes=8192))
    require(archive.read(candidate["skill_digest"], max_bytes=4096) == skill and
            manifest["files"] == graph["artifacts"] == [
                {"path": "SKILL.md", "digest": candidate["skill_digest"], "size": len(skill), "executable": False}] and
            manifest["tree_digest"] == graph["tree_digest"] == candidate["tree_digest"] and
            graph["root_manifest_digest"] == candidate["manifest_digest"] and
            graph["verifier"]["implementation_digest"] == candidate["graph_verifier_digest"] and
            graph["authority"] == "CLOSURE_EVIDENCE_ONLY_NOT_INSTALLER_AUTHORITY",
            "B105 retained admission inputs differ")
    read(ROOT / "src/aragorn/admission_artifact_graph.py", candidate["graph_verifier_digest"][7:], 1 << 20)
    for path, pin in catalog["evidence_readers"].items():
        read(ROOT / path, pin[7:], 1 << 20)
    return catalog


if __name__ == "__main__":
    try:
        verify_evidence_inputs()
    except (CASError, ValueError, OSError, RuntimeError, KeyError, TypeError):
        print("B105 evidence input verification refused. Nothing was activated.", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps({"verified_input_catalog": "sha256:" + CATALOG_PIN, "activation_authorized": False}))
