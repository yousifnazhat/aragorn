"""Independently project B75's five review pins. No target imports, materialization or image build."""
import json
from pathlib import Path

from scripts import derive_pi_core_b69_payload as prior


REVISION = "80818a521459fb23112f71184cb42fa809f644c9"
TREE = "5a661a00511f4dbd29b85be5de4a8759e2f9cb48"
DIRECTORY = Path.home() / "Library/Application Support/Aragorn-B69-Offline"
OUTCOME = "fa8ed1160ef21e6a0233a85e534b991f47c731c914d40d49306efdf309419430"
PREDECESSOR = "efc1b36a0a033992805cb60cbca14e3bfe5d4f21fb5e58c9d3ee80c0b1bb3a24"
HOST_ADDED = tuple("aragorn/pi_core_" + name + ".py" for name in (
    "sensor_state_custody", "sensor_state_entry", "sensor_state_evidence", "sensor_state_observer",
    "stopped_worker_walk", "worker_walk_evidence"))
# Lifecycle -> sensor_state_entry -> coordinator_entry -> managed_bootstrap;
# native_supervisor also now imports the protected mask release.
SERVICE_ADDED = HOST_ADDED + tuple("aragorn/pi_core_" + name + ".py" for name in (
    "coordinator_entry", "managed_bootstrap", "mask_capture_release"))
WORKER_ROOTS = ("/var/lib/aragorn/pi-os", "/var/lib/aragorn/pi-runtime")
PLAN_PINS = {
    "/var/lib/aragorn/pi-runtime/node/bin/node": "b4855de8c4781130b722ceaec9718fed77cca3eed2e5cfc5455e267c0b9ee3b0",
    "/var/lib/aragorn/pi-runtime/observer/source-gate": "7bbb6d6ad10732747f8145abc51b9732598bb0e926acd82f14196469ec316620",
    "/opt/aragorn/src/aragorn/pi_core_node_source_observer.py": "7eca9a6c0457089c32b3d2bf80a8809db0c820c4cb64cafc2118d64729be8c02",
    "/opt/aragorn/src/aragorn/pi_core_source_observer.py": "ee9c6fad39901275fa17d2908c265e7ac4715bfa4a3608499e12cde60dc093cb",
}


def _review_delta(old, new):
    allowed_additions = {"/" + prior.IMPORT + p for p in HOST_ADDED} | {
        prior.RUNTIME + "root/" + prior.IMPORT + p for p in SERVICE_ADDED}
    if old.keys() - new.keys() or new.keys() - old.keys() != allowed_additions:
        raise ValueError("unexpected source addition or removed guest row")
    prefix = prior.RUNTIME + "root/"
    metadata = {prior.HOST, prior.WRAPPER, prior.RECEIPT, prior.MANIFEST, prior.BINDING,
                *(prefix + "opt/aragorn/bin/" + role + ".py" for role in ("action", "sensor", "provider"))}
    for name, row in new.items():
        source = name.startswith(("/" + prior.IMPORT + "aragorn/", prefix + prior.IMPORT + "aragorn/")) and name.endswith(".py")
        if old.get(name) != row and (not source and name not in metadata or row["type"] != "file" or
                name in old and any(row[k] != old[name][k] for k in ("type", "mode", "uid", "gid"))):
            raise ValueError("unrelated guest row or metadata changed")
    for name, pin in PLAN_PINS.items():
        if old[name] != new[name] or new[name]["sha256"] != pin:
            raise ValueError("changed B63 worker observation-plan bytes")
        copy = prefix + name[1:]
        if name.startswith("/" + prior.IMPORT) and (old[copy] != new[copy] or new[copy]["sha256"] != pin):
            raise ValueError("changed service copy of B63 worker observation-plan bytes")
    if not all(root in old for root in WORKER_ROOTS):
        raise ValueError("missing B64 worker root")
    # All other worker directory entries, symlinks (if present), interpreters,
    # libraries and native clients were confined to unchanged rows above.
    changed = {p for p in new if new[p] != old.get(p)}
    return dict(entries=len(new), added_files=len(allowed_additions), changed_files=len(changed),
                host_additions=len(HOST_ADDED), service_additions=len(SERVICE_ADDED))


def reviewed_projection(*, directory=DIRECTORY):
    outcome = prior.retained(directory / "outcome.json", OUTCOME)
    if outcome["schema"] != "aragorn/pi-core-managed-guest-inputs/v1" or outcome["payload_sha256"] != PREDECESSOR:
        raise ValueError("not the signed B69 predecessor reference")
    pins, old, new = prior.project(directory=directory, predecessor=PREDECESSOR, host_additions=HOST_ADDED,
                                   service_additions=SERVICE_ADDED, revision=REVISION, tree=TREE)
    stats = _review_delta(old, new)
    stats.update(host_files=outcome["host_files"] + len(HOST_ADDED),
                 service_files=outcome["service_files"] + len(SERVICE_ADDED))
    return pins, stats


def derive():
    return reviewed_projection()[0]


if __name__ == "__main__":
    print(json.dumps(derive(), indent=2))
