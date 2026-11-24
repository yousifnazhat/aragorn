"""Stage the host retention route without changing B109 services, worker or media."""
import json

from scripts import prepare_pi_core_b109_payload as b109
from scripts import prepare_pi_core_b111_sources as sources
from scripts.build_pi_core_linux import require, sha256


managed = b109.managed
BASE = b109.OUT
OUT = BASE.with_name("Aragorn-B111-Offline")
BASE_PAYLOAD = "f84e61381e72d7630964e07d5b4a6ee97006e7642a1666eaba4fbce7e1563232"
REVIEW = managed.ROOT / "packaging/pi-core/managed-payload-b111.json"
REVIEW_PIN = "5d11ee1be982d0b92e7f1621e9c6c52cacbcb39cb551379b1fb6d37bc9065860"
OUTCOME_PIN = "e8c292f30ed8442db237749711f6ed1e64523697eb568bcfe8e44dbfc7e5b2d3"
_ADDED = {managed._SRC + name + ".py" for name in ("pi_core_pilot_output_custody", "pi_core_pilot_retention_entry")}
_CHANGED = _ADDED | {managed._WRAPPER, managed.image.PROFILE}


def prepare():
    """Publish once from authenticated inputs; existing or incomplete output is never adopted."""
    spec = managed._Successor("b109", BASE, OUT, b109.OUTCOME_PIN, BASE_PAYLOAD,
                              sources.REVISION, sources.TREE, REVIEW, REVIEW_PIN, (1791, 819, 807, 4, 2))
    result = managed._prepare_successor(spec, sources.prepare)
    require(result == json.loads(managed.image.read(OUT / "outcome.json", OUTCOME_PIN, 16384)),
            "published result differs from independent B111 outcome")
    return result


def readback():
    """Check the full path delta and read its four files without staging a second copy."""
    read = managed.image.read
    old = json.loads(read(BASE / "payload.json", BASE_PAYLOAD, 2 << 20))
    pins = json.loads(read(REVIEW, REVIEW_PIN, 8192))
    outcome = json.loads(read(OUT / "outcome.json", OUTCOME_PIN, 16384))
    payload = json.loads(read(OUT / "payload.json", pins["payload_sha256"], 2 << 20))
    before, after = (managed.split._index(doc["entries"]) for doc in (old, payload))
    require(before.keys() <= after.keys() and after.keys() - before.keys() == _ADDED and
            {p for p in after if after[p] != before.get(p)} == _CHANGED, "unexpected B111 payload delta")
    changes = {}
    for path in sorted(_CHANGED):
        row = after[path]
        raw = managed.prior._retained(OUT / "root", path[1:], row)
        require(len(raw) == row["size"] and sha256(raw) == row["sha256"], "staged host bytes differ: " + path)
        changes[path] = raw
    return payload, changes, outcome


if __name__ == "__main__":
    print(json.dumps(prepare(), sort_keys=True))
