"""Stage the B108 caller and output reader together; no image, install or activation."""

import json

from scripts import prepare_pi_core_b105_payload as b105
from scripts import prepare_pi_core_b109_sources as sources
from scripts.build_pi_core_linux import require, sha256


BASE = b105.OUT
OUT = BASE.with_name("Aragorn-B109-Offline")
managed = b105.managed
REVIEW = managed.ROOT / "packaging/pi-core/managed-payload-b109.json"
REVIEW_PIN = "642b1eee20183d304d135f1479befdf587b7b77e21f43388a3e5026119f0be83"
OUTCOME_PIN = "14327842684fcf9f3f4f716eabace5f2b9bb2f1e08a3be3e2b8174ea540e1ba7"


def prepare():
    """One new private staging directory; the shared publisher refuses any existing one."""
    spec = managed._Successor("b105", BASE, OUT, b105.OUTCOME_PIN, b105.PAYLOAD_PIN,
                              sources.REVISION, sources.TREE, REVIEW, REVIEW_PIN,
                              (1789, 817, 807, 15, 2))
    result = managed._prepare_successor(spec, sources.prepare)
    require(result == json.loads(b105.image.read(OUT / "outcome.json", OUTCOME_PIN, 16384)),
            "published result differs from independent B109 outcome")
    return result


def readback():
    """Read the pinned, staged delta; never re-run preparation or repair a partial result."""
    read = b105.image.read
    old = json.loads(read(BASE / "payload.json", b105.PAYLOAD_PIN, 2 << 20))
    pins = json.loads(read(REVIEW, REVIEW_PIN, 8192))
    outcome = json.loads(read(OUT / "outcome.json", OUTCOME_PIN, 16384))
    payload = json.loads(read(OUT / "payload.json", pins["payload_sha256"], 2 << 20))
    before, after = (b105.split._index(doc["entries"]) for doc in (old, payload))
    changes = {}
    for path, row in after.items():
        if before.get(path) == row:
            continue
        require(row["type"] == "file", "unexpected non-file change: " + path)
        raw = b105.prior._retained(OUT / "root", path[1:], row)
        require(len(raw) == row["size"] and sha256(raw) == row["sha256"],
                "staged successor bytes differ: " + path)
        changes[path] = raw
    return payload, changes, outcome


if __name__ == "__main__":
    print(json.dumps(prepare(), sort_keys=True))
