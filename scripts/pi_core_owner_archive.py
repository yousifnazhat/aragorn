"""Copy the B47 evidence files only; preservation is not a claim about VM state."""
from contextlib import ExitStack
import os
from pathlib import Path

from scripts import pi_core_host_evidence_export as custody
from scripts.build_pi_core_linux import canonical, require, sha256


SCHEMA = "aragorn/b48-owner-archive/v1"
MANIFEST = "archive.json"
OWNER = {"owner-events.jsonl": 48 * 2048, "owner-terminal.json": 32768, "serial.raw": 8 << 20}
WATCH = {n: 65536 for n in ("watchdog.json", "watchdog.json.started", "watchdog.json.owner-arm",
                            "watchdog.json.graceful", "watchdog.json.force", "watchdog.json.kill", "refusal.stderr")}
LIMITS = OWNER | WATCH


def _inventory(fd, allowed):
    names = set()
    cursor = os.open(".", custody.D, dir_fd=fd)
    try:
        with os.scandir(cursor) as entries:
            for entry in entries:
                require(entry.name in allowed, "unexpected evidence entry; preserve source")
                names.add(entry.name)
    finally:
        os.close(cursor)
    return names


def _present(parent, uid):
    try:
        st = custody._named(parent, uid)
    except FileNotFoundError:
        return None
    return custody._dirid(st)


def _root_stable(path, ident):
    require(path.resolve(strict=True) == path and custody._dirid(path.lstat()) == ident,
            "custody root replaced or renamed")


def export_owner_archive(fixture, ledger, dest, uid):
    """Snapshot absent/present UUID leaves in exclusive cooperating roots. Never remove or replace."""
    custody._uuid(uid)
    roots = {k: Path(p) for k, p in (("fixture", fixture), ("ledger", ledger), ("destination", dest)) if p is not None}
    require(all(not a.is_relative_to(b) for k,a in roots.items() for j,b in roots.items() if k != j),
            "custody roots overlap")
    with ExitStack() as stack:
        opened = {k: stack.enter_context(custody._root(p)) for k,p in roots.items()}
        identities = [ident for _,ident in opened.values()]
        require(all(ident not in identities[:i] for i,ident in enumerate(identities)), "aliased custody roots")
        leaves = {}
        inputs = {}
        for k, allowed in (("fixture", OWNER), ("ledger", WATCH)):
            if k not in opened:
                continue
            parent = opened[k][0]
            ident = _present(parent, uid)
            if ident is None:
                leaves[k] = (None, None, set(), allowed)
                continue
            src, sid = stack.enter_context(custody._directory(parent, uid))
            require(ident == sid and sid not in identities, "replaced or aliased source directory")
            identities.append(sid)
            names = _inventory(src, allowed)
            leaves[k] = (src, sid, names, allowed)
            for n in sorted(names):
                inputs[n] = custody._read(src, n, allowed[n])

        def stable():
            for k, path in roots.items():
                _root_stable(path, opened[k][1])
            for k, (src, sid, names, allowed) in leaves.items():
                require(_present(opened[k][0], uid) == sid, "source UUID directory changed")
                if src is not None:
                    require(_inventory(src, allowed) == names and all(
                        custody._fileid(custody._named(src, n)) == inputs[n][1] for n in names),
                        "source evidence changed during export")

        stable()
        d, did = opened["destination"]
        os.mkdir(uid, 0o700, dir_fd=d)  # An existing incomplete export is not ours to overwrite.
        os.fsync(d)
        with custody._directory(d, uid) as (out, oid):
            records = {}
            for n, (data, info) in inputs.items():
                records[n] = {"source": info, "export": custody._write(out, n, data), "sha256": sha256(data)}
            doc = {"schema": SCHEMA, "attempt_uuid": uid, "fixture_identity": opened["fixture"][1] if fixture is not None else None,
                   "attempt_identity": leaves["fixture"][1] if fixture is not None else None,
                   "ledger_identity": opened["ledger"][1], "ledger_attempt_identity": leaves["ledger"][1],
                   "destination_identity": did, "export_identity": oid, "files": records,
                   "cleanup_authorized": False, "phase3_exit_eligible": False}
            stable()
            raw = canonical(doc) + b"\n"
            custody._write(out, MANIFEST, raw)
            os.fsync(out)
            digest = sha256(raw)
            _read(out, oid, did, uid, digest, portable=False)
            stable()
            require(_present(d, uid) == oid, "export directory changed")
            return digest


def _dir_identity(value):
    return type(value) is dict and set(value) == {"dev", "ino"} and all(type(v) is int and v >= 0 for v in value.values())


def _metadata(value, limit, modes):
    return (type(value) is dict and set(value) == {"dev", "ino", "mode", "bytes", "mtime_ns", "ctime_ns"}
            and all(type(v) is int for v in value.values()) and 0 <= value["bytes"] <= limit
            and value["dev"] >= 0 and value["ino"] > 0 and value["mode"] in modes)


def _read(fd, oid, did, uid, digest, *, portable):
    require(custody._digest(digest), "external manifest SHA-256 required")
    raw, manifest_info = custody._read(fd, MANIFEST, custody.LIMIT, sealed=True)
    require(sha256(raw) == digest, "archive digest mismatch")
    doc = custody._json(raw)
    required = {"schema", "attempt_uuid", "fixture_identity", "attempt_identity", "ledger_identity",
                "ledger_attempt_identity", "destination_identity", "export_identity", "files",
                "cleanup_authorized", "phase3_exit_eligible"}
    require(set(doc) == required and doc["schema"] == SCHEMA and doc["attempt_uuid"] == uid and
            doc["cleanup_authorized"] is False and doc["phase3_exit_eligible"] is False, "invalid archive contract")
    dirs = [doc[k] for k in ("fixture_identity", "attempt_identity", "ledger_identity", "ledger_attempt_identity",
                             "destination_identity", "export_identity") if doc[k] is not None]
    require(all(_dir_identity(v) and v not in dirs[:i] for i,v in enumerate(dirs)) and
            all(doc[k] is not None for k in ("ledger_identity", "destination_identity", "export_identity")) and
            (doc["fixture_identity"] is not None or doc["attempt_identity"] is None), "invalid directory provenance")
    require(portable or (doc["export_identity"] == oid and doc["destination_identity"] == did),
            "archive not at original export directory")
    records = doc["files"]
    require(type(records) is dict and records.keys() <= LIMITS.keys() and
            (doc["attempt_identity"] is not None or not records.keys() & OWNER.keys()) and
            (doc["ledger_attempt_identity"] is not None or not records.keys() & WATCH.keys()), "invalid source inventory")
    names = set(records) | {MANIFEST}
    require(_inventory(fd, names) == names, "archive entries differ from manifest")
    payloads, seen = {}, {MANIFEST: manifest_info}
    for n, record in records.items():
        require(type(record) is dict and set(record) == {"source", "export", "sha256"} and
                _metadata(record["source"], LIMITS[n], (0o400, 0o600)) and
                _metadata(record["export"], LIMITS[n], (0o400,)), "invalid evidence metadata")
        data, info = custody._read(fd, n, LIMITS[n], sealed=True)
        require((portable or record["export"] == info) and info["bytes"] == record["export"]["bytes"] ==
                record["source"]["bytes"] and sha256(data) == record["sha256"], "archive bytes or identity changed")
        seen[n] = info
        payloads[n] = data
    require(_inventory(fd, names) == names and all(custody._fileid(custody._named(fd, n)) == v
            for n, v in seen.items()), "archive changed during readback")
    return doc, payloads


def read_owner_archive(dest, uid, digest, *, portable=False):
    """Rehash exact sealed bytes. Portable copies keep the original provenance, not original local inodes."""
    custody._uuid(uid)
    dest = Path(dest)
    with custody._root(dest) as (d, did), custody._directory(d, uid) as (fd, oid):
        result = _read(fd, oid, did, uid, digest, portable=portable)
        require(_present(d, uid) == oid, "export directory changed")
        _root_stable(dest, did)
        return result
