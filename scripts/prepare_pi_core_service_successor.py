"""Compose retained service binaries and reviewed sources into one offline guest payload."""
import json
import os
from pathlib import Path, PurePosixPath
import stat

from aragorn import pi_core_service_provision as service
from scripts import pi_core_capture_mountpoints as original
from scripts import prepare_pi_core_service_successor_sources as sources
from scripts import prepare_pi_core_split_guest_payload as split
from scripts.build_pi_core_linux import ROOT, canonical, require, sha256


OUT = split.OUT.parent / "Aragorn-B65-Offline"
B64_RECEIPT = "18dd1e8d57a4ca40e1f6bdbe188fe2ad647fed7386ca66793b74d08436916f38"
B15_CHECKPOINT = "369e6f19327c286bab3c3a63b288ace5191c0691bcb87103af5c9c6654141252"
REVIEW = ROOT / "packaging/pi-core/service-successor-inputs-b65.json"
DEPLOY = "/var/lib/aragorn/pi-service-runtime"
TREE = DEPLOY + "/root"
REFS = "/etc/aragorn/service-runtime-inputs"
PIN_DOCS = ("manifest.json", "runtime-binding.json")


def _pin(raw):
    return "sha256:" + sha256(raw)


def service_inputs(prior, binding, code):
    previous = {r["path"]: r for r in prior["files"]}
    wrappers = {v["path"] for v in binding["wrappers"].values()}
    require(set(binding["source_digests"]) | wrappers <= code.keys() and
            all(p in wrappers or (p.startswith(service.SOURCE_ROOT + "/") and p.endswith(".py")) for p in code),
            "new code omits protected source, adds a foreign wrapper or changes a retained native")
    rows = {**previous, **{p: dict(path=p, size=len(raw), digest=_pin(raw), executable=p in wrappers)
                            for p, raw in code.items()}}
    directories = sorted({str(d) for name in rows for d in PurePosixPath(name).parents if str(d) != "."})
    manifest = dict(prior, directories=directories, files=[rows[n] for n in sorted(rows)])
    binding = dict(binding, source_digests={p: rows[p]["digest"] for p in code if p not in wrappers},
                   wrappers={k: dict(v, digest=rows[v["path"]]["digest"]) for k,v in binding["wrappers"].items()})
    m, b = _pin(canonical(manifest)), _pin(canonical(binding))
    service.validate_service_runtime_inputs(manifest, m, binding, b)
    receipt = canonical(service._receipt(Path(TREE), m, binding, b))
    return manifest, {REFS + "/manifest.json": canonical(manifest), REFS + "/runtime-binding.json": canonical(binding),
                      DEPLOY + "/" + service.RECEIPT: receipt}


def _no_collision(paths):
    for path in paths:
        require(not any(p == path or path.startswith(p + "/") for p in (DEPLOY, REFS)),
                "would conceal existing guest contents")


def compose(base, manifest, docs):
    rows = split._index(base["entries"])
    _no_collision(rows)
    for dest in (DEPLOY, REFS):
        p = str(PurePosixPath(dest).parent)
        require(rows.get(p) == split._dir(p, 0o755), "missing or foreign service parent")
    for path, mode in ((DEPLOY, 0o755), (TREE, 0o755), (REFS, 0o700)):
        rows[path] = split._dir(path, mode)
    for directory in manifest["directories"]:
        p = TREE + "/" + directory
        rows[p] = split._dir(p, 0o555)
    for r in manifest["files"]:
        p = TREE + "/" + r["path"]
        rows[p] = dict(path=p, type="file", uid=0, gid=0, size=r["size"], sha256=r["digest"][7:],
                       mode=0o555 if r["executable"] else 0o444)
    require(set(docs) == {DEPLOY + "/" + service.RECEIPT, *(REFS + "/" + n for n in PIN_DOCS)},
            "unreviewed runtime document set")
    for p, raw in docs.items():
        rows[p] = dict(path=p, type="file", uid=0, gid=0, size=len(raw), sha256=sha256(raw),
                       mode=0o400 if p.startswith(REFS + "/") else 0o444)
    return dict(base, entries=[rows[p] for p in sorted(rows)])


def _retained(root, name, row):
    path = root / name
    require(path.resolve(strict=True) == path, "linked retained source")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == row["mode"],
            "invalid retained source type or mode")
    raw = split.image.regular_bytes(path, row["size"])
    after = path.lstat()
    require((before.st_dev, before.st_ino, before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_ctime_ns),
            "retained source replaced")
    # The B64 staging routine hashes this buffer against the committed full manifest before writing it.
    return raw


def prepare():
    read = split.image.read
    require(not os.path.lexists(OUT), "output already present; no adoption or retry")
    b64 = json.loads(read(split.OUT / "outcome.json", B64_RECEIPT, 8192))
    base = json.loads(read(split.OUT / "payload.json", b64["payload_sha256"], 2 << 20))
    checkpoint = json.loads(read(ROOT / "packaging/pi-core/service-artifact-v3.json", B15_CHECKPOINT, 1 << 20))
    path = ROOT / checkpoint["receipt_local_path"]
    b15 = json.loads(read(path, checkpoint["receipt_file_sha256"], 1 << 20))
    manifest_raw = read(path.parent / "manifest.json", b15["manifest_digest"][7:], 1 << 20)
    prior = json.loads(manifest_raw)
    binding = json.loads(read(path.parent / "runtime-binding.json", b15["runtime_binding_digest"][7:], 1 << 20))
    code, evidence = sources.prepare(manifest_raw)
    manifest, docs = service_inputs(prior, binding, code)
    host = split._index(base["entries"])
    for p, raw in code.items():
        if p.startswith(service.SOURCE_ROOT + "/") and ("/" + p) in host:
            require(host["/" + p]["sha256"] == sha256(raw), "shared service and host module bytes differ")
    payload = compose(base, manifest, docs)
    orig = read(original._INVENTORY, original._PIN, 64 << 20)
    _no_collision(json.loads(line)["path"] for line in orig.splitlines())
    encoded = canonical(payload)
    expected = dict(schema="aragorn/pi-core-service-successor-inputs/v1", payload_sha256=sha256(encoded),
                    manifest_sha256=sha256(docs[REFS + "/manifest.json"]),
                    binding_sha256=sha256(docs[REFS + "/runtime-binding.json"]),
                    layout_receipt_sha256=sha256(docs[DEPLOY + "/" + service.RECEIPT]))
    require(json.loads(split.image.regular_bytes(REVIEW, 8192)) == expected, "independent service payload pins differ")
    parent = OUT.parent
    require(parent.resolve(strict=True) == parent and parent.stat().st_uid == os.geteuid()
            and not parent.stat().st_mode & 0o022, "unsafe output parent")
    def content(row):
        p = row["path"]
        if p in docs:
            return docs[p]
        if p.startswith(TREE + "/"):
            name = p[len(TREE)+1:]
            return code[name] if name in code else _retained(path.parent / "root", name, row)
        return _retained(split.OUT / "root", p[1:], row)
    OUT.mkdir(mode=0o700)
    split._stage(OUT / "root", payload, content)
    section = dict(deployment_path=DEPLOY, receipt_digest=_pin(docs[DEPLOY + "/" + service.RECEIPT]),
                   manifest=dict(path=REFS + "/manifest.json", digest=_pin(docs[REFS + "/manifest.json"])),
                   runtime_binding=dict(path=REFS + "/runtime-binding.json", digest=_pin(docs[REFS + "/runtime-binding.json"])))
    result = dict(**{k:v for k,v in expected.items() if k != "schema"},
                  schema="aragorn/pi-core-service-successor-payload/v1", b64_outcome_sha256=B64_RECEIPT,
                  b15_receipt_sha256=checkpoint["receipt_file_sha256"], service_files=len(manifest["files"]),
                  carried_service_files=len(manifest["files"])-len(code), entries=len(payload["entries"]),
                  source_evidence=evidence, service_runtime=section,
                  installed_identity_verified=False, activation_performed=False, image_assembled=False,
                  phase3_exit_eligible=False)
    for name, raw in (("payload.json", encoded), ("outcome.json", canonical(result))):
        split.image.new(OUT / name, raw)
        require(read(OUT / name, sha256(raw), len(raw)) == raw, "service metadata readback differs")
    return result
