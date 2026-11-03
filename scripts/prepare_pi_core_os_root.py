"""Static minimal Pi OS closure from an already-retained Docker-save archive.

No target, shell, ldd, Docker, VM or service is executed. OCI digest chains,
uncompressed layer identities and bounded overlay semantics precede a static
ELF dependency walk. Output is a regular-file staging artifact, not an installed
root, usable provider route, ABI execution result or native qualification.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import posixpath
import re
import struct
import tarfile
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location("pi_os_build_helpers", Path(__file__).with_name("build_pi_core_linux.py"))
assert _SPEC and _SPEC.loader
_build = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_build)
canonical = _build.canonical
sha256 = _build.sha256
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_LAYER = 256 * 1024 * 1024
MAX_TREE = 512 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_ENTRIES = 100_000
_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SONAME = re.compile(r"[A-Za-z0-9_+.-]{1,255}\Z")
DEFAULT_LIBRARY_DIRS = ("lib/aarch64-linux-gnu", "usr/lib/aarch64-linux-gnu", "lib", "usr/lib")
REQUIRED_DIRECTORIES = (
    "dev", "proc", "sys", "tmp", "var/tmp", "run", "opt/aragorn/pi-runtime",
    "run/aragorn-pi-bootstrap", "var/lib/aragorn/admitted",
)


class OSRootError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise OSRootError(message)


def pin(raw: bytes) -> str:
    return "sha256:" + sha256(raw)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def document(raw: bytes):
    require(len(raw) <= 1024 * 1024, "source metadata exceeds limit")
    return json.loads(raw, object_pairs_hook=_pairs)


def relative(value: str, *, root: bool = False) -> str:
    require(type(value) is str and len(value.encode("utf-8")) <= 4096 and
            not any(ord(c) < 32 for c in value) and "\\" not in value and
            not value.startswith("/"), "invalid archive path")
    if value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    if root and value in ("", "."):
        return ""
    require(value and all(part not in ("", ".", "..") for part in value.split("/")), "unsafe archive path")
    return value


def link_target(parent: str, target: str) -> str:
    require(type(target) is str and target and len(target.encode("utf-8")) <= 4096 and
            not any(ord(c) < 32 for c in target) and "\\" not in target,
            "invalid image link")
    pieces = [] if target.startswith("/") else parent.split("/") if parent else []
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            require(bool(pieces), "image link escapes virtual root")
            pieces.pop()
        else:
            pieces.append(part)
    return "/".join(pieces)


class ImageTree:
    def __init__(self):
        self.entries: dict[str, dict] = {}

    def resolve(self, name: str) -> str:
        name = relative(name)
        for _ in range(64):
            parts = name.split("/")
            for index in range(1, len(parts) + 1):
                prefix = "/".join(parts[:index])
                item = self.entries.get(prefix)
                if item and item["kind"] == "symlink":
                    target = link_target(posixpath.dirname(prefix), item["target"])
                    suffix = parts[index:]
                    name = "/".join(([target] if target else []) + suffix)
                    require(bool(name), "image link resolves to root")
                    break
                if index < len(parts):
                    require(item is None or item["kind"] == "directory", "non-directory image ancestor")
            else:
                return name
        raise OSRootError("image link cycle or depth limit")

    def file(self, name: str) -> tuple[str, dict]:
        resolved = self.resolve(name)
        item = self.entries.get(resolved)
        require(item is not None and item["kind"] == "file", f"required image file absent: {name}")
        return resolved, item

    def remove(self, name: str, *, children_only: bool = False) -> None:
        for candidate in tuple(self.entries):
            if candidate.startswith(name + "/") or (candidate == name and not children_only):
                del self.entries[candidate]

    def apply_layer(self, raw: bytes) -> None:
        require(len(raw) <= MAX_LAYER, "expanded layer exceeds limit")
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            require(len(members) <= MAX_ENTRIES, "too many layer entries")
            names = set()
            rows = []
            expanded = 0
            for member in members:
                name = relative(member.name, root=True)
                if not name:
                    require(member.isdir(), "invalid layer root")
                    continue
                require(name not in names, "duplicate layer path")
                names.add(name)
                require(member.sparse is None and not any(key.startswith("GNU.sparse") for key in member.pax_headers), "sparse layer entries are unsupported")
                expanded += member.size
                require(0 <= member.size <= MAX_FILE and expanded <= MAX_LAYER, "layer file expansion exceeds limit")
                rows.append((name, member))
            # Whiteouts affect lower layers, including when their tar entries
            # follow new members of this same layer.
            for name, member in rows:
                base = posixpath.basename(name)
                if base.startswith(".wh."):
                    require(member.isfile() or member.ischr(), "invalid whiteout entry")
                    parent = posixpath.dirname(name)
                    parent = self.resolve(parent) if parent else ""
                    if base == ".wh..wh..opq":
                        if parent:
                            self.remove(parent, children_only=True)
                        else:
                            self.entries.clear()
                    else:
                        require(len(base) > 4, "empty whiteout target")
                        self.remove(posixpath.join(parent, base[4:]))
            for name, member in rows:
                if posixpath.basename(name).startswith(".wh."):
                    continue
                parent = posixpath.dirname(name)
                parent = self.resolve(parent) if parent else ""
                name = posixpath.join(parent, posixpath.basename(name))
                if member.isdir():
                    old = self.entries.get(name)
                    if old and old["kind"] != "directory":
                        self.remove(name)
                    self.entries[name] = {"kind": "directory"}
                elif member.isfile():
                    stream = archive.extractfile(member)
                    require(stream is not None, "layer file bytes unavailable")
                    with stream:
                        data = stream.read(MAX_FILE + 1)
                    require(len(data) == member.size, "layer file size mismatch")
                    self.remove(name)
                    self.entries[name] = {"kind": "file", "raw": data, "mode": member.mode}
                elif member.issym():
                    link_target(parent, member.linkname)
                    self.remove(name)
                    self.entries[name] = {"kind": "symlink", "target": member.linkname}
                elif member.islnk():
                    # Tar hardlinks snapshot an already-existing inode; never
                    # follow a future-layer replacement of the pathname.
                    _, original = self.file(relative(member.linkname))
                    self.remove(name)
                    self.entries[name] = dict(original)
                else:
                    raise OSRootError("unsupported image special entry")
            require(len(self.entries) <= MAX_ENTRIES and
                    sum(len(row["raw"]) for row in self.entries.values() if row["kind"] == "file") <= MAX_TREE,
                    "virtual image exceeds closure limits")


def read_source(archive_path: Path, source: dict) -> tuple[ImageTree, dict]:
    require(source.get("schema") == "aragorn/pi-core-os-source/v1" and
            source.get("platform") == {"os": "linux", "architecture": "arm64", "variant": "v8"}, "unsupported OS source")
    for field in ("index_digest", "platform_manifest_digest", "config_digest"):
        require(type(source.get(field)) is str and _PIN.fullmatch(source[field]) is not None, "invalid source pin")
    require(source.get("source_reference") == "python@" + source["index_digest"], "source reference differs from index pin")
    raw = _build.regular_bytes(archive_path, MAX_ARCHIVE)
    blobs = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        require(len(members) <= 256, "save archive entry limit")
        seen = set()
        for member in members:
            name = relative(member.name)
            require(name not in seen, "duplicate save archive member")
            seen.add(name)
            if member.isdir():
                continue
            require(member.isfile() and member.sparse is None and 0 <= member.size <= MAX_ARCHIVE,
                    "save archive contains unsupported entries")
            stream = archive.extractfile(member)
            require(stream is not None, "save metadata unavailable")
            with stream:
                content = stream.read(MAX_ARCHIVE + 1)
            require(len(content) == member.size, "save archive size mismatch")
            blobs[name] = content

    def blob(digest: str, size: int | None = None) -> bytes:
        require(type(digest) is str and _PIN.fullmatch(digest) is not None, "invalid OCI descriptor digest")
        content = blobs.get("blobs/sha256/" + digest[7:])
        require(content is not None and pin(content) == digest and
                (size is None or (type(size) is int and size == len(content))), "OCI blob digest or size differs")
        return content

    index = document(blob(source["index_digest"]))
    require(index.get("schemaVersion") == 2 and index.get("mediaType") == "application/vnd.oci.image.index.v1+json", "invalid pinned OCI index")
    candidates = [row for row in index["manifests"] if row.get("platform") == source["platform"]]
    require(len(candidates) == 1 and candidates[0]["digest"] == source["platform_manifest_digest"], "arm64 platform selection differs")
    manifest = document(blob(candidates[0]["digest"], candidates[0]["size"]))
    require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") == "application/vnd.oci.image.manifest.v1+json" and
            manifest["config"]["digest"] == source["config_digest"], "invalid platform manifest or config pin")
    config = document(blob(manifest["config"]["digest"], manifest["config"]["size"]))
    require({key: config.get(key) for key in ("os", "architecture", "variant")} == source["platform"] and
            config.get("rootfs") == {"type": "layers", "diff_ids": source["layer_diff_ids"]}, "platform or uncompressed layer pins differ")
    save = document(blobs["manifest.json"])
    require(type(save) is list and len(save) == 1 and save[0]["Config"] == "blobs/sha256/" + source["config_digest"][7:] and
            save[0]["Layers"] == ["blobs/sha256/" + row["digest"][7:] for row in manifest["layers"]], "Docker save selection differs from pinned OCI chain")
    require(len(manifest["layers"]) == len(source["layer_diff_ids"]) <= 16, "layer inventory differs")
    tree = ImageTree()
    for descriptor, diff_id in zip(manifest["layers"], source["layer_diff_ids"], strict=True):
        require(descriptor["mediaType"] == "application/vnd.oci.image.layer.v1.tar+gzip", "unsupported layer encoding")
        compressed = blob(descriptor["digest"], descriptor["size"])
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            layer = stream.read(MAX_LAYER + 1)
        require(len(layer) <= MAX_LAYER and pin(layer) == diff_id, "expanded layer differs from pinned diff ID")
        tree.apply_layer(layer)
    return tree, {"archive_sha256": sha256(raw), "archive_bytes": len(raw),
        "source_reference": source["source_reference"], "index_digest": source["index_digest"],
        "platform_manifest_digest": source["platform_manifest_digest"], "source_config_digest": source["config_digest"],
        "layer_diff_ids": source["layer_diff_ids"], "source_annotations": manifest.get("annotations", {})}


def elf_dependencies(raw: bytes) -> dict:
    """Read ELF64 program/dynamic headers only; never load or execute ELF."""
    require(len(raw) >= 64 and raw[:7] == b"\x7fELF\x02\x01\x01" and
            struct.unpack_from("<H", raw, 16)[0] in (2, 3) and
            struct.unpack_from("<H", raw, 18)[0] == 183, "ELF is not little-endian Linux arm64 executable/shared object")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    require(size == 56 and 0 < count <= 128 and offset + size * count <= len(raw), "invalid ELF program table")
    loads, dynamics, interpreters = [], [], []
    for index in range(count):
        kind, flags, file_offset, address, _, file_size, memory_size, _ = struct.unpack_from("<IIQQQQQQ", raw, offset + index * size)
        require(file_offset + file_size <= len(raw) and file_size <= memory_size, "ELF segment outside file")
        if kind == 1:
            loads.append((address, file_offset, file_size))
        elif kind == 2:
            dynamics.append((file_offset, file_size))
        elif kind == 3:
            value = raw[file_offset:file_offset + file_size]
            require(1 < len(value) <= 4096 and value[-1:] == b"\0" and b"\0" not in value[:-1], "invalid ELF interpreter")
            interpreter = value[:-1].decode("ascii")
            require(interpreter.startswith("/") and relative(interpreter[1:]) == interpreter[1:], "unsafe ELF interpreter")
            interpreters.append(interpreter)
    require(bool(loads) and len(dynamics) <= 1 and len(interpreters) <= 1, "ambiguous ELF load contract")
    needed, soname = [], None
    if dynamics:
        start, length = dynamics[0]
        require(length % 16 == 0 and length <= 128 * 1024, "invalid ELF dynamic segment")
        values: dict[int, list[int]] = {}
        terminated = False
        for index in range(length // 16):
            tag, value = struct.unpack_from("<qQ", raw, start + index * 16)
            if tag == 0:
                terminated = True
                break
            values.setdefault(tag, []).append(value)
        require(terminated, "unterminated ELF dynamic table")
        require(not any(tag in values for tag in (15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff)),
                "ELF uses unapproved RPATH/RUNPATH/audit/filter loading")
        require(all(not (value & 0x800) for value in values.get(0x6ffffffb, [])), "ELF disables reviewed default library search")
        require(len(values.get(5, [])) == len(values.get(10, [])) == 1 and values[10][0] <= 16 * 1024 * 1024,
                "ELF string table missing or ambiguous")
        address, string_size = values[5][0], values[10][0]
        matches = [(file_offset + address - virtual, string_size) for virtual, file_offset, file_size in loads
                   if virtual <= address and address + string_size <= virtual + file_size]
        require(len(matches) == 1, "ELF string table not in one file-backed load")
        table_offset, _ = matches[0]
        table = raw[table_offset:table_offset + string_size]
        def string(index: int) -> str:
            require(index < len(table), "ELF string index outside table")
            end = table.find(b"\0", index)
            require(end >= 0 and end - index <= 255, "ELF name exceeds bound")
            value = table[index:end].decode("ascii")
            require(_SONAME.fullmatch(value) is not None and value not in (".", ".."), "unsafe ELF dependency name")
            return value
        needed = [string(value) for value in values.get(1, [])]
        require(len(needed) <= 64 and len(set(needed)) == len(needed), "duplicate or excessive ELF dependencies")
        require(len(values.get(14, [])) <= 1, "multiple ELF sonames")
        if 14 in values:
            soname = string(values[14][0])
    return {"interpreter": interpreters[0] if interpreters else None, "needed": needed, "soname": soname}


def closed_elf_inventory(tree: ImageTree, node: bytes) -> tuple[dict, list[dict]]:
    selected: dict[str, dict] = {}
    edges = []
    queue = [("@compiled-node", node)]
    source, env = tree.file("usr/bin/env")
    require(bool(env["mode"] & 0o111), "source env is not executable")
    selected["usr/bin/env"] = {**env, "source_path": source}
    queue.append(("usr/bin/env", env["raw"]))
    seen = set()
    while queue:
        name, raw = queue.pop(0)
        if name in seen:
            continue
        seen.add(name)
        require(len(seen) <= 128, "ELF closure exceeds bound")
        elf = elf_dependencies(raw)
        if name in ("@compiled-node", "usr/bin/env"):
            require(elf["interpreter"] == "/lib/ld-linux-aarch64.so.1", "entry ELF interpreter is not the reviewed arm64 glibc route")
        requests = []
        if elf["interpreter"]:
            requests.append(("interpreter", elf["interpreter"], elf["interpreter"][1:]))
        for dependency in elf["needed"]:
            candidates = []
            for directory in DEFAULT_LIBRARY_DIRS:
                path = directory + "/" + dependency
                resolved = tree.resolve(path)
                item = tree.entries.get(resolved)
                if item is not None and item["kind"] == "file":
                    candidates.append((path, resolved, item))
            require(bool(candidates), f"unresolved ELF dependency: {name} -> {dependency}")
            # Aliases may resolve to the same file. Different candidate bytes
            # would depend on runtime search/cache semantics: refuse ambiguity.
            require(len({pin(item["raw"]) for _, _, item in candidates}) == 1, f"ambiguous library candidates: {dependency}")
            requests.append(("needed", dependency, candidates[0][0]))
        for kind, requested, path in requests:
            source, member = tree.file(path)
            details = elf_dependencies(member["raw"])
            if kind == "needed":
                require(details["soname"] == requested, "library SONAME does not match dependency")
            else:
                require(bool(member["mode"] & 0o111), "ELF interpreter is not executable")
            if path not in selected:
                selected[path] = {**member, "source_path": source}
                queue.append((path, member["raw"]))
            edges.append({"requester": name, "kind": kind, "requested": requested,
                          "path": path, "source_path": source, "digest": pin(member["raw"])})
    return selected, edges


def license_provenance(tree: ImageTree, selected: dict) -> tuple[list[dict], dict[str, bytes]]:
    selected_paths = {value["source_path"] for value in selected.values()}
    selected_names = {posixpath.basename(path) for path in selected_paths}
    packages = set()
    covered = set()
    for path, item in tree.entries.items():
        if not path.startswith("var/lib/dpkg/info/") or not path.endswith(".list") or item["kind"] != "file":
            continue
        for line in item["raw"].decode("utf-8").splitlines():
            if not line.startswith("/") or posixpath.basename(line) not in selected_names:
                continue
            candidate = tree.resolve(line[1:])
            if candidate in selected_paths:
                packages.add(posixpath.basename(path)[:-5].split(":")[0])
                covered.add(candidate)
    require(covered == selected_paths, "selected OS bytes lack Debian package ownership provenance")
    documents = {}
    rows = []
    _, status = tree.file("var/lib/dpkg/status")
    metadata = {}
    for paragraph in status["raw"].decode("utf-8").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
        if fields.get("Package") in packages:
            metadata[fields["Package"]] = {key: fields[key] for key in ("Package", "Version", "Architecture", "Source") if key in fields}
    require(set(metadata) == packages, "selected OS package metadata incomplete")
    for package in sorted(packages):
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", package) is not None, "invalid provenance package name")
        source, item = tree.file("usr/share/doc/" + package + "/copyright")
        key = "licenses/" + package + ".copyright"
        documents[key] = item["raw"]
        rows.append({**metadata[package], "copyright_source": source, "retained_path": "provenance/" + key, "digest": pin(item["raw"])})
        for license_name in re.findall(rb"/usr/share/common-licenses/([A-Za-z0-9.-]+)", item["raw"]):
            name = license_name.decode("ascii").rstrip(".")
            _, common = tree.file("usr/share/common-licenses/" + name)
            documents["licenses/common/" + name] = common["raw"]
    return rows, documents


def prepare_os_root(archive: Path, node: Path, *, node_digest: str, output: Path, source: dict) -> dict:
    node_raw = _build.regular_bytes(node, MAX_FILE)
    require(pin(node_raw) == node_digest, "compiled Node bytes differ from expected digest")
    tree, provenance = read_source(archive, source)
    selected, edges = closed_elf_inventory(tree, node_raw)
    packages, licenses = license_provenance(tree, selected)
    directories = set()
    for name in (*REQUIRED_DIRECTORIES, *(posixpath.dirname(name) for name in selected)):
        pieces = relative(name).split("/")
        directories.update("/".join(pieces[:index]) for index in range(1, len(pieces) + 1))
    files = [{"path": path, "size": len(item["raw"]), "digest": pin(item["raw"]), "executable": bool(item["mode"] & 0o111)}
             for path, item in sorted(selected.items())]
    protected_tree = {"schema": "aragorn/pi-core-protected-tree/v1", "files": files, "directories": sorted(directories)}
    destination = output.absolute()
    require(destination == destination.resolve() and not destination.exists() and not destination.is_symlink(), "OS staging destination must be fresh and unlinked")
    destination.mkdir(mode=0o700)
    root = destination / "root"
    root.mkdir(mode=0o755)
    for name in sorted(directories, key=lambda value: (value.count("/"), value)):
        (root / name).mkdir(mode=0o755)
    for row in files:
        target = root / row["path"]
        with target.open("xb") as stream:
            stream.write(selected[row["path"]]["raw"])
        target.chmod(0o555 if row["executable"] else 0o444)
    for name in sorted(directories, key=lambda value: value.count("/"), reverse=True):
        (root / name).chmod(0o555)
    root.chmod(0o555)
    for name, raw in licenses.items():
        target = destination / "provenance" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(0o444)
    receipt = {"schema": "aragorn/pi-core-os-root/v1", "status": "PREPARED_NOT_INSTALLED_OR_EXECUTED",
        "target": "linux-arm64-glibc", **provenance, "node_digest": node_digest,
        "protected_tree": protected_tree, "closure_digest": pin(canonical(protected_tree)),
        "elf_dependencies": edges, "library_search_directories": list(DEFAULT_LIBRARY_DIRS),
        "loader_cache_included": False, "ld_preload_included": False,
        "packages": packages, "source_pin_digest": pin(canonical(source)),
        "executed_target_code": False, "native_cleanup_verified": False,
        "qualification": "STATIC_CLOSURE_ONLY_NOT_ABI_EXECUTION_OR_PHASE3_QUALIFICATION"}
    (destination / "os-root-receipt.json").write_bytes(canonical(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--node-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1] / "packaging/pi-core/os-source-v1.json")
    args = parser.parse_args()
    try:
        receipt = prepare_os_root(args.archive, args.node, node_digest=args.node_digest,
                                  output=args.output, source=document(_build.regular_bytes(args.source)))
    except (OSRootError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        parser.exit(1, f"Pi OS preparation refused: {exc}\n")
    print(json.dumps({"status": receipt["status"], "closure_digest": receipt["closure_digest"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
