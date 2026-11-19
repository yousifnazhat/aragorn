"""Check GNU versioned undefined dynamic symbols on ONE nominated AArch64 ELF edge.

Developer input only: the caller authenticates the two payloads. Not an ELF
loader, proof of OS identity or relocation safety, or a substitute for host preparation.
Unversioned imports, executable copy relocations and runtime loading are not checked.
"""
import hashlib
from pathlib import Path
import re
import resource
import subprocess
import tempfile

from scripts.build_pi_core_linux import regular_bytes

READELF = Path("/opt/homebrew/Cellar/mingw-w64/14.0.0_3/toolchain-x86_64/bin/x86_64-w64-mingw32-readelf")
ZSTD = Path("/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.5.7.dylib")
TOOL_PINS = {
    READELF: "f739381a6d6d6b17aa3e6b01e6396a9ea14f09244c957eee09323ba5a8f25ffa",
    ZSTD: "e2847c4613b386683c234913ae3b7b04299254096caf7616e3b3cd9bb97a39ab",
}
_NAME = r"[a-zA-Z0-9_.$+-]+"
_OUT = 16 << 20


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def _tools():
    _require(Path("/opt/homebrew/opt/zstd/lib/libzstd.1.dylib").resolve(strict=True) == ZSTD,
             "readelf library target differs")
    for path, digest in TOOL_PINS.items():
        _require(path.resolve(strict=True) == path and
                 hashlib.sha256(regular_bytes(path, 2 << 20)).hexdigest() == digest, "readelf toolchain differs")


def _limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (_OUT, _OUT))


def _readelf(raw):
    _require(type(raw) is bytes and 64 <= len(raw) <= 128 << 20 and
             raw[:7] == b"\x7fELF\x02\x01\x01" and raw[16:18] in (b"\x02\x00", b"\x03\x00") and
             raw[18:20] == b"\xb7\x00", "expected bounded little-endian Linux arm64 ELF")
    with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        path = Path(directory) / "candidate.elf"
        path.write_bytes(raw)
        result = subprocess.run([str(READELF), "--wide", "--use-dynamic", "--symbols", "--dynamic", "--version-info", str(path)],
                                stdout=output, stderr=errors, stdin=subprocess.DEVNULL, cwd=directory, env={"LC_ALL": "C"},
                                preexec_fn=_limit_output, timeout=10, check=False)
        _require(result.returncode == 0 and not errors.tell() and 0 < output.tell() < _OUT,
                 "readelf reported invalid, incomplete or excessive metadata")
        output.seek(0)
        return output.read().decode("ascii")


def _parse(report):
    """Read GNU readelf's dynamic symbol table, VERNEED/VERDEF and VERSYM indexes."""
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", report)
    sonames = re.findall(r"\(SONAME\)\s+Library soname: \[([^\]]+)\]", report)
    _require(len(needed) == len(set(needed)) and len(sonames) <= 1, "ambiguous ELF dependencies")
    imports, definitions = {}, {}
    groups = []
    for line in report.splitlines():
        parent = re.fullmatch(rf"\s*[0-9a-fx]+: Version: 1\s+File: ({_NAME})\s+Cnt: (\d+)", line)
        entry = re.fullmatch(rf"\s*[0-9a-fx]+:\s+Name: ({_NAME})\s+Flags: \S+\s+Version: (\d+)", line)
        defined = re.fullmatch(rf"\s*[0-9a-fx]+: Rev: 1\s+Flags: \S+\s+Index: (\d+)\s+Cnt: \d+\s+Name: ({_NAME})", line)
        if parent:
            library, count = parent.groups()
            _require(library in needed and not any(g[0] == library for g in groups), "invalid version provider")
            groups.append([library, int(count)])
        elif entry:
            version, key = entry.groups()
            index = int(key)
            _require(groups and groups[-1][1] > 0 and index >= 2 and index not in imports, "invalid version requirement")
            imports[index] = (groups[-1][0], version)
            groups[-1][1] -= 1
        elif defined:
            index, version = defined.groups()
            _require(int(index) not in definitions, "duplicate version definition")
            definitions[int(index)] = version
    _require(all(n == 0 for _, n in groups) and not definitions.keys() & imports.keys(), "incomplete version definitions")
    counts = re.findall(r"^Symbol table for image contains (\d+) entries:$", report, re.M)
    version_counts = re.findall(r"^Version symbols section '\.gnu\.version' contains (\d+) entries:$", report, re.M)
    _require(len(counts) == 1 and counts == version_counts, "incomplete or unsupported GNU dynamic-symbol table")
    table = report.split("Version symbols section '.gnu.version'", 1)[1].split("\n\n", 1)[0]
    indexes = []
    for line in table.splitlines():
        row = re.fullmatch(r"\s*([0-9a-f]+):\s*(.*)", line)
        if row:
            _require(int(row[1], 16) == len(indexes), "invalid GNU version-symbol offset")
            indexes.extend(int(i, 16) for i in re.findall(r"([0-9a-f]+)[h ]*\([^()]*\)", row[2]))
    _require(0 < len(indexes) == int(counts[0]) <= 131072, "missing GNU version-symbol indexes")
    refs, exports = {}, {}
    rows = re.findall(r"^\s*(\d+):\s+[0-9a-f]+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)[ \t]*(.*)$", report, re.M)
    _require(len(rows) == len(indexes), "incomplete dynamic symbol rows")
    for offset, ((number, typ, bind, visibility, section, name), index) in enumerate(zip(rows, indexes)):
        _require(int(number) == offset, "dynamic symbol ordering differs")
        if index < 2:
            _require("@" not in name, "versioned name lacks a GNU version index")
            continue
        if section == "UND":
            match = re.fullmatch(rf"({_NAME})@({_NAME}) \((\d+)\)", name)
            _require(match and int(match[3]) == index and index in imports and
                     imports[index][1] == match[2] and bind in ("GLOBAL", "WEAK") and
                     visibility == "DEFAULT", "unattributed versioned symbol")
            refs.setdefault(imports[index][0], []).append((match[1], match[2], typ))
        elif bind in ("GLOBAL", "WEAK", "UNIQUE") and visibility in ("DEFAULT", "PROTECTED"):
            if index not in definitions:
                continue  # Executable copy relocations aren't definitions for this provider.
            # ELF version labels themselves may be unadorned absolute symbols.
            if section == "ABS" and name == definitions[index]:
                continue
            match = re.fullmatch(rf"({_NAME})@@?({_NAME})", name)
            _require(match and match[2] == definitions[index], "invalid versioned export")
            key = (match[1], match[2])
            _require(key not in exports, "ambiguous versioned export")
            exports[key] = typ
    return sonames, imports, definitions, refs, exports


def _edge(requester_report, provider_report, soname):
    _, imports, _, refs, _ = _parse(requester_report)
    sonames, _, definitions, _, exports = _parse(provider_report)
    _require(sonames == [soname] and refs.get(soname), "provider SONAME differs or has no attributed symbols")
    required = sorted(set(refs[soname]))
    versions = {version for library, version in imports.values() if library == soname}
    missing = []
    for name, version, typ in required:
        found = exports.get((name, version))
        if found is None or not (typ == found or typ == "NOTYPE" or (typ == "FUNC" and found == "IFUNC")):
            missing.append(name + "@" + version)
    _require(not missing and versions <= set(definitions.values()),
             "unavailable versioned symbols/versions: " + ", ".join((missing + sorted(versions - set(definitions.values())))[:12]))
    return {"provider_soname": soname, "versioned_symbol_count": len(required),
            "required_versions": sorted(versions), "scope": "SELECTED_STATIC_VERSIONED_UNDEFINED_SYMBOLS_ONLY",
            "runtime_verified": False, "phase3_exit_eligible": False}


def check_versioned_provider(requester_raw, provider_raw, soname):
    _require(type(soname) is str and re.fullmatch(_NAME, soname), "invalid selected SONAME")
    _tools()
    try:
        return _edge(_readelf(requester_raw), _readelf(provider_raw), soname)
    finally:
        _tools()
