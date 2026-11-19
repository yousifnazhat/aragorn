"""Build and ad-hoc sign the B45 host executable; never run it, allocate or open a VM/store."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess

from scripts.build_pi_core_linux import ROOT, canonical, require, sha256
from scripts.prepare_pi_core_guest_disk import WORK as B41, opened, put
from scripts.prepare_pi_core_guest_firmware_trust import private_dir


PACK = ROOT / "packaging/pi-core/immutable-host-b45"
B44 = PACK.parent / "immutable-host-b44"
WORK = B41.parent / "build-b45"
SOURCES = ("host-runner.m", "serial-recorder.h", "serial-recorder.m", "runner.entitlements.plist")
IDENTIFIER = "org.aragorn.pi-core.b45.host-runner"
ENTITLEMENT = "com.apple.security.virtualization"
CLT = Path("/Library/Developer/CommandLineTools")
SDK = CLT / "SDKs/MacOSX26.5.sdk"
CC, LD, ALLOC = (CLT / "usr/bin" / n for n in ("clang", "ld", "codesign_allocate"))
SIGN = Path("/usr/bin/codesign")
TOOLS = {
    CC: "1220c0afafa12a6ae599d097ee7cf8b87c6b4d8e3fbb9783cee6b319a80683ba",
    LD: "765e5fa4e30980ddf2803c8a973b20fcc63e403098d2dd9b6cefa38e0cde3c2e",
    ALLOC: "1f4aa6cb65068983ff9de8a71bc18426ab622c90b4442952fe822d4cb9f9ba59",
    SIGN: "844d30a12929b59c9f2215e2a308c3e1db572831a478f35906e452a54025603e",
    SDK / "SDKSettings.json": "f8d005f09381389167f9e0aeaa169bc9e7dff162ef22ca2fd8e98df7ff1acafe",
    SDK / "usr/lib/libSystem.tbd": "20cfce043f11a083e2eb6111efe3579919a8082fa4cc912a7bd839af2010ec57",
    **{SDK / f"System/Library/Frameworks/{n}.framework/{n}.tbd": h for n, h in (
        ("Foundation", "f425b7c55986e46ab62fd8d8a457ee3fb1ddbe4af46b41abe1e63110ef7fba44"),
        ("Security", "b48c590fd9800709635008783bbc6bcec18826a7da94235e33ca692427f42ad3"),
        ("Virtualization", "09d6a67bda0e97a2f89ff7c8c90b52ecf55bcee99fa8705faedbd4317c63bb6f"),
    )},
}


def source_bytes(path):
    with opened(path) as f:
        raw = f.read((1 << 20) + 1)
        require(0 < len(raw) <= 1 << 20, "unexpected build source size")
        return raw


def run(work, argv, *, writable=False):
    # A local ad-hoc signature needs no signing account, timestamp service or identity key.
    profile = "(version 1)(allow default)(deny network*)(deny file-write*)"
    if writable:
        profile += '(allow file-write* (literal "/dev/null") (subpath ' + json.dumps(str(work)) + '))'
    result = subprocess.run(["/usr/bin/sandbox-exec", "-p", profile, *map(str, argv)], cwd=work,
                            env={"HOME": str(work), "TMPDIR": str(work), "LC_ALL": "C", "PATH": "/usr/bin:/bin",
                                 "CODESIGN_ALLOCATE": str(ALLOC)}, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=90)
    if result.returncode and writable:
        put(work / "failed-command.json", canonical({"argv": list(map(str, argv)), "returncode": result.returncode,
                                                      "stderr": result.stderr.decode("utf-8", "replace")[-32768:]}))
    require(result.returncode == 0, "host build/signature command failed: " +
            result.stderr.decode("utf-8", "replace")[-4096:])
    return result


def macho_uuid(raw):
    require(len(raw) >= 32 and struct.unpack_from("<II", raw) == (0xfeedfacf, 0x0100000c)
            and struct.unpack_from("<I", raw, 12)[0] == 2, "not a thin ARM64 Mach-O executable")
    count, size = struct.unpack_from("<II", raw, 16)
    pos, end = 32, 32 + size
    require(0 < count <= 1024 and 8 * count <= size and end <= len(raw), "invalid load-command bounds")
    uuid = None
    for _ in range(count):
        require(pos + 8 <= end, "truncated load command")
        kind, width = struct.unpack_from("<II", raw, pos)
        require(8 <= width <= end - pos and width % 8 == 0, "invalid load-command size")
        if kind == 0x1b:  # struct uuid_command from mach-o/loader.h
            require(uuid is None and width == 24 and any(raw[pos + 8:pos + 24]), "invalid or duplicate LC_UUID")
            uuid = raw[pos + 8:pos + 24].hex()
        pos += width
    require(pos == end and uuid is not None, "missing LC_UUID or unclaimed load-command bytes")
    return uuid


def verify_runner(path):
    """Independent readback; caller must also match these fields to the trusted Git-signed release pin."""
    with opened(path) as f:
        st = os.fstat(f.fileno())
        require(st.st_uid == os.getuid() and stat.S_IMODE(st.st_mode) == 0o500 and 32 <= st.st_size <= 8 << 20,
                "expected private sealed executable")
        raw = f.read(st.st_size)
        uuid = macho_uuid(raw)
        run(path.parent, [SIGN, "--verify", "--strict", "--all-architectures", path])
        details = run(path.parent, [SIGN, "--display", "--verbose=4", path]).stderr.decode()
        values = dict(line.split("=", 1) for line in details.splitlines() if "=" in line)
        cd = values.get("CDHash", "")
        require(values.get("Identifier") == IDENTIFIER and values.get("Signature") == "adhoc" and
                values.get("TeamIdentifier") == "not set" and re.fullmatch("[0-9a-f]{40}", cd) and
                "runtime" in values.get("CodeDirectory v", "").partition("flags=")[2].partition(")")[0],
                "unexpected runner code signature")
        ent = plistlib.loads(run(path.parent, [SIGN, "--display", "--entitlements", "-", "--xml", path]).stdout)
        require(type(ent) is dict and set(ent) == {ENTITLEMENT} and ent[ENTITLEMENT] is True,
                "unexpected code-signed entitlements")
        return {"runner_sha256": sha256(raw), "runner_bytes": len(raw), "macho_uuid_hex": uuid,
                "cdhash": cd, "identifier": IDENTIFIER,
                "signing": "ad-hoc-local-integrity", "team_identifier": None, "entitlements": ent}


def build():
    require(os.uname().sysname == "Darwin" and os.uname().machine == "arm64", "requires local Apple ARM64 tools")
    for path, pin in TOOLS.items():
        actual = path.resolve(strict=True)
        require(actual == path or actual.is_relative_to(SDK), "tool resolves outside pinned SDK")
        with actual.open("rb") as f:
            require(fstat_trusted(os.fstat(f.fileno())) and hashlib.file_digest(f, "sha256").hexdigest() == pin,
                    "host build tool differs: " + path.name)
    sources = {name: source_bytes(PACK / name) for name in SOURCES}
    request, pins = (source_bytes(B44 / n) for n in ("boot-request.json", "media-output.json"))
    disk = json.loads(pins)["disk_sha256"]
    require(re.fullmatch("[0-9a-f]{64}", disk) and json.loads(request)["guest"]["disk_sha256"] == disk,
            "B44 disk and boot request differ")
    ingredients = {"sources": {n: sha256(data) for n, data in sources.items()},
                   "tools": {str(p): h for p, h in TOOLS.items()}, "recipe": sha256(source_bytes(Path(__file__).resolve())),
                   "request_sha256": sha256(request), "media_pins_sha256": sha256(pins), "disk_sha256": disk}
    inputs = canonical(ingredients)
    private_dir(WORK)
    dst = WORK / ("build-" + sha256(inputs))
    dst.mkdir(mode=0o700, exist_ok=False)  # keep failed and completed builds; never retry or overwrite
    put(dst / "inputs.json", inputs)
    for name, raw in sources.items():
        put(dst / name, raw)
    binary = dst / "host-runner"
    defines = [f'-DB45_{name.upper()}="{ingredients[name]}"'
               for name in ("request_sha256", "media_pins_sha256", "disk_sha256")]
    run(dst, [CC, "-arch", "arm64", "-isysroot", SDK, "--ld-path=" + str(LD), "-mmacosx-version-min=14",
              "-fobjc-arc", "-fno-modules", "-Werror", "-Os", *defines,
              "host-runner.m", "serial-recorder.m", "-framework", "Foundation", "-framework", "Virtualization",
              "-framework", "Security", "-o", binary], writable=True)
    run(dst, [SIGN, "--force", "--sign", "-", "--identifier", IDENTIFIER, "--options", "runtime",
              "--timestamp=none", "--entitlements", dst / "runner.entitlements.plist", binary], writable=True)
    binary.chmod(0o500)
    return seal(dst, ingredients)


def seal(dst, ingredients):
    """Finish a built, never executed artifact using independently reviewed build inputs; exclusive receipt."""
    raw = source_bytes(dst / "inputs.json")
    require(raw == canonical(ingredients) and dst.parent == WORK and dst.name == "build-" + sha256(raw),
            "build input identity mismatch")
    for name in SOURCES:
        require(sha256(source_bytes(dst / name)) == ingredients["sources"][name] == sha256(source_bytes(PACK / name)),
                "compiled source snapshot differs from checkout")
    build_recipe = ingredients["recipe"]
    reader = sha256(source_bytes(Path(__file__).resolve()))
    if reader != build_recipe:
        require(sha256(source_bytes(dst / "original-build-recipe.py")) == build_recipe,
                "original build recipe unavailable or differs")
    receipt = dict(schema="aragorn/bound-host-runner-artifact/v1", directory=dst.name,
                   **verify_runner(dst / "host-runner"), build_recipe_sha256=build_recipe,
                   verification_recipe_sha256=reader, boot_authorized=False,
                   **{key: ingredients[key] for key in ("request_sha256", "media_pins_sha256", "disk_sha256")})
    put(dst / "receipt.json", canonical(receipt) + b"\n")
    return receipt


def fstat_trusted(st):
    return stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(build(), sort_keys=True))
