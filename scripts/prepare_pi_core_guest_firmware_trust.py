"""Prepare only an ordinary EFI_SIGNATURE_LIST file for the retained B41 UKI.

This is *not* an authenticated variable update, enrollment, firmware access or
permission to boot. UEFI 2.11, Secure Boot and Driver Signing, image validation:
https://uefi.org/specs/UEFI/2.11/32_Secure_Boot_and_Driver_Signing.html
"""
import hashlib
import json
import os
import stat
import struct
import uuid

from scripts.build_pi_core_linux import ROOT, regular_bytes, require, sha256
from scripts.inspect_pi_core_guest_disk import sections
from scripts.prepare_pi_core_guest_disk import PACK, WORK, opened, put


PIN = ROOT / "packaging/pi-core/immutable-host-b42/firmware-trust.json"
B41 = PACK / "media-output.json"
UKI = WORK / "media-v1/BOOTAA64.EFI"
OUT = WORK.parent / "build-b42/firmware-trust"
FILE = "b41-uki-sha256.esl"
EFI_CERT_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
OWNER = uuid.uuid5(uuid.NAMESPACE_URL, "urn:aragorn:pi-core-managed-phase3:firmware-image-hash-owner:v1")


def image_hash(pe):
    """Authenticode SHA-256, strictly limited to this dense, unsigned ARM64 UKI layout."""
    v = memoryview(pe)
    sections(v)  # Reuse the B41 certificate/architecture/header, entry and section guards.
    p = struct.unpack_from("<I", v, 60)[0]
    opt = p + 24
    hdr = struct.unpack_from("<I", v, opt + 60)[0]
    sec = opt + struct.unpack_from("<H", v, p + 20)[0]
    count = struct.unpack_from("<H", v, p + 6)[0]
    checksum, cert_dir = opt + 64, opt + 144
    h = hashlib.sha256()
    for part in (v[:checksum], v[checksum + 4:cert_dir], v[cert_dir + 8:hdr]):
        h.update(part)
    # UEFI/Authenticode uses raw section sizes (including alignment padding),
    # in increasing PointerToRawData order. Do not hash only virtual payloads.
    spans = sorted((offset, size) for size, offset in (
        struct.unpack_from("<II", v, s + 16) for s in range(sec, sec + 40 * count, 40)
    ) if size)
    cursor = hdr
    for offset, size in spans:
        require(offset == cursor, "ambiguous PE body: section gap or overlap")
        cursor += size
        h.update(v[offset:cursor])
    require(cursor == len(v), "unexpected PE overlay or trailer")
    return h.digest()


def proposal(pe, pin, b41):
    require(pin["schema"] == "aragorn/immutable-guest-firmware-hash-proposal/v1"
            and pin["source"] == B41.relative_to(ROOT).as_posix()
            and pin["status"] == "inert-proposal-only"
            and all(pin[k] is False for k in ("firmware_grant", "enrolled", "boot_observed", "phase3_exit_eligible"))
            and all(pin[k] == "unknown" for k in ("firmware_db", "firmware_dbx", "firmware_policy")),
            "not an inert firmware proposal")
    require(b41["schema"] == "aragorn/immutable-guest-disk/v1" and b41["directory"] == "media-v1"
            and b41["secure_boot_enrollment"] is False and b41["boot_observed"] is False,
            "unexpected B41 media contract")
    require(len(pe) == pin["uki_bytes"] and sha256(pe) == pin["uki_sha256"] == b41["uki_sha256"],
            "whole UKI differs; UEFI digest alone cannot authorize substitutions")
    digest = image_hash(pe)
    require(digest.hex() == pin["authenticode_sha256"] and pin["signature_type"] == str(EFI_CERT_SHA256)
            and pin["signature_owner"] == str(OWNER), "unexpected PE digest or ESL identity")
    # EFI_GUID uses little-endian first three fields on this platform. The
    # digest is *not* byte-swapped. There are no attributes or auth descriptors.
    record = struct.pack("<16sIII16s32s", EFI_CERT_SHA256.bytes_le, 76, 0, 48, OWNER.bytes_le, digest)
    require(len(record) == pin["esl_bytes"] and sha256(record) == pin["esl_sha256"], "record pin differs")
    return record


def private_dir(path):
    require(path.parent.resolve(strict=True) == path.parent, "linked output parent")
    path.mkdir(mode=0o700, exist_ok=True)
    s = path.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and s.st_mode & 0o077 == 0,
            "expected a private owned directory")


def prepare():
    pin = json.loads(regular_bytes(PIN))
    with opened(UKI) as stream:
        require(os.fstat(stream.fileno()).st_size == pin["uki_bytes"] <= 128 << 20, "unexpected UKI size")
        record = proposal(stream.read(), pin, json.loads(regular_bytes(B41)))
    private_dir(OUT.parent)
    private_dir(OUT)
    final = OUT / FILE
    if os.path.lexists(final):
        with opened(final) as f:
            require(f.read(len(record) + 1) == record, "existing ESL differs; refusing replacement")
    else:
        put(final, record)
    return final


if __name__ == "__main__":
    print(prepare())
