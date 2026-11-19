"""Read only the regular raw disk: both GPTs, FAT32 removable path, UKI payloads and SquashFS partition."""
import hashlib
import os
import struct
import uuid
import zlib

from scripts.build_pi_core_linux import require, sha256
from scripts.prepare_pi_core_guest_disk import CMDLINE, GPT, LINUX_VERSION, OSREL, PARTS, opened


# Directly read from the signed-index systemd-boot-efi_259.5-0ubuntu3_arm64.deb
# member linuxaa64.efi.stub, SHA-256 2484474a4f3a09330478fbc6982acdd8bdf96752d1313382e5e291c5942fa072.
# ukify appends data sections but must not replace, move or alter executable startup code.
EFI_ENTRY_RVA = 0x112E4
EFI_TEXT = (0x5000, 64376, 0x60000020, "48ddf82d02b9a25eedcc15c78548779113b57128db2cbf7db5f17124fe925f69")


def integer(raw, at, n):
    require(0 <= at <= len(raw) - n, "field outside artifact")
    return int.from_bytes(raw[at:at+n], "little")


def gpt(h, table, here, there, where):
    require(len(h) == 512 and h[:8] == b"EFI PART" and integer(h, 8, 4) == 0x10000
            and integer(h, 12, 4) == 92 and not any(h[92:]), "invalid GPT header")
    require(zlib.crc32(h[:16] + bytes(4) + h[20:92]) == integer(h, 16, 4)
            and not any(h[20:24]), "invalid GPT header CRC")
    require(struct.unpack_from("<QQQQ", h, 24) == (here, there, 34, max(here, there)-33)
            and h[56:72] == GPT.bytes_le and struct.unpack_from("<QII", h, 72) == (where, 128, 128),
            "misplaced GPT geometry or disk identity")
    require(len(table) == 16384 and zlib.crc32(table) == integer(h, 88, 4) and not any(table[256:]),
            "invalid partition array")
    extents = []
    for i, (label, kind, ident) in enumerate(PARTS):
        typ, uid, begin, end, flags, name = struct.unpack_from("<16s16sQQQ72s", table, i*128)
        require((str(uuid.UUID(bytes_le=typ)), str(uuid.UUID(bytes_le=uid)), name.decode("utf-16-le").rstrip("\0"))
                == (kind, ident, label) and flags == (1 << 60 if i else 0)
                and 34 <= begin <= end <= max(here, there)-33, "invalid partition")
        extents.append((begin, end))
    require(extents[0][0] == 2048 and extents[0][1]+1 == extents[1][0] and
            extents[1][1] == max(here, there)-33, "unexpected GPT gap or overlap")
    return extents


def redundant_name(slot, short, expected):
    """mtools can spell the *same* short name as one VFAT record; no alternate path."""
    checksum = 0
    for byte in short:
        checksum = (((checksum >> 1) | ((checksum & 1) << 7)) + byte) & 255
    data = slot[1:11] + slot[14:26] + slot[28:32]
    expected = expected.encode("utf-16-le") + b"\0\0"
    require(len(slot) == 32 and slot[0] == 0x41 and slot[11:14] == bytes((15, 0, checksum))
            and slot[26:28] == b"\0\0" and data == expected.ljust(26, b"\xff"),
            "ambiguous VFAT name or checksum")


def fat_uki(volume, esp_lba):
    """Narrow independent FAT32 reader: accept only this one boot path."""
    require(len(volume) >= 512, "missing FAT32 boot sector")
    # A firmware reader may consult legacy fields before their FAT32 counterparts.
    # For this mirrored FAT32/v0 ESP none of these fields may override the geometry.
    require(all(integer(volume, pos, 2) == 0 for pos in (17, 19, 22, 40, 42)),
            "conflicting FAT32 boot parameters")
    sector, spc, reserved, copies = struct.unpack_from("<HBHB", volume, 11)
    nsect, fatsz = struct.unpack_from("<II", volume, 32)
    require(sector == 512 and spc in (1, 2, 4, 8) and reserved >= 2 and copies == 2 and
            bytes(volume[510:512]) == b"\x55\xaa" and integer(volume, 28, 4) == esp_lba and
            0 < fatsz < nsect//2 and nsect*sector == len(volume), "invalid FAT32 geometry")
    first = (reserved + copies*fatsz)*sector
    fat = volume[reserved*sector:(reserved+fatsz)*sector]
    require(fat == volume[(reserved+fatsz)*sector:first], "FAT mirrors differ")
    cluster_bytes = sector * spc
    total = (len(volume)-first)//cluster_bytes
    require(65525 <= total < len(fat)//4 - 1, "not a bounded FAT32 volume")
    used = set()

    def content(cluster, limit):
        parts = []
        while True:
            require(2 <= cluster < total+2 and cluster not in used and
                    len(parts)*cluster_bytes < limit, "FAT chain alias, cycle or length")
            used.add(cluster)
            off = first + (cluster-2)*cluster_bytes
            parts.append(volume[off:off+cluster_bytes])
            cluster = integer(fat, 4*cluster, 4) & 0xfffffff
            if 0xffffff8 <= cluster <= 0xfffffff:
                return b"".join(parts)

    cluster = integer(volume, 44, 4)
    for depth, (expected, directory) in enumerate(((b"EFI        ", True), (b"BOOT       ", True), (b"BOOTAA64EFI", False))):
        data = content(cluster, 64 << 10)
        entries, slot, label_seen = [], None, False
        for pos in range(0, len(data), 32):
            row = data[pos:pos+32]
            if row[0] == 0:
                break
            if row[11] == 15:
                require(slot is None and row[0] == 0x41, "unexpected multipart VFAT name")
                slot = row
                continue
            if slot is not None:
                display = {b"BOOTAA64EFI": "BOOTAA64.EFI", b"ARAGORN_EFI": "ARAGORN_EFI"}.get(row[:11])
                require(display is not None, "unexpected VFAT alias")
                redundant_name(slot, row[:11], display)
                slot = None
            if row[11] == 8:
                require(depth == 0 and not label_seen and row[:11] == b"ARAGORN_EFI", "unexpected FAT label")
                label_seen = True
                continue
            if row[:11] in (b".          ", b"..         "):
                require(depth and row[11] == 16, "invalid dot directory")
                continue
            entries.append(row)
        require(slot is None and len(entries) == 1 and entries[0][:11] == expected and
                (entries[0][11] & 0x18) == (0x10 if directory else 0), "unexpected EFI boot namespace")
        row = entries[0]
        cluster = (integer(row, 20, 2) << 16) + integer(row, 26, 2)
    length = integer(row, 28, 4)
    data = content(cluster, 128 << 20)
    require(0 < length <= len(data) < length + cluster_bytes, "wrong EFI file extent")
    return data[:length]


def sections(pe):
    require(pe[:2] == b"MZ", "not an EFI binary")
    off = integer(pe, 60, 4)
    require(pe[off:off+4] == b"PE\0\0" and integer(pe, off+4, 2) == 0xaa64, "not ARM64 PE")
    count, opt = integer(pe, off+6, 2), integer(pe, off+20, 2)
    start = off+24
    require(1 <= count <= 64 and opt >= 152 and integer(pe, start, 2) == 0x20b
            and start+opt+count*40 <= len(pe) and integer(pe, start+68, 2) == 10
            and integer(pe, start+108, 4) >= 5, "not a PE32+ EFI application")
    # No Authenticode signature on the outer candidate; don't conflate the nested signed kernel with a signed UKI.
    require(not any(pe[start+144:start+152]), "unexpected outer EFI certificate directory")
    entry = integer(pe, start+16, 4)
    require(entry == EFI_ENTRY_RVA, "unexpected firmware entrypoint")
    page, file_align = struct.unpack_from("<II", pe, start+32)
    image_size, headers = struct.unpack_from("<II", pe, start+56)
    require((page, file_align) == (4096, 512) and headers % file_align == 0 and
            start+opt+count*40 <= headers <= len(pe) and image_size % page == 0, "invalid mapped PE geometry")
    mapped, spans, found = [], [], {}
    for i in range(count):
        p = start + opt + i*40
        name = bytes(pe[p:p+8]).rstrip(b"\0")
        length, rva, size, at = struct.unpack_from("<IIII", pe, p+8)
        flags = integer(pe, p+36, 4)
        require(name not in found and at+size <= len(pe), "duplicate or out-of-range PE section")
        if size:
            require(at >= headers and at % file_align == size % file_align == 0 and
                    all(at+size <= a or b <= at for a,b in spans), "overlapping or unaligned raw PE sections")
            spans.append((at, at+size))
        # Include raw padding in the checked mapped extent, rounded to the VM page.
        end = rva + ((max(size, length) + page - 1) // page) * page
        require(rva % page == 0 and headers <= rva < end <= image_size and
                all(end <= a or b <= rva for a, b in mapped), "overlapping or invalid mapped PE sections")
        mapped.append((rva, end))
        if name in (b".linux", b".initrd", b".cmdline", b".osrel", b".uname"):
            require(0 < length <= size, "invalid embedded boot payload")
        found[name] = pe[at:at+min(length, size)]
        if name == b".text":
            require(length <= size and rva <= entry < rva+length and
                    (rva, length, flags, sha256(found[name])) == EFI_TEXT and
                    not any(pe[at+length:at+size]), "unapproved firmware entry code")
        else:
            require(not flags & 0x20000000, "unexpected executable firmware section")
    require(b".text" in found, "missing firmware entry code")
    return found


def inspect(path, pins):
    """A single independent streaming read of the final disk. No firmware or guest calls."""
    with opened(path) as f:
        size = os.fstat(f.fileno()).st_size
        require(size == pins["disk_bytes"] and size % 512 == 0 and (129 << 20) < size <= 33 << 30, "wrong disk length")
        prefix = f.read(34*512)
        mbr = prefix[:512]
        require(mbr[510:] == b"\x55\xaa" and mbr[450] == 0xee and integer(mbr,454,4) == 1
                and integer(mbr,458,4) == size//512-1 and not any(mbr[462:510]), "invalid protective MBR")
        table = prefix[2*512:]
        last = size//512-1
        (es, ee), (rs, re) = gpt(prefix[512:1024], table, 1, last, 2)
        require((ee-es+1)*512 == 128 << 20, "unexpected EFI partition length")
        gap = f.read((es-34)*512)
        require(not any(gap), "unexpected hidden pre-partition data")
        esp = f.read((ee-es+1)*512)
        require(sha256(esp) == pins["esp_sha256"], "EFI partition differs")
        uki = fat_uki(memoryview(esp), es)
        require(sha256(uki) == pins["uki_sha256"], "UEFI fallback file differs")
        s = sections(uki)
        require(sha256(s[b".linux"]) == pins["kernel_sha256"] and sha256(s[b".initrd"]) == pins["initramfs_sha256"]
                and s[b".cmdline"] == CMDLINE.encode() and s[b".uname"] == LINUX_VERSION.encode()
                and s[b".osrel"] == OSREL.encode() and b".profile" not in s, "embedded UKI policy/payload differs")
        whole, part = hashlib.sha256(), hashlib.sha256()
        for data in (prefix, gap, esp):
            whole.update(data)
        remaining = pins["root_size"]
        require(96 <= remaining <= (re-rs+1)*512 < remaining+512, "wrong root extent")
        hdr = f.read(96)
        require(hdr[:4] == b"hsqs" and integer(hdr,40,8) == remaining, "invalid embedded SquashFS")
        whole.update(hdr); part.update(hdr); remaining -= len(hdr)
        while remaining:
            chunk = f.read(min(4 << 20, remaining))
            require(bool(chunk), "truncated root")
            whole.update(chunk); part.update(chunk); remaining -= len(chunk)
        require(part.hexdigest() == pins["root_sha256"], "embedded root differs")
        pad = f.read((-pins["root_size"]) % 512)
        require(not any(pad), "nonzero root sector padding")
        end = f.read(33*512)
        require(not f.read(1) and end[:-512] == table and gpt(end[-512:], end[:-512], last, 1, last-32)
                == [(es,ee),(rs,re)], "backup GPT differs")
        whole.update(pad); whole.update(end)
        require(whole.hexdigest() == pins["disk_sha256"], "disk SHA-256 differs")
    return {"disk_sha256": whole.hexdigest(), "root_sha256": part.hexdigest(), "efi_path": "/EFI/BOOT/BOOTAA64.EFI",
            "uki_sha256": sha256(uki), "kernel_sha256": pins["kernel_sha256"], "initramfs_sha256": pins["initramfs_sha256"],
            "root_partition_guid": PARTS[1][2], "boot_observed": False, "phase3_exit_eligible": False}
