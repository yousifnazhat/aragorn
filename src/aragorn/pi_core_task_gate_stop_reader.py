"""Read-only site observation on the originally held static task worker."""
import os
import re
from types import MappingProxyType

from . import pi_core_task_owner_roles as roles
from .pi_core_state_admission import _need
from .pi_core_task_observer_binding import _StaticWorker


# File coordinates in the pinned, non-PIE ARM64 gate; verified against the two svc instructions.
RX_VADDR, RX_OFFSET, RX_SIZE = 0x210344, 0x344, 0x810
POST_SVC_PC = MappingProxyType({"first":0x210524, "final":0x21054c})
_WORD = re.compile(rb"0x(?:0|[1-9a-f][0-9a-f]{0,15})")
_MAP = re.compile(rb"([0-9a-f]{1,16})-([0-9a-f]{1,16}) ([r-][w-][x-][ps]) ([0-9a-f]{1,16}) "
                  rb"([0-9a-f]{2,8}):([0-9a-f]{2,8}) ([0-9]{1,20})(?: +(.*))?")


def _site(raw, pid):
    fields = raw.removesuffix(b"\n").split(b" ")
    _need(raw.endswith(b"\n") and ((fields[0]==b"-1" and len(fields)==3)
          or (fields[0]==b"129" and len(fields)==9)) and all(_WORD.fullmatch(s) for s in fields[1:]),
          "unrecognized stopped syscall record")
    values = [int(s,16) for s in fields[1:]]
    if fields[0]==b"129":
        # x5 is not supplied by the gate's five-argument syscall wrapper.
        _need(values[:5] == [pid,19,0,0,0], "different gate syscall arguments")
    # arm64 may forget syscallno before taking a group stop. Neither ABI row proves the signal sender.
    sp, pc = values[-2:]
    _need(sp > 0 and sp % 16 == 0 and pc in POST_SVC_PC.values(), "not at a reviewed static gate stop site")
    return next(k for k,v in POST_SVC_PC.items() if v==pc), pc, int(fields[0])


def _mapping(raw, pc, st, page):
    _need(page in (4096,16384,65536), "unsupported ARM64 page size")
    lines = raw.splitlines()
    _need(raw.endswith(b"\n") and 0 < len(lines) <= 128, "invalid static gate map inventory")
    previous, found = 0, None
    dev = os.major(st.st_dev),os.minor(st.st_dev)
    for line in lines:
        row = _MAP.fullmatch(line)
        _need(row, "malformed static gate map inventory")
        lo,hi,offset,major,minor = (int(row[n],16) for n in (1,2,4,5,6))
        _need(previous <= lo < hi and not (lo%page or hi%page or offset%page), "unordered or unaligned task maps")
        previous = hi
        if (major,minor)!=dev or int(row[7])!=st.st_ino:
            _need(not lo <= pc < hi, "gate stop PC mapped to a different object")
            continue
        _need(b"w" not in row[3], "writable mapping of the static gate")
        if b"x" not in row[3]: continue
        _need(found is None and row[3]==b"r-xp" and (row[8] or b"").startswith(b"/")
              and not row[8].endswith(b" (deleted)") and lo==RX_VADDR//page*page
              and hi==(RX_VADDR+RX_SIZE+page-1)//page*page and offset==RX_OFFSET//page*page
              and lo <= pc < hi and offset+pc-lo == RX_OFFSET+pc-RX_VADDR,
              "unexpected executable mapping of the static gate")
        found = line
    _need(found is not None, "missing original static gate executable mapping")
    return found


def read_gate_stop(subject, *, phase, deadline):
    """Classify only a stable kernel PC on this held generation, never a caller-provided label."""
    _need(type(subject) is _StaticWorker and phase in ("stopped","traced-gate"), "original stopped worker required")
    subject.guard(phase=phase,deadline=deadline)
    gate = str(roles.sources.GATE_PATH)
    fd = subject.files[gate]
    st = os.fstat(fd)
    identity = roles.sources._file_identity(st)
    worker, clock = subject.worker, subject.clock
    def read(name, maximum):
        return roles.kernel._read(subject._proc,name,maximum,subject._mount,deadline)
    syscall = read("syscall",256)
    maps = read("maps",64<<10)
    site,pc,nr = _site(syscall,worker["pid"])
    row = _mapping(maps,pc,st,os.sysconf("SC_PAGE_SIZE"))
    _need(read("maps",64<<10)==maps and read("syscall",256)==syscall, "gate stop changed during readback")
    subject.guard(phase=phase,deadline=deadline)
    _need(roles.sources._file_identity(os.fstat(fd)) == identity, "gate file identity changed during readback")
    return dict(site=site,instruction_pointer=pc,file_offset=RX_OFFSET+pc-RX_VADDR,syscall_number=nr,phase=phase,
                worker=worker,clock=clock,gate_digest=roles._WORKER_PINS[gate][0],gate_identity=identity,
                syscall_raw_hex=syscall.hex(),mapping_raw_hex=(row+b"\n").hex())
