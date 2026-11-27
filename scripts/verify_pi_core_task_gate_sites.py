"""Read-only instruction-site verification for one retained ARM64 task gate."""
import struct

from scripts import build_pi_core_linux as elf


GATE = "2a54fd7f91e1349ceecad3ac27ec6d111230c1913f4030ae91a67fa4210cab7a"
SVC = 0xd4000001
# mov w1,#SIGSTOP; zero x2,x3,x4; mov w8,#__NR_kill; svc #0
SELF_STOP = (0x52800261,0xaa1f03e2,0xaa1f03e3,0xaa1f03e4,0x52801028,SVC)
EXEC = (0x52801ba8,SVC)  # mov w8,#__NR_execve; svc #0


def _need(condition, why):
    if not condition:
        raise ValueError(why)


def verify_gate_sites(raw, catalog):
    """Authenticate the entire ET_EXEC image before interpreting any instruction as a site."""
    _need(type(raw) is bytes and len(raw) == 4176 and elf.sha256(raw) == GATE,"different task gate bytes")
    elf.require_static_arm64_elf(raw)
    _need(struct.unpack_from("<H",raw,16)[0] == 2, "not the fixed ET_EXEC gate")
    entry, phoff = struct.unpack_from("<QQ",raw,24)
    entsize, count = struct.unpack_from("<HH",raw,54)
    loads = [struct.unpack_from("<IIQQQQQQ",raw,phoff+i*entsize) for i in range(count)]
    executable = [row for row in loads if row[0]==1 and row[1]&1]
    _need(len(executable)==1 and executable[0][1]==5, "ambiguous executable task segment")
    _,_,offset,base,_,size,memsize,align = executable[0]
    _need(entry==base and size==memsize and size%4==0 and offset+size<=len(raw), "wrong task segment layout")
    words = struct.unpack_from(f"<{size//4}I",raw,offset)
    def ends(pattern):
        return [i+len(pattern) for i in range(len(words)-len(pattern)+1) if words[i:i+len(pattern)] == pattern]
    stops, execs = ends(SELF_STOP), ends(EXEC)
    _need(len(stops)==2 and len(execs)==1, "ambiguous task stop or execve sites")
    first, final = stops
    after_exec, call = execs[0], first+2
    # Both successful stops fall through; failures branch past execve to refuse.
    for i in stops:
        cbnz = words[i]
        _need((cbnz & 0xff00001f) == 0xb5000000 and i + ((cbnz>>5)&0x7ffff) == after_exec, "wrong kill failure branch")
    bl = words[call]
    _need(words[first-len(SELF_STOP)-1]==0xaa0003f3 and words[first+1]==words[call+1]==0xaa1303e0
          and bl>>26==0b100101 and call+2==final-len(SELF_STOP), "wrong PID preservation or fixed-view call")
    target = call+(bl & 0x3ffffff)
    _need(first<call<final<after_exec<target<len(words), "wrong forward fixed-view branch")
    def pc(i): return base+4*i
    found = dict(schema="aragorn/fixed-task-gate-stop-sites/v1",gate_sha256=GATE,
                 rx_segment=dict(offset=offset,vaddr=base,size=size,align=align),
                 first_return_pc=pc(first),fixed_view_call_pc=pc(call),fixed_view_entry=pc(target),
                 final_return_pc=pc(final),execve_svc_pc=pc(after_exec-1))
    _need(elf.canonical(found)==elf.canonical(catalog), "different task gate site catalog")
    return found
