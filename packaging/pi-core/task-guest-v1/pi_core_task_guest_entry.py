"""One-shot post-exec fixed task role. No activation, ticket creation, retries or cleanup of foreign resources."""
from contextlib import ExitStack
import hashlib
import math
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import time

from . import pi_core_identity_handoff as channel, pi_core_service_entry as protected
from . import pi_core_task_guest_binding as mode, pi_core_task_service as task, runtime_action_broker as wire
from .native_phase3_workload_json_sum_contract import validate_request
from .oci_worker_protocol import canonical_digest


_OWNER = Path("/run/aragorn-pi-task-owner")
_WRAPPER = "/opt/aragorn/bin/pi-fixed-task.py"
_RELEASE = "aragorn/pi-core-task-owner-release/v1"
_PACKET = "aragorn/pi-core-task-owner-packet/v1"
_PACKET_MAX = 32768


def _need(value):
    if not value:
        raise ValueError("FIXED_TASK_GUEST_BINDING_REFUSED")


def _nonce(value):
    _need(type(value) is str and re.fullmatch("[0-9a-f]{64}", value))
    return value


def _local():
    return os.getpid(), os.geteuid(), os.getegid()


def _wrapper_pin():
    fd = os.open(_WRAPPER, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(fd)
        _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == st.st_gid == 0
              and stat.S_IMODE(st.st_mode) == 0o555 and 0 < st.st_size <= 1024*1024)
        raw = f.read(st.st_size+1)
        def identity(s):
            return s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_size, s.st_nlink, s.st_ctime_ns, s.st_mtime_ns
        _need(len(raw) == st.st_size and identity(st) == identity(os.fstat(fd)) ==
              identity(os.stat(_WRAPPER, follow_symlinks=False)))
        return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_release(p, *, owner, service, service_pin, outer_deadline):
    _need(type(p) is dict and set(p) == {"schema","ticket","ticket_pin","nomination","nomination_pin","deadline_ns"}
          and p["schema"] == _RELEASE)
    t, n = p["ticket"], p["nomination"]
    _need(type(t) is dict and type(n) is dict and t.get("schema") == "aragorn/pi-core-task-ticket/v1"
          and n.get("schema") == "aragorn/pi-task-guest-nomination/v1"
          and canonical_digest(t) == p["ticket_pin"] and canonical_digest(n) == p["nomination_pin"]
          and p["nomination_pin"] == t.get("environment_digest")
          and n.get("request_digest") == canonical_digest(t["request"]) and n.get("clock") == t["clock"]
          and n.get("service_code", {}).get("wrapper_digest") == service_pin and owner[1:] == (0, 0)
          and min(service[1:]) > 0 and list(owner) == t["manager_peer"] and list(service) == t["service_peer"]
          and all(n[k] == t[k] for k in ("service_peer", "manager_peer", "pi_peer")))
    validate_request(t["request"])
    ns = p["deadline_ns"]
    _need(type(ns) is int and 0 < ns < 2**63 and time.monotonic_ns() < ns)
    deadline = math.nextafter(ns/1e9, 0.)
    _need(time.monotonic() < deadline <= outer_deadline)
    return deadline


def _fd_id(fd):
    s = os.fstat(fd)
    return [s.st_dev, s.st_ino]


def _service_address(sock):
    address = sock.getsockname()
    # The transferred stream retains its manager-side bind address, not a pathname in the service view.
    match = re.fullmatch(r"/proc/self/fd/([1-9][0-9]{0,9})/service\.sock", address) if type(address) is str else None
    _need(match and 3 <= int(match[1]) < 2**31)
    return address, int(match[1])


def check_service_listener(pi, listener, t):
    address, parent = _service_address(listener)
    _need(_service_address(pi)[0] == address)
    for sock, listening in ((listener,1),(pi,0)):
        _need(sock.getsockopt(socket.SOL_SOCKET,channel._DOMAIN) == socket.AF_UNIX and
              sock.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) == socket.SOCK_STREAM and
              sock.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN) == listening)
    # Only the owner interprets its /proc/self/fd. Its namespace custody guard additionally
    # pins the initially created nodes against unlink/rebind, not just their printable names.
    path = Path("/run/aragorn-pi-task-view/tasks")
    gid = t["pi_peer"][2]
    for held, named, kind in (
            (os.fstat(parent),os.stat(path, follow_symlinks=False),stat.S_IFDIR|0o710),
            (os.stat("service.sock",dir_fd=parent,follow_symlinks=False),
             os.stat(path/"service.sock",follow_symlinks=False),stat.S_IFSOCK|0o660)):
        _need(os.path.samestat(held,named) and all(s.st_mode == kind and s.st_uid == 0 and s.st_gid == gid
              and (stat.S_ISDIR(kind) or s.st_nlink == 1) for s in (held,named)))


def check_pi(sock, t, nominated_id):
    _service_address(sock)
    _need(sock.family == socket.AF_UNIX and sock.type == socket.SOCK_STREAM
          and not sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
          and tuple(wire._peer_credentials(sock)) == tuple(t["pi_peer"])
          and canonical_digest(_fd_id(sock.fileno())) == canonical_digest(nominated_id))


def _packet(kind, nonce, pin, **fields):
    return dict(schema=_PACKET,kind=kind,nonce=_nonce(nonce),ticket_pin=pin,**fields)


def _send(control, doc, deadline, fd=None):
    channel.send_authenticated_packet(control, doc, deadline, rights=() if fd is None else (fd,), max_bytes=_PACKET_MAX)


def _recv(control, peer, deadline, *, right=False):
    return channel.receive_authenticated_packet(control, peer, deadline, expected_rights=int(right),max_bytes=_PACKET_MAX)


def _owner_guard(control, t, pin, guard):
    _need(_local() == tuple(t["manager_peer"]) and _local()[1:] == (0,0)
          and tuple(wire._peer_credentials(control)) == tuple(t["service_peer"])
          and canonical_digest(t) == pin and callable(guard) and guard() == t["environment_digest"])


def send_release(control, *, ticket, ticket_pin, nomination, nomination_pin, service_listener, copy_directory_fd, deadline, guard):
    """Root owner already holds the single-use claim, active mode, guest identity and both accepted channel generations."""
    _owner_guard(control,ticket,ticket_pin,guard)
    channel.validate_deadline(deadline)
    service = tuple(ticket["service_peer"])
    hello, _ = _recv(control, service, deadline)
    nonce = _nonce(hello.get("nonce"))
    _need(hello == _packet("HELLO",nonce,None))
    # Independent current readback before lending even the single accepted descriptor.
    mode.observe_task_guest(ticket,nomination=nomination,nomination_pin=nomination_pin,deadline=deadline)
    p = dict(schema=_RELEASE,ticket=ticket,ticket_pin=ticket_pin,nomination=nomination,nomination_pin=nomination_pin,
             deadline_ns=math.floor(math.nextafter(deadline,0.) * 1e9))
    validate_release(p,owner=_local(),service=service,service_pin=nomination["service_code"]["wrapper_digest"],outer_deadline=deadline)
    _need(("copy" in ticket) == (type(copy_directory_fd) is int and copy_directory_fd >= 0))
    if "copy" in ticket:
        _need(stat.S_ISDIR(os.fstat(copy_directory_fd).st_mode))
    _service_address(service_listener)
    channel._timeout(service_listener,deadline)
    # Only this accept can supply the released FD. A stream from some older listener
    # cannot be laundered by supplying an identical /proc/self/fd/N path string.
    with service_listener.accept()[0] as pi:
        desc_id = _fd_id(pi.fileno())
        check_pi(pi,ticket,desc_id)
        _owner_guard(control,ticket,ticket_pin,guard)
        check_service_listener(pi,service_listener,ticket)
        _send(control,_packet("RELEASE",nonce,ticket_pin,release=p,pi_inode=desc_id),deadline,pi.fileno())
    if "copy" in ticket:
        _send(control,_packet("COPY_DIRECTORY",nonce,ticket_pin),deadline,copy_directory_fd)


def answer_guard(control, *, ticket, ticket_pin, nomination, nomination_pin, deadline, guard):
    """May be called only by the independently holding manager. Return retirement challenge, or None."""
    _owner_guard(control,ticket,ticket_pin,guard)
    q,_ = _recv(control,tuple(ticket["service_peer"]),deadline)
    nonce = _nonce(q.get("nonce"))
    if q == _packet("RETIRE_READY",nonce,ticket_pin):
        return nonce
    _need(q == _packet("OBSERVE",nonce,ticket_pin))
    found = mode.observe_task_guest(ticket,nomination=nomination,nomination_pin=nomination_pin,deadline=deadline)
    observed = dict(found,service_show=found["service_show"].decode("ascii"),sensor_show=found["sensor_show"].decode("ascii"))
    _owner_guard(control,ticket,ticket_pin,guard)
    _send(control,_packet("OBSERVED",nonce,ticket_pin,observation=observed),deadline)


def retire_service(control, *, ticket, ticket_pin, deadline, guard, retire_nonce):
    """Caller must positively verify retention/retirement prerequisites first. No timeout implies success."""
    _owner_guard(control,ticket,ticket_pin,guard)
    _send(control,_packet("RETIRE",retire_nonce,ticket_pin),deadline)


def _observed(control, owner, p, deadline):
    nonce = secrets.token_hex(32)
    _send(control,_packet("OBSERVE",nonce,p["ticket_pin"]),deadline)
    answer,_ = _recv(control,owner,deadline)
    found = answer.get("observation")
    _need(type(found) is dict and set(found) == {"service_show","sensor_show","clock","installed_service_pin"}
          and answer == _packet("OBSERVED",nonce,p["ticket_pin"],observation=found)
          and type(found["service_show"]) is type(found["sensor_show"]) is str)
    return mode.bound_environment(p["ticket"],nomination=p["nomination"],nomination_pin=p["nomination_pin"],
        **dict(found,service_show=found["service_show"].encode("ascii"),sensor_show=found["sensor_show"].encode("ascii")))


def run(*, loader, deadline):
    protected._flags()
    me = _local()
    _need(min(me[1:]) > 0 and os.getresuid() == (me[1],)*3 and os.getresgid() == (me[2],)*3 and not os.getgroups())
    wrapper = _wrapper_pin()
    loader.snapshot()
    # Root learns this DynamicUser generation, arms deadlines and listeners, then resumes once.
    os.kill(me[0], signal.SIGSTOP)
    channel.validate_deadline(deadline)
    options = dict(parent_identity=dict(uid=0,gid=me[2],mode=0o750),socket_identity=(0,me[2]))
    with ExitStack() as stack:
        hand = stack.enter_context(protected._connect(_OWNER/"handoff.sock", socket.SOCK_SEQPACKET, (None,0,0), deadline, **options))
        owner = tuple(wire._peer_credentials(hand))
        nonce = secrets.token_hex(32)
        _send(hand,_packet("HELLO",nonce,None),deadline)
        release, fds = _recv(hand,owner,deadline,right=True)
        stack.callback(os.close,fds[0])
        p = release.get("release")
        _need(type(p) is dict and "ticket_pin" in p and release == _packet("RELEASE",nonce,p["ticket_pin"],
              release=p, pi_inode=_fd_id(fds[0])))
        deadline = validate_release(p,owner=owner,service=me,service_pin=wrapper,outer_deadline=deadline)
        ticket, pin = p["ticket"], p["ticket_pin"]
        pi = stack.enter_context(socket.fromfd(fds[0],socket.AF_UNIX,socket.SOCK_STREAM))
        # fromfd's family/type arguments are metadata, not independent kernel readback.
        _need(pi.getsockopt(socket.SOL_SOCKET,channel._DOMAIN) == socket.AF_UNIX
              and pi.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) == socket.SOCK_STREAM)
        check_pi(pi,ticket,release["pi_inode"])
        directory = None
        if "copy" in ticket:
            doc, fds = _recv(hand,owner,deadline,right=True)
            directory = fds[0]
            stack.callback(os.close,directory)
            _need(doc == _packet("COPY_DIRECTORY",nonce,pin) and stat.S_ISDIR(os.fstat(directory).st_mode))
        witness = stack.enter_context(protected._connect(_OWNER/"witness.sock",socket.SOCK_STREAM,owner,deadline,**options))
        def held():
            loader.snapshot()
            return _observed(hand,owner,p,deadline)
        task.serve_one(ticket,pin,pi=pi,witness=witness,guard=held,deadline=deadline,copy_directory_fd=directory)
        retirement = secrets.token_hex(32)
        _send(hand,_packet("RETIRE_READY",retirement,pin),deadline)
        ack,_ = _recv(hand,owner,deadline)
        _need(ack == _packet("RETIRE",retirement,pin))
        loader.snapshot()
