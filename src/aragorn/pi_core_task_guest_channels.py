"""Manager-owned one-shot channels for the fixed task guest."""
from contextlib import ExitStack, contextmanager
import os
import socket
import stat
import sys

from .pi_core_identity_handoff import validate_deadline


VIEW = "aragorn-pi-task-view"
OWNER = "aragorn-pi-task-owner"
ENDPOINTS = ((VIEW+"/tasks/control.sock", socket.SOCK_STREAM, "pi"),
             (VIEW+"/tasks/service.sock", socket.SOCK_STREAM, "pi"),
             (OWNER+"/handoff.sock", socket.SOCK_SEQPACKET, "service"),
             (OWNER+"/witness.sock", socket.SOCK_STREAM, "service"))
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _need(ok, why):
    if not ok:
        raise ValueError("task guest channels: " + why)


def node_id(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def remove_owned(parent, name, expected, *, directory):
    _need(node_id(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected, "replaced entry; cleanup held")
    (os.rmdir if directory else os.unlink)(name, dir_fd=parent)


def require_groups(pi_gid, service_gid):
    _need(all(type(g) is int and 0 < g < 2**31 for g in (pi_gid, service_gid)) and
          pi_gid != service_gid, "distinct nominated nonroot groups required")


@contextmanager
def hold_task_namespace(*, deadline, guard):
    """Called by a separately authorized guest owner, never by installation or boot.

    Bind sources exist at mode 0700 before either DynamicUser unit is started.
    The owner calls publish once, after independently identifying both stopped roles.
    Only the two Pi names are in the view bind. Caller owns the original
    deadline, one-shot claim, verified peer handoff and retirement before exit.
    The prerequisite guard must explicitly return True; it cannot issue task authority.
    No existing directory is adopted or recursively removed.
    """
    _need(callable(guard), "missing custody guard")
    validate_deadline(deadline)
    _need(sys.platform == "linux" and os.geteuid() == os.getegid() == 0, "guest root required")
    def authorized():
        _need(guard() is True, "owner prerequisite unavailable")
    authorized()
    with ExitStack() as stack:
        def hold(fd):
            stack.callback(os.close, fd)
            return fd
        run = hold(os.open("/run", _DIR))
        run_meta = os.fstat(run)
        _need(run_meta.st_uid == run_meta.st_gid == 0 and not run_meta.st_mode & 0o022, "unsafe /run")
        dirs, pinned, listeners = {"":run}, [], {}
        def opened(parent, name, fd, isdir):
            info = os.fstat(fd)
            typ = stat.S_ISDIR if isdir else stat.S_ISSOCK
            _need(typ(info.st_mode) and info.st_uid == 0 and (isdir or info.st_nlink == 1),
                  "unexpected newly created object; cleanup held")
            ident = node_id(info)
            stack.callback(remove_owned, parent, name, ident, directory=isdir)
            return ident
        nodes = {}
        for path in (OWNER, VIEW, VIEW+"/tasks"):
            parent_name, _, name = path.rpartition("/")
            parent = dirs[parent_name]
            os.mkdir(name, mode=0o700, dir_fd=parent)
            fd = hold(os.open(name, _DIR, dir_fd=parent))
            nodes[path] = (parent, name, fd, opened(parent, name, fd, True))
            dirs[path] = fd
        active, spent = True, False
        def publish(pi_gid, service_gid):
            nonlocal spent
            _need(active and not spent, "already spent or closed")
            spent = True
            require_groups(pi_gid, service_gid)
            validate_deadline(deadline)
            authorized()
            for path, kind, role in ENDPOINTS:
                parent_name, _, name = path.rpartition("/")
                parent, gid = dirs[parent_name], pi_gid if role == "pi" else service_gid
                s = stack.enter_context(socket.socket(socket.AF_UNIX, kind | socket.SOCK_CLOEXEC))
                if kind == socket.SOCK_SEQPACKET:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                s.bind(f"/proc/self/fd/{parent}/{name}")
                fd = hold(os.open(name, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent))
                pinned.append((parent, name, fd, opened(parent, name, fd, False), 0o660, gid))
                os.chown(name, 0, gid, dir_fd=parent, follow_symlinks=False)
                os.chmod(name, 0o660, dir_fd=parent)
                s.listen(1)
                listeners[name] = s
            for path, mode, gid in ((VIEW+"/tasks",0o710,pi_gid), (OWNER,0o750,service_gid), (VIEW,0o755,0)):
                fd = dirs[path]
                os.fchown(fd, 0, gid)
                os.fchmod(fd, mode)
                pinned.append((*nodes[path], mode, gid))
            custody()
            return dict(listeners), custody
        def custody():
            _need(active and spent, "outside published endpoint lifetime")
            validate_deadline(deadline)
            authorized()
            _need(node_id(os.stat("/run", follow_symlinks=False)) == node_id(run_meta), "replaced /run")
            for parent, name, fd, ident, mode, gid in pinned:
                before, named = os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False)
                _need(node_id(before) == ident == node_id(named) and named.st_uid == 0 and named.st_gid == gid
                      and stat.S_IMODE(named.st_mode) == mode and (ident[2] == stat.S_IFDIR or named.st_nlink == 1),
                      "named endpoint or access rights changed")
            for path, expected in ((VIEW,{"tasks"}), (VIEW+"/tasks",{"control.sock","service.sock"}),
                                   (OWNER,{"handoff.sock","witness.sock"})):
                _need(set(os.listdir(dirs[path])) == expected, "foreign directory contents")
        try:
            yield publish
            if spent:
                custody()
        finally:
            active = False
