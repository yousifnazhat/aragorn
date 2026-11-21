"""Measure the handle portion of a stopped Pi exposure walk; never claim a Pi-visible tree.

The owner retains the gate stop, generation, worker root and namespace. Only
fixed, verified proc magic links are resolved, as O_PATH; no directory in the
worker tree is enumerated and no file or device contents are read.
"""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import stat
import time

from . import pi_core_stopped_mask_view as kernel
from .materialization import _TARGET_NAME
from .pi_core_confined_launch import _ADMITTED


SCHEMA = "aragorn/pi-core-stopped-worker-spine/v1"
_VERSIONS = _ADMITTED / ".aragorn-versions"


def _path(admitted):
    kernel._require(isinstance(admitted, Path) and admitted.anchor == "/" and len(str(admitted)) <= 4096
                    and admitted.parent.parent == _VERSIONS and _TARGET_NAME.fullmatch(admitted.parent.name)
                    and re.fullmatch(r"[0-9a-f]{64}-[0-9a-f]{64}", admitted.name),
                    "expected the owned absolute admitted bundle version directory")
    return admitted


def _pins(stack, view, admitted, deadline):
    # Open only the three named descriptor references even if the enumerated
    # table is hostile. Never access the underlying device for reading.
    pid, proc = view._roles["worker"]
    mount = view._mount
    held = {name:kernel._proc_child(stack, proc, name, os.O_RDONLY | os.O_DIRECTORY, mount)
            for name in ("task", "fd")}
    def census():
        tasks = kernel._names(held["task"], deadline, 1)
        numbers = kernel._names(held["fd"], deadline, 3)
        kernel._require(tasks == [str(pid)] and numbers == ["0", "1", "2"],
                        "unexpected kernel task or open descriptor set")
        return [int(n) for n in tasks], [int(n) for n in numbers]
    tasks, fds = census()
    root = kernel._magic(stack, proc, "root", os.O_PATH | os.O_DIRECTORY, mount)
    cwd = kernel._magic(stack, proc, "cwd", os.O_PATH | os.O_DIRECTORY, mount)
    held.update(root=root, cwd=cwd)
    current = root
    for i, part in enumerate(admitted.parts[1:]):
        current = kernel._pin(stack, current, part, directory=True)
        held["component-" + str(i)] = current
    held["named"] = current
    for n in fds:
        held[str(n)] = kernel._magic(stack, held["fd"], str(n), os.O_PATH, mount)
    kernel._require(census() == (tasks, fds), "kernel handle census changed while opening")
    return held, tasks, fds


def _stats(held):
    return {name: kernel._stat(fd) for name, fd in held.items()}


def _sample(stack, view, admitted, deadline, originals=None):
    ctx = view.worker_context()
    pid, proc = view._roles["worker"]
    held, tasks, fds = _pins(stack, view, admitted, deadline)
    snap = _stats(held)
    if originals is not None:
        kernel._require(snap == _stats(originals), "held and freshly resolved worker objects differ")
    ticks, _, states, threads, creds = kernel._parse_subject(
        kernel._read(proc, "stat", 8192, view._mount, deadline),
        kernel._read(proc, "status", 65536, view._mount, deadline), pid)
    kernel._limited(creds)
    kernel._require(threads == 1 and states[0] == states[1] and states[0] in ("T", "t")
                    and ticks == view.worker["start_ticks"] and all(ctx[k] == v for k,v in creds.items()),
                    "not the same stopped singleton or credential context")
    root, cwd = snap["root"], snap["cwd"]
    kernel._require(root == ctx["root"] == kernel._stat(view.root_fd) and stat.S_ISDIR(root["mode"])
                    and stat.S_ISDIR(cwd["mode"]) and cwd == snap["named"]
                    and (cwd["dev"], cwd["ino"]) != (root["dev"], root["ino"]),
                    "process root or admitted cwd differs from the held exact path")
    stdio = {str(n):snap[str(n)] for n in fds}
    kernel._require(all(stat.S_ISCHR(s["mode"]) and s["rdev"] == "1:3" for s in stdio.values()),
                    "standard descriptor is not a null character device")
    kernel._require(view.worker_context() == ctx, "worker context changed around kernel census")
    kernel._check(deadline)
    frame = dict(pid=pid, start_ticks=ticks, mount_namespace=ctx["mount_namespace"], state=states[0],
                 task_ids=tasks, fd_numbers=fds)
    return held, snap, frame, dict(root=root, cwd=cwd, named_cwd=snap["named"], fds=stdio)


@contextmanager
def hold_worker_spine(view, *, admitted_path, deadline):
    """Bracket the existing denial probe. finish() must run once, before the view is closed."""
    admitted = _path(admitted_path)
    kernel._require(type(view) is kernel._View and deadline == view._deadline, "foreign or extended held mask view")
    view._guard()
    with ExitStack() as stack:
        start = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        original, original_stats, before, objects = _sample(stack, view, admitted, deadline)
        active, attempted, ok = True, False, False

        def finish():
            nonlocal attempted, ok
            kernel._require(active and not attempted, "worker handle census is spent")
            attempted = True
            view._guard()
            with ExitStack() as edge:
                _, current, after, final_objects = _sample(edge, view, admitted, deadline, original)
                kernel._require(current == original_stats and before == after and objects == final_objects,
                                "worker handles, version path or stopped generation changed")
            end = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            kernel._require(0 < start < end <= start + 5_000_000_000, "handle census exceeded stopped-view window")
            kernel._check(deadline)
            ok = True
            return dict(schema=SCHEMA, worker=view.worker, admitted_path=str(admitted),
                        opened_boottime_ns=start, closed_boottime_ns=end, before=before, after=after,
                        objects={"before":objects, "after":final_objects})

        try:
            yield finish
            kernel._require(ok, "worker handle census not completed")
            view._guard()
        finally:
            active = False
