"""Cross-build only the three batch-38 systemd clients. Never run a target.

Run from the checkout with python -m scripts.build_pi_core_host_clients.
The authenticated development inputs are prepared separately. No fetching,
package installation, Meson fallback, host service, or guest boot here.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import time

from scripts.build_pi_core_linux import ROOT, regular_bytes, require, sha256
from scripts import prepare_pi_core_host_tool_targets as source


INPUTS = ROOT / ".aragorn/host-preflight/build-b38"
BASE = ROOT / ".aragorn/host-preflight/build-b40"
PACK = ROOT / "packaging/pi-core/host-tools-b40"
WORK = BASE / "client-work"
SYSROOT = BASE / "sysroot-work/root"
TOOLBIN = BASE / "tools-work/sealed/bin"
TARGETS = source.TARGETS
TAG = "aragorn-coordinator-client"
MAX_SECONDS = {"configure": 600, "compile": 1800, "stage": 120}
EPOCH = "1776277973"  # 259.5-0ubuntu3 changelog
QUERY = PACK / "meson-bpf-version.py"
# This one real configure succeeded before Meson's ambiguous untyped CLI
# selector failed. Ninja ran zero actions. Preserve its logs and configure bytes.
CONFIGURE_ONLY = "ec81aebb4090abbec28061cc3bf0d2b5730a4e97264cfb84313d17f92b4fef17"
CONFIGURED_TREE = "1560fded49c02a69a956ca8f0bfaf7b922d80688163e346252304e6c99280394"
SOURCE_TREE = "3802659155837a90aeb0e7507273d36f64cd6c817776a8ac40aab053ae1beee4"
SELECTORS = tuple("./" + name + ":executable" for name in TARGETS)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save_new(path, raw):
    with path.open("xb") as f:
        f.write(raw)


def reserve(owned, closure):
    private_directory(owned)
    fingerprint = sha256(compact(closure))
    attempt = owned / fingerprint
    attempt.mkdir(mode=0o700, exist_ok=False)
    save_new(attempt / "inputs.json", compact(closure))
    return fingerprint, attempt


def private_directory(path):
    row = path.lstat()
    require(path.is_absolute() and path.resolve(strict=True) == path and stat.S_ISDIR(row.st_mode)
            and row.st_uid == os.geteuid() and row.st_mode & 0o077 == 0,
            f"private unlinked build directory required: {path}")


def target_file(sysroot, tools):
    # No exe_wrapper. This includes Meson feature probes, not just the clients.
    # cmd_array() is also used by shell/Python header generators in this release.
    # They split it on whitespace; reject ambiguous paths instead of miscompiling.
    for path in [sysroot, *tools.values()]:
        require(re.fullmatch(r"/[a-zA-Z0-9/_@.+-]+", str(path)) is not None,
                "unrepresentable path in cross toolchain")
    triple = "aarch64-linux-gnu"
    data = [f"--target={triple}", f"--sysroot={sysroot}", f"--gcc-toolchain={sysroot}/usr"]
    def arr(values):
        return "[" + ", ".join("'" + str(x) + "'" for x in values) + "]"
    pkgs = [sysroot / "usr/lib" / triple / "pkgconfig", sysroot / "usr/lib/pkgconfig",
            sysroot / "usr/share/pkgconfig"]
    return "\n".join([
        "[binaries]", "c = " + arr([tools["clang"], *data]),
        f"ar = '{tools['llvm-ar']}'", f"pkg-config = '{tools['pkg-config']}'",
        "bpftool = " + arr([tools["python3"], QUERY]),
        "[host_machine]", "system = 'linux'", "cpu_family = 'aarch64'", "cpu = 'aarch64'",
        "endian = 'little'", "[properties]", "needs_exe_wrapper = true",
        f"sys_root = '{sysroot}'", "pkg_config_libdir = " + arr(pkgs), "[built-in options]",
        "c_args = " + arr(["-O2", "-D_FORTIFY_SOURCE=3", "-fstack-protector-strong",
                           "-ffile-prefix-map=" + str(WORK) + "=/usr/src/aragorn"]),
        "c_link_args = " + arr([f"--ld-path={tools['ld.lld']}", "-Wl,-z,relro,-z,now",
                               "-Wl,--build-id=sha1"]), ""])


def options():
    return [row for row in regular_bytes(PACK / "ubuntu-client-options.txt", 8192).decode("ascii").splitlines()
            if row and not row.startswith("#")]


def audit_install_plan(build):
    plan = json.loads(regular_bytes(build / "meson-info/intro-install_plan.json", 8 << 20))
    selected = [(kind, Path(name), row) for kind, rows in plan.items() for name, row in rows.items()
                if row["tag"] == TAG]
    require(len(selected) == len(TARGETS) and
            {p for _, p, _ in selected} == {build / t for t in TARGETS},
            "unexpected target set for isolated install tag")
    for kind, p, row in selected:
        require(kind == "targets" and row["destination"] == "{bindir}/" + p.name and
                row["install_rpath"] is None and row["subproject"] is None,
                "non-client destination, RPATH or source selected by install tag")
    # The pinned upstream install hooks have no coordinator tag. In pinned
    # Meson, --tags filters scripts as well as files. Nothing installs hostwide.


def answer_query(request, directory, env, send, budget):
    end = time.monotonic() + min(45, budget)
    require(request == b"--version\n", "malformed or repeated host capability request")
    # This *parent* is outside Meson's sandbox. The sealed helper applies its
    # stricter no-fork/no-network/read-confined sandbox to the actual translator.
    # No value, option or path from the requesting child is forwarded.
    helper = TOOLBIN / "bpftool"
    log_dir = directory / "bpf-query"
    isolated = BASE / "tools-work/bpf-host-probe"
    private_directory(isolated.parent)
    for p in (isolated, isolated / "tmp"):
        p.mkdir(mode=0o700, exist_ok=True)
        private_directory(p)
    helper_env = dict(env, HOME=str(isolated), TMPDIR=str(isolated / "tmp"), XDG_CACHE_HOME=str(isolated))
    with (log_dir / "stdout").open("xb") as out, (log_dir / "stderr").open("xb") as err:
        probe = subprocess.Popen([str(helper), "--version"], cwd=isolated, env=helper_env,
                                 stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                 start_new_session=True, close_fds=True)
        try:
            probe.wait(timeout=max(0, end - time.monotonic()))
        except BaseException:
            if probe.poll() is None:
                os.killpg(probe.pid, signal.SIGKILL)
            probe.wait()
            raise
    raw = regular_bytes(log_dir / "stdout", 240)
    rc = probe.returncode if 0 <= probe.returncode <= 255 else 1
    reply = compact({"rc": rc, "stdout": base64.b64encode(raw).decode("ascii")}) + b"\n"
    require(len(reply) <= 512 and os.write(send, reply) == len(reply), "incomplete capability response")
    require(rc == 0 and raw, "real host capability probe failed; see bpf-query/stderr")


def wait_configure(proc, directory, env, pipes):
    end = time.monotonic() + MAX_SECONDS["configure"]
    used = False
    while proc.poll() is None:
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("configure deadline exceeded")
        if select.select([pipes["request"]], [], [], min(0.20, remaining))[0]:
            require(not used, "second bpftool capability request")
            used = True
            answer_query(os.read(pipes["request"], 512), directory, env, pipes["response"], remaining)
            if time.monotonic() >= end:
                raise TimeoutError("configure deadline exceeded during genuine capability query")
    require(proc.returncode != 0 or used, "configure skipped the genuine bpftool capability probe")
    require(not select.select([pipes["request"]], [], [], 0)[0], "extra bpftool capability request")
    return proc.returncode


def launch(phase, argv, directory, env, already_configured=None):
    # No implicit internet access even from build-system children. Writable
    # locations are the owned attempt (+ /dev/null); tools/sysroot are read-only.
    sandbox = ('(version 1)(allow default)(deny network*)(deny file-write*)'
               '(allow file-write* (subpath ' + json.dumps(str(directory)) + ') (literal "/dev/null"))'
               '(deny file-write* (subpath ' + json.dumps(str(directory / "source")) + '))')
    query = directory / "bpf-query"
    sandbox += ('(deny file-write* (subpath ' + json.dumps(str(query)) + '))'
                '(deny file-write* (subpath ' + json.dumps(str(directory / "configure-snapshot")) + '))'
                '(allow file-write-data (literal ' + json.dumps(str(query / "request")) + '))')
    if already_configured is not None:
        require(phase in ("compile", "stage") and already_configured == WORK / CONFIGURE_ONLY / "build",
                "unreviewed build-directory reuse")
        sandbox += '(allow file-write* (subpath ' + json.dumps(str(already_configured)) + '))'
    command = ["/usr/bin/sandbox-exec", "-p", sandbox, *map(str, argv)]
    log = directory / (phase + ".log")
    save_new(directory / (phase + ".argv.json"), compact(command))
    pipes = {}
    try:
        if phase == "configure":
            query.mkdir(mode=0o700)
            for name in ("request", "response"):
                path = query / name
                os.mkfifo(path, 0o600)
                pipes[name] = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
                row = os.fstat(pipes[name])
                require(stat.S_ISFIFO(row.st_mode) and row.st_nlink == 1 and os.path.samestat(row, path.lstat()),
                        "replaced capability FIFO")
        with log.open("xb", buffering=0) as output:
            proc = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                rc = (wait_configure(proc, directory, env, pipes) if phase == "configure"
                      else proc.wait(timeout=MAX_SECONDS[phase]))
            except BaseException:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
                raise
    finally:
        for name, fd in pipes.items():
            path = query / name
            if os.path.lexists(path) and os.path.samestat(os.fstat(fd), path.lstat()):
                path.unlink()
            os.close(fd)
    require(rc == 0, f"{phase} exited {rc}; retained {log}")


def reused_configure(old, closure, cross, attempt):
    from scripts.prepare_pi_core_host_build_tools import tree
    private_directory(old)
    require(old == WORK / CONFIGURE_ONLY, "unexpected configure predecessor")
    def verified(name, digest, limit):
        raw = regular_bytes(old / name, limit)
        require(sha256(raw) == digest, f"substituted predecessor: {name}")
        return raw
    prior = json.loads(verified("inputs.json", CONFIGURE_ONLY, 64 << 10))
    # Only the selector/driver changed. All consumed configure sources/tools,
    # machine, distro switches, helper code and sysroot must compare exactly.
    common = {k: v for k, v in closure.items() if k not in ("recipe", "reuse_configure", "selectors")}
    require(compact({k: v for k, v in prior.items() if k != "recipe"}) == compact(common),
            "predecessor configure inputs differ")
    verified("configure.argv.json", "8c46b4533a93d3974f6d16f6765bd22d8a72d0efe7e26cab0c16cf667ef11952", 64 << 10)
    verified("compile.log", "6df3106230ade9a45d763b07eeaff730fc363c8d1f82c359cd0311c13356c34a", 8192)
    verified("bpf-query/stdout", "f99bb52549d8473548ea5a784d7fa05960870d8cbefe83c383ec16fbe0f7736e", 240)
    require(regular_bytes(old / "target.ini", 8192) == cross.encode() and tree(old / "source") == SOURCE_TREE
            and tree(old / "build") == CONFIGURED_TREE, "altered configured source, commands or machine")
    # Retain the pristine state before Ninja writes objects to Meson's original
    # absolute build directory. Never modify the original failure/argv/log.
    retained = attempt / "configure-snapshot"
    shutil.copytree(old / "build", retained, symlinks=True)
    require(tree(retained) == CONFIGURED_TREE, "configuration snapshot differs")
    save_new(attempt / "configure-reuse.json", compact({"from": CONFIGURE_ONLY, "source_tree": SOURCE_TREE,
             "configured_tree": CONFIGURED_TREE, "selectors": list(SELECTORS)}))
    return old / "build"


def build():
    from scripts.prepare_pi_core_host_build_tools import verify_existing
    from scripts.prepare_pi_core_host_sysroot import verify
    require(sys.platform == "darwin" and platform.machine() == "arm64", "expected Darwin arm64 build host")
    private_directory(BASE)
    if not WORK.exists():
        WORK.mkdir(mode=0o700)
    private_directory(WORK)
    t = verify_existing()
    s = verify(SYSROOT)
    paths = {k: Path(v["path"]) for k, v in t["tools"].items()}
    for name in ("clang", "ld.lld", "llvm-ar", "pkg-config", "ninja", "meson", "python3",
                 "gperf", "bpftool"):
        require(paths[name] == TOOLBIN / name, "unpinned tool dispatch: " + name)
    cross = target_file(SYSROOT, {k: paths[k] for k in ("clang", "ld.lld", "llvm-ar", "pkg-config", "python3")})
    args = options()
    closure = {"ubuntu_source": [source.DSC, source.ORIG, source.DEBIAN], "overlay": source.OVERLAY_SHA,
               "source_preparer": sha256(Path(source.__file__).read_bytes()),
               "tool_manifest": t["manifest_sha256"], "tool_tree": t["sealed_sha256"],
               "host_helper_runner": t["runner_sha256"], "host_helper_inputs": t["bpf_input"],
               "probe_client": sha256(regular_bytes(QUERY, 8192)),
               "sysroot_tree": s["inventory_sha256"],
               "sysroot_packages": s["package_lock_sha256"], "recipe": sha256(Path(__file__).read_bytes()),
               "options": args, "machine": cross, "targets": list(TARGETS)}
    old = WORK / CONFIGURE_ONLY
    closure.update(reuse_configure=CONFIGURE_ONLY if old.exists() else None, selectors=list(SELECTORS))
    # Exclusive reservation. A failed or interrupted fingerprint is never retried.
    # Successful actual products are consumed by the verification stage, not rebuilt.
    fingerprint, attempt = reserve(WORK, closure)
    env = {"PATH": str(TOOLBIN) + ":/usr/bin:/bin", "LC_ALL": "C", "HOME": str(attempt),
           "TMPDIR": str(attempt / "tmp"), "XDG_CACHE_HOME": str(attempt / "cache"),
           "GIT_CEILING_DIRECTORIES": str(attempt), "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_NOSYSTEM": "1", "SOURCE_DATE_EPOCH": EPOCH, "TZ": "UTC",
           "PIP_NO_INDEX": "1", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
           "PKG_CONFIG_LIBDIR": ":".join(str(SYSROOT / p) for p in
               ("usr/lib/aarch64-linux-gnu/pkgconfig", "usr/lib/pkgconfig", "usr/share/pkgconfig")),
           "PKG_CONFIG_PATH": "", "PKG_CONFIG_SYSROOT_DIR": str(SYSROOT), "NINJA": str(paths["ninja"])}
    try:
        (attempt / "tmp").mkdir(mode=0o700)
        stage = attempt / "stage"
        reused = None
        if closure["reuse_configure"]:
            build_dir = reused = reused_configure(old, closure, cross, attempt)
        else:
            src_dir = attempt / "source"
            prep = source.prepare(INPUTS, src_dir)
            save_new(attempt / "source.json", compact(prep))
            src = src_dir / "systemd-259.5"
            save_new(attempt / "target.ini", cross.encode())
            build_dir = attempt / "build"
            vmh = SYSROOT / "usr/include/aarch64-linux-gnu/linux/bpf/vmlinux.h"
            require(vmh.is_file() and vmh.resolve(strict=True).is_relative_to(SYSROOT),
                    "protected target vmlinux.h required")
            launch("configure", [paths["meson"], "setup", build_dir, src, "--cross-file", attempt / "target.ini",
                                 "--backend=ninja", *args, f"-Dvmlinux-h-path={vmh}"], attempt, env)
        audit_install_plan(build_dir)
        launch("compile", [paths["meson"], "compile", "-C", build_dir, "-j", "4", *SELECTORS], attempt, env, reused)
        launch("stage", [paths["meson"], "install", "-C", build_dir, "--no-rebuild", "--tags", TAG,
                         "--destdir", stage], attempt, env, reused)
        expected = {"usr", "usr/bin", *("usr/bin/" + x for x in TARGETS)}
        require({x.relative_to(stage).as_posix() for x in stage.rglob("*")} == expected,
                "unexpected files installed by isolated tag")
        rows = {}
        for name in TARGETS:
            p = stage / "usr/bin" / name
            row = p.lstat()
            require(p.resolve(strict=True) == p and stat.S_ISREG(row.st_mode) and row.st_nlink == 1
                    and row.st_mode & 0o111, "not an installed executable: " + name)
            rows[name] = sha256(regular_bytes(p, 128 << 20))
        result = {"status": "CROSS_BUILT_NOT_EXECUTED", "fingerprint": fingerprint, "clients": rows,
                  "directory": str(stage), "guest_execution": False, "phase3_exit_eligible": False}
        save_new(attempt / "result.json", compact(result))
        return result
    except BaseException as e:
        save_new(attempt / "failure.json", compact({"fingerprint": fingerprint, "error": str(e)[:2048]}))
        raise


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(build(), sort_keys=True))
