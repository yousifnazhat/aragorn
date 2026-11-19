"""Prepare the reviewed Ubuntu systemd source for three host clients. Never build or run it."""
from pathlib import Path
import os
import stat
import subprocess

from scripts.build_pi_core_linux import regular_bytes, require, sha256


OVERLAY = Path(__file__).resolve().parents[1] / "packaging/pi-core/host-tools-b38/coordinator-tools.patch"
# The Ubuntu archive's signed resolute/main Sources record authenticates these exact inputs.
DSC = ("systemd_259.5-0ubuntu3.dsc", 8771, "b8168448fa8307117663ce6a7aeee8ccddf5f736b1de70eabaefff04779bf731")
ORIG = ("systemd_259.5.orig.tar.gz", 17336729, "80ed55a8a69c4bd1fb12a36659303372b37baf9ee224ef4f032db4b748be0f76")
DEBIAN = ("systemd_259.5-0ubuntu3.debian.tar.xz", 252636, "a3a1d6e6bd1edf972badef67c85425206a727329f42070db3f469b149df2619c")
OVERLAY_SHA = "55f92421288ab00e3d9f88268ef91db940407665288a1586bea911dc9986a802"
PRE = "f4ba13148b68620872775dad931016a6b76447a07a1b710d7ceac2a7f64e5580"
POST = "19c3cc650bd3e2d856a172db57a359d04392adbb0e6a53226952998a3d9a5428"
TARGETS = ("systemctl", "systemd-run", "busctl")


def prepare(inputs: Path, destination: Path) -> dict:
    """Apply Ubuntu's complete quilt series and one pinned target overlay into a fresh directory.

    Failure preserves the partial directory for inspection. Never reuse it or auto-retry.
    """
    require(inputs.is_absolute() and inputs.resolve(strict=True) == inputs and inputs.is_dir(),
            "unlinked source input directory required")
    require(destination.is_absolute() and destination.parent.resolve(strict=True) == destination.parent
            and destination.name not in ("", ".", ".."), "unlinked preparation parent required")
    owner = destination.parent.stat()
    require(stat.S_ISDIR(owner.st_mode) and owner.st_uid == os.geteuid() and
            not owner.st_mode & 0o022, "unowned or writable preparation parent")
    require(not os.path.lexists(destination), "refuse existing source preparation")
    artifacts = {}
    for name, size, digest in (DSC, ORIG, DEBIAN):
        raw = regular_bytes(inputs / name, size)
        require(len(raw) == size and sha256(raw) == digest, "unapproved Ubuntu source input: " + name)
        artifacts[name] = raw
    overlay = regular_bytes(OVERLAY, 4096)
    require(sha256(overlay) == OVERLAY_SHA, "unapproved host-tool source overlay")
    destination.mkdir(mode=0o700, exist_ok=False)
    source = destination / "systemd-259.5"
    env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "HOME": str(destination),
           "GIT_CEILING_DIRECTORIES": str(destination), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null"}

    def run(argv, cwd, raw):
        subprocess.run(argv, input=raw, cwd=cwd, env=env, check=True, timeout=60)

    # Both archives are byte-pinned before extraction. Never unpack arbitrary caller archives.
    extract = ["/usr/bin/tar", "--no-same-owner", "-xf", "-"]
    run(extract, destination, artifacts[ORIG[0]])
    run(extract, source, artifacts[DEBIAN[0]])
    patches = source / "debian/patches"
    series = regular_bytes(patches / "series", 16384).decode("ascii").splitlines()
    require(len(series) == len(set(series)) == 19, "Ubuntu quilt series differs")
    apply = ["/usr/bin/git", "apply", "--whitespace=nowarn", "-p1", "-"]
    for name in series:
        patch = patches / name
        require(patch.resolve(strict=True) == patch and patch.is_relative_to(patches)
                and not Path(name).is_absolute() and ".." not in Path(name).parts,
                "unsafe Ubuntu series entry")
        run(apply, source, regular_bytes(patch, 2 << 20))
    meson = source / "meson.build"
    require(sha256(regular_bytes(meson, 256 << 10)) == PRE, "Ubuntu Meson preimage differs")
    run(apply, source, overlay)
    require(sha256(regular_bytes(meson, 256 << 10)) == POST, "host-tool Meson postimage differs")
    require(os.path.samestat(owner, destination.parent.lstat()), "preparation parent changed")
    return {"status": "PREPARED_PATCHED_SOURCE_NOT_BUILT", "ubuntu_version": "259.5-0ubuntu3",
            "ubuntu_patches": len(series), "meson_sha256": POST, "overlay_sha256": OVERLAY_SHA,
            "targets": list(TARGETS), "built": False, "installed": False, "phase3_exit_eligible": False}
