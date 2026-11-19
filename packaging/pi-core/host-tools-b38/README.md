# Coordinator-only systemd build input

The source preparer applies the Ubuntu `259.5-0ubuntu3` quilt series before
the local Meson overlay. The three exact target names retain their Ubuntu
sources, options and dependencies. They use upstream's internal static
archives instead of the private systemd shared library, request no installed
RPATH, and get a unique install tag. They are **not** fully static binaries.
The manager, worker, public library and branded version are not replaced.

In the independently pinned Linux ARM64 toolchain/sysroot, configure the
prepared source for the matching guest's Ubuntu feature set and `/usr`
prefix. Run only these targets and stage into a **fresh private directory**:

    meson compile -C "$build" systemd-run systemctl busctl
    meson install -C "$build" --no-rebuild --tags aragorn-coordinator-client --destdir "$stage"

Require exactly the three installed clients in `$stage/usr/bin`; do not use
build-tree executables, install into a running OS, or ship helper libraries
from the build directory. Verify the staged bytes with the existing native
parser, check actual versioned symbol requirements against the one selected
loader/library set, and bind the reviewed output hashes to the host profile.
Meson settings predict neither the actual ELF metadata nor runtime mappings.
