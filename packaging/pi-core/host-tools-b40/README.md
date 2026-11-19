# Immutable guest: three coordinator client build

The unit of work is **one cross-build**, not an Ubuntu installation or a
systemd test run. Prepare the pinned host-build tools and compiled-against
Linux ARM64 sysroot first. From the Aragorn checkout use the coordinator's
one reviewed build invocation:

    python3 -m scripts.build_pi_core_host_clients

The program verifies those inputs and prepares a fresh source directory
from the batch-38 archive pins, 19 Ubuntu patches and target-only Meson
overlay. Its target machine is Linux/aarch64 without an executable wrapper.
It requests exactly `systemctl`, `systemd-run` and `busctl`; it does not build
or run the manager. Tool configuration is the normal Ubuntu ARM64 feature
profile, **not** the reduced bootstrap profile. The distro config references
its actual ARM64 BTF header even on Darwin. `/usr/sbin` is a real directory
in the authenticated base-files package; the two login.defs minimum system-ID
rows are commented in resolute's login.defs package (SHA-256
`3331efa0bfbf0caeed828beddb179e32719f744891359bd28beb489f8f7a9fbd`).

Darwin cannot apply a second sandbox inside the first. For Meson's one
`bpftool --version` query, two private FIFOs let the build parent invoke the
**real** signed-input x86_64 build helper in its separate no-network/no-fork
sandbox and return its actual exit status and bytes. The configuration cannot
supply any other argument, forge the response, or ask for a second invocation.
No socket, service, saved version substitution or kernel probe is involved.

Outputs and commands are retained in
`.aragorn/host-preflight/build-b40/client-work/<input-fingerprint>/`.
Meson and its descendants have no network access and use a private writable
build area. Tagged installation into a fresh `stage/usr/bin` uses
`--no-rebuild` and must produce exactly three regular executables. A failed,
interrupted or successful reservation is not a reason to re-run the same
fingerprint. Keep logs and intermediate files; diagnose the cause.

The build receipt records *staged* bytes. Independently inspect those bytes,
including ELF architecture, interpreter, dynamic tags, symbol providers and
the client feature vector; a target build cannot certify installed protected
paths, runtime library loads, immutable boot layout, or Phase 3 qualification.
