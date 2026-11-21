# D2 B82 — candidate for the worker side of the filesystem proof

B81 can tell an independent reader what the manager saw. Only the actual
confined task can supply the other side of this claim. B82 prepares a new
version of the small program that runs before Node. Nothing in this batch
selects it for an existing launch, starts it, or admits a state volume.

The candidate uses a fixed probe sequence, not user-supplied paths or
commands. It uses the worker's existing credentials and read-only view.
There are 28 planned metadata calls between the initial and final stops:
six for the socket directories/endpoints and 22 for the six named links and
their corroborating targets. A stop or exit alone is not their transcript.
The two directory opens must fail with access denied; a missing directory,
another error, or a successful open is not a passing denial. Exact socket
paths have separate metadata lookups. The process-relative checks are for
`/proc/self`, `/proc/thread-self`, `/dev/fd` and the three standard I/O
aliases only. They do not authorize access to the rest of procfs or confer
an exception on any other link. No socket connection, directory widening,
or protected data read is part of this protocol.

For review of the target ABI, the retained B40 sysroot's
`aarch64-linux-gnu/asm/fcntl.h` supplies the architecture-specific
`O_DIRECTORY` and `O_NOFOLLOW` values; the generic header alone is wrong for
this target. The pinned systemd 259.5 `src/shared/dev-setup.c` specifies the
standard I/O aliases. These are inputs to the design, **not** a report of
what was installed or observed on a guest.

The future independent reader needs evidence from the original worker stop,
the exact operation arguments and kernel results, object identities in the
worker's mounts, and the same worker generation and final stop. For the two
sockets, join to B81's independently pinned manager evidence without assuming
manager and worker mount IDs are identical across a bind. For procfs,
correlate the proc mount's PID namespace and the actual task; for standard
I/O, correlate B71's original descriptor generations. A compiled binary, a
program's own exit code, or a root observer looking up its own `/proc/self`
cannot make any of these findings.

**Offline delivery.** The [signed checkpoint's artifact pins](../../../packaging/pi-core/worker-view-gate-artifact-v3.json)
identify a 4,232-byte static ARM64 ELF, SHA-256
`ffc723e70a72421226b554d7e0407680f9e2a41262ddd7c1456bacd923073d78`.
Eight new contract checks passed:
`85ee34e73c29d038421953f85133071b0b48fbdae3e40e23d6a34eb0f05440c5`.
The original host compiler and linker ran exactly once each, both returned
zero and were reaped. No target instruction ran. Their build-stage fingerprint
`0a06663a8f1180ede3a8e5329d5515c8cf297d20e134dbd2bb380e9ea35f0264`
remains **failed**: its post-build comparison treated Python's tuple of
commands as different from the equivalent JSON array. Its output was not
removed, adopted as a fresh compile, or rebuilt.

The corrected comparison is over canonical bytes. A **readback-only** stage
checked the original source, toolchain, expected command sequence, receipt,
object, final ELF and command logs against independent pins. Its first
assertion about log metadata omitted the recorded relative filename; failed
fingerprint `fcc6d41f9b51dd2e2aa37ca749a0becdb687a62f4d71944e2871d317f6419429`
was retained. Corrected readback passed (one check,
`f15865b38061a088e3a52a5d19ef3f43e72d7569ce2328b06bbc36cbce61b825`).
This verifies the existing artifact, not a second fresh build or a pilot.

1. D2: wire the new, separately pinned gate to the matching observer, private
   evidence retention and independent replay. Common guest provisioning,
   storage custody, real health/recovery/timing and pilot approval remain.
2. D3: remaining admission, RUN/health, workloads and sink evidence.
3. D4: close the verifier inventory and freeze a single deployment.
4. D5: separate approval for fresh acceptance, measured attempts/pairs,
   cleanup and replay. No qualification or installed observation.
