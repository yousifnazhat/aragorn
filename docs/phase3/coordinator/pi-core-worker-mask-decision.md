# D2 decision: how to prove an intentional worker mask

Status: **A approved for offline implementation.** Preserve confinement and
version the observation format. [Batch 58](pi-core-mask-witness-batch-58.md)
implements the offline reader. B49 remains null. This is a source-level
compatibility finding, **not** a report from an installed guest.

The [worker launcher](../../../src/aragorn/pi_core_confined_launch.py) deliberately
uses `PrivateDevices=yes` and masks `/dev/pts`, `/dev/shm` and `/dev/hugepages`.
The [B55 reader](../../../src/aragorn/pi_core_state_exposure.py) requires two
complete child lists for every directory, and a resolved stat for every link,
from the worker's view. Its [acquisition contract](pi-core-storage-admission-batch-55.md)
refuses an inaccessible path. An unprivileged Pi cannot enumerate the contents
of a root-owned mode-0000 mask. Recording an empty list on permission failure,
or substituting a root observer's successful listing, would change what was proved.

The [pinned systemd 259.5 source archive](../../../scripts/prepare_pi_core_host_tool_targets.py)
has SHA-256 `80ed55a8a69c4bd1fb12a36659303372b37baf9ee224ef4f032db4b748be0f76`.
In `src/core/namespace.c` (1334–1355, 1853–1885) and
`src/shared/dev-setup.c` (100–121), systemd constructs a private device tree
and selects mode-0000 mask objects. Depending on the system's original
`/dev/ptmx`, the worker may see a symlink to the masked `pts/ptmx` or a
cloned character device. The former lacks B55's required resolved stat;
the latter is not a device B55 permits. Neither branch was observed on a VM.
Also, blindly following `/proc/self` from a privileged observer would identify
the observer, not the stopped worker.

| Choice | What changes | What must remain true |
|---|---|---|
| **A — selected: preserve confinement, version the observation format** | Add a narrowly defined record for an explicitly approved mask. Independently bind its trusted empty backing object, stable target mount/namespace, held worker identity and actual denial under worker-equivalent credentials. Handle only corroborated, named link outcomes. Explicitly mask an accessible PTY device in the successor if necessary. | No generic permission-error or dangling-link exception. No new Pi access to devices or state. An incomplete walk, wrong mask, accessible disallowed device, changed namespace or unaccounted process-relative link still refuses. Keep B55/v1 unchanged. |
| **B — preserve the literal B55 walk** | Design and pin a different worker view that can be fully enumerated and has no unresolved links or unauthorized devices. | Do not expose masked resources to make enumeration succeed. Prove compatibility for the exact launcher, runtime and all required worker functions before selecting it. |

Neither choice changes a Phase 3 threshold or authorizes spending, enrollment,
boot, provider use, or an acceptance run. **Do not wire an offline comparison
result into launch authority**. A real positive outcome would also
require current independent capture and custody for the same deployment.
