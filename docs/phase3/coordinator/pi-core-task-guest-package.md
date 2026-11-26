# D3 — fixed task service and channels in the common guest payload

The prepared **image input**, not a bootable disk or running installation, is
`~/Library/Application Support/Aragorn-Task-Guest-v1-Offline/`. Its `root/`
and `payload.json` use the existing immutable-image format. The complete payload
SHA-256 is `57284c68ac3785e694cbc06dde9b3c5449df7d552f6316e6d6474e4d296ce3dc`.
All 1,791 B111 paths remain identical. The 157 additions bring the total to 1,948.
Git retains the [package catalog](../../../packaging/pi-core/task-guest-payload-v1.json),
[Python source pins](../../../packaging/pi-core/task-guest-sources-v1.json) and
[Pi build receipt](../../../packaging/pi-core/task-worker-v1/build.json), not the disk
or installed state. Existing B111/B112 pins and boot authority do not change.

The fixed service uses the retained ARM64 CPython, a wrapper with an embedded
140-file source inventory, and the original same-byte source loader. Its read-only
source bind is local to that service; it does not replace the old coordinator's
sources. The task worker has a **separate** runtime using the original ARM64 Node
and package metadata, a single-file Pi task entry and a new ARM64 pre-exec gate.
The gate retains both stops and checks just the two task endpoints. Neither unit
is enabled, socket activated, or automatically restarted.

| Channel | Visible to | How it is bound |
| --- | --- | --- |
| `tasks/control.sock` | Pi and the manager | Fixed stream in the worker's read-only task view |
| `tasks/service.sock` | Pi and the manager | Manager accepts on this exact listener and transfers that connected FD once |
| `handoff.sock` / `witness.sock` | Service and manager only | Separate private directory; credential-checked one-shot handoff and independent response |

The owner prepares empty bind-source directories first. Both dynamic roles stop
so their actual identities can be checked **before** the owner publishes either
Pi socket. The Pi socket directory is root:Pi-group 0710 and both nodes are
0660. The separate owner directory is root:service-group 0750, not mounted in
Pi. The manager checks the held service listener, its parent and its node under
custody; Pi credentials on a control stream are not equivalent.

For a future release, the independent owner must take the service-unit, wrapper
and interpreter digests from the reviewed package, **not** from the task. It
must independently nominate the request, processes, clock and unit invocation.
The root reader checks the actual executing interpreter, argv, wrapper and unit,
and rereads the original systemd state. Baseline requires observed absence of
the fixed transient sensor; instrumented requires its nominated running generation.
Unknown state, a swapped mode or missing readback refuses. This discriminator
does not prove continuous instrumentation, zero loss or a healthy sensor.

## What was checked

| New pipeline stage | Passed | Final fingerprint |
| --- | ---: | --- |
| `pi-core-task-guest-worker-offline` | 3 | `5d5b59f1b798b9e399706b609a8a579675d12d11d48360f95b18dfaee67f096f` |
| `pi-core-task-guest-binding-offline` | 10 | `4cbe1ae5c73306455bd5537fc1d1efee9ffe64a11556c5a4366d4b3e1388e126` |
| `pi-core-task-guest-package-offline` | 5 | `eed29427d872904d1bfbfb164478a77ad849464be76b02d502a9780dc51638ab` |

The physical package was read back against its independently projected inventory;
new names were also checked against the stock guest inventory. The worker bundle
and ELF gate were built once, not run. Inert dispatch accepted the nominated
baseline, executed the fixed calculation, and required explicit retirement.
Injected conflicting mode evidence stopped the calculation before work. Substituted
wrapper, interpreter, arguments, invocation, drop-in and wrong Pi channel were
rejected. The wrong-channel check failed first even with the correct Pi credentials;
the reviewed correction binds acceptance to the held listener. No live Linux
peer, boot, provider, real timing sample or acceptance result was produced.

The one-shot preparer refuses existing output. On a machine with the exact retained
offline prerequisites and worker input, its command is
`PYTHONPATH=src:. python3.12 -B -m scripts.prepare_pi_core_task_guest_payload prepare`.
For an already-prepared package use `readback`, **not** another build.

## Next boundary

1. **D2:** still needs independently evidenced installed identity, health, useful
   effect, recovery, timing and cleanup in a separately authorized pilot. B49 stays null.
2. **D3:** connect the native owner to a durable single-use claim, both stopped
   roles, the source observer, the real sensor-health guard, evidence retention and
   verified retirement. Independently locate the copy directory FD **in the service**;
   a transferred FD number need not equal the manager's number. A substituted service
   or mode, or an uncertain effect, must never consume a second execution. The
   new payload still needs inclusion in separately pinned deployment media before boot.
3. **D4:** complete the independent verifier inventory for all 29 logical requirements;
   freeze only when prerequisites close.
4. **D5:** separate post-freeze authorization, fresh acceptance, 100 actual attempts
   and 100 measured pairs, cleanup and independent replay. None was attempted here.
