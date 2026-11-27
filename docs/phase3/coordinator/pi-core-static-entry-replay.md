# D3: check exec before consuming it; replay the fixed worker's entrypoint reads

Parent: signed main `7bc6906e6d485e9025a153e84cd146d2bf1e36d0`.
This is an offline implementation checkpoint, not a guest capture.

## What the owner enforces

Authorizing the final gate stop installs a wait handler on that worker's original
tracer session only. Before the normal wait consumes a pre-exec notification, the
handler peeks on the held pidfd. An empty poll returns without a consuming wait.
For exec, the handler first calls the owner's [existing Node identity check](pi-core-static-task-node-exec.md).
It then uses the original wait method and compares the emitted stop's PID, worker
generation, raw status and former TID to the pending event. A missing or changed
stop refuses the task. The passive receipt alone no longer suffices for release.
The frozen observer, historical inventories and guest media are unchanged.

## What independent replay accepts

`task.entry_replay_records(observer)` exports four canonical byte strings from
the protected owner: the static binding, gate authorization, pending exec receipt
and consumed-stop link. Retain these originals privately and nominate their
digests independently of the candidate trace. The link identifies the exact
sequence and digest of the original tracer STOP rather than a later Node snapshot.

`verify_task_entry_read` takes those four pins plus the existing Node replay
inputs: the original trace and its expected digest, externally expected worker,
clock, profile, inventories, challenge and retained file bytes. It checks the
fixed task's unit, gate, Node, argv and entrypoint. The existing verifier pairs
raw read entries and exits, checks thread membership and file identity, and
requires the delivered byte ranges to cover the entire immutable entrypoint.
The fixed task does not inherit the older restricted bundle's profile or pins.

The positive offline fixture used the retained **398,741-byte** packaged
`entrypoint.js` (SHA-256 `062508c46c4dcfa5bf5663ce3681b5347715af79e0db1c9414d5e5cf40f1afcb`).
The actual wait handler emitted the consumed STOP used by replay; kernel replies
and read events were inert fixtures. A one-byte gap, identical bytes on another
inode, a changed invocation at the same PID, a substituted or duplicate stop,
and a PASS summary without raw evidence were rejected.

| New or affected offline stage | Passing checks | Fingerprint (SHA-256) |
| --- | ---: | --- |
| Pending/consumed exec ordering | 4 | `809445ce602d3a1a00c7e01147855ebb4e7d40054094abcc7abcf887bf3250e8` |
| Independent entrypoint replay | 5 | `4bc037418422fc8c6f33f42fa59ef7574c4e22249bdca74ea8cedcc60e1724e8` |
| Original gate/owner integration | 9 | `a8821124ec5627a460ff74cf29f2de1a3efd6c68ea60d1d45a6790b9cea34181` |
| Owner dispatch boundary | 13 | `598300e5ad87e652bbc84a01a33521f121fabcd8ee0b87908408251497f4d3bc` |

The new checks failed first on the missing event handler, replay consumer and
owner integration. No worker or tracer was launched and no historical capture
or qualification campaign was repeated.

**Next D3 acceptance:** connect the actual static-session lifecycle to the
original stopped worker and private evidence store: retain the read trace and
four originals so an independent reader can replay them after retirement.
Loss of custody must prevent dispatch and leave an explicit cleanup outcome.
Instrumented sensor loss accounting is still open. D2 pilot authorization,
D4 freeze and D5 acceptance are unchanged. Recorded file delivery is not proof
of JavaScript execution, live acquisition authenticity or sensor health.
