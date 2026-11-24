# B108 — bracket the calculate-and-save action in the protected caller

The normal protected coordinator can now select the [B107 output reader](pi-core-calculate-save-output-batch-107.md)
for **one** prepared calculate-and-save activation. Selection is optional; it
does not switch on the provider, submit a request or authorize an effect. No
frozen source inventory, worker plan, media, or private B49 value was changed.

**Custody.** The only new ordinary plan field is `pilot_output`, with exactly
`reader_source_digest` and `path_descriptor`. The latter is the existing
`aragorn/runtime-protected-path/v1` descriptor: independently nominated
directory device/inode and the fixed basename `result.json`. Neither a pathname
nor a function is selectable. Unavailable and sensor-capture plans refuse it.
The coordinator checks the reader against both the host source inventory and
the source loader's execution record before acquiring the provider credential.
It opens the action service's fixed `/var/lib/aragorn-runtime-action/protected`
and checks the held and named 0710 directory against the action principal and
the nomination. This is not the provider approval directory.

**Ordering inside the existing native exchange:**

1. After HELLO and authenticated activation binding, check the exact B95
   manifest, skill, source tree, prompt and task against the prepared START.
   Establish absence from the held directory **before the START frame**. The
   worker process already exists at this point. An existing target refuses
   START; the reader neither removes it nor tries again.
2. Wait for the existing protected provider and request dispatch. A worker
   summary alone does not trigger a read. Require the one-call/one-tool completed
   worker result and a matching managed action: terminal `ALLOW/CREATED` for
   `result.json`, receipt joined, handles closed, no reported evidence uncertainty,
   and the same activation digest.
3. Read the exact public bytes once, inside the original shortened work window,
   **before** request/provider dispatcher cleanup, worker RELEASE and supervisor
   cleanup. This is after the broker's own terminal processing. Cancellation,
   block, no-tool completion and uncertain action do not trigger a fallback
   read. Uncertain descriptor closure is a cleanup hold, not a reason to retry.

The original observation is returned privately at
`managed_result.worker.pilot_output_observation`; a later failed RELEASE does
not discard an already successful read or turn the attempt into success. The
public wrapper still reports a digest, **not** the raw finding. The same reader
source serves the existing offline import and the protected caller. Its reviewed
source SHA-256 is `932d2585f5757c4c2ead987c7d54f9f147efc048a71aead0b785384beb1d4dbd`;
this is not an installed source inventory or independent capture/export receipt.

**Focused verification.** The new caller stage ran 15 tests under inert service,
socket and process edges. Fourteen passed, including the actual bootstrap frame
order with disposable file reads. One source-refusal test errored in mock teardown:
patching a mock's `return_value` repeatedly tried to delete its descriptor.
Retained failed fingerprint: `3130ce07bcd29be3bea07d71fc06c845a54eda2a873beedddb85ac158fb4841a`.
The fix changed only that fixture to set its return value directly. Only its
missing, wrong and duplicate source subcases ran again and passed (one test,
`d3a96023e889e3ecfc40cd904f9556e8a70534192a10cdff426493bf189bbfa0`).
No previous stage reran. The earlier combined run is not recorded as PASS.

1. **D2:** Next, re-pin the changed coordinator, managed bootstrap, supervisor
   and reader together for the common successor. Establish approved independent
   private retention; do not substitute the public digest. Installed source and
   sensor health, full timing/recovery, the calculate-and-save task, separate
   refusal cases and cleanup still require evidence. B49 stays null.
2. **D3:** Complete remaining connected admission, RUN/health and workload coverage.
3. **D4:** Verify all 29 managed requirements against one deployment; then freeze.
4. **D5:** Obtain separate authorization for fresh acceptance, 100 attempts,
   100 task pairs, cleanup and independent replay.

Source re-pinning is offline work. Before installing, booting or observing, bind
the exact guest/media, state volume, owners, private evidence destination, budget,
window and cleanup authority. Before provider egress or creation, separately
authorize the model/address/CA, protected service credential, one request, one
create and the spending limit. No allocation, boot, service, provider or pilot ran.
