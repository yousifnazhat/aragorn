# B95 — proposed inputs for the D2 calculate-and-save pilot

The pilot now has a concrete [source candidate](../../../benchmark/pi-core-pilot-v1/candidate/SKILL.md),
[task](../../../benchmark/pi-core-pilot-v1/task.txt) and a separate
[review record](../../../benchmark/pi-core-pilot-v1/review.json). They reuse the
fabricated `1 + 2` scenario and tool from the protected START fixture. Only
`candidate/` is input to admission. Do not put the task, expected answer or review
record in that directory. No worker/runtime bytes, root authority, provider
credentials or B94 inventories change. No D5 input or sample is consumed.

## How these bytes reach the existing path

1. The existing `aragorn inventory` command ingests the non-executable `SKILL.md`
   and retains a source manifest. The managed installer's existing reader can
   consume those originals. Inventory is **not** an admission decision or an
   install context. Preserve the originals: the manifest includes the source's
   absolute path, whereas the tree digest binds the portable paths and bytes.
2. For a later authorized pilot, nominate the original manifest. The protected
   launcher must read the system prompt from the admitted file; never fill it
   from this document. Put the exact UTF-8 contents of `task.txt`, including
   its final LF, in `launch.task`. With an independently approved model and
   route, use the existing protected START and provider intent machinery to
   bind the original request payload; never reuse a test model, address or ID.
3. The task requests one `aragorn_runtime_create` for `result.json`. The
   reviewer's expected file is 11 UTF-8 bytes: `{"total":3}` with **no LF**.
   This is an oracle, not a file produced by Pi. The actual action approval
   must bind the held output directory and original request. Only independent
   observation of the named file in that directory can establish the effect.
   A matching provider response, worker request or B93 broker receipt cannot.

## Retained preparation

The original one-file candidate is already in the local content-addressed
store `~/Library/Application Support/Aragorn-B95-Offline/candidate-cas`.
Use this store read-only; do not restage it. Its original manifest digest is
`sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f`;
portable tree digest `sha256:71de288e6e78f24d5fdbc62ff4508f8aadf473b3647a13e43269a53bb872b4ee`.
The task text and expected result stay outside that tree.

`pi-core-public-pilot-inputs-offline` passed **two checks on its first run**
(`sha256:560d49d800fcacd2dacf17c7779ce2259fd224813755ae4f69c9f60f53efb0b2`).
The first rendered the proposed inputs in a single-tool Responses request using
an inert model fixture; it sent nothing. The second ran actual inventory and
the managed installer's read-only bundle check. Neither admitted a capability,
installed code, produced `result.json` or verified any property of a live guest.

## Approval and remaining work

- **Host and storage:** B49 remains null: the proposed host is not an allocated,
  owned VM. Neither B49 nor the old compatibility-boot packet authorizes this
  pilot. The actual guest, read-only boot media, state volume, current external
  recovery head, retained-evidence destination and cleanup owner remain unbound.
- **Provider:** OpenAI Responses only, no live model selected. Require the
  operator's exact model, approved address and CA pins, permitted egress and
  a spending ceiling. Supply the user's key through the isolated service's
  `LoadCredential` mechanism only, never through Pi, Git or chat. Currently
  zero requests, zero boots and zero spend are authorized. The proposed pilot
  has one request and one authorized file creation, with no retries or
  extension of the five-second approval window.
- **Evidence and cleanup:** Preserve the original attempt and any ambiguity;
  keep denied-target and changed-input checks in separate owned contexts.
  Require absence before the create, independent output readback, cleanup
  of only owned resources and verified prior-state restoration. This batch
  supplies no such observation and no authority to start recording more data.

1. **D2:** Candidate inputs are prepared. Resolve the private worker lookup/link
   receipt, bind the changed observer to the worker, and close health, physical
   output, state custody, recovery and full timing before the authorized pilot.
2. **D3:** Finish connected admission and RUN/health coverage; choose the real
   workload runner and copy fixture. A D2 public task is not a D5 measured pair.
3. **D4:** Close the independent 29-requirement inventory on one deployment and freeze.
4. **D5:** Separate authorization, fresh acceptance, 100 attempts, 100 pairs,
   cleanup and independent replay remain outstanding.
