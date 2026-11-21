# B97 — dependency evidence for the public pilot candidate

B95 inventoried one non-executable `SKILL.md`. An inventory is not the
artifact graph that the admission decision consumes. For the local Markdown
profile, the existing graph producer reads the original content and classifies
its references. The decision reader re-derives the graph from those originals
and an independently nominated verifier. Neither step runs the skill.

Use the B95 source manifest
`sha256:e6de9001bdd41e7908d0b9097798d1ab8ae13037c4ad1a7dbceb4cea985ad77f`,
not a new inventory of a working directory. The existing verifier implementation
at signed merge `0d87af7` has digest
`sha256:05c70d81f1fac7c32ef455397079f9b73d80dfe4dc24d7427ce587f21001af85`.
Its file digest identifies source, not an installed executable. The original
B95 store is read-only; only the two pinned public objects are copied into a
separate store so the existing producer and reader can use their normal API.

**Retained result:** `sha256:c773c261e45868ceea221d8ce63db28cbed0a23278da540b25a6532a91067299`.
The independent read-only replay found exactly one non-executable 47-byte
Markdown file, no outgoing edges and no unresolved references under
`self-contained-local-markdown/v1`. Reuse the three original blobs in
`~/Library/Application Support/Aragorn-B97-Offline/admission-cas` read-only.
The one affected stage, `pi-core-public-pilot-admission-closure-offline`,
passed once (`sha256:d21d9c590240682bef950a4ed23afbda0a9d5272b5f14d597b0c92390874c6de`).
Do not rerun its one-use preparation or adopt an incomplete output.

## Admission boundary

Supply the retained graph digest to the admission decision as
`artifact_graph_digest` with the **original** manifest and independently
selected verifier digest. The decision still needs the appropriate policy,
analyzer evidence and verifier expectations. Installation separately needs a
current protected context bound to the destination and runtime. An absence of
unresolved Markdown references is neither approval of the instructions nor a
claim about what a future model or worker will do. Do not use a fixture policy,
synthetic scanner success or a grant from another candidate.

1. **D2:** Candidate dependency evidence; policy decision, actual worker view,
   protected state, health, recovery, full timing and authorized useful pilot remain.
   Keep the B49 bindings null and the two socket directories non-listable.
2. **D3:** Complete connected admission, RUN/health and real workloads.
3. **D4:** Complete the independent 29-requirement inventory and freeze one deployment.
4. **D5:** Separately authorize fresh acceptance, 100 attempts and 100 task pairs,
   verify cleanup and replay the evidence.
