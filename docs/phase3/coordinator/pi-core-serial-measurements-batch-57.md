# D4 batch 57 — enforce serial measurement windows at qualification

Starting point: signed merge `03e3468`. The existing collector executes one
sample at a time. Previously the managed qualification reader checked only
each baseline against its paired instrumented run. It could accept two reported
decision intervals, different pairs, or a decision and a task occupying the
same time when other requirements and arithmetic returned PASS.

The reader now checks the exact evidence digest used for the quantitative
thresholds. It retains the baseline-first rule and sorts all 100 decision and
200 full task intervals by their reported timestamps. One interval may end on
the next one's start; a one-nanosecond overlap refuses qualification. Case ID
order is not a clock. No changes to collection, the seven deployment bindings,
the legacy OpenClaw contract, the 29 managed requirements or any threshold.

| Focused stage | Passed once | Fingerprint |
|---|---:|---|
| `pi-core-managed-timing-serialization-offline` | 6 new and 4 affected | `53ca8c7b422b5ea388a9cf0eebeabf2d8e81409f77f7d24935597e8879367d3c` |
| `pipeline-capacity` | 4 at the 286-stage boundary | `a4d1a37cca7ed89492d7274a29b34b0c1dd8eeffe26ad4dec5ff07c0c779a742` |

These are parser/qualification contract checks against inert fixtures. They
do not establish truthful boundaries, one boot or clock domain, or that
capture, cleanup and observer activities outside those intervals did not
overlap. Independent raw evidence and serialized operations remain mandatory.

1. D2: keep B49 null and the pilot held. Verify actual guest isolation, health,
   recovery and end-to-end timing after separate authorization.
2. D3: connect remaining managed admission, RUN/health and the four workloads
   on the same deployment; the copy replay work is not a measured pair.
3. D4: complete the independent verifier inventory and close prerequisites
   before freezing. This batch tightens one check and does not create a freeze.
4. D5: only with separate approval after freeze, acquire fresh admission
   evidence, 100 attempts and 100 pairs; verify cleanup and replay.
