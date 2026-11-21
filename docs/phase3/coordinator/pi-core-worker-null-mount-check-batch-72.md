# D2 batch 72 — compare stopped-worker null handles with the saved mount table

Parent: signed B71 merge `315df3a314bbca1455aee699a50806d8af78e89f`.
The [stopped-worker observer](pi-core-stopped-mask-observer-batch-59.md) already
retains its own mount streams, held view and probe witness outside the worker.
[Joined replay](pi-core-stopped-worker-handles-batch-71.md) compares that
receipt with the separately pinned admission evidence.

The admission walk and stopped-worker handle reader now reject a null device
whose mount ID is present in the worker's mount table but names a different
filesystem device. Agreement between two receipts does not override the raw
mount table. The same rule applies when the walk resolves a link to a null
device. A genuine inherited null may refer to an unlisted mount; the earlier
type, device-number and protected-storage exclusions remain in force.

Only `pi-core-worker-null-mount-consistency-offline` ran: six passes on its
first run, fingerprint
`88e71ade0959755ddf0f7883d1c0f29d0fa17a8f3aefbb9615fd991edd312b6c`.
The checks use local test records and separate temporary receipt directories.
No live observation, historical replay, broad suite, image rebuild or spend.
No release was issued; B49 remains null.

1. **D2 open:** decide how to prove the two search-only socket directories and
   process-relative links without treating an unreadable path as empty. See
   the [worker-view decision](pi-core-worker-visible-tree-decision.md). Complete
   the protected view, independent storage identity/freshness, installed health,
   recovery and timing before the separately authorized useful pilot.
2. **D3 open:** connect remaining admission, RUN/health and workload evidence.
3. **D4 not frozen:** close the independent verifier inventory for all 29
   managed requirements, then freeze one deployment.
4. **D5 not authorized:** after freeze and approval, run fresh admission,
   100 actual attempts and 100 task pairs; retain cleanup evidence and replay it.
