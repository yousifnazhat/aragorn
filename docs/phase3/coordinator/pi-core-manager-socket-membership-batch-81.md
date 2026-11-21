# D2 B81 — the manager's half of the two socket exceptions

The operator [approved keeping confinement](pi-core-worker-visible-tree-decision.md).
Neither directory gains read permission for Pi. This batch concerns the
restricted, provider-enabled path; the unavailable path and the capture-only
device-mask path cannot substitute for it.

The [supervisor](../../../src/aragorn/pi_core_native_supervisor.py) takes
the first sample after both real dispatchers own their sockets and before
starting the unit. The [source observer](../../../src/aragorn/pi_core_node_source_observer.py)
takes the second on its own thread, after authenticating the initial stopped
gate and before permitting it to resume. The [manager-side walk](../../../src/aragorn/pi_core_owned_socket_directories.py)
uses the manager's held root, actual directory and listener handles, complete
bounded listings and named endpoint identities. It rejects extra names,
changed ownership, replacement, mount substitution or a changed worker.
The two samples are not continuous monitoring. A later failure or uncertain
cleanup cannot become a successful result.

The [offline reader](../../../scripts/verify_pi_core_owned_socket_directories.py)
needs the pinned plan and original public wrapper output, the separately
retained canonical **private** result, the expected deployment, boot and
unit invocation. It compares the two samples against the original worker
stop and resume. The public wrapper still emits only a digest of the managed
result. It cannot reconstruct missing bytes. No new private destination was
selected, and no managed result from a running guest was obtained.

This proves neither Pi's lookup nor its inability to enumerate, and it
does not resolve a process-relative link as Pi. The next worker-side proof
must run under the actual task's restrictions, identify the same sockets
and bind link targets to its task, root, namespaces and descriptor
generation. Do not infer later Node behavior from a pre-exec observation.
Retain all frozen profiles; an old guest lacks these sources and cannot
satisfy the new proof. No changes to B49 or the state unlock/host approvals.

**Affected checks only: 25 passed.** Manager acquisition (7),
`1d8f92f9907b1b2800f2f32c718599a4606c324e45079b166221ead5c30ab4b2`;
stopped-owner ordering/cleanup (6),
`af426596668cd80be61677a82735c64fec080a7c39b341d53e1ce116b9a6167c`;
private replay (12),
`f4636e5f08fb0ef731132d54ae2dbfedd120b40cae03d2c1cf53385f25a0c0b5`.
The first replay fixture incorrectly paired a restricted profile with an
empty legacy build receipt (retained failure
`969e9702e271d29208ebd0db081313a8fc056656b880e6cc82251515b544d924`).
It now uses the retained B36 receipt without rebuilding. Replay checks the
whole restricted receipt. The next replay run exposed an untyped error for
a sequence pointing at a non-stop event (retained failure
`dbc5c7f455802f2a20cc1a6a1c8a6f9abcdba294df833598c1433e83c4da7396`).
Replay now rejects that case explicitly. Neither successful stage reran.

1. D2: manager-side source connected; private retention, actual worker
   evidence, state custody, installed health/recovery/timing and a separately
   authorized pilot remain open.
2. D3: connect remaining admission, RUN/health and workloads/sink evidence.
3. D4: complete independent coverage for all 29 requirements, then freeze.
4. D5: separately authorize and run fresh admission, 100 attempts and
   100 pairs; verify cleanup and replay. No qualification claimed.
