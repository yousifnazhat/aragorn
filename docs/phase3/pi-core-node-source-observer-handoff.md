# D2 Node source acquisition lane

This source-only batch preserves `pi-core-source-observation/v1` and adds the
narrow `pi-core-node-source-observation/v2` producer to the same sealed
`PiSourceObserver` facade. It does not establish successful Node startup,
deployed acquisition authenticity, useful pilot completion, or Phase 3
qualification. No tests, imports, builds, activation, credentials, or paid calls
were executed by this lane; the coordinator owns focused pipeline validation.

## Connected ownership

`start_node_observer(owned, profile, operation_deadline=..., cleanup_deadline=...)`
starts one dedicated tracer owner. It returns only after actual acquisition of
the pinned pre-Node stop. The same thread acquires syscall stops during the
supervisor's blocking bootstrap/request operations. Factory and command failures
retain the exact facade and owned handles, including failed partial startup.

`begin_owned_stop` switches to exit-only draining before the existing owner stops
the unit. `shutdown_after_owned_stop` reaps only captured TIDs, closes owned
duplicates, then requires the tracer thread to join before native handle closure.
It never detaches, resumes an ordinary failed syscall, widens deadlines, retries a
failed cleanup, or starts another effect. The selected launch profile requires
immediate owned SIGKILL to avoid spending the existing cleanup budget waiting for
SIGTERM while the worker is deliberately stopped.

## V2 evidence boundary

- Actual per-TID ENTRY/EXIT pairing, exact thread-only clone/clone3 requests,
  kernel child joins, initial child stops, explicit resumes, fresh all-stop
  epochs, terminal lifecycle records, and no TID reuse.
- `read`, `readv`, `pread64`, and `preadv` source delivery is independently
  acquired through held FD duplication and immutable file identities. Shared
  file-descriptor/offset operations are parent/focus-only until exit. Failed reads
  do not deliver even a zero-byte required source.
- Pinned loader reads and private ELF mappings are separate evidence and never
  satisfy required JavaScript source coverage. Anonymous mappings and ordinary
  runtime operations do not prove arbitrary in-memory JavaScript behavior.
- `pipe2`, `eventfd2`, and Unix `socketpair` outputs are actually read under
  all-stop, and duplicated kernel objects stay held through cleanup.
  An actual same-process `KCMP_FILE` comparison joins each internal input to its
  retained open description; shared anonymous-inode metadata is not identity.
  Stdio must be the independently observed fixed null device. Root Unix input must match
  the exact owned bootstrap or existing request-dispatch listener and peer.
  These are non-source input records, not claims that data cannot become code.
- Thread/source/loader inventory limits and the original 100 ms challenge are
  unchanged. Cleanup has a per-thread reserved share of the existing event cap.
  Source reads remain limited to 16 MiB; separately pinned ELF files retain the
  existing executable-size limit.

The explicit required-source subset is not the entire installed dependency
closure. Inventory digests contain installed object identities and must be
prepared from the actual protected deployment view. A root owner-write bit is
accepted only when the actual held file descriptor proves a read-only mount;
group/other writable objects, links, aliases and unstable objects remain refused.

Health is a fresh all-stop **snapshot**, not a continuously held or atomic
source-health-to-effect guarantee. Known pending polling/futex operations and
fully accounted non-source IO can remain visible; pending source/loader reads,
mapping, clone and FD-creation operations cannot qualify. The exact latest
successful HELD snapshot is retained separately through `health_observation`;
the final CLOSED/REFUSED full record retains subsequent failure and cleanup
events and must not be relabelled as that prior health boundary.

## Remaining prerequisites

The coordinator must validate only new/affected stages, assemble the changed
artifact successor and the independently supplied pinned static gate, then
prepare post-install immutable identities. Actual pinned Node/libuv startup,
kernel ptrace behavior, source inventory sufficiency, timing, and cleanup remain
unproven until separately authorized bounded Linux validation. Unclassified
regular/procfs reads, unpinned loading, process forks, process-memory transfer,
sendmsg/recvmsg FD exchange, AIO/io_uring, later exec and unsupported syscalls stay
explicit refusals; there is no generic bypass to turn missing runtime coverage
into healthy evidence. No D2, D3, D4 or D5 exit gate is closed by this lane.

Coordinator validation is complete for this source batch: 47 distinct acquisition
checks passed, with only the seven new and three affected identity/close cases
selected after the initial 40 passes. See the retained fingerprints and evidence
limits in [batch 18](coordinator/pi-core-preexec-node-batch-18.md).
