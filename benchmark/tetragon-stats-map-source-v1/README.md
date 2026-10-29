# Tetragon stats-map readback source slice

These are exact selected files from Tetragon commit
`1de2ed8ebea18e56257dc59597aa13bf8f0e471e`. The sibling lock retains SHA-256,
byte sizes and Git blob IDs, checked against the pinned GitHub tree before
retention. The original candidate and loss source locks remain unchanged.

`bpf/lib/process.h` defines `tg_stats_map` as a per-CPU array with one u32
key and a `u64 sent_failed[256][7]` value (14,336 bytes per possible CPU).
`pkg/api/processapi/processapi.go` independently specifies the userspace
KernelStats layout. Error columns are UNKNOWN, ENOENT, E2BIG, EBUSY, EINVAL,
ENOSPC and EAGAIN. This is the backing map of the sparse BPF send-failure
collector retained in the earlier loss source slice.

The JSON file retains selected Linux v6.8 ABI excerpts, pinned to commit
`e8f897f4afef0031fe618a8e94127a0934896aba`, for read-only OBJ_GET,
GET_INFO_BY_FD and key-zero LOOKUP_ELEM. Whole fetched source files were
checked against Git blob IDs and sizes at collection time; only excerpts
are retained, so offline whole-file Git verification is not claimed.
Neither tag signatures nor the deployed kernel image were verified.

The syscall buffer is round_up(value_size, 8) times the number of possible
CPUs, copied in possible-CPU order. That sequential copy is **not an atomic
snapshot** across CPUs or counters. The pinned CPU-hotplug documentation states
that the possible mask is fixed after boot; online/present masks are different.
The retained CPU driver excerpt binds the sysfs `possible` attribute to that
mask. LOOKUP_ELEM does not receive a userspace buffer length, so buffer safety
requires the genuine sysfs topology, not merely a before/after string comparison.
The reader must refuse substituted/nested mounts and changed mount namespaces,
bound the CPU list and
buffer, verify the exact map info and pin before/after, and refuse failed or
partial readback. Map readability does not establish which sensor/program
uses it. Even a successful all-zero snapshot does not establish complete
loss accounting, sensor liveness, event attribution, RUN coverage or Phase 3
qualification.
