# Tetragon sensor/program/map association source slice

This is source custody, not a new runtime observer or a live coverage result.
Fifteen complete selected files come from Tetragon commit
`1de2ed8ebea18e56257dc59597aa13bf8f0e471e`, including the exact vendored
cilium/ebpf attachment implementation. Each fetched file was checked against
its pinned Git tree byte size and Git blob SHA before retention; the sibling
lock also records SHA-256 and why each file is needed. Original source headers
are preserved. Existing source locks and the retained `process.h` are unchanged.

The Linux JSON retains 24 bounded excerpts from seven files at Linux v6.8 commit
`e8f897f4afef0031fe618a8e94127a0934896aba`. The complete fetched bytes were
checked against the pinned contents API size/Git blob and SHA-256; only selected
inclusive line excerpts are retained. Offline whole-file Git verification of
those Linux sources, tag-signature verification, executed-image verification,
and running-kernel attestation are **not** claimed.

## Exact source chain

- `pkg/config/config_linux.go` selects exec/exit object variants; the base
  sensor declares exec at `sched/sched_process_exec`, and exit at
  `acct_process` or the `disassociate_ctty` fallback.
- The registered `execve` loader uses `LoadTracepointProgram`; standard
  `kprobe` uses `LoadKprobeProgram`. The Linux loader resolves pinned map
  replacements, clones and retains the main program FD, and attaches using
  the vendored tracepoint/kprobe functions.
- Those functions use BPF perf-event links where supported, but can fall back
  to legacy perf-event ioctls. The legacy wrapper's `Info()` is unsupported.
  A future narrow observer must refuse that case rather than infer a link.
- Exec sends `MSG_OP_EXECVE` through `event_output_metric` in
  `execve_send`, after the `execve_calls` tail calls through
  `execve_rate`. Querying only the directly attached root program cannot
  establish the send chain.
- Exit's selected kprobe calls `event_exit_send`; with an existing execve
  entry, nonzero execve ktime, and available exit heap, it calls
  `event_output_metric` for `MSG_OP_EXIT`. This is the smaller candidate
  producer association, not proof that an event occurred.
- The unchanged `process.h` implements the selected perf/ringbuf
  send-failure accounting. Its separate `event_output()` helpers do not
  provide the same accounting. Neither helper establishes complete delivery.

These files identify the source-level route; they are not a full build,
configuration, userspace-exporter, or loaded-instruction closure.

## Kernel query contract and limits

`pidfd_getfd` is syscall 438 on both selected x86-64 and asm-generic ABIs,
requires flags zero, and uses
`ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS)`. It returns a
CLOEXEC duplicate of the selected process FD. Refuse permission failures:
do not change ptrace policy or replace PIDFD authority with a numeric-PID guess.

Program info reports `map_ids` from `prog->aux->used_maps`, returning the
full count while copying only the smaller of supplied capacity and that count.
A future bounded reader must reject truncation or a changed inventory.
**Membership is not instruction use:** `BPF_PROG_BIND_MAP` explicitly allows
adding a map that the program's instructions do not reference. Even source
identity and a kernel program tag are not full loaded-instruction proof.

For the selected kernel, perf links have type 7; the selected perf subtypes
are kprobe 3 and tracepoint 5. Link info returns program/probe identity, but
does not return the perf event's enabled state. The disable path sets
`PERF_EVENT_STATE_OFF` without removing `event->prog`; the info path does
not check that state. Thus a successful info read **does not prove an active,
enabled, or responsive producer**.

The selected perf-link operations have no detach callback, so generic
`BPF_LINK_DETACH` returns `EOPNOTSUPP` for this type. Final reference release
frees the perf-event BPF program and its perf-file reference. Duplication itself
extends object lifetime: the observer must promptly close its copies and
recheck the original sensor-held FDs. It must not report that holding its own
copy proves the sensor still owns the object, or that the operation is
lifecycle-neutral.

The smallest follow-on is bounded sensor-FD/program/map/perf-link association,
with exact caller-held identities and before/after custody checks. Exec
tail-call closure, legacy ioctl links, other link types, current enabled
state, and instruction/build equivalence remain outside that initial scope.
Meaningful responsiveness needs separate positive event evidence from the
bound producer and reader, such as a newly authorized owned exec/exit challenge;
no challenge was executed here. A positive event would still not prove
complete event coverage, zero loss, attribution, sensor health, RUN conformance,
or Phase 3 qualification.
