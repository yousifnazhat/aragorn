# Protected reader transport and actual telemetry loop design

Status: coordinator design only; not an implementation, stage or operational release.
Reviewed against the source base originating at signed `d87572182584f9c106393a2ca952c69703b6da6d` and the new reader-storage provider contract. Existing live-operation, private-retention and cleanup holds remain.

## Smallest useful integration

Use the existing Tetragon candidate and its `tetra getevents` JSON stream. Add one Python reader service that actually consumes that stream, plus one protected accepted-connection adapter calling `acquire_owned_reader_response`. Do not add a custom eBPF sensor, a generic transport framework, a replacement protobuf stack or a heartbeat daemon.

The existing smoke reference already used a bounded nonblocking stdout/stderr pipe consumer:

`benchmark/evidence/reference/tetragon-isolated-exec-exit-smoke-v1-2026-09-13.py.txt`.

Its fixed candidate image was `quay.io/cilium/tetragon@sha256:1bffeee60f1d47e367d237129e576729d14fe8db748440328aded8a6091c4a40`. Its successful selected exec/exit records came from a separate, subsequently removed VM. They do not establish installation, readiness or continuity in the common native fixture. No common staged Tetragon reader/service was found in current source.

The proposed first real reader scope is selected process exec/exit acquisition. Reuse the existing restricted parser in `runtime_tetragon_process.py`; do not pretend its two supported event types close the seven-event runtime inventory. The former smoke's single-marker executable filter is not suitable for the full workload. The reviewed deployment must specify its real event selection and downstream attribution requirements.

## Exact upstream facts and limits

All Tetragon links below select commit `1de2ed8ebea18e56257dc59597aa13bf8f0e471e` (the repository's v1.7.0 candidate). The current candidate source lock is a selected slice, not a complete reproducible build or installed-binary identity.

- [`cmd/tetra/getevents/getevents.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/cmd/tetra/getevents/getevents.go): the CLI calls `GetEvents`, repeatedly receives a message and encodes it. JSON is the default. It uses `SignalCtx`, so the ordinary CLI timeout does not bound the streaming call. CLI reconnect is separately controlled by `--reconnect` and defaults false.
- [`cmd/tetra/common/client.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/cmd/tetra/common/client.go): gRPC retry configuration is independent of the CLI reconnect flag. The old smoke used `--retries 1`; do not copy it as a no-retry policy. Verify the selected grpc-go dependency's behavior, including transparent reconnect/retry, before claiming a single continuous upstream connection. `--retries 0` alone is not reviewed proof of that property.
- [`pkg/encoder/encoder.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/encoder/encoder.go): the JSON encoder preserves protobuf field names but ignores the error returned by its final `fmt.Fprintln`. A nil encoder result therefore is not proof that all bytes reached the pipe.
- [`pkg/server/server.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/server/server.go): each event listener has a bounded queue, default 10,000 entries. Queue overflow drops events and increments `tetragon_notify_overflowed_events_total`. Without aggregation, failed stream sends return an error. Configure and pin the queue/aggregation settings; an empty pipe does not prove zero upstream drops.
- [`pkg/exporter/exporter.go`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/pkg/exporter/exporter.go): the file exporter can rate-limit events and logs encoding errors while returning nil. Tailing its rotating export file would add rotation and error-accounting obligations; it is not the smallest dependable route here.
- [`api/v1/tetragon/events.proto`](https://raw.githubusercontent.com/cilium/tetragon/1de2ed8ebea18e56257dc59597aa13bf8f0e471e/api/v1/tetragon/events.proto): exec/exit are distinct event variants; aggregation and field filters are explicit request options. The API's PID-set filter is documented for testing/development because PID cycling can admit unexpected events. Do not use it as protected process identity.

Linux reference: [`v6.8 net/unix/af_unix.c`](https://raw.githubusercontent.com/torvalds/linux/v6.8/net/unix/af_unix.c), specifically `unix_sock_inherit_flags`, `unix_accept`, `unix_passcred_enabled` and `maybe_add_creds`. Accepted UNIX sockets inherit the listener's PASSCRED/PASSPIDFD/PASSSEC flags. Configure the listener before connection/traffic and verify the accepted values. This source fact does not attest the deployed kernel.

The CLI pipe remains the quickest reusable acquisition route, with an explicit ceiling: an idle checkpoint proves our actual pipe-consuming loop performed its bounded poll/read. It cannot distinguish an idle producer from a hung `tetra` gRPC bridge or a stalled kernel producer. Producer continuity/progress and loss remain separate gates. A final completeness claim also needs an accounted bridge write-failure boundary, potentially a small source-pinned encoder correction and reviewed build; a reader ACK cannot repair that gap.

## Protected accepted connection

Proposed bounded root entry point, requiring a separate published implementation contract. `listener` is a guarded service/campaign-owned object, opened once from fixed protected credentials and held across explicitly authorized fresh requests:

```python
accept_reader_response_once(
    *, listener: ReaderListener,
    epoch_raw: bytes, expected_epoch_digest: str,
    request_digest: str, sequence_before: int,
    accept_deadline_ns: int,
) -> dict
```

Use only `/run/aragorn-phase3-reader/challenge.sock`. Root provisioning must create and pin its parent beforehand: root-owned, not writable by the reader or runtime, traversable only by root and the exact dedicated reader group. The proposed parent mode is 0710 and socket mode 0660, with root UID and that reviewed reader GID. The GID is not selected by a received request; it comes from the installed account/epoch binding. The new implementation must not create/repair the parent or remove a stale socket.

The listener owner holds nofollow ancestor descriptors and checks named/held identities for its entire guarded lifetime. Require an absent socket name when this lifetime begins. Set PASSCRED=1 and PASSPIDFD=0 on the noninheritable AF_UNIX/SOCK_SEQPACKET listener before binding/listening. Provision only the newly created socket's exact owner/mode, checking the protected named inode before and after. Do not accept an abstract socket or supervisor-created socketpair.

For each explicitly authorized new request, accept at most one new connection under that request's original BOOTTIME deadline. Reject wrong credentials, identity, queued traffic or mode without searching for a replacement peer or retrying the request. Recheck listener/path custody on every request. Explicitly set/verify accepted nonblocking and noninheritable state. Socket options and an accepted connection alone are not authentication: SO_PEERCRED supplies connection-time PID/UID/GID; the existing leaf independently requires matching per-message SCM_CREDENTIALS, held socket-derived PIDFD, fresh process/boot readbacks and time-namespace joins.

The exact reader must create/connect its socket after adopting its final account and capability-free identity, once for each explicitly authorized new request. It sends no greeting or readiness payload on this channel; the existing leaf rejects prequeued traffic. The root adapter transfers exclusive connection ownership once to `acquire_owned_reader_response`, which mints a fresh challenge, and preserves its complete result or error. The listener owner retains its own listener/ancestor descriptors between requests. No accepted-connection pooling, copied connection, challenge replay or automatic accept retry is allowed.

Each request closes its accepted connection exactly once; it does not close or recreate the listener. Reuse of the same guarded listener for a distinct authorized request is neither an operational restart nor a retry. A failed request preserves its failure and cannot trigger an automatic replacement connection; loss of listener custody ends the listener lifetime. At service/campaign termination, close the listener and its held descriptors without ambiguous close retries, leaving the socket path untouched under the cleanup hold. A later operational start at the same path must refuse; implementation does not authorize removal, VM restart or a fresh capture.

The exact service/campaign lifetime, request admission bounds, and protected mechanism notifying the real reader of each newly authorized request still require a concrete coordinator contract. Do not invent a polling/reconnect convention to fill that gap. The contract must permit repeated distinct requests within one held lifetime, including the planned multi-attempt campaign, while prohibiting automatic retries of failed requests. This lifecycle decision is a design proposal to freeze before implementation release; all work remains offline.

## Actual reader loop, not a separate heartbeat

Proposed service entry point: `run_process_reader_from_credentials()`. It reads fixed protected service credentials and has no arbitrary command, endpoint, output-path or callback argument. A reviewed service profile launches the fixed source/byte-pinned `tetra` executable directly with `shell=False`, stdin `/dev/null`, bounded stdout/stderr pipes, a fixed public environment and explicit no-CLI-reconnect configuration. The implementation must not invoke Docker/SSH or reuse the smoke helper's live orchestration.

One reader main thread owns the challenge connection, both bridge pipes, parsing, bounded delivery and checkpoint sequence. It multiplexes those actual descriptors under finite poll budgets:

1. Authenticate and decode at most one canonical challenge against the reader's protected epoch credential. Bind its exact digest, request, nonce and absolute deadline. Receipt only creates pending work; it does not increment sequence or emit an ACK.
2. Perform a subsequent actual nonblocking stdout read or bounded poll, checking held stream/bridge identities. Bound each batch so continuous event traffic cannot starve challenge handling. Monitor stderr, bridge exit/PIDFD and cancellation as well.
3. Parse every complete selected NDJSON record with the existing restricted parser. Retain the original bytes. Unknown variants, malformed/oversized records, EOF, I/O errors, changed identity or exceeded bounds invalidate the epoch; none is an idle success.
4. Deliver the complete batch into a fixed protected checkpoint spool, with exclusive record creation, file/directory fsync and exact readback. Include sequence, stream binding, raw records, read/poll brackets and backlog accounting. No ACK follows failed or blocked delivery.
5. Increment sequence and stamp CLOCK_BOOTTIME in this same loop only after the completed checkpoint. The initial baseline is zero only for a newly bound reader epoch. An idle checkpoint can qualify only after a real post-challenge EAGAIN/poll and no unaccounted partial record or undelivered batch. A partial JSON line remains pending and prevents an ACK.
6. Emit exactly the existing six-field reader-response schema on the challenge connection, with the pending challenge digest and checkpoint timestamp. Do not ACK from a timer thread, receive handler or subprocess liveness check. Close the one-use connection after its terminal outcome. Initiate another connection only for a separately authorized new request through the still-to-be-frozen protected scheduling interface; never reconnect automatically after success or failure.

The protected spool must be a distinct, fixed directory, proposed `/var/lib/aragorn-phase3-reader-events`, provisioned for the dedicated reader identity and inaccessible to workload identities. Keep the root-only claim/evidence store `/var/lib/aragorn-phase3-reader` unchanged and inaccessible to the reader service. The external root monitor independently reads the exact checkpoint sequence and raw bytes from the event spool. Reader-owned bytes remain claims of a trusted reader, not hostile-root-resistant evidence.

Use fixed exclusive names such as `checkpoint-<sequence>.json` under held custody; never replace an earlier checkpoint. A checkpoint binds its previous digest, stream identity, poll/read brackets, complete raw records and explicit buffered/delivery counts. Select finite limits in the implementation contract. No implicit discard or truncation may advance the sequence. This concrete file publication supplies the downstream path; do not substitute a new user callback returning `True`.

Root remains responsible for cancellation of the reader and bridge using owned process handles and existing service stop mechanisms. A syscall such as fsync can overrun a policy deadline; no ACK may be accepted late, and the monitor must time out independently of a hung reader. A finite poll timeout is not a hard bound on every syscall or service shutdown.

## Three roles need a separate stream binding

Do not relabel the existing two-role acquisition epoch. It names the challenged `reader` and Tetragon `sensor`; the `tetra` bridge is an additional process and connection. Its custody cannot be inferred from either PID.

Before implementation release, define and pin one additive `aragorn/native-phase3-tetragon-stream-binding/v1` record. Its minimum concrete inventory is:

| Field | Required retained meaning |
| --- | --- |
| `schema`, `stream_nonce`, `deployment_digest`, `source_lock_digest`, `configuration_digest` | Exact profile, fresh stream instance and reviewed source/config identities. No invented installed hash. |
| `reader`, `bridge`, `sensor` | Three distinct process records: PID, start ticks, UID/GID, executable digest, source-inventory digest, cgroup digest and held PIDFD acquisition/readback evidence. |
| Each role's `namespaces` | Device/inode identities for user, PID, mount, network and active time namespaces, with explicit required equalities rather than assumed equality. |
| `clock` | Kernel boot ID, CLOCK_BOOTTIME and independently observed active time-namespace device/inode; no wall-time conversion. |
| `bridge_argv`, `bridge_environment_digest` | Exact command/options, reviewed public environment and all filtering/retry/receive-size choices. |
| `sensor_endpoint` | Fixed UNIX endpoint path, protected ancestry, socket metadata and authenticated sensor peer identity. The selected gRPC connection must be joined to the bridge's actual socket, not a separate successful probe. |
| `stdout_pipe`, `stderr_pipe` | Held reader descriptors and corresponding bridge output descriptors, FIFO device/inode identities, access/status flags and fresh named descriptor readbacks. The launcher must establish that no other process retains a writer. |
| `checkpoint_root` | Fixed directory identity/owner/mode and exact exclusive record format/limits; unavailable custody refuses. |
| `loss_scope_digest`, `program_map_digest` | Exact applicable series/labels, loaded object bindings and separately acquired raw observation references. They are not derived from idle pipe state. |

Set the existing epoch's `stream_digest` to the independently expected digest of this complete binding; retain and independently verify the binding separately. Do not add fields to frozen acquisition schemas or claim that the current reader-evidence verifier checks this new object. Bridge restart, pipe replacement, stream reconnect, sequence reset or changed source/config ends the stream epoch. A fresh challenge does not heal an old stream.

The selected CLI does not currently expose a protected gRPC-connection epoch or peer-readback API. Exact socket discovery/custody, transparent retry behavior and complete writer inventory therefore remain concrete implementation prerequisites. Do not replace them with a PID-is-alive assertion.

## Loss and required upstream/deployment checks

Reuse `runtime_tetragon_loss`, `runtime_tetragon_stats_map` and `runtime_tetragon_program_map` for their existing bounded semantics. Their current schemas do not acquire the complete three-role stream binding above. Missing series remain unknown; decreases indicate reset; increases indicate loss. Bind all relevant queue/parser/delivery failure paths, including the server's notify-overflow metric and the bridge's output boundary.

Before stronger operational release, root must settle and retain:

1. The actual common Tetragon installation and reader/bridge executable bytes, source/build closure, service identities, kernel feature support and access to the selected BPF objects. The historical isolated privileged container is not this deployment.
2. Exact gRPC retry/reconnect and UNIX socket permission behavior for the selected build, with same-connection peer custody. Review the relevant grpc-go source/version, not only the CLI flag names.
3. An accounted encoder/output failure path; the upstream ignored write result is a known limit. If patched, retain a successor source/build identity rather than treating the original image signature as a signature for the changed binary.
4. The raw program/map/loss before/after providers and exact metric applicability. Existing missing BPF-missed series cannot become zero.
5. Independent checkpoint/stream verification and later broker pre-effect serialization. An idle ACK alone authorizes no effect. Submitted/unknown state remains indeterminate.

## Proposed bounded ownership and review

The smallest next implementation release is the guarded listener lifetime and accepted transport, after the lifecycle and scheduling contract is frozen. The concrete reader loop follows once its stream binding and checkpoint contract are exact. Keep the existing response/acquisition/store modules unchanged:

- Root: `src/aragorn/native_phase3_run_reader_transport.py`, `src/aragorn/native_phase3_tetragon_reader.py`.
- Root integration: one successor service/profile materializer, its new service entry point/unit, source inventory and fixed credential/spool provisioning. Choose exact paths in the release; do not edit frozen predecessors implicitly.
- A subsequent explicit RUN assignment: an independent checkpoint/stream consumer, once the exact additive schemas above are settled.
- Focused tests: new syscall/pipe/parser/delivery and accepted-transport tests only, with full actual import/fixture/generated-source closure reviewed before coordinator stage registration.

Tests must show that challenge arrival alone never ACKs, idle real-pipe polling can checkpoint, partial lines and undelivered records cannot checkpoint, sustained traffic is bounded, malformed/EOF/bridge-exit/changed-pipe states fail closed, writes/fsync/readbacks precede ACK, and stale/replayed challenge and connection identities refuse. Verify multiple distinct requests through the same held listener, fresh challenge/connection per request, no automatic replacement after a failed request, listener custody checks between requests, and terminal cleanup preserving failures and the socket path. Mocked checks do not establish actual kernel credential delivery, deployment or live loss completeness.

This document records the shortest reusable route and the remaining concrete interfaces. It releases no new lane paths, stage, socket, service start, private retention, cleanup or Phase 3 qualification.
