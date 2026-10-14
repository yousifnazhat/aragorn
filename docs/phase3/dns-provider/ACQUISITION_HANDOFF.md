# Bounded DNS acquisition — first focused 50-check PASS

Owner: existing RUN / health lane, `/Users/yousi/Documents/Commits/aragorn-phase3-run-health`,
branch `codex/phase3-run-health`. Exact verified published base:
`c0b99007ed9cdc43dfdf7a9f1a0b1ce4dacd42ac`.
Correction/dependency base: verified signed `722c4794c349acc022dd6a751344408af82f454e`.
Renewed review base: verified signed `34c1f8239d177a267dbdf8c06736976685d23f09`.
First selected schedule: verified signed `a7c771c243aa303d765a18f8ed4860d3e825acc4`;
owner fast-forwarded its own branch preserving all five drafts and the HTML.
Owner fast-forwarded its existing branch preserving all drafts, read and accepted
the complete dns-acquisition-source-review-v1.md and http-fixture-cleanup-handoff.md,
and implemented the six original and seven renewed-review corrections within
the same five paths. No behavioral execution occurred between these reviews.
Owner inspected the branch and worktree, verified the ED25519 commit signature,
fast-forwarded its own existing branch and preserved every draft. No additional
DNS worktree appeared in the read-only inventory. No worktree was created,
replaced, reset or stashed. Owner read ownership-and-release-v2.md,
provider-release-v7.md and the complete unchanged dns-provider-contract-v1.md,
acknowledged exact agreement to Root and began only its five released paths.
The v7 explicit reassignment supersedes the contract's old additional-owner text.

Exact new write paths:

```text
src/aragorn/native_phase3_dns_acquisition.py
src/aragorn/native_phase3_dns_context.py
src/aragorn/native_phase3_dns_acquisition_verify.py
tests/test_native_phase3_dns_acquisition.py
docs/phase3/dns-provider/ACQUISITION_HANDOFF.md
```

No existing transport, DNS builder/verifier, fixture/process/clock helper,
launcher, dispatch, registry or shared source was edited. The integrated original
transport `5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f`, its actual first 30-check PASS
`sha256:b31f41624a6b096e7d009f690f26706c7531f7fd4c1a48a9eccac728ba26b97f` and
original reader-evidence 14-check PASS remain unchanged and were not rerun.
The untracked HTML remains SHA-256
`5d7eaf298adc1aed11434f83dbd3cb3e6506256bacfa62213035a97922830d23`.
The original first-activation evidence, private-retention and cleanup holds remain.

## Concrete implementation and authority limits

`capture_dns_acquisition` is the actual owning caller, with no CLI or arbitrary
provider callback. It receives exclusive cancellation-read ownership before
metadata validation, captures actual held identity, validates the caller's exact
canonical request/pin, enforces Linux little-endian 64-bit root/main-thread and
fixed MSG_DONTWAIT/errno ABI, and observes the kernel release without attesting it.
It reuses `owned_http_fixture` and the existing bounded process/clock helpers.
The fixture alone owns its held network descriptors/PIDFD; this caller snapshots
`session._fds[0:2]` read-only as the contract explicitly directs.

The owner holds both active and child time namespaces. Named/held identity/link,
original process/start/accounts, cancellation flags/link and socket custody are
checked around external reads and operations. It creates one AF_INET/SOCK_DGRAM/
IPPROTO_UDP socket with native nonblocking/CLOEXEC creation flags; checks zero
reuse options, type, family, unconnected state, descriptor and link before one
fixed `127.0.0.1:47632` bind; and checks them afterward. No connect, reuse enable,
alternate bind, fallback, system DNS, canary send or protected action exists.

The before/after snapshots retain bounded actual raw proc/stat/status/cgroup/boot/
time-offset/UDP bytes before interpretation, along with actual structured local
socket and namespace observations. Proc UDP rows match the held inode and exact
fixed endpoint under the frozen layout, preserving a nonzero uint32 drop baseline.
Malformed/missing/conflicting/duplicate rows cannot become zero loss. Drop decrease
and increase are explicit RESET/INCREASED refusals; equality remains only a sample
and cannot exclude an unobserved full wrap. UDP raw observation precedes process
and final offsets within each snapshot, followed by closing metadata guards.

One sample starts after a complete before snapshot and guards, has an absolute
two-second BOOTTIME budget, polls at most 50ms per wait, caps recvmsg calls at 64
and received datagrams at 16, and reserves row/after-snapshot/cleanup document
capacity before another call. Zero-byte and malformed packets remain journaled.
Each call publishes a pending ERROR row before recvmsg and then bounded syscall
facts before classification. EAGAIN is an explicit no-data row; other receive
errors, truncation, unknown flags/controls and non-loopback peers refuse with
retained available bytes. Unsupported controls are never treated as transferred
FDs. A returned result that cannot be published makes accounting unknown. Resource
exhaustion propagates without success and does not promise a recoverable partial.

The public integrated readiness builder supplies the sole query. The first exact
complete nonce query gets one fixed QR/NOERROR sendto with recorded actual count
and clock bracket. Wrong nonce/other packets get no reply. Replay, short/unknown/
would-block/interrupted send refuses and never retries. Receive/send checks stop
at an observed deadline or cancellation; an in-flight syscall/read/cleanup may
return late. No hard-return, client-receipt or post-close absence claim is made.

Cancellation gives pipe readiness priority over simultaneous UDP. A guarded byte
or EOF is consumed once without retaining/interpreting the byte, and no subsequent
datagram receive/send occurs. Spurious EAGAIN resumes the same bounded loop.
Identity/read failures remain explicit. Cleanup rechecks the initially observed
pipe flags/link as well as fstat, including a replacement pipe end sharing inode.
Every started snapshot closes its clock bracket even when its first custody
guard refuses. Cleanup consumes each owned resource once,
detaches the socket once, validates number and current identity, skips unknown or
substituted handles, attempts independent remaining closes and preserves fixed
cleanup codes. Namespace/fixture/cancellation/socket failures cannot produce a
normal sample. Original KeyboardInterrupt/SystemExit and resource exhaustion
survive later cleanup failures with partial bytes/codes when recoverable.
Fixture helper final-guard and descriptor-close notes retain their designated codes.

Failed detach is unresolved custody, not completed release. A single process-local
strong quarantine retains that socket and owner until process exit independently
of exceptions/GC. The first such uncertainty poisons subsequent socket acquisition;
later calls still accept/close their transferred cancellation FD as required. An
exclusive active-owner latch prevents reentrant socket acquisition from bypassing
that bound. No reset, recovery, detach retry, or production quarantine-removal API
exists. Tests isolate only fabricated module state and verify disposal/GC plus
poisoned later acquisition. Successfully detached skipped handles cannot be
destruct-closed. The supplement cannot attest local object/FD lifetime.

`verify_dns_acquisition` imports neither producer/context nor DNS builder/private
parsers. Its independent raw decoder reconstructs the exact query/response,
parenthesized proc identities/root vectors, fixture/cgroup/boot, offsets, namespace,
UDP/socket rows, timing, readiness, cancellation and available journal counters.
It requires independently caller-held request bytes and both expected pins.
It accepts consistent partial/refusal records while refusing unbound bytes,
forged derived fields and unsupported claim promotion. Producer internals are
poisoned in an independence check; handcrafted consumer fixtures are inline and
do not import historical producer fixtures.

Every result remains incomplete: all eleven contract booleans are false,
submission is UNKNOWN and effect disposition INDETERMINATE. A send is not client
readiness; zero queue/equal drops/EAGAIN are not completeness or quiescence.
Returned bytes do not prove durable retention or successful deployment. This
leaf does not emit accepted observation/coverage envelopes or call the existing
DNS coverage verifier to replace missing acquisition.

## Reviewed correction closure, implementation only

1. ERROR receives, fatal flags/controls/peer, readiness replay and failed sends
   forbid later receive/send activity even with unknown counters; the earlier
   successful first response remains verifiable before a later receive failure.
2. Every available call/snapshot/cancellation timestamp (also READ_ERROR and
   IDENTITY_CHANGE) is joined. Null clock-failed endpoints stay unknown; a bare
   clock-error code cannot excuse contradictory known marks. Failure completion
   may follow the after snapshot; actual completed I/O must precede that snapshot.
3. A successful cancellation close requires matching available actual before/after
   identities, even during a wrong-input refusal. Retained socket acquisition plus
   an unsuccessful close requires SOCKET_CLOSE_FAILED.
4. Socket nonblocking/CLOEXEC derives from actual F_GETFL/F_GETFD alongside object
   state, exact original FD number and held identity; cached timeout is insufficient.
5. Custody is closed after empty polls and namespace/socket observations, immediately
   before cancellation read/bind/poll/recv/send, after spurious/read cancellation,
   and by a final identity sample after close-time flag/link observations. Unknown
   or substituted handles are skipped with explicit cleanup failures. These are
   finite point checks, not atomic FD-table or syscall-return guarantees.
6. The bounded strong failed-detach quarantine and poisoned later acquisition keep
   the unresolved owner alive until exit without depending on traceback retention.

Renewed source-review-v2 corrections are also implemented:

- An unresponded first exact readiness query is terminal; later ordinary receives
  cannot be excused by an unrelated refusal code.
- Available sample start, after start, call end or known start, sample completion
  and cancellation marks are joined, including empty and clock-partial samples.
  Missing endpoints remain null; known contradictory marks always refuse. A before
  snapshot with a missing finish still contributes its known start as a lower
  boundary for later snapshots/I/O. Ordered and equal partial boundaries remain
  accepted; reversed known boundaries refuse even when both finishes are missing.
- Recoverable actual sendto/cancellation-read MemoryError partials preserve their
  original exception and EVIDENCE_LIMIT, without allowing unrelated short-count
  or known-errno rows to use that exception as an escape.
- Actual entry PID/native-thread/saved-account vectors are pinned before further
  fallible FD metadata. Unchanged entry custody permits invalid-input FD release;
  changed/unknown custody skips numeric closes and preserves per-resource codes.
  Still-owning unresolved sockets enter the existing bounded strong quarantine.
  Owner checks close external observation and cleanup brackets.
- Cancellation and close-time status/FD flags are sampled again after link reads,
  followed by final held identity and owner checks.
- Relevant operation guards complete before fresh call-start/deadline samples.
  Poll budgets are also recomputed after guard work from the original deadline.
- The GC regression raises fresh unretained detach errors; the failed-send later
  row is an ordinary datagram, avoiding a second readiness-replay rejection cause.

Eight added methods exercise the renewed findings, including the final available-snapshot-boundary correction. Production has no state-reset
API; per-Harness patches isolate fabricated process state only. No live operation,
private retention, helper rerun or schema widening was introduced.

The integrated fixture helper pin above is Root's separately reviewed/tested
repair. Its actual 25-check cleanup fingerprint remains in Root's checkout:
`sha256:eb00a04f5617bf8caac3b558f8e0dab0f7b7491a523409bd4b0eb6e1d18a6c37`.
It has not been run/copied here. This changed dependency is included in the new DNS
closure; historical HTTP/DNS-builder/reader/transport successes remain on their
original closures. No aggregate native-custody or qualification claim follows.

## Stable actual closure and proposed first stage

Before the signed first schedule, only static AST parsing/hash traversal was
performed: no new source/test module was imported, compiled or behaviorally
executed. The first scheduled stage below then executed the actual sources under
mocked native boundaries. No owning API was invoked live. Exactly 14 repository
files are actual transitive inputs,
including package initialization, the public DNS builder, fixture helper and its
private-layout dependency, process/clock and broker transitives, independent
consumer and the one new test. No generated source, external fixture, historical
TestCase, service/config file or runtime data supplies these mocked cases.
The independence test reads the consumer source through its __file__; that exact
source is already an input below. Interpreter-owned standard-library transitives
belong to the toolchain. The new regressions also use gc and weakref solely for
fabricated-object lifetime checks. Root's pipeline additionally binds runner, worker lock,
selected stage metadata, absolute checkout and controlled environment. Mutable
handoff/review documents are not behavioral stage inputs.

```json
{
  "id": "native-dns-acquisition",
  "description": "Mocked fixed owning UDP sample, cancellation, raw journal and independent partial replay; no native operation or complete DNS interval",
  "tests": ["test_native_phase3_dns_acquisition"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_clock_domain.py",
    "src/aragorn/native_phase3_dns_acquisition.py",
    "src/aragorn/native_phase3_dns_acquisition_verify.py",
    "src/aragorn/native_phase3_dns_context.py",
    "src/aragorn/native_phase3_http_canary_contract.py",
    "src/aragorn/native_phase3_http_fixture.py",
    "src/aragorn/native_phase3_workload_dns_canary.py",
    "src/aragorn/oci_worker_protocol.py",
    "src/aragorn/runtime_action_broker.py",
    "src/aragorn/runtime_action_decision.py",
    "src/aragorn/runtime_action_observation_publisher.py",
    "src/aragorn/runtime_process_profile.py",
    "tests/test_native_phase3_dns_acquisition.py"
  ],
  "needs": [],
  "timeout_seconds": 120
}
```

Actual SHA-256 closure and focused method inventory follow; they are stable source
submission, distinct from the actual result fingerprint below. All 50 mocked
methods passed in the first coordinator-scheduled run after source/closure review. Every native OS/socket/proc/
clock/fixture boundary is mocked before invocation. No raw capture, real socket,
pipe, namespace, PIDFD, fixture, container, VM, service or effect is exercised.

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b  src/aragorn/native_phase3_clock_domain.py
df33b2747e5d1b3ef30d8d941eb26076420ac8d1dca96b4ee2ae24ecabecdf83  src/aragorn/native_phase3_dns_acquisition.py
fe2da5e6bee9c478187ad4b0f16a125e0e3466932a137d3cef31694224a47c37  src/aragorn/native_phase3_dns_acquisition_verify.py
b04c45652bd86743c5704a0d42838f7a14f5c0aea877b2ffab0e675422c2fd24  src/aragorn/native_phase3_dns_context.py
bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2  src/aragorn/native_phase3_http_canary_contract.py
caa7ec1bf5ff1f768fe626009fdf208472f169abca539c5374ccf69b0f144f93  src/aragorn/native_phase3_http_fixture.py
dd0cba7a146a1ad3167facc28219576e12fa5d971fd2d0743d41196235c90566  src/aragorn/native_phase3_workload_dns_canary.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21  src/aragorn/runtime_action_broker.py
3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d  src/aragorn/runtime_action_decision.py
288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90  src/aragorn/runtime_action_observation_publisher.py
a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68  src/aragorn/runtime_process_profile.py
72dd5592981c0be8afb702adbeb8805b0dc2c3dacf3fdaa1f4eef746e953be2f  tests/test_native_phase3_dns_acquisition.py
```

- `test_actual_context_one_fixed_bind_deadline_and_owned_cleanup`
- `test_invalid_request_and_descriptor_syntax_consume_only_known_owned_fd`
- `test_request_exact_fields_types_and_caller_pins`
- `test_platform_pointer_endian_and_missing_native_support_refuse`
- `test_root_main_thread_process_and_fixture_substitution_refuse`
- `test_socket_options_name_remote_link_and_bind_failure`
- `test_cancel_pipe_exact_identity_flags_and_anonymous_link`
- `test_nonzero_loss_queue_reset_increase_unknown_and_malformed`
- `test_proc_udp_exact_layout_duplicate_conflict_width_and_bounds`
- `test_journal_zero_byte_malformed_canary_and_would_block_are_not_filtered`
- `test_exact_first_readiness_response_once_without_client_authority`
- `test_readiness_wrong_nonce_and_replay_never_send_twice`
- `test_short_would_block_interrupted_and_unknown_readiness_sends_do_not_retry`
- `test_receive_errors_and_interrupted_unknown_calls_are_journaled`
- `test_truncation_unknown_flags_and_ancillary_preserve_bounded_bytes`
- `test_nonloopback_peer_refuses_after_retaining_payload`
- `test_offsets_parentheses_cgroup_boot_and_namespace_substitutions`
- `test_cancellation_byte_eof_priority_and_no_receive_or_send_after_signal`
- `test_cancellation_before_bind_and_spurious_eagain_or_read_failure`
- `test_poll_failure_and_cancel_error_flags_do_not_receive`
- `test_receive_and_datagram_limits_refuse_without_extra_call`
- `test_document_reserve_refuses_before_receive_and_preserves_partial`
- `test_interruptions_preserve_original_class_and_cleanup_notes`
- `test_substituted_or_unknown_fd_is_not_closed_and_socket_detaches`
- `test_fixture_final_guard_and_close_failure_codes_survive_primary`
- `test_nonmonotonic_clock_and_late_poll_never_receive_after_deadline`
- `test_independent_handcrafted_empty_and_readiness_records`
- `test_consumer_expected_pins_canonical_duplicate_extra_and_literal_flags`
- `test_consumer_rejects_raw_proc_namespace_clock_counter_and_wire_substitutions`
- `test_consumer_independence_and_partial_refusal_reconstruction`
- `test_retired_context_and_fork_during_sampling_cannot_be_reused`
- `test_final_table_read_mutations_are_closed_by_process_clock_and_fd_guards`
- `test_resource_exhaustion_and_cleanup_interruptions_never_return_success`
- `test_detach_failure_retains_uncertain_object_and_never_closes_foreign_number`
- `test_replay_error_rows_require_terminal_refusal_even_with_unknown_counts`
- `test_replay_every_fatal_datagram_and_send_forbids_later_io`
- `test_partial_known_chronology_and_all_cancellation_kinds_are_joined`
- `test_replay_cleanup_requires_matching_actual_close_identities_and_failure_code`
- `test_kernel_flags_and_exact_socket_fd_override_cached_object_state`
- `test_late_empty_poll_namespace_and_readlink_mutations_stop_operations`
- `test_close_readlink_mutation_gets_final_identity_check_and_no_foreign_close`
- `test_failed_detach_quarantine_survives_discard_and_poison_consumes_next_pipe`
- `test_first_unresponded_query_is_terminal_without_inventing_send`
- `test_known_partial_starts_join_sample_finish_and_empty_after_boundary`
- `test_clock_partial_snapshot_available_boundaries_are_ordered`
- `test_send_and_cancel_read_exhaustion_replay_recoverable_original_partials`
- `test_entry_owner_change_skips_detach_and_numeric_closes`
- `test_owner_change_during_terminal_cleanup_or_close_readback_skips_closes`
- `test_flags_changed_during_pipe_link_are_checked_before_read_and_close`
- `test_operation_guard_exhausting_original_deadline_prevents_recv_and_send`

## First actual selected result — retained and Root reviewed

Root reviewed the complete corrected source, 14 actual inputs and 50 methods in
`dns-acquisition-review-and-scheduling-v1.md`, registering only this new stage in
signed published `a7c771c243aa303d765a18f8ed4860d3e825acc4`. Owner verified its
ED25519 signature, fast-forwarded its own existing branch and confirmed source,
fixture and preserved-HTML pins before execution. The selected status command
reported NEW; the selected run executed exactly once:

`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-dns-acquisition`

Actual result: **PASS**, exit 0, **50 tests in 1.221 seconds**. Pre/post fingerprint:
`sha256:3b989508ec43b9ab89102eae7723aeefcf5bff8702b1266f21a770099a0bb88c`.
All fourteen tested source pins remained unchanged. No failure, retry, historical
suite, additional stage, cache copy, fixture cleanup rerun or native operation
occurred. The actual result and logs remain at their original owning-worktree path:

```text
/Users/yousi/Documents/Commits/aragorn-phase3-run-health/.aragorn/phase3-pipeline/native-dns-acquisition/3b989508ec43b9ab89102eae7723aeefcf5bff8702b1266f21a770099a0bb88c/
```

Original retained artifact SHA-256 / byte counts:

```text
e27d4379220187ccdcaffac1eb4e397fde5bbdde25f4334583504ec4b6f8ef80  341  preflight-started.json
ef3ed9a8f4f7696a28f4f439773cff9e708e1c5a3b885fecaa66aa21ad4edff5  174  preflight.json
f0c6c33ea21d9d96a9fbcfb7fe79b0003c6e75ed447455e7c09f0fc3c132f4fe  205  started.json
5172fe7e84f5efe7f3cc12ce671f4b68ff30b9e480a1e60d72617941ec35a66e  804  result.json
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855    0  stdout.log
f4c4f78f5a63bd5d3dfd670f94f6d9da60373f9b1c047fc7b4453e35205b8299 9907  stderr.log
```

Root independently reviewed the actual first PASS, matching pre/post fingerprint,
original result/log hashes and unchanged fourteen source pins, and released the
single signed five-path delivery. No retry or additional validation is needed.
These checks close the reviewed finite leaf/replay failure semantics at mocked
boundaries only. Their successful result is not native source/provider custody,
durable retention, complete telemetry/loss, client readiness, pre-effect blocking,
submission evidence, RUN metrics or Phase 3 qualification. Operational and cleanup
holds remain unchanged.

## Out-of-scope prerequisites and checkpoint

Root retains real pinned launch/source/interpreter/kernel/config custody, distinct
readiness-client receipt/process/PIDFD/clock evidence, actual protected DNS dispatch
and authenticated request/process/cgroup/capability/decision timing, serialized
submission/quiescence/in-flight state, final drain/kernel-arrival observation,
durable retention/readbacks and the independent adapter into accepted DNS
observation/coverage. Root also retains reader/session/shared integration. Workloads
remains available for destructive actions and real a100. No shared change is
proposed as already authorized or implemented by this five-path assignment.

Completed: five-path finite implementation, all original and renewed reviewed
corrections, complete source/import review and the first selected 50-check PASS.
Completed: Root actual-result review and authorization for the single signed
five-path delivery. Owner retains original evidence, stages only these five paths,
creates one git commit -S, verifies with git verify-commit HEAD and inspects the
worktree. The post-commit report supplies the original hash/results/limits.
Pending: coordinator verification/integration of that original local commit;
no feature push or integration-branch change is made by this lane.
Implementation readiness remains distinct from full RUN/DNS and qualification.

1. Implement/integrate ready shared providers with newly scheduled focused validation.
2. Wire full HTTP then DNS/destructive, all admission/RUN, real a100, cancellation,
   full timing and four actual paired tasks.
3. Close the 48-entry path/consumer/source-custody inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases/100 actions/100 pairs on one
   deployment, independently replay, evaluate the existing gate and verify approved cleanup.
