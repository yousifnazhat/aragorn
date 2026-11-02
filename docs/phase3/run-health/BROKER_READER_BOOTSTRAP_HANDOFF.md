# Fixed broker reader bootstrap — reviewed 69-check delivery

## Current delivery, 29 October

Root reviewed all four corrected source boundaries with independent ownership
and fixture reviewers. The owning RUN worktree safely fast-forwarded from
fc96aed to published signed first schedule
`38ddb2f15c60f63f4a1f29518ca706eabb1edd21`, then correction schedule
`8c0606508d5f10d22ed409214a8148c1b779f1b9`. Its three drafts, unrelated
HTML and retained evidence were preserved. The first three input hashes below
are the complete behavioral closure; runner and worker-lock pins stayed unchanged.

Only `native-broker-reader-bootstrap` ran through scripts/phase3_pipeline.py:

- Initial fingerprint
  `sha256:5b07605a92ef38f655e087517a3dd15c4e532bdf86d9a6cecda2606d49752004`:
  FAIL, exit1, 68 successful methods and one method with two failing subcases.
  Its test pin was c774dc87e1baefe06c74ac1cb9aeec588406e96a340d89ca31990d571b306ef8.
  The late-cancel fixture mutated the first readlink before initial metadata/
  flags were pinned, so altered values became the known cleanup baseline. Root
  and independent diagnosis confirmed this did not test the claimed late change.
- The reviewed fixture-only repair substitutes on the second readlink inside the
  held-resource guard. Original no-read/no-close assertions remain, with explicit
  failure-cause assertions added. Production, registry and other methods did not
  change. The original failed fingerprint was not rerun or erased.
- Corrected fingerprint
  `sha256:8f564bf4208fb8c5c9f5f3719d7fe79e5c6f29eec5c353ae67a8bd51190d4e45`:
  PASS, exit0, all69 methods, 8.371 seconds. Before/after fingerprints match.
  The existing runner selects one module; only this same selected stage ran
  after its genuinely changed test input. No unrelated/historical stage ran.

Both cleanup preflights passed. Root inspected actual outcomes, late-boundary
method results, source pins, result/log hashes and sizes. The original artifacts
remain under this owning worktree's `.aragorn/phase3-pipeline/native-broker-reader-bootstrap/`,
in subdirectories named by the two full fingerprint hex strings above. No cache
was copied to integration or another lane. Each row below is exact bytes / SHA-256:

| Artifact | Initial FAIL | Corrected PASS |
| --- | --- | --- |
| preflight-started.json | 349 / abffa4cbc19fc582f46571478d299e69fa29f120099322000069c412fba59c92 | 349 / 9f367dea329c424a5e5f37c943abf443a5acd74d5d15e3cb64acc44b1c46149a |
| preflight.json | 174 / 4058b33a402d0043550c29303613ded99786afa2fc1b0db219fc46442c45a039 | 174 / 783060ea26d259a667270c4f9b49deb4dbbcdb00920fae7a7c7c06de005fe132 |
| started.json | 213 / 9d10baca97cb4c070cf0d73e6ff1ba4e697ca59d9a88581e60874b940610e7c3 | 213 / 581885a3ee6b423ffd566f0d76d534fb703eb77cbfb25c29427d53fc916a5a20 |
| result.json | 813 / e2d1a7a93ddd8718828824e13bb4bf098cb78879fa2aa7a039433d0e0e848188 | 813 / 75ef62424ef5f18675e900e8c6569b7a2de571c1f61dcf6747e50d29dfbc8b9f |
| stderr.log | 16253 / 01020ddcead9ca3afee8af4f8e29b1d330bddcb571a86a12ac598ab809ebe637 | 13418 / 097b2ffc1920b9748121c247dba2ee3a865198e72b646657d1c822122c2d699b |
| stdout.log | 0 / e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | 0 / e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |

Runner SHA-256: 46163b06a07679d157d1d37b23a8b627ea52fce1e37808753937ebbfd6edee58.
Worker lock SHA-256: 945fd7620689d38962297a61f5e888f3156b90780e7ea8d3bf62a1459d75d0f4.
This is a modeled component PASS, not live/bootstrap deployment, full sensor
health, usable positive enforcement or Phase 3 qualification. No native/live
operation, service activation, historical recapture or private cleanup occurred.
The original signed delivery hash is recorded by Root's integration checkpoint
after committing this exact source, test and handoff; unrelated HTML stays out.

## Original source-only handoff history

Owner: `/Users/yousi/Documents/Commits/aragorn-phase3-run-health`,
`codex/phase3-run-health`. Verified published release:
`fc96aed3ca6018f06a866ca50caf20409a606bc0`, good ED25519 signature.
On 2026-10-28 the owner inspected its branch/worktree and safely fast-forwarded
the existing branch from `f65e8f3b8a79f3ac7251a69f6facc7df89042364`, preserving
all three bootstrap drafts, evidence and the original untracked reader-response-plan.html. No reset,
stash, forced update, replacement/additional worktree or feature push.

Read and acknowledged ownership-and-release-v2.md (Hard coordinator/Mission
rules), provider-release-v12.md, the complete broker-reader-bootstrap-contract-v1.md,
bootstrap-source-review-v1.md including its 59-method successor recheck,
and the common/RUN worktree handoff. Root supplied the exact target; its local
signature and fast-forward ancestry were verified without a remote operation.
The remote observed supervisor PIDFD uses existing
SUPERVISOR_TRANSFER/PEER/closed=false, as Root explicitly clarified; it is never
local ownership. The held guard.sock O_PATH handle uses TRANSIENT/SELF.

Exactly three new assigned write paths:

```text
src/aragorn/native_phase3_broker_reader_bootstrap.py
tests/test_native_phase3_broker_reader_bootstrap.py
docs/phase3/run-health/BROKER_READER_BOOTSTRAP_HANDOFF.md
```

No existing/shared protocol, context, journal, session, transport, service/client,
renderer, unit, activator, source inventory or registry is edited. The bootstrap
is stdlib only; it imports no project/private helpers. Its owning APIs are the
released server, client and one-use configuration transfer; it creates no daemon,
child, helper thread, service framework, arbitrary endpoint or truth callback.

## Named requirement and finite implementation

This drafts the bounded descriptor-bootstrap prerequisite in the existing real
serialized broker/reader/HTTP causal path. It does not close that prerequisite
or the whole path before reviewed focused execution and integration.

The server holds nofollow Root-owned ancestry and separately holds the newly
created pathname endpoint through O_PATH; pathname and sockfs identities remain
distinct. Root binds once at the fixed seqpacket endpoint, refuses existing
paths, applies the exact new endpoint account/mode and never unlinks. The client
holds searchable O_PATH ancestry and the protected named endpoint, creates one
socket and makes one connect call. In-progress connect polls the same socket and
checks SO_ERROR. Both use actual nonblocking/CLOEXEC kernel flags, PASSCRED=1,
PASSPIDFD=0, ordinary requested buffers and actual getter/capacity checks.

HELLO -> HANDLES -> RECEIVED -> RELEASE occurs once under the original startup
cap/minimum deadline. Every packet retains its actual canonical bytes and digest.
Every receive authenticates the native 12-byte per-message credentials and held
socket-derived live PIDFD. The server discovers actual broker proc identity, then
joins Root's independent protected unit/source expectation before any transfer.
Actual bounded stat/status/stat, cmdline, cgroup, executable digest, boot and
held/named mount/time namespaces are retained. The client retains actual self
and kernel connection evidence; inaccessible Root proc/named namespace fields
stay null. Supplied Root start/source bindings never become local observations.

HANDLES transfers exactly cancellation read then supervisor PIDFD, using one
SCM_RIGHTS item. The actual received FD numbers are reported in RECEIVED and Root
independently reads those broker fd/fdinfo associations before closing its sender
copies. Remote roles are explicitly nonowned and never passed to local close.
All actually installed ancillary FDs are recorded before metadata reads, including
malformed inventories, unexpected SCM_PIDFD, duplicate/aliased and low-numbered
handles. Payload integers never confer local ownership. Safe unexpected installed
handles close once; unknown/substituted custody is retained, not guessed safe.

RELEASE consumes separate exclusively transferred readiness-read/provider-PIDFD
copies. It joins the protected ready endpoints, actual provider process and
remote writer fd/fdinfo flags, reads the bounded LF frame with partial retention,
and rejects extra data, premature EOF, changed custody, provider exit or timeout.
A spurious EAGAIN preserves the original budget. Actual guard.sock named/held
metadata is joined separately from the reader listener. Actual provider construction
and bind/listen-before-write remain the loaded Root caller's obligation. Root
rechecks broker/provider/receiver bindings after readiness before sending RELEASE,
then waits for actual connection EOF; a credential-bearing empty packet is not
EOF. No positive authorization or configured-effect success is inferred.

The transfer owner closes the bootstrap connection before returning; one
`take_configuration` rechecks original process/thread/accounts, pipe custody,
liveness and cancellation, closes its other owned handles and transfers exactly
the two descriptors with the fixed configuration fields. Ownership is removed
before return. Root's entrypoint must immediately give these fields to actual
configure_broker_reader_guard, including ownership on configure failure. This
module does not substitute a verifier returning INDETERMINATE for that call.

## Retention, cleanup and limits

Successful observations include bounded raw packet/readiness artifacts and actual
process/credential/PIDFD/file prefixes with base64, length and digest; errors keep
the same actual bytes directly. Initial/latest snapshots per executed edge are
bounded by 16. Every persistent/received/remote descriptor record is retained;
only the latest successfully closed ephemeral proc/executable-read TRANSIENT
record is kept. Raw read prefixes remain in their actual snapshot fields. The
held endpoint/guard TRANSIENT records are not evicted by that consolidation.
Unobserved raw reads stay null. Actual empty EOF is retained as empty bytes, and
recoverable partial fdinfo reads are retained directly in their actual handle row.
A final source review caught and corrected pre-read empty-prefix initialization
before any execution; a focused regression distinguishes null from observed EOF.
This is the frozen bounded supplement, not a complete syscall trace/history.

Original PID/native-thread/saved-account custody is pinned before resource
metadata. Final flags, link, PIDFD association, held identity and owner checks
surround I/O and consumed-once close/detach boundaries. Original interruption and
resource-exhaustion instances survive cleanup findings when available. Socket
objects and unresolved numeric custody remain strongly retained until exit;
one process-lifetime attempt latch prevents reacquisition/retry. A nonblocking
internal claim lock rejects reentry/concurrency without launching a thread.
There is no production reset, reconnect, resend, detach retry, kill or reap API.

Every packet, raw field, handle/snapshot and aggregate artifact retains its
contract bound. The supplement proves neither durable retention nor complete
syscall acquisition. All limitations remain exactly the contract list. Lifecycle
OPENED/RECEIVED/RELEASED is not health, loss completeness, loaded-source
attestation, effect authority, deployment readiness or Phase 3 qualification.
Current missing loss still stays UNKNOWN -> REFUSED/LOSS_UNAVAILABLE. A possibly
submitted effect remains INDETERMINATE; this leaf supplies no submission latch.

## Source-only response to all four coordinator corrections

The earlier 55- and 59-method proposals remain unexecuted. The earlier handoff's
claim that two fixes closed review was incorrect; the signed successor review
identified all four conditions still open. This 69-method draft supersedes that
source proposal, not any retained execution result. Changes are source-reviewed
locally only and await Root review and the first separately scheduled stage:

1. Offer/release reject wrong-owner, wrong-state and reentry before taking any
   new handles, changing owner state or cleaning up existing resources. Once
   entry is accepted, both valid distinct arguments are recorded before clock,
   metadata or argument validation. Malformed/unhashable values do not prevent
   later valid transfers from being retained. Pre-entry refusal fixtures now
   require untouched owner/caller handles; post-entry failure fixtures arm only
   after acceptance. Actual recvmsg ingress still records every installed FD
   before owner/metadata observations, since those handles are already owned.
2. Opening/hello/offer/release observations are assembled before the final slow
   custody guards. Closing guards remain deadline-free for safe cleanup; every
   startup success, including client receipt, subsequently enforces the original
   BOOTTIME deadline and finishes with finite held flags/identity/owner checks.
   Configuration transfer retains its observation-before-final-guards ordering.
   Added fixtures arm after serialization, final closing and final clock seams,
   including descriptor substitution. No deadline or budget is renewed.
3. Ready-frame receipt is sampled directly after the read, before parsing,
   owner/proc/namespace checks or guard.sock acquisition. The LF-completing
   receipt is retained as the actual zero-span READY/SELF snapshot using existing
   timestamp fields; later full snapshots/closing checks are distinct. A frame
   with ready_ns later than actual receipt remains invalid despite later work.
   Actual bytes survive even a receipt-clock failure; no schema field is added.
4. Known PIDFD roles start with association UNKNOWN. Observing the PIDFD link
   classifies it before later metadata; bounded actual fdinfo is required to
   establish association. Unknown or changed association prevents numeric close
   and retains strong quarantine. Fixtures cover pre-configuration metadata
   failure, safe unexpected PIDFD close, unavailable association and late foreign
   association with unchanged anonymous inode/link/flags. All ancillary numbers
   remain owned before the first one's metadata can fail.

Only the three assigned draft paths changed. No API/schema expansion, registry
edit, project import, compilation, AST execution, test/pipeline run or status,
live operation, commit, push or unchanged retry occurred in this source batch.
Admission alone was permitted a focused execution by the coordinator this run.

## Stable actual closure and proposed stage

This update used only static source reads, text edits and hash reads. No project
source was imported, parsed by Python, compiled or executed; no new stage or owning native API was invoked. All tests
fabricate native OS/socket/proc/clock/namespace/PIDFD/pipe boundaries before call.
Lock acquisition is interpreter synchronization; GC/weakref exercises fabricated
owners only. No native service, VM/container, filesystem retention or cleanup.

Exactly three repository behavioral inputs: package initialization, the new
stdlib-only module and its one test. All fixtures are authored inline from the
contract; no historical TestCases, generated source, external files, captures,
HTTP94 bytes or prior caches are read. The single source read is the dependency
check through the inventoried bootstrap.__file__. All other transitives belong
to Python's stdlib/toolchain. Root's runner additionally binds runner, worker
lock, selected stage metadata, toolchain/environment and absolute worktree.
Mutable contract/handoff documents are not behavioral stage inputs.

```json
{
  "id": "native-broker-reader-bootstrap",
  "description": "Mocked fixed authenticated four-message bootstrap, exact FD custody, concrete provider readiness and retained partial failures; no native operation or health authority",
  "tests": ["test_native_phase3_broker_reader_bootstrap"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_broker_reader_bootstrap.py",
    "tests/test_native_phase3_broker_reader_bootstrap.py"
  ],
  "needs": [],
  "timeout_seconds": 120
}
```

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
c7b304e749c27da383570874d5f8094ce6241f3540566e0f262593c9cdd19486  src/aragorn/native_phase3_broker_reader_bootstrap.py
85bdf2af88204a1c4cb231a22e81dc5ee8630c7873d3ccccfc8bfe69a25b7918  tests/test_native_phase3_broker_reader_bootstrap.py
```

Source: 74370 bytes. Test: 82845 bytes. Behavioral closure remains exactly the
initializer, bootstrap module and test above. This document is not a stage input.

29 October coordinator pre-execution review corrected two fixture issues:
Linux errno is now modeled rather than inherited from macOS, and the final
take-configuration clock substitution arms after post-observation supervisor
verification and the following cancel guard. Both corrections passed independent
static re-review. Production and the 69-method inventory are unchanged. The prior
test pin 8e926916d84877532dca0444316d98e8a8c22bc5d0fe65de9a918577981e7a96
was never executed. This fixed-number model does not establish FD numeric-reuse
coverage. The initial test pin and later diagnosed correction are recorded in
the current delivery section; the following inventory is unchanged.

69 mocked methods, all PASS under the current corrected fingerprint above:

- `test_server_all_four_messages_actual_dynamic_receipt_and_ready`
- `test_client_actual_received_fds_one_configuration_transfer`
- `test_client_close_without_take_releases_handles_once`
- `test_process_lifetime_attempt_and_rejected_state_preserve_owner`
- `test_original_startup_cap_and_session_deadline`
- `test_platform_endian_main_thread_and_account_refusals`
- `test_existing_endpoint_is_retained_and_never_modified`
- `test_native_buffer_getters_and_send_capacity_refuse`
- `test_kernel_socket_nonblocking_and_cloexec_override_cached_state`
- `test_peer_kernel_credentials_must_match_protected_accounts`
- `test_peer_pidfd_association_missing_changed_and_exit`
- `test_per_message_missing_duplicate_and_substituted_credentials`
- `test_canonical_duplicate_extra_nonfinite_and_oversize_packets`
- `test_truncation_and_unknown_controls_refuse`
- `test_unexpected_ancillary_fds_are_owned_before_refusal_and_close_once`
- `test_malformed_rights_track_complete_installed_prefix_before_metadata`
- `test_client_rights_inventory_order_alias_and_pidfd_controls`
- `test_protected_unit_source_and_credential_expectation_joins`
- `test_stale_nonce_chain_deadline_and_dynamic_receipt_substitutions`
- `test_send_short_eagain_interruption_and_memory_preserve_attempt`
- `test_provider_ready_partial_reads_and_spurious_eagain`
- `test_ready_eof_extra_frame_missing_lf_and_oversize_preserve_prefix`
- `test_ready_identity_clock_reader_pin_guard_and_timing_substitutions`
- `test_readiness_expectation_endpoints_and_pipe_separation`
- `test_provider_exit_and_deadline_win_queued_readiness`
- `test_cancellation_eof_data_priority_and_spurious_eagain`
- `test_queued_release_with_socket_hup_is_consumed_before_close`
- `test_final_provision_source_profile_credential_and_fd_joins`
- `test_remote_writer_flags_and_pidfd_readbacks_are_actual`
- `test_late_cancel_flag_and_identity_changes_prevent_read_and_close`
- `test_original_owner_change_prevents_foreign_close_and_retains_objects`
- `test_failed_detach_strong_quarantine_and_attempt_poison`
- `test_take_rechecks_cancellation_pidfd_and_process_before_removing_ownership`
- `test_no_project_helper_import_or_historical_fixture_dependency`
- `test_connect_in_progress_is_same_single_attempt_and_so_error_checked`
- `test_native_peer_pidfd_failure_has_no_numeric_pid_fallback`
- `test_successful_raw_observations_are_actual_not_hash_only`
- `test_installed_low_descriptor_is_retained_and_closed_on_inventory_refusal`
- `test_late_deadline_guard_prevents_send_and_retains_original_budget`
- `test_late_pidfd_association_change_prevents_numeric_close`
- `test_cleanup_interruption_preserves_original_instance_and_other_close_attempts`
- `test_readback_failure_keeps_actual_prefix_and_never_claims_source_digest`
- `test_wrong_eof_payload_and_zero_packet_with_credentials_refuse`
- `test_namespace_boot_and_saved_account_readback_changes_refuse`
- `test_wire_deadline_is_original_minimum_without_renewal`
- `test_late_named_namespace_change_prevents_release`
- `test_protected_boot_file_cannot_be_broker_owned_or_group_writable`
- `test_late_owner_change_during_close_readlink_skips_detach_and_close`
- `test_timing_boundary_descriptor_substitution_prevents_actual_file_read`
- `test_failed_socket_profile_getters_remain_actual_failure_observations`
- `test_unknown_oversized_and_boolean_send_returns_are_not_success`
- `test_detach_wrong_return_retains_unknown_number_without_foreign_close`
- `test_client_original_deadline_remains_below_received_session_deadline`
- `test_cancel_fd_and_supervisor_pidfd_cannot_alias_same_argument`
- `test_unobserved_readiness_is_null_but_actual_empty_eof_is_retained`
- `test_ingress_first_invalid_argument_still_retains_later_valid_transfer`
- `test_accepted_entry_owner_failure_retains_both_transferred_arguments`
- `test_received_ancillary_owner_failure_tracks_all_installed_numbers`
- `test_take_serialization_exhausting_original_deadline_cannot_transfer`
- `test_rejected_owner_state_and_reentry_leave_caller_handles_untouched`
- `test_unhashable_first_argument_still_retains_valid_second_transfer`
- `test_accepted_entry_metadata_failure_retains_later_valid_transfer`
- `test_success_observation_deadline_seams_refuse_open_hello_offer_release`
- `test_late_closing_deadline_refuses_offer_release_and_client_receipt`
- `test_post_observation_substitution_cannot_transfer_configuration`
- `test_final_clock_boundary_substitution_cannot_escape_success`
- `test_ready_timestamp_uses_lf_read_not_later_guard_work`
- `test_pidfd_metadata_failure_before_configuration_retains_unknown`
- `test_unexpected_pidfd_requires_actual_association_before_close`

Actual selected command:
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-broker-reader-bootstrap`.
The published schedules and actual outcomes are recorded above. Retain every
actual result/fingerprint; no unchanged failure or historical stage was rerun.

## Preserved evidence, pending assignments and blockers

Integrated DNS original signed `a32477b0b38248f7dca825ec022ad4c0e467558d` and its
actual first 50-check PASS remain unchanged:
`sha256:3b989508ec43b9ab89102eae7723aeefcf5bff8702b1266f21a770099a0bb88c`.
Original result/logs stay in this owning worktree. Completed reader/transport/DNS
builder and fixture-helper results and all earlier failures remain untouched;
none is rerun/copied or relabeled as bootstrap evidence. Original HTML remains
sha256:5d7eaf298adc1aed11434f83dbd3cb3e6506256bacfa62213035a97922830d23.
Operational/private-retention/cleanup holds are unchanged.

Completed: all four requested corrections, source/closure review, one registered
stage, diagnosed fixture repair and reviewed69-method PASS in the owning tree.
Only the exact three assigned paths enter the signed delivery. Root records its
verified original commit and integration/push separately; no completed deployed
requirement is inferred from this component result.

Root still supplies fixed-unit/MainPID/InvocationID/source/credential acquisitions,
actual launch inputs and before/after unit checks; sole writer/reader lineage and
final dynamic process/FD provision; actual session/provider and guard-listener
construction, provider-ready one-write caller, protected source inventory and
original cancellation/supervision handles; lifecycle through the outer broker
result, configure/service/HTTP caller wiring, loaded bridge CLOEXEC/subscription,
complete real loss/program/map and policy/lifecycle providers. Existing context
acquisition remains Admission-owned; destructive/a100 remains Workloads-owned.
None of these is claimed complete from this bounded bootstrap. No additional
worktree or broader source release is requested.

1. Implement/integrate released providers with only newly necessary focused validation.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, genuine a100,
   cancellation, full timing and four actual paired tasks.
3. Close the existing 48-entry path/consumer/source-custody inventory and freeze.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Final qualification remains pending.
