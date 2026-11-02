# Finite reader response — reviewed and focused checks passed

Base: signed combined checkpoint `55a87ea1f7ab3924ade5fa629935ffc03962ba05`.
Branch: `codex/phase3-run-health`. User released this one finite implementation
against coordinator contract v1 and READER_RESPONSE_PLAN.md. The coordinator
confirmed source work and required stable closure review before test scheduling.
Coordinator approved the corrected source and full closure, supplied signed
registry-only parent `1cc410760abddebc4ee4b280ea922e7b3a244c1c`, and scheduled
one selected stage after RUN verified its signature, one-path diff and fast-forward.
Registry SHA-256: `d6cb04908fe9a0099a190561e8798c13e7994c009df05c254e21f4ef9cbd7a57`.
RUN made no registry edit. The first focused run passed; no live operation.

## Lane delta and review boundary

Only three new paths: this handoff, native_phase3_run_reader_response.py and
its mocked test. Existing callers, exports, schemas, fixtures, registry and shared
runtime are read-only. No caller wiring is included; the agreed API returns the
existing reader subrecord or raises ReaderResponseError with partial evidence.
The separate plan HTML remains untracked and untouched.

The leaf validates an exclusively borrowed, preconfigured nonblocking Linux
AF_UNIX/SOCK_SEQPACKET socket and exact SO_PEERCRED plus per-packet credentials.
It reuses open_peer_pidfd/require_live_pidfd unchanged; owns only acquired PIDFD
and namespace descriptors; rejects rights/PIDFD ancillary data after closing all
installed recognized descriptors; never closes or reconfigures the borrowed socket.
Fresh bounded stat/status/fdinfo/boot bytes are retained before parsing, including
reader fixed UID/GID, zero capability vectors and NoNewPrivs. Held time namespace
readbacks reuse the clock helper. Local proc decoding is new behavior because
existing start/status helpers reread without returning the bytes they validate.
The observer's process identity and time domain are bracketed separately. The
caller must invoke from the observer's thread-group leader (native TID == PID),
so the process-level proc/namespace observations bind the calling task; an
arbitrary coordinator worker thread is not an accepted invocation context.

Coordinator review required explicit invocation flag evidence: send_call_flags and
recvmsg_call_flags are recorded before their syscalls, separate from returned
receive_flags, including short/interrupted failures. Success and refusal assertions
cover these fields. All 17 selected checks subsequently passed.

One consume_once call precedes any send and must return exact claim bytes. No
release or retry exists. EAGAIN permits wait/retry before delivery under the same
absolute deadline; interrupted/short/ambiguous sends refuse. recvmsg interruption
refuses; readiness-poll interruption can repeat its remaining-budget wait. ACK
chronology joins actual send-start, independently retained send-return, ACK and
receive; final readback/acceptance must remain before deadline. Complete no-packet
timeout alone emits null ACK/receive and unchanged sequence. Other partial outcomes
raise with original error, cleanup failures and any retention failure. No usable
reader is returned before cleanup and exact retention acknowledgment. Evidence
capacity overflow is explicit refusal with bounded partial evidence, never silent
truncation into success. Kernel proc reads and trusted callbacks do not provide a
hard wall-clock return bound; external supervision remains a shared interface.

Static review parsed source without importing/running it, traced all repository
imports below (including existing test fixture imports), and inspected the consumer
boundary: acquisition_verify imports only progress_verify, not the new leaf or
acquisition producer. There is no new independent syscall-custody verifier. Existing
consumer composition remains a consistency check; mocked composition retains unknown
loss and partial submitted state as INDETERMINATE with authenticity/authority false.

## Exact coordinator-registered stage and checked closure

```json
{
  "id": "native-run-reader-response",
  "description": "Only mocked finite reader exchange, retained partial failures and existing independent acquisition join; no live custody or qualification",
  "tests": [
    "test_native_phase3_run_reader_response"
  ],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_clock_domain.py",
    "src/aragorn/native_phase3_run_acquisition.py",
    "src/aragorn/native_phase3_run_acquisition_verify.py",
    "src/aragorn/native_phase3_run_progress.py",
    "src/aragorn/native_phase3_run_progress_verify.py",
    "src/aragorn/native_phase3_run_reader_response.py",
    "src/aragorn/oci_worker_protocol.py",
    "src/aragorn/runtime_action_broker.py",
    "src/aragorn/runtime_action_decision.py",
    "src/aragorn/runtime_action_observation_publisher.py",
    "src/aragorn/runtime_process_profile.py",
    "tests/test_native_phase3_run_acquisition.py",
    "tests/test_native_phase3_run_reader_response.py"
  ],
  "needs": [],
  "timeout_seconds": 30
}
```

Only the new module is selected. Importing the existing acquisition test fixture
does not schedule its ten historical tests. No prerequisite stages are needed.
The repository closure is 14 files; no external file fixtures or third-party
packages. Standard-library roots: __future__, ast, base64, collections, contextlib,
copy, dataclasses, fcntl, hashlib, inspect, json, logging, math, os, pathlib, re,
secrets, select, socket, stat, struct, sys, threading, time, typing, unicodedata,
unittest (and interpreter-owned transitives). Pipeline additionally binds its own
runner, requirements-worker.lock, interpreter/toolchain and controlled environment.
Contract/plan/handoff are review evidence, not behavior inputs. No shell commands,
socket creation, fork, service, real proc read, real PIDFD or live connection occurs
in these tests; syscall/provider boundaries are mocked before leaf invocation.

Stable reviewed-input SHA-256 inventory (bare hex):

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b  src/aragorn/native_phase3_clock_domain.py
80afdbcab0a4a076712b65db22b091b0a1276ae952ee276a76c1b83ffe06652e  src/aragorn/native_phase3_run_acquisition.py
46d3e86571ae5b9fe9c25e3e96624bc8cbd0473e24ba12c5a83647a17c411113  src/aragorn/native_phase3_run_acquisition_verify.py
18cd904c7dfa32cf537ac9881bc22167cbdcc7442ea32d6c8590e66f8f0f2a2d  src/aragorn/native_phase3_run_progress.py
5537cab55237ed1db873edddd50612cc33fcc98ae0357c6aaf15f2184bdd70cf  src/aragorn/native_phase3_run_progress_verify.py
769cdf49fc380f97048ebe01ca2227b71584b19e8715c76ca2629dee3037d51b  src/aragorn/native_phase3_run_reader_response.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21  src/aragorn/runtime_action_broker.py
3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d  src/aragorn/runtime_action_decision.py
288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90  src/aragorn/runtime_action_observation_publisher.py
a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68  src/aragorn/runtime_process_profile.py
32fbdcc1a708cd11081599819ee339d97139ff340acc41546e6362d1d29d2572  tests/test_native_phase3_run_acquisition.py
159adf04d8b7daa8cb1fa732f83c4d63bbcaeae1abb5df952caa9603132e2b45  tests/test_native_phase3_run_reader_response.py
```

All 17 selected test methods passed:

- `test_acquires_and_retains_actual_readbacks_then_joins_independently`
- `test_socket_preflight_refuses_before_claim_without_mode_mutation`
- `test_sender_must_match_even_while_original_peer_is_alive`
- `test_ancillary_fds_close_before_refusal_even_on_truncation`
- `test_ancillary_rejection_never_closes_unknown_integers`
- `test_claim_is_single_use_and_failed_or_partial_readback_never_sends`
- `test_prequeued_or_expired_inputs_do_not_consume`
- `test_send_eagain_waits_but_short_or_interrupted_send_never_retries`
- `test_receive_wait_retries_keep_budget_and_timeout_has_no_invented_ack`
- `test_pidfd_poll_and_readback_discontinuities_refuse`
- `test_raw_stat_and_status_parsers_refuse_malformed_or_privileged_state`
- `test_ack_framing_pins_and_chronology_refuse`
- `test_late_receive_final_readback_and_rollback_refuse`
- `test_primary_error_survives_cleanup_and_retention_failures`
- `test_retention_ack_must_be_exact_and_is_never_retried`
- `test_input_mutation_and_evidence_capacity_refuse_without_claim`
- `test_changed_post_claim_socket_and_timeout_pending_packet_refuse`

The coordinator reviewed the stable source and this complete closure, registered
one stage in its separate signed parent and explicitly scheduled one execution.
Selected command executed exactly once:
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-reader-response`.
Result: PASS, exit code 0; 17 unittest methods in 0.073 seconds. Retained stage
interval: 0.565558 seconds. Pre/post fingerprints match exactly:
`sha256:f1fab4f0fbe5eb90a0bdfebc731c576ba28f84db04e66d447767cf8150025e8b`.
Retained directory:
`.aragorn/phase3-pipeline/native-run-reader-response/f1fab4f0fbe5eb90a0bdfebc731c576ba28f84db04e66d447767cf8150025e8b/`.
`stderr.log`: 3289 bytes,
`sha256:99d23f5a1d47b05b72ba717ff693c775c5c758a6817acb43ea1a3c2cbbd1486e`.
`stdout.log`: empty, SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
No failed/interrupted attempt occurred, no retries or historical/broad suites ran,
and no retained prior evidence was removed or copied. Reuse this exact success
while its closure remains unchanged; any future failure must remain retained.

Existing exact successes are unaffected and must be reused without rerun/cache copy:

- Progress: `sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`.
- Acquisition: `sha256:c135daacf0473b0d2e80cc6f6ebc4671c429a2a3681c3e51433db46abe057ead`.

## Explicit coordinator interfaces and claim ceilings

Coordinator supplies the protected accepted connection and capability/namespace
custody, durable challenge provider, protected retention provider and actual reader
checkpoint loop. It also supplies genuine sensor/source/program/map/loss bindings,
serialized broker submission state, composition/callers, staging/source pins and
HTTP94 shared repair. No shared module has been edited to manufacture availability.
Returned supplied sensor/source/map fields remain labeled separately from actual
reader/clock observations in supplemental evidence. Authenticated sender identity
does not prove meaningful sensor progress, historical exclusive descriptor custody,
loss completeness or effect authority. An independent custody consumer is still
needed. Post-connect continuation policy remains separate; possible submitted effects
remain INDETERMINATE. No synthetic zero loss or NOT_SUBMITTED is introduced.

## Checkpoint and four remaining steps

Complete: implementation, coordinator source/closure review, separate signed stage
registration and one scheduled focused run. Commit exactly the new source, test and
this handoff with git commit -S; verify git verify-commit HEAD and inspect state.
The post-commit report supplies the signed hash, avoiding a self-referential document.
The coordinator's registry-only parent is outside this three-path lane commit.
Leave the commit local for coordinator integration; original untracked HTML stays.
The October 9 capture/evidence and unresolved cleanup approval are untouched.
No captures, VM/container/service operations or acceptance campaign are authorized.

1. Shared runtime integration and retained-evidence/cleanup hold remain unresolved.
2. Remaining admission/RUN/workload implementation: this finite leaf passed mocked
   checks; real reader/provenance/loss/broker providers and caller wiring remain open.
3. Independent verifier inventory and same-deployment custody/freeze remain pending.
4. Final 31-case and 100-attempt/100-pair acceptance/replay/cleanup remains blocked.
