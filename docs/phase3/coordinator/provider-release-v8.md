# Connected reader writer and Root session: internal implementation release

Review base: verified signed and remote-matched
`0d61902277f35b3186d72d052bfb171ef3039f3d`. This document becomes a source release
only in its containing signed published checkpoint, whose exact hash Root supplies.
Read `reader-session-contract-v1.md` together with the frozen checkpoint,
transport, reader evidence and broker contracts. No new execution is scheduled.

## Exact owners and paths

Root delegates two bounded assignments in the coordinator worktree. These are
internal owners sharing Root's existing branch, not replacement lane worktrees.
They must not change the index, create commits, switch branches, move worktrees
or execute project code. Root alone integrates their reviewed source and evidence.

| Internal owner | Exact writable paths |
| --- | --- |
| `reader_store_implementation` | `src/aragorn/native_phase3_run_reader_checkpoint.py`, `tests/test_native_phase3_run_reader_checkpoint.py` |
| `coverage_ledger` | `src/aragorn/native_phase3_run_reader_checkpoint_session.py`, `tests/test_native_phase3_run_reader_checkpoint_session.py` |

`provider_path_review` independently reviews both implementations and their real
dependency closure without editing either owner's files. Root owns the contract,
registry, scheduling, `docs/phase3/coordinator/reader-session-handoff.md`, source
inventories and every shared integration file. No existing source module or frozen
test is released for modification. Report concrete incompatibilities before any
scope expansion. The original design draft is preserved separately.

The writer owns actual bounded telemetry consumption, immutable publication,
original challenge response and refresh handling. The session owns the actual
listener, independent owned-reader replay, protected checkpoint acquisition and
independent checkpoint replay. Both implementations must call the real reviewed
public APIs with actual returned bytes. No injected evidence/health provider,
standalone manifest builder or synthetic responder completes this assignment.

## Reviewed decisions and evidence limits

Root approves the contract's syntax-only NDJSON preservation, previous-manifest
chain, separately provisioned FD8 completion notice and supervisor-owned FD7 EOF
cancellation. The restricted reader receives no Root archive/store access. Full
epoch/stream/source pins remain protected caller inputs; neither self-hashing
arguments nor a candidate upstream commit establishes installed identities.

The contract supersedes only the earlier unreleased process-parser writer
direction and proposed future FD ownership. Every implemented checkpoint artifact,
reader challenge/ACK, transport supplement and broker packet schema stays frozen.
Preserve raw valid JSON-object variants unchanged. Independent checkpoint replay
checks framing and custody-record consistency, not vendor semantics or JSON syntax.
Upstream continuity and complete loss remain UNKNOWN; missing loss still forces
the later service to refuse a positive evidence response.

Contract review resolved the ACK/peer-close race: keep the reader socket alive
after its one ACK until Root closes, servicing telemetry and cancellation under
the original outer request/ACK-age/session bounds. Root close is a lifecycle
observation, not proof of successful retention. Also retain startup/opening raw
evidence and Root's actual completion receipt stamp; no producer timestamp may
substitute for that observation. Failed detach leaves unresolved ownership held
by the supervising session/error, never silently garbage-collected or retried.

The separately reviewed fixed launcher must supply actual process/source/pipe
provisioning and protected pins. Root's reserved broker service is the next
production caller. This release does not claim either exists or silently assign
their paths. Root continues their concrete contracts and wiring while these
owners implement; the two leaves must be joined before reporting a connected
path. No full timing, native authenticity, health, effect authority, RUN or Phase 3
qualification follows from this source release or a later mocked PASS.

## Review, selected validation and integration

Before execution each owner supplies stable hashes, the complete actual
project/standard-library/import/generated/fixture closure and focused cases.
Review both directions of the shared schemas and production-call ordering,
including idle/nonempty input, partial tails, all-event preservation, ACK close,
original-ACK refresh, identity changes, cancellation, immutable partial residue
and submitted ambiguity. Test only fabricated OS primitives; no live socket or
protected storage operation is authorized during development.

Root reviews stable source, registers only the newly necessary focused stage and
publishes its exact schedule. Run it only in this coordinator worktree using
`/opt/homebrew/bin/python3.12`. Retain every actual result/fingerprint. No historical
suite, unchanged retry, cache copy, live operation, private retention or cleanup.
Reuse the unaffected transport 30, checkpoint 53, broker 28, DNS 13 and HTTP
evidence. A contract change alone does not warrant repeating those checks.

After reviewed PASS, Root stages only exact assigned source/tests/handoff and
reviewed coordinator records, signs and verifies one checkpoint, pushes normally
and verifies the remote tip. Original signed lane commits remain ancestors.

Completed: signed RUN transport integration and next connected contract review.
Released: the two internal assignments above; external RUN keeps v7's five DNS
paths. Admission's scheduled replay result and Workloads' destructive/a100 design
remain pending. No additional worktree is requested. Blockers: these actual
implementations plus launcher/service/bridge/loss/source custody and remaining
requirement paths. Receipt/agreement is recorded separately from publication.

1. Implement and integrate ready providers/consumers with selected focused checks.
2. Wire full HTTP/DNS/destructive, admission/RUN, real a100, cancellation, full
   timing and four actual paired tasks.
3. Close all 48 paths/consumers/source-custody conditions and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs;
   independently replay, evaluate the existing gate and verify approved cleanup.
