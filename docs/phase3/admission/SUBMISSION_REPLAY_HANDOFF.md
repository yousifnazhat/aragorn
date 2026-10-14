# Independent broker submission replay — reviewed focused PASS

Base: verified signed published `95b676eca174ae5cb117fe778d3359f0e924b425`.
The owner fast-forwarded the existing `codex/phase3-admission` branch without
conflicts, preserving `.lavish/` and `ADM03_NATIVE_MAP.md`. Accepted ownership-v2,
provider-release-v4 and `broker-reader-provider-contract-v1.md`. This delivery
changes only the assigned independent verifier, test and this handoff. Root's
codec/journal and its original 28-test PASS remain unchanged. Integrated original
policy-tamper `d3c5ffed8dbbf0520c9b8d2e9d798e204d09f96d` is not rerun or reimplemented.
The owner subsequently verified signed published
`c0b99007ed9cdc43dfdf7a9f1a0b1ce4dacd42ac` and fast-forwarded without conflicts.
Root's `submission-replay-review-and-scheduling-v1.md` approved the complete
three-file closure and all 33 independently authored cases. All three source
pins below matched before the one explicitly scheduled owning-worktree run.

## Stable source and actual complete dependency closure

SHA-256 values omit the `sha256:` prefix. This is the complete repository
behavioral input closure of the registered focused stage:

| Path | Bytes | SHA-256 |
| --- | ---: | --- |
| `src/aragorn/native_phase3_run_submission_verify.py` | 18165 | `277f090094e8335850605c5ee793042cafc831764c24a136fddb1b277cf335a7` |
| `tests/test_native_phase3_run_submission_verify.py` | 29025 | `616258ca1bba22b1e9d6c7d1a619b690f46b0a9594cc1f36ad9afc40ffe1c8a1` |
| `src/aragorn/__init__.py` | 78 | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |

Verifier imports only `__future__`, `base64`, `hashlib`, `json` and `re`.
Tests import only the public independent verifier API and stdlib `base64`, `copy`,
`hashlib`, `json`, `unittest`. All fixture bytes are authored in the new test module
from the published contract. No producer codec, journal, parser, fixture or other
runtime module is imported, executed or used to generate expected records. No
generated source, external fixture, file read or installed-source dependency is
used by the tests. The package initializer above has no imports.

The pipeline automatically binds its runner, `requirements-worker.lock`, selected
registry metadata, interpreter/toolchain and environment. The handoff and contract
are review references, not behaviorally read inputs. No cache is copied. No
historical successful result is being substituted for this new implementation.

## Independent API and enforced semantics

```python
verify_submission_transcript(
    context_raw: bytes, events_raw: list[bytes], packets: dict[str, bytes],
    *, expected_context_digest: str, expected_request_digest: str,
    expected_broker: dict, expected_provider: dict, expected_clock: dict,
    expected_terminal_digest: str | None,
) -> dict
```

Invalid input raises `ValueError`. The verifier performs no OS reads/writes,
socket operations, callbacks, clocks, native effects or retention. It validates
canonical ASCII JSON, duplicates/nonfinite/trailing bytes, exact schemas, strict
integers, caller-held context/request/process/clock joins, nonce/pin syntax and
preparse individual/aggregate byte bounds. The raw aggregate is counted once as
context + event bytes + unique packet-map value bytes, capped at 786432.

Context replay independently reconstructs the original remaining monotonic budget,
the exact BOOTTIME wire deadline, accepted/bracket/BOUND chronology, positive
non-root broker and root provider identities. It cannot attest that those values
were actually read in one process or that a float deadline was originally converted
correctly before serialization. Those are owning acquisition responsibilities.

Every event must follow the six-phase graph and sequential previous-byte hashes.
Only checked phases reference their required request/response pair; only terminal
can reference opaque bounded canonical transport bytes and a failure class. All
packets must be referenced and independently hash to their map keys. At most two
checked pairs and one transport artifact can occur. Complete non-null expected
terminal pins require the actual final TERMINAL event and exact digest.

Each packet independently checks its exact schema/phase/echoes, original request
digest, wire deadline, reader bindings, canonical base64/length/digest artifacts,
retention receipt and all five literal-false claim flags. EVIDENCE requires complete
artifacts/receipt. REFUSED can preserve ACK-shaped partial evidence with unavailable
items null; neither shape releases intent. Reader evidence/summary/checkpoint
remain opaque matching bytes. The loss object is independently parsed for its
frozen shape, pins, samples and nullable counters.

Checked responses must fit the context bracket, phase cap, event bracket and wire
deadline, and be younger than 200 ms at both check and intent. Phase-two receipt
must follow connect intent; reader evidence/summary/bindings/connection/receipt
remain identical, and a present phase-two loss record preserves the original
before sample. Every present after-loss sample fits its own fresh response interval.
Intent requires EVIDENCE with both loss samples, all counters known and unchanged.
Missing/reset/increased loss can be retained as a checked observation but cannot
justify a subsequent intent.

Output has exactly the nine contract keys. A verified connect intent yields
SUBMITTED throughout later refusal, timeout, terminal or opaque transport claims.
Otherwise replay yields UNKNOWN, including terminal before intent. No retained
transcript yields NOT_SUBMITTED. The five authenticity/health/authorization/
qualification flags always remain false. No OS-lock attestation is added.

Root accepted both conservative interpretations: a null expected
terminal pin permits only OPEN_PREFIX analysis even if the candidate includes a
terminal event; a phase-two REFUSED record may omit unavailable loss but must keep
the immutable reader fields, and cannot justify payload intent. These do not
promote completion, health or nonsubmission. No source changes were required
after the reviewed stable-hash submission.

## Focused independent cases

The test module contains 33 independently authored methods:

1. Complete terminal record and exact false-flag output inventory.
2. Every open prefix, UNKNOWN before intent and SUBMITTED after intent.
3. Terminal after each phase with conservative classification.
4. Unpinned terminal permits prefix analysis only.
5. Missing terminal and substituted expected terminal digest.
6. External context/request/process/clock pin substitutions.
7. Exact context fields, nonce, accounts, PID/start and namespace bounds.
8. Exact monotonic/BOOTTIME budget and accepted/bracket/BOUND chronology.
9. Event chain, sequence, phase order and unknown fields.
10. Nondecreasing event time, strict integers and nonterminal deadline.
11. Late terminal retains submitted ambiguity.
12. Packet echoes, context/effect/request/deadline and previous-response substitution.
13. Missing/altered packet pins and unreferenced extras.
14. Response status/error ordering and all five false flags.
15. REFUSED ACK-shaped partial evidence and failed retention cannot release intent.
16. Entirely unavailable REFUSED evidence stays UNKNOWN.
17. Required EVIDENCE artifacts and retention receipt joins.
18. Artifact base64/pad bits/decoded size/length/digest/extra-field refusals.
19. Loss pins, shapes, sample times and nullable counter lengths/types.
20. Unknown/reset/increased counts preserved at check but rejected at intent.
21. Phase-two reader/connection/receipt and loss-baseline substitution.
22. Payload refusal with unavailable loss preserves SUBMITTED.
23. Payload loss reset prevents payload intent without downgrading submission.
24. Response sampled before connect intent refuses.
25. Fresh after-loss samples required within each phase response bracket.
26. Phase duration boundary, deadline and 200 ms staleness.
27. Intent/effect-possible cannot downgrade or use numeric Boolean substitutes.
28. Terminal error enum, null-success preconditions and opaque transport.
29. Nonterminal packet/terminal-field misuse.
30. Opaque transport claims cannot attest health, custody or nonsubmission;
    unsolicited wire credential ABI fields refuse.
31. Duplicate/nonfinite/noncanonical/non-ASCII/trailing JSON.
32. Individual raw bounds, event/packet counts and complete aggregate bound.
33. Inputs remain unchanged during replay.

Native FD custody, fdinfo locks, immutable file/fsync/readback ordering, fork/thread
ownership, descriptor cleanup and failed publication belong to Root's producer
and cannot be reconstructed from this API. Their original checks are not repeated.
Missing/partial journals are represented here by pinned completeness refusal or
conservative prefix classification; no absent file or unobserved intent attempt
is treated as proof of nonsubmission.

## Registered and scheduled focused stage

```json
{
  "id": "native-run-submission-replay",
  "description": "33 independent fabricated-byte broker submission replay checks; no producer imports, native custody, health or qualification authority",
  "tests": ["test_native_phase3_run_submission_verify"],
  "inputs": [
    "src/aragorn/__init__.py",
    "src/aragorn/native_phase3_run_submission_verify.py",
    "tests/test_native_phase3_run_submission_verify.py"
  ],
  "needs": [],
  "timeout_seconds": 120
}
```

The owner inspected the stage's cache locations in both this worktree and the
integration checkout: neither had a prior result. Selected status was `NEW`,
with no dependency stages. The one scheduled command was:
`/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-submission-replay`.
No unchanged Root broker check, policy-tamper check or historical suite was run.

## Actual retained result and signed delivery

PASS: 33 independent fabricated-byte tests in 0.044 seconds, exit 0. Equal
pre/post fingerprint:
`sha256:913ead583dc4eff79e8b3986d89b1d0e85e86972cb173c2771737c96a20138d9`.
Original result/logs remain in this owning worktree under
`.aragorn/phase3-pipeline/native-run-submission-replay/913ead583dc4eff79e8b3986d89b1d0e85e86972cb173c2771737c96a20138d9/`.

| Actual artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `result.json` | 810 | `8ae24aba65a79e7c407979116b544d8e81bcb6be9ad120f8d725861e345386f2` |
| `stderr.log` | 6105 | `9e3a96640e9fb1aeba1aecd4ac5d918898c5a69ec5c3e47902cfc735e7b395bc` |
| `stdout.log` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The actual status, stage ID, exit code, equal fingerprints and both log lengths/
digests were verified against retained bytes. The complete stderr lists all 33
individual `ok` outcomes and the unittest `OK` summary. No failure, retry, cache
copy, native operation, private retention or cleanup occurred. This PASS validates
independent bounded replay behavior over fabricated bytes, not actual producer
composition, native acquisition or OS/source custody.

The signed batch contains exactly the independent verifier, its test and this
handoff. The original commit hash and `git verify-commit` outcome are reported
separately to avoid a self-referential commit claim. Root remains sole integrator/
pusher. Existing drafts, original passing evidence and operational holds remain.

## Missing shared evidence and blockers

- Independently acquired accepted request/effect/grant/deployment/epoch context,
  broker/provider PID/start/accounts, boot/time namespace, original accepted stamp,
  monotonic/BOOTTIME bracket and unextended original deadline are required.
  Matching serialized values alone do not authenticate their provenance.
- Actual root/broker IPC service/client, per-message kernel credentials, socket
  provisioning, held PIDFD/process/namespace/source identity and durable custody
  are outside this retained schema. The replay API has no fdinfo/lock descriptors
  or complete reader/runtime identities; OS lock ownership and account separation
  from those independently provisioned actors remain external obligations.
- Real reader/bridge/sensor launch custody and checkpoint semantics, independent
  reader replay, ACK age and refresh, program/map/loss scope membership/order and
  complete acquired before/after counts remain prerequisites for authorization.
- Root must wire replay-consumed request/grant, actual protected acquisition,
  journal intent publication before each broker callback permits effects, current
  policy/revocation checks, conservative attempted-intent/cleanup propagation and
  full REQUEST_ACCEPTED → DECISION_FINALIZED timing. Opaque HTTP status cannot
  certify effect absence. No composition with actual producer output is claimed
  by these independent fabricated fixtures.
- Admission's protected policy request/decision/subject/source joins and fresh
  installed config/Node pins, retained admitted bytes and catalog state, separate
  target-absence custody, and restart INITIAL/BOUNDARY/AFTER lifecycle acquisition
  with exact clock/trace mappings remain Root provider obligations. This released
  support assignment does not change their source ownership or claim closure.

Completed: independently implemented source/test, reviewed actual complete closure
and accepted interpretations, and the single scheduled 33-test PASS. Released:
these three files only; this signed handoff is ready for original-commit integration.
Later route/provider assignments still require published concrete contracts and
exact paths. Historical passes and the unresolved fixture-cleanup hold are preserved.

1. Implement and integrate ready shared providers with only newly scheduled focused validation.
2. Wire the full HTTP causal path, then DNS/destructive actions, all admission/RUN paths,
   cancellation, full timing and four actual paired tasks.
3. Close the 48-entry path/consumer/source-custody inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs on one
   deployment; independently replay, evaluate the existing gate and verify approved cleanup.
