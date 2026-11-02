# Fixed bootstrap: source review and first focused schedule

## 29 October: corrected 69-check first execution release

This section supersedes the unexecuted 55/59 scheduling holds below; those
historical source reviews and all prior evidence remain intact. Root and two
independent static reviewers checked the v12 contract, all four corrections,
mocked native boundaries and the complete three-file behavioral closure.
No remaining blocker was found in this bounded review. Production is unchanged
from the corrected 69-check submission. Before any execution, Root corrected two test
fixture defects: explicitly model Linux errno instead of host Darwin values,
and arm the configuration-transfer final-clock substitution only after the
post-observation supervisor check and its following cancellation guard finish.
Independent re-review confirmed both repairs without adding/removing methods.

Reviewed inputs (SHA-256):

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
c7b304e749c27da383570874d5f8094ce6241f3540566e0f262593c9cdd19486  src/aragorn/native_phase3_broker_reader_bootstrap.py
c774dc87e1baefe06c74ac1cb9aeec588406e96a340d89ca31990d571b306ef8  tests/test_native_phase3_broker_reader_bootstrap.py
```

Sizes are 78, 74370 and 82316 bytes respectively. All 69 methods are still
unexecuted at registration. The stdlib-only producer imports no other project
module; the sole project-source read is this same inventoried producer. Every
OS/socket/proc/clock/namespace/PIDFD/pipe boundary is modeled. The monotonic
fixture descriptor allocator does not establish numeric-reuse coverage.

Only `native-broker-reader-bootstrap` is appended to the shared registry with
these three inputs, one test module, no prerequisite stages and a 120-second
bound. All 127 prior rows, runner and worker lock remain unchanged. This is the
128th and last row permitted by the current runner; any later capacity change
needs a separate reviewed batch, not a silent extension here.

After this signed schedule is published, the coordinator may safely fast-forward
the existing RUN-health worktree from fc96aed to that exact commit, preserving
its three drafts, unrelated HTML and original evidence. In that owning checkout,
inspect status for this stage only; execute once only if NEW, reuse exact PASS,
and never rerun an unchanged failed/interrupted/timed-out fingerprint. Review
actual results and pre/post input pins before signing exactly the three owned
bootstrap paths. Integrate the original signed ancestry, without copying caches.
No historical tests, broad suite, live operations, installed activation,
private cleanup, health/effect authority or final qualification is released.

## 29 October: diagnosed late-substitution fixture correction

Published first schedule `38ddb2f15c60f63f4a1f29518ca706eabb1edd21` was
fast-forwarded into RUN without changing its drafts. The sole selected stage
ran69 methods at unchanged pre/post fingerprint
`sha256:5b07605a92ef38f655e087517a3dd15c4e532bdf86d9a6cecda2606d49752004`:
68 methods passed and the late-cancel substitution method failed in two subcases.
The actual result/logs/preflight remain in that owning fingerprint directory;
the unchanged failed fingerprint is not released for retry.

Root and independent diagnosis found the fixture changed FD60 on the first
pin_resource readlink, before initial metadata/flags were captured. The altered
values became the baseline, which configuration subsequently refused and cleanup
could safely close. This did not exercise the claimed later custody change.
The minimal correction moves substitution to the second readlink, inside the
held-resource guard. Existing no-read/no-close assertions are preserved; explicit
original-failure assertions now prove late flags/identity guards are reached.
No production code, stage definition, dependency, runner or unrelated test changed.

Reviewed replacement test: 82845 bytes,
`sha256:85bdf2af88204a1c4cb231a22e81dc5ee8630c7873d3ccccfc8bfe69a25b7918`.
Source and initializer retain the first schedule pins. Independent static review
confirmed the cause and repair. After publication and safe RUN fast-forward,
only this same69-method stage may run at its genuinely changed fingerprint;
the existing runner selects modules, not individual methods. No runner extension,
extra stage, broad regression or live operation is authorized. Review actual
outcome before signed delivery; preserve both evidence records separately.

## Historical first source review, no execution release

Reviewed candidate: RUN source 70447 bytes,
`sha256:35a74d79f2b5154caf04c1ff4f18710b937b42bc370c13fd936360cf196dcbe8`;
test 60579 bytes,
`sha256:6bb0d204b7a4315f24e5fc5766b31695903e715387348f667abdc7d3a5dc744f`;
handoff `sha256:abd45bcdc40e8e323798d7a0992fd9b75d694aad9db19da35e0dea58f4e8187c`.
Root read the complete source, owning cases and v12 contract. Independent reviews
confirmed the concrete boundaries below. The 55-method proposal has never run;
there is no bootstrap registry row, actual outcome or PASS to reuse or retry.
Its exact three-file behavioral closure is the initializer, this stdlib-only
module and its test. Existing DNS50 evidence remains unaffected and unchanged.

## Bounded corrections in the existing three assigned paths

1. **Entry and transfer custody.** `offer_handles` and `release` sequentially
   adopt their two arguments; a malformed first argument or an early owner/metadata
   failure leaves the valid later transfer outside ownership. Reject wrong-owner,
   wrong-state and reentry before accepting any new arguments. Once an invocation
   has accepted its one valid entry, register every valid distinct FD supplied
   to that invocation before any fallible metadata, clock or argument validation.
   Do not hash malformed values. Keep existing borrowed/owned aliases distinct;
   an integer in a packet grants no local ownership. Add malformed-first/valid-
   second and late-metadata cases, preserving strong unresolved ownership and
   untouched caller handles on rejected pre-entry calls.
2. **Final configuration transfer.** `take_configuration` builds observation bytes
   after its final deadline-enforcing check. That observation takes another
   non-enforcing clock sample; an expired deadline or changed descriptor at that
   seam can still escape as a configuration. Assemble the actual observation,
   perform blocking PIDFD-association and other slow custody guards before the
   final enforcing BOOTTIME sample, then finish with finite local flags/held
   identity/owner checks immediately before consuming ownership. Preserve
   the original deadline; do not renew it or invent new return-time guarantees.
   Add genuinely late-armed clock and descriptor substitution cases after all
   earlier acquisition/guards have succeeded. The same successful-return defect
   applies to offer/release cleanup: close_resource deliberately disables deadlines
   while preserving cleanup, then observation uses tick(False). Keep cleanup
   possible after expiry, but require the original deadline after all potentially
   blocking closing guards before a successful opening/hello/offer/release/client
   receipt/configuration return. Explicit terminal cleanup is not a new startup
   success. Cover the real late closing seams without historical reruns.
3. **Readiness receipt chronology.** `consume_ready` uses a timestamp acquired
   after parsing, guard.sock acquisition and full proc/namespace guards as the
   ready-frame receipt. Capture immutable actual BOOTTIME immediately after the
   read that completes the LF frame. Require ready_ns <= that actual receipt;
   retain it in the existing actual snapshot/observation structure. Keep the
   later closing guard as a separate deadline check. A frame timestamp after
   actual receipt must not become valid during later work.
4. **PIDFD association before close.** Known PIDFD roles and newly observed
   `anon_inode:[pidfd]` resources must start association-UNKNOWN, never pid=None.
   Set that classification as soon as the actual link is observed, before any
   later fallible metadata. Acquire bounded actual fdinfo association before a
   permitted numeric close; unknown or changed association stays quarantined.
   Cover a failure before configure_pidfd, an actual late same-anon-inode
   substitution, and unexpected ancillary PIDFDs. Preserve every actually
   installed ancillary integer before inspecting the first one's metadata.

These are implementation corrections under the published v12 API, schemas,
account protections, startup/session deadlines and original three-path allowlist.
Do not edit Root service/client, journal, shared acquisition, registry, renderer,
unit, launch or inventories. Retain null for unobserved raw bytes; an actual empty
read remains an observed empty artifact. Cancellation EOF/data/exit/custody loss
wins; readiness followed by EAGAIN is explicitly not cancellation and keeps the
unchanged original budget. Do not replace that rule with event-only cancellation.

Resubmit stable source/test/handoff pins, the complete actual closure and focused
case inventory. Root reviews before publishing the first selected stage. No
project imports, compilation, test execution, historical rerun, cache copying,
live operation, private retention or cleanup is released by this document.
After actual scheduled PASS and Root evidence review, sign/verify exactly the
three assigned paths and hand off the original commit; Root integrates ancestry.

## Unexecuted59-method successor recheck

RUN submitted source71214 bytes,
sha256:22e02a87634dfd8e830bceaf4f261ff6c56cdaaf7b46ad8ecc8fa2837a5adbed;
test65020 bytes,
sha256:205a122ffa3c3cf04fc397dd4f460273b08978eadfd8a96de817ce23c50916c0;
handoff sha256:fa7bad934050814f523869c5195c32234a232fa2e3bee587a02df20cd75058b7.
Independent before/after static review confirms those stable bytes. No execution.
Batch registration and the final take-configuration serialization deadline case
are meaningful progress. The same four corrective conditions remain open:

- Public offer/release still register incoming arguments before enter rejects
  owner/state/reentry; rejected calls must leave existing owner and new caller
  handles untouched. The owner-failure test currently injects before API entry,
  and the wrong-state test expects a newly taken handle. Correct those fixtures
  to distinguish accepted entry from later failure. Actual recvmsg ancillary
  ingress is different: those FDs are already installed and MUST be tracked
  before owner/metadata checks. Preserve that valid ancillary regression.
- Take-configuration's final sample is improved, but opening/hello/offer/release/
  client-receipt successful returns still need deadline enforcement after final
  observations and potentially blocking cleanup. Keep original budgets.
- Ready receipt is still sampled after parsing/guard/socket work; move it to the
  actual LF-completing read boundary and preserve the later closing sample.
- Known/observed PIDFDs still start pid=None; association UNKNOWN and safe close
  semantics remain required before pre-configuration/ancillary refusal cleanup.

Correct the existing same three paths, acknowledge all four conditions and
resubmit stable closure. No bootstrap row/run, historical rerun, shared edit or
new scope is authorized. The first55 and successor59 proposals are both unexecuted.

## Completed, assignments and remaining steps

Completed: source-based review and exact corrective handoff; no execution.
RUN corrects its bootstrap; Admission's first67 context stage/result remains
pending; Workloads corrects its published four custody/fixture defects. Root's
service review/fixes proceed concurrently. Root retains actual protected launch,
HTTP successor/caller, full loss/program/map, lifecycle, destructive and paired
providers. Newer exact checkpoint acknowledgments remain unconfirmed.

1. Implement/integrate released providers with only necessary new focused checks.
2. Wire full HTTP, DNS/destructive, all admission/RUN paths, genuine a100,
   cancellation, full timing and four actual paired tasks.
3. Close the existing 48-entry path/consumer/source-custody inventory and freeze.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs
   on one deployment; independently replay, evaluate the existing gate and verify
   approved cleanup. Qualification and operational holds are unchanged.
