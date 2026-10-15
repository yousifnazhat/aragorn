# Fixed bootstrap: first source review, no execution release

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
