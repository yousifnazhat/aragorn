# B115 — B112 compatibility boot approval packet

**Decision: HOLD. Authorized spend: USD 0. Authorized boot attempts: 0.**
Prepared against signed integration `173de0251af46f87005a00371c074c9619d65dbf`.
This is a decision sheet, not an approval, build seal, private grant, or issued
runner. Signing it in Git grants no authority. No B49 value is assigned here.

**Proposed question:** On the exact nominated host, does this B112 guest
report the expected read-only NVMe disk and partition, 512-byte logical sectors,
root and `/lib` mounts, and PID 1 manager identity? A matching serial record
answers only what the observer reported. It does not establish independent
boot attestation, systemd readiness, sensor health or a successful pilot.

## Four missing B49 bindings

All four private decision records are **missing**. These are four operator
decisions, not four of the eight empty fields in the public B113 request.
The B114 build approval is a separate, later gate. Leave identifiers, people,
quotes, destinations and signed decisions in private custody, not Git or chat.

| B49 binding | Accepted private record | What would resolve it |
|---|---|---|
| `host_nomination` | `null` | Name the asset owner and account/asset reference; specify existing exclusive asset versus proposed acquisition, availability zone, exact regional AMI ID and verified publisher, and permitted isolated management access. After any separately authorized allocation, verify the actual host/instance, exclusive placement, OS/SDK/firmware and required APIs. |
| `budget_and_window` | `null` | Name the billing owner; attach a dated all-in quote and hard USD ceiling including release delays, with an overrun owner. Give allocation start/end UTC, a narrower boot window, earliest release and required release deadline. No estimate is a cap. |
| `evidence_destination` | `null` | Name the independent observer with readback authority, custodian and independent recipient. Specify private fixture ID, distinct fixture/ledger/export roots, a separate off-host namespace and attempt-specific object, access/retention policy and an authenticated channel for the recipient's digest acknowledgment. |
| `cleanup_owner` | `null` | Obtain acceptance from a primary release operator, backup/escalation contact, independent reviewer and lease/billing readback owner. Specify their authority over the fixture, volumes, instance and dedicated host; record prior inventory, retention/disposal policy, release deadline and restoration criteria. |

Each binding requires a signed source reference, who accepted responsibility,
and when (UTC). The [public request](../../../packaging/pi-core/immutable-host-b113/boot-request.json)
proposes an unshared AWS EC2 `mac-m4.metal` Dedicated Host in `us-east-1`,
macOS `27.2.1`, AMI release label `2026.11.18`, using Apple
Virtualization.framework. Its 24-hour minimum is a planning constraint, not a
reservation, current offer, approved window, or quote. The label is not an AMI ID.

## Candidate to review — not an issued runner

| Object | Pinned identity |
|---|---|
| [B112 raw ARM64 disk](../../../packaging/pi-core/immutable-host-b112/media-output.json), 3,595,017,728 bytes | SHA-256 `aae016bd1b7ef412e619bd82adc6cb9b436349fe9bfe48a0a0ba091e8b646cec` |
| Whole unsigned `BOOTAA64.EFI`, 25,274,880 bytes | SHA-256 `7c5d6d5ed501780c352416c0b71f07d0a6d57aa0aa30d0f4fdb3ed6680d766f8` |
| Sole proposed guest db entry (PE/COFF Authenticode hash) | `b4cf97d568d0d060c7a308f287ccb65f0bb122391707c57080ded396e52339a7` |
| [Detached EFI signature list](../../../packaging/pi-core/immutable-host-b113/firmware-proposal.json), 76 bytes | SHA-256 `517294dfd51f6788a7bdc63e3afd2eecdbe918fe12e8ab4cd6d68be273bc5aa4` (not the db entry) |
| [B113 held host runner](../../../packaging/pi-core/immutable-host-b113/runner-output.json) | SHA-256 `a209e62302def49a64e2f47bbc309c4f19a7a4a90bb259ee8063a8a70dac714b`; CDHash `5462f0b7f1035db8c694534b41a70c1ac16a6fc8`. Local ad-hoc integrity signature, not Developer ID or distribution approval. |
| [B114 public build seal](../../../packaging/pi-core/immutable-host-b114/build-seal.json) | SHA-256 `986156f3741639facb6b82dea95dc91573757540f42bb8933e7840d973d3a21f`; `approved: null`. The [B113 release](../../../packaging/pi-core/immutable-host-b113/owner-release.json) has an empty attempt list. There is no issued B114 catalog or executable from this campaign. |

## Separate decisions, in order

1. **Nomination, funding and transfer — not approved.** Complete the four
   private records. If acquisition is needed, obtain a scoped purchase
   decision before allocating anything. Verify the assigned asset and budget
   against that decision. Media transfer must be explicitly covered.
2. **Guest-store enrollment — not approved.** Obtain separate permission for
   one fresh private **guest** EFI store on that host. Pin the prior state,
   signing/distribution policy, complete nonempty KEK/dbx baselines and source
   and date of revocations. Require Secure Boot enabled, db containing only the
   proposed Authenticode digest (not the whole-file or ESL hash), no conflicting
   revocation, and readback of the same store identity, whole-store digest and
   canonical policy. No broad default allowlist. If byte-level PK readback is
   mandatory, stop: the selected interface cannot provide it.
3. **One-time release and compatibility attempt — not approved.** Independently
   authenticate the original nomination, enrollment and boot decisions. Only
   then could an operator sign a distinct B114 prebuild seal binding their
   three digests and the canonical private release digest. One fresh UUID must
   bind the exact host, fixture, disk/store identities, policy and half-open UTC
   window. Pin the issued receipt in a separately signed descendant commit;
   verify the distributed executable against it and retain the independent
   pre-attempt record before START. Do not substitute the held runner, use B50
   approval records, or create an attempt ID to fill out this packet.
4. **Evidence, stop and reconciliation.** The permitted future graph is 2 CPUs,
   4 GiB, one read-only NVMe disk and one output-only serial port; no network,
   guest serial input, host shares, sockets, extra media or writable overlay.
   Arm the bounded recorder, stop observer and external watchdog first. Limits
   are 180 s run + 15 s graceful stop + 15 s force-stop wait (absolute
   +180/+195/+210 s); serial capture at **8 MiB equality is indeterminate**.
   No automatic retries. Preserve original serial bytes, owner journal,
   watchdog decision and terminal records, including partial failures. Verify
   the archive at the independent destination against its nominated digest.
   Prove same-VM stop, closed handles, unchanged disk and accounted-for store;
   reconcile restoration, instance/volumes, Dedicated Host release and final
   billing separately. Host loss or ambiguity means preserve and reconcile,
   not retry or dispose. Provider, pilot and Phase 3 acceptance remain excluded.

For each future gate keep a **separate private decision slip**: approve /
decline / defer; scope and exclusions; candidate and evidence references;
allowed spend, effective and expiry UTC; approver's authority, signature and
decision time. A missing or mismatched record leaves that gate closed.

**Evidence boundary:** See the [B114 builder/replay checkpoint](pi-core-b112-single-use-release-batch-114.md)
for the already-verified engineering work. This packet changes no code, pins,
private records, or behavior and produces no boot evidence.
