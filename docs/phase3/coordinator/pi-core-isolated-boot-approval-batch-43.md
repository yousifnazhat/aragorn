# D2 batch 43 — dedicated ARM64 backend and isolated boot request

Base: signed merge `4edda15fd95d5531098e92438f91be64ee387314`. **Prepared for
review; no host allocated, media transferred, firmware enrolled or VM started.**
The [request](../../../packaging/pi-core/immutable-host-b43/boot-request.json)
is inert. Its empty private bindings are blockers, not defaults.

## Candidate, price and custody

Select an [EC2 M4 Mac Dedicated Host](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-mac-instances.html),
`mac-m4.metal` (ARM64 bare metal), in [US East (N. Virginia)](https://aws.amazon.com/about-aws/whats-new/2025/09/amazon-ec2-m4-pro-mac-instances-generally-available/).
Use Apple's Virtualization.framework directly on the Mac, with the AWS
[macOS 27.2.1 AMI release dated 2026.11.18](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/macos-ami-overview.html),
not a moving latest alias. The Mac is the physical host; the Linux guest is a
private VZ fixture, not a second EC2 instance. No account, AZ capacity, Host ID,
regional AMI ID, installed OS build or actual target API was inspected.

The [AWS regional price list](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20261118220254/us-east-1/index.csv)
lists On-Demand host SKU `J55GDGNX36ANHZ9M` at **USD 1.23/hour**. At the
[24-hour minimum](https://aws.amazon.com/ec2/instance-types/mac/faqs/) that is
**USD 29.52 for the host alone**; EBS, transfers, taxes and additional hours
are not included. Confirm a current quote before purchase. Stopping the guest
is not release of the billed Dedicated Host. A budget alert is not a spending cap.

## What the offline preview measured

The [host preview](../../../packaging/pi-core/immutable-host-b43/boot-config-preview.m)
assembled and read back an EFI configuration **without a variable store or VM
instance** on the existing 26.6.2 ARM64 Mac: two CPUs, 4 GiB, one read-only
NVMe attachment backed by the retained raw file and one output-only serial
pipe. Guest serial input, networking, shares, sockets, graphics, other boot
devices and writable overlays are absent. It did not recompute unchanged media
or validate a bootable target. All four target firmware selectors were absent
locally. This demonstration cannot stand in for the signed runner and actual
target validation on macOS 27.

## Gates for an operator — approve each separately

1. **Nominate and bind a host; no enrollment or boot.** First decide whether
   the compatibility-only outcome below is useful. Privately identify the
   account/asset owner and release owner, all-in spending ceiling, allocation
   window, isolated management access and least-privilege operators. If an
   already-owned dedicated Mac is available, propose its name and equivalent
   OS/firmware profile for review instead of purchasing. After explicit
   acquisition/transfer authority, record the unshared Host ID, AZ, actual
   region-specific ARM64 AMI ID and verified AWS publisher, host OS/SDK build,
   firmware and signed runner identity with the
   [virtualization entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.virtualization).
   Verify VZ support and all required selectors on the named host. No host/guest
   keys, credentials or private identifiers belong in Git. Bind the fixture
   ID, fresh private store path, evidence owner/destination and cleanup scope.
   After controlled transfer, verify the full raw disk, its EFI bytes and the
   detached ESL against [B41](pi-core-immutable-guest-image-batch-41.md) and
   [B42](pi-core-firmware-trust-batch-42.md); seal the single-link disk
   read-only under private custody. Refuse on any mismatch.
2. **Approve guest-store enrollment only.** No host firmware changes, host
   OS updates, template stores, broad default allowlists or removal of
   revocations. Use a fresh VM-specific store. Record its before-state and
   the operator-approved PK policy, exact KEK/db baseline and current forbidden
   entries. Empty dbx is not evidence that revocations are current. Propose
   Apple's guest-managed default platform key and an allow database containing
   only the B42 image hash. Apple's
   [enrollment API](https://developer.apple.com/documentation/virtualization/vzefivariablestore/enrollsecurebootsignatures%28_%3A%29)
   adds entries; it does not replace an existing broad allowlist. In the
   [signature database configuration](https://developer.apple.com/documentation/virtualization/vzefisignaturedatabaseconfiguration),
   supply the 32-byte PE/COFF digest in db, not its ASCII hex, the whole EFI file
   digest or the 76-byte ESL as a digest. Keep the separate whole-file check.
   On reopening the same store, compare the
   [enabled flag](https://developer.apple.com/documentation/virtualization/vzefivariablestore/issecurebootenabled)
   and **all** [enrolled KEK, db and dbx entries](https://developer.apple.com/documentation/virtualization/vzefivariablestore/enrolledsecurebootsignatures)
   to approved post-state (signature type plus exact digest or certificate
   DER). Require Secure Boot enabled, exact allow set and no revocation conflict;
   reject unexpected, unknown or missing authorities. These getters do not
   attest PK bytes, ESL owner GUID, SetupMode or that firmware accepted a
   particular boot. If policy requires proof unavailable through these
   interfaces, stop. Keep a private receipt of baseline, delta and readback;
   validate the exact bound VZ configuration without starting it.
3. **Approve at most one isolated compatibility boot**, only after reviewing
   the preceding receipts, objective and observer. Bind the same runner, store,
   disk and device graph to this one attempt; exclude networking, metadata,
   serial input, shared storage and alternative boot paths. Proposed bounds:
   180 s monotonic watchdog, 8 MiB serial cap, then 15 s graceful stop and 15 s
   for a permitted force-stop. On limit or ambiguity stop, preserve partial
   bytes and timestamps, and label the result indeterminate; no second boot,
   effect retry or substitution. Verify VM stopped, handles closed, sealed
   disk digest unchanged, unrelated resources untouched, evidence export
   acknowledged and temporary store/fixture disposed of per explicit retention
   policy. Reconcile host/volume release and billing after the minimum period.
   If a resource cannot be stopped/released, leave its identity with the owner;
   do not claim cleanup. No provider, user key, application pilot or D5 campaign.

**Observation decision before spending.** B41 checks both whole-disk and
partition-2 read-only flags, 512-byte logical sectors, partition length,
SquashFS content and padding, the read-only library bind and pinned manager.
Its [init](../../../packaging/pi-core/immutable-host-b41/boot-init.c) emits
failure messages, not positive per-check or post-exec PID 1 receipts. Its
locked command line does not select the VZ serial console. A host start event,
silence or timeout cannot establish any of those guest properties. **Recommend
deferring a paid boot** unless a suitable independent observation path is
validated, or a separately reviewed observable successor is built and its
changed disk/UKI/firmware pins approved. Otherwise explicitly approve only a
compatibility experiment with a possible indeterminate result; do not modify
the retained command line or attempt a write to prove read-only behavior.

## Focused developer evidence

| Stage | Checks on passing fingerprint | Fingerprint |
|---|---:|---|
| Isolated request, native preview and wrong-file/symlink refusals | 3 | `9be443a8639f83848a6ab5de2d0c66bf7826334d323c41f3b7cdbddccb115321` |
| Exact registry capacity (262 → 263), duplicate and cycle guards | 4 | `ca53762c032bd9ad9e5b89bc13aea13772c4383ef3cb25667c73dadb338cab10` |

Two preview failures remain in the ledger: `bcfd2598704a4fbe37a3511cf7f4c529b5df9701338e1e3fa6a01b19ff140992`
(SDK requires designated initializers) and `171dbd14646b121b4b6d00716f9fd6c6038e3f4772b69067219eb33bfa0bc415`
(Objective-C equality boxed as JSON 1, not boolean true). Only that stage was
rerun after correcting each cause. No unchanged stage or media build reran.

1. **D2 open:** bind custody/observation, then separately approve enrollment
   and isolated boot. Installed identities, protected worker, observed source,
   health, recovery/timing and separately authorized useful pilot remain.
2. **D3 open:** complete admission, RUN/health and workload evidence on that deployment.
3. **D4 not frozen:** close concrete surfaces and independent verifiers for all
   29 managed requirements; freeze once.
4. **D5 not authorized:** after freeze, fresh admission, 100 actual attempts,
   100 task pairs, thresholds, cleanup and independent replay.
