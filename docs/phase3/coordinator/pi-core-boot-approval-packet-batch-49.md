# D2 batch 49 — decision packet for one isolated compatibility boot

**Decision now: HOLD. Authorized spend: USD 0. Authorized boots: 0.**
Prepared from signed merge `49fa1d9df06061c1c0372c61f5d909d0d0be17cf`.
The [B44 request](../../../packaging/pi-core/immutable-host-b44/boot-request.json)
has eight unfilled private bindings and all seven authority flags are false.
This packet collects a decision; signing its Git commit is not that decision.
Do not enter private identifiers, endpoints, firmware inventories or credentials
in Git. Complete a copy in the operator's approved private records system.

**Question this boot could answer:** does this guest report a read-only disk
and partition, 512-byte logical sectors, the expected mounts and post-exec PID 1
identity on this exact host? Preserve the original serial bytes for independent
reading. A framework start, guest output alone, silence or timeout is not host
attestation, proof that systemd became ready, or a useful pilot.

## Private decision sheet

Each row needs an exact value or private record reference, its source, the
responsible person's acceptance and a UTC timestamp. A role label or unsigned
estimate is not an assignment. No private decision record has been supplied.

| Field | What is known | What the operator must supply privately |
|---|---|---|
| Host and custody | Candidate: AWS EC2 unshared ARM64 Dedicated Host, `mac-m4.metal`, `us-east-1`, macOS `27.2.1` AMI release `2026.11.18`; Linux runs inside Apple Virtualization.framework. No actual host is bound. | Before purchase: account, asset owner, permitted AZ, isolation and management policy, exact regional AMI ID and verified publisher. After separately authorized allocation: AZ, Dedicated Host ID, instance ID, exclusive placement, reservation/allocation receipt, installed OS/SDK/firmware builds and observed required API support. Reject substitutions. |
| Money and window | [B43 historical estimate](pi-core-isolated-boot-approval-batch-43.md): USD 1.23/hour × 24-hour minimum = USD 29.52 for the host **alone**. Not a current quote or cap. No approved start/end. | Billing owner and dated quote; all-in USD ceiling including host, volumes, transfer, taxes and possible release delay; allocation window **start and end UTC**, shorter boot window within it, earliest permitted release and release deadline UTC. Show the conservative total fits the cap and who handles an overrun; if it cannot be bounded to the owner's satisfaction, do not allocate. |
| Firmware and release | Approved candidate bytes below; neither the actual guest store nor its authorities have been observed. B47 is local ad-hoc signed, with no permitted attempt. | Security approver; source/effective date for revocations; proposed PK and complete nonempty KEK/dbx inventories; exact expected post-enrollment policy; target signing/distribution policy and independently trusted signer. After enrollment attach before/after receipts. |
| Observation and evidence destination | No target destination or transfer approval on record. The [B48 archive](pi-core-owner-evidence-batch-48.md) is a **local copy of a previous refusal**. | Name the observation operator independent of the VM owner, their readback authority and receipt reference. Name the evidence custodian and independent recipient; exact private fixture ID, local fixture, ledger and export roots; distinct off-host destination (system, namespace and attempt-specific object/path), access/retention policy and authenticated receipt channel. Recipient must accept custody and acknowledge the independently supplied manifest digest after reading back the bytes. |
| Cleanup and loss | No person has accepted responsibility for this host or its charges. A stopped guest does not release the Dedicated Host. | Named primary cleanup/release operator, backup/escalation contact and independent reviewer; confirm their authority for the named fixture, volumes, instance and Dedicated Host. Record the prior inventory, retention/disposal policy, release deadline, billing readback owner and handoff if the host or operator becomes unavailable. |

## Exact public candidate pins

Use the [B44 media inventory](../../../packaging/pi-core/immutable-host-b44/media-output.json)
and [B47 runner pin](../../../packaging/pi-core/immutable-host-b47/runner-output.json).
These describe retained artifacts, **not** an installed or enrolled system.

| Object or policy input | Pinned value |
|---|---|
| Read-only raw disk (3,542,227,456 bytes) | `c87cf6ef3a6f728958256bd278a748f5f71fae78b3f0de91c02ee1dba1a4837c` |
| Whole unsigned outer EFI image, SHA-256 | `bc5ce331a61b4a35350adfbf4d6a4acb4061754d94078a94f558a009449f6a27` |
| Sole allowed image in guest db: binary 32-byte PE/COFF SHA-256 | `fa2ccca39b781d7e20baad88944bf0a52c5b578034d49b6839dd79f4040a22fa` |
| Detached 76-byte EFI signature list, SHA-256 (not the db entry) | `ef48fe74972ba8f7343ea74fcd44544bcf8c467521c750031f02cfe11b5fbb30` |
| Held B47 owner, SHA-256 / CDHash | `a396b63bc16b52699b2ae82884199652a6506dab3896f99bec27285698bb33ea` / `e8d543da657b914f7bb28c69aeee14c759a16352` |

## Separate decisions, in order

1. **Nomination and funding — not approved.** Complete the pre-purchase fields.
   If there is an already-owned host, supply its inventory and ownership receipt;
   do not acquire another to fill in an ID. Otherwise a separate acquisition
   decision must name the exact allowed offer, spend, UTC window, operators and
   resources. Record whether media transfer is allowed. Before enrollment, match
   the assigned host/instance and media to those terms. Do not use a moving AMI
   alias. A cost alert, watchdog deadline or guest stop is not a spending cap.
2. **Guest-store enrollment — not approved.** On the bound host only, require
   separate authority for one fresh guest-only `efi-vars.fd` (never host
   firmware). Approve the proposed Apple-managed guest PK policy; preserve
   the before-state and all approved revocations. Enrollment adds entries, so
   reject a broad or unknown starting policy rather than assuming it is replaced.
   Reopen the same store: require
   Secure Boot enabled, exact approved KEK/db/dbx entries, no extra allow entry
   or revocation conflict. Retain file identities and whole-store/canonical
   policy SHA-256 as specified in [B45](pi-core-bound-host-runner-batch-45.md).
   An empty dbx or a digest alone does not prove revocation freshness. If PK
   byte readback is mandatory, stop: the selected interface cannot provide it.
3. **Release and compatibility boot — not approved.** The [B47 release](../../../packaging/pi-core/immutable-host-b47/owner-release.json)
   allows zero attempts; the [B48 reader](../../../scripts/replay_pi_core_owner_evidence.py)
   accepts only that held release. **Engineering prerequisite:** review and pin a
   single-use runner **and** a verifier for its exact release/attempt. Do not
   edit the frozen hold, use an environment override or disable platform signing
   controls. Before seeking boot approval, bind the new signed release and
   signer, exact distributed binary, fresh UUID, host/instance/fixture, disk,
   store and policy; retain independent pre-attempt bindings outside the owner
   transcript. Review the target graph: 2 CPUs, 4 GiB, one read-only NVMe raw
   disk, one output-only serial pipe; no network, metadata path, host shares,
   guest input, extra boot media or writable overlay. Require armed recorder,
   stop observer and external watchdog before start. Approve at most one boot
   in its UTC window: 180 seconds plus 15 seconds graceful stop and 15 seconds
   force-stop wait (absolute +180/+195/+210); the 8 MiB capture limit **at
   equality** is indeterminate. No retry. This excludes provider use and pilot.
4. **Preservation and closure.** Retain raw serial, owner journal, watchdog
   decision and both terminals when produced; keep partial/missing evidence
   explicit. Verify the manifest at the named off-host destination before any
   authorized disposal. Require same-VM stop evidence, handles closed, original
   disk unchanged and owned store/fixture accounted for. Separately reconcile
   the instance, volumes, Dedicated Host release and final billing; preserve
   unrelated resources. On host loss or an ambiguous effect, **no retry**:
   invoke [B48 reconciliation](pi-core-owner-evidence-batch-48.md), preserve
   the UUID, and keep disposition unresolved until independent custody, resource
   and restoration records agree. Do not apply B46 preview cleanup.

Use one decision slip **per gate** in the private record:

    Gate and decision (approve / decline / defer):
    Authorized resources, actions and exclusions:
    Completed decision-sheet and evidence references/digests:
    Decision time UTC / effective start UTC / expiry UTC:
    Approver, authority and signature:

Missing, expired or mismatched facts mean HOLD. One gate never signs off another.
No host resources were queried or created to prepare this packet. Only
documentation changed; no behavioral stage is affected.
