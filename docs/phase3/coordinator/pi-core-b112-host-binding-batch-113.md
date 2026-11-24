# B113 — host and serial evidence bindings for the B112 disk

B112 produced the [ARM64 disk and media catalog](pi-core-successor-media-batch-112.md).
This batch concerns the host that could eventually boot those bytes and the
reader that could inspect its evidence. It does not nominate a host or schedule
an attempt. The B112 disk, worker, services and frozen B44–B52 artifacts are not
changed. No B44 store baseline, B50 refusal archive or previously signed release
is evidence of a B112 boot.

## Firmware proposal, not enrollment

The [boot request](../../../packaging/pi-core/immutable-host-b113/boot-request.json)
keeps the two-CPU, 4 GiB, read-only NVMe graph, with one output-only serial
port and no network, shared filesystems or writable overlay. The
[firmware proposal](../../../packaging/pi-core/immutable-host-b113/firmware-proposal.json)
keeps these distinct:

| Value | What it identifies |
|---|---|
| `aae016bd1b7ef412e619bd82adc6cb9b436349fe9bfe48a0a0ba091e8b646cec` | Entire 3,595,017,728-byte B112 disk |
| `7c5d6d5ed501780c352416c0b71f07d0a6d57aa0aa30d0f4fdb3ed6680d766f8` | All bytes of `BOOTAA64.EFI`; not the firmware db entry |
| `b4cf97d568d0d060c7a308f287ccb65f0bb122391707c57080ded396e52339a7` | PE/COFF Authenticode SHA-256, the **only proposed** image in db |
| `517294dfd51f6788a7bdc63e3afd2eecdbe918fe12e8ab4cd6d68be273bc5aa4` | Detached 76-byte EFI signature list containing that digest |

The actual guest-only store, KEK and revocation baseline still need independent
nomination, authorization and readback before any future use. No store was
created, opened or enrolled. The B49 host, budget/window, evidence destination
and cleanup owner remain unbound.

## Held host owner and recorder

The [owner recipe](../../../scripts/prepare_pi_core_b113_owner.py) reuses the
B45 recorder, B46 stop handler, B47 supervised owner and B50 single-use entry.
It replaces the old disk length and firmware digest, embeds the B112 media and
proposal bindings, and uses a distinct B113 [empty release](../../../packaging/pi-core/immutable-host-b113/owner-release.json).
The recorder uses the same output-only pipe and must arm before supervised
START. Its limit remains 8 MiB (equality is indeterminate); the watchdog's
run/grace/force windows remain 180/15/15 seconds. No recorder, watchdog or VM
was run and no attempt, receipt or serial file was created by a target.

The [runner catalog](../../../packaging/pi-core/immutable-host-b113/runner-output.json)
pins a 142,784-byte ARM64 executable, SHA-256
`a209e62302def49a64e2f47bbc309c4f19a7a4a90bb259ee8063a8a70dac714b`,
CDHash `5462f0b7f1035db8c694534b41a70c1ac16a6fc8`. Its macOS signature is
local and ad hoc, with the virtualization entitlement only; it is not a
Developer ID or approval to distribute. The private binary stays outside Git.
To verify it **without executing it**, use a trusted checkout and independently
nominated full signed commit and SSH signing-key fingerprint:

```sh
python3.12 -B -m scripts.prepare_pi_core_b113_owner verify "$ARTIFACT_COMMIT" "$TRUSTED_SIGNER"
```

## What replay can and cannot prove

The [B113 reader](../../../scripts/verify_pi_core_b113_boot_evidence.py) reads
the catalogs and recorder pin from the operator-nominated signed Git commit,
not from a mutable checkout. A held-owner archive must have the exact pre-target
refusal and matching, unarmed watchdog records. These can be *consistent with*
that refusal; they do not independently identify an executing binary. A target
journal, serial stream or ARM record conflicts with the empty release. Loss of
the host stays unresolved and never grants a retry. There is no original B113
archive or guest observation from this batch.

The separate `compare-serial` diagnostic matches original, digest-nominated
bytes against the B112 root geometry, root hash and manager hash. The unchanged
observer emits the `ARAGORN_B44_V1` wire format; the record cannot identify its
own enclosing EFI image or prove host custody, boot or restoration. Matching
content must never be promoted to a successful host replay.

## Affected checks

All three new pipeline stages passed on their first runs. Replay used inert
wire records in private disposable directories, not a historical recapture or
pilot sample. The existing B112 disk readback was retained, not repeated.

| Stage | Checks | SHA-256 fingerprint |
|---|---:|---|
| `pi-core-b113-firmware-proposal-offline` | 4 | `d207d74e6cb1dc96344dbef89eea00adaeb3afe0d2d42c89146389fcc526eaac` |
| `pi-core-b113-held-owner-offline` | 4 | `f87b8201c31bb6b168d6e40b46cd25d63cc5989e6fc8795f54315d438d5b5a77` |
| `pi-core-b113-boot-replay-offline` | 6 | `bb60aac31df08ad0faaaccc1f812dbffb63538838d638a6865fcb0ff96fc9b1f` |

## Remaining plan

1. **D2 open:** The next offline engineering step is the B112-specific one-slot
   release builder and matching authorized-replay entry, reusing B50's sealed
   issuance checks and the B113 bindings. Do not issue a slot or modify this
   held binary. Separately nominate host, budget/window, evidence destination
   and cleanup owner before allocation, enrollment or boot. Installed identity,
   genuine sensor health, recovery, full timing
   and independently observed cleanup are still outstanding. The calculate-and-save
   task needs a separate bounded provider and file-effect approval.
2. **D3 open:** Finish the connected admission, RUN/sensor-health and workload paths.
3. **D4 not frozen:** Complete the evidence-to-verifier mapping for all 29 managed
   requirements on one deployment, then freeze it.
4. **D5 gated:** Obtain separate authorization after freeze for fresh acceptance,
   100 attempts, 100 baseline/instrumented pairs, cleanup and independent replay.
