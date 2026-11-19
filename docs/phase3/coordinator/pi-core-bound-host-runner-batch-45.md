# D2 batch 45 — B44 host runner, firmware-store binding and raw serial recorder

Base: signed merge `3b29bb9c34cbeb03093f3482e3cc0d5aa022676c`.
**Delivered:** a signed, retained macOS ARM64 no-boot executable. The actual
B44 disk and its isolated Virtualization.framework configuration passed local
readback with the recorder armed. **Not delivered as evidence:** an assigned
host, physical firmware-store identity, enrolled trust, VM execution, guest
observations, provider access or Phase 3 qualification.

## Which bytes are trusted

The [runner pin](../../../packaging/pi-core/immutable-host-b45/runner-output.json)
binds the 115,488-byte executable (SHA-256
`c32960d879cdf0ccd55ea275d43a3c30fdfa0eee142b9453a5d9c826c77f2795`,
CDHash `8a3a68d420250a3f57b3923029f63b839dd1ed8e`) to the exact
[B44 request](../../../packaging/pi-core/immutable-host-b44/boot-request.json),
media catalog and disk. The retained executable is
`.aragorn/host-preflight/build-b45/build-6b98a0562df709cf551e615e7b1ec5e85669fd4e7c66e891af896eb577cfa28f/host-runner`.
The [build recipe](../../../scripts/prepare_pi_core_bound_host_runner.py) pins
the compiler, linker, signing tools and selected SDK files, not every installed
header. No binary or private host/fixture evidence is committed.

The Mac has no valid Apple code-signing identity. The executable has a **local
ad-hoc hardened signature** with the sole entitlement
`com.apple.security.virtualization`. That verifies code integrity, not a named
Apple publisher or target distribution approval. The separately verified
SSH-signed Git commit authenticates the full executable digest and CDHash.
Before any use on another host, use a trusted checkout, operator-pinned full
commit and out-of-band signer fingerprint with trusted SSH allowed signers:

```sh
python3.12 -B -m scripts.verify_pi_core_host_binding "$APPROVED_COMMIT" "$TRUSTED_SSH_SIGNER" "$RUNNER_PATH"
```

This command only verifies files. It refuses a signer, entitlement, CDHash or
byte mismatch. If the target requires Developer ID, approve an actual identity,
sign a successor and re-pin it; do not disable Gatekeeper or treat ad-hoc
signing as Developer ID.

## What is bound

- **Disk/configuration:** the [runner](../../../packaging/pi-core/immutable-host-b45/host-runner.m)
  holds and hashes the exact 3,542,227,456-byte B44 disk, requiring a canonical
  private path and a singly linked, owned 0400 file. It verifies the held file
  and name around the framework URL attachment and recording. This is a
  cooperating, exclusively owned host boundary, not defense against host root.
  It checks EFI/generic ARM64, 2 CPUs, 4 GiB, one read-only NVMe disk, one
  output-only serial port and no additional devices, network or shares.
- **Existing store (target branch only):** fixed private `efi-vars.fd` on
  exactly macOS 27.2.1, stable file identity, external whole-store digest
  and external approved policy digest. It opens an existing store only, requires
  [Secure Boot enabled](https://developer.apple.com/documentation/virtualization/vzefivariablestore/issecurebootenabled)
  and reads [all enrolled KEK, db and dbx lists](https://developer.apple.com/documentation/virtualization/vzefivariablestore/enrolledsecurebootsignatures).
  Approve the complete nonempty KEK and dbx baselines privately. The db must
  contain exactly the B44 PE digest; duplicates, unknown types, extra allow
  entries and revocation of this image are refused. Policy bytes are sorted
  ASCII rows `database:type:value\n` with database `kek`, `db` or `dbx`,
  type `sha256` (hex digest) or `x509-sha256` (hex SHA-256 of certificate DER).
  The same store is assigned to the same EFI loader, and target configuration
  validation precedes handoff. No store has been created, opened or enrolled
  in this batch. Offline policy cases used inert objects, not firmware.
  This API cannot prove PK certificate bytes, image acceptance or freshness of
  revocations; the separately approved enrollment record remains mandatory.
- **Pipe/attempt:** a private fixture lock and fresh UUID directory prevent
  concurrent cooperating runs and overwriting an existing attempt. The
  [recorder](../../../packaging/pi-core/immutable-host-b45/serial-recorder.m)
  consumes the read end of the exact pipe assigned to the serial attachment.
  It signals readiness after exclusive raw-file creation and nonblocking setup,
  while the configuration still exists. In this preparation-only executable
  the configuration is then retired and its writer closed; no VM is created.
  The binding receipt links attempt, fixture/disk/store identities, code and
  graph digests, raw SHA-256 and byte count, and monotonic arm/retirement/EOF
  ordering. The independent file reader compares the receipt digest supplied by
  the evidence owner and rejects substitution or any purported guest output in
  this mode. A digest is not by itself an authenticated export.
- **Bounds/retention:** 8 MiB at equality is indeterminate; the 180-second
  clock does not restart when bytes arrive. No automatic effect retries.
  Partial data, write failures and incomplete attempts are not successes.
  The guest reader still consumes original raw bytes, never text reconstructed
  from logs. A future live supervisor must bound the entire VM lifetime and
  handle blocked host I/O; a pipe watchdog cannot guarantee a deadline on a
  hung filesystem. No guest EOF, successful shutdown or cleanup is inferred
  from the dry transport.

## Focused verification

| Passing stage | Checks | Final fingerprint |
|---|---:|---|
| Signed runner, loader ID, changed binary, isolated graph, replay/refusals and firmware policy adapter | 6 | `1094536f08fabb8a81868e3e5930455c9e30b2b6ed55f3d7d58b9083bf605825` |
| Raw binary capture, arm-before-release, empty EOF, 8 MiB equality, deadline with active writer, write failure and ownership refusals | 8 | `d9a523f24f13e3eb717db87bd895c0cca6bab1977b305c621d80899d97901b3b` |
| Registry capacity/guards, 265 → 267 | 4 | `24910b9680cc9366bad1cb92c08a3a93fc4461fe7cf31162c65d9a8e7ef0db15` |

18 checks in the final results. The private runner-stage log contains the actual
receipt: no store, graph SHA-256 `bd7ded277dcb4ee0a8b207412c1451970bb60af97b582fd4bdbf98a806f6db4b`,
recorder armed, zero bytes and empty EOF. No B44 image build or historical
stage was repeated. Earlier recorder fingerprint `c7026bfb2d4d6ab053005963ba8e99b202a86cbb94f4c093b48889a7a8873d5b`
passed before the arm handshake was added. The initial artifact and runner-stage
failure `9f12cb992efd1686d6ab840d6e499f24b792e5e26576f853ad157a1745f7f465`
were retained: the signing readback first needed explicit XML output; then
dyld refused the signed but UUID-less binary before main. The successor uses
the normal linker UUID and verifies exactly one nonzero UUID before use.

1. **D2 open.** Prepare the separate VM lifecycle, external watchdog, raw-evidence export,
   stop and cleanup. Privately bind the host and signing policy, spend/window,
   store and reviewed revocation baseline; authorize allocation, enrollment and
   one isolated boot separately. Worker identity, sensor health, recovery/timing
   and the separately authorized useful pilot still require independent evidence.
2. **D3 open.** Connect remaining admission, RUN/health and workload paths on this deployment.
3. **D4 not frozen.** Complete independent coverage across all 29 managed requirements and freeze once.
4. **D5 not authorized.** After freeze and separate approval, run fresh admission, 100 attempts and
   100 paired tasks; verify thresholds, cleanup and independent replay.
