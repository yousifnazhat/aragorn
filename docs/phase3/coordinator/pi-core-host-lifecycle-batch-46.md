# D2 batch 46 — supervise a no-boot preview and retain its evidence

Base: signed merge `1fd46c7928c74dd3afa5839752782a6743425ea4`.
The [coordinator](../../../scripts/prepare_pi_core_host_lifecycle.py) supervises
the actual B45 runner with the exact B44 disk, replays its receipt, and seals a
separate local copy. This is evidence of host preparation, **not** guest boot,
guest shutdown, VM cleanup, cloud release, or Phase 3 qualification.

## What the new path establishes

- Before spawn, verify the operator-pinned Git commit and signer, executable,
  entitlement and B44 media catalog. Reserve a fresh UUID and a private journal.
  Only the no-store `preview` operation is reachable. The child has no network
  or EFI-store access. No changes to the signed executable or disk.
- The [watchdog](../../../scripts/pi_core_host_watchdog.py) owns one direct child.
  The monotonic deadlines are 180 s, 195 s and 210 s from one start; cancellation
  can shorten but not extend them. Graceful and force requests use a private
  pipe. Only an unreaped owned host process is eligible for last-resort kill.
  A queued command, host exit, callback or empty EOF does not prove VM stop.
  The watcher cannot bound a wedged host kernel, an unreturned spawn, or host
  death. Do not start a future VM before the external owner is established.
- The [native stop bridge](../../../packaging/pi-core/immutable-host-b46/vm-stop.m)
  operates on a supplied machine and its queue. It samples the same previously
  active machine for an actual stopped state. No discovery, machine construction
  or start; the native checks used a stand-in. The bridge is not in the B45
  binary, which has no machine object. Do not deploy it as a complete VM owner.
- The [exporter](../../../scripts/pi_core_host_evidence_export.py) joins
  original stdout, retained binding/serial identity (via B45 replay), watchdog
  identity and RAW-clock intervals. It preserves failed/partial data and refuses
  ambiguous source or destination contents. Local cleanup is a separate command:
  it needs an externally acknowledged export digest, stable bytes and inodes.
  It can only remove the two named no-boot source files and their empty attempt
  directory. The independent copy, ledger, media, EFI store and unrelated
  resources are outside cleanup scope. A second local copy is not off-host
  custody or an authenticated remote handoff. Private roots require exclusive
  cooperating ownership and stable storage, not an untrusted host administrator.

## Operator interface (offline only)

Use three existing disjoint canonical, owned 0700 directories on stable local
storage outside the checkout, Desktop, Documents and cloud-provider folders.
Supply the trusted B45 release commit and SSH signer separately. From repo root:

```sh
python3.12 -B -m scripts.prepare_pi_core_host_lifecycle preview "$FIXTURE" "$LEDGER" "$EXPORTS" "$FRESH_UUID" "$APPROVED_COMMIT" "$TRUSTED_SIGNER"
python3.12 -B -m scripts.prepare_pi_core_host_lifecycle read-export "$EXPORTS" "$FRESH_UUID" "$EXPECTED_MANIFEST_SHA256"
```

Only after independent custody acknowledgment, `cleanup-preview` accepts the
exact source attempt directory, export root and acknowledged digest. No automatic
cleanup or retry. A missing terminal record or unreaped child is indeterminate.
The connected check deliberately leaves the original and the copy intact.

## Reviewed pipeline receipts

| Affected stage | Passing checks | Fingerprint |
|---|---:|---|
| External watchdog | 12 | `87b415b29faf888f8399fec26b41ef21f5b34b67c3fe87bfa5bc1cd05814e29c` |
| Native stop bridge | 6 | `d324e4df61e3f6f6740f5f64d3185da3f52fa5dc0d4b996eb54ca5b801f94c5b` |
| Export and acknowledged cleanup | 7 | `b293990ba06f6a83aa98728fc2de256ab8e336a37309bc95b5b68b3c2698bf85` |
| Connected signed preview and custody guards | 4 | `00dc2cb2b7e8047fdfc4a0e5f498152c3c8728ec9aba01c9f20518d756c327e2` |
| Registry capacity and refusal guards | 4 | `83e3c55ae3b7d4a9d3fb80c78f0d9cf9848b91f9be968e39d9e6ab5080004692` |

33 checks in the final results. The first connected-stage fingerprint
`4a603e34ddb67e7dac5257565ef89a93c52d6992638742d079ec9732e942062c`
failed before export seal: the source identity check detected a change. The
checkout artifacts showed ctimes later than content mtimes and macOS hidden
flags; the process responsible was not established. Its originals, journal,
partial export and failed result remain. The successor rejects managed custody
locations and uses a private Application Support fixture. No seal was weakened;
only the changed connected stage ran again, never the failed fingerprint.
Final binding SHA-256: `385b3921a6372caf022bd031dcae0d47dd96044e3ff4955bec0893b1253fb60a`.
Verified export SHA-256: `972f2206ab387ec8f7ef5f8e566c86b2790ccdae41ec04fbeb9ce9d525b72077`.
The private stage log locates the original, export and ledger. Serial: zero bytes.

1. **D2 open.** Wire and pin the machine-owning successor, arm watcher/recorder
   before release, retain real same-machine stop evidence and define restoration
   under host loss. Bind host, cost, signer policy, export owner and firmware
   baseline. Allocation, enrollment, one compatibility boot and a later useful
   pilot are separate approvals. Worker identity, sensor health and recovery/timing
   still need independent evidence.
2. **D3 open.** Connect remaining admission, RUN/health and workload paths.
3. **D4 not frozen.** Complete the independent 29-requirement mapping, close
   prerequisites and freeze one deployment.
4. **D5 not authorized.** After freeze and separate approval, run the full
   admission inventory, 100 attempts and 100 baseline/instrumented pairs;
   independently replay the retained evidence including cleanup.
