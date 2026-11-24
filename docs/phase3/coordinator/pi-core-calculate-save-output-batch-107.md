# B107 — read the calculate-and-save output independently of the broker

The open question from [B99](pi-core-pilot-provider-action-batch-99.md) was whether a
separate reader can distinguish the proposed output from a file actually observed
in the nominated directory. This batch supplies the read-only observation function
and its offline replay. It does not install a reader, produce a pilot observation,
or change [B106's worker/observer plan](pi-core-worker-observer-binding-batch-106.md).
That plan covers worker **source** observation, not the pilot output.

### Inputs and ordering for an authorized caller

1. An independent owner must hold the real broker output directory and nominate its
   device, inode and fixed basename, `result.json`. Use the existing
   `aragorn/runtime-protected-path/v1` commitment. A directory discovered in submitted
   evidence, the broker control directory and the developer staging tree are not substitutes.
2. Before releasing the prepared START, give the independently trusted reader only
   that directory handle, its original descriptor and the protected launcher's actual
   prepared activation ID. The worker request digest is **not** known then: it includes
   the tool-call ID assigned by the provider. Enter
   [hold_pilot_output](../../../scripts/pi_core_pilot_output_observer.py) to check absence
   without following links or scanning the directory. Keep the context open across the attempt.
3. After the one action has reached a terminal outcome, but before cleanup removes
   the file, the owner can take the single `after()` read on the held directory.
   It checks the named and opened file's identity, ownership, mode, link count and
   bytes. Only a matching public 11-byte result is returned (including the actual
   bytes as hex). Wrong or unexpected file contents are not exported. A failed read
   cannot be retried with that handle. Preserve any refusal, interruption or ambiguous
   effect; neither a second run nor a repaired file completes the original attempt.
4. Under the approved evidence scope, retain the canonical observation independently
   and nominate its digest out of band. The reader does not accept a worker-provided
   path, write to the target or automatically export anything. An implementation
   that copies the oracle into a record would not be independent acquisition.

### Replay

With independently supplied pins and existing read-only archives, run:

```sh
PYTHONPATH=src:. python3 -B -m scripts.verify_pi_core_pilot_output \
  --action-archive "$ACTION_CAS" --action-pin "$ACTION_NOMINATION" \
  --provider-archive "$PROVIDER_CAS" --provider-pin "$PROVIDER_NOMINATION" \
  --deployment-pin "$MANAGED_DEPLOYMENT" --expected-path-digest "$NOMINATED_OUTPUT_PATH_DIGEST" \
  --output-archive "$OBSERVER_CAS" --output-pin "$ORIGINAL_OBSERVATION"
```

Replay uses the existing B99 provider/action comparison against the B95 inputs,
the nominated managed deployment and both original policies. It requires a recorded
`ALLOW/CREATED`, not just a matching requested output. The exact create rule must
exist in the runtime policy: a provider-only rule is insufficient. The original
terminal envelope's run, path, name and payload must match the observation.

`MATCHED_RECORDED_PILOT_OUTPUT` means those independently nominated **records agree**.
The two point-in-time reads do not authenticate the collector, establish exclusive
writer identity, rule out intervening changes or prove cleanup. The full pilot also
needs the install/action lineage join, source and health evidence, trusted bracketing
and custody, timing and recovery. Only the offline fixture produced a file this batch.

### Checks and authorization boundary

- The new fixed-output stage ran eight tests (three observer, five replay), once:
  `7470aca9eee2cec66ad365a046ceb9fafc704e8fdfaa3bd3b2143fbc0fff5142`.
  Review then found an impossible same-device directory/file inode combination.
  Only the new comparison check ran after that fix (one test covering refusal and
  the distinct-inode control): `a33d2d064704e4f863b794fec810ce3d228cee9cbd8247e17c7942256a029c35`.
  No historical stage, media build, guest or model ran. Neither result is a pilot sample.
- **Before installing, booting or observing:** approve the actual dedicated arm64
  guest, exact successor media and directly attached inline-header LUKS2 volume,
  owners, spend/window (including acquisition if needed), pre-state, private
  evidence destination and cleanup/restoration authority. Approve the separate
  reader's pinned code, descriptor, prepared-ID handoff, completion signal and
  limited retained fields. These interfaces still have to be connected to the
  protected caller and independently checked in that guest. No key or private IDs in Git.
- **Before provider egress or a protected effect:** explicitly authorize this
  fabricated task, one OpenAI Responses request on the nominated model/address/CA
  profile, one exact file create in the nominated directory, a spending ceiling,
  deadline and no retries. Supply the operator's key only to the service credential
  mechanism, never Pi or chat. Changed-input and unauthorized-target denials need
  separate owned contexts. Nothing here grants any of these permissions.
- B49 remains **null**. Its older B44 compatibility-only boot would not authorize
  this successor or the pilot even if approved. D5 remains separately gated after freeze.

1. **D2:** file observation and replay implemented offline; protected reader handoff,
   installed source/health, custody, timing/recovery, authorized pilot and cleanup remain.
2. **D3:** finish connected admission, RUN/health and workload coverage.
3. **D4:** verify evidence for all 29 requirements on one deployment, then freeze.
4. **D5:** separately authorize fresh acceptance, 100 attempts and 100 task pairs;
   verify cleanup and independently replay the originals.
