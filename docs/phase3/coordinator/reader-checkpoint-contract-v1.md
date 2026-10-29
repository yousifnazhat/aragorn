# Reader checkpoint readback and immutable archive contract v1

Status: coordinator review draft only. Root must review and publish a verified
signed release naming the exact owner before any source implementation. No
stage, live operation, protected write, private retention or cleanup is released
by this document. Preserve the frozen reader response, transport and broker APIs.

## Minimum ready slice and exact paths

Release protected Root readback/archive and its independent byte consumer first.
The owning function performs actual bounded filesystem/proc/clock observations
and immutable writes; it does not call a supplied evidence/health callback.
It can be implemented and tested against fabricated syscalls without an
unreviewed launcher, bridge or reader successor. It does not implement the pipe
reader or establish real reader progress from filesystem metadata.

Root owns these two new paths:

- `src/aragorn/native_phase3_run_reader_checkpoint_acquisition.py`
- `tests/test_native_phase3_run_reader_checkpoint_acquisition.py`

A separately assigned independent owner owns these two new paths:

- `src/aragorn/native_phase3_run_reader_checkpoint_verify.py`
- `tests/test_native_phase3_run_reader_checkpoint_verify.py`

Root owns `docs/phase3/coordinator/reader-checkpoint-acquisition-handoff.md`, registry changes,
source inventories, integration and this contract. The independent module uses
only the standard library, never the producer, its parser, fixture or private
record normalizer. Root must name its owner in the release; this draft does not
implicitly extend Admission or RUN's active assignment.

Reserved, **unreleased**: `src/aragorn/native_phase3_run_reader_checkpoint.py`
and its test. That future source owns actual pipe consumption, raw publication
and refresh processing described below. Root retains launch/service/bridge and
root-to-broker integration. No modification of the current RUN listener is needed.

## Fixed storage and immutable names

Source: `/var/lib/aragorn-phase3-reader-events`, preprovisioned reader-UID:
reader-GID 0700, beneath root-owned, non-group/world-writable ancestors. The
reader cannot access the existing root-only ReaderStore. Root archive:
`/var/lib/aragorn-phase3-reader-checkpoints`, root:root 0700 with root-owned
non-group/world-writable ancestry. Neither constructor creates, repairs, cleans
or changes either directory. Pin held/named identities from protected provisioning.

For a first challenge, the source manifest name is
`challenge-<challenge digest hex>.json`; for a refresh it is
`refresh-<refresh command digest hex>.json`. After validating that manifest:

- raw batch: `batch-<session nonce>-<sequence_after>.ndjson`;
- publication receipt: `receipt-<manifest digest hex>.json`.

Names are derived solely from validated pins/scalars and fixed literals; no
record supplies a path. Source files are reader-UID:reader-GID regular, single
link, 0400. Raw empty batches are valid zero-byte files; manifests/receipts are
nonempty canonical ASCII JSON. Source/readback opens use
O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC, with held fstat type/owner/mode/link/size
validation before any read; substituted FIFOs cannot block an open before that
validation. Directory opens use O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC.
Use held parents; compare
full nine-field file identity and held/named equality before and after every
bounded read. Directory identities use device/inode/mode/UID/GID, excluding
timestamps changed by legitimate publications. Recheck ancestry and identities
after reads. Reader ownership is a supplied custody boundary, not hostile-reader
or hostile-root resistance.

Root archives under `checkpoint-<trigger digest hex>-` with suffixes
`claim.json`, `batch.ndjson`, `manifest.json`, `publication.json`, `acquisition.json`.
The claim is created first, exclusively, even for repeated identical input.
Every path is a permanent one-attempt record; existing/partial/link/directory
residue refuses. Never overwrite, rename, unlink, deduplicate, recover or retry.
Use O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC and root:root 0400 single-link files;
write fully, fsync(file), fsync(parent), held/named exact readback before proceeding.
The claim contains exactly `schema,expectation_digest,manifest_digest,trigger_digest`;
schema is `aragorn/native-phase3-reader-checkpoint-claim/v1`.

## Scalars, provisioning and expectation

All JSON is exact-key canonical ASCII with strict duplicate/nonfinite rejection,
sorted compact keys, no trailing bytes; uint excludes Boolean and is [0,2**63).
Pins are `sha256:` plus 64 lowercase hex; session nonce is 64 lowercase hex.
`process` is exactly `pid,start_time_ticks,uid,gid`, with PID in 1..2147483647,
positive start ticks and
uint32 accounts. `clock` is exactly `boot_id,clock_id,time_namespace`; canonical
lowercase UUID, CLOCK_BOOTTIME and namespace `device,inode` (positive inode).

Protected `provision_raw` is <=8192 bytes, exactly:

```text
schema epoch_digest session_id reader observer clock stream_digest
source_inventory_digest access_inventory_digest directories session_deadline_ns
```

Schema: `aragorn/native-phase3-reader-checkpoint-provision/v1`. Reader is the
non-root epoch reader; observer is the independently pinned root process, with
different PID and UID/GID zero. Directories is exactly five entries in order
`/`, `/var`, `/var/lib`, the source path, the archive path; each has exactly
`path,device,inode,mode,uid,gid`, including the directory type in mode. Inventory
pins are supplied protected authority, not freshly verified loaded source or
historical exclusion of ptrace/copied descriptors. The caller holds the expected
provision digest independently. Matching candidate JSON alone is not provisioning.

Protected `expectation_raw` is <=8192 bytes, exactly:

```text
schema provision_digest phase epoch_digest request_digest challenge_digest
trigger_digest trigger_issued_ns trigger_deadline_ns deadline_ns previous_checkpoint_digest
sequence_before sequence_after offset_before records_before
reader_evidence_digest reader_summary_digest reader_connection_epoch reader_ack_ns
loss_scope_digest
```

Schema: `aragorn/native-phase3-reader-checkpoint-expectation/v1`; phase is
CHALLENGE or REFRESH; all named digests are pins except previous_checkpoint_digest,
which is null only for the initial session checkpoint (sequence_before=0,
offset_before=records_before=0). Connection epoch is nonce. Sequence_after is
exactly sequence_before+1. Require trigger_issued_ns < trigger_deadline_ns <=
deadline_ns <= provision session deadline; timestamps/counters are uint.
trigger_deadline_ns is the original challenge/refresh deadline; deadline_ns is
the existing outer acquisition budget, never a newly extended deadline. For CHALLENGE trigger_digest is
challenge_digest. For REFRESH it is the separate exact command digest below.
REFRESH requires sequence_before >0 and a non-null previous_checkpoint_digest:
it follows an acquired initial checkpoint and cannot initialize a session.

The future root broker-reader service constructs this expectation from its
protected request context, unchanged successful owned reader result and separately
verified reader evidence. For CHALLENGE it uses the frozen ACK sequence_after and
original ack_ns; no caller computes a replacement ACK. For REFRESH it uses the
next checkpoint sequence while retaining the **original** ACK, reader evidence,
summary and connection epoch. Prior offset/count/checkpoint pins come from the
last successfully acquired checkpoint, never a candidate manifest.

For CHALLENGE require trigger_issued_ns <= reader_ack_ns < trigger_deadline_ns. For
REFRESH require reader_ack_ns <= trigger_issued_ns < deadline_ns <=
reader_ack_ns + 200000000, without integer overflow. Actual acquisition starts
at or after both the original ACK and trigger issuance, and remains before this
same deadline. These checks supplement the caller's required original request,
phase-budget and independently verified ACK bindings; they do not replace them.
The ready API checks agreement with that expected authority; it cannot prove that the
caller used the actual broker or independently authenticated the ACK.

## Frozen future writer manifest and publication receipt

Manifest bound: 16384 bytes. Exact fields:

```text
schema provision_digest epoch_digest session_id stream_digest phase
request_digest challenge_digest trigger_digest previous_checkpoint_digest
sequence_before sequence_after offset_before offset_after records_before records_after
clock trigger_received_ns reads drain_finished_ns raw_digest raw_bytes raw_records
raw_publish_started_ns raw_readback_finished_ns manifest_prepared_ns
loss_scope_digest loss_evidence_digest upstream_loss_state
```

Schema: `aragorn/native-phase3-reader-checkpoint/v1`. Context/pins/phase, sequence
and prior offsets/counts agree with the independently held expectation/provision.
Clock agrees with the held provision clock. `loss_evidence_digest` is null and
`upstream_loss_state` is UNKNOWN in this slice; the scope pin is preserved, but
missing upstream/bridge/queue/BPF evidence is never changed into zero loss.

Batch bytes <=262144, LF-delimited records <=256; session total <=4194304 bytes
and 4096 records. Each nonempty LF-inclusive record is <=65536 bytes, no CRLF,
blank LF record or unterminated tail. Empty batch means zero raw bytes/records,
equal before/after offsets/counts and SHA256 of empty bytes. Otherwise
offset_after=offset_before+raw_bytes and records_after=records_before+raw_records.
The original bytes are retained, not reserialized JSON or normalized events.

`reads` has 1..64 exact entries `started_ns,finished_ns,offset,bytes,outcome`.
Outcomes are DATA or EAGAIN. Actual DATA reads are 1..65536 bytes; EAGAIN has zero
bytes. Offsets start at offset_before and advance exactly by DATA bytes. Entries
have serialized BOOTTIME brackets, started<=finished and each previous finished
<= the next started. Their byte sum equals
the batch and their final offset equals offset_after. The final entry must be
an actual os.read EAGAIN whose start is at/after trigger_received_ns; earlier
buffered DATA may precede the trigger. There is at least one real read invocation
after the trigger; poll readiness alone is insufficient. No EOF is EAGAIN.
Require trigger_issued_ns <= trigger_received_ns, and final read finished <=
drain_finished_ns <= raw_publish_started_ns <= raw_readback_finished_ns <=
manifest_prepared_ns < trigger_deadline_ns. All readings share the held BOOTTIME domain.

The future reader owns one bounded cumulative buffer between checkpoints.
The signed v8 release and `reader-session-contract-v1.md` now supersede the earlier
unreleased process-parser direction: consume actual telemetry FD4 in the original
main loop, preserve every valid syntax-only JSON-object variant, and retain any
incomplete tail until bounded completion. No `_event` wrapper or change to the
implemented acquisition/verifier is released. Those independent consumers retain
their framing/byte-consistency ceiling and do not parse vendor semantics or JSON
syntax. The writer cannot ACK with a tail or unretained batch.
Do not call normalize_process_capture, fabricate quiescence/EOF, create a timer
responder, silently rotate a full buffer or discard unsupported records.
Overflow, EOF, malformed/unsupported input, read/parse/publication failure,
changed custody or deadline poison that stream and preserve bounded actual
partial evidence. No error path can issue a successful checkpoint/ACK.

Publication order is raw batch -> manifest -> separate publication receipt,
each exclusive with file/parent fsync and exact readback. Receipt <=2048 bytes,
exactly:

```text
schema manifest_digest raw_digest sequence_after
manifest_publish_started_ns manifest_readback_finished_ns receipt_prepared_ns
```

Schema: `aragorn/native-phase3-reader-checkpoint-publication/v1`.
Require manifest_prepared_ns <= manifest_publish_started_ns <=
manifest_readback_finished_ns <= receipt_prepared_ns < trigger_deadline_ns, with exact
manifest/raw pins and sequence. **The immutable manifest cannot contain its own
completed publication timestamps.** The receipt records completion of the
manifest, not its own future fsync/readback. The reader stamps/sends the frozen
ACK only after receipt publication/readback and final custody succeeds; require
receipt_prepared_ns <= original ACK ack_ns < trigger_deadline_ns for CHALLENGE. A later checkpoint
never changes that original ACK timestamp.

## Ready owning acquisition and independent consumer APIs

```python
acquire_reader_checkpoint(
    *, provision_raw: bytes, expected_provision_digest: str,
    expectation_raw: bytes, expected_expectation_digest: str,
) -> dict

verify_reader_checkpoint(
    manifest_raw: bytes, publication_raw: bytes, batch_raw: bytes,
    acquisition_raw: bytes, *, provision_raw: bytes, expectation_raw: bytes,
    expected_provision_digest: str, expected_expectation_digest: str,
    expected_acquisition_digest: str,
) -> dict
```

The Root acquisition function owns all descriptors it opens; no borrowed-FD,
caller-path, injected filesystem/process/clock/retention callback or refresh
writer is accepted by this first release. It runs only in the original Linux
root main process/thread with all real/effective/saved UID/GIDs zero. Validate
all input shapes/pins before storage mutation. Open/hold nofollow ancestors and
source/archive directories; check the independently pinned identities.

Open a reader PIDFD using the expected reader PID, then fresh stat/status/stat
joins, PIDFD liveness and actual reader/observer active time namespace handles.
Recheck the held reader PIDFD's bounded /proc/self/fdinfo PID association as well
as liveness before and after each acquisition/publication boundary.
Reuse suitable frozen process/namespace helpers with full source closure. Reader
saved/account vectors match, all five capability sets are zero, NoNewPrivs=1;
observer PID/start/account vectors match its protected provision. Read actual
kernel boot ID and hold namespace handles; no packet supplies current time.
Both actual active namespace device/inode pairs must equal the provision clock's
time_namespace, and actual boot bytes must equal its boot_id plus one LF.
This root profile requires access to the same protected proc sources as the
existing reader response owner; the later launcher must provision it explicitly.

Guard process/clock/ancestry before and after reads and each publication. Bound
every read before allocation; require exact file size/read bytes. Read manifest,
derive only its fixed receipt/batch names, read both, verify all exact structural
and expected joins, and retain the complete source file identities. A missing
source file refuses this one call; there is no polling/recovery/retry API here.
Actual closing BOOTTIME must remain before the original expectation acquisition
deadline, with original reader_ack_ns <= now and now-reader_ack_ns <200000000.
The first Root readback may follow the challenge deadline; that does not extend
the earlier ACK deadline or substitute for the separately required closed loss window.

Create the permanent claim, copy the three exact source artifacts to the Root
archive, fsync/read back each, then produce the acquisition record. It is <=16384
bytes and has exactly:

```text
schema provision_digest expectation_digest phase trigger_digest
manifest_digest publication_digest batch_digest
started_ns source_readback_finished_ns retention_started_ns retention_finished_ns
observer clock source_files retained_files
acquisition_authenticity_verified sensor_health_verified effect_authorized
run_qualified phase3_qualified
```

Schema: `aragorn/native-phase3-reader-checkpoint-acquisition/v1`.
The five flags are false. Source_files and retained_files are each exactly three
ordered entries with roles BATCH, MANIFEST, PUBLICATION and fields
`role,device,inode,mode,uid,gid,nlink,bytes,mtime_ns,ctime_ns,digest`. Record the
actual identities and raw pins; source/retained bytes/digests agree, source
owners match reader and retained owners root.
The six held source/archive device/inode pairs must be distinct; one inode cannot
substitute for multiple single-link source roles or independent archive copies.
Brackets satisfy
started<=source_readback_finished<=retention_started<=retention_finished<deadline.
Require publication.receipt_prepared_ns <= source_readback_finished_ns in both
the acquisition and independent consumer, and
0 <= retention_finished_ns-reader_ack_ns <200000000 for both phases.
This record describes completed retention of the three inputs, not its own
future publication. Publish/read it back separately; recheck all owned custody,
time and source bytes, close every owned descriptor exactly once, and only then
return exactly `acquisition_raw,acquisition_digest,manifest_raw,publication_raw,
batch_raw`. The unchanged broker checkpoint artifact can carry acquisition_raw;
all referenced original bytes remain separately available for external replay.

Any failure returns no usable result. `ReaderCheckpointAcquisitionError` has
public attributes `original_failure`, `cleanup_failures` (tuple, at most 32
owned-descriptor failures), and `observed`. Its fixed message is "reader checkpoint
acquisition refused; preserve claims and observed bytes". Do not interpolate raw
records into diagnostics. `observed` has exactly `manifest_raw,publication_raw,
batch_raw,acquisition_raw,source_files,retained_files,claim_attempted`.
Each raw field is None or the actual bounded prefix/complete bytes acquired;
file lists contain at most three completed identity/readback observations with
the record shape above. claim_attempted is a strict Boolean set before the
exclusive claim open, and never asserts that an attempted write was absent.
Preserve the original failure, cleanup failures, actual partial bytes and
completed retention observations.
Keep the claim descriptor held and revalidate its bytes/identity through the
final guard; do not close it early to save a descriptor slot. The fixed ownership
inventory has at most 17 simultaneous descriptors including a transient proc
read; the cleanup bound leaves room to preserve that read's close failure.
It never synthesizes absent source bytes. Consume handle ownership before close;
check held identities and do not close a foreign reused descriptor. Failure after
partial publication leaves every artifact/claim untouched and is not retryable.

The independent consumer reconstructs canonical manifests/receipts/acquisition,
exact raw SHA256/byte/LF-record counts, contiguous read offsets and checkpoint
sequence, clock/trigger/deadline/ACK joins and immutable-record agreement. It
does not import the producer's record parser or certify vendor execution records.
Return exactly `status,acquisition_digest,manifest_digest,trigger_digest,
sequence_after,offset_after,records_after,stream_continuity,loss_completeness`
plus the same five false flags. Status is CONSISTENT_CHECKPOINT_READBACK;
stream_continuity and loss_completeness are UNKNOWN. No transcript proves actual
OS reads, protected provenance, live sensor health or complete event delivery.

## Frozen two-phase direction; reader/refresh implementation unreleased

FD ABI: reader FD3 existing connect notice; FD4 bridge stdout; FD5 separate Root
refresh command pipe; FD6 bridge stderr; FD7 remains reserved until a cancellation
contract is selected. Bridge FD1 stdout/FD2 stderr/FD3 successor sensor socket.
Intentional descriptor transfer across exec precedes setting/checking CLOEXEC;
do not demand CLOEXEC on descriptors while they must survive that exec.
Supporting PIDFD/namespace descriptor numbers are provisioned, not invented here.

The first-phase future Root service calls ReaderListener and the unchanged owned
reader acquisition; independently checks its returned ACK/evidence, then calls
acquire_reader_checkpoint with the deterministic challenge filename and actual
ACK sequence. It cannot add a checkpoint digest to the frozen ACK schema. The
source manifest pin is observed by protected readback and retained; it is not
misrepresented as an independently transmitted ACK field.

For phase two the future Root owner emits one canonical LF-terminated <=2048-byte
command through its separate anonymous nonblocking pipe (whole record <=PIPE_BUF,
single exact write, consumed before write, no retry). Exact fields:

```text
schema session_id ordinal epoch_digest request_digest challenge_digest
reader_evidence_digest reader_summary_digest reader_connection_epoch
previous_checkpoint_digest sequence_before second_request_digest issued_ns deadline_ns
```

Schema: `aragorn/native-phase3-reader-checkpoint-refresh/v1`. Ordinal is strictly
next, permanently consumed; only one outstanding refresh is permitted. Its pins
refer to the original first-phase ACK/evidence/connection and acquired checkpoint,
plus the exact broker BEFORE_PAYLOAD_SEND packet. Deadline never exceeds that
packet/original request budget or the original ACK max-age; it is never reset.
Digest covers the exact LF-inclusive bytes. The actual reader consumes this FD5
command, performs another real post-command read through EAGAIN, publishes the
next checkpoint/receipt under refresh-<command pin>.json, and emits **no new ACK**.
Root's future command owner waits only under that original deadline for first
availability, then invokes the ready one-shot acquisition method. Waiting and
command emission belong to a separately reviewed caller, not retries of a failed
acquisition. The original reader evidence/summary/connection/retention receipt
and original ACK age remain unchanged in the broker response. Only fresh
checkpoint/loss-after observations may differ; submission stays SUBMITTED.

No second BEFORE_FIRST_EFFECT challenge, no ReaderListener.begin_request for
this refresh, no reused challenge connection or synthetic ACK is permitted.
The selected cancellation mechanism must terminate the reader/refresh lifetime,
retain partial state and leave files untouched. Until its exact FD7 or pipe-EOF
protocol and source are reviewed, no prompt-cancellation claim is released.
Individual filesystem calls may outlast deadlines; late completion still refuses.

## Source limits, proposed checks and remaining steps

Source anchors: reader_response.py:349 fixes the ACK fields; reader_acquisition.py
internally mints/owns the challenge and closes the connection; reader transport
contract requires notice FD3 and terminal cancellation; runtime_tetragon_process.py:265
is single-record parsing, while :324+ requires closed/quiescent capture;
native_phase3_run_acquisition.py:94,:123,:133 enforces the closed challenge/loss
window. `tetragon-stream-loss-decisions-v1.md` records unresolved upstream identity,
continuity and loss; those remain UNKNOWN here.

Focused tests use entirely fabricated source files/syscalls: zero/nonzero batches,
partial/LF/count/offset substitution, missing/changed sequence or prior checkpoint,
deadline/ACK/clock rollback, publication-receipt circularity rejection, named/held
owner/mode/link/process/namespace changes, duplicate/partial archive writes,
fsync/readback order, source mutation during final readback, ambiguous close,
independent parser disagreement and all five claim ceilings. Submit stable actual
source/import/generated/fixture closure before Root registers one new stage.
No historical suite, cache copy, unchanged retry or real protected path is used.

1. Publish this minimum acquisition/archive and independent-consumer release;
   implement/review its four source/test paths and run only the scheduled stage.
2. Finish and separately release actual reader pipe/refresh/cancellation code,
   protected launcher/bridge/source identities and genuine loss/checkpoint joins.
3. Wire the shortest real broker path and remaining Phase 3 requirement ledger;
   publish a freeze candidate only after actual shared paths close.
4. Keep final qualification, operational observation, private retention and cleanup
   pending their separate release. This readback slice does not finish Phase 3.
