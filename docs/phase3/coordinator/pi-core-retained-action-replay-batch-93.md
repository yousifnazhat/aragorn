# B93 — independently replay one retained managed action

Use this when reviewing the broker's **recorded** disposition for the
pilot. The B31 native owner closes after reading the broker's terminal
state under its lock. B77 checked a source observation around each local
send, but relied on the caller to supply the matching CHECK and attempt.
This reader checks those selections against the **original action index**,
and the recorded grant result against the original control-file bytes. It
does not run recovery, read a target file, reacquire a sample or send an ACK.

## Inputs

Use an existing, private read-only CAS and an **independently held**
nomination digest. The nomination is canonical JSON (no trailing newline):

| Field | Meaning |
|---|---|
| `schema` | `aragorn/pi-core-retained-action-nomination/v1` |
| `owner_digest`, `index_digest` | Exact canonical B31 native action-owner observation and original action-attempt JSONL bytes, including the final LF. A valid prefix or the storage observation by itself is not a closed native owner. |
| `configuration_digest`, `grant_digest` | Original protected service configuration and independently approved grant. The configuration and request context contain the grant. |
| `activation_digest`, `request_digest`, `broker_nonce`, `deadline_ns` | Original activation and worker request, expected broker offer nonce and its original monotonic deadline. |
| `summary_digest`, `selections` | Ordered original B77 send summary, CHECK/attempt/observation pins and challenges from independent custody. |
| `source_expectations` | B77's independent worker, source, clock, gate and root endpoint expectations. The three fields ending in `_raw` name CAS digests for their exact original bytes. |

Retain the referenced private blobs and the [B77 source evidence](pi-core-action-current-boundary-batch-77.md)
in the same read-only export. The new reader opens no live control file and
does not copy or discover missing objects. Do not nominate an index based
solely on what a submitted archive calls its latest entry. Do not export a
full managed result into Git or treat this interface as export approval.

From the checkout, with its usual Python environment:

```sh
PYTHONPATH=src:. python3 -B -m scripts.verify_pi_core_retained_action "$PRIVATE_CAS" "$NOMINATION_DIGEST"
```

A consistent recorded BLOCK stays a BLOCK; a recorded creation is not
independent observation of a file. A missing, partial, contradictory or
unclosed attempt is not evidence of non-execution and must never authorize
a retry. The original timestamps are not full-task timing.

`pi-core-retained-action-replay-offline` passed once: seven new checks and
one affected B77 compatibility check (eight total). Fingerprint:
`sha256:46e6ef9805ec7fc7b323a6c30d210929cdbf387c359656fe5190aaa4d40f2c5f`.
No other stage, workload, device, network service or guest was exercised.

1. D2: a reviewer can check action records; actual worker-side permissions,
   a useful result at the sink, sensor health, recovery, complete timing and
   an authorized pilot are outstanding. B49 remains null.
2. D3: finish connected admission, event/response and workload paths, with
   independently observed effects on the common deployment.
3. D4: complete independent coverage for all 29 requirements and freeze once.
4. D5: separately authorize fresh acceptance, 100 attempts and 100 pairs,
   verify cleanup and independently replay. No qualification from this batch.
