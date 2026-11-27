# D3: separate original worker custody from proof of retirement

Parent: signed main `bff3d503bb90142eca0a3afbe112fba951fd389b`. This is a
checked software boundary, not a guest observation or an acceptance result.

The owner reserves the original stopped worker before publishing either task
channel. Its tracer borrows that worker's original proc and code descriptors,
and keeps a separate reference to the original pidfd. Binding a session does
not attach to a process. At the final gate the manager accepts a fixed worker
session only after the observed tracer TID, the original thread, and the held
worker agree. The custody check on either side of the health challenge uses
that same TID, even if the release check runs on the manager thread. The final
health freshness check includes time spent doing the custody read.

For a completed recorded trace, the manager's `retain_entry_trace` takes the
snapshot from the nominated observer, **not** from the task. The private writer
stores the four original gate/exec records, raw trace, inventories and profile in
the nominated store. It replays them against the original entrypoint bytes
before returning a receipt. Neither the receipt nor closing a session proves
worker exit.

`retire_entry_trace` disables dispatch before reading the original pidfd and
the nominated systemd unit. The single-use terminal record requires a definite
exit on that file description and a dead unit with no replacement process.
If that evidence is missing, the outcome is **not verified**; failed publication
does not grant a new attempt. This record makes no claim about cleanup of other
services, mounts or the guest.

`replay_after_retirement` needs the independently provided binding, receipt,
terminal and deployment inputs. It reopens the named private roots read-only.
The reader verifies both the original-worker terminal record and the contiguous
entrypoint delivery; it has no access to the retired owner's descriptors.

## Evidence for the offline change

The private-store test ran full source replay from the retained 398,741-byte
entrypoint after closing the original fixture handles and discarding its capture
objects. Terminal and trace events in this test were **fixtures**, not observed
guest events. The reader rejected a missing terminal seal, substituted receipt,
wrong worker generation, changed terminal unit, and a symlink in place of the
sealed record. A separate one-byte gap in the read observations left no eligible
trace receipt. Owner tests showed that lost custody before or during health
prevents service handoff, even if a later guard would succeed.

| Reviewed stage | Checks | Passing fingerprint (SHA-256) |
| --- | ---: | --- |
| Original stopped-worker binding | 9 | `dafacefad2c5b9fd58593857f7ab59d049ecc5ef31fdb1b67964108684fa3c48` |
| Original gate/exec order | 9 | `b277240b7428222ad838220e3569bfc712358186c8b926ae50ffd352032f1464` |
| Tracer lifetime | 8 | `f6bbd8f97b31750c51922d4856c8514d28b5612db6ecfccf1c8b46b682bba483` |
| Private trace storage | 4 | `e40aa0249ec204d8dcebc035fb3efc4144d07e425b87997f84415e71b519d46a` |
| Independent terminal replay | 5 | `eadfc43413c7585a5cb22543692ab20bfbb57e029e9ca3aa312d3901c3abb99c` |
| Owner/dispatch | 16 | `445ca3fe56e791e9d8b565a8a2cf971c2e8b6cdaf24b8eda61b45a40905d4c43` |
| Health freshness after custody | 5 | `9286da658418ef5c1b2b265abe962c4950af7fbdc025cd847cab2ae2d5608ace` |

These are developer results, not acceptance receipts. Missing interfaces and the
new freshness boundary failed before implementation. Only the affected dispatch
and health checks were run for the final freshness correction.

## Remaining plan

1. **D2:** unchanged. No pilot or installation was authorized.
2. **D3:** connect acquisition on the original worker to the static event reader.
   A useful next offline check is that the static observer produces the required
   read/challenge evidence for that same generation and that missing events or
   loss cannot satisfy health. The current session does not drive events or issue
   health challenges; instrumented loss accounting remains open.
3. **D4:** finish the independent evidence inventory against the common deployment
   before freezing it. No threshold or mapping changed.
4. **D5:** no captures, measurements or qualification; separate authorization
   remains required after freeze.
