# D3: one fixed-task claim for both stopped roles

Starting point: signed main `e251a2242387d80b74f4663b15296774034564e2`.
This is owner-side source for the [common task payload](pi-core-task-guest-package.md).
No new payload, media, credentials, operational release or pilot was produced.

## What now prevents dispatch

1. The manager reads the independently pinned, root-private
   `/etc/aragorn/approvals/fixed-task-owner.json`. It holds the two pidfds, checks the
   released package against the executing bodies and units, and observes both untraced,
   single-threaded group stops. A systemd active bit or a PID alone is not sufficient.
2. The existing exclusive, fsynced collector claim records both start times, unit
   invocations, identities, boot/clock, and ticket and release digests. Its **filename**
   depends only on collection, pair and mode: changing the ticket or restarting a role
   does not create a second slot on the nominated ledger. An interrupted or partial file
   remains spent. The manager rechecks the original file and both stopped generations
   before publishing the channels. It does not send a resume signal.
3. After worker execution, release requires a new source-observer challenge for the
   same activation and complete scoped accounting. Baseline additionally requires
   observed absence of the fixed instrumented unit. Instrumented mode refuses: the
   independent RUN checkpoint does not measure upstream losses for that sensor.
4. For copy only, the owner holds a duplicate of the approved sender directory descriptor.
   After receipt, it identifies exactly one matching **open file description** in the
   nominated service (Linux ARM64 `KCMP_FILE`); a matching inode, service-supplied number
   or guessed sender number is not enough. The original copy observer checks the pinned
   guest generation, mount, fixture, directory, and output. Inside the existing full
   task interval, before the first write to Pi, the owner rechecks mode, health and the
   receiver descriptor. A failed or ambiguous handoff does not retry.

The private ledger must be a pre-provisioned CAS at `/var/lib/aragorn-task-owner-claims`
on the approved writable ext4/xfs device; the release pins its inode and mount. This
work does **not** establish anti-rollback across restored snapshots or replacement media.
Stopped observations establish identities at the readbacks, not exclusive signal authority.

## Offline evidence

| New stage | Checks | Passing fingerprint (SHA-256) |
| --- | ---: | --- |
| Stopped roles | 4 | `15323b9ce08abaa994c0bf244164d31ec2ca420acb7db45565d4ea4242dec5ec` |
| Health | 4 | `1f150208c07d8218fed32f6676f15de253fa5ee202e3f19b15d5599427d1f0dc` |
| Copy descriptor | 6 | `a16ca635038ca927e89ba707a9cf07702afe9c4550a97d507c13841bdbcd61dd` |
| Claim and dispatch | 8 | `4ae3a97e3d5fdb30cb57541c53f23e68b4266ec2f869d9a0915997e5897aa8a7` |

The tests created real private claim files, reopened the same slot, and replaced a
named claim with identical bytes to confirm inode custody. Other checks used inert
kernel, unit, transport and sensor inputs. The existing measurement function reached
its send boundary but did not send when health expired or the receiver FD changed.
No Linux syscall or isolation claim was validated on a live guest.

The original 384-entry registry is full. The [new four-stage catalog](../../../benchmark/phase3-task-owner-pipeline-v1.json)
uses the **unchanged** Phase 3 runner, lock, cache, failure records and fingerprints.
To inspect locally retained results without starting a check, use
`python3.12 -B -m scripts.phase3_task_owner_pipeline status` in the worktree that ran them.
Earlier stages, guest/service/worker source pins, B49, and acceptance thresholds are unchanged.

## Remaining plan

1. **D2:** installed identity, healthy observation, recovery, timing and independently
   verified calculate-and-save pilot still require their prerequisites and separate authority.
2. **D3:** adapt observer arming and replay to the fixed static task worker (the existing
   armer requires its earlier transient profile). Independently account for the instrumented
   sensor's actual upstream losses. Package the owner and the exact existing guest handoff
   module together. Service its synchronous OBSERVE requests on the original owner thread
   while collecting Pi/witness replies; retain evidence and verify retirement. Do not drop
   guards, use another owner thread, subtract their timing, or enable a mode based on these tests.
   Other admission, RUN and workload surfaces remain open.
3. **D4:** finish the 29-requirement independent verifier inventory before freezing.
4. **D5:** separate execution authorization after freeze, then fresh attempts, paired
   measurements, cleanup and independent replay.
