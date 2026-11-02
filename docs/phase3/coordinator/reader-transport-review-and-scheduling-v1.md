# RUN guarded transport: final review and first selected schedule

Reviewed source base: verified published
`514ae19612cc30a0da786bb2bde979dcf9717d8b`.
Root confirmed the RUN worktree at this base read-only; the owner preserved its
three drafts and original HTML. The containing signed published checkpoint
registers and schedules the first selected transport stage in RUN only.

Root reviewed the complete source, both correction deltas, actual import closure
and focused case inventory. Independent source and test/closure reviewers agreed.
The last read-order blocker is closed: final PIDFD association sampling precedes
the final pipe snapshot; the remaining held-resource checks reuse acquired PIDFD
bytes. No later blocking proc sample can stale that closing reader-flags sample.
The late-reader-flags subcase mutates during the second post-wrapper PIDFD read
and checks candidate quarantine, terminal lifetime, legitimate cleanup and no
second transfer/notice. No concrete blocking finding remains at these hashes.

## Stable complete repository closure

```text
4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01  src/aragorn/__init__.py
600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b  src/aragorn/native_phase3_clock_domain.py
80afdbcab0a4a076712b65db22b091b0a1276ae952ee276a76c1b83ffe06652e  src/aragorn/native_phase3_run_acquisition.py
66cce03e029441d01bd7de72f67da0bd927259a292be28e3e5555a0b0a353fe1  src/aragorn/native_phase3_run_reader_acquisition.py
769cdf49fc380f97048ebe01ca2227b71584b19e8715c76ca2629dee3037d51b  src/aragorn/native_phase3_run_reader_response.py
24dbd8cdba584a55e7a787952dfa5a12d96c8b040973537c569dd52f582aba98  src/aragorn/native_phase3_run_reader_store.py
609a5a32c33a4bb5ae0dec45eb6637b9d5b853e00797308244a92b1e86aa5fe0  src/aragorn/native_phase3_run_reader_transport.py
0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b  src/aragorn/oci_worker_protocol.py
94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21  src/aragorn/runtime_action_broker.py
3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d  src/aragorn/runtime_action_decision.py
288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90  src/aragorn/runtime_action_observation_publisher.py
a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68  src/aragorn/runtime_process_profile.py
e3528aed2fe94ceaf8b7f8bc4718aa9fce20e696fee47587031c754041b613a3  tests/test_native_phase3_run_reader_transport.py
```

Root rechecked all 13 actual hashes; the 11 reused files also equal coordinator
bytes. Static import traversal includes the unchanged owning wrapper, store,
response leaf, process/clock helpers and their transitives. All remaining imports
are standard library. There are no generated sources, dynamic imports, external
fixtures or historical TestCase dependencies. The pipeline separately binds its
runner, worker lock, selected stage metadata and interpreter/toolchain/environment.
Mutable handoff and review documents are not behavioral inputs.

The 30 methods cover fixed socket/pipe custody, root/process/namespace/clock joins,
atomic notices, replay/capacity/budgets, acceptance and wrong peers, actual owning-
wrapper transfer, ACK/TIMEOUT/terminal failures, safe descriptor release, final
read mutations, candidate quarantine and bounded evidence. Subcases do not add
to the method count. All exercised OS boundaries are mocked before invocation.
The real-wrapper case calls the existing wrapper and challenge issuer with mocked
store/leaf/OS boundaries; it does not execute their historical test suites.

Failed socket detach remains an unresolved custody handoff: the owner and error
retain the object, and later supervision must retain those references rather than
discard, garbage-collect or retry the uncertain handle. This is not completed
cleanup. The accepted absence of raw reader-FD3 fdinfo and point-sample ceiling
remain explicit. All authority flags stay false; this stage cannot establish
native transport authenticity, real sensor progress, complete loss, prompt
post-transfer cancellation, full request timing, deployment or qualification.

## First execution release — RUN worktree only

After verifying the supplied published signed hash, RUN fast-forwards its own
existing branch without reset, stash or replacement; stop and report any conflict.
Recheck the exact pins above. Only this stage is scheduled:

```sh
cd /Users/yousi/Documents/Commits/aragorn-phase3-run-health
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py status native-run-reader-transport
/opt/homebrew/bin/python3.12 -S -B scripts/phase3_pipeline.py run native-run-reader-transport
```

Inspect status and any actual prior result first. At final review neither Root
nor RUN had a directory for this stage. If a matching successful result now
exists, hand it off instead of rerunning. Otherwise execute once only when NEW.
Registry: the single test module and 13 inputs above; needs=[]; timeout 30 seconds.
All 117 prior registry entries are unchanged. Root does not execute in or mutate
the RUN tree. No other stage, live operation, private retention or cleanup is
authorized by this schedule.

Preserve the actual result, fingerprint and log bytes on PASS or failure. Diagnose
any failure before a documented changed-input/environment review and retry.
After reviewed PASS, stage exactly the transport module, its test and
`docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md`, create one git commit -S,
verify with git verify-commit HEAD, and return the original hash, changed paths,
actual result/fingerprint, claim limits and blockers. No feature push is needed;
Root verifies the original signature and merges preserving ancestry.

Completed: correction/closure review and first selected-stage release.
Assignments: RUN executes this stage; Admission retains its already scheduled
replay assignment; Workloads destructive design and requested extra DNS owner
remain separate. Root owns connected reader/refresh/broker and shared providers.
Blockers: actual RUN and Admission results/signed delivery; all remaining real
provider wiring and source/consumer custody. No implementation or evidence row
becomes qualified from this schedule.

1. Finish providers/consumers with selected checks and signed integration.
2. Wire HTTP/DNS/destructive, all admission/RUN paths, real a100, cancellation,
   full timing and four actual paired tasks.
3. Close the same 48-entry inventory and publish a freeze candidate.
4. After separate operational release, collect 31 cases, 100 actions and 100 pairs;
   independently replay, evaluate the existing gate and verify approved cleanup.
