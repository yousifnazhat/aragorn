# Root broker reader service v13 handoff

Source release: verified published `d7ebe099cc692eff476338668e5edd27a0af76cd` and
`broker-reader-service-contract-v1.md`. Current delivery, 29 October 2026:
the registered service stage has an actual **44-method PASS**, exit 0, after
one diagnosed shared-fixture correction. This is service-unit evidence, not
installed identity, native composition, operational observation or qualification.

First schedule `2c6487d5f5e137e372b60f37f40344de004afc92` and correction schedule
`3144fcebf33b9bd748ce84a36906a421b15c8e41` were signed, verified and published.
Root ran only `native-broker-reader-service` through the existing pipeline.
No other stage, broad regression, live operation, private retention or cleanup ran.

## Actual outcomes and minimal fixture correction

First run: 43 methods passed, one failed, exit 1, matching pre/post fingerprint
`sha256:1a49e077a561c7c630b742bf3a06f616aaa8cefc31ed4b8f63a0b79984da9b44`.
The failed method was
`test_confirmed_close_is_retired_before_snapshot_clock_failure`. The shared
`Native.read` fixture mistook reused descriptor 15 for the old cancellation
pipe, injecting BlockingIOError during a later supervisor fdinfo read. Root and
independent static review confirmed production had already retired the old
generation correctly. The only correction resolves the current descriptor row
and checks kind `pipe` before applying cancellation behavior. All original
44 methods and assertions remain; production source is unchanged.

The changed shared-fixture closure was reviewed and scheduled before execution.
Its status was NEW, then 44 methods passed in 0.151 seconds, exit 0, matching
pre/post fingerprint
`sha256:3a3931727362b25199c19374d6f2e82a967664c2eacd5fe05b39f1582a826201`.
No unchanged failed fingerprint reran. Root read both actual results and logs;
the original FAIL is retained, never relabeled or combined into an invented PASS.

Original artifact directories in the integration checkout are
`.aragorn/phase3-pipeline/native-broker-reader-service/<fingerprint-without-prefix>/`.
Artifact SHA-256 values below omit the prefix:

| Outcome | Artifact | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Original FAIL | result.json | 810 | c3e8de3bf16f1f9b7155c0c4aaeb125d256a015c09546789e31099045f5d75e5 |
| Original FAIL | stderr.log | 8881 | 9c084467432cd19f787de253ade6a0db2987e3ab07e15a2d8d80d9ec292c2e4f |
| Original FAIL | stdout.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| Original FAIL | preflight-started.json | 347 | 94ac524b73de4d06ca40d156d3b1004d2525347228750407dcbe0e19fe9d2990 |
| Original FAIL | preflight.json | 174 | f140f2a46d320fa87c45e597d7d1ca1b731c8b68bbb8dd724226c37125fe4312 |
| Original FAIL | started.json | 211 | 66290139c4dd802b12718dbdb0434676f1066bc3b46b5877195355529f1e3649 |
| Corrected PASS | result.json | 810 | bfc875ee2a8cb615abe1848053bd22c68d225672bb723070a72336a77ec47a37 |
| Corrected PASS | stderr.log | 8235 | ca9b734ba4a6c1d30977a68796482685d8dde1505993d6f1e328dbbd3b172a52 |
| Corrected PASS | stdout.log | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| Corrected PASS | preflight-started.json | 347 | 9787684164f82911b8525b3a485c039833e2f35c5a9345eca317b587bd90d88b |
| Corrected PASS | preflight.json | 174 | 80b04545fea7ece0103ba83296aff6152a30b3286477a2c863658cfb8783caa4 |
| Corrected PASS | started.json | 211 | 3001480ca53c3c4a9fdd184229baf15088e76ffb67c861e4a5fbb6057042ad72 |

The reviewed source/test/handoff batch is ready for a verified signed commit on
the existing integration branch. Its original hash is recorded in the subsequent
integration checkpoint. No lane branch or unrelated draft was changed.

## Assigned files and review candidate

Only these assigned paths were written:

| Path | SHA-256 |
| --- | --- |
| `src/aragorn/native_phase3_broker_reader_service.py` | `99b61fa1a258464a64017d4dad6231d9bd5f7cd87ff03c2e85f490a58ee048ed` |
| `tests/test_native_phase3_broker_reader_service.py` | `474fd55ec3914de29ea11d0da3eb041a63549eed52544abe614f49f8dbec589f` |
| `docs/phase3/coordinator/broker-reader-service-handoff.md` | This handoff; final byte pin supplied separately, avoiding self-reference. |

The owning service takes eight descriptors, transfers the original five once to
the actual public `ReaderCheckpointSession`, separately binds/listens on the
fixed guard endpoint, and writes the actual v12 readiness frame once. It retains
the service writer through the explicit lifetime, accepts one authenticated
broker, calls the public protected context acquirer and real session, validates
the frozen refusal response with the public codec, waits for peer EOF, and calls
the public finish operation only after a completed successful acquisition/send.
There is no positive profile, callback/factory or private helper/state import.

The service retains actual request/response/context/session bytes, role-tagged
handle snapshots, transport observations, original exceptions and unresolved
owners. Descriptor generations are removed after confirmed close; a later
temporary FD can legitimately reuse that number without inheriting the old
role. Unknown/changed custody is quarantined rather than closed or retried.
The separate IPC/readiness pipes cannot alias one another or a reader channel.

Independent pre-execution review corrections are included in this revised
candidate. The accepted socket is registered before the post-accept clock;
failure before identity acquisition leaves the actual object strongly tracked
and quarantined, without a speculative close. Constructor argument collection
does not hash malformed inputs and merges PIDFD classification across duplicate
positions. A confirmed closed generation is retired before fallible snapshot
bookkeeping, permitting safe later numeric reuse. EOF control bytes/flags are
retained before refusal. Every actually installed ancillary FD, including0..2,
is registered before the first metadata read; existing aliases are not adopted.
An observed PIDFD link immediately marks an unclassified descriptor's association
unknown, before later opening guards can fail; a same-anon-inode substitution is
not closed using file metadata alone. Eight additional focused regressions cover
these findings; actual selected execution and its limits are recorded above.

## Registered selected stage and limits

Registered stage: `native-broker-reader-service`, selecting only
`test_native_phase3_broker_reader_service` under the coordinator-selected
`/opt/homebrew/bin/python3.12 -S -B`, after independent review and published
scheduling. There are **44 test methods**. The existing 126 registry rows and
their results are unchanged; `needs: []` selects no historical dependency stage.

The tests use the real public packet codec and an independently authored
in-memory Linux descriptor/socket/proc/clock/poll model. They explicitly mock the
public context-acquisition and session boundaries and use opaque caller-supplied
reader fixtures. These are service-unit tests: they do **not** establish actual
context/session native composition, stream continuity, installed source custody,
sensor health, effect authority, performance or qualification. The production
code imports/calls the real public dependencies directly; tests introduce no
production injection API. Later actual-leaf composition needs a separately
reviewed concrete fixture/closure and selected new checks.

Cases cover readiness ordering and original bytes, exact five-FD transfer,
request/expectation/receipt joins, immutable returned observations, supplied-source
ceiling, short/interrupted ready and response writes, endpoint residue, malformed
inputs, aliases, second/fork/thread ownership refusal, cancellation/data/EAGAIN,
context and session failures, later cancellation after context acquisition,
expected EOF/extra packet boundaries, installed ancillary descriptors/truncation,
kernel flags, foreign/late-substituted handles, ordinary clamped buffers, late
ready completion, primary/cleanup errors, confirmed close snapshots, ordinary
low-number FD reuse, partial proc retention, separate channels, and unknown
temporary-descriptor metadata.

Every native boundary invoked by the new service is intercepted on that module's
local `os`, `socket`, `fcntl`, `select`, `time` and platform objects. The model
supplies Linux-only symbols explicitly, including attributes absent on Darwin;
it does not patch global standard-library OS modules. `unittest.addCleanup`
unwinds every successfully started patch if later setup fails. A focused test
temporarily changes the thread identity boundary and restores it. No test opens
host files, creates native sockets, reads real proc, sleeps or launches processes.

## Actual static project dependency closure

Direct new-service project imports are the public codec, context acquirer and
reader session. Static source import reads give **22 production paths plus the
one new test = 23 paths**. No generated module, fixture file, historical TestCase,
test helper, renderer, registry, bootstrap implementation or journal producer is
imported by this slice. All remaining imports are Python standard library.

Admission's original signed context delivery
`018959a4fd47205d3b467cfc99794fd649671fb7` is integrated. Root and independent
review confirmed the actual 23-file closure before scheduling. No lane source or
cache was copied. The following Root paths were read and byte-pinned; these are
repository-source inputs, not claimed generated/deployed hashes.

| Production path under `src/aragorn/` | SHA-256 |
| --- | --- |
| `__init__.py` | `4b573d061d6b777ac928a08a368cfbea9dee0e2071b78ffe3d105f9cf1a40c01` |
| `native_phase3_broker_reader_service.py` | `99b61fa1a258464a64017d4dad6231d9bd5f7cd87ff03c2e85f490a58ee048ed` |
| `native_phase3_broker_reader_context.py` | `53aedfa46cd67c5febcd4f5aef3ff54d41f1227cd4a5d780b42cea2fb37e9493` |
| `native_phase3_broker_reader_protocol.py` | `8d17e7930d2c560ade4b5c0fb5b539e00ecbfb3fb9f40d910d271dd42eb48007` |
| `native_phase3_run_reader_checkpoint_session.py` | `dcf897c9f2b501e1c29287051812fa8969e2b7522da518270d62bb2bafdc442a` |
| `native_phase3_run_reader_transport.py` | `609a5a32c33a4bb5ae0dec45eb6637b9d5b853e00797308244a92b1e86aa5fe0` |
| `native_phase3_run_reader_evidence_verify.py` | `ee6eba09de97df0c1b2f9eeeb74e22849e56d7c876a11daf211e1d626d7abbf0` |
| `native_phase3_run_reader_checkpoint_acquisition.py` | `0fe4a8a8a1bf86839fa4a7fa1bd6ecb8b5fd56e5e3ff9a1f1ad50f8ed5889d22` |
| `native_phase3_run_reader_checkpoint_verify.py` | `460d25fbc8eb8cd53d2fedf7802313d7f157c22b122c0151e92e42cbd3a92cb4` |
| `native_phase3_run_reader_acquisition.py` | `66cce03e029441d01bd7de72f67da0bd927259a292be28e3e5555a0b0a353fe1` |
| `native_phase3_run_reader_response.py` | `769cdf49fc380f97048ebe01ca2227b71584b19e8715c76ca2629dee3037d51b` |
| `native_phase3_run_reader_store.py` | `24dbd8cdba584a55e7a787952dfa5a12d96c8b040973537c569dd52f582aba98` |
| `native_phase3_clock_domain.py` | `600d5da48f4a5b4702245936972c796162ca01b37c74f0ac46ea6c619ed82a7b` |
| `runtime_process_profile.py` | `a6cbac4f3eeab0f6b1853a3f77e42a54f53cd711deeb0e5490ab506d70e58f68` |
| `native_phase3_run_acquisition.py` | `80afdbcab0a4a076712b65db22b091b0a1276ae952ee276a76c1b83ffe06652e` |
| `runtime_action_broker.py` | `94a0da837f3c6562fc53f9c9126170c2d49b3734db21081abd133ea14deeae21` |
| `runtime_action_observation_publisher.py` | `288714579b5df19c5b3137caee21ede1a5c8bf69f690e3e9434bd3d646806a90` |
| `runtime_action_decision.py` | `3b3b7beffd331280dfbc8088a1ef28f6b32affe59d0abf75305ff97fe93d459d` |
| `oci_worker_protocol.py` | `0af6b5fc1fa6b4a3a4b4ec6fd514c2edc475cf339cda01cf9a1b66d3a6e81c2b` |
| `native_phase3_run_submission_verify.py` | `277f090094e8335850605c5ee793042cafc831764c24a136fddb1b277cf335a7` |
| `runtime_http_action.py` | `823ffdcaf114bdc8bcd7ca43009f67d6bf46969d4a27856e104ceedc979b0ac5` |
| `native_phase3_http_canary_contract.py` | `bcdd7b92d3ddaddb4ab38ce5cabcdbd68c7f87c79a6251f81c1bb225313946c2` |

## Completed and remaining Phase 3 steps

Completed: service/readiness implementation, integrated context dependency,
complete closure review, selected scheduling and actual 44-method unit PASS after
the reviewed fixture correction. RUN bootstrap and Workloads lineage corrections
remain unexecuted drafts with their existing owners. Actual protected launch,
context/session composition and complete source/health custody remain open.

1. Sign/publish this reviewed service delivery; next review and separately schedule
   RUN bootstrap and Workloads lineage corrections without historical reruns.
2. Implement the protected Root launcher/input acquisition, bootstrap/service/client
   caller and finite HTTP94 successor; retain actual launch/source/FD identities.
3. Finish shared admission/RUN/loss/broker paths, both action families and genuine
   a100, actual paired tasks, timing/cancellation and independent retained replay.
4. Close the existing coverage ledger before an implementation freeze; separately
   release final operational qualification, retention and cleanup.
