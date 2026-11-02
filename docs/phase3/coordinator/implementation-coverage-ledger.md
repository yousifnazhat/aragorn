# Phase 3 implementation coverage ledger

Source base: published checkpoint `d87572182584f9c106393a2ca952c69703b6da6d`.
This is the coordinator's implementation inventory, not a gate result or a new
gate framework. The requirement IDs below are exactly those constructed by
`src/aragorn/phase3_exit_qualification.py:required_phase3_evidence_ids` from
`benchmark/phase3-exit-gate-manifest-v1.json`: 31 admission, 15 RUN, one external
boundary and one measurement requirement. Admission case order also agrees with
`src/aragorn/admission_openclaw_final_v3_campaign.py` and its dispatch inventory.

Update this document when a reviewed implementation or evidence handoff changes
a row. Keep the original result and its source/environment binding. File presence,
a proposal, a signed commit, a mocked PASS and actual deployed evidence are
different facts. No historical test, live observation or acceptance run was
executed to assemble this source inventory.

## Status and ownership notation

Latest integration, 29 October: original verified signed RUN bootstrap
`ec171a674b45eeb7a3c9473e266b072aefacce5f` is fast-forward integrated with
69 modeled checks passing at matching pre/post fingerprint
`sha256:8f564bf4208fb8c5c9f5f3719d7fe79e5c6f29eec5c353ae67a8bd51190d4e45`.
The initial 68-pass/one-method failure remains retained; a diagnosed fixture-only
timing correction preceded this changed-input PASS. No unchanged failure reran.
See `../integration-checkpoint-2026-10-29-run-bootstrap.md`. Workloads' 32-method
lineage draft is next for review, and the128-row pipeline is now at capacity.
Actual protected launch and caller composition remain open; no full requirement
or final qualification state is promoted.

Prior integration, 29 October: verified signed broker service
`721e63cbb8f3bc47fe5fd58cbc8793538c4851db` is integrated with a complete
44-method unit PASS at matching pre/post fingerprint
`sha256:3a3931727362b25199c19374d6f2e82a967664c2eacd5fe05b39f1582a826201`.
The initial 43-pass/one-failure result is retained separately; a diagnosed shared
fixture correction, not production changes or an unchanged retry, preceded PASS.
See `../integration-checkpoint-2026-10-29-broker-service.md`. Actual native
composition, launch/source custody and full health remain open. RUN's 69 and
Workloads' 32 corrected methods remain unexecuted drafts. No full requirement or
final qualification state is promoted.

Prior checkpoint, 28 October: original verified signed Admission context
`018959a4fd47205d3b467cfc99794fd649671fb7` is integrated. Its first scheduled
67-method stage passed once at matching pre/post fingerprint
`sha256:befda78d72d7a2a0c35c2c05887bcf84825cdf8ef64a8750036903e98141bd12`.
See `../integration-checkpoint-2026-10-28-admission-context.md` and the Admission
handoff for retained evidence. This removes the service's signed context
dependency, not its own pending 44-method validation or deployment prerequisites.
RUN/Workloads acknowledged fc96aed and are correcting their existing drafts;
neither correction batch has executed checks or signed delivery. No complete
requirement or final qualification state is promoted. The 15 October recheck
below is historical and its pending Admission delivery is superseded here.

Current coordination recheck, 15 October, at published signed
`ac7f95157315a0ae834f0fba62954f1137bbd2bd`: the original DNS acquisition
delivery `a32477b0b38248f7dca825ec022ad4c0e467558d` is integrated with its
actual 50-method result; preserve V-DNS-acquisition below. Admission's corrected
context source/test still match the published 12-input/67-method first schedule,
but its actual outcome and signed delivery remain pending. Its observed branch
tip is `722c4794c349acc022dd6a751344408af82f454e`. RUN and Workloads explicitly
acknowledged `f65e8f3b8a79f3ac7251a69f6facc7df89042364` and v12/v11;
their current tips still match that checkpoint. Newer receipt is unconfirmed;
the unavailable outbound bridge has not been retried unchanged. RUN's unexecuted
59-method bootstrap and Workloads' unexecuted 27-method lineage candidates need
the corrections in their published source reviews before first scheduling.

Root v13's real service caller has reviewed stable source and 44 proposed methods;
execution awaits the original signed Admission dependency. Root v14's HTTP reader
client and v15's finite seven-output HTTP94 renderer proceed under distinct
three-path internal assignments. Client source review now accepts terminal journal
retention after late constructor failure and a final original accept-deadline
check, with38 first-stage methods. The renderer's29 isolated generated-unit checks
remain separate from actual v12/v14 composition and installed custody. Both full
closures passed Root and independent source review; first schedules are published
by signed c141775745f36723f322ac30de44cb9393269885. Root then ran each once: client38
PASS at sha256:f490d36c2f7106bcef7396371c87a4628a23fa93732bc4170f37ec1b23d8058f;
renderer29 PASS at sha256:08040bb8feb1309b5124944f40f4e19dd6a4fd035fc6cf8c70b2e2a668dc5d4d.
Actual results/logs and all post-run source pins were reviewed; see
integration-checkpoint-2026-10-15-http-run-guard.md for exact retained artifacts. No complete requirement state is promoted by this recheck.
Actual protected launch inputs, bridge build/subscription closure, full loss/
program/map and policy/lifecycle acquisition, destructive interval observation
and actual paired contexts remain Root-owned open conditions in the provider
rows below. Missing loss remains UNKNOWN and REFUSED/LOSS_UNAVAILABLE.

The four state positions are **leaf implemented / shared path wired / evidence
verified / final qualified**. `partial` means existing bounded code supplies
only part of that exact requirement. `legacy` means a predecessor probe/consumer
exists but its native common-deployment successor remains open. `pending` means
the published assignment has no integrated implementation at this source base.
`false` means the complete claim has not been established; it does not discard
any existing bounded evidence. All rows have final qualification `false`.

`Admission`, `RUN`, `Workloads` and `Root` identify the existing worktree owners.
Rows do not grant new write permission: only the explicit paths in
`ownership-and-release-v2.md` and the applicable published provider releases
(including v7 DNS, v8 reader/session, v9 protected broker context, v11 peer lineage
and v12 fixed bootstrap)
are released. Root must publish a concrete
contract and exact additional paths before a lane begins a later family. Root
owns shared dispatch/registry and the providers below except the explicitly
delegated RUN transport leaf in `reader-transport-contract-v1.md` /
`provider-release-v3.md` and Admission's independent submission replay in
`broker-reader-provider-contract-v1.md` / `provider-release-v4.md`. RUN transport
is integrated with its reviewed first 30-check PASS (V-reader-transport);
Admission replay is integrated from original signed `5889169` with its actual
33-check PASS (V-submission-replay). Root's bounded protocol/journal implementation now
has its reviewed 28-test PASS (V-broker-submission); actual shared broker wiring
and actual acquired transcript composition remain pending. Root checkpoint acquisition/
archive and independent byte replay have the 53-check V-reader-checkpoint result;
the v8 writer and Root refresh/session source are now integrated (V-reader-session).
Actual launch/IPC, authenticated stream and complete loss closure remain open.

Path shorthand is literal: **P/** means `src/aragorn/`, **S/** means `scripts/`,
and **B/** means `benchmark/admission/openclaw-v2026.7.1/`. A path identified as
pending is an assigned future path, not an assertion that it exists at the base.

## Shared providers and their existing implementation anchors

Each row names its needed provider here and states its additional case-specific
unresolved condition. Existing anchors are reuse candidates; none alone proves
the complete provider interface is implemented or deployed.

| Provider | Root-owned implementation anchors | Evidence and completion condition |
| --- | --- | --- |
| Admission invocation and loaded identity | `S/runtime_native_admission_case.py`, `S/capture_native_phase3_admission_case.py`, `P/native_phase3_admission_case.py`, `P/native_phase3_admission_capture.py`, `P/native_phase3_live_identity.py`, `S/stage_runtime_native_admission_profile.py` | One current inventory must bind actual command, runtime/interpreter/policy/config bytes, loaded credentials, admitted artifact, namespace/process and activation identity. Current common admission case selection covers direct-write, rename, symlink and plugin-package replacement, not all 31 cases. Its frozen profile/config pins differ from the repaired HTTP successor and cannot be silently relabeled. |
| Policy/lifecycle acquisition | Existing admission command helpers; `docs/phase3/coordinator/restart-lifecycle-contract-v1.md` and `admission-policy-tamper-contract-v1.md` | Root must provide actual protected invocation/request observation and lifecycle readback with source/config joins, retained raw output and externally held identities. A gateway-account log remains an emitter assertion. The baseline-present force route is separate from an absent-target route. |
| Authenticated reader and permanent claim | `P/native_phase3_run_reader_checkpoint.py`, `P/native_phase3_run_reader_checkpoint_session.py`, `P/native_phase3_run_reader_transport.py`, `P/native_phase3_run_reader_response.py`, `P/native_phase3_run_acquisition.py`, `P/native_phase3_run_progress.py`; `P/runtime_process_profile.py` PIDFD helpers | Accepted Linux seqpacket transport, protected observer/reader identities, a fresh connection epoch, real read-loop challenge acknowledgement, permanent consume-once claim, retained bytes/readback and cancellation supervision. A successful reader leaf is not yet a real sensor-read-loop provider. |
| Loss/program/map acquisition | `P/runtime_tetragon_loss.py`, `P/runtime_tetragon_program_map.py`, `P/runtime_tetragon_stats_map.py`, `P/runtime_tetragon_process.py` | Protected before/after raw samples, exact producer continuity, program/map identities and applicable counter inventory. Missing families remain unknown; resets and increases fail closed. Parsers do not authenticate a scrape or establish complete event delivery. |
| Serialized broker and causal lineage | `P/runtime_action_broker.py` through `P/runtime_action_broker_v5.py`, `P/runtime_http_broker.py`, `P/native_phase3_broker_reader_protocol.py`, `P/runtime_http_run_submission.py`, `P/runtime_lineage_capability_issuer.py`, `P/runtime_active_skill_lineage_v2.py`, `P/runtime_action_observation_publisher_v4.py` | Actual activation/session → tool request → PID/start/cgroup → digest/capability → serialized broker decision/result. Health and submission state must be checked inside the real serialization boundary. Missing receipts cannot establish NOT_SUBMITTED; SUBMITTED/UNKNOWN retain INDETERMINATE. |
| Responses and start barriers | `P/runtime_response_service.py`, `P/runtime_health_watchdog.py`, `P/runtime_health_service.py`, `P/runtime_revocation_service.py`, `P/runtime_quarantine_response.py`, `P/runtime_quarantine_service.py`, `P/runtime_skill_startup.py` | Retained trigger, pending latch, identity-bound stop/mask/quarantine/revocation and subsequent denial evidence. Fixed profile masking alone is not arbitrary digest quarantine; an intended response is not completed enforcement. |
| Protected workload contexts | `P/native_phase3_common_preparation.py`, `P/native_phase3_common_attempt_inputs.py`, `S/runtime_native_common_attempt.py`, `P/native_phase3_http_fixture.py`, `P/native_phase3_http_sink.py`, `P/native_phase3_http_collection.py` | Fresh owned per-attempt directories and descriptors, held execution/process/sink identities, readiness before effect, cancellation and continuous destructive-object custody. HTTP readiness is separate from canary traffic; DNS needs its own protected observer and completeness source. |
| Full timing and paired environments | `P/phase3_measurement_collector.py`, `P/phase3_measurement_replay.py`, `P/native_phase3_clock_domain.py`, `P/native_phase3_clock_domain_verify.py`, `P/native_phase3_ingress_interval_verify.py`, `P/runtime_broker_decision_measurement.py`, `P/runtime_broker_decision_measurement_verify.py` | Retain actual REQUEST_ACCEPTED → DECISION_FINALIZED and TASK_ACCEPTED → TASK_COMPLETED in a validated CLOCK_BOOTTIME/time-namespace domain. Select real baseline/instrumented contexts, retain identical task/input/host joins and execute both sides. A mode label or narrower broker timestamp interval is insufficient. |
| Deployed inventory and offline replay | `P/phase3_deployment.py`, `P/native_phase3_common_identity.py`, `P/native_phase3_common_process_verifier.py`, `P/native_phase3_common_attempt_capture.py`, `P/phase3_exit_qualification.py`; `S/materialize_native_phase3_http_credential_helpers.py` and `S/materialize_native_phase3_http_credential_capture.py` | Freeze source, generated payloads, loaded credentials, units, interpreter/runtime and all independent consumer dependencies under one deployment. Select trusted semantic verifier functions explicitly. Existing composer rejects incomplete maps and has no default PASS verifier. Offline composition does not establish installed-source custody. |

## Validation references retained at the source base

These are bounded development results recorded in integrated handoffs. They are
not complete requirement PASS results and were not rerun for this ledger. Reuse
only if their actual behavioral closure and relevant environment remain equal.

| Reference | Existing selected result | Fingerprint / retained source of result |
| --- | --- | --- |
| V-broker-bootstrap | 69 modeled four-message bootstrap, descriptor custody, readiness and transfer checks; PASS after diagnosed late-substitution fixture repair | `sha256:8f564bf4208fb8c5c9f5f3719d7fe79e5c6f29eec5c353ae67a8bd51190d4e45`; original signed `ec171a674b45eeb7a3c9473e266b072aefacce5f`, ancestry preserved. Initial FAIL and corrected PASS retained in RUN with artifact pins in `../run-health/BROKER_READER_BOOTSTRAP_HANDOFF.md`. No live launch/caller composition, full-health, positive-enforcement or qualification claim. |
| V-broker-service | 44 mocked service/readiness/refusal/custody checks; PASS after diagnosed shared-fixture repair | `sha256:3a3931727362b25199c19374d6f2e82a967664c2eacd5fe05b39f1582a826201`; original signed `721e63cbb8f3bc47fe5fd58cbc8793538c4851db`. Both initial FAIL and corrected PASS retained with artifact pins in `broker-reader-service-handoff.md`. No native context/session composition, installed-source, full-health or qualification claim. |
| V-broker-context | 67 new mocked protected context and retained-byte replay checks; first selected PASS | `sha256:befda78d72d7a2a0c35c2c05887bcf84825cdf8ef64a8750036903e98141bd12`; original signed `018959a4fd47205d3b467cfc99794fd649671fb7`, integrated preserving ancestry. Original Admission result/log pins: `docs/phase3/admission/BROKER_READER_CONTEXT_HANDOFF.md`. No native custody, installed-source, service composition or qualification claim. |
| V-source | Source inspected; no current requirement-level result asserted | Existing inventory/probe/consumer only. Historical standalone qualification must not become same-deployment campaign evidence. |
| V-install | INSTALL recorder/consumer: 16 checks; native leaf: 17 mocked checks | `sha256:0d3692546c31cc2733070f93f85a83a7ee6cd13b45f1d93b8974b53c6cd105c2`; `sha256:62afde843001570524bafaed58dfcfab678f3a2dd1ac9e61712e7ff0a8217882`; `docs/phase3/admission/INSTALL_RECORDING.md`, `INSTALL_LEAF.md`, integration batch2/batch3 checkpoints. |
| V-restart | 26 mocked checks | `sha256:70b1548feb59a4bd38673bb01cd9d52a78e26c31ebca95a1f5d47f7588b335b8`; `docs/phase3/admission/RESTART_SOURCE_HANDOFF.md`. |
| V-reader | Progress: 3 inert checks; acquisition: 10 inert checks; response: 17 mocked checks | `sha256:1ebdd044c7dd535f86f7fba19322a03a6254e96a8aa81adac0ca153eeb5a7226`; `sha256:c135daacf0473b0d2e80cc6f6ebc4671c429a2a3681c3e51433db46abe057ead`; `sha256:f1fab4f0fbe5eb90a0bdfebc731c576ba28f84db04e66d447767cf8150025e8b`; RUN handoffs. |
| V-benign | JSON sum 6, line count 7, SHA256 8, copy/readback 12 checks | `sha256:9d5945fdbad517531b6cc61d32645596ded265683cbf82504651274557f16a82`; `sha256:79464c1432034d5d5a0298be6c1645e328dba1859bd75c5611fb73fb55480d0b`; `sha256:5c26a3df4d6f464ba8458d7ef60139bcc7e74c3f473044654edc3b22739c779f`; `sha256:bc7e9c5b46f7c44569ae94dd00fcf80aafa3b51d6ff883f985b1327e5790d8db`; four workload handoffs. |
| V-HTTP | Credential repair 14 checks; composition 7 checks | `sha256:0d119c82b5671c45d08a1a1705a15ea092b601ff60caa32639b4ed4e4e1032a2`; `sha256:fc5ec4385aef9eb1263089fcd9aaa53be2c464d77d48c64efe9fad0b5c158a19`; `docs/phase3/integration-checkpoint-2026-10-12-http-credentials.md`. Actual public report: `benchmark/evidence/phase3-http-credential-staged-profile-v1.json`, 68263 bytes, `sha256:88d08ad1024d27426fecbde9eb73c4fff5ca03e783425a36d1d6559d47f5d1a9`. No repeated staging. |
| V-fixture-cleanup | Shared HTTP/DNS fixture descriptor custody and cleanup: 25 new mocked checks, first selected PASS | `sha256:eb00a04f5617bf8caac3b558f8e0dab0f7b7491a523409bd4b0eb6e1d18a6c37`; `http-fixture-cleanup-handoff.md`. Local persistent handles and owned fdinfo temporary cleanup only; unchanged process-helper reads retain prior limits. No historical rerun, native custody or qualification claim. |
| V-broker-group-delta | Four new shared-group and real journal-to-independent-replay composition methods: PASS | `sha256:7107b9706c8e9efa605f5d39343a754e88a95fecb419f16718ea00485b1c2144`; `broker-shared-group-handoff.md`. Actual source compatibility and mocked custody checks only; no original28 rerun or combined aggregate. |
| V-submission-replay | Independent submission replay: 33 fabricated-byte checks | `sha256:913ead583dc4eff79e8b3986d89b1d0e85e86972cb173c2771737c96a20138d9`; original signed `5889169dad07814788508cdc377f543ed17af9ef`, verified and fast-forward integrated. `docs/phase3/admission/SUBMISSION_REPLAY_HANDOFF.md`; raw result/logs remain in Admission. Open-prefix UNKNOWN is not NOT_SUBMITTED or native custody. |
| V-contract | Published contract only | `ownership-and-release-v2.md` and its three linked contracts. Contract publication does not establish implementation or test execution; current delivery/agreement is recorded separately below. |
| V-reader-evidence | Independent ACK/TIMEOUT byte consumer: 14 new checks | `sha256:855ae03253e17074a4ff66c5e4d060f7906cc70a2b25efadb6ca36492cd655c9`; signed original `33f54e2aca224b216a4ae67f0a73588e03252939`, merged preserving ancestry. Byte consistency only. |
| V-policy-tamper | Finite recorder/independent consumer: 26 new inert checks | `sha256:c08b47026e885e68bab6482ca5d858863ef442774f40db55eedea486b3e9ce46`; original signed `d3c5ffed8dbbf0520c9b8d2e9d798e204d09f96d`, merged preserving ancestry. Actual protected policy acquisition and complete ADM-03 remain open. |
| V-reader-store | Permanent claim/retention and owning caller: 16 new mocked checks | `sha256:920a28df3aa7a8f1fab8b55f6d29dea566b16bf070a44b510994e1e13d82e9e8`; root provider checkpoint. Actual accepted telemetry transport and deployment remain absent. |
| V-DNS | Fixed DNS builder and independent retained-byte consumer: 13 new checks | `sha256:89b7cb5add286a2fc0de48c41797455250b5e26f34367fc577aed04f566fe262`; original signed `11dabe6ffeeaddc9e317fc46f93e188ae7fff614`, merged preserving ancestry. Actual result and logs remain in Workloads; `docs/phase3/workload-verifiers/dns-canary-handoff.md`. No live acquisition, completeness or blocking claim. |
| V-broker-submission | Protocol and immutable broker journal: 28 new mocked checks | `sha256:d36e14e55f23068293e2159caa74311a9519b23ce61ab7816108035d58ef574b`; actual result/logs and stable eight-file closure in `broker-reader-provider-handoff.md`. No IPC/provider acquisition, independent transcript agreement, caller/deployment or health authority follows. |
| V-reader-checkpoint | Protected checkpoint acquisition/archive and independent replay: 53 new mocked/fabricated-byte checks | `sha256:091fd6c1739b55e7fae680a4612fd81bdb1d43e2007cf8ded86715855692c67e`; `reader-checkpoint-acquisition-handoff.md`, five-file closure and original Root result/log pins. That result alone does not establish writer/refresh, stream continuity, loss completeness, deployment or effect authority. |
| V-reader-transport | Guarded listener/notice/accepted-connection and actual owning-wrapper wiring: 30 new mocked checks | `sha256:b31f41624a6b096e7d009f690f26706c7531f7fd4c1a48a9eccac728ba26b97f`; original verified signed `5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f`, integrated preserving ancestry. Actual result/log pins and complete 13-file closure: `docs/phase3/run-health/READER_TRANSPORT_HANDOFF.md`. No native custody, loop/health, full timing or qualification claim. |

| V-reader-session | v8 writer and Root session connected to real listener/retention/checkpoint/independent consumers under mocked OS boundaries | Writer 31-check PASS `sha256:d12e062c205649df1c382c07296637e9167944092d02bec2f961172eac0dba6c`; 28 unchanged session methods actually ok in retained aggregate FAIL `sha256:0e4c30d84cc8e12c9a7c5e708ecc611e7b2f598216a4989bf0d4e1a0e99b9ed5`. No successful 59-method aggregate is claimed. `reader-session-handoff.md` preserves final 20-file closure, both results/logs and exact limits. Actual launch/IPC/bridge/source custody and complete loss remain open. |

## Admission: exact 31 requirements

Every row requires Root's admission invocation/loaded identity and deployed
inventory/replay providers. Policy/lifecycle acquisition is additionally required
where named. Consumer paths below identify existing partial consumers or explicitly
pending successors; their independence and full closure must be reviewed before
registration in the final semantic verifier map.

| # | Exact requirement ID | Owner; implementation | Raw evidence and independent consumer | State; validation | Exact unresolved implementation condition |
| --- | --- | --- | --- | --- | --- |
| 1 | `DET-01` | Admission; `S/materialize_openclaw_final_v3_det01.py`, `P/admission_openclaw_final_v3_det01.py` | Canonical input vectors, actual decisions, policy/runtime bytes and repeated invocations; `P/admission_openclaw_final_v3_det01_campaign_qualification.py` | legacy / false / false / false; V-source | Bind deterministic replay to the one current native deployment and complete raw campaign/source custody; standalone DET receipt is insufficient. |
| 2 | `ADM-01/exact-admitted-bytes` | Admission; `B/model-activation-probe.mjs`, `P/admission_evidence_coordinator_activation.py` | Admitted manifest/artifact and bytes actually consumed by native activation/session; legacy consumer `P/admission_evidence_coordinator_activation.py`, native complete consumer pending | legacy / false / false / false; V-source | Port the actual activation/consumption path and verifier to current deployment. Catalog or installed-file equality alone does not prove consumed bytes. |
| 3 | `ADM-02/install` | Admission; `S/runtime_native_admission_install.py`, `P/native_phase3_admission_install.py` | Raw upload-disabled command/response, protected boundary, catalog and target absence; `P/native_phase3_admission_install.py` | partial / false / false / false; V-install | Wire native leaf into shared dispatch/inventory; cover declared local-path, ClawHub and dependency INSTALL ports. Upload-disabled denial is only one branch. |
| 4 | `ADM-02/direct-write` | Admission; `S/runtime_native_admission_direct_write.py` | Six sealed roots/admitted-file mutation outcomes and raw command/catalog bytes; `P/native_phase3_admission_direct_write.py` plus `P/native_phase3_admission_capture.py` | partial / false / false / false; V-source | Existing four-case dispatcher uses an older inventory. Join the repaired common identity and protect observation/custody across the complete operation. |
| 5 | `ADM-02/rename` | Admission; `S/runtime_native_admission_path_mutation.py` | Six insertions, five retargets, errno and retained root/catalog identity; `P/native_phase3_admission_path_mutation.py` plus `P/native_phase3_admission_capture.py` | partial / false / false / false; V-source | Rebind current shared path and retain structural EXDEV/EBUSY separately from permission denials; complete protected custody and semantic gate adapter. |
| 6 | `ADM-02/symlink` | Admission; `S/runtime_native_admission_path_mutation.py` | Six fixed insertion outcomes, target bytes/identities and catalogs; `P/native_phase3_admission_path_mutation.py` plus `P/native_phase3_admission_capture.py` | partial / false / false / false; V-source | Rebind current shared path and complete independently acquired identity/custody and semantic gate adapter. |
| 7 | `ADM-02/auto-discovery` | Admission; `S/runtime_native_admission_auto_discovery.py` | Actual two outside-root fixture creations and fresh CLI/gateway catalog bytes; `P/native_phase3_admission_auto_discovery.py` | partial / false / false / false; V-source | Leaf explicitly lacks common dispatcher/source inventory. Complete declared discovery coverage and actual consumer behavior; two excluded fixtures do not prove active-session consumption. |
| 8 | `ADM-02/restart` | Admission; `S/runtime_native_admission_restart.py` | Retained command output, protected lifecycle log prefix and clock brackets, old/new identity and catalogs; `P/native_phase3_admission_restart.py` | partial / false / false / false; V-restart | Supply policy/lifecycle provider and current shared launch/inventory. Gateway-account emitter authenticity and actual activation/consumption remain unresolved despite mocked joins. |
| 9 | `ADM-02/update/archive-source-force-replacement` | Admission; `S/openclaw_final_v3_archive_replacement_case.py`, `B/protected-archive-replacement-probe.mjs` | Archive/candidate bytes, force invocation, denial and before/after protected target/catalog; `P/admission_protected_final_combined_v3_archive_replacement.py`, `P/admission_openclaw_final_v3_archive_replacement_subfixture.py` | legacy / false / false / false; V-source | Port/rebind predecessor case under current native lifecycle and common evidence/consumer inventory. |
| 10 | `ADM-02/update/clawhub-tracked-replacement` | Admission; declared case only in `P/admission_openclaw_final_v3_campaign_dispatch.py` | Required actual tracked metadata, old/new artifact, update request and protected lifecycle; dedicated native consumer pending | pending / false / false / false; V-source | Implement the distinct ClawHub tracked replacement route and raw-evidence consumer; generic plugin force is not this route. Publish source-confirmed interface before implementation. |
| 11 | `ADM-02/update/config-entry-activation` | Admission; `S/openclaw_final_v3_config_entry_case.py` | Config-entry mutation/activation trigger, loaded config and protected catalog/session observations; `P/admission_protected_final_combined_v3_config_entry_activation.py`, `P/admission_openclaw_final_v3_config_entry_subfixture.py` | legacy / false / false / false; V-source | Native port must join source-to-loaded config and actual activation under current shared inventory. |
| 12 | `ADM-02/update/core-updater-plugin-replacement` | Admission; `S/openclaw_final_v3_core_updater_case.py`, `S/materialize_openclaw_final_v3_core_updater_plugin_replacement.py` | Actual updater/audit-listener invocation, baseline/candidate bytes, denial and target preservation; `P/admission_openclaw_final_v3_core_updater_qualification.py`, `P/admission_openclaw_final_v3_core_updater_plugin_replacement_subfixture.py` | legacy / false / false / false; V-source | Integrate real native updater and protected audit acquisition with current deployment; standalone route qualification is not campaign evidence. |
| 13 | `ADM-02/update/curator-restore-activation` | Admission; `S/openclaw_final_v3_curator_restore_case.py`, `B/protected-curator-restore-denial-probe.mjs` | Restore authority/request bytes, observed denial and catalog/target preservation; `P/admission_protected_final_combined_v3_curator_restore.py`, `P/admission_openclaw_final_v3_curator_restore_subfixture.py` | legacy / false / false / false; V-source | Port and bind native protected restore invocation/lifecycle; retain exact producer, loaded config and artifact joins. |
| 14 | `ADM-02/update/plugin-enable-activation` | Admission; `S/openclaw_final_v3_plugin_enable_case.py` | Enable request, disabled baseline, resulting runtime/catalog and policy observations; `P/admission_protected_final_combined_v3_plugin_enable.py`, `P/admission_openclaw_final_v3_plugin_enable_subfixture.py` | legacy / false / false / false; V-source | Integrate actual enable activation on one native inventory and protected lifecycle; historical route flag does not close it. |
| 15 | `ADM-02/update/plugin-force-reinstall` | Admission; `S/openclaw_final_v3_plugin_force_case.py`, `B/protected-plugin-force-reinstall-v3-probe.py` | Force command/result, installed baseline/candidate identity and protected readbacks; `P/admission_protected_final_combined_v3_plugin_force_reinstall.py`, `P/admission_openclaw_final_v3_plugin_force_subfixture.py` | legacy / false / false / false; V-source | Rebind actual force route and root policy invocation on current deployment; retain baseline-present and absent-target semantics distinctly. |
| 16 | `ADM-02/update/plugin-package-skill-replacement` | Admission; `S/runtime_native_plugin_update_case.py`, `S/runtime_native_plugin_package_check.py`, `P/native_phase3_plugin_update_case.py` | Native package force command, baseline/package/skill/catalog bytes, loaded identity and source bundle; `P/native_phase3_plugin_update_collection.py`, `P/native_phase3_admission_capture.py` | partial / false / false / false; V-source | A native successor exists although frozen V3 dispatch says MISSING_ADAPTER. Integrate it with repaired identity/common source map; do not count generic baseline preservation as all activation or absent-target coverage. |
| 17 | `ADM-02/update/workshop-proposal-apply` | Admission; `S/openclaw_final_v3_workshop_proposal_apply_case.py`, `B/protected-route-probe.mjs` | Actual proposal apply route, proposal bytes, protected target/catalog observations; `P/admission_protected_final_combined_v3_workshop_proposal_apply.py`, `P/admission_openclaw_final_v3_workshop_proposal_apply_subfixture.py` | legacy / false / false / false; V-source | Port actual native proposal lifecycle and current protected observation, then register independent same-deployment semantic joins. |
| 18 | `ADM-02/reload/chat-session-snapshot-consumer` | Admission; `S/openclaw_final_v3_chat_session_snapshot_case.py` | Chat session snapshot, actual consumer output, protected prompt/catalog identity; `P/admission_protected_final_combined_v3_chat_session_snapshot_consumer.py`, `P/admission_openclaw_final_v3_chat_session_snapshot_subfixture.py` | legacy / false / false / false; V-source | Port runtime consumer and retain session/prompt consumption under current native identity; catalog-only observation cannot substitute. |
| 19 | `ADM-02/reload/config-invalidation` | Admission; `B/config-activation-probe.mjs` | Config-change/invalidation trigger, source and loaded config, cache/readback and consumer result; dedicated native consumer pending (legacy `P/admission_protected_config.py`) | legacy / false / false / false; V-source | Source-confirm and port the reload invalidation trigger/consumer separately from update config-entry activation. |
| 20 | `ADM-02/reload/cron-rescan` | Admission; `S/openclaw_final_v3_cron_rescan_case.py`, `B/protected-cron-rescan-probe.mjs` | Actual cron rescan and consumer output with protected files/catalog/session; `P/admission_protected_final_combined_v3_cron_rescan.py`, `P/admission_openclaw_final_v3_cron_rescan_subfixture.py` | legacy / false / false / false; V-source | Join native cron producer/consumer and lifecycle to current source/config inventory, fresh fixture and protected acquisition. |
| 21 | `ADM-02/reload/filesystem-watch-invalidation` | Admission; `B/live-reload-probe.mjs` | Actual watched mutation, watcher/invalidation event and subsequent active consumer bytes; dedicated native consumer pending | legacy / false / false / false; V-source | Port real watcher trigger and independently establish consumer reload, not only final filesystem or CLI state. |
| 22 | `ADM-02/reload/fresh-session-reset` | Admission; `S/openclaw_final_v3_fresh_session_reset_case.py` | Actual reset/new session, prompt snapshot and admitted-byte consumption; `P/admission_protected_final_combined_v3_fresh_session_reset.py`, `P/admission_openclaw_final_v3_fresh_session_reset_subfixture.py` | legacy / false / false / false; V-source | Port reset/session lifecycle and exact protected consumer evidence into common native deployment. |
| 23 | `ADM-02/reload/manual-plugin-invalidation` | Admission; declared case in `P/admission_openclaw_final_v3_campaign_dispatch.py` | Required actual manual invalidation request, plugin/cache identity and subsequent consumer output; native consumer pending | pending / false / false / false; V-source | Missing concrete native adapter/consumer; first confirm actual entrypoint and publish exact path/evidence contract. |
| 24 | `ADM-02/reload/missing-prompt-blob-rebuild` | Admission; `S/openclaw_final_v3_missing_prompt_blob_case.py`, `B/protected-prompt-rebuild-probe.mjs` | Missing prompt blob trigger, actual rebuilt bytes and consumer evidence; `P/admission_protected_final_combined_v3_prompt_rebuild.py`, `P/admission_openclaw_final_v3_missing_prompt_blob_subfixture.py` | legacy / false / false / false; V-source | Port protected absence/rebuild/consumption lifecycle with current source/config and independent native custody. |
| 25 | `ADM-02/reload/plugin-skill-dir-activation` | Admission; `B/plug01-probe.mjs`, `P/admission_evidence_plug01.py` | Plugin-skill directory activation trigger, artifact identity and actual catalog/session consumption; legacy consumer `P/admission_evidence_plug01.py` | legacy / false / false / false; V-source | Port this distinct reload route with current native protected acquisition; plugin-package replacement does not substitute. |
| 26 | `ADM-02/reload/remote-eligibility-invalidation` | Admission; declared case in `P/admission_openclaw_final_v3_campaign_dispatch.py` | Required eligibility-change trigger, invalidation and consumer evidence; native consumer pending | pending / false / false / false; V-source | Missing source-confirmed native adapter and complete raw-evidence contract. Avoid introducing live remote operations during offline implementation. |
| 27 | `ADM-02/reload/sandbox-per-run-rescan` | Admission; declared case in `P/admission_openclaw_final_v3_campaign_dispatch.py` | Required actual sandbox run/rescan, per-run identity and consumed manifest/artifact; native consumer pending | pending / false / false / false; V-source | Implement and independently verify true per-run rescan under current sandbox/native profile, including refusal paths. |
| 28 | `ADM-02/reload/session-snapshot-consumer` | Admission; `S/openclaw_final_v3_session_snapshot_case.py`, `B/protected-session-snapshot-fixed-probe.mjs` | Session snapshot and actual consumer bytes, protected prompt/catalog joins; `P/admission_protected_final_combined_v3_session_snapshot_consumer.py`, `P/admission_openclaw_final_v3_session_snapshot_subfixture.py` | legacy / false / false / false; V-source | Integrate current native session consumer with protected source/config custody; keep distinct from chat consumer case. |
| 29 | `ADM-02/reload/workshop-invalidation` | Admission; `S/openclaw_final_v3_workshop_invalidation_case.py` | Actual workshop invalidation/proposal and subsequent protected consumer observation; `P/admission_protected_final_combined_v3_workshop_invalidation.py`, `P/admission_openclaw_final_v3_workshop_invalidation_subfixture.py` | legacy / false / false / false; V-source | Port/rebind current native lifecycle and protected consumer evidence; route-only historical qualification is insufficient. |
| 30 | `ADM-03/policy-failure` | Admission; `B/adm03-probe.mjs` | Actual unavailable/failing/malformed policy invocation, denied activation and protected target/loaded config; native consumer pending | legacy / false / false / false; V-source | Publish exact current failure modes and native command/provider contract; complete each fail-closed route including required absent-target route. |
| 31 | `ADM-03/policy-tampering` | Admission; `P/native_phase3_admission_policy_tamper.py` and `P/native_phase3_admission_policy_tamper_verify.py` | Twelve retained mutation callbacks, raw source/config/printf readbacks, post-mutation actual policy observation and baseline/catalog preservation; independent verifier | partial / false / false / false; V-policy-tamper | Wire Root's actual protected policy invocation/acquisition into the integrated finite recorder/consumer. Structural rename refusals stay distinct; baseline-present route and no authentic emitter proof do not close full ADM-03. |

## RUN: exact 15 requirements

Every RUN row requires Root's serialized broker/causal lineage and deployed
inventory providers. Reader/loss/response providers are additional dependencies
where named. Existing evidence modules below may cover a narrower predecessor
profile; a final trusted semantic adapter must independently establish the exact
row and its campaign joins rather than accept embedded PASS flags.

| # | Exact requirement ID | Owner; implementation | Raw evidence and independent consumer | State; validation | Exact unresolved implementation condition |
| --- | --- | --- | --- | --- | --- |
| 32 | `RUN-01` | RUN + Root; `P/runtime_active_skill_lineage_v2.py`, `P/runtime_lineage_capability_issuer.py`, `P/runtime_action_broker_v5.py` | Activation/session/request/process/cgroup/digest/capability/decision/result chain and actual unattributed a100; partial `P/runtime_producer_lineage_openclaw_systemd_evidence.py`, `P/runtime_active_lineage_openclaw_systemd_evidence.py`, workload consumers; complete semantic adapter pending | partial / false / false / false; V-source | Connect every protected action to real authenticated lineage; implement a100 through a genuinely unattributed unlink path and independently prove pre-effect denial. Removing an attribution label is invalid. |
| 33 | `RUN-02` | RUN + Root; `P/native_phase3_run_reader_transport.py`, `P/native_phase3_run_progress.py`, `P/native_phase3_run_acquisition.py`, `P/native_phase3_run_reader_response.py`, `P/native_phase3_run_reader_checkpoint_acquisition.py`, broker and response modules | Protected ACK/TIMEOUT, claim/readback, loss/program/map snapshots, serialized submission state and actual effect/response evidence; `P/native_phase3_run_progress_verify.py`, `P/native_phase3_run_acquisition_verify.py`; `P/native_phase3_run_reader_evidence_verify.py`, `P/native_phase3_run_reader_checkpoint_verify.py` | partial / false / false / false; V-reader, V-reader-evidence, V-reader-store, V-reader-checkpoint, V-reader-transport, V-reader-session, V-submission-replay, V-broker-group-delta | Connect the implemented reader loop and Root checkpoint/refresh session to actual launch/IPC/loss acquisition and enforce them under the broker lock. Idle/hung distinction, stale/replayed challenges and unknown/reset/lost counters must fail closed; post-submission ambiguity must remain explicit. |
| 34 | `EVENT/SKILL_ACTIVATION_AND_COMPLETION` | RUN + Root; `P/runtime_active_skill_lineage_v2.py`, `P/runtime_skill_startup.py` | Actual admitted skill activation and completion events with session/process interval and digest; partial `P/runtime_active_lineage_openclaw_systemd_evidence.py`; completion semantic consumer pending | partial / false / false / false; V-source | Add actual completion acquisition and causal joins; a startup/active binding alone is not the two-ended event lifecycle. |
| 35 | `EVENT/TOOL_CALL_ATTEMPT_AND_RESULT` | RUN + Root; `S/materialize_runtime_native_tool_hooks.py`, `P/runtime_native_tool_receipts.py`, `P/runtime_action_observation_publisher_v4.py` | Real request/tool identity, process/capability, attempt and final/ambiguous result bytes; partial `P/runtime_broker_effective_receipt_verify.py`, `P/runtime_action_worker_openclaw_systemd_evidence.py` | partial / false / false / false; V-source | Join native hooks to authenticated broker/sensor records for all protected tools; retain actual attempts even when request/result delivery fails. |
| 36 | `EVENT/PROCESS_EXECUTION_AND_ANCESTRY` | RUN + Root; `P/runtime_tetragon_process.py`, `P/runtime_process_profile.py`, `S/runtime_phase3_common_process_observer.py` | Raw exec/parent events, process start/PIDFD/cgroup and namespaces, reader/loss continuity; partial `P/native_phase3_common_process_verifier.py`, `P/runtime_process_profile_openclaw_systemd_evidence.py` | partial / false / false / false; V-source, V-HTTP (identity composition only) | Wire genuine process event acquisition and causal ancestry with protected continuity; point-in-time process identity is not a complete event stream. |
| 37 | `EVENT/FILE_READ_WRITE_RENAME_AND_EXECUTABLE_CREATION` | RUN + Root; `P/runtime_action_worker.py`, `P/runtime_action_broker_v5.py`, existing Tetragon/source modules | Actual file read/write/rename/creation event bytes, object/actor identity and applicable loss evidence; partial `P/runtime_acquisition_action_multifile_systemd_evidence.py`, `P/runtime_acquisition_action_nested_systemd_evidence.py` | partial / false / false / false; V-source | Cover each named operation on the current deployment; existing protected-create boundary and direct-write admission snapshots do not cover all runtime file events. |
| 38 | `EVENT/NETWORK_CONNECTION_AND_DNS_ATTEMPT` | RUN + Workloads + Root; `P/runtime_http_broker.py`, `P/native_phase3_http_collection.py`; `P/native_phase3_workload_dns_canary.py`, `P/native_phase3_workload_dns_verify.py` | Raw connection/DNS attempts, retained HTTP ingress/DNS packets, process/cgroup and loss joins; `P/native_phase3_http_collection_verify.py`; `P/native_phase3_workload_dns_verify.py` | partial / false / false / false; V-HTTP, V-DNS | Wire actual network event acquisition plus owned DNS observer/readiness/completeness. Empty sink output cannot prove no attempt or blocked exfiltration. |
| 39 | `EVENT/CREDENTIAL_OR_CANARY_ACCESS` | RUN + Workloads + Root; `P/native_phase3_http_canary.py`, `P/native_phase3_http_fixture.py`, owned HTTP/DNS workloads | Actual access event tied to canary/credential identity, actor and protected sink interval; partial HTTP collection consumer; complete access-event consumer pending | partial / false / false / false; V-source, V-HTTP (credential plumbing only) | Acquire and attribute actual access, not only delivery/absence at sink. Repaired service credential reads are infrastructure, not automatic event coverage. |
| 40 | `EVENT/PROMPT_CONTEXT_OR_MEMORY_MUTATION_WHERE_RUNTIME_EXPOSES_IT` | RUN + Admission + Root; predecessor prompt/session consumers, native tool hooks | Exposed runtime mutation request/result, before/after protected prompt/context/memory identity, session and actor; partial `P/admission_protected_final_combined_v3_prompt_rebuild.py` and session consumers | partial / false / false / false; V-source | Source-confirm exposed mutation ports and implement acquisition/semantic replay on native runtime. Admission reload checks alone do not prove runtime mutation-event coverage. |
| 41 | `RESPONSE/ALERT_AND_RETAIN_EVIDENCE` | RUN + Root; `P/runtime_action_observation_publisher_v4.py`, `P/runtime_response_service.py`, reader response leaf | Trigger, actual alert/result, permanent retained bytes/digest/readback and failure disposition; `P/native_phase3_run_reader_evidence_verify.py`; complete alert/retention consumer pending | partial / false / false / false; V-reader, V-reader-evidence, V-reader-store, V-reader-checkpoint | Wire protected durable retention and actual alert delivery to the event. Complete supplemental bytes can exist after retention failure; they are not evidence of leaf success or retention. |
| 42 | `RESPONSE/BLOCK_PRE_EFFECT_TOOL_OR_NETWORK_ACTION` | RUN + Workloads + Root; `P/runtime_action_broker_v5.py`, `P/runtime_http_broker.py`, `P/native_phase3_blocked_create_verify.py` | Serialized request/decision and independently observed effect interval/residue for each family; partial blocked-create/HTTP consumers | partial / false / false / false; V-source, V-HTTP (offline composition only) | Wire reader/loss gates before real submission, support DNS/truncate/unlink and preserve INDETERMINATE after submitted uncertainty. A receipt or final unchanged snapshot is insufficient. |
| 43 | `RESPONSE/TERMINATE_CAPABILITY_PROCESS_TREE` | RUN + Root; `P/runtime_response_service.py` | Exact trigger/capability/process tree, held identities, stop results, descendant/cgroup-empty readback and retention; partial `P/runtime_revocation_openclaw_systemd_evidence.py`, `P/runtime_action_worker_sensor_loss_systemd_evidence.py` | partial / false / false / false; V-source | Compose actual cause-bound termination and complete descendants on current profile. Fixed service stop alone does not establish arbitrary capability process-tree termination. |
| 44 | `RESPONSE/QUARANTINE_INSTALLED_DIGEST` | RUN + Root; `P/runtime_quarantine_response.py`, `P/runtime_quarantine_service.py`, `P/protected_skill_quarantine.py`, `P/runtime_skill_startup.py` | Exact installed artifact/digest, protected denial publication, active-stop result, subsequent start denial and immutable readback; complete same-deployment consumer pending | partial / false / false / false; V-source | Integrate deployed quarantine/startup hook and independent raw consumer. Existing source explicitly requires successor producers/service overlays/startup enforcement together; profile masks do not equal digest quarantine. |
| 45 | `RESPONSE/REVOKE_FUTURE_STARTS_OF_DIGEST` | RUN + Root; `P/runtime_revocation_service.py`, `P/runtime_skill_startup.py`, `P/runtime_response_service.py` | Revocation trigger/snapshot/readback, exact digest and later actual startup refusal; partial `P/runtime_revocation_openclaw_systemd_evidence.py` | partial / false / false / false; V-source | Wire actual digest-specific revocation into all admitted starts and verify future refusal under current deployment; a current process stop or generic service mask does not close it. |
| 46 | `RESPONSE/ISOLATE_EGRESS_OR_SUSPEND_HIGH_RISK_OPERATIONS_WHEN_SENSOR_HEALTH_IS_LOST` | RUN + Root; `P/runtime_health_watchdog.py`, `P/runtime_response_service.py`, `S/runtime_native_sensor_loss_check.py` | Reader/loss failure trigger, protected pending latch, PIDFD/cgroup-bound stop/mask, subsequent action denial and retained result; partial `P/runtime_action_worker_sensor_loss_systemd_evidence.py` and reader verifiers | partial / false / false / false; V-reader, V-source | Connect actual hung/idle/expiry/missing/reset/loss detection to existing response mechanisms, cover in-flight ambiguity and independently verify suspension. Historical idle-sensor response does not cover all health failure modes. |

## External boundary and measurements: exact final two requirements

| # | Exact requirement ID | Owner; implementation | Raw evidence and independent consumer | State; validation | Exact unresolved implementation condition |
| --- | --- | --- | --- | --- | --- |
| 47 | `EXTERNAL_OS_BROKER_AND_OUT_OF_PROCESS_SENSOR` | Root; `P/runtime_action_broker_v5.py`, `P/runtime_observation_service_v4.py`, `P/native_phase3_live_identity.py`, `S/materialize_native_phase3_http_credential_helpers.py`, `S/materialize_native_phase3_http_credential_capture.py` | Held broker/sensor/runtime identity, UID/GID/capabilities/cgroups/namespaces, executable/loaded credentials/units, protected sockets and source closure; `P/native_phase3_common_process_verifier.py` as transformed by credential helper, plus capture consumers | partial / false / false / false; V-HTTP | Complete common admission/runtime/workload deployment wiring, protected real reader/provider acquisition, and one explicit independent external-boundary semantic adapter. Offline read-only credential checks and generated units are not deployed isolation proof. |
| 48 | `MEASUREMENT_SEMANTICS` | Workloads + Root; `P/phase3_measurement_collector.py`, `P/phase3_quantitative_metrics.py`, `P/phase3_reference_tasks.py`, four `P/native_phase3_workload_*` callbacks below | 100 real action attempts, independent sink/residue/attribution evidence, full request/decision timing and 100 actual task pairs with equal task/input/host identity; `P/phase3_measurement_replay.py`, four benign consumers, HTTP/clock/ingress/broker consumers below | partial / false / false / false; V-benign, V-HTTP, V-DNS | Wire all four action scenarios and genuine a100, real paired environments, protected fresh contexts, cancellation, full clock-domain joins and trusted independent measurement consumer map. Arithmetic and callback timing do not establish metrics without actual complete acquisition. |

### Workload implementation breakdown for requirement 48 (not extra gate rows)

The fixed reference plan is `benchmark/phase3-reference-workload-plan-v1.json`.
Its declarative NOT_IMPLEMENTED_ON_COMMON_DEPLOYMENT fields are planning state;
the completed leaves below refine source implementation status without claiming
the full shared path is complete. Counts are fixed: HTTP a001–a025, DNS a026–a050,
truncate a051–a075, unlink a076–a100; a100 is the one actual unattributed control
inside the DESTRUCTIVE denominator. No additional action or benign task is needed.

| Component | Existing implementation / independent consumer | Root provider and precise remaining work |
| --- | --- | --- |
| HTTP canary | `P/native_phase3_http_canary.py`, `P/native_phase3_http_collection.py`, `P/native_phase3_http_sink.py` / `P/native_phase3_http_collection_verify.py`, `P/native_phase3_http_readiness_verify.py` | Reuse repaired credentials/retained stage report. Complete actual common protected execution, readiness/acquisition, full ingress timing, loss and independently authentic sink joins; no deployed-success claim. |
| DNS canary | Integrated `P/native_phase3_workload_dns_canary.py` / `P/native_phase3_workload_dns_verify.py`; V-DNS, `dns-canary-contract-v1.md` | Reviewed finite builder/retained-byte consumer are implemented; Root supplies actual loopback UDP observer, separate readiness, held endpoint/process identity and applicable complete/loss evidence. Literal canaries in malformed/refused packets count. |
| Truncate | Fixed scenario in reference plan; full native execution adapter and independent interval consumer pending | Publish exact action/broker/object-custody contract and lane paths; protect original bytes throughout interval, including temporary truncation restored before final readback. |
| Unlink and a100 | Fixed scenario/control in reference plan; full native execution adapter and independent interval consumer pending | Publish contract and paths; observe continuous name/object custody and detect deletion/recreation. Actual unattributed process must reach the separate fail-closed broker path without fabricated lineage. |
| BENIGN_JSON_SUM | `P/native_phase3_workload_json_sum.py` / `P/native_phase3_workload_json_sum_verify.py` | Completed bounded task/consumer (V-benign); connect collector/replay and source identity to actual baseline/instrumented contexts. |
| BENIGN_LINE_COUNT | `P/native_phase3_workload_line_count.py` / `P/native_phase3_workload_line_count_verify.py` | Completed bounded task/consumer (V-benign); same actual pairing/context dependency. |
| BENIGN_SHA256 | `P/native_phase3_workload_sha256.py` / `P/native_phase3_workload_sha256_verify.py` | Completed bounded task/consumer (V-benign); same actual pairing/context dependency. |
| BENIGN_COPY_READBACK | `P/native_phase3_workload_copy_readback.py` / `P/native_phase3_workload_copy_readback_verify.py` | Completed bounded task/consumer (V-benign); Root supplies fresh held directory and cancellation/retained file custody. Post-task identity alone does not establish uninterrupted creation-to-readback custody. |
| Full decision timing | `P/runtime_broker_decision_measurement.py`, `P/native_phase3_ingress_interval_verify.py` / `P/runtime_broker_decision_measurement_verify.py`, `P/native_phase3_clock_domain_verify.py` | Retain authenticated REQUEST_ACCEPTED and DECISION_FINALIZED endpoints in the same validated CLOCK_BOOTTIME domain; do not replace with a narrower internal broker interval. |
| Full task timing and replay | `P/phase3_measurement_collector.py` / `P/phase3_measurement_replay.py`, four task consumers | Retain TASK_ACCEPTED and TASK_COMPLETED for two actual executions per pair. Mode labels do not prove an environment switch; source/task/input/host/clock joins and independent replay remain required. |

The existing thresholds remain unchanged: attribution >=99%; residue-free
pre-effect blocking 100% separately for EXFILTRATION and DESTRUCTIVE; nearest-rank
p95 over 100 full decision intervals <500ms; aggregate instrumented task duration
strictly below 110% of baseline across 100 pairs. No threshold is evaluated here.

## Current checkpoint and release order

V15 releases a second non-overlapping Root internal implementation: finite HTTP94
seven-output renderer/accessor/real caller, including the two HTTP-specific reason
consumers that reject mapped RUN refusals. Actual original/report/generated pins
are distinguished; no historical stage executes. Root client35 stable candidate
is submitted for source/20-path closure review, with the generated accessor honestly
mocked. Source-only client/renderer work does not close native launch, actual
protected inputs, stream/loss/program/map, lifecycle, destructive or paired-context
providers. No new result or48-entry requirement status is inferred.

Root service44 frozen source is now independently reviewed with no remaining
concrete source blocker (broker-reader-service-source-review-v1.md); actual
Admission signed dependency/result is still pending before execution. The
available Root internal owner receives v14's exact client module/test/handoff
assignment, with real public journal/readback, configuration lifetime, missing
accessor and non-root observation ceilings fixed. Source implementation can proceed
concurrently; generated caller/accessor/launch remains separate Root work. RUN's
unexecuted59 successor has the same four precise corrective conditions still
open; no new stage or PASS is inferred. All48 row states/old results remain intact.

15 October follow-up source review: Admission's corrected context67 stage is
published at d7ebe099; exact newer receipt and actual result remain pending.
RUN's acknowledged v12 bootstrap55 draft has its complete three-input closure
reviewed, but four concrete transfer/deadline/PIDFD/receipt corrections are
published in bootstrap-source-review-v1.md before any execution. Workloads'
v11 first27 proposal remains unexecuted pending its four published corrections.
Root's actual v13 service44 candidate now includes bounded review corrections
and is undergoing frozen-byte approval; original signed Admission integration
still blocks its execution. These are draft/review facts, not new validation
references or changes to any of the48 requirement states. No unaffected evidence
or HTTP94 predecessor report was changed or rerun.

Latest 15 October active coordination: direct incoming messages confirm RUN and
Workloads verified/fast-forwarded f65e8f3 and agreed the complete v12/v11 contracts;
both began their exact released implementations. Admission submitted corrected
stable v9 source, twelve-input closure and67 methods. Root plus two independent
reviews found the two read/close corrections and late-armed cases ready for the
first selected native-broker-reader-context stage. This checkpoint publishes
its owning Admission schedule; actual result/new schedule receipt remain pending.
The preceding123 registry entries remain unchanged. No new result is inferred.

Root v13 releases only its three-path actual broker/reader service, including
real session construction, guard listener/readiness writer, public context
acquisition and complete raw/error retention. Actual Admission signed delivery
is a service execution dependency; offline implementation proceeds concurrently.
Root retains client/HTTP renderer/launch, stable generated/deployed inventories,
stream/loss/program/map, policy/lifecycle, destructive and paired providers.
V12 remote supervisor-PIDFD observation is clarified using existing role/schema;
no packet or privilege changes. All final qualification positions remain false.

15 October infrastructure release: Root inspected all three active lane heads
read-only; all are ancestors of 6af32a0 and no unintegrated signed lane delivery
exists. Admission's two published context corrections remain unapplied. RUN's
actual DNS result is complete and unchanged. Workloads receives the bounded
four-path actual peer-lineage/independent-comparison assignment under v11 and
`destructive-lineage-contract-v1.md`; source-backed version-path and sequential
caller decisions are resolved. This source-only release creates no stage or
native a100/enforcement claim. Root retains actual loaded-config/positive-hold,
bootstrap/caller/observer and deployed custody prerequisites. The detailed shared
and four-owner prompts are `worktree-handoffs-2026-10-15.md`. All final positions
remain false; earlier dated entries below are historical checkpoint records.

The subsequent v12 release delegates the three-path fixed broker/provider
bootstrap to available RUN, with exact four-packet/two-FD/readiness APIs and
self-contained schemas. Successful and failed raw acquisitions remain retained;
transport lifecycle cannot assert health or effect authority. Root retains
actual unit/source/protected launch origins, provider construction/lifetime,
service/client/HTTP renderer/configure and deployed inventory. No new stage or
native support result is inferred from this source release.

14 October DNS delivery: Root verified original signed
`a32477b0b38248f7dca825ec022ad4c0e467558d`, its exact five assigned paths,
parent `a7c771c243aa303d765a18f8ed4860d3e825acc4` and all fourteen tested
dependency pins, then fast-forward integrated it preserving ancestry. The first
selected `native-dns-acquisition` stage passed all 50 methods once in RUN:
`sha256:3b989508ec43b9ab89102eae7723aeefcf5bff8702b1266f21a770099a0bb88c`.
Root reviewed its actual result and all method logs; their pins are retained in
`../dns-provider/ACQUISITION_HANDOFF.md`. Reuse that unchanged result; no rerun
or invented composition aggregate. This closes the bounded acquisition/context/
replay leaf, not real DNS readiness, completeness, retention, dispatch or native
qualification. All final positions remain false. Admission's two published
descriptor-boundary corrections remain pending before its first schedule.
Workloads' destructive/a100 source release remains pending a concrete contract.
Earlier dated entries below describe their respective historical checkpoints.

Latest first DNS schedule: RUN acknowledged v2/34c1f82 and corrected all reviewed
boundaries. Root reviewed the final 14-file closure and 50 new methods, including
the present-snapshot start requirement and missing-finish fallback. The first
`native-dns-acquisition` schedule is released only by its signed published
containing checkpoint; no actual result yet. See
`dns-acquisition-review-and-scheduling-v1.md`. Admission submitted its exact
12-input/55-method context slice; `broker-context-source-review-v1.md` records
two read/close custody corrections before its first schedule. Workloads remains
available pending Root's concrete destructive/a100 source contract. No requirement
or final qualification state is promoted by either source review or schedule.


Latest DNS correction review: all three owners acknowledged and fast-forwarded
their own branches to signed 722c479, preserving drafts. RUN submitted corrected
source with a matching 14-file closure and 42 focused methods, including the
integrated fixture helper. `dns-acquisition-source-review-v2.md` records remaining
terminal/partial/resource-exhaustion/cleanup-owner/flag/deadline and regression
premise corrections before execution. No DNS stage is registered/scheduled and
no test result or requirement-state promotion follows. Admission implements v9;
Workloads is available pending Root's four concrete destructive/a100 decisions.


14 October DNS source review: RUN submitted its actual fourteen-file dependency
closure and 34 focused methods; Root verified their inventory without execution.
The first DNS schedule remains unreleased pending corrections in
`dns-acquisition-source-review-v1.md`: terminal replay/partial chronology/cleanup
joins and actual descriptor checks at read/poll/close boundaries. Root releases
its separate two-path fixture cleanup repair under v10; RUN must not edit that
shared helper. The repair is now integrated after independent review and the
first selected 25-method PASS (V-fixture-cleanup). Its exact integrated helper pin
sha256:caa7ec1bf5ff1f768fe626009fdf208472f169abca539c5374ccf69b0f144f93
must enter the corrected DNS closure. No DNS validation or requirement-state
promotion follows from either source review or this bounded cleanup result.


Latest reviewed integration: original signed Admission `5889169`, preserving c0
and all preceding lane ancestry. All three lane owners explicitly acknowledged
c0 and their released assignments. Admission replay is delivered; RUN implements
v7 DNS; Workloads delivered only its assigned destructive/a100 design review
(SHA-256 `3028a8d267d9cc6b50d354b521e881155b86693b2026a66c6cc02d843c97838a`).
The four unresolved destructive decisions are real ingress/intent, mutation
custody/backend, start/quiescence barriers and genuine a100 lineage absence.

v9 releases protected broker context acquisition to available Admission in three
new exact paths. Root retains actual service/caller/launch and independently
protected expectations. v9 receipt is unconfirmed; outgoing bridge delivery
still failed after incoming acknowledgments and will not be retried unchanged.
No additional tree is needed for these ready assignments. Root's shared-group
journal correction preserves actual broker identity and all filesystem custody;
its four new selected delta/composition checks passed once (V-broker-group-delta), separately from the original 28 checks. Their old fingerprint remains bound to old journal bytes. Neither a new
contract nor bounded source PASS promotes a requirement-level state.

Completed at the source base: signed integrated bounded admission/RUN/benign-task
leaves, published three-lane contracts, offline HTTP protected credential repair
and composition. In this coordinator turn all three actual lane owners sent
acknowledgements, and Root's read-only branch checks confirmed each at
`d87572182584f9c106393a2ca952c69703b6da6d`. Delivery/agreement is confirmed by those
messages and checks, independently of the still-unavailable outbound task bridge.
Subsequently RUN completed its reviewed 14-case stage under the corrected runner,
signed `33f54e2aca224b216a4ae67f0a73588e03252939` and Root merged it. Admission
subsequently acknowledged `4ec18f8`, passed its scheduled 26 checks and delivered
verified signed `d3c5ffe`, now integrated. Workloads acknowledged `4ec18f8`, corrected
the full-marker bug and submitted the unchanged six-file closure; Root reviewed
the delta and scheduled its 13-method stage in
`dns-delta-review-and-scheduling-v1.md`. Workloads then verified and fast-forwarded
to `95b676e`, accepted v4 and delivered original signed `11dabe6` with the actual
13-check PASS (V-DNS). Root inspected source/result/log pins and merged without
rerunning or copying evidence. Admission and RUN explicitly acknowledged their
v4/v3 contracts at `95b676e`. Admission later delivered original signed `5889169` with the actual 33-check PASS; Root verified and fast-forwarded it without rerun. RUN
subsequently accepted both custody corrections and the final closing-read ordering
fix, verified/fast-forwarded its own branch to schedule `afb06c4`, and delivered
the original signed transport commit `5193a2f` with actual first 30-check PASS.

Released implementation paths are those in `ownership-and-release-v2.md`:
policy-tamper recorder/consumer, completed reader evidence consumer, DNS
builder/consumer and the now integrated RUN guarded transport leaf. Actual launch of the integrated reader loop/writer, independent transport replay
and deployment remain open.
Root checkpoint acquisition/archive and independent byte verifier are implemented
under v6 and passed the one reviewed 53-check stage (V-reader-checkpoint).
They do not establish live checkpoint production, refresh or loss completeness.
The published broker contract splits Root protocol/journal from Admission
independent transcript replay. Root's two modules are implemented and have the
28-test V-broker-submission PASS; Admission's independent consumer source is reviewed
and its 33-method stage was scheduled by `ce038d8`; actual result and original signed delivery are now reviewed and integrated (V-submission-replay).
RUN completed both custody corrections and the final PIDFD/pipe read-order fix.
Root reviewed the stable 13-file closure and 30 methods, published the first
selected schedule, then reviewed actual PASS/result/log bytes and verified original
signed `5193a2fcdd0cb4173ddeeaa7188aa74fd2c7b09f`. Root fast-forwarded its own
integration branch to this direct child, preserving original ancestry and leaving
the lane untouched. The result remains in RUN; no rerun or cache copy occurred.
The original fdinfo replay and point-sample limits remain. An uncertain socket
detach requires retained supervising owner/error references; no completed cleanup
is inferred. Root reuses the now available RUN owner for the already reviewed DNS acquisition
slice under v7. The connected reader/session contract is now reviewed and
source-released by v8 to two internal Root owners, with independent review.
Both source/test pairs are now implemented and reviewed. The first 59-method
stage retained FAIL with 57 ok; a diagnosed writer fixture-only correction then
passed the newly scheduled writer-only 31 methods. The unchanged 28 session
method results are reused transparently (V-reader-session), without inventing a
successful aggregate. Real caller/launch/IPC and loss/source custody remain open;
none of the four complete requirement-state positions is promoted.
The conservative terminal result is SUBMITTED or UNKNOWN; only the actual guarded
broker can emit a current pre-connect snapshot. Real acquisition/IPC and owning
broker integration remain open, so no requirement-level row becomes qualified.
The DNS builder dependency is integrated. v5 originally proposed an additional
operator-created DNS worktree; no creation or owner agreement was confirmed.
After signed transport integration freed the RUN owner, `provider-release-v7.md`
reassigns the ready five-path acquisition/context contract to that existing RUN
worktree and withdraws the additional-tree request. RUN acknowledged c0/v7 and is implementing DNS. Stable source/closure and actual focused validation remain pending. Its bounded receive sample always reports incomplete
observation; full readiness/quiescence/drain and protected retention remain separate
missing provider conditions.
Only the individually reviewed stages are released by the scheduling documents.
DNS's selected stage is complete; do not rerun it unchanged. No acquisition stage
is scheduled until its stable source closure is reviewed. Root checkpoint acquisition
has completed that review and selected execution; this is separate from DNS acquisition.
Root continues shared providers in parallel and must connect
each completed leaf rather than treating local PASS as full requirement closure.

Root's bounded provider assignment is documented in
`reader-storage-provider-contract-v1.md`: new
`P/native_phase3_run_reader_store.py`, `P/native_phase3_run_reader_acquisition.py`
and `tests/test_native_phase3_run_reader_store.py`. It now has reviewed source and
16 passing mocked checks (V-reader-store), supplying permanent consume-once
storage, retention/readback and an owning caller of the existing reader leaf;
accepted endpoint provisioning, actual sensor loop, loss/program/map acquisition
and serialized broker enforcement remain separate Root obligations.

The blocking sequence is provider completeness, source/loaded-identity coherence,
independent semantic coverage and actual paired execution. Publish next bounded
contracts promptly for the admission gaps, remaining RUN events/responses and
destructive workload/control paths. No row here authorizes live operations,
private retention or cleanup. All existing holds remain.

1. Complete the shared common runtime/provider path from the repaired HTTP base.
2. Finish the released lane slices and remaining admission/RUN/workload paths;
   integrate actual attribution, cancellation, full timing and paired contexts.
3. Complete the exact 48-entry independent verifier/evidence inventory and deployed
   custody, then publish a freeze candidate only after implementation gaps close.
4. After separate operational release, perform same-deployment 31 admission cases,
   100 attempts and 100 pairs, independent replay and verified cleanup; evaluate
   final qualification only from that complete evidence.
