# Native restart lifecycle contract v1

Coordinator base: `b3fca83615cd6fd69b463ca8cebcebc660990dec`.
Status: source-confirmed command and file-log design, with an exact proposed
reader API. No protected lifecycle provider, guest launch, native observation,
stage registration or test scheduling is implemented by this document.
The admission lane must agree to the interface and the coordinator must publish
a containing signed checkpoint before releasing one finite mocked leaf batch.
Root owns actual provisioning, protected reading, source/config inventories,
supervision, retention, registration, closure review and later scheduling.
All existing qualification ceilings and the evidence/cleanup hold remain.

## Offline source confirmation and installed-byte boundary

The existing public build archive was read in memory, without extraction or code
execution, after its byte count and SHA-256 matched the tracked build receipt
`benchmark/evidence/phase3-native-tool-runtime-build-development-v2-2026-09-13.json`:

```text
.aragorn/artifacts/native-cache-build-79ed6eb/openclaw-2026.7.1.tgz
bytes = 19921213
sha256 = 9923017c01a2905a4cc953f817e5ea2dfb75ece462f6376d589a664bfdbb4df2
upstream signed commit = 7fa98d8e21b6d5937f25a7f19445ff683bb980bf
Aragorn source overlay commit = 79ed6ebe170a4926081874a141ae149d4cd0db6c
recorded installed runtime-tree/v1 digest = 4e6e94cf4fb8a2527ec1cd789b20a7ddf6c84f03973b3579ded64ef8e2ef96c3
```

The upstream commit signature was verified. The overlay is an Aragorn commit,
not an OpenClaw revision. `dist/build-info.json` has `commit: null`; it cannot
substitute for this provenance chain. These checks confirm the inspected public
package bytes and their recorded source context, not a currently installed guest.
Before any future native attempt, the coordinator must independently read back
the actual installed runtime tree, selected members, Node executable, entry,
gateway unit and credential config. Entry equality alone cannot identify a whole
build. Any new build requires its own signed inventory and selected-member review.

Selected package members below are relative to `package/`; SHA-256 values are
over exact uncompressed member bytes, including original newlines:

| Member | SHA-256 |
| --- | --- |
| `openclaw.mjs` | `f643b005d6db233a0b45204e8d8e943256874ccc6897b8a6e0cf42a9b376a188` |
| `dist/entry.js` | `593f0d4cb319789517f5cdc13d6fe67f3c665d4de4649d67a4a4158bb42d1e77` |
| `dist/cli/run-main.js` | `7c41d8f11ccc9efdfe14c29185e331ec537ff9b3bee383733df10ac8f2af1202` |
| `dist/program-CMrT2U8B.js` | `f6d53c59240ffcc8336d99ad0dbce9dcc72472c8331b6f68f3c8df6a5a3e5c6d` |
| `dist/register.subclis-core-BJmLUN18.js` | `7a8a4911536ee6e548ac584d4af8e84d6b07edbf370d979b2bcd99216d03ec5f` |
| `dist/gateway-cli-DQXs76A9.js` | `f011fcdd3b81f3857a05eed0afb465b1666a7ce7cc2d4f2eed261e382a4ba8f5` |
| `dist/register-service-commands-Br1-4-DD.js` | `f8637aa6509b9f95423a0766f6c73195226e48081a95a95bf445628b59243c2c` |
| `dist/lifecycle.runtime.js` | `38567ca99aad1e8389b53867ca7578096221d6f7977cbf23e66a89ef8b361d39` |
| `dist/lifecycle.runtime-BFu6ywCh.js` | `a9729616cfaf4327c839aaa8c38ec0ea8965266d6bb12c6b76d36aae63a3d584` |
| `dist/lifecycle-DVIgbP7g.js` | `6851530a60f82792760311928bbe58964a24264b94d43d6a7e4e23b391980ee3` |
| `dist/restart-Cx1Esxi8.js` | `34516c74aa12e858141056e6cca5d68956541dc6876a788d8631c1ecf6c09795` |
| `dist/restart-BsqXS59K.js` | `a0c30f8fc3f3af9c826255be2e18f797830f43f000f5c29f9f8b24d23f032f67` |
| `dist/command-startup-policy-Bq9-nxRO.js` | `61019e6609645c0f002320aeebf36ff5496a9d2a97898147f3b07d4b1c2741e4` |
| `dist/command-execution-startup-DMrUT-xv.js` | `47c3a0bcac6eb0d012bb508f7dc7a4ada07bb4677ce30d8613dacc1fa2e01b59` |
| `dist/console-DDSYsaep.js` | `faff7c61cb0001572ebe3d91f05969d5c376c67a754931a38ba696de0778a1fb` |
| `dist/runtime-Bz6o617W.js` | `9af5022ec649764fddf3040207f03109d49f5a8c2aeb6a71e051b5bd1c8e13d0` |
| `dist/run-command-CHUT0sgt.js` | `115b778818877ee33910cf70c658ec942d0cecd6e49b9243e1a5affb477a711e` |
| `dist/run-command-faE14xVE.js` | `d7a804c583312d3beddb807bd1c5345bfcd2bca282bd38f5d6fcf6fdf3dfaf17` |
| `dist/run-BO64ei9s.js` | `b8cbd359733f4aa96eba56ccdd490b9bb58f7883f45acea959bbc8a7e8553f1b` |
| `dist/cli/gateway-lifecycle.runtime.js` | `0b3a976cf3dbda5c158f244738c2365220f57168db9a6e646f7f0954f1a4943c` |
| `dist/server-BlFdCOko.js` | `3b59507f913be683ef5440ab1c03d87dd21395dcf6f0660f7790b0aed4f7e137` |
| `dist/server.impl-LClSwLYM.js` | `3e1e3d206dcd61bbe26b94b6a4cb7fdc536c0cac2a257b39c074bb4339b00d1b` |
| `dist/server-methods-mj06PYQm.js` | `335efb4080c7194e56fdcc3ce44f0a73c1c40b095fba2160179fe09eca06cd1e` |
| `dist/server-close.runtime.js` | `c9f3ff955d93322fd3b6d313e63de9026fedd12c54489ec02e6b43374c4c460b` |
| `dist/server-startup-post-attach-C_v2J7XH.js` | `57c35044824a85f3c8274d2db97f5692bc2f9ca5f2253b38fb4eca018282b700` |
| `dist/subsystem-C3fiUGN1.js` | `c910fb41a4791d03ffe06b94cb18a8563a15af8e2b8aeecdbecd9c72ebd475c1` |
| `dist/logger-DPps3u8A.js` | `90366fb73663dd713d58f4389e41331566a1ed82b1649844cf05d0c769175d44` |
| `dist/regular-file-CuvhUtZS.js` | `308fcd639a8a49e5181a3f38758c38200ed4ff237b6e717a5e5d72a1625cfa0b` |
| `dist/tmp-openclaw-dir-uPgNO8da.js` | `c12ed50f959d17d9e4ca3e3cce60aa471ee160bdd705035a6d1ed63c47207b23` |
| `dist/call-0pFnAOMd.js` | `a1918dd13bb95bc483fb6d5ccb2e6dc715342e15b03b3ba698cbd2e3df4bdacb` |
| `dist/call-ni-mRgVy.js` | `a57731de94b198020f7a59559cee37be2fc878c71d6490856d6472340c9e2c9c` |
| `dist/call-BWOeX_u7.js` | `491c3b6d16ce9cee51abac5f9547cea47ea0f8ab0de6be6987d3ea5477b946ab` |
| `dist/call-CXp-TK3b.js` | `abb36395d8cbf4c7b53b6387357ac43bb06fe2c105ea591d78dfd8eff9d8f9c4` |
| `dist/client-CE2rtDfj.js` | `bc1a52483851c5780383bff02f72f9f747e7a7d0ab7bc603204bb5fdba1c7082` |
| `dist/src-DZzKBMa7.js` | `262a1ddf58310b68c6eb195b48a77282c8d494e22763ce5482c7b832c6eed837` |
| `dist/connect-error-details-BxqBqDDT.js` | `5fdbafc9eb1150f4e6b89b768dc257f41de7b26b44ce9261c7ab809ecac8e2de` |
| `dist/connection-details-BBobR8Xp.js` | `6c9c3e7698eea74177a4bb32a799570ae571a806277b3fc604eaec816b72e261` |
| `dist/server-ws-runtime-DGGrfLbo.js` | `d0b99fe9187fafd64b7ef69a18f74b31c9445620684352d59dac7a79d6470bab` |
| `dist/message-handler-CffUu4c6.js` | `92da8e1991e182f60389224bcd69a81a1e1aac0662ee9a83dae6d23833d87be6` |
| `dist/auth-B27MflKU.js` | `212e5fee77f117ec33c246fa56e1c4529356e078b78f1c6528d232f297223c58` |
| `dist/close-reason-D2Hhty2p.js` | `486a37a79b57d2bceb7fd8cd8c4e1a7c80c6c5af4e4716a71b36faca7ae9499f` |
| `dist/logger-D7QYAmug.js` | `af76f89a417348d8e8c85d21a15e2f6dfd669d7a0623d1c0cd58b9f937a3240d` |
| `dist/state-CZ7QadD1.js` | `8a4efc7d86de470db4e99b3dde593f7b8dd9b62a61cef32b00c151ab50c69495` |

This is a selected semantic inventory, not a certified complete import closure.
The recorded full runtime tree includes dependencies such as external `tslog`;
the current review does not certify their independent complete schemas.

CLI reachability: `openclaw.mjs:784` loads `dist/entry.js`; `entry.js:517`
loads `cli/run-main.js`; its program/subcommand registration reaches
`register.subclis-core-BJmLUN18.js:86-88` and `gateway-cli-DQXs76A9.js:289-298`.
`register-service-commands-Br1-4-DD.js:72-74` loads `lifecycle.runtime.js`,
which forwards through `lifecycle.runtime-BFu6ywCh.js` to the reviewed safe branch.
Gateway run-only registration instead forwards through `run-command-CHUT0sgt.js`
and `run-command-faE14xVE.js` into `run-BO64ei9s.js`.
That module loads `server-BlFdCOko.js:11`, then `server.impl-LClSwLYM.js`;
`server.impl-LClSwLYM.js:2306` loads `server-methods-mj06PYQm.js`, whose
lines 55 and 440-441 register the reviewed `restart-Cx1Esxi8.js` handler.
It calls the same `restart-BsqXS59K.js` scheduler used by the lifecycle loop.

## Required successor configuration

Use one fixed explicit native file:

```json
{"logging":{"level":"info","file":"/var/lib/aragorn-agent-gateway/gateway-lifecycle.log"}}
```

This is a fragment added to the complete coordinator-generated config, not a
replacement config. Preserve its other approved settings. The fresh complete
canonical config receives a new independently inventoried digest; do not reuse
`sha256:dcb02812b2d531f62079ca6a6a66800659635459f9b21432cf4b5d093d6b586c`.
The successor's admission readers must receive the same new pin through their
approved coordinator-owned source/config selection; historical frozen captures
and receipts are not edited or relabeled.

The new restart consumer owns its exact boundary validator against independently
caller-held fresh config/source/runtime pins. It may reuse safe primitives and
catalog conventions from existing admission code. It must not mutate
`native_phase3_admission_direct_write.CONFIG_PIN`, call historical `_boundary`
with rewritten records, monkeypatch module globals, or transfer ownership of
existing direct-write/install modules to the lane. Coordinator later supplies
separate finite pin generation for fresh staged install/direct-write adapters.

`packaging/systemd/aragorn-agent-gateway.service:56-58` uses
`ProtectSystem=strict` and permits writes to `/var/lib/aragorn-agent-gateway`.
The alternative `/var/lib/aragorn/gateway-lifecycle.log` is outside that allowance.
The fixed path avoids `PrivateTmp=yes` and the native preferred/fallback temp
resolver, whose `/tmp/openclaw/openclaw-YYYY-MM-DD.log` is conditional on directory
ownership/writability and can fall back to `os.tmpdir()/openclaw-<uid>`.
The explicit basename is not a native rolling-date name, but native size rotation
still exists: default maximum 100 MiB, at most five rotated logs. Rotation or
replacement during this finite capture refuses; it is never followed silently.

The gateway service itself must have `OPENCLAW_NO_RESPAWN=1`; setting this only
on a CLI child does not affect the daemon. The reviewed compiled
`cli/gateway-lifecycle.runtime.js:60-62` checks this before supervisor detection.
With the flag and the generic safe reason, `run-BO64ei9s.js:398` emits the exact
in-process marker below. Without it, a systemd-supervised gateway can exit and
change PID. Retain unit and actual gateway environment/source readback, with
`TZ=UTC` and the fixed account UID/GID 992. New unit/config pins must be part of
the fresh successor inventory before any native attempt.

## Exact accepted CLI result

Invoke once with exactly:

```text
/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs gateway restart --safe --json
```

No force, wait, skip-deferral, direct signal, systemctl fallback or second attempt.
`lifecycle-DVIgbP7g.js:209-234` calls `gateway.restart.request`, passing only
`reason: "gateway.restart.safe"`, with RPC timeout 10000 ms. A normal accepted
result has exit 0, empty stdout and one strict JSON object on stderr:

```json
{
  "ok": true,
  "result": "scheduled",
  "message": "safe restart requested; gateway will restart momentarily",
  "preflight": {
    "safe": true,
    "counts": {
      "queueSize": 0,
      "pendingReplies": 0,
      "embeddedRuns": 0,
      "cronRuns": 0,
      "activeTasks": 0,
      "totalActive": 0
    },
    "blockers": [],
    "summary": "safe to restart now"
  },
  "restart": {
    "ok": true,
    "pid": 123,
    "signal": "SIGUSR1",
    "delayMs": 0,
    "reason": "gateway.restart.safe",
    "mode": "emit",
    "coalesced": false,
    "cooldownMsApplied": 0,
    "emitHooksQueued": false
  }
}
```

The example PID 123 is a placeholder only: require exact equality to the held
gateway PID. Field inventory is exact at every shown level, booleans are not
integers, and duplicate/nonfinite JSON values refuse. The `warnings` field is
omitted when blockers are empty (`lifecycle-DVIgbP7g.js:205-207,221-229`).
Native preflight and summary come from `restart-Cx1Esxi8.js:43-93`; scheduling
fields come from `restart-BsqXS59K.js:632-752`. That scheduler can apply a 30000 ms
cooldown or coalesce, even with safe preflight. These are retained refusals under
this bounded contract, not reasons to wait longer or retry the restart.

Stderr routing is source-confirmed: compiled `program-CMrT2U8B.js:99-114`
recognizes JSON mode; `command-startup-policy-Bq9-nxRO.js:16-21` suppresses
doctor stdout; `command-execution-startup-DMrUT-xv.js:71-72` calls
`routeLogsToStderr`; patched console log uses stderr. The safe branch uses
`defaultRuntime.log`, which calls that console log. Additional diagnostics or
partial/multiple JSON output cannot be discarded to make the result match.

## Exact invalid-token controls

Use two fresh one-shot CLI processes, before and after restart, with exactly:

```text
/usr/local/bin/node /runtime/lib/node_modules/openclaw/openclaw.mjs gateway call system.info --token aragorn-native-restart-invalid-token-v1 --json --timeout 5000
```

Require the independently pinned complete config to select local loopback,
port 18789, TLS off and token auth. The coordinator checks privately that the
fixed invalid literal differs from the actual configured gateway token; neither
secret nor a secret-bearing config is copied into public evidence. Child env is
an explicit fixed inventory with NO_COLOR=1, no FORCE_COLOR, no gateway URL or
auth override, no test/handshake override, and no inherited user/device-auth
selection. CLI and gateway must read the same approved config context. No URL,
password, approval-runtime or agent-runtime-identity flag is added.

The exact accepted denial has exit 1, this stdout object and this one stderr line.
All shown field inventories and values are exact; there are no volatile output
fields or optional fields in the accepted token-mismatch path:

```json
{
  "ok": false,
  "error": {
    "type": "gateway_transport_error",
    "kind": "closed",
    "message": "gateway closed (1008): unauthorized: gateway token mismatch (set gateway.remote.token to match gateway.auth.token)",
    "code": 1008,
    "reason": "unauthorized: gateway token mismatch (set gateway.remote.token to match gateway.auth.token)"
  },
  "gateway": {
    "url": "ws://127.0.0.1:18789",
    "urlSource": "local loopback",
    "bindDetail": "Bind: loopback"
  }
}
```

```text
gateway connect failed: GatewayClientRequestError: unauthorized: gateway token mismatch (set gateway.remote.token to match gateway.auth.token)
```

Both streams are ASCII/UTF-8 with exactly one terminal LF, no BOM, CR, ANSI,
prefix/suffix diagnostics or blank trailing line. Stdout uses the shown native
two-space JSON indentation, field order and newline; independently parse strict
JSON as well as checking the exact bytes. The source-derived expected stdout is
481 bytes, SHA-256 `d88557eaf82b003daed20aeb2d0c1c9a6271e9c3bb95686181e9ecf19d4668ae`;
expected stderr is 143 bytes, SHA-256
`25b45fe227920562cda00967eb52d40dd6380d96f3c7112b267f16fec27f7322`.
These are offline expected bytes, not observed native results.

Compiled reachability and behavior are fixed: `gateway-cli-DQXs76A9.js:299-310`
invokes `call-0pFnAOMd.js`, which forwards through `call-ni-mRgVy.js` into
`call-CXp-TK3b.js`. `call-ni-mRgVy.js:7-25` disables progress in JSON mode and
passes the explicit token and 5000 ms timeout. For token auth on loopback,
`call-CXp-TK3b.js:295-302,678` deliberately supplies deviceIdentity=null;
the client therefore has no stored-device-token fallback or identity creation.
Ordinary CLI calls do not surface handshake request errors directly
(`call-CXp-TK3b.js:602-608,711`); the close callback at 589-600 creates a
closed transport error. The error formatter at 159-177 generates the exact
object above; `gateway-cli-DQXs76A9.js:61-76` writes it with native
`defaultRuntime.writeJson` to stdout and exits 1. `runtime-Bz6o617W.js:23-26,43-45`
supplies two-space formatting and the single LF.

Server `server-ws-runtime-DGGrfLbo.js:99` loads the pinned
`message-handler-CffUu4c6.js`. Its lines 410/414 select the exact CLI token
mismatch reason, and 1154-1166 send the handshake error followed by close 1008.
`auth-B27MflKU.js:256-259` supplies token_mismatch for unequal token bytes.
The reason is 91 ASCII bytes, below `close-reason-D2Hhty2p.js:6-10`'s 120-byte
limit, so it is not truncated. `src-DZzKBMa7.js:177-187,606-610` constructs the
named GatewayClientRequestError and logs it once; the pinned error formatter
`connect-error-details-BxqBqDDT.js:274-277` leaves token-mismatch text intact.
`client-CE2rtDfj.js:176-190` supplies logError, which reaches native console.error
through `logger-D7QYAmug.js:17-24,60-68`; JSON routing writes the single LF to
stderr. Console timestamp prefix starts false (`state-CZ7QadD1.js:12`), and this
call command does not enable gateway-run timestamp decoration.

Any timeout, missing token, rate limit, transport error with another code/reason,
success, retry, partial/extra output or mismatched context is a retained refusal.
Do not globally loosen the existing catalog runner's exit-0 contract: the new
leaf owns a separate fixed denial-control exit-1 contract. Both denials must
match exactly; preserve their full actual streams even on refusal.

## Proposed protected reader API

The coordinator-supplied callable is fixed:

```python
read_native_restart_lifecycle(
    *,
    phase: str,                       # INITIAL | BOUNDARY | AFTER
    previous_snapshot_digest: str | None,
    after_cursor: str | None,
    deadline_monotonic_ns: int,
) -> bytes
```

The lane receives this callable from the coordinator and mocks it in focused
tests. Its name and Python call boundary are not authentication. The actual root
provider is pending. A later coordinator-owned protected adapter may implement
the same exchange using inherited anonymous one-way pipes to an exclusively
owned root helper; no caller-chosen path, unit, PID, shell command, arbitrary
journal selector, socket listener or privilege expansion belongs in the leaf.

Coordinator provisions immutable context out of band: one fresh 64-lowercase-hex
capture nonce; independently held source/config/runtime inventory digest; boot
ID; fixed gateway unit and InvocationID; gateway PID/start ticks; fixed mount,
PID, user and active time namespace identities; exact UID/GID/capability and
NoNewPrivs profile; root-held gateway PIDFD; and the fixed file above. The helper
must independently check this context before and after each read. Caller-supplied
snapshot bytes cannot select or replace it. No public endpoint is implemented.

Calls occur in order: INITIAL, BOUNDARY, AFTER. INITIAL requires both optional
arguments null. Subsequent calls require the byte digest and opaque cursor of
the preceding accepted snapshot, also held and checked by the provider. The
BOUNDARY call follows all positive prechecks and the separately confirmed
before-control, immediately before the single restart dispatch. AFTER follows
dispatch and may wait only for this one suffix under the original deadline.
No successful snapshot is reused across attempts.

The returned bytes are canonical ASCII JSON with exactly these keys:

```text
schema = aragorn/native-restart-file-lifecycle-snapshot/v1
capture_nonce = independently held capture nonce
phase = requested phase
context_digest = independently pinned complete coordinator context digest
previous_snapshot_digest = requested value
file_identity = {dev, ino, mode, uid, gid, nlink}
prefix_bytes = strict integer length of raw decoded bytes
prefix_digest = sha256: digest of those bytes
raw_base64 = canonical standard padded base64 of the entire acquired prefix
cursor = opaque provider-generated identifier for this exact prefix/context
acquisition = {clock: CLOCK_MONOTONIC, started_ns, completed_ns}
emission_clock = {clock: CLOCK_REALTIME, timezone: UTC, precision_ns: 1000000}
complete = true
```

The context digest resolves through the protected inventory to the full process,
boot, namespace, unit, runtime, installed source and config bindings; it is not
an unverified digest supplied by the file or leaf. Snapshot SHA-256 is computed
over the exact returned canonical bytes. All digest strings use lowercase
`sha256:` plus 64 hex; IDs and integers use strict types, excluding booleans and
negative/overflow values. The maximum decoded prefix is 1048576 bytes, 512 JSONL
records and 65536 bytes per record including newline. The returned envelope is
at most 1500000 bytes. Noncanonical base64/JSON, extra/duplicate fields, blank
lines, partial final lines, invalid UTF-8 and bounds violations refuse. No record
or secret is silently redacted by the reader; native writer redaction is already
part of the retained original bytes.

File identity `mode` is the full st_mode integer, requiring S_IFREG|0600. The
cursor is an opaque 64-lowercase-hex string; its format does not authenticate it.

Provider cursor state binds the capture nonce, phase, context digest, held inode,
prefix length and prefix digest. It is not a decimal FD, timestamp, PID or caller
offset. The lane treats it as opaque. Initial and boundary prefixes must be
byte-for-byte prefixes of each later accepted snapshot; independently recompute
all byte counts and digests. Rotation, truncation, replacement, prefix mutation,
missing cursor, context drift or an unexpected phase refuses with bounded partial
evidence. Digest joins prove consistency, not continuous historical custody.

Hold no-follow descriptors for every ancestor and the file. Require a regular,
single-link 0600 file owned by UID/GID 992, inside the independently verified
gateway mount namespace; hold the original descriptor throughout the capture.
Check held/named device and inode, mode, owner and link count before and after
reads; the path may not resolve to a new inode. Read a finite fstat-selected
prefix with positional reads, then re-read/check that same prefix. Growth is
allowed only by appending complete records; unchanged mtime/size cannot be
required across a legitimately growing log. Parent directories must match the
coordinator's protected expected identities and reject symlink traversal.

One read/acquisition operation has at most 3 seconds and AFTER has at most 20
seconds total from dispatch, also constrained by the caller's absolute deadline.
Allow at most one outstanding request and at most 100 bounded observations
spaced by 200 ms during AFTER; never dispatch another restart. Expiry, EOF,
interrupt, partial IPC, source/file drift, overflow or provider failure yields no
usable complete snapshot and preserves bounded partial records and original
failure. Blocking read/fsync syscalls have no proven in-process hard deadline;
the later root-owned helper/supervisor must enforce the operational boundary and
retain cancellation uncertainty. No timeout thread or automatic replacement
provider can turn an uncertain observation into success.

## Native records, markers and presence-aware joins

`subsystem-C3fiUGN1.js:175-196` sends subsystem messages to a child file logger.
`logger-DPps3u8A.js:547-553` encodes its bindings as a JSON name. Its transport at
478-510 produces:

```text
redactSensitiveText(JSON.stringify(redactLogRecordForTransport(record))) + "\n"
```

`record` preserves the original tslog object, replaces `_meta` hostname when
available, always adds `time` and `hostname`, adds the nonempty computed message,
and conditionally adds trace/context fields. The exact original raw record and
field presence are retained. No assumed complete `_meta` field inventory is
certified here; that is partly supplied by external tslog. Do not invent kernel
PID/unit/credential fields in native JSON. The regular writer at
`regular-file-CuvhUtZS.js:192-225` rejects symlink/nonregular/multiply-linked
targets, uses O_APPEND|O_CREAT|O_WRONLY|O_NOFOLLOW, and opens/chmods 0600. It does
not authenticate which same-account process generated a record. Native transport
errors can be swallowed; missing required records must therefore refuse.

Require one initial readiness record before BOUNDARY, then these five markers
strictly after BOUNDARY in raw-byte order, exactly one selected record per marker:

| Role | Exact native message | Compiled emitter |
| --- | --- | --- |
| signal | `signal SIGUSR1 received` | `run-BO64ei9s.js:733` |
| restarting | `received SIGUSR1; restarting` | `run-BO64ei9s.js:691` |
| clean shutdown | `shutdown completed cleanly in <N>ms`, decimal nonnegative N | `server-close.runtime.js:568` |
| mode | `restart mode: in-process restart (OPENCLAW_NO_RESPAWN)` | `run-BO64ei9s.js:398` |
| second readiness | `gateway ready` | `server-startup-post-attach-C_v2J7XH.js:739` for default start; `server.impl-LClSwLYM.js:2708` for defer |

Initial readiness uses the same readiness emitter. Signal/restarting/mode/ready
are gateway subsystem messages in source; clean shutdown is gateway/shutdown.
Those source labels are semantic context, not an assumed raw-file projection.
The selected source binds a JSON child-logger name but external tslog determines
its raw placement. Retain any subsystem/name/binding metadata presence-aware and
do not require an unconfirmed top-level or numeric-key representation. Marker
selection joins exact raw messages/times and the protected source context;
subsystem metadata cannot authenticate the emitter. Reject ambiguous duplicate
candidates, shutdown warning/error
variants, full-process mode, unauthorized signal or unrelated restart markers.
Each marker reference has exact byte offset/length and record SHA-256 into the
retained prefix; its parsed message and original time string must equal the
referenced raw record. Additional records remain retained and do not reorder or
replace the required markers.

Trace fields are presence-aware. `logger-DPps3u8A.js:321-342` first uses a valid
explicit trace in bindings/arguments, otherwise activeDiagnosticTraceContext.
If no valid trace exists, it adds no trace fields. Record for each of traceId,
spanId, parentSpanId and traceFlags whether that key is present; when present,
retain its exact native value and require byte/parsed equality to the referenced
record. Never add null, a synthesized UUID or historical traceId. Static source
does not guarantee nonempty trace IDs or one equal trace across all lifecycle
records. A stricter cross-marker trace predicate can accept only a native
observation that actually supplies it; this document supplies no such evidence.
`OPENCLAW_GATEWAY_RESTART_TRACE` emits optional textual performance measurements
and is separate from diagnostic traceId presence.

## Clock, process and claim ceilings

The native `time` is emission time, not reader acquisition or journal receipt.
`logger-DPps3u8A.js:487` uses logObj.date or new Date and formats millisecond
ISO time with an explicit offset; lines 96-139 resolve process TZ. Under the
required TZ=UTC, expect `YYYY-MM-DDTHH:MM:SS.mmm+00:00`. Keep that original string
and lossless parsed epoch milliseconds. Use CLOCK_REALTIME for command start,
completion and fresh post-RPC start brackets; use CLOCK_MONOTONIC only for
acquisition/deadlines. Do not numerically compare the two clock domains or use
optional performance trace totals as emission timestamps.

For a parsed native epoch millisecond `m`, conservatively represent emission as
the inclusive nanosecond interval `[m*1000000, (m+1)*1000000-1]`. Keep actual
caller-observed command/RPC CLOCK_REALTIME start/completion nanoseconds without
rounding them into emitter precision. Require the inequalities for whole
intervals: command-start <= signal lower bound; restarting upper bound <=
command-completion <= clean-shutdown lower bound; and fresh post-RPC-start >=
second-ready upper bound. Strict raw marker order remains independent of
timestamp equality; native records may share one millisecond. Initial authenticated catalog commands
complete before dispatch; original gateway PID/start/namespace/cgroup/privilege
bindings and PIDFD remain live through final acceptance. Post-RPC clients are
fresh distinct command processes, not reuse of the pre-restart connection.
Clock discontinuity or ambiguous precision refuses the causal claim.

The native scheduler returns a response while a timer independently emits the
restart. Neither source nor the schema guarantees that CLI process completion
precedes clean shutdown: response delivery/printing can lag behind daemon
cleanup. These strict historical timing predicates may honestly refuse a native
run. Do not manufacture command-completion time, reorder markers, widen bounds
or assert that source confirmation proved the inequalities. A later relaxation
would require a separately reviewed semantic contract, not an adapter shortcut.

The root reader proves bounded acquisition and consistency with supplied custody;
the file is writable by the gateway account. File records, including their time,
trace, subsystem and message, remain runtime assertions, not authenticated
per-record kernel emitter observations or protection from same-account forgery.
This design does not replace protected state/catalog/admitted-byte comparisons,
confirm active-session consumption, establish telemetry loss/health, or qualify
ADM-02, RUN, Phase 3, deployment or production activation. The actual provider,
fresh installed/config inventory, independent
consumer implementation and reviewed complete stage closure remain outstanding.
