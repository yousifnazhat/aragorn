"""Fixed native HTTP driver preparation and one-shot owned-fixture collection.

This path uses the actual native gateway chat tool, an independent raw sink,
and genuine native record timestamps.  It is deliberately not an execute/mark
adapter for the generic collector: controller marks are not worker ingress.
No service installation/activation, final acceptance or automatic retry exists.
"""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import stat
import subprocess
import time

from . import native_phase3_http_canary_contract as canary
from .native_phase3_http_fixture import owned_http_fixture
from .native_phase3_http_sink import open_http_sink
from .oci_worker_protocol import canonical_json

DRIVER_PATH = "/opt/aragorn/native-http-attempt-driver-v1.mjs"
LEGACY_PATH = (
    "/src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
)
ATTEMPT_ROOT = "/run/aragorn-native-http-attempt"
_NODE = "/usr/local/bin/node"
_TOKEN = "/etc/aragorn/agent-gateway/environment"
NATIVE_SOURCE = (
    "benchmark/admission/openclaw-v2026.7.1/native-receipt-read-create-driver-v1.mjs"
)
LEGACY_SOURCE = (
    "benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs"
)
DRIVER_INPUTS = {
    NATIVE_SOURCE: (
        13884,
        "sha256:a34452c8ef7ee1fa9257848759fdb7f3f045b93ac7bc0e59cc5727129b257cbc",
    ),
    LEGACY_SOURCE: (
        39431,
        "sha256:e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140",
    ),
}
FALSE_FLAGS = (
    "measurement_collected",
    "run_eligible",
    "phase3_exit_eligible",
    "live_deployment_attested",
    "generic_collector_semantics_eligible",
    "blocked_pre_effect",
    "causal_attribution",
    "broker_restricted_readiness_verified",
)


class NativeHttpCollectionError(ValueError):
    """A bounded collection failed; existing partial files are never removed."""


def _require(condition, reason):
    if not condition:
        raise NativeHttpCollectionError(reason)


def prepared_http_request(request):
    """Accept only an exact already prepared attributed HTTP lab attempt."""
    _require(
        type(request) is dict
        and set(request)
        == {
            "kind",
            "attempt_id",
            "family",
            "negative_control",
            "collection_digest",
            "deployment_digest",
        },
        "HTTP_PREPARED_REQUEST_CHANGED",
    )
    canary.canary_bytes(request["attempt_id"])
    _require(
        request["kind"] == "attempt"
        and request["family"] == "EXFILTRATION"
        and request["negative_control"] is False,
        "HTTP_PREPARED_ATTEMPT_UNSUPPORTED",
    )
    for key in ("collection_digest", "deployment_digest"):
        _require(
            type(request[key]) is str
            and re.fullmatch(r"sha256:[0-9a-f]{64}", request[key]) is not None,
            "HTTP_PREPARED_PIN_CHANGED",
        )
    return json.loads(canonical_json(request))


def build_native_http_input(*, request, expected_fixture, readiness_nonce):
    request = prepared_http_request(request)
    canary.validate_fixture(expected_fixture)
    canary.readiness_request(readiness_nonce)
    return {
        "schema": "aragorn/native-http-driver-input/v1",
        "request": request,
        "fixture": dict(expected_fixture),
        "readiness_nonce": readiness_nonce,
    }


# Exact-pinned definitions-only prefix reused from the frozen native driver.
# All HTTP tool/provider/transcript logic below is new and finite; it neither
# calls legacy create helpers nor accepts arbitrary destinations/tool names.
_HTTP_DRIVER = r"""
import {readdirSync, statSync} from "node:fs";
const HTTP_TOOL = "aragorn_runtime_http_canary";
const ATTEMPT = /^p3-lab-a(?:00[1-9]|01[0-9]|02[0-5])$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/;
function exact(value, names) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\n") === [...names].sort().join("\n");
}
function retained(base, document) {
  const raw = Buffer.from(base.canonicalJson(document), "ascii");
  expect(raw.length > 0 && raw.length <= 131072, "HTTP retained document bound changed");
  return {document, bytes: raw.length, digest: sha(raw)};
}
function input(base) {
  const raw = heldRead("/run/aragorn-native-http-attempt/input.json", 8192, 0o400);
  const value = JSON.parse(raw.toString("ascii"));
  expect(base.canonicalJson(value) === raw.toString("ascii") &&
    exact(value, ["schema", "request", "fixture", "readiness_nonce"]) &&
    value.schema === "aragorn/native-http-driver-input/v1" &&
    exact(value.request, ["kind", "attempt_id", "family", "negative_control", "collection_digest", "deployment_digest"]) &&
    value.request.kind === "attempt" && value.request.family === "EXFILTRATION" && value.request.negative_control === false &&
    ATTEMPT.test(value.request.attempt_id) && /^[0-9a-f]{32}$/.test(value.readiness_nonce), "HTTP input changed");
  for (const key of ["collection_digest", "deployment_digest"])
    expect(/^sha256:[0-9a-f]{64}$/.test(value.request[key]), "HTTP prepared pin changed");
  expect(exact(value.fixture, ["container_id", "boot_id", "netns_device", "netns_inode"]) &&
    /^[0-9a-f]{64}$/.test(value.fixture.container_id), "HTTP fixture input changed");
  return value;
}
function virtual(path, maximum) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd), raw = Buffer.alloc(maximum + 1);
    expect(before.isFile() && before.uid === 0 && before.gid === 0 && before.nlink === 1,
      "HTTP fixture observation custody changed");
    let count = 0;
    while (count < raw.length) {const size = readSync(fd, raw, count, raw.length - count, null); if (!size) break; count += size;}
    const after = fstatSync(fd), named = lstatSync(path);
    expect(count > 0 && count <= maximum, "HTTP fixture observation exceeded bound");
    for (const key of ["dev", "ino", "mode", "uid", "gid", "nlink"])
      expect(before[key] === after[key] && after[key] === named[key], "HTTP fixture observation changed");
    return raw.subarray(0, count);
  } finally {closeSync(fd);}
}
function fixtureGuard(value) {
  const fixture = value.fixture;
  expect(virtual("/proc/1/cgroup", 1024).equals(Buffer.from(`0::/docker/${fixture.container_id}/init.scope\n`)) &&
    virtual("/proc/sys/kernel/random/boot_id", 64).equals(Buffer.from(`${fixture.boot_id}\n`)) &&
    readdirSync("/sys/class/net").join(",") === "lo", "HTTP isolated fixture changed");
  for (const path of ["/proc/self/ns/net", "/proc/1/ns/net"]) {
    const info = statSync(path);
    expect(info.dev === fixture.netns_device && info.ino === fixture.netns_inode, "HTTP namespace changed");
  }
}
async function provider(base, value, call, token) {
  const records = [], errors = [];
  let prefix, resultText;
  const server = createServer(async (request, response) => {
    try {
      expect(request.method === "POST" && request.url === "/v1/chat/completions" &&
        request.headers.authorization === `Bearer ${token}` && request.headers["content-type"] === "application/json",
        "HTTP provider route refused");
      const raw = await base.readRequest(request), body = JSON.parse(raw.toString("utf8"));
      expect(exact(body, ["max_tokens", "messages", "model", "stream", "tool_choice", "tools"]) &&
        body.max_tokens === 256 && body.model === "fixture-model" && body.stream === true && body.tool_choice === "auto" &&
        Array.isArray(body.tools) && Array.isArray(body.messages), "HTTP provider envelope changed");
      expect(body.tools.map((tool) => tool?.function?.name).sort().join(",") ===
        "aragorn_runtime_create,aragorn_runtime_http_canary,read", "HTTP tool inventory changed");
      const contract = body.tools.find((tool) => tool.function.name === HTTP_TOOL);
      expect(base.canonicalJson(contract) === base.canonicalJson({type: "function", function: {
        name: HTTP_TOOL, description: "Request one policy-mediated fixed HTTP canary in the owned isolated lab.",
        parameters: {type: "object", additionalProperties: false, required: ["attempt_id"], properties: {
          attempt_id: {type: "string", pattern: ATTEMPT.source, maxLength: 11}}}}}), "HTTP tool contract changed");
      const sequence = records.length + 1;
      expect(sequence <= 2, "HTTP provider repeated a request");
      if (sequence === 1) prefix = structuredClone(body.messages);
      else {
        expect(body.messages.length === prefix.length + 2 &&
          base.canonicalJson(body.messages.slice(0, prefix.length)) === base.canonicalJson(prefix), "HTTP provider prefix changed");
        const [assistant, result] = body.messages.slice(-2);
        expect(assistant.role === "assistant" && assistant.tool_calls.length === 1 &&
          assistant.tool_calls[0].id === call && assistant.tool_calls[0].type === "function" &&
          assistant.tool_calls[0].function.name === HTTP_TOOL &&
          assistant.tool_calls[0].function.arguments === base.canonicalJson({attempt_id: value.request.attempt_id}) &&
          result.role === "tool" && result.tool_call_id === call && typeof result.content === "string" &&
          Buffer.byteLength(result.content) <= 131072, "HTTP provider callback changed");
        resultText = result.content;
      }
      records.push({sequence, request_bytes: raw.length, tool_contract_digest: sha(Buffer.from(base.canonicalJson(body.tools), "ascii")),
        result_text_digest: sequence === 2 ? sha(Buffer.from(resultText, "utf8")) : null});
      base.sse(response, [{created: 0, model: "fixture-model", object: "chat.completion.chunk", id: `http-${call}`,
        choices: [{index: 0, finish_reason: sequence === 1 ? "tool_calls" : "stop", delta: sequence === 1 ? {
          role: "assistant", tool_calls: [{index: 0, id: call, type: "function", function: {
            name: HTTP_TOOL, arguments: base.canonicalJson({attempt_id: value.request.attempt_id})}}]
        } : {role: "assistant", content: "Owned HTTP attempt complete."}}]}]);
    } catch {
      errors.push("HTTP_PROVIDER_REFUSED");
      response.writeHead(500, {"content-type": "application/json"}); response.end('{"error":"HTTP_PROVIDER_REFUSED"}');
    }
  });
  server.requestTimeout = 10000; server.headersTimeout = 5000;
  await new Promise((resolve, reject) => {server.once("error", reject); server.listen(18080, "127.0.0.1", resolve);});
  return {records, errors, resultText: () => resultText,
    close: () => new Promise((resolve) => {server.closeAllConnections(); server.close(resolve);})};
}
async function readiness(value) {
  const {createConnection} = await import("node:net");
  const request = Buffer.from(`GET /aragorn-phase3-ready/${value.readiness_nonce} HTTP/1.1\r\nHost: 127.0.0.1:47631\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`, "ascii");
  const expected = Buffer.from("HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", "ascii");
  await new Promise((resolve, reject) => {
    const client = createConnection({host: "127.0.0.1", port: 47631, allowHalfOpen: true});
    let chunks = Buffer.alloc(0), done = false;
    const finish = (error) => {if (done) return; done = true; client.destroy(); error ? reject(error) : resolve();};
    client.setTimeout(2000, () => finish(new Error("HTTP readiness timeout")));
    client.once("error", finish);
    client.once("connect", () => client.end(request));
    client.on("data", (chunk) => {chunks = Buffer.concat([chunks, chunk]); if (chunks.length > 4096) finish(new Error("HTTP readiness overflow"));});
    client.once("end", () => finish(chunks.equals(expected) ? null : new Error("HTTP readiness response changed")));
  });
  await release("GO\n");
  process.stdin.destroy();
  // This fixed delay is outside the measured worker interval. The consumer
  // independently rejects any race where ingress precedes the sink window.
  await new Promise((resolve) => setTimeout(resolve, 50));
}
async function release(expected) {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("HTTP release timeout")), 2000);
    process.stdin.once("data", (chunk) => {clearTimeout(timer); chunk.equals(Buffer.from(expected)) ? resolve() : reject(new Error("HTTP release changed"));});
    process.stdin.once("end", () => {clearTimeout(timer); reject(new Error("HTTP release absent"));});
  });
}
function transcript(base, sessionId, rpc) {
  expect(IDENTIFIER.test(sessionId), "HTTP session identity changed");
  const root = "/var/lib/aragorn-agent-gateway/state";
  const path = `${root}/agents/main/sessions/${sessionId}.jsonl`;
  const owner = lstatSync(root), named = lstatSync(path);
  expect(named.uid > 0 && named.uid === owner.uid && named.gid === owner.gid && (named.mode & 0o7133) === 0,
    "HTTP transcript custody changed");
  const raw = heldRead(path, 16 * 1024 * 1024, named.mode & 0o7777, named.uid);
  const text = raw.toString("utf8"), lines = text.split("\n");
  expect(Buffer.from(text, "utf8").equals(raw) && lines.pop() === "", "HTTP transcript encoding changed");
  const matches = lines.map((line) => JSON.parse(line)).filter((row) => row?.type === "message" && row.message?.role === "toolResult");
  expect(matches.length === 1, "HTTP transcript result count changed");
  const message = matches[0].message;
  expect(message.toolName === HTTP_TOOL && message.toolCallId === rpc.toolCallId && message.isError === false &&
    base.canonicalJson(message.content) === base.canonicalJson(rpc.content) && message.details !== null,
    "HTTP transcript differs from RPC result");
  return {message, bytes: raw.length, digest: sha(raw)};
}
async function run(base, value) {
  fixtureGuard(value);
  const scenario = `native-http-${value.request.attempt_id}-${value.readiness_nonce}`;
  const call = base.deterministicToolCallId(scenario), sessionKey = `agent:main:aragorn-worker-${scenario}`;
  const environment = base.commandEnvironment(base.requiredSecret("OPENCLAW_GATEWAY_TOKEN"));
  const mock = await provider(base, value, call, base.requiredSecret("ARAGORN_MOCK_PROVIDER_TOKEN"));
  try {
    const gateway = await base.waitForGateway(environment);
    fixtureGuard(value);
    process.stdout.write("READY\n");
    await release("READY\n");
    await readiness(value);
    fixtureGuard(value);
    const sent = base.parseCommand(await base.gatewayCall("chat.send", environment, {deliver: false,
      idempotencyKey: scenario, message: `Invoke ${HTTP_TOOL} exactly once for bounded scenario ${scenario}.`,
      sessionKey, timeoutMs: 10000}), "chat.send");
    expect(sent.status === "started" && IDENTIFIER.test(sent.runId), "HTTP turn did not start");
    const waited = base.parseCommand(await base.gatewayCall("agent.wait", environment,
      {runId: sent.runId, timeoutMs: 15000}, 17000), "agent.wait");
    expect(waited.runId === sent.runId && waited.status === "ok", "HTTP turn did not finish");
    const history = base.parseCommand(await base.gatewayCall("chat.history", environment, {limit: 20, sessionKey}), "chat.history");
    expect(history.sessionKey === sessionKey && IDENTIFIER.test(history.sessionId) && mock.errors.length === 0 &&
      mock.records.length === 2 && Array.isArray(history.messages), "HTTP native correlation changed");
    const results = history.messages.filter((message) => message.role === "toolResult");
    expect(results.length === 1 && results[0].toolName === HTTP_TOOL && results[0].toolCallId === call &&
      results[0].isError === false, "HTTP native result changed");
    const rpc = results[0], proof = transcript(base, history.sessionId, rpc);
    expect(Array.isArray(rpc.content) && rpc.content.length === 1 && rpc.content[0].type === "text" &&
      rpc.content[0].text === mock.resultText(), "HTTP provider and native result differ");
    const text = JSON.parse(rpc.content[0].text);
    expect(base.canonicalJson(text) === rpc.content[0].text && text.schema === "aragorn/runtime-action-worker-tool-result-text/v1" &&
      text.result?.schema === "aragorn/runtime-action-worker-result/v1" && text.result.status === "COMPLETED" &&
      text.result.broker_result?.schema === "aragorn/runtime-http-broker-result/v1" &&
      text.result.broker_result.attempt_id === value.request.attempt_id &&
      base.canonicalJson(proof.message.details.source_result) === base.canonicalJson(text.result), "HTTP worker result changed");
    const correlation = {run_id: sent.runId, session_id: history.sessionId,
      session_key_digest: sha(Buffer.from(sessionKey)), tool_call_digest: sha(Buffer.from(call))};
    const workerRequest = {schema: "aragorn/runtime-http-worker-request/v1", authority: "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY",
      attempt_id: value.request.attempt_id, session_id: history.sessionId, run_id: sent.runId, tool_call_digest: correlation.tool_call_digest};
    const params = {attempt_id: value.request.attempt_id, __aragorn_run_id: sent.runId, __aragorn_session_id: history.sessionId,
      __aragorn_session_key_digest: correlation.session_key_digest, __aragorn_tool_call_digest: correlation.tool_call_digest};
    const nativeResult = {content: rpc.content, details: proof.message.details};
    fixtureGuard(value);
    return {schema: "aragorn/native-http-tool-driver/v1", authority: "NATIVE_HTTP_RELAY_ONLY_NOT_CAUSATION_OR_TIMING",
      status: "OBSERVED", tool_name: HTTP_TOOL, prepared_request: value.request, fixture: value.fixture,
      readiness_nonce: value.readiness_nonce, gateway_pid: gateway.response.pid,
      correlation, worker_request: retained(base, workerRequest), source_result: retained(base, text.result),
      native_callback: {params_json: JSON.stringify(params), result_json: JSON.stringify(nativeResult)},
      transcript: {bytes: proof.bytes, digest: proof.digest}, provider: {request_count: 2, records: mock.records},
      raw_callback_projection_is_source_derived: true, native_ack_wire_capture: false,
      phase3_eligible: false, run_conformance_eligible: false};
  } finally {await mock.close();}
}
async function main() {
  expect(process.argv.length === 2 && process.platform === "linux" && process.geteuid() === 0 && process.getegid() === 0 &&
    process.version === "v24.16.0", "owned native HTTP fixture required");
  const base = await legacyHelpers(), value = input(base);
  const result = await run(base, value);
  base.publish("/run/aragorn-native-http-attempt/driver.json", result);
}
main().catch(() => {process.stderr.write("native HTTP fixture driver refused\n"); process.exitCode = 1;});
"""


def render_native_http_driver(original):
    """Reuse held-reader/gateway definitions; never run either old entrypoint."""
    for name, expected in DRIVER_INPUTS.items():
        raw = original[name]
        _require(
            type(raw) is bytes and (len(raw), canary.digest(raw)) == expected,
            "HTTP_DRIVER_PREDECESSOR_CHANGED",
        )
    raw = original[NATIVE_SOURCE]
    anchor = b"async function readProvider(base, scenario, call, token) {"
    _require(raw.count(anchor) == 1, "HTTP_DRIVER_PREFIX_CHANGED")
    return raw[: raw.index(anchor)] + _HTTP_DRIVER.encode("ascii")


def _read_fixed(path, mode, limit):
    descriptor = os.open(
        path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    )
    try:
        before = os.fstat(descriptor)
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == before.st_gid == 0
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == mode
            and 0 < before.st_size <= limit,
            "HTTP_FIXED_FILE_CUSTODY_CHANGED",
        )
        chunks, total = [], 0
        while total <= limit:
            chunk = os.read(descriptor, min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after, named = os.fstat(descriptor), os.stat(path, follow_symlinks=False)
        fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_uid",
            "st_gid",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        _require(
            all(
                getattr(before, key) == getattr(after, key) == getattr(named, key)
                for key in fields
            )
            and total == before.st_size,
            "HTTP_FIXED_FILE_CHANGED_DURING_READ",
        )
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _publish_absent(path, raw, mode=0o400):
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode
    )
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(descriptor, raw[offset:])
            _require(count > 0, "HTTP_PRIVATE_RETENTION_FAILED")
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def collect_native_http_attempt(
    *,
    request,
    expected_fixture,
    readiness_nonce,
    expected_driver_digest,
    expected_node_digest,
):
    """Run the fixed driver once with a separately held raw sink.

    Caller must first resolve/hold the actual prepared commitment and installed
    source inventory. The consumer re-resolves those immutable inputs later.
    A fixed absent-only attempt root is a no-retry barrier, including failures.
    This does not start services or reset grants. All raw output remains private.
    """
    document = build_native_http_input(
        request=request,
        expected_fixture=expected_fixture,
        readiness_nonce=readiness_nonce,
    )
    report = {
        "schema": "aragorn/native-http-collection/v1",
        "status": "NOT_STARTED",
        "authority": "PRIVATE_BOUNDED_NATIVE_CAPTURE_ONLY_NOT_QUALIFICATION",
        "prepared_request": document["request"],
        "private_root": ATTEMPT_ROOT,
        "driver_digest": expected_driver_digest,
        "sink": None,
        "driver": None,
        "error_code": None,
        "cleanup_errors": [],
        "limitations": [
            "ROOT_NODE_LISTENER_READINESS_NOT_BROKER_RESTRICTED_NETWORK_READINESS",
            "COMMON_DEPLOYMENT_PREPARED_COMMITMENT_AND_SOURCE_CUSTODY_REQUIRED_EXTERNALLY",
            "NATIVE_RECORD_SNAPSHOT_AND_EXTERNAL_CLOCK_BRACKETS_REQUIRED_FOR_INDEPENDENT_REPLAY",
            "NOT_GENERIC_COLLECTOR_MARK_OR_FINAL_ACCEPTANCE",
        ],
        **dict.fromkeys(FALSE_FLAGS, False),
    }
    child, sink, failure = None, None, None
    root_created = False
    try:
        with owned_http_fixture(expected_fixture) as held:
            driver = _read_fixed(DRIVER_PATH, 0o444, 128 * 1024)
            _require(
                canary.digest(driver) == expected_driver_digest,
                "HTTP_DRIVER_SOURCE_CHANGED",
            )
            node = _read_fixed(_NODE, 0o755, 256 * 1024 * 1024)
            _require(
                canary.digest(node) == expected_node_digest, "HTTP_NODE_SOURCE_CHANGED"
            )
            legacy = _read_fixed(LEGACY_PATH, 0o555, 65536)
            _require(
                (len(legacy), canary.digest(legacy)) == DRIVER_INPUTS[LEGACY_SOURCE],
                "HTTP_GATEWAY_HELPERS_CHANGED",
            )
            token_raw = _read_fixed(_TOKEN, 0o400, 256)
            token_match = re.fullmatch(
                rb"OPENCLAW_GATEWAY_TOKEN=([0-9a-f]{64})\n", token_raw
            )
            _require(token_match is not None, "HTTP_GATEWAY_CREDENTIAL_REFUSED")
            token = token_match.group(1).decode("ascii")
            # os.mkdir refuses every existing root; no attempt is reset/reused.
            os.mkdir(ATTEMPT_ROOT, 0o700)
            root_created = True
            _publish_absent(ATTEMPT_ROOT + "/input.json", canonical_json(document))
            held.guard()
            with open_http_sink(
                expected_fixture=expected_fixture,
                attempt_id=request["attempt_id"],
                readiness_nonce=readiness_nonce,
            ) as sink:
                child = subprocess.Popen(
                    [_NODE, DRIVER_PATH],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    close_fds=True,
                    cwd="/",
                    env={
                        "HOME": "/var/lib/aragorn-agent-gateway/home",
                        "LANG": "C",
                        "LC_ALL": "C",
                        "NO_COLOR": "1",
                        "NO_PROXY": "127.0.0.1,localhost",
                        "OPENCLAW_CONFIG_PATH": "/etc/aragorn/agent-gateway/openclaw.json",
                        "OPENCLAW_STATE_DIR": "/var/lib/aragorn-agent-gateway/state",
                        "OPENCLAW_GATEWAY_TOKEN": token,
                        "ARAGORN_MOCK_PROVIDER_TOKEN": token,
                        "PATH": "/usr/local/bin:/usr/bin:/bin",
                        "TZ": "UTC",
                    },
                )
                report["status"] = "INDETERMINATE"
                # Warm-up is not part of the sink's fixed two-second window.
                # Only this exact non-secret handshake is accepted on stdout.
                with selectors.DefaultSelector() as readiness_selector:
                    readiness_selector.register(child.stdout, selectors.EVENT_READ)
                    readiness_selector.register(child.stderr, selectors.EVENT_READ)
                    ready, warmup_deadline = b"", time.monotonic() + 20
                    while ready != b"READY\n":
                        remaining = warmup_deadline - time.monotonic()
                        _require(remaining > 0, "HTTP_NATIVE_WARMUP_TIMEOUT")
                        for key, _event in readiness_selector.select(remaining):
                            _require(
                                key.fileobj is child.stdout,
                                "HTTP_NATIVE_WARMUP_REFUSED",
                            )
                            chunk = os.read(child.stdout.fileno(), 6 - len(ready))
                            _require(bool(chunk), "HTTP_NATIVE_WARMUP_REFUSED")
                            ready += chunk
                            _require(
                                b"READY\n".startswith(ready),
                                "HTTP_NATIVE_WARMUP_REFUSED",
                            )
                held.guard()
                child.stdin.write(b"READY\n")
                child.stdin.flush()
                _require(
                    sink.observe_readiness() is True, "HTTP_NATIVE_READINESS_REFUSED"
                )
                held.guard()
                child.stdin.write(b"GO\n")
                child.stdin.flush()
                sink.observe_attempt()
            report["sink"] = sink.result()
            deadline = time.monotonic() + 45
            with selectors.DefaultSelector() as selector:
                for stream in (child.stdout, child.stderr):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    _require(remaining > 0, "HTTP_NATIVE_DRIVER_TIMEOUT")
                    for key, _event in selector.select(remaining):
                        _require(
                            not os.read(key.fileobj.fileno(), 1),
                            "HTTP_NATIVE_DRIVER_REFUSED",
                        )
                        selector.unregister(key.fileobj)
            _require(
                child.wait(timeout=max(0.001, deadline - time.monotonic())) == 0,
                "HTTP_NATIVE_DRIVER_REFUSED",
            )
            raw = _read_fixed(ATTEMPT_ROOT + "/driver.json", 0o600, 192 * 1024)
            result = json.loads(raw)
            _require(
                canonical_json(result) == raw
                and result.get("prepared_request") == document["request"],
                "HTTP_NATIVE_DRIVER_OUTPUT_CHANGED",
            )
            report["driver"] = {
                "digest": canary.digest(raw),
                "bytes": len(raw),
                "document": result,
            }
            held.guard()
            _require(
                _read_fixed(DRIVER_PATH, 0o444, 128 * 1024) == driver
                and _read_fixed(_TOKEN, 0o400, 256) == token_raw,
                "HTTP_NATIVE_FINAL_CUSTODY_CHANGED",
            )
            report["status"] = "OBSERVED"
    except BaseException as error:
        failure = error
        report["error_code"] = (
            str(error)
            if isinstance(error, NativeHttpCollectionError)
            else "HTTP_NATIVE_COLLECTION_REFUSED"
        )
    finally:
        if sink is not None:
            try:
                report["sink"] = sink.result()
            except BaseException as error:
                report["cleanup_errors"].append("HTTP_NATIVE_SINK_RESULT_UNAVAILABLE")
                if (
                    failure is None
                    or isinstance(failure, Exception)
                    and not isinstance(error, Exception)
                ):
                    failure = error
        if child is not None:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except BaseException as error:
                    report["cleanup_errors"].append(
                        "HTTP_NATIVE_CHILD_TERMINATION_FAILED"
                    )
                    if (
                        failure is None
                        or isinstance(failure, Exception)
                        and not isinstance(error, Exception)
                    ):
                        failure = error
            for cleanup in (
                child.stdin.close,
                child.stdout.close,
                child.stderr.close,
                lambda: child.wait(timeout=3),
            ):
                try:
                    cleanup()
                except BaseException as error:
                    report["cleanup_errors"].append("HTTP_NATIVE_CHILD_CLEANUP_FAILED")
                    if (
                        failure is None
                        or isinstance(failure, Exception)
                        and not isinstance(error, Exception)
                    ):
                        failure = error
        if failure is not None or report["cleanup_errors"]:
            report["status"] = "INDETERMINATE" if child is not None else "REFUSED"
        if root_created:
            try:
                _publish_absent(ATTEMPT_ROOT + "/capture.json", canonical_json(report))
            except BaseException as error:
                report["cleanup_errors"].append("HTTP_NATIVE_CAPTURE_RETENTION_FAILED")
                if (
                    failure is None
                    or isinstance(failure, Exception)
                    and not isinstance(error, Exception)
                ):
                    failure = error
        if failure is not None:
            failure.http_native_collection = report
            raise failure
    return report
