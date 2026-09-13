// Owned-fixture driver only. No credential/client mocks or direct tool execution.
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { createHash } from "node:crypto";
import { createServer } from "node:http";

const LEGACY = "/src/benchmark/runtime-action-worker-openclaw-systemd/openclaw-worker-driver.mjs";
const LEGACY_PIN = [39431, "e6e1803e9593d8c1bcb1ad4a3fdf2cb5c3657f1b4bd06e65470b8ad16e9e0140"];
const READ_PATH = "/var/lib/aragorn-agent-gateway/workspace/native-receipt-read.txt";
const READ_TEXT = "Aragorn inert native receipt read.";
const sha = (raw) => "sha256:" + createHash("sha256").update(raw).digest("hex");
const expect = (value, message) => { if (!value) throw new Error(message); };

function heldRead(path, maximum, mode, uid = 0) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    expect(before.isFile() && before.uid === uid && before.gid === uid && before.nlink === 1 &&
      (before.mode & 0o7777) === mode && before.size <= maximum, "fixture file custody changed");
    const buffer = Buffer.alloc(maximum + 1);
    let count = 0;
    while (count < buffer.length) {
      const size = readSync(fd, buffer, count, buffer.length - count, null);
      if (!size) break;
      count += size;
    }
    const after = fstatSync(fd), named = lstatSync(path);
    for (const key of ["dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtimeMs", "ctimeMs"]) {
      expect(before[key] === after[key] && after[key] === named[key], "fixture file changed during read");
    }
    expect(count === before.size && count <= maximum, "fixture file size changed");
    return buffer.subarray(0, count);
  } finally { closeSync(fd); }
}

async function legacyHelpers() {
  const raw = heldRead(LEGACY, LEGACY_PIN[0], 0o555);
  expect(raw.length === LEGACY_PIN[0] && sha(raw) === "sha256:" + LEGACY_PIN[1], "legacy driver source changed");
  const source = raw.toString("utf8");
  const anchor = "\nmain().catch((cause) => {";
  expect(source.indexOf(anchor) === source.lastIndexOf(anchor) && source.includes(anchor), "legacy entrypoint changed");
  // Definitions only; the old executable main is removed from exact-pinned bytes.
  const names = ["canonicalJson", "readInput", "commandEnvironment", "requiredSecret", "gatewayCall",
    "waitForGateway", "parseCommand", "commandSummary", "deterministicToolCallId", "startProvider",
    "readRequest", "providerEnvelope", "providerResponse", "sse", "transcriptToolResult", "workerRequest",
    "relaySummary", "expectedOutcome", "publish"];
  const module = source.slice(0, source.indexOf(anchor)) + "\nexport { " + names.join(",") + " };\n";
  return import("data:text/javascript;base64," + Buffer.from(module).toString("base64"));
}

async function readProvider(base, scenario, call, token) {
  const records = [], errors = [];
  let prefix;
  const server = createServer(async (request, response) => {
    try {
      expect(request.method === "POST" && request.url === "/v1/chat/completions" &&
        request.headers.authorization === `Bearer ${token}` && request.headers["content-type"] === "application/json",
      "fixed read provider route or authentication changed");
      const raw = await base.readRequest(request), body = JSON.parse(raw.toString("utf8"));
      const contract = base.providerEnvelope(body, "read provider");
      expect(body.tools.map((tool) => tool.function.name).sort().join(",") === "aragorn_runtime_create,read",
        "read provider advertised an unsupported tool set");
      const sequence = records.length + 1;
      expect(sequence <= 2, "read provider repeated a request");
      if (sequence === 1) {
        prefix = structuredClone(body.messages);
      } else {
        expect(body.messages.length === prefix.length + 2 &&
          base.canonicalJson(body.messages.slice(0, prefix.length)) === base.canonicalJson(prefix),
        "read provider message prefix changed");
        const [assistant, result] = body.messages.slice(-2);
        expect(assistant.role === "assistant" && assistant.tool_calls.length === 1 &&
          assistant.tool_calls[0].id === call && assistant.tool_calls[0].type === "function" &&
          assistant.tool_calls[0].function.name === "read" &&
          assistant.tool_calls[0].function.arguments === base.canonicalJson({ path: READ_PATH }) &&
          result.role === "tool" && result.tool_call_id === call && result.content === READ_TEXT,
        "read provider callback result is unbound");
      }
      records.push({ sequence, request_bytes: raw.length, tool_contract_digest: contract,
        emitted_tool_call_id: sequence === 1 ? call : null, result_text_digest: sequence === 2 ? sha(Buffer.from(READ_TEXT)) : null });
      base.sse(response, sequence === 1 ? [{
        created: 0, model: "fixture-model", object: "chat.completion.chunk", id: `chatcmpl-${scenario.id}-read`,
        choices: [{ delta: { role: "assistant", tool_calls: [{
          function: { arguments: base.canonicalJson({ path: READ_PATH }), name: "read" },
          id: call, index: 0, type: "function",
        }] }, finish_reason: "tool_calls", index: 0 }],
      }] : base.providerResponse(2, scenario, call));
    } catch {
      errors.push("READ_PROVIDER_REFUSED");
      response.writeHead(500, { "content-type": "application/json" });
      response.end('{"error":"fixed read provider refused"}');
    }
  });
  server.requestTimeout = 10000;
  server.headersTimeout = 5000;
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(18080, "127.0.0.1", resolve); });
  return { records, errors, close: () => new Promise((resolve) => server.close(resolve)) };
}

function projection(value) {
  const raw = Buffer.from(JSON.stringify(value), "utf8");
  expect(raw.length <= 65536, "fixed native projection exceeded bound");
  return { bytes: raw.length, digest: sha(raw) };
}

function readTranscript(base, sessionId, rpc) {
  const root = "/var/lib/aragorn-agent-gateway/state";
  const path = `${root}/agents/main/sessions/${sessionId}.jsonl`;
  const owner = lstatSync(root), named = lstatSync(path);
  expect(named.uid > 0 && named.uid === owner.uid && named.gid === owner.gid &&
    (named.mode & 0o7133) === 0, "read transcript ownership or mode changed");
  const raw = heldRead(path, 16 * 1024 * 1024, named.mode & 0o7777, named.uid);
  const text = raw.toString("utf8"), lines = text.split("\n");
  expect(Buffer.from(text, "utf8").equals(raw) && lines.pop() === "", "read transcript is not UTF-8 JSONL");
  const results = lines.map((line) => JSON.parse(line)).filter((row) =>
    row?.type === "message" && row.message?.role === "toolResult").map((row) => row.message);
  expect(results.length === 1, "read transcript contains another tool result");
  const result = results[0];
  expect(result.toolName === "read" && result.toolCallId === rpc.toolCallId && result.isError === false &&
    !Object.hasOwn(result, "details") && base.canonicalJson(result.content) === base.canonicalJson(rpc.content),
  "read transcript and RPC result differ");
  return { bytes: raw.length, digest: sha(raw), exact_transcript_rpc_join: true };
}

async function run(base, kind, input) {
  const scenario = input.scenario;
  expect(scenario.target_name === "runtime-worker-qualified.txt" && scenario.content === "Aragorn P3.7b distinct worker create\n" &&
    base.canonicalJson(scenario.expected_result) === base.canonicalJson({
      schema: "aragorn/runtime-action-worker-result/v1", status: "COMPLETED", broker_result: { verdict: "ALLOW", effect_status: "CREATED" },
    }), "fixed create input changed");
  const tool = kind === "read" ? "read" : "aragorn_runtime_create";
  const call = base.deterministicToolCallId(scenario.id);
  const sessionKey = `agent:main:aragorn-worker-${scenario.id}`;
  const environment = base.commandEnvironment(base.requiredSecret("OPENCLAW_GATEWAY_TOKEN"));
  const token = base.requiredSecret("ARAGORN_MOCK_PROVIDER_TOKEN");
  const provider = kind === "read" ? await readProvider(base, scenario, call, token) : await base.startProvider(scenario, call, token);
  let closed = false;
  try {
    const gateway = await base.waitForGateway(environment);
    const sendCommand = await base.gatewayCall("chat.send", environment, {
      deliver: false, idempotencyKey: `aragorn-worker-${scenario.id}`,
      message: kind === "create" ? `Invoke aragorn_runtime_create exactly once for bounded scenario ${scenario.id}.` :
        "Invoke read exactly once for the owned inert fixture.",
      sessionKey, timeoutMs: 10000,
    });
    const sent = base.parseCommand(sendCommand, "chat.send");
    expect(sent.status === "started" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(sent.runId), "native turn did not start");
    const waitCommand = await base.gatewayCall("agent.wait", environment, { runId: sent.runId, timeoutMs: 15000 }, 17000);
    const waited = base.parseCommand(waitCommand, "agent.wait");
    expect(waited.runId === sent.runId && waited.status === "ok" && Number.isSafeInteger(waited.endedAt) && waited.endedAt > 0,
      "native turn did not finish");
    const historyCommand = await base.gatewayCall("chat.history", environment, { limit: 20, sessionKey });
    const history = base.parseCommand(historyCommand, "chat.history");
    await provider.close(); closed = true;
    expect(provider.errors.length === 0 && provider.records.length === 2 && history.sessionKey === sessionKey &&
      /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/.test(history.sessionId), "native turn correlation changed");
    const results = history.messages.filter((message) => message.role === "toolResult");
    expect(results.length === 1 && results[0].toolName === tool && results[0].toolCallId === call && results[0].isError === false,
      "native turn has another tool result");
    const rpc = results[0];
    const correlation = { run_id: sent.runId, session_id: history.sessionId, session_key_digest: sha(Buffer.from(sessionKey)),
      tool_call_digest: sha(Buffer.from(call)) };
    let params, nativeResult, requestDigest = null, relay = null, readTranscriptProof = null;
    if (kind === "read") {
      expect(base.canonicalJson(rpc.content) === base.canonicalJson([{ type: "text", text: READ_TEXT }]), "read text changed");
      readTranscriptProof = readTranscript(base, history.sessionId, rpc);
      params = { path: READ_PATH };
      // Exact small-text callback projection verified by the pinned real read factory;
      // its own details:undefined member is omitted by JSON.stringify.
      nativeResult = { content: [{ type: "text", text: READ_TEXT }] };
    } else {
      const transcript = base.transcriptToolResult(history.sessionId, rpc);
      const request = base.workerRequest(scenario, history.sessionId, sent.runId, call);
      relay = base.relaySummary(rpc, transcript.message, request);
      expect(base.expectedOutcome(relay.observed, scenario.expected_result) && Object.values(transcript.checks).every(Boolean) &&
        Object.values(relay.details_checks).every(Boolean), "create source result changed");
      requestDigest = sha(Buffer.from(base.canonicalJson(request), "ascii"));
      params = { content: scenario.content, target_name: scenario.target_name, __aragorn_run_id: sent.runId,
        __aragorn_session_id: history.sessionId, __aragorn_session_key_digest: correlation.session_key_digest,
        __aragorn_tool_call_digest: correlation.tool_call_digest };
      const retained = JSON.parse(rpc.content[0].text);
      nativeResult = { content: [{ type: "text", text: rpc.content[0].text }], details: {
        schema: "aragorn/runtime-action-worker-openclaw-details/v1", status: "completed", source_result: retained.result,
      } };
    }
    return {
      schema: "aragorn/native-receipt-tool-driver/v1", status: "OBSERVED", tool_name: tool,
      gateway: { system_info: { command: gateway.command, response: { pid: gateway.response.pid } } },
      provider: { request_count: provider.records.length, error_count: 0, records: provider.records },
      turn: { identifiers: { ...correlation, request_digest: requestDigest, tool_call_id: call },
        send: { command: base.commandSummary(sendCommand), run_id: sent.runId },
        wait: { command: base.commandSummary(waitCommand), run_id: waited.runId, status: waited.status },
        history: { command: base.commandSummary(historyCommand), session_id: history.sessionId } },
      native_projection: { params: projection(params), result: projection(nativeResult) },
      relay, read_transcript: readTranscriptProof, raw_callback_projection_is_source_derived: true, native_ack_wire_capture: false,
      phase3_eligible: false, run_conformance_eligible: false,
    };
  } finally { if (!closed) await provider.close(); }
}

async function main() {
  expect(process.argv.length === 5 && ["read", "create"].includes(process.argv[2]), "usage: native-receipt-driver read|create INPUT OUTPUT");
  expect(process.platform === "linux" && process.geteuid() === 0 && process.version === "v24.16.0", "owned Linux fixture required");
  const base = await legacyHelpers();
  const input = base.readInput(process.argv[3]);
  const result = await run(base, process.argv[2], input);
  base.publish(process.argv[4], result);
}

main().catch(() => { process.stderr.write("native receipt fixture driver refused\n"); process.exitCode = 1; });
