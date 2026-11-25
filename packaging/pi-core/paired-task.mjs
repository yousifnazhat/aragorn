// Opt-in fixed task only. No model, grant, listener, reconnect or measurement clock.
import {runToolCall} from "@earendil-works/pi-agent-core";
import {once} from "node:events";
import {lstatSync} from "node:fs";
import {createConnection} from "node:net";

const ROOT = "/run/aragorn-pi-bootstrap/tasks", CONTROL = ROOT + "/control.sock", SERVICE = ROOT + "/service.sock";
const MAX = 64 * 1024, CALL = "aragorn_fixed_reference_task";
const REQUEST = "aragorn/pi-core-fixed-task-request/v1", RESPONSE = "aragorn/pi-core-fixed-task-response/v1";
const pin = s => typeof s === "string" && /^sha256:[0-9a-f]{64}$/.test(s) && s.length === 71;
const object = v => v !== null && typeof v === "object" && !Array.isArray(v);
function need(ok, reason) { if (!ok) throw new Error("Paired tool: " + reason); }
function keys(v, expected) {
  return object(v) && Object.keys(v).length === expected.length && expected.every(k => Object.hasOwn(v, k));
}

// Python's canonical observations include real inode and nanosecond integers, not IEEE doubles.
function canonical(v, depth = 0) {
  need(depth <= 24, "nested frame");
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return "[" + v.map(x => canonical(x, depth + 1)).join(",") + "]";
  if (object(v)) return "{" + Object.keys(v).sort().map(k => canonical(k) + ":" + canonical(v[k], depth + 1)).join(",") + "}";
  return JSON.stringify(v).replace(/[\u007f-\uffff]/g, c => "\\u" + c.charCodeAt(0).toString(16).padStart(4,"0"));
}
function body(raw) {
  need(raw instanceof Uint8Array && raw.byteLength > 0 && raw.byteLength <= MAX, "frame length");
  const bytes = Buffer.from(raw);
  need(!bytes.some(b => b > 127), "frame encoding");
  const text = bytes.toString("ascii");
  const doc = JSON.parse(text, (_k, v, context) => {
    if (typeof v !== "number") return v;
    need(/^-?(0|[1-9][0-9]{0,19})$/.test(context.source), "integer form");
    return BigInt(context.source);
  });
  need(canonical(doc) === text, "noncanonical frame");
  return {bytes, doc};
}

async function bounded(signal, deadlineMs, work) {
  const remaining = deadlineMs - performance.now();
  need(signal instanceof AbortSignal && Number.isFinite(deadlineMs) && remaining > 0 && remaining <= 30_000, "original deadline");
  signal.throwIfAborted();
  const expiry = new AbortController();
  const timer = setTimeout(() => expiry.abort(new Error("Paired tool: expired")), Math.ceil(remaining));
  const bound = AbortSignal.any([signal, expiry.signal]);
  const guard = () => { bound.throwIfAborted(); need(performance.now() < deadlineMs, "expired"); };
  const aborted = once(bound, "abort").then(() => { throw bound.reason; });
  try { return await Promise.race([aborted, work(bound, guard)]); }
  finally { clearTimeout(timer); expiry.abort(); }
}

async function route(manager, service, signal, guard) {
  guard();
  need(manager !== service && [manager, service].every(c => c && typeof c.read === "function" &&
    typeof c.write === "function"), "two complete channels required");
  const {bytes, doc} = body(await manager.read(signal));
  need(keys(doc, ["schema","request_digest","ticket_digest"]) && doc.schema === REQUEST &&
    pin(doc.request_digest) && pin(doc.ticket_digest), "request");
  const tool = {
    name: CALL, label: CALL, description: "Execute the single manager-nominated fixed task",
    parameters: {type:"object", properties:{}, additionalProperties:false},
    async execute() {
      guard(); await service.write(bytes, signal);
      guard(); const reply = body(await service.read(signal)); guard();
      need(keys(reply.doc, ["schema","request_digest","ticket_digest","service_nonce","observation"]) && reply.doc.schema === RESPONSE &&
        reply.doc.request_digest === doc.request_digest && reply.doc.ticket_digest === doc.ticket_digest &&
        typeof reply.doc.service_nonce === "string" && reply.doc.service_nonce.length === 64 && !/[^0-9a-f]/.test(reply.doc.service_nonce) &&
        object(reply.doc.observation), "unbound reply");
      return {content:[], details:reply.bytes};
    },
  };
  // This explicit local tool call uses Pi's validator and executor, never its agent loop or a model response.
  const call = {type:"toolCall", id:doc.ticket_digest, name:CALL, arguments:{}};
  const outcome = await runToolCall(call, {tools:[tool], context:{systemPrompt:"", messages:[], tools:[tool]},
    assistantMessage:{role:"assistant", content:[call]}, signal});
  guard();
  need(!outcome.isError && Buffer.isBuffer(outcome.result.details), "failed or uncertain; do not retry");
  await manager.write(outcome.result.details, signal);
  guard();
}

export function runPairedTool(manager, service, signal, deadlineMs) {
  return bounded(signal, deadlineMs, (bound, guard) => route(manager, service, bound, guard));
}

function endpointIdentity(path, uid, gid) {
  need(process.platform === "linux" && Number.isSafeInteger(uid) && uid > 0 && Number.isSafeInteger(gid) && gid > 0 &&
    process.getuid() === uid && process.geteuid() === uid && process.getgid() === gid && process.getegid() === gid &&
    process.getgroups().every(g => g === gid), "confined identity");
  const parts = ["/","/run","/run/aragorn-pi-bootstrap",ROOT,path].map(name => {
    const s = lstatSync(name, {bigint:true});
    need(s.uid === 0n && (name === path
      ? s.isSocket() && s.nlink === 1n && s.gid === BigInt(gid) && (s.mode & 0o7777n) === 0o660n
      : s.isDirectory() && (s.mode & 0o022n) === 0n), "unprotected endpoint");
    if (name === ROOT) need(((s.mode >> (s.gid === BigInt(gid) ? 3n : 0n)) & 7n) === 1n, "listable task directory");
    return [s.dev,s.ino,s.uid,s.gid,s.mode].join(":");
  });
  return parts.join("|");
}

// All directions are one bounded 4-byte-BE length/body, followed by EOF, not a persistent bootstrap stream.
function framed(socket) {
  return {
    async read() {
      const buf = Buffer.allocUnsafe(MAX + 4);
      let size = 0;
      for await (const chunk of socket) {
        need(Buffer.isBuffer(chunk) && size + chunk.length <= buf.length, "oversized framed stream");
        chunk.copy(buf, size); size += chunk.length;
        if (size >= 4) need(buf.readUInt32BE(0) > 0 && buf.readUInt32BE(0) <= MAX && size <= buf.readUInt32BE(0) + 4, "frame length");
      }
      need(size >= 5 && buf.readUInt32BE(0) === size - 4, "truncated frame");
      return buf.subarray(4, size);
    },
    async write(bytes) {
      need(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX, "frame length");
      const head = Buffer.alloc(4); head.writeUInt32BE(bytes.length);
      await new Promise((resolve, reject) => socket.end(Buffer.concat([head, bytes]), err => err ? reject(err) : resolve()));
    },
  };
}

export async function runPairedSocketTool({workerUid, workerGid, signal, deadlineMs}) {
  const sockets = [];
  async function connect(path, bound, guard) {
    guard();
    const identity = endpointIdentity(path, workerUid, workerGid);
    const socket = createConnection({path, allowHalfOpen:true, signal:bound});
    sockets.push(socket);
    socket.on("error", () => {}); // read/connect/write still fail closed; never expose packet contents
    await once(socket, "connect", {signal:bound}); guard();
    need(endpointIdentity(path, workerUid, workerGid) === identity, "endpoint changed");
    return framed(socket);
  }
  try {
    await bounded(signal, deadlineMs, async (bound, guard) => {
      const manager = await connect(CONTROL,bound,guard), service = await connect(SERVICE,bound,guard);
      await route(manager, service, bound, guard);
    });
  } finally { for (const socket of sockets) socket.destroy(); }
}
