import assert from "node:assert/strict";
import {syncBuiltinESMExports} from "node:module";
import net from "node:net";
import tls from "node:tls";
import http from "node:http";
import https from "node:https";
import child from "node:child_process";
const refuse = () => { throw new Error("live IO disabled"); };
globalThis.fetch = refuse;
for (const [mod, names] of [[net, ["connect","createConnection","createServer"]], [tls, ["connect","createServer"]],
  [http, ["get","request","createServer"]], [https, ["get","request","createServer"]],
  [child, ["spawn","spawnSync","exec","execSync","execFile","execFileSync","fork"]]]) {
  for (const name of names) mod[name] = refuse;
}
net.Socket.prototype.connect = net.Server.prototype.listen = refuse;
syncBuiltinESMExports();
const {runPairedTool,runPairedSocketTool} = await import("./paired-task.mjs");
const request = "sha256:" + "a".repeat(64), ticket = "sha256:" + "b".repeat(64);
const packet = Buffer.from(JSON.stringify({request_digest:request,schema:"aragorn/pi-core-fixed-task-request/v1",ticket_digest:ticket}));
const nonce = "c".repeat(64), nonceField = ',"service_nonce":"'+nonce+'"';
const reply = Buffer.from('{"observation":{"retained_file":{"mtime_ns":1728159999000000001}},' +
  '"request_digest":"'+request+'","schema":"aragorn/pi-core-fixed-task-response/v1"'+nonceField+',"ticket_digest":"'+ticket+'"}');
const run = (manager, service) => runPairedTool(manager, service, new AbortController().signal, performance.now()+2000);
const trace = [];
const manager = {read: async () => { trace.push("from-manager"); return packet; },
  write: async b => { assert.deepEqual(b, reply); trace.push("to-manager"); }};
const service = {write: async b => { assert.deepEqual(b, packet); trace.push("to-service"); },
  read: async () => { trace.push("from-service"); return reply; }};
// The worker must preserve the protected service's post-work nonce, never supply a missing one.
for (const raw of [reply.toString().replace(nonceField, ""), reply.toString().replace(nonce, "C".repeat(64)),
  reply.toString().replace(nonce, "c".repeat(63)), reply.toString().replace('"'+nonce+'"', "null")]) {
  const writes = [];
  await assert.rejects(run({...manager, write:async b => { writes.push(b); }}, {...service, read:async () => Buffer.from(raw)}));
  assert.equal(writes.length, 0);
}
trace.length = 0;
await run(manager, service);
assert.deepEqual(trace, ["from-manager", "to-service", "from-service", "to-manager"]);
let attempts = 0;
await assert.rejects(run(manager, {...service, write: async () => { attempts++; throw Error("uncertain"); }}));
assert.equal(attempts, 1);
for (const invalid of [Buffer.from('{"schema":"wrong"}'), Buffer.alloc(65537),
    Buffer.from(packet.toString().replace('"schema":', '"schema":"duplicate","schema":'))]) {
  trace.length = 0;
  await assert.rejects(run({...manager, read:async () => invalid}, service));
  assert.deepEqual(trace, []);
}
for (const bad of [Buffer.from(reply.toString().replace(request,ticket)), Buffer.from(reply.toString().replace(ticket,request)),
  Buffer.from(reply.toString().replace("response/v1","request/v1")), Buffer.concat([reply,Buffer.from("\n")])]) {
  trace.length = 0;
  await assert.rejects(run(manager, {...service,read:async () => bad}));
  assert.deepEqual(trace, ["from-manager","to-service"]);
}
trace.length = 0;
await assert.rejects(runPairedTool(manager, service, AbortSignal.abort(), performance.now()+2000));
await assert.rejects(runPairedTool(manager, service, new AbortController().signal));
await assert.rejects(runPairedTool(manager, service, new AbortController().signal, performance.now()-1));
await assert.rejects(runPairedSocketTool({signal:new AbortController().signal,deadlineMs:performance.now()+2000}));
assert.deepEqual(trace, []);
let settle;
await assert.rejects(runPairedTool(manager, {...service, read:() => new Promise(r => {settle = r;})},
  new AbortController().signal, performance.now()+50));
assert.deepEqual(trace, ["from-manager","to-service"]);
settle(reply); await new Promise(r => setImmediate(r));
assert.deepEqual(trace, ["from-manager","to-service"]); // late completion cannot be forwarded or retried
