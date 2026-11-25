// Single inert transport for the cross-language check; no listening endpoint.
import assert from "node:assert/strict";
import {createInterface} from "node:readline";
assert.ok(process.permission && !process.permission.has("net") && !process.permission.has("child"));
const {runPairedTool} = await import("./paired-task.mjs");
const lines = createInterface({input:process.stdin});
const incoming = lines[Symbol.asyncIterator]();
const read = async () => {
  const {value, done} = await incoming.next();
  assert.ok(!done && value.length <= 65536);
  return Buffer.from(value, "ascii");
};
const write = bytes => new Promise((resolve, reject) =>
  process.stdout.write(Buffer.concat([bytes, Buffer.from("\n")]), e => e ? reject(e) : resolve()));
try {
  await runPairedTool({read, write}, {read, write}, new AbortController().signal, performance.now()+4000);
} finally {
  lines.close();
  process.stdin.destroy();
}
