from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_PLUGIN = _ROOT / "packaging" / "openclaw" / "aragorn-runtime-action"


class RuntimeActionOpenClawPluginTests(unittest.TestCase):
    def test_manifest_exposes_one_optional_native_tool(self) -> None:
        manifest_path = _PLUGIN / "openclaw.plugin.json"
        package_path = _PLUGIN / "package.json"
        manifest_raw = manifest_path.read_bytes()
        package_raw = package_path.read_bytes()
        manifest = json.loads(manifest_raw)
        package = json.loads(package_raw)

        self.assertEqual(
            manifest_raw,
            json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
            + b"\n",
        )
        self.assertEqual(
            package_raw,
            json.dumps(package, separators=(",", ":"), sort_keys=True).encode()
            + b"\n",
        )
        self.assertEqual(manifest["contracts"]["tools"], ["aragorn_runtime_create"])
        self.assertEqual(
            manifest["toolMetadata"],
            {"aragorn_runtime_create": {"optional": True}},
        )
        self.assertFalse(manifest["configSchema"]["additionalProperties"])
        self.assertEqual(package["openclaw"]["extensions"], ["./index.js"])
        source = (_PLUGIN / "index.js").read_text(encoding="utf-8")
        self.assertIn('{ name: TOOL_NAME, optional: true }', source)
        self.assertNotIn("http", source.lower())

    @unittest.skipUnless(shutil.which("node"), "Node.js is required")
    def test_canonical_framed_client_rejects_trailing_response(self) -> None:
        script = r"""
const assert = require("node:assert/strict");
const { mkdtempSync, rmSync } = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const plugin = require(process.argv[1]);
const { buildEnvelope, canonicalJson, requestBroker, sha256 } = plugin.__testing;
const digest = (character) => `sha256:${character.repeat(64)}`;
const config = {
  activeSkillDigest: digest("2"), expectedBrokerUid: 1, expectedRuntimeGid: 2,
  expectedRuntimeUid: 3, policyDigest: digest("4"), policyVersion: 1,
  protectedRoot: "/protected", runtimeDigest: digest("1"), socketPath: "/unused",
};
let factory;
plugin.register({
  pluginConfig: config,
  on() { assert.fail("the private tool must not require a global parameter hook"); },
  registerTool(value, options) {
    factory = value;
    assert.deepEqual(options, { name: "aragorn_runtime_create", optional: true });
  },
});
assert.equal(typeof factory, "function");
for (const sessionKey of [
  "agent:main:whatsapp:group:120363000000@g.us",
  "agent:main:matrix:room:!room/id=example:server",
  "agent:main:signal:group:+group/key=",
]) {
  const tool = factory({ sessionId: "session-1", sessionKey });
  const prepared = tool.prepareBeforeToolCallParams(
    { content: "payload", target_name: "action.txt" },
    {
      toolCallId: "call_123|fc_123",
      hookContext: { runId: "run-1", sessionId: "session-1", sessionKey },
    },
  );
  assert.equal(Object.isFrozen(prepared), true);
  assert.equal(Reflect.set(prepared, "__aragorn_run_id", "forged"), false);
  const adjusted = tool.finalizeBeforeToolCallParams(
    { ...prepared, target_name: "adjusted.txt", __aragorn_run_id: "overwritten" },
    prepared,
  );
  assert.equal(adjusted.__aragorn_run_id, "run-1");
  assert.equal(adjusted.__aragorn_session_id, "session-1");
  assert.equal(
    adjusted.__aragorn_session_key_digest,
    sha256(Buffer.from(sessionKey, "utf8")),
  );
  assert.equal(
    adjusted.__aragorn_tool_call_id_digest,
    sha256(Buffer.from("call_123|fc_123", "utf8")),
  );
  assert.equal(adjusted.target_name, "adjusted.txt");
}
const tool = factory({ sessionId: "session-1", sessionKey: "agent:main:run-1" });
assert.throws(() => tool.prepareBeforeToolCallParams(
  { content: "payload", target_name: "action.txt", __aragorn_run_id: "forged" },
  {
    toolCallId: "call_123|fc_123",
    hookContext: {
      runId: "run-1", sessionId: "session-1", sessionKey: "agent:main:run-1",
    },
  },
), /ambiguous/);
assert.throws(() => tool.prepareBeforeToolCallParams(
  { content: "payload", target_name: "action.txt" },
  { toolCallId: "call-1" },
), /ambiguous/);
assert.throws(() => tool.prepareBeforeToolCallParams(
  { content: "payload", target_name: "action.txt" },
  {
    hookContext: {
      runId: "run-1", sessionId: "session-1", sessionKey: "agent:main:run-1",
    },
  },
), /tool call id/);
const envelope = buildEnvelope(
  config,
  { sessionId: "session-1", runId: "run-1", toolCallId: "call-1" },
  "action.txt",
  Buffer.from("Aragorn mediated exactly one action.\n"),
  { device: 7, inode: 9 },
  100,
);
assert.equal(envelope.request.path_digest, sha256(Buffer.from(canonicalJson({
  root_device: 7, root_inode: 9, schema: "aragorn/runtime-protected-path/v1",
  target_name: "action.txt",
}), "ascii")));

const temporary = mkdtempSync(path.join(os.tmpdir(), "aragorn-plugin-"));
const socketPath = path.join(temporary, "broker.sock");
let trailing = false;
const server = net.createServer((socket) => {
  const chunks = [];
  socket.on("data", (chunk) => chunks.push(chunk));
  socket.on("end", () => {
    const frame = Buffer.concat(chunks);
    const size = frame.readUInt32BE(0);
    assert.equal(frame.length, size + 4);
    assert.equal(canonicalJson(JSON.parse(frame.subarray(4).toString("ascii"))), frame.subarray(4).toString("ascii"));
    const result = {
      schema: "aragorn/runtime-action-broker-result/v1",
      authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
      request_digest: sha256(Buffer.from(canonicalJson(envelope.request), "ascii")),
      observation_digest: digest("6"), target_name: "action.txt", verdict: "ALLOW",
      reason_codes: [], effect_status: "CREATED", decision: { verdict: "ALLOW" },
    };
    const raw = Buffer.from(canonicalJson(result), "ascii");
    const response = Buffer.alloc(4 + raw.length + (trailing ? 1 : 0));
    response.writeUInt32BE(raw.length, 0); raw.copy(response, 4);
    if (trailing) response[response.length - 1] = 10;
    socket.end(response);
  });
});

server.listen(socketPath, async () => {
  try {
    const result = await requestBroker(socketPath, envelope);
    assert.equal(result.effect_status, "CREATED");
    trailing = true;
    await assert.rejects(
      requestBroker(socketPath, envelope),
      (error) => error.effectStatus === "INDETERMINATE" && /framing/.test(error.message),
    );
  } finally {
    server.close(() => { rmSync(temporary, { recursive: true, force: true }); });
  }
});
"""
        completed = subprocess.run(
            ["node", "-e", script, str(_PLUGIN / "index.js")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())


if __name__ == "__main__":
    unittest.main()
