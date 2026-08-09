from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PLUGIN = _ROOT / "packaging" / "openclaw" / "aragorn-runtime-action-worker"


class RuntimeActionWorkerPluginTests(unittest.TestCase):
    def test_manifest_exposes_only_the_gateway_worker_surface(self) -> None:
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
            json.dumps(package, separators=(",", ":"), sort_keys=True).encode() + b"\n",
        )
        self.assertEqual(manifest["id"], "aragorn-runtime-action-worker")
        self.assertEqual(manifest["contracts"]["tools"], ["aragorn_runtime_create"])
        self.assertEqual(
            manifest["toolMetadata"],
            {"aragorn_runtime_create": {"optional": True}},
        )
        schema = manifest["configSchema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            set(schema["required"]),
            {
                "expectedGatewayGid",
                "expectedGatewayUid",
                "expectedWorkerUid",
                "workerSocketPath",
            },
        )
        self.assertEqual(set(schema["properties"]), set(schema["required"]))
        self.assertEqual(package["openclaw"]["extensions"], ["./index.js"])
        source = (_PLUGIN / "index.js").read_text(encoding="utf-8")
        self.assertIn("{ name: TOOL_NAME, optional: true }", source)
        self.assertIn("UID-owned endpoint metadata is the claim ceiling", source)
        self.assertIn("the sensor measures", source)
        self.assertNotIn("expectedBrokerUid", source)
        self.assertNotIn("sensorSocketPath", source)
        self.assertNotIn("protectedRoot", source)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required")
    def test_exact_protocol_and_relay_semantics(self) -> None:
        script = r"""
const assert = require("node:assert/strict");
const plugin = require(process.argv[1]);
const {
  buildRequest, canonicalJson, clientErrorResult, parseWorkerResult, sha256,
  workerToolResult,
} = plugin.__testing;
const digest = (character) => `sha256:${character.repeat(64)}`;
const config = {
  expectedGatewayGid: 20,
  expectedGatewayUid: 501,
  expectedWorkerUid: 502,
  workerSocketPath: "/run/aragorn-runtime-action-worker/worker.sock",
};

assert.throws(() => plugin.register({
  pluginConfig: { ...config, sensorSocketPath: "/forbidden" },
  registerTool() {},
}), /fields/);
let factory;
plugin.register({
  pluginConfig: config,
  registerTool(value, options) {
    factory = value;
    assert.deepEqual(options, { name: "aragorn_runtime_create", optional: true });
  },
});
const tool = factory({ sessionId: "session-1", sessionKey: "agent:main:session-1" });
const prepared = tool.prepareBeforeToolCallParams(
  { content: "payload", target_name: "action.txt" },
  {
    toolCallId: "call_123|fc_123",
    hookContext: {
      runId: "run-1",
      sessionId: "session-1",
      sessionKey: "agent:main:session-1",
    },
  },
);
assert.equal(Object.isFrozen(prepared), true);
const finalized = tool.finalizeBeforeToolCallParams(
  { ...prepared, __aragorn_run_id: "forged" },
  prepared,
);
assert.equal(finalized.__aragorn_run_id, "run-1");
assert.equal(finalized.__aragorn_session_id, "session-1");
assert.equal(finalized.__aragorn_tool_call_digest, sha256(Buffer.from("call_123|fc_123", "utf8")));

const request = buildRequest(
  {
    runId: "run-1",
    sessionId: "session-1",
    toolCallDigest: finalized.__aragorn_tool_call_digest,
  },
  "action.txt",
  Buffer.from("payload"),
);
assert.deepEqual(Object.keys(request).sort(), [
  "authority", "payload_base64", "run_id", "schema", "session_id",
  "target_name", "tool_call_digest",
]);
assert.equal(request.schema, "aragorn/runtime-action-worker-request/v1");
assert.equal(request.authority, "GATEWAY_REQUEST_ONLY_NOT_EFFECT_AUTHORITY");
assert.equal(request.payload_base64, "cGF5bG9hZA==");
assert.throws(
  () => buildRequest({ runId: "run-1", sessionId: "session-1", toolCallDigest: "bad" }, "action.txt", Buffer.alloc(0)),
  /digest/,
);

const brokerRequestDigest = digest("5");
const decision = {
  active_context_digest: digest("a"),
  authority: "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
  evaluated_at_unix: 100,
  measured_action_digest: digest("b"),
  mediator_health_digest: digest("c"),
  mediator_health_epoch: 4,
  minimum_mediator_health_epoch: 2,
  minimum_revocation_generation: 2,
  policy_digest: digest("d"),
  policy_version: 7,
  reason_codes: [],
  request_digest: brokerRequestDigest,
  revocation_generation: 3,
  revocation_snapshot_digest: digest("e"),
  schema: "aragorn/runtime-action-decision/v1",
  verdict: "ALLOW",
};
const brokerResult = {
  authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
  decision,
  effect_status: "CREATED",
  observation_digest: digest("6"),
  reason_codes: [],
  request_digest: brokerRequestDigest,
  schema: "aragorn/runtime-action-broker-result/v1",
  target_name: "action.txt",
  verdict: "ALLOW",
};
const completed = {
  authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
  broker_result: brokerResult,
  request_digest: sha256(Buffer.from(canonicalJson(request), "ascii")),
  schema: "aragorn/runtime-action-worker-result/v1",
  status: "COMPLETED",
};
const parsed = parseWorkerResult(Buffer.from(canonicalJson(completed), "ascii"), request);
const allowed = workerToolResult(parsed);
assert.equal(allowed.isError, false);
assert.deepEqual(allowed.details, completed);
assert.equal(canonicalJson(JSON.parse(allowed.content[0].text)), allowed.content[0].text);
assert.equal(Object.keys(decision).length, 16);

const rejectDecision = (candidate) => assert.throws(
  () => parseWorkerResult(Buffer.from(canonicalJson({
    ...completed,
    broker_result: { ...brokerResult, decision: candidate },
  }), "ascii"), request),
  (error) => error.status === "INDETERMINATE" && /decision/.test(error.message),
);
rejectDecision({ reason_codes: [], verdict: "ALLOW" });
rejectDecision({ ...decision, extra: true });
rejectDecision({ ...decision, authority: "WRONG_AUTHORITY" });
rejectDecision({ ...decision, request_digest: digest("f") });
rejectDecision({ ...decision, active_context_digest: null });
rejectDecision({ ...decision, verdict: "BLOCK", reason_codes: ["ACTION_UNATTRIBUTED"] });
rejectDecision({
  ...decision,
  reason_codes: Array.from({ length: 129 }, (_value, index) => `R${String(index).padStart(3, "0")}`),
  verdict: "BLOCK",
});

const blocked = {
  ...completed,
  broker_result: {
    ...brokerResult,
    decision: null,
    effect_status: "NOT_PERFORMED",
    reason_codes: ["BROKER_REPLAY_BLOCKED"],
    verdict: "BLOCK",
  },
};
assert.equal(
  workerToolResult(parseWorkerResult(Buffer.from(canonicalJson(blocked), "ascii"), request)).isError,
  true,
);
assert.equal(
  parseWorkerResult(Buffer.from(canonicalJson({
    ...blocked,
    broker_result: { ...blocked.broker_result, decision: brokerResult.decision },
  }), "ascii"), request).status,
  "COMPLETED",
);
const missingContextDecision = {
  ...decision,
  active_context_digest: null,
  measured_action_digest: null,
  reason_codes: ["ACTION_UNATTRIBUTED", "ACTION_UNMEASURED"],
  verdict: "BLOCK",
};
assert.equal(
  parseWorkerResult(Buffer.from(canonicalJson({
    ...blocked,
    broker_result: { ...blocked.broker_result, decision: missingContextDecision },
  }), "ascii"), request).status,
  "COMPLETED",
);
assert.equal(
  parseWorkerResult(Buffer.from(canonicalJson({
    ...blocked,
    broker_result: {
      ...blocked.broker_result,
      decision: {
        ...missingContextDecision,
        reason_codes: ["ACTION_REQUEST_INVALID"],
      },
    },
  }), "ascii"), request).status,
  "COMPLETED",
);
const notSubmitted = { ...completed, broker_result: null, status: "NOT_SUBMITTED" };
assert.equal(
  workerToolResult(parseWorkerResult(Buffer.from(canonicalJson(notSubmitted), "ascii"), request)).isError,
  true,
);
assert.throws(
  () => parseWorkerResult(Buffer.from(canonicalJson({ ...completed, broker_result: null }), "ascii"), request),
  /broker result/,
);
assert.throws(
  () => parseWorkerResult(Buffer.from(`${canonicalJson(completed)}\n`, "ascii"), request),
  /canonical/,
);
assert.throws(
  () => parseWorkerResult(Buffer.from(canonicalJson({ ...completed, request_digest: digest("9") }), "ascii"), request),
  /binding/,
);
const clientError = clientErrorResult(new Error("unavailable"));
assert.equal(clientError.isError, true);
assert.equal(clientError.details.status, "NOT_SUBMITTED");
assert.equal(
  clientError.details.authority,
  "GATEWAY_CLIENT_ERROR_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
);
"""
        completed = subprocess.run(
            ["node", "-e", script, str(_PLUGIN / "index.js")],
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    @unittest.skipUnless(shutil.which("node"), "Node.js is required")
    def test_uid_owned_endpoint_uses_exact_framing_without_retry(self) -> None:
        script = r"""
const assert = require("node:assert/strict");
const { chmodSync, mkdtempSync, realpathSync, rmSync } = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const plugin = require(process.argv[1]);
const { buildRequest, canonicalJson, requestWorker, sha256 } = plugin.__testing;
const digest = (character) => `sha256:${character.repeat(64)}`;

(async () => {
  const temporary = mkdtempSync(path.join(realpathSync(os.tmpdir()), "aragorn-worker-plugin-"));
  chmodSync(temporary, 0o711);
  const socketPath = path.join(temporary, "worker.sock");
  const config = {
    expectedGatewayGid: process.getgid(),
    expectedGatewayUid: process.getuid() === 0 ? 1 : 0,
    expectedWorkerUid: process.getuid(),
    workerSocketPath: socketPath,
  };
  const request = buildRequest(
    { runId: "run-1", sessionId: "session-1", toolCallDigest: digest("1") },
    "action.txt",
    Buffer.from("payload"),
  );
  let connections = 0;
  let trailing = false;
  const server = net.createServer((socket) => {
    connections += 1;
    const chunks = [];
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => {
      const frame = Buffer.concat(chunks);
      if (frame.length === 0) return;
      const size = frame.readUInt32BE(0);
      assert.equal(frame.length, size + 4);
      const received = frame.subarray(4).toString("ascii");
      assert.equal(received, canonicalJson(request));
      const brokerRequestDigest = digest("2");
      const result = {
        authority: "WORKER_RELAY_RESULT_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
        broker_result: {
          authority: "RUNTIME_EFFECT_RESULT_ONLY_NOT_RUN_CONFORMANCE_AUTHORITY",
          decision: {
            active_context_digest: digest("a"),
            authority: "RUNTIME_POLICY_DECISION_ONLY_NOT_EFFECT_OR_RUN_CONFORMANCE_AUTHORITY",
            evaluated_at_unix: 100,
            measured_action_digest: digest("b"),
            mediator_health_digest: digest("c"),
            mediator_health_epoch: 4,
            minimum_mediator_health_epoch: 2,
            minimum_revocation_generation: 2,
            policy_digest: digest("d"),
            policy_version: 7,
            reason_codes: [],
            request_digest: brokerRequestDigest,
            revocation_generation: 3,
            revocation_snapshot_digest: digest("e"),
            schema: "aragorn/runtime-action-decision/v1",
            verdict: "ALLOW",
          },
          effect_status: "CREATED",
          observation_digest: digest("3"),
          reason_codes: [],
          request_digest: brokerRequestDigest,
          schema: "aragorn/runtime-action-broker-result/v1",
          target_name: "action.txt",
          verdict: "ALLOW",
        },
        request_digest: sha256(Buffer.from(canonicalJson(request), "ascii")),
        schema: "aragorn/runtime-action-worker-result/v1",
        status: "COMPLETED",
      };
      const raw = Buffer.from(canonicalJson(result), "ascii");
      const response = Buffer.alloc(4 + raw.length + (trailing ? 1 : 0));
      response.writeUInt32BE(raw.length, 0);
      raw.copy(response, 4);
      if (trailing) response[response.length - 1] = 10;
      socket.end(response);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  try {
    chmodSync(socketPath, 0o660);
    const result = await requestWorker(config, request);
    assert.equal(result.status, "COMPLETED");
    trailing = true;
    await assert.rejects(
      requestWorker(config, request),
      (error) => error.status === "INDETERMINATE" && /framing/.test(error.message),
    );
    const originalPeerCredentials = net.Socket.prototype.getPeerCredentials;
    try {
      net.Socket.prototype.getPeerCredentials = () => ({
        gid: process.getgid(), pid: process.pid, uid: process.getuid() + 1,
      });
      await assert.rejects(
        requestWorker(config, request),
        (error) => error.status === "NOT_SUBMITTED" && /credentials/.test(error.message),
      );
    } finally {
      if (originalPeerCredentials === undefined) {
        delete net.Socket.prototype.getPeerCredentials;
      } else {
        net.Socket.prototype.getPeerCredentials = originalPeerCredentials;
      }
    }
    const originalEnd = net.Socket.prototype.end;
    try {
      net.Socket.prototype.end = function (...args) {
        if (!this.server) throw new Error("synthetic post-submission end failure");
        return originalEnd.apply(this, args);
      };
      await assert.rejects(
        requestWorker(config, request),
        (error) => error.status === "INDETERMINATE" && /end failure/.test(error.message),
      );
    } finally {
      net.Socket.prototype.end = originalEnd;
    }
    let abortedReads = 0;
    let abortListenerAdded = false;
    let abortListenerRemoved = false;
    const racingSignal = {
      get aborted() {
        abortedReads += 1;
        return abortedReads > 1;
      },
      addEventListener(event) {
        assert.equal(event, "abort");
        abortListenerAdded = true;
      },
      removeEventListener(event) {
        assert.equal(event, "abort");
        abortListenerRemoved = true;
      },
    };
    await assert.rejects(
      requestWorker(config, request, racingSignal),
      (error) => error.status === "NOT_SUBMITTED" && /aborted/.test(error.message),
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(abortListenerAdded, true);
    assert.equal(abortListenerRemoved, true);
    assert.equal(connections, 4);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    rmSync(temporary, { recursive: true, force: true });
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
"""
        completed = subprocess.run(
            ["node", "-e", script, str(_PLUGIN / "index.js")],
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())


if __name__ == "__main__":
    unittest.main()
