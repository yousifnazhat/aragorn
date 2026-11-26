// This role has one request, two fixed channels and no CLI, provider or retry.
import {runPairedSocketTool} from "./paired-task.mjs";

const node = "/opt/aragorn/pi-runtime/node/bin/node";
const entry = "/opt/aragorn/pi-runtime/pi-core/entrypoint.js";
try {
  if (process.platform !== "linux" || process.arch !== "arm64" || process.execPath !== node ||
      process.argv.length !== 2 || process.argv[1] !== entry ||
      process.execArgv.length !== 1 || process.execArgv[0] !== "--disallow-code-generation-from-strings") {
    throw new Error("wrong fixed task launch");
  }
  const deadlineMs = performance.now() + 25_000;
  await runPairedSocketTool({workerUid:process.getuid(), workerGid:process.getgid(),
    signal:new AbortController().signal, deadlineMs});
  // Stay identifiable for the manager's final guard and owned retirement, never accept more work.
  // This local cap does not renew or replace the manager's original, independent deadline.
  await new Promise(resolve => setTimeout(resolve, Math.max(1, deadlineMs-performance.now())));
} finally {
  // Expiry or failure without explicit retirement must never report success.
  process.exitCode = 1;
}
