#!/usr/bin/env node

/**
 * Subprocess worker for SandboxServer's `subprocess: true` mode.
 *
 * This script is forked by the server and communicates via Node IPC.
 * It receives scenario data, runs them through ScenarioRunner, and
 * sends the report back. Because it runs in a separate process, the
 * OS can enforce resource limits (cgroups, ulimit, seccomp) independently
 * of the parent server process.
 *
 * This file is NOT meant to be imported directly — it is executed by
 * `child_process.fork()` from sandbox-server.ts.
 */

import { ScenarioRunner } from "./scenario-runner.js";
import type { AttackScenario } from "./types.js";
import type { ScanWorkerMessage } from "./sandbox-server.js";

interface WorkPayload {
  type: "run";
  scenarios: AttackScenario[];
  timeoutMs: number;
}

process.on("message", async (msg: WorkPayload) => {
  if (msg.type !== "run") return;

  try {
    // NOTE: In subprocess mode the adapter is not transferred — the worker
    // creates a no-op adapter that always returns empty strings. Real
    // subprocess isolation requires the adapter to be reconstructable from
    // serialisable config, which is adapter-specific. Extend this block
    // to instantiate the correct adapter from a config payload.
    const noopAdapter = {
      name: "subprocess-noop",
      async invoke(_prompt: string): Promise<string> {
        return "[subprocess mode: no adapter configured]";
      },
    };

    const runner = new ScenarioRunner(noopAdapter as never, {
      timeoutMs: msg.timeoutMs,
    });

    const report = await runner.runScenarios(msg.scenarios);

    const response: ScanWorkerMessage = { type: "result", report };
    process.send!(response);
  } catch (err) {
    const response: ScanWorkerMessage = {
      type: "error",
      message: err instanceof Error ? err.message : String(err),
    };
    process.send!(response);
  }

  // Exit cleanly after completing the work
  process.exit(0);
});
