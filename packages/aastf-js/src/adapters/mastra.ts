/**
 * Mastra framework adapter for AASTF.
 *
 * Bridges AASTF attack scenarios to agents built with the Mastra framework.
 * Intercepts Mastra agent execution, extracting tool calls and responses
 * for security evaluation via the sandbox server.
 */

import { BaseAdapter } from "./base.js";
import type { AdapterConfig } from "./base.js";
import { SandboxClient } from "../sandbox-client.js";
import type { AttackScenario, TestResult, ToolInvocation } from "../types.js";
import { Verdict } from "../types.js";

/** Mastra adapter-specific configuration. */
export interface MastraAdapterConfig extends AdapterConfig {
  /** Mastra agent name to target (if the module exports multiple agents). */
  agentName?: string;
  /** Model override (e.g., "gpt-4o", "claude-sonnet-4-20250514"). Optional. */
  model?: string;
  /** Whether to capture Mastra tool execution traces. Default: true. */
  captureToolTraces?: boolean;
}

/**
 * Adapter for agents built with the Mastra framework.
 *
 * Mastra agents use a tool-calling pattern where tools are registered on the
 * agent and invoked during execution. This adapter intercepts those calls
 * to build an AASTF-compatible trace.
 *
 * @example
 * ```ts
 * const adapter = new MastraAdapter({
 *   agentModule: "./my-mastra-agent.ts",
 *   sandboxUrl: "http://127.0.0.1:9100",
 *   agentName: "researcher",
 * });
 * const result = await adapter.runScenario(scenario);
 * ```
 */
export class MastraAdapter extends BaseAdapter {
  private readonly client: SandboxClient;
  private readonly mastraConfig: MastraAdapterConfig;

  constructor(config: MastraAdapterConfig) {
    super(config);
    this.mastraConfig = config;
    this.client = new SandboxClient(config.sandboxUrl, {
      timeoutMs: config.timeoutMs ?? 30_000,
    });
  }

  get name(): string {
    return "mastra";
  }

  /**
   * Extract tool invocations from a Mastra-style execution trace.
   *
   * Mastra agents produce step results that contain tool call information.
   * This method normalizes them into AASTF ToolInvocation format.
   */
  extractToolInvocations(
    steps: MastraStepResult[],
  ): ToolInvocation[] {
    return steps
      .filter((step) => step.type === "tool-call")
      .map((step) => ({
        toolName: step.toolName ?? "unknown",
        input: step.input ?? null,
        output: step.output ?? null,
        timestampMs: step.timestampMs ?? Date.now(),
        durationMs: step.durationMs ?? 0,
      }));
  }

  async runScenario(scenario: AttackScenario): Promise<TestResult> {
    this.validateConfig();
    const startMs = Date.now();

    try {
      const response = await this.client.submitMessage(scenario.payload);
      const executionTimeMs = Date.now() - startMs;

      return {
        resultId: `${scenario.id}-${Date.now()}`,
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        category: scenario.category,
        severity: scenario.severity,
        verdict: Verdict.INCONCLUSIVE,
        trace: response.trace,
        executionTimeMs,
      };
    } catch (error) {
      const executionTimeMs = Date.now() - startMs;
      return {
        resultId: `${scenario.id}-${Date.now()}`,
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        category: scenario.category,
        severity: scenario.severity,
        verdict: Verdict.ERROR,
        trace: {
          messages: [],
          toolInvocations: [],
          rawOutput: error instanceof Error ? error.message : String(error),
        },
        executionTimeMs,
      };
    }
  }
}

/**
 * Represents a single step result from a Mastra agent execution.
 * Used to extract tool invocations from the agent's step trace.
 */
export interface MastraStepResult {
  /** Step type: "tool-call", "llm-response", "system", etc. */
  type: string;
  /** Name of the tool that was called (only for tool-call steps). */
  toolName?: string;
  /** Input passed to the tool. */
  input?: unknown;
  /** Output returned by the tool. */
  output?: unknown;
  /** Timestamp in milliseconds. */
  timestampMs?: number;
  /** Duration of the step in milliseconds. */
  durationMs?: number;
}
