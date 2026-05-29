/**
 * Vercel AI SDK adapter for AASTF.
 *
 * Bridges AASTF attack scenarios to agents built with the Vercel AI SDK.
 * Intercepts streamText/generateText calls and extracts tool invocations
 * for security evaluation via the sandbox server.
 */

import { BaseAdapter } from "./base.js";
import type { AdapterConfig } from "./base.js";
import { SandboxClient } from "../sandbox-client.js";
import type { AttackScenario, TestResult, ToolInvocation } from "../types.js";
import { Verdict } from "../types.js";

/** Vercel AI SDK adapter-specific configuration. */
export interface VercelAIAdapterConfig extends AdapterConfig {
  /** Provider to use (e.g., "openai", "anthropic", "google"). Optional. */
  provider?: string;
  /** Model ID override (e.g., "gpt-4o", "claude-sonnet-4-20250514"). Optional. */
  model?: string;
  /** Whether to intercept streaming calls (streamText). Default: true. */
  interceptStreaming?: boolean;
}

/**
 * Adapter for agents built with the Vercel AI SDK.
 *
 * The Vercel AI SDK exposes `generateText` and `streamText` functions that
 * return structured tool invocation results. This adapter intercepts those
 * calls and normalizes tool usage into AASTF-compatible traces.
 *
 * @example
 * ```ts
 * const adapter = new VercelAIAdapter({
 *   agentModule: "./my-vercel-agent.ts",
 *   sandboxUrl: "http://127.0.0.1:9100",
 *   provider: "openai",
 * });
 * const result = await adapter.runScenario(scenario);
 * ```
 */
export class VercelAIAdapter extends BaseAdapter {
  private readonly client: SandboxClient;
  private readonly vercelConfig: VercelAIAdapterConfig;

  constructor(config: VercelAIAdapterConfig) {
    super(config);
    this.vercelConfig = config;
    this.client = new SandboxClient(config.sandboxUrl, {
      timeoutMs: config.timeoutMs ?? 30_000,
    });
  }

  get name(): string {
    return "vercel-ai";
  }

  /**
   * Extract tool invocations from a Vercel AI SDK tool call result.
   *
   * The Vercel AI SDK returns tool results in its `toolCalls` and
   * `toolResults` arrays from generateText/streamText. This method
   * normalizes them into AASTF ToolInvocation format.
   */
  extractToolInvocations(
    toolCalls: VercelAIToolCall[],
    toolResults?: VercelAIToolResult[],
  ): ToolInvocation[] {
    const resultMap = new Map<string, VercelAIToolResult>();
    if (toolResults) {
      for (const result of toolResults) {
        resultMap.set(result.toolCallId, result);
      }
    }

    return toolCalls.map((call) => {
      const result = resultMap.get(call.toolCallId);
      return {
        toolName: call.toolName,
        input: call.args ?? null,
        output: result?.result ?? null,
        timestampMs: call.timestampMs ?? Date.now(),
        durationMs: result?.durationMs ?? 0,
      };
    });
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
 * Represents a tool call from the Vercel AI SDK's generateText/streamText.
 * Mirrors the `ToolCall` type from the `ai` package.
 */
export interface VercelAIToolCall {
  /** Unique identifier for this tool call. */
  toolCallId: string;
  /** Name of the tool that was called. */
  toolName: string;
  /** Arguments passed to the tool. */
  args?: unknown;
  /** Timestamp in milliseconds (AASTF extension). */
  timestampMs?: number;
}

/**
 * Represents a tool result from the Vercel AI SDK.
 * Mirrors the `ToolResult` type from the `ai` package.
 */
export interface VercelAIToolResult {
  /** Matches the toolCallId from the corresponding ToolCall. */
  toolCallId: string;
  /** Name of the tool. */
  toolName: string;
  /** Result returned by the tool execution. */
  result: unknown;
  /** Duration of the tool execution in milliseconds (AASTF extension). */
  durationMs?: number;
}
