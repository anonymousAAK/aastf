/**
 * OpenAI Agents SDK adapter for AASTF.
 *
 * Bridges AASTF attack scenarios to agents built with the OpenAI Agents SDK.
 * The actual agent execution happens via the sandbox server — this adapter
 * configures the sandbox and collects results.
 */

import { BaseAdapter } from "./base.js";
import type { AdapterConfig } from "./base.js";
import { SandboxClient } from "../sandbox-client.js";
import type { AttackScenario, TestResult } from "../types.js";
import { Verdict } from "../types.js";

/** OpenAI Agents adapter-specific configuration. */
export interface OpenAIAgentsAdapterConfig extends AdapterConfig {
  /** OpenAI model to use (e.g., "gpt-4o"). Optional — uses agent default. */
  model?: string;
  /** API key override. If omitted, uses OPENAI_API_KEY env var. */
  apiKey?: string;
}

/**
 * Adapter for agents built with the OpenAI Agents SDK.
 *
 * @example
 * ```ts
 * const adapter = new OpenAIAgentsAdapter({
 *   agentModule: "./my-agent.ts",
 *   sandboxUrl: "http://127.0.0.1:9100",
 * });
 * const result = await adapter.runScenario(scenario);
 * ```
 */
export class OpenAIAgentsAdapter extends BaseAdapter {
  private readonly client: SandboxClient;

  constructor(config: OpenAIAgentsAdapterConfig) {
    super(config);
    this.client = new SandboxClient(config.sandboxUrl, {
      timeoutMs: config.timeoutMs ?? 30_000,
    });
  }

  get name(): string {
    return "openai-agents";
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
