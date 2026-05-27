/**
 * Base adapter interface and abstract class for AASTF agent adapters.
 *
 * Each adapter bridges AASTF scenarios to a specific agent framework
 * (OpenAI Agents, LangChain.js, etc.) via the sandbox server.
 */

import type { AttackScenario, TestResult } from "../types.js";

/** Configuration required by all adapters. */
export interface AdapterConfig {
  /** Path or module specifier for the agent under test. */
  agentModule: string;
  /** URL of the AASTF sandbox server (e.g., "http://127.0.0.1:9100"). */
  sandboxUrl: string;
  /** Optional timeout per scenario in milliseconds. Default: 30_000. */
  timeoutMs?: number;
}

/**
 * Abstract base class for framework-specific adapters.
 *
 * Subclasses implement `runScenario` to bridge AASTF attack scenarios
 * to the target agent framework's execution model.
 */
export abstract class BaseAdapter {
  constructor(protected config: AdapterConfig) {}

  /** Run a single attack scenario against the agent and return the result. */
  abstract runScenario(scenario: AttackScenario): Promise<TestResult>;

  /** Get the adapter name for reporting. */
  abstract get name(): string;

  /** Validate that the adapter configuration is usable. */
  validateConfig(): void {
    if (!this.config.agentModule) {
      throw new Error("AdapterConfig.agentModule is required");
    }
    if (!this.config.sandboxUrl) {
      throw new Error("AdapterConfig.sandboxUrl is required");
    }
    try {
      new URL(this.config.sandboxUrl);
    } catch {
      throw new Error(
        `AdapterConfig.sandboxUrl is not a valid URL: ${this.config.sandboxUrl}`,
      );
    }
  }
}
