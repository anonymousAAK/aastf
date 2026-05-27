/**
 * Tests for AASTF TypeScript SDK adapters and CLI argument parsing.
 */

import { describe, it, expect } from "vitest";
import { BaseAdapter } from "../src/adapters/base.js";
import type { AdapterConfig } from "../src/adapters/base.js";
import { OpenAIAgentsAdapter } from "../src/adapters/openai-agents.js";
import { LangChainAdapter } from "../src/adapters/langchainjs.js";
import type { AttackScenario, TestResult } from "../src/types.js";
import { ASICategory, Severity, InjectionPoint, Verdict } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Minimal valid scenario for testing. */
function makeScenario(overrides: Partial<AttackScenario> = {}): AttackScenario {
  return {
    id: "ASI01-001",
    name: "Test Scenario",
    category: ASICategory.ASI01,
    severity: Severity.HIGH,
    description: "A test scenario",
    attackVector: "user_message",
    preconditions: [],
    injectInto: InjectionPoint.USER_MESSAGE,
    payload: "Ignore previous instructions",
    payloadVariants: [],
    toolResponses: [],
    availableTools: [],
    mcpResources: [],
    detection: {
      toolCalled: [],
      toolNotCalled: [],
      toolInputContains: {},
      outputContains: [],
      outputNotContains: [],
    },
    expectedBehavior: "Agent should refuse",
    remediation: "Add input filtering",
    tags: ["test"],
    references: [],
    author: "test",
    version: "1.0.0",
    cweIds: [],
    nistAiRmf: [],
    ...overrides,
  };
}

/** Concrete adapter for testing the abstract BaseAdapter. */
class TestAdapter extends BaseAdapter {
  get name(): string {
    return "test";
  }

  async runScenario(scenario: AttackScenario): Promise<TestResult> {
    return {
      resultId: `${scenario.id}-test`,
      scenarioId: scenario.id,
      scenarioName: scenario.name,
      category: scenario.category,
      severity: scenario.severity,
      verdict: Verdict.SAFE,
      trace: { messages: [], toolInvocations: [], rawOutput: "" },
      executionTimeMs: 0,
    };
  }
}

// ---------------------------------------------------------------------------
// BaseAdapter interface compliance
// ---------------------------------------------------------------------------

describe("BaseAdapter", () => {
  it("can be subclassed and instantiated", () => {
    const adapter = new TestAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(adapter.name).toBe("test");
  });

  it("runScenario returns a TestResult", async () => {
    const adapter = new TestAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const result = await adapter.runScenario(makeScenario());
    expect(result.scenarioId).toBe("ASI01-001");
    expect(result.verdict).toBe(Verdict.SAFE);
  });

  it("validateConfig rejects empty agentModule", () => {
    const adapter = new TestAdapter({
      agentModule: "",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(() => adapter.validateConfig()).toThrow("agentModule is required");
  });

  it("validateConfig rejects empty sandboxUrl", () => {
    const adapter = new TestAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "",
    });
    expect(() => adapter.validateConfig()).toThrow("sandboxUrl is required");
  });

  it("validateConfig rejects invalid sandboxUrl", () => {
    const adapter = new TestAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "not-a-url",
    });
    expect(() => adapter.validateConfig()).toThrow("not a valid URL");
  });

  it("validateConfig accepts valid config", () => {
    const adapter = new TestAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(() => adapter.validateConfig()).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// OpenAI Agents adapter
// ---------------------------------------------------------------------------

describe("OpenAIAgentsAdapter", () => {
  it("instantiates with valid config", () => {
    const adapter = new OpenAIAgentsAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(adapter.name).toBe("openai-agents");
  });

  it("accepts optional model and apiKey", () => {
    const adapter = new OpenAIAgentsAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
      model: "gpt-4o",
      apiKey: "sk-test",
    });
    expect(adapter.name).toBe("openai-agents");
  });

  it("validateConfig rejects missing agentModule", () => {
    const adapter = new OpenAIAgentsAdapter({
      agentModule: "",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(() => adapter.validateConfig()).toThrow("agentModule is required");
  });

  it("validateConfig rejects invalid sandboxUrl", () => {
    const adapter = new OpenAIAgentsAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "bad",
    });
    expect(() => adapter.validateConfig()).toThrow("not a valid URL");
  });
});

// ---------------------------------------------------------------------------
// LangChain adapter
// ---------------------------------------------------------------------------

describe("LangChainAdapter", () => {
  it("instantiates with valid config", () => {
    const adapter = new LangChainAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(adapter.name).toBe("langchainjs");
  });

  it("accepts optional agentType and chainConfig", () => {
    const adapter = new LangChainAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
      agentType: "react",
      chainConfig: { temperature: 0 },
    });
    expect(adapter.name).toBe("langchainjs");
  });

  it("validateConfig rejects missing agentModule", () => {
    const adapter = new LangChainAdapter({
      agentModule: "",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    expect(() => adapter.validateConfig()).toThrow("agentModule is required");
  });

  it("validateConfig rejects invalid sandboxUrl", () => {
    const adapter = new LangChainAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "nope",
    });
    expect(() => adapter.validateConfig()).toThrow("not a valid URL");
  });
});

// ---------------------------------------------------------------------------
// CLI argument parsing (unit test the parseArgs logic)
// ---------------------------------------------------------------------------

describe("CLI argument parsing", () => {
  // Re-implement the parse logic here for unit testing since cli.ts
  // runs as a script. This validates the algorithm.
  function parseArgs(argv: string[]) {
    const args = argv.slice(2);
    const command = args[0] ?? "";
    const flags: Record<string, string> = {};

    for (let i = 1; i < args.length; i++) {
      const arg = args[i];
      if (arg.startsWith("--")) {
        const key = arg.slice(2);
        const next = args[i + 1];
        if (next !== undefined && !next.startsWith("--")) {
          flags[key] = next;
          i++;
        } else {
          flags[key] = "true";
        }
      }
    }

    return { command, flags };
  }

  it("parses scan command with all flags", () => {
    const { command, flags } = parseArgs([
      "node",
      "cli.js",
      "scan",
      "--adapter",
      "openai-agents",
      "--module",
      "./agent.ts",
      "--sandbox-url",
      "http://localhost:9100",
    ]);
    expect(command).toBe("scan");
    expect(flags["adapter"]).toBe("openai-agents");
    expect(flags["module"]).toBe("./agent.ts");
    expect(flags["sandbox-url"]).toBe("http://localhost:9100");
  });

  it("parses report command", () => {
    const { command, flags } = parseArgs([
      "node",
      "cli.js",
      "report",
      "--input",
      "results.json",
      "--format",
      "sarif",
    ]);
    expect(command).toBe("report");
    expect(flags["input"]).toBe("results.json");
    expect(flags["format"]).toBe("sarif");
  });

  it("handles boolean flags", () => {
    const { flags } = parseArgs(["node", "cli.js", "scan", "--help"]);
    expect(flags["help"]).toBe("true");
  });

  it("returns empty command for no args", () => {
    const { command } = parseArgs(["node", "cli.js"]);
    expect(command).toBe("");
  });

  it("handles --output flag", () => {
    const { flags } = parseArgs([
      "node",
      "cli.js",
      "report",
      "--input",
      "results.json",
      "--format",
      "json",
      "--output",
      "out.json",
    ]);
    expect(flags["output"]).toBe("out.json");
  });
});
