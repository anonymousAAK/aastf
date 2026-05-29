/**
 * Tests for the native scenario execution engine (scenario-runner.ts).
 */

import { describe, it, expect, vi } from "vitest";
import {
  ScenarioRunner,
  ScenarioRunError,
  evaluateVerdict,
  buildFinding,
  buildScanReport,
  parseSimpleYAML,
  withTimeout,
  discoverScenarioFiles,
} from "../src/scenario-runner.js";
import { BaseAdapter } from "../src/adapters/base.js";
import type { AttackScenario, TestResult, AgentTrace } from "../src/types.js";
import { Verdict, ASICategory, Severity, InjectionPoint } from "../src/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

function makeTrace(overrides: Partial<AgentTrace> = {}): AgentTrace {
  return {
    messages: [],
    toolInvocations: [],
    rawOutput: "",
    ...overrides,
  };
}

class MockAdapter extends BaseAdapter {
  public verdict: Verdict = Verdict.SAFE;
  public shouldThrow = false;
  public delayMs = 0;
  public callCount = 0;

  get name(): string {
    return "mock";
  }

  async runScenario(scenario: AttackScenario): Promise<TestResult> {
    this.callCount++;
    if (this.shouldThrow) {
      throw new Error("adapter error");
    }
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    return {
      resultId: `${scenario.id}-mock`,
      scenarioId: scenario.id,
      scenarioName: scenario.name,
      category: scenario.category,
      severity: scenario.severity,
      verdict: this.verdict,
      trace: makeTrace({ rawOutput: "test output" }),
      executionTimeMs: 10,
    };
  }
}

// ---------------------------------------------------------------------------
// evaluateVerdict
// ---------------------------------------------------------------------------

describe("evaluateVerdict", () => {
  it("returns SAFE when no detection criteria are triggered", () => {
    const scenario = makeScenario();
    const trace = makeTrace();
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.SAFE);
    expect(result.triggeredBy).toBe("");
  });

  it("returns VULNERABLE when tool_called matches", () => {
    const scenario = makeScenario({
      detection: {
        toolCalled: ["send_email"],
        toolNotCalled: [],
        toolInputContains: {},
        outputContains: [],
        outputNotContains: [],
      },
    });
    const trace = makeTrace({
      toolInvocations: [
        { toolName: "send_email", input: {}, output: {}, timestampMs: 0, durationMs: 0 },
      ],
    });
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.VULNERABLE);
    expect(result.triggeredBy).toContain("tool_called:send_email");
  });

  it("returns VULNERABLE when tool_input_contains matches", () => {
    const scenario = makeScenario({
      detection: {
        toolCalled: [],
        toolNotCalled: [],
        toolInputContains: { exec: "rm -rf" },
        outputContains: [],
        outputNotContains: [],
      },
    });
    const trace = makeTrace({
      toolInvocations: [
        { toolName: "exec", input: "rm -rf /", output: "", timestampMs: 0, durationMs: 0 },
      ],
    });
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.VULNERABLE);
    expect(result.triggeredBy).toContain("tool_input_contains");
  });

  it("returns VULNERABLE when output_contains matches", () => {
    const scenario = makeScenario({
      detection: {
        toolCalled: [],
        toolNotCalled: [],
        toolInputContains: {},
        outputContains: ["secret_key"],
        outputNotContains: [],
      },
    });
    const trace = makeTrace({ rawOutput: "Here is the secret_key: abc123" });
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.VULNERABLE);
    expect(result.triggeredBy).toContain("output_contains:secret_key");
  });

  it("returns REFUSAL_ECHO when output_not_contains is violated", () => {
    const scenario = makeScenario({
      detection: {
        toolCalled: [],
        toolNotCalled: [],
        toolInputContains: {},
        outputContains: [],
        outputNotContains: ["password"],
      },
    });
    const trace = makeTrace({ rawOutput: "I cannot do that, but the password is xyz" });
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.REFUSAL_ECHO);
    expect(result.triggeredBy).toContain("output_not_contains_violated");
  });

  it("returns VULNERABLE when tool_call_count_exceeds is triggered", () => {
    const scenario = makeScenario({
      detection: {
        toolCalled: [],
        toolNotCalled: [],
        toolInputContains: {},
        outputContains: [],
        outputNotContains: [],
        toolCallCountExceeds: 2,
      },
    });
    const trace = makeTrace({
      toolInvocations: [
        { toolName: "fetch", input: {}, output: {}, timestampMs: 0, durationMs: 0 },
        { toolName: "fetch", input: {}, output: {}, timestampMs: 1, durationMs: 0 },
        { toolName: "fetch", input: {}, output: {}, timestampMs: 2, durationMs: 0 },
      ],
    });
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.VULNERABLE);
    expect(result.triggeredBy).toContain("tool_call_count_exceeds");
  });

  it("returns VULNERABLE when loop_iterations_exceed is triggered", () => {
    const scenario = makeScenario({
      detection: {
        toolCalled: [],
        toolNotCalled: [],
        toolInputContains: {},
        outputContains: [],
        outputNotContains: [],
        loopIterationsExceed: 1,
      },
    });
    const trace = makeTrace({
      messages: [
        { role: "assistant", content: "step 1" },
        { role: "assistant", content: "step 2" },
      ],
    });
    const result = evaluateVerdict(scenario, trace);
    expect(result.verdict).toBe(Verdict.VULNERABLE);
    expect(result.triggeredBy).toContain("loop_iterations_exceed");
  });
});

// ---------------------------------------------------------------------------
// buildFinding
// ---------------------------------------------------------------------------

describe("buildFinding", () => {
  it("creates a VulnerabilityFinding from scenario and trace", () => {
    const scenario = makeScenario({ id: "ASI02-003", name: "Tool Exploit" });
    const trace = makeTrace({ rawOutput: "compromised output" });
    const finding = buildFinding(scenario, trace, "tool_called:exec");

    expect(finding.scenarioId).toBe("ASI02-003");
    expect(finding.scenarioName).toBe("Tool Exploit");
    expect(finding.verdict).toBe(Verdict.VULNERABLE);
    expect(finding.triggeredBy).toBe("tool_called:exec");
    expect(finding.description).toBe(scenario.description);
    expect(finding.remediation).toBe(scenario.remediation);
  });
});

// ---------------------------------------------------------------------------
// buildScanReport
// ---------------------------------------------------------------------------

describe("buildScanReport", () => {
  it("computes summary statistics correctly", () => {
    const results: TestResult[] = [
      {
        resultId: "r1", scenarioId: "ASI01-001", scenarioName: "S1",
        category: ASICategory.ASI01, severity: Severity.HIGH,
        verdict: Verdict.VULNERABLE, trace: makeTrace(), executionTimeMs: 10,
      },
      {
        resultId: "r2", scenarioId: "ASI01-002", scenarioName: "S2",
        category: ASICategory.ASI01, severity: Severity.MEDIUM,
        verdict: Verdict.SAFE, trace: makeTrace(), executionTimeMs: 5,
      },
      {
        resultId: "r3", scenarioId: "ASI02-001", scenarioName: "S3",
        category: ASICategory.ASI02, severity: Severity.LOW,
        verdict: Verdict.ERROR, trace: makeTrace(), executionTimeMs: 0,
      },
    ];
    const report = buildScanReport("mock", results);

    expect(report.totalScenarios).toBe(3);
    expect(report.vulnerable).toBe(1);
    expect(report.safe).toBe(1);
    expect(report.errors).toBe(1);
    expect(report.adapter).toBe("mock");
    expect(report.aastfVersion).toBe("1.0.0");
  });

  it("marks compliant when no vulnerabilities", () => {
    const results: TestResult[] = [
      {
        resultId: "r1", scenarioId: "ASI01-001", scenarioName: "S1",
        category: ASICategory.ASI01, severity: Severity.HIGH,
        verdict: Verdict.SAFE, trace: makeTrace(), executionTimeMs: 5,
      },
    ];
    const report = buildScanReport("mock", results);
    expect(report.euAiActReadiness).toBe("compliant");
  });

  it("builds ASI summary by category", () => {
    const results: TestResult[] = [
      {
        resultId: "r1", scenarioId: "ASI01-001", scenarioName: "S1",
        category: ASICategory.ASI01, severity: Severity.HIGH,
        verdict: Verdict.SAFE, trace: makeTrace(), executionTimeMs: 5,
      },
      {
        resultId: "r2", scenarioId: "ASI02-001", scenarioName: "S2",
        category: ASICategory.ASI02, severity: Severity.HIGH,
        verdict: Verdict.VULNERABLE, trace: makeTrace(), executionTimeMs: 5,
      },
    ];
    const report = buildScanReport("mock", results);
    expect(report.asiSummary["ASI01"]?.["SAFE"]).toBe(1);
    expect(report.asiSummary["ASI02"]?.["VULNERABLE"]).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// parseSimpleYAML
// ---------------------------------------------------------------------------

describe("parseSimpleYAML", () => {
  it("parses basic key-value pairs", () => {
    const yaml = `id: ASI01-001\nname: Test\nseverity: HIGH`;
    const result = parseSimpleYAML(yaml);
    expect(result.id).toBe("ASI01-001");
    expect(result.name).toBe("Test");
    expect(result.severity).toBe("HIGH");
  });

  it("parses block lists", () => {
    const yaml = `tags:\n  - security\n  - owasp\n  - testing`;
    const result = parseSimpleYAML(yaml);
    expect(result.tags).toEqual(["security", "owasp", "testing"]);
  });

  it("parses flow sequences", () => {
    const yaml = `tags: [alpha, beta, gamma]`;
    const result = parseSimpleYAML(yaml);
    expect(result.tags).toEqual(["alpha", "beta", "gamma"]);
  });

  it("parses booleans and numbers", () => {
    const yaml = `enabled: true\ncount: 42\nlabel: false`;
    const result = parseSimpleYAML(yaml);
    expect(result.enabled).toBe(true);
    expect(result.count).toBe(42);
    expect(result.label).toBe(false);
  });

  it("skips comments and empty lines", () => {
    const yaml = `# comment\n\nid: ASI01-001\n\n# another comment\nname: Test`;
    const result = parseSimpleYAML(yaml);
    expect(result.id).toBe("ASI01-001");
    expect(result.name).toBe("Test");
  });
});

// ---------------------------------------------------------------------------
// withTimeout
// ---------------------------------------------------------------------------

describe("withTimeout", () => {
  it("resolves when promise completes before timeout", async () => {
    const result = await withTimeout(Promise.resolve(42), 1000);
    expect(result).toBe(42);
  });

  it("rejects when promise exceeds timeout", async () => {
    const slow = new Promise((resolve) => setTimeout(resolve, 5000));
    await expect(withTimeout(slow, 10)).rejects.toThrow("timed out");
  });

  it("propagates original rejection", async () => {
    const failing = Promise.reject(new Error("boom"));
    await expect(withTimeout(failing, 1000)).rejects.toThrow("boom");
  });
});

// ---------------------------------------------------------------------------
// discoverScenarioFiles
// ---------------------------------------------------------------------------

describe("discoverScenarioFiles", () => {
  it("returns empty array for nonexistent path", () => {
    const files = discoverScenarioFiles("/nonexistent/path/abc123");
    expect(files).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// ScenarioRunner
// ---------------------------------------------------------------------------

describe("ScenarioRunner", () => {
  it("runs scenarios sequentially by default", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const runner = new ScenarioRunner(adapter);
    const scenarios = [makeScenario({ id: "ASI01-001" }), makeScenario({ id: "ASI01-002" })];
    const report = await runner.runScenarios(scenarios);

    expect(report.totalScenarios).toBe(2);
    expect(report.safe).toBe(2);
    expect(adapter.callCount).toBe(2);
  });

  it("handles adapter errors gracefully", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    adapter.shouldThrow = true;
    const runner = new ScenarioRunner(adapter);
    const report = await runner.runScenarios([makeScenario()]);

    expect(report.errors).toBe(1);
    expect(report.results[0].verdict).toBe(Verdict.ERROR);
  });

  it("calls onResult callback for each scenario", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const results: TestResult[] = [];
    const runner = new ScenarioRunner(adapter, {
      onResult: (r) => results.push(r),
    });
    await runner.runScenarios([makeScenario(), makeScenario({ id: "ASI01-002" })]);

    expect(results).toHaveLength(2);
  });

  it("runs scenarios concurrently when concurrency > 1", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const runner = new ScenarioRunner(adapter, { concurrency: 3 });
    const scenarios = [
      makeScenario({ id: "ASI01-001" }),
      makeScenario({ id: "ASI01-002" }),
      makeScenario({ id: "ASI01-003" }),
    ];
    const report = await runner.runScenarios(scenarios);

    expect(report.totalScenarios).toBe(3);
    expect(adapter.callCount).toBe(3);
  });

  it("re-evaluates INCONCLUSIVE verdicts from adapter", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    adapter.verdict = Verdict.INCONCLUSIVE;
    const runner = new ScenarioRunner(adapter);
    const scenario = makeScenario({
      detection: {
        toolCalled: [],
        toolNotCalled: [],
        toolInputContains: {},
        outputContains: ["test output"],
        outputNotContains: [],
      },
    });
    const report = await runner.runScenarios([scenario]);

    // The runner should re-evaluate and find "test output" in rawOutput
    expect(report.results[0].verdict).toBe(Verdict.VULNERABLE);
  });

  it("throws ScenarioRunError for empty scenario list via runAll", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const runner = new ScenarioRunner(adapter);
    await expect(runner.runAll("/nonexistent/path")).rejects.toThrow(ScenarioRunError);
  });
});
