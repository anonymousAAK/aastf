/**
 * Tests for the native TypeScript sandbox server (sandbox-server.ts).
 */

import { describe, it, expect, afterEach } from "vitest";
import { SandboxServer } from "../src/sandbox-server.js";
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

  get name(): string {
    return "mock";
  }

  async runScenario(scenario: AttackScenario): Promise<TestResult> {
    return {
      resultId: `${scenario.id}-mock`,
      scenarioId: scenario.id,
      scenarioName: scenario.name,
      category: scenario.category,
      severity: scenario.severity,
      verdict: this.verdict,
      trace: makeTrace({ rawOutput: "mock output" }),
      executionTimeMs: 5,
    };
  }
}

/** Helper to make HTTP requests to the server. */
async function request(
  port: number,
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<{ status: number; data: Record<string, unknown> }> {
  const method = options.method ?? "GET";
  const url = `http://127.0.0.1:${port}${path}`;
  const init: RequestInit = { method };
  if (options.body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(url, init);
  const data = (await response.json()) as Record<string, unknown>;
  return { status: response.status, data };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

let server: SandboxServer | null = null;

afterEach(async () => {
  if (server) {
    await server.stop();
    server = null;
  }
});

describe("SandboxServer", () => {
  it("starts and stops without error", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address();
    expect(addr).not.toBeNull();
    expect(addr!.port).toBeGreaterThan(0);
    await server.stop();
    server = null;
  });

  it("GET /health returns healthy status", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/health");
    expect(status).toBe(200);
    expect(data.status).toBe("healthy");
    expect(data.version).toBe("1.0.0");
  });

  it("GET /health reports scenario count", async () => {
    const scenarios = [makeScenario(), makeScenario({ id: "ASI01-002" })];
    server = new SandboxServer({ port: 0, scenarios });
    await server.start();
    const addr = server.address()!;

    const { data } = await request(addr.port, "/health");
    expect(data.scenarios).toBe(2);
  });

  it("GET /health reports adapter configured status", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    server = new SandboxServer({ port: 0, adapter });
    await server.start();
    const addr = server.address()!;

    const { data } = await request(addr.port, "/health");
    expect(data.adapterConfigured).toBe(true);
  });

  it("GET /scenarios returns loaded scenarios", async () => {
    const scenarios = [
      makeScenario({ id: "ASI01-001", name: "Scenario A" }),
      makeScenario({ id: "ASI02-001", name: "Scenario B", category: ASICategory.ASI02 }),
    ];
    server = new SandboxServer({ port: 0, scenarios });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/scenarios");
    expect(status).toBe(200);
    expect(data.count).toBe(2);
    const items = data.scenarios as Array<Record<string, unknown>>;
    expect(items[0].id).toBe("ASI01-001");
    expect(items[1].id).toBe("ASI02-001");
  });

  it("GET /scenarios returns empty list when no scenarios loaded", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address()!;

    const { data } = await request(addr.port, "/scenarios");
    expect(data.count).toBe(0);
    expect(data.scenarios).toEqual([]);
  });

  it("POST /scan returns 400 when no adapter configured", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/scan", { method: "POST" });
    expect(status).toBe(400);
    expect(data.error).toContain("No adapter configured");
  });

  it("POST /scan returns 400 when no scenarios available", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    server = new SandboxServer({ port: 0, adapter });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/scan", { method: "POST" });
    expect(status).toBe(400);
    expect(data.error).toContain("No scenarios");
  });

  it("POST /scan runs scenarios and returns SARIF", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const scenarios = [makeScenario()];
    server = new SandboxServer({ port: 0, adapter, scenarios });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/scan", {
      method: "POST",
      body: {},
    });
    expect(status).toBe(200);
    expect(data.summary).toBeDefined();
    const summary = data.summary as Record<string, unknown>;
    expect(summary.total).toBe(1);
    expect(summary.safe).toBe(1);
    expect(data.sarif).toBeDefined();
    const sarif = data.sarif as Record<string, unknown>;
    expect(sarif.version).toBe("2.1.0");
  });

  it("POST /scan filters by scenarioIds", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    const scenarios = [
      makeScenario({ id: "ASI01-001" }),
      makeScenario({ id: "ASI01-002" }),
      makeScenario({ id: "ASI02-001" }),
    ];
    server = new SandboxServer({ port: 0, adapter, scenarios });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/scan", {
      method: "POST",
      body: { scenarioIds: ["ASI01-002"] },
    });
    expect(status).toBe(200);
    const summary = data.summary as Record<string, unknown>;
    expect(summary.total).toBe(1);
  });

  it("returns 404 for unknown routes", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address()!;

    const { status, data } = await request(addr.port, "/nonexistent");
    expect(status).toBe(404);
    expect(data.error).toContain("Not found");
  });

  it("returns 405 for wrong HTTP methods", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address()!;

    const { status } = await request(addr.port, "/health", { method: "POST" });
    expect(status).toBe(405);
  });

  it("returns 400 for invalid JSON body on /scan", async () => {
    const adapter = new MockAdapter({
      agentModule: "./agent.ts",
      sandboxUrl: "http://127.0.0.1:9100",
    });
    server = new SandboxServer({ port: 0, adapter, scenarios: [makeScenario()] });
    await server.start();
    const addr = server.address()!;

    const url = `http://127.0.0.1:${addr.port}/scan`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not valid json{{{",
    });
    const data = (await response.json()) as Record<string, unknown>;
    expect(response.status).toBe(400);
    expect(data.error).toContain("Invalid JSON");
  });

  it("getScenarios returns loaded scenarios", () => {
    const scenarios = [makeScenario()];
    const srv = new SandboxServer({ scenarios });
    expect(srv.getScenarios()).toHaveLength(1);
    expect(srv.getScenarios()[0].id).toBe("ASI01-001");
  });

  it("address returns null when server not started", () => {
    const srv = new SandboxServer();
    expect(srv.address()).toBeNull();
  });

  it("handles CORS preflight (OPTIONS)", async () => {
    server = new SandboxServer({ port: 0 });
    await server.start();
    const addr = server.address()!;

    const url = `http://127.0.0.1:${addr.port}/health`;
    const response = await fetch(url, { method: "OPTIONS" });
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });
});
