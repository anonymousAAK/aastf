#!/usr/bin/env node

/**
 * Native TypeScript sandbox server for @aastf/core.
 *
 * HTTP server using Node built-in `http` module — zero external dependencies.
 * Provides routes: POST /scan, GET /health, GET /scenarios.
 * Loads scenario YAML files, runs them against a provided adapter,
 * and returns results in SARIF format.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { formatSARIF } from "./reporter.js";
import {
  ScenarioRunner,
  discoverScenarioFiles,
  loadScenarioFromFile,
} from "./scenario-runner.js";
import type { BaseAdapter } from "./adapters/base.js";
import type { AttackScenario, ScanReport, SARIFLog } from "./types.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Configuration for the SandboxServer. */
export interface SandboxServerConfig {
  /** Host to bind to. Default: "127.0.0.1". */
  host?: string;
  /** Port to listen on. Default: 9200. */
  port?: number;
  /** Path to scenario directory or file. */
  scenariosPath?: string;
  /** Pre-loaded scenarios (alternative to scenariosPath). */
  scenarios?: AttackScenario[];
  /** Adapter to run scenarios against. Required for /scan. */
  adapter?: BaseAdapter;
  /** Timeout per scenario in milliseconds. Default: 30_000. */
  timeoutMs?: number;
}

/** Scan request body for POST /scan. */
export interface ScanRequest {
  /** Override scenario IDs to run (optional, runs all if omitted). */
  scenarioIds?: string[];
  /** Override scenarios path (optional, uses server default). */
  scenariosPath?: string;
}

/** Scan response body returned by POST /scan. */
export interface ScanResponse {
  /** SARIF log with scan results. */
  sarif: SARIFLog;
  /** Summary statistics. */
  summary: {
    total: number;
    vulnerable: number;
    safe: number;
    errors: number;
    riskScore: number;
  };
}

/**
 * Native TypeScript sandbox server.
 *
 * Runs as a standalone HTTP server, providing endpoints for health checks,
 * scenario listing, and full scan execution with SARIF output.
 *
 * @example
 * ```ts
 * const server = new SandboxServer({ adapter, scenariosPath: "./scenarios" });
 * await server.start();
 * // POST http://127.0.0.1:9200/scan
 * // GET  http://127.0.0.1:9200/health
 * // GET  http://127.0.0.1:9200/scenarios
 * ```
 */
export class SandboxServer {
  private readonly config: Required<
    Pick<SandboxServerConfig, "host" | "port" | "timeoutMs">
  > & SandboxServerConfig;
  private server: Server | null = null;
  private loadedScenarios: AttackScenario[] = [];

  constructor(config: SandboxServerConfig = {}) {
    this.config = {
      ...config,
      host: config.host ?? "127.0.0.1",
      port: config.port ?? 9200,
      timeoutMs: config.timeoutMs ?? 30_000,
    };

    // Pre-load scenarios if path or scenarios provided
    if (config.scenarios) {
      this.loadedScenarios = config.scenarios;
    } else if (config.scenariosPath) {
      this.loadedScenarios = this.loadScenariosFromPath(config.scenariosPath);
    }
  }

  /**
   * Start the HTTP server. Returns a promise that resolves when listening.
   */
  async start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch((err) => {
          this.sendError(res, 500, `Internal server error: ${err}`);
        });
      });

      this.server.on("error", reject);

      this.server.listen(this.config.port, this.config.host, () => {
        resolve();
      });
    });
  }

  /**
   * Stop the HTTP server gracefully.
   */
  async stop(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close((err) => {
        this.server = null;
        if (err) reject(err);
        else resolve();
      });
    });
  }

  /**
   * Get the address the server is listening on, or null if not started.
   */
  address(): { host: string; port: number } | null {
    if (!this.server) return null;
    const addr = this.server.address();
    if (!addr || typeof addr === "string") return null;
    return { host: this.config.host, port: addr.port };
  }

  /**
   * Get the currently loaded scenarios.
   */
  getScenarios(): AttackScenario[] {
    return this.loadedScenarios;
  }

  /**
   * Reload scenarios from a path.
   */
  reloadScenarios(scenariosPath: string): void {
    this.loadedScenarios = this.loadScenariosFromPath(scenariosPath);
  }

  // ---------------------------------------------------------------------------
  // Request routing
  // ---------------------------------------------------------------------------

  private async handleRequest(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    const method = req.method?.toUpperCase() ?? "GET";
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const path = url.pathname;

    // CORS headers for development
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    switch (path) {
      case "/health":
        if (method === "GET") {
          this.handleHealth(res);
        } else {
          this.sendError(res, 405, "Method not allowed");
        }
        break;

      case "/scenarios":
        if (method === "GET") {
          this.handleListScenarios(res);
        } else {
          this.sendError(res, 405, "Method not allowed");
        }
        break;

      case "/scan":
        if (method === "POST") {
          await this.handleScan(req, res);
        } else {
          this.sendError(res, 405, "Method not allowed");
        }
        break;

      default:
        this.sendError(res, 404, `Not found: ${path}`);
        break;
    }
  }

  // ---------------------------------------------------------------------------
  // Route handlers
  // ---------------------------------------------------------------------------

  private handleHealth(res: ServerResponse): void {
    this.sendJSON(res, 200, {
      status: "healthy",
      version: "1.0.0",
      scenarios: this.loadedScenarios.length,
      adapterConfigured: this.config.adapter !== undefined,
    });
  }

  private handleListScenarios(res: ServerResponse): void {
    const summaries = this.loadedScenarios.map((s) => ({
      id: s.id,
      name: s.name,
      category: s.category,
      severity: s.severity,
      description: s.description,
      tags: s.tags,
    }));

    this.sendJSON(res, 200, {
      count: summaries.length,
      scenarios: summaries,
    });
  }

  private async handleScan(
    req: IncomingMessage,
    res: ServerResponse,
  ): Promise<void> {
    // Validate adapter is configured
    if (!this.config.adapter) {
      this.sendError(res, 400, "No adapter configured. Provide an adapter in SandboxServerConfig.");
      return;
    }

    // Parse request body
    let body: ScanRequest = {};
    try {
      const rawBody = await readBody(req);
      if (rawBody.length > 0) {
        body = JSON.parse(rawBody) as ScanRequest;
      }
    } catch {
      this.sendError(res, 400, "Invalid JSON in request body");
      return;
    }

    // Determine scenarios to run
    let scenarios: AttackScenario[];
    if (body.scenariosPath) {
      scenarios = this.loadScenariosFromPath(body.scenariosPath);
    } else {
      scenarios = this.loadedScenarios;
    }

    // Filter by scenario IDs if provided
    if (body.scenarioIds && body.scenarioIds.length > 0) {
      const idSet = new Set(body.scenarioIds);
      scenarios = scenarios.filter((s) => idSet.has(s.id));
    }

    if (scenarios.length === 0) {
      this.sendError(res, 400, "No scenarios to run. Load scenarios or provide scenarioIds.");
      return;
    }

    // Run the scan
    const runner = new ScenarioRunner(this.config.adapter, {
      timeoutMs: this.config.timeoutMs,
    });

    const report = await runner.runScenarios(scenarios);
    const sarif = formatSARIF(report);

    const response: ScanResponse = {
      sarif,
      summary: {
        total: report.totalScenarios,
        vulnerable: report.vulnerable,
        safe: report.safe,
        errors: report.errors,
        riskScore: report.overallRiskScore,
      },
    };

    this.sendJSON(res, 200, response);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private loadScenariosFromPath(scenariosPath: string): AttackScenario[] {
    const files = discoverScenarioFiles(scenariosPath);
    const scenarios: AttackScenario[] = [];

    for (const file of files) {
      try {
        scenarios.push(loadScenarioFromFile(file));
      } catch {
        // Skip invalid files silently during server loading
      }
    }

    return scenarios;
  }

  private sendJSON(res: ServerResponse, status: number, data: unknown): void {
    const body = JSON.stringify(data);
    res.writeHead(status, {
      "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(body),
    });
    res.end(body);
  }

  private sendError(res: ServerResponse, status: number, message: string): void {
    this.sendJSON(res, status, { error: message });
  }
}

// ---------------------------------------------------------------------------
// Body reader utility
// ---------------------------------------------------------------------------

/**
 * Read the full body of an incoming HTTP request as a string.
 */
function readBody(req: IncomingMessage): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------------------
// CLI entry point (when run as aastf-server)
// ---------------------------------------------------------------------------

/**
 * Start the server from CLI arguments.
 * Usage: aastf-server [--port 9200] [--host 127.0.0.1] [--scenarios <dir>]
 */
export async function startFromCLI(argv: string[]): Promise<void> {
  const args = argv.slice(2);
  const flags: Record<string, string> = {};

  for (let i = 0; i < args.length; i++) {
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

  if (flags["help"]) {
    console.log(`
AASTF Sandbox Server v1.0.0

Usage:
  aastf-server [options]

Options:
  --port <number>       Port to listen on (default: 9200)
  --host <string>       Host to bind to (default: 127.0.0.1)
  --scenarios <path>    Path to scenario directory or file
  --help                Show this help message

Routes:
  GET  /health          Health check
  GET  /scenarios       List loaded scenarios
  POST /scan            Run scan (requires adapter via SDK)
`.trim());
    return;
  }

  const port = flags["port"] ? parseInt(flags["port"], 10) : 9200;
  const host = flags["host"] ?? "127.0.0.1";
  const scenariosPath = flags["scenarios"];

  const server = new SandboxServer({
    host,
    port,
    scenariosPath,
  });

  await server.start();
  const addr = server.address();
  console.log(`AASTF Sandbox Server listening on http://${addr?.host}:${addr?.port}`);
  console.log(`  Scenarios loaded: ${server.getScenarios().length}`);
  console.log("  Press Ctrl+C to stop.");

  // Graceful shutdown
  const shutdown = async () => {
    console.log("\nShutting down...");
    await server.stop();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// Run if executed directly
const isDirectRun =
  typeof process !== "undefined" &&
  process.argv[1] &&
  (process.argv[1].endsWith("sandbox-server.js") ||
   process.argv[1].endsWith("sandbox-server.ts"));

if (isDirectRun) {
  startFromCLI(process.argv).catch((err: unknown) => {
    console.error(
      "Fatal error:",
      err instanceof Error ? err.message : String(err),
    );
    process.exit(1);
  });
}
