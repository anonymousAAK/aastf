#!/usr/bin/env node

/**
 * AASTF Standalone CLI — runs security scans without requiring the Python backend.
 *
 * Parses scenario YAML/JSON files natively, runs them against a configured adapter,
 * and outputs SARIF reports.
 *
 * Usage:
 *   aastf-standalone scan     --adapter <name> --module <path> --scenarios <dir|file> [--output <path>] [--format sarif|json|console]
 *   aastf-standalone list-scenarios --scenarios <dir>
 *   aastf-standalone version
 */

import { readFileSync, readdirSync, writeFileSync, statSync, existsSync } from "node:fs";
import { join, extname, resolve } from "node:path";
import { loadScenario, ScenarioLoadError } from "./scenario-loader.js";
import { formatConsole, formatJSON, formatSARIF } from "./reporter.js";
import { OpenAIAgentsAdapter } from "./adapters/openai-agents.js";
import { LangChainAdapter } from "./adapters/langchainjs.js";
import { MastraAdapter } from "./adapters/mastra.js";
import { VercelAIAdapter } from "./adapters/vercel-ai.js";
import type { BaseAdapter } from "./adapters/base.js";
import type { AttackScenario, ScanReport, TestResult, VulnerabilityFinding } from "./types.js";
import { Verdict, SEVERITY_NUMERIC } from "./types.js";

const VERSION = "0.1.0-beta.1";

// ---------------------------------------------------------------------------
// Minimal argument parser (no external deps)
// ---------------------------------------------------------------------------

interface ParsedArgs {
  command: string;
  flags: Record<string, string>;
}

function parseArgs(argv: string[]): ParsedArgs {
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

// ---------------------------------------------------------------------------
// YAML parser (minimal, handles AASTF scenario subset)
// ---------------------------------------------------------------------------

/**
 * Minimal YAML parser that handles the subset used by AASTF scenario files.
 * Supports: scalars, quoted strings, lists (block and flow), nested maps.
 * Does NOT handle anchors, tags, multi-doc, or complex YAML features.
 */
function parseSimpleYAML(content: string): Record<string, unknown> {
  const lines = content.split("\n");
  const result: Record<string, unknown> = {};
  const stack: Array<{ indent: number; obj: Record<string, unknown> }> = [
    { indent: -1, obj: result },
  ];
  let currentKey = "";
  let currentIndent = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimEnd();

    // Skip empty lines and comments
    if (trimmed === "" || trimmed.trimStart().startsWith("#")) continue;

    const indent = line.length - line.trimStart().length;

    // Pop stack to find parent at correct indentation
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
      stack.pop();
    }
    const parent = stack[stack.length - 1].obj;

    const content_ = trimmed.trimStart();

    // List item
    if (content_.startsWith("- ")) {
      const value = content_.slice(2).trim();
      if (Array.isArray(parent[currentKey])) {
        (parent[currentKey] as unknown[]).push(parseScalar(value));
      }
      continue;
    }

    // Key-value pair
    const colonIdx = content_.indexOf(":");
    if (colonIdx > 0) {
      const key = content_.slice(0, colonIdx).trim();
      const rawValue = content_.slice(colonIdx + 1).trim();

      currentKey = key;
      currentIndent = indent;

      if (rawValue === "") {
        // Check if next non-empty line is a list or nested map
        const nextLine = peekNextNonEmpty(lines, i + 1);
        if (nextLine !== null && nextLine.trimStart().startsWith("- ")) {
          parent[key] = [];
        } else if (nextLine !== null) {
          const nextIndent =
            nextLine.length - nextLine.trimStart().length;
          if (nextIndent > indent) {
            const nested: Record<string, unknown> = {};
            parent[key] = nested;
            stack.push({ indent, obj: nested });
          } else {
            parent[key] = "";
          }
        } else {
          parent[key] = "";
        }
      } else if (rawValue.startsWith("[") && rawValue.endsWith("]")) {
        // Flow sequence
        const inner = rawValue.slice(1, -1).trim();
        parent[key] = inner === ""
          ? []
          : inner.split(",").map((s) => parseScalar(s.trim()));
      } else {
        parent[key] = parseScalar(rawValue);
      }
    }
  }

  return result;
}

function peekNextNonEmpty(lines: string[], start: number): string | null {
  for (let i = start; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed !== "" && !trimmed.startsWith("#")) return lines[i];
  }
  return null;
}

function parseScalar(value: string): string | number | boolean {
  // Remove quotes
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  // Multiline indicator — return as-is for now
  if (value === "|" || value === ">") return "";
  // Booleans
  if (value === "true" || value === "True") return true;
  if (value === "false" || value === "False") return false;
  // Numbers
  const num = Number(value);
  if (!isNaN(num) && value !== "") return num;
  return value;
}

// ---------------------------------------------------------------------------
// Scenario loading
// ---------------------------------------------------------------------------

function loadScenarioFromYAML(filePath: string): AttackScenario {
  const content = readFileSync(filePath, "utf-8");
  const ext = extname(filePath).toLowerCase();

  let raw: Record<string, unknown>;
  if (ext === ".json") {
    raw = JSON.parse(content) as Record<string, unknown>;
  } else if (ext === ".yaml" || ext === ".yml") {
    raw = parseSimpleYAML(content);
  } else {
    throw new ScenarioLoadError(
      `Unsupported file extension: ${ext}. Use .yaml, .yml, or .json`,
    );
  }

  return loadScenario(raw);
}

function discoverScenarioFiles(scenariosPath: string): string[] {
  const resolved = resolve(scenariosPath);

  if (!existsSync(resolved)) {
    console.error(`Error: path does not exist: ${resolved}`);
    process.exit(1);
  }

  const stat = statSync(resolved);
  if (stat.isFile()) {
    return [resolved];
  }

  const files: string[] = [];
  collectFiles(resolved, files);
  return files.sort();
}

function collectFiles(dir: string, result: string[]): void {
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      collectFiles(fullPath, result);
    } else {
      const ext = extname(entry.name).toLowerCase();
      if (ext === ".yaml" || ext === ".yml" || ext === ".json") {
        result.push(fullPath);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Adapter factory
// ---------------------------------------------------------------------------

const ADAPTER_NAMES = ["openai-agents", "langchainjs", "mastra", "vercel-ai"];

function createAdapter(
  adapterName: string,
  agentModule: string,
  sandboxUrl: string,
): BaseAdapter {
  const config = { agentModule, sandboxUrl };
  switch (adapterName) {
    case "openai-agents":
      return new OpenAIAgentsAdapter(config);
    case "langchainjs":
      return new LangChainAdapter(config);
    case "mastra":
      return new MastraAdapter(config);
    case "vercel-ai":
      return new VercelAIAdapter(config);
    default:
      console.error(
        `Error: unknown adapter "${adapterName}". Valid: ${ADAPTER_NAMES.join(", ")}`,
      );
      process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// Report builder
// ---------------------------------------------------------------------------

function buildReport(
  adapter: BaseAdapter,
  results: TestResult[],
): ScanReport {
  const findings: VulnerabilityFinding[] = results
    .filter((r) => r.finding !== undefined)
    .map((r) => r.finding!);

  const vulnerable = results.filter((r) => r.verdict === Verdict.VULNERABLE).length;
  const refusalEcho = results.filter((r) => r.verdict === Verdict.REFUSAL_ECHO).length;
  const safe = results.filter((r) => r.verdict === Verdict.SAFE).length;
  const inconclusive = results.filter((r) => r.verdict === Verdict.INCONCLUSIVE).length;
  const errors = results.filter((r) => r.verdict === Verdict.ERROR).length;

  // Risk score: percentage of non-safe outcomes weighted by severity
  const total = results.length || 1;
  const overallRiskScore = Math.round(
    ((vulnerable * 10 + refusalEcho * 5) / (total * 10)) * 100,
  );

  // EU AI Act readiness
  let euAiActReadiness: "compliant" | "at_risk" | "non_compliant";
  if (vulnerable === 0 && refusalEcho === 0) {
    euAiActReadiness = "compliant";
  } else if (vulnerable <= total * 0.1) {
    euAiActReadiness = "at_risk";
  } else {
    euAiActReadiness = "non_compliant";
  }

  // ASI category summary
  const asiSummary: Record<string, Record<string, number>> = {};
  for (const r of results) {
    const cat = r.category;
    if (!asiSummary[cat]) asiSummary[cat] = {};
    asiSummary[cat][r.verdict] = (asiSummary[cat][r.verdict] ?? 0) + 1;
  }

  return {
    runId: `standalone-${Date.now()}`,
    generatedAt: new Date().toISOString(),
    aastfVersion: VERSION,
    adapter: adapter.name,
    totalScenarios: results.length,
    vulnerable,
    refusalEchoCount: refusalEcho,
    safe,
    inconclusive,
    errors,
    overallRiskScore,
    euAiActReadiness,
    results,
    findings,
    asiSummary,
  };
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdScan(flags: Record<string, string>): Promise<void> {
  const adapterName = flags["adapter"];
  const agentModule = flags["module"];
  const sandboxUrl = flags["sandbox-url"] ?? "http://127.0.0.1:9100";
  const scenariosPath = flags["scenarios"];
  const output = flags["output"];
  const format = flags["format"] ?? "console";

  if (!adapterName) {
    console.error(`Error: --adapter is required (${ADAPTER_NAMES.join(", ")})`);
    process.exit(1);
  }
  if (!agentModule) {
    console.error("Error: --module is required (path to agent module)");
    process.exit(1);
  }
  if (!scenariosPath) {
    console.error("Error: --scenarios is required (path to scenario dir or file)");
    process.exit(1);
  }

  const validFormats = ["sarif", "json", "console"];
  if (!validFormats.includes(format)) {
    console.error(
      `Error: unknown format "${format}". Valid: ${validFormats.join(", ")}`,
    );
    process.exit(1);
  }

  const adapter = createAdapter(adapterName, agentModule, sandboxUrl);
  const scenarioFiles = discoverScenarioFiles(scenariosPath);

  console.log("AASTF Standalone Scan");
  console.log(`  Adapter:    ${adapter.name}`);
  console.log(`  Module:     ${agentModule}`);
  console.log(`  Sandbox:    ${sandboxUrl}`);
  console.log(`  Scenarios:  ${scenarioFiles.length} file(s)`);
  console.log(`  Format:     ${format}`);
  console.log();

  // Load scenarios
  const scenarios: AttackScenario[] = [];
  for (const file of scenarioFiles) {
    try {
      const scenario = loadScenarioFromYAML(file);
      scenarios.push(scenario);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error(`  SKIP ${file}: ${msg}`);
    }
  }

  if (scenarios.length === 0) {
    console.error("Error: no valid scenarios found.");
    process.exit(1);
  }

  console.log(`Loaded ${scenarios.length} scenario(s). Running scan...`);
  console.log();

  // Run scenarios
  const results: TestResult[] = [];
  for (const scenario of scenarios) {
    process.stdout.write(`  ${scenario.id} ${scenario.name} ... `);
    try {
      const result = await adapter.runScenario(scenario);
      results.push(result);
      console.log(result.verdict);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.log(`ERROR: ${msg}`);
      results.push({
        resultId: `${scenario.id}-${Date.now()}`,
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        category: scenario.category,
        severity: scenario.severity,
        verdict: Verdict.ERROR,
        trace: { messages: [], toolInvocations: [], rawOutput: msg },
        executionTimeMs: 0,
      });
    }
  }

  console.log();

  // Build report
  const report = buildReport(adapter, results);

  // Output
  let outputStr: string;
  switch (format) {
    case "sarif":
      outputStr = JSON.stringify(formatSARIF(report), null, 2);
      break;
    case "json":
      outputStr = formatJSON(report);
      break;
    case "console":
    default:
      outputStr = formatConsole(report);
      break;
  }

  if (output) {
    writeFileSync(output, outputStr, "utf-8");
    console.log(`Report written to ${output}`);
  } else {
    console.log(outputStr);
  }

  // Exit with non-zero if vulnerabilities found
  if (report.vulnerable > 0) {
    process.exit(1);
  }
}

function cmdListScenarios(flags: Record<string, string>): void {
  const scenariosPath = flags["scenarios"];
  if (!scenariosPath) {
    console.error("Error: --scenarios is required (path to scenario dir or file)");
    process.exit(1);
  }

  const scenarioFiles = discoverScenarioFiles(scenariosPath);
  console.log(`Found ${scenarioFiles.length} scenario file(s):\n`);

  let loaded = 0;
  let failed = 0;

  for (const file of scenarioFiles) {
    try {
      const scenario = loadScenarioFromYAML(file);
      console.log(
        `  ${scenario.id}  [${scenario.severity}]  ${scenario.category}  ${scenario.name}`,
      );
      loaded++;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.log(`  SKIP  ${file}: ${msg}`);
      failed++;
    }
  }

  console.log();
  console.log(`Loaded: ${loaded}  Skipped: ${failed}`);
}

function cmdVersion(): void {
  console.log(`@aastf/core v${VERSION} (standalone CLI)`);
}

function printUsage(): void {
  console.log(`
AASTF Standalone CLI v${VERSION}

Usage:
  aastf-standalone scan             --adapter <name> --module <path> --scenarios <dir|file> [--sandbox-url <url>] [--output <path>] [--format <fmt>]
  aastf-standalone list-scenarios   --scenarios <dir|file>
  aastf-standalone version

Commands:
  scan              Run AASTF security scenarios against an agent
  list-scenarios    List available scenarios from a directory
  version           Print version and exit

Options:
  --adapter         Agent framework adapter (openai-agents, langchainjs, mastra, vercel-ai)
  --module          Path to the agent module under test
  --scenarios       Path to scenario directory or single scenario file
  --sandbox-url     Sandbox server URL (default: http://127.0.0.1:9100)
  --format          Output format: console, json, sarif (default: console)
  --output          Write output to file instead of stdout
  --help            Show this help message
`.trim());
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv);

  if (flags["help"] || command === "help" || command === "") {
    printUsage();
    process.exit(0);
  }

  switch (command) {
    case "scan":
      await cmdScan(flags);
      break;
    case "list-scenarios":
      cmdListScenarios(flags);
      break;
    case "version":
      cmdVersion();
      break;
    default:
      console.error(`Unknown command: "${command}"`);
      printUsage();
      process.exit(1);
  }
}

main().catch((error: unknown) => {
  console.error(
    "Fatal error:",
    error instanceof Error ? error.message : String(error),
  );
  process.exit(1);
});
