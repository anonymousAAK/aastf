#!/usr/bin/env node

/**
 * AASTF CLI wrapper for the TypeScript SDK.
 *
 * Provides `aastf scan` and `aastf report` commands that bridge
 * to the Python sandbox server via SandboxClient.
 *
 * Usage:
 *   aastf scan --adapter openai-agents --module ./agent.ts [--sandbox-url http://127.0.0.1:9100]
 *   aastf report --input results.json --format sarif|json|console
 */

import { readFileSync, writeFileSync } from "node:fs";
import { SandboxClient } from "./sandbox-client.js";
import { formatConsole, formatJSON, formatSARIF } from "./reporter.js";
import type { ScanReport } from "./types.js";

// ---------------------------------------------------------------------------
// Minimal argument parser (no external deps)
// ---------------------------------------------------------------------------

interface ParsedArgs {
  command: string;
  flags: Record<string, string>;
}

function parseArgs(argv: string[]): ParsedArgs {
  // Skip node binary and script path
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
        i++; // skip the value
      } else {
        flags[key] = "true";
      }
    }
  }

  return { command, flags };
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async function cmdScan(flags: Record<string, string>): Promise<void> {
  const adapter = flags["adapter"];
  const module_ = flags["module"];
  const sandboxUrl = flags["sandbox-url"] ?? "http://127.0.0.1:9100";
  const output = flags["output"];

  if (!adapter) {
    console.error("Error: --adapter is required (openai-agents | langchainjs)");
    process.exit(1);
  }
  if (!module_) {
    console.error("Error: --module is required (path to agent module)");
    process.exit(1);
  }

  const validAdapters = ["openai-agents", "langchainjs"];
  if (!validAdapters.includes(adapter)) {
    console.error(
      `Error: unknown adapter "${adapter}". Valid: ${validAdapters.join(", ")}`,
    );
    process.exit(1);
  }

  const client = new SandboxClient(sandboxUrl);

  console.log(`AASTF Scan`);
  console.log(`  Adapter:     ${adapter}`);
  console.log(`  Module:      ${module_}`);
  console.log(`  Sandbox URL: ${sandboxUrl}`);
  console.log();

  // Check sandbox health
  const healthy = await client.health();
  if (!healthy) {
    console.error(
      `Error: sandbox server at ${sandboxUrl} is not reachable.`,
    );
    console.error("Start the sandbox with: aastf sandbox --serve");
    process.exit(1);
  }

  console.log("Sandbox server is healthy. Starting scan...");
  console.log(
    "(Full scan orchestration requires the Python harness. " +
    "Use `aastf scan` from the Python CLI for complete runs.)",
  );

  // In a full implementation, this would load scenarios, run them through
  // the adapter, and collect results. For now, we confirm connectivity.
  if (output) {
    console.log(`Results would be written to: ${output}`);
  }
}

function cmdReport(flags: Record<string, string>): void {
  const input = flags["input"];
  const format = flags["format"] ?? "console";

  if (!input) {
    console.error("Error: --input is required (path to results JSON)");
    process.exit(1);
  }

  const validFormats = ["sarif", "json", "console"];
  if (!validFormats.includes(format)) {
    console.error(
      `Error: unknown format "${format}". Valid: ${validFormats.join(", ")}`,
    );
    process.exit(1);
  }

  let raw: string;
  try {
    raw = readFileSync(input, "utf-8");
  } catch {
    console.error(`Error: cannot read file "${input}"`);
    process.exit(1);
  }

  let report: ScanReport;
  try {
    report = JSON.parse(raw) as ScanReport;
  } catch {
    console.error(`Error: "${input}" is not valid JSON`);
    process.exit(1);
  }

  const output = flags["output"];

  switch (format) {
    case "console": {
      const text = formatConsole(report);
      console.log(text);
      break;
    }
    case "json": {
      const json = formatJSON(report);
      if (output) {
        writeFileSync(output, json, "utf-8");
        console.log(`JSON report written to ${output}`);
      } else {
        console.log(json);
      }
      break;
    }
    case "sarif": {
      const sarif = formatSARIF(report);
      const sarifStr = JSON.stringify(sarif, null, 2);
      if (output) {
        writeFileSync(output, sarifStr, "utf-8");
        console.log(`SARIF report written to ${output}`);
      } else {
        console.log(sarifStr);
      }
      break;
    }
  }
}

function printUsage(): void {
  console.log(`
AASTF — Agentic AI Security Testing Framework (TypeScript SDK)

Usage:
  aastf scan    --adapter <name> --module <path> [--sandbox-url <url>] [--output <path>]
  aastf report  --input <path> --format <sarif|json|console> [--output <path>]

Commands:
  scan      Run security scenarios against an agent via the sandbox server
  report    Format scan results into console, JSON, or SARIF output

Options:
  --adapter       Agent framework adapter (openai-agents, langchainjs)
  --module        Path to the agent module under test
  --sandbox-url   Sandbox server URL (default: http://127.0.0.1:9100)
  --input         Path to scan results JSON file
  --format        Output format: console, json, sarif (default: console)
  --output        Write output to file instead of stdout
  --help          Show this help message
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
    case "report":
      cmdReport(flags);
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
