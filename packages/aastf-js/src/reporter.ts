/**
 * Report formatters — console, JSON, and SARIF output for scan results.
 */

import type {
  ScanReport,
  SARIFLog,
  SARIFRun,
  SARIFRule,
  SARIFResult,
  Severity,
  VulnerabilityFinding,
} from "./types.js";
import { SEVERITY_NUMERIC } from "./types.js";

// ---------------------------------------------------------------------------
// Console formatter
// ---------------------------------------------------------------------------

/**
 * Format a scan report as a human-readable console string.
 * Suitable for printing to stdout in CI/CD pipelines.
 */
export function formatConsole(report: ScanReport): string {
  const lines: string[] = [];

  lines.push("=".repeat(60));
  lines.push(`  AASTF Scan Report  (v${report.aastfVersion})`);
  lines.push("=".repeat(60));
  lines.push("");
  lines.push(`  Run ID:       ${report.runId}`);
  lines.push(`  Adapter:      ${report.adapter}`);
  lines.push(`  Generated at: ${report.generatedAt}`);
  lines.push("");

  // Summary
  lines.push("-".repeat(40));
  lines.push("  SUMMARY");
  lines.push("-".repeat(40));
  lines.push(`  Total scenarios:  ${report.totalScenarios}`);
  lines.push(`  Vulnerable:       ${report.vulnerable}`);
  lines.push(`  Refusal echo:     ${report.refusalEchoCount}`);
  lines.push(`  Safe:             ${report.safe}`);
  lines.push(`  Inconclusive:     ${report.inconclusive}`);
  lines.push(`  Errors:           ${report.errors}`);
  lines.push("");
  lines.push(`  Risk score:       ${report.overallRiskScore.toFixed(1)} / 100`);
  lines.push(`  EU AI Act:        ${report.euAiActReadiness}`);
  lines.push("");

  // Findings
  if (report.findings.length > 0) {
    lines.push("-".repeat(40));
    lines.push("  FINDINGS");
    lines.push("-".repeat(40));

    for (const f of report.findings) {
      lines.push("");
      lines.push(`  [${f.severity}] ${f.scenarioId} - ${f.scenarioName}`);
      lines.push(`    Verdict:     ${f.verdict}`);
      lines.push(`    Triggered:   ${f.triggeredBy}`);
      if (f.cvssScore !== undefined) {
        lines.push(`    CVSS:        ${f.cvssScore.toFixed(1)}`);
      }
      lines.push(`    Description: ${f.description}`);
      lines.push(`    Remediation: ${f.remediation}`);
    }
    lines.push("");
  }

  // ASI category breakdown
  if (Object.keys(report.asiSummary).length > 0) {
    lines.push("-".repeat(40));
    lines.push("  CATEGORY BREAKDOWN");
    lines.push("-".repeat(40));
    for (const [category, counts] of Object.entries(report.asiSummary)) {
      const parts = Object.entries(counts)
        .map(([k, v]) => `${k}=${v}`)
        .join(", ");
      lines.push(`  ${category}: ${parts}`);
    }
    lines.push("");
  }

  lines.push("=".repeat(60));
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// JSON formatter
// ---------------------------------------------------------------------------

/**
 * Format a scan report as a pretty-printed JSON string.
 */
export function formatJSON(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

// ---------------------------------------------------------------------------
// SARIF formatter
// ---------------------------------------------------------------------------

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

/** Map AASTF severity to SARIF level. */
function sarifLevel(
  severity: Severity,
): "error" | "warning" | "note" | "none" {
  const num = SEVERITY_NUMERIC[severity];
  if (num >= 4) return "error";
  if (num >= 3) return "warning";
  if (num >= 1) return "note";
  return "none";
}

/**
 * Format a scan report as a SARIF v2.1.0 log object.
 * Can be serialized with `JSON.stringify` for tool ingestion.
 */
export function formatSARIF(report: ScanReport): SARIFLog {
  // Build unique rules from findings
  const ruleMap = new Map<string, SARIFRule>();
  const results: SARIFResult[] = [];

  for (const finding of report.findings) {
    const ruleId = finding.scenarioId;

    if (!ruleMap.has(ruleId)) {
      ruleMap.set(ruleId, {
        id: ruleId,
        name: finding.scenarioName,
        shortDescription: { text: finding.description },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
      });
    }

    results.push({
      ruleId,
      level: sarifLevel(finding.severity),
      message: { text: formatFindingMessage(finding) },
      properties: {
        verdict: finding.verdict,
        category: finding.category,
        triggeredBy: finding.triggeredBy,
        ...(finding.cvssScore !== undefined
          ? { cvssScore: finding.cvssScore }
          : {}),
      },
    });
  }

  const run: SARIFRun = {
    tool: {
      driver: {
        name: "AASTF",
        version: report.aastfVersion,
        informationUri: "https://github.com/anonymousAAK/aastf",
        rules: Array.from(ruleMap.values()),
      },
    },
    results,
  };

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [run],
  };
}

function formatFindingMessage(finding: VulnerabilityFinding): string {
  return (
    `[${finding.severity}] ${finding.scenarioId}: ${finding.description}` +
    (finding.remediation ? ` | Remediation: ${finding.remediation}` : "")
  );
}
