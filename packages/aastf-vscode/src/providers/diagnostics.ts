/**
 * DiagnosticsProvider — parse SARIF output and surface VS Code diagnostics.
 *
 * Maps AASTF findings to inline squiggles in the editor with appropriate
 * severity levels.
 */

import * as vscode from "vscode";

/* ------------------------------------------------------------------ */
/*  SARIF type stubs (subset needed for parsing)                       */
/* ------------------------------------------------------------------ */

interface SarifMessage {
  text: string;
}

interface SarifArtifactLocation {
  uri: string;
}

interface SarifRegion {
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
}

interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
}

interface SarifResult {
  ruleId: string;
  level?: "error" | "warning" | "note" | "none";
  message: SarifMessage;
  locations?: SarifLocation[];
}

interface SarifRun {
  results: SarifResult[];
}

interface SarifLog {
  $schema?: string;
  version: string;
  runs: SarifRun[];
}

/* ------------------------------------------------------------------ */
/*  Severity mapping                                                   */
/* ------------------------------------------------------------------ */

type AastfSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const SEVERITY_RANK: Record<AastfSeverity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

function sarifLevelToSeverity(
  level: string | undefined,
): vscode.DiagnosticSeverity {
  switch (level) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "note":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function aastfSeverityToSarifLevel(sev: AastfSeverity): string {
  switch (sev) {
    case "CRITICAL":
      return "error";
    case "HIGH":
      return "warning";
    case "MEDIUM":
      return "warning";
    case "LOW":
      return "note";
    case "INFO":
      return "none";
  }
}

/* ------------------------------------------------------------------ */
/*  Provider                                                           */
/* ------------------------------------------------------------------ */

export class DiagnosticsProvider {
  private readonly collection: vscode.DiagnosticCollection;

  constructor(collection: vscode.DiagnosticCollection) {
    this.collection = collection;
  }

  /**
   * Clear all AASTF diagnostics.
   */
  clear(): void {
    this.collection.clear();
  }

  /**
   * Parse a SARIF JSON string and populate the diagnostics collection.
   *
   * @param sarifJson  Raw SARIF 2.1.0 JSON content.
   * @param workspaceRoot  Workspace root URI for resolving relative paths.
   * @returns Number of diagnostics created.
   */
  loadFromSarif(sarifJson: string, workspaceRoot: vscode.Uri): number {
    this.collection.clear();

    const minSeverity = vscode.workspace
      .getConfiguration("aastf")
      .get<AastfSeverity>("severity.minimum", "MEDIUM");
    const minRank = SEVERITY_RANK[minSeverity];

    let log: SarifLog;
    try {
      log = JSON.parse(sarifJson) as SarifLog;
    } catch {
      vscode.window.showErrorMessage("AASTF: Failed to parse SARIF output.");
      return 0;
    }

    const diagMap = new Map<string, vscode.Diagnostic[]>();
    let count = 0;

    for (const run of log.runs) {
      for (const result of run.results) {
        // Filter by minimum severity
        const level = result.level ?? "warning";
        const sevLabel = sarifLevelToAastf(level);
        if (SEVERITY_RANK[sevLabel] > minRank) {
          continue;
        }

        const severity = sarifLevelToSeverity(level);

        const location = result.locations?.[0]?.physicalLocation;
        const uri = location?.artifactLocation?.uri ?? "";
        const region = location?.region;

        const fileUri = uri
          ? vscode.Uri.joinPath(workspaceRoot, uri).toString()
          : "unknown";

        const range = new vscode.Range(
          new vscode.Position(
            (region?.startLine ?? 1) - 1,
            (region?.startColumn ?? 1) - 1,
          ),
          new vscode.Position(
            (region?.endLine ?? region?.startLine ?? 1) - 1,
            (region?.endColumn ?? 80) - 1,
          ),
        );

        const diag = new vscode.Diagnostic(
          range,
          `[${result.ruleId}] ${result.message.text}`,
          severity,
        );
        diag.source = "AASTF";
        diag.code = result.ruleId;

        const list = diagMap.get(fileUri) ?? [];
        list.push(diag);
        diagMap.set(fileUri, list);
        count++;
      }
    }

    for (const [fileUri, diags] of diagMap) {
      this.collection.set(vscode.Uri.parse(fileUri), diags);
    }

    return count;
  }

  /**
   * Load diagnostics from a SARIF file on disk.
   */
  async loadFromFile(
    sarifPath: vscode.Uri,
    workspaceRoot: vscode.Uri,
  ): Promise<number> {
    const bytes = await vscode.workspace.fs.readFile(sarifPath);
    const json = new TextDecoder().decode(bytes);
    return this.loadFromSarif(json, workspaceRoot);
  }
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function sarifLevelToAastf(level: string): AastfSeverity {
  switch (level) {
    case "error":
      return "CRITICAL";
    case "warning":
      return "HIGH";
    case "note":
      return "LOW";
    default:
      return "INFO";
  }
}

// Re-export for use by other modules
export { AastfSeverity, aastfSeverityToSarifLevel };
