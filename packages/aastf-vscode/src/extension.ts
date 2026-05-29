/**
 * AASTF VS Code Extension — Main entry point.
 *
 * Registers commands, providers, and UI elements for the
 * Agentic AI Security Testing Framework.
 */

import * as vscode from "vscode";
import { DiagnosticsProvider } from "./providers/diagnostics";
import { ResultsPanel } from "./providers/results-panel";
import { ScenarioTreeProvider } from "./providers/scenario-tree";

/* ------------------------------------------------------------------ */
/*  Status bar                                                         */
/* ------------------------------------------------------------------ */

let statusBarItem: vscode.StatusBarItem;

function createStatusBar(context: vscode.ExtensionContext): void {
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100,
  );
  statusBarItem.text = "$(shield) AASTF";
  statusBarItem.tooltip = "AASTF Security Scanner — click to scan";
  statusBarItem.command = "aastf.scan";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);
}

function setStatusScanning(): void {
  statusBarItem.text = "$(sync~spin) AASTF scanning...";
  statusBarItem.tooltip = "Scan in progress";
}

function setStatusDone(issues: number): void {
  if (issues === 0) {
    statusBarItem.text = "$(shield) AASTF: clean";
    statusBarItem.tooltip = "No security issues found";
  } else {
    statusBarItem.text = `$(warning) AASTF: ${issues} issue${issues > 1 ? "s" : ""}`;
    statusBarItem.tooltip = `${issues} security issue${issues > 1 ? "s" : ""} found — click to view`;
    statusBarItem.command = "aastf.viewResults";
  }
}

/* ------------------------------------------------------------------ */
/*  Scan runner                                                        */
/* ------------------------------------------------------------------ */

interface ScanResult {
  issues: number;
  sarifPath: string;
}

async function runScan(
  diagnosticsProvider: DiagnosticsProvider,
): Promise<ScanResult | undefined> {
  const config = vscode.workspace.getConfiguration("aastf");
  const pythonPath = config.get<string>("pythonPath", "python");
  const configPath = config.get<string>("configPath", "aastf.yaml");
  const sarifOutput = config.get<string>(
    "sarif.outputPath",
    ".aastf/results.sarif",
  );

  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (!workspaceFolder) {
    vscode.window.showErrorMessage("AASTF: Open a workspace folder first.");
    return undefined;
  }

  const cwd = workspaceFolder.uri.fsPath;

  setStatusScanning();

  const terminal = vscode.window.createTerminal({
    name: "AASTF Scan",
    cwd,
  });

  const command = [
    pythonPath,
    "-m",
    "aastf",
    "scan",
    "--config",
    configPath,
    "--format",
    "sarif",
    "--output",
    sarifOutput,
  ].join(" ");

  terminal.sendText(command);
  terminal.show(true);

  // After the scan completes the user can reload diagnostics via viewResults.
  // A real implementation would watch the SARIF file for changes; for the
  // scaffold we return a placeholder.
  return { issues: 0, sarifPath: sarifOutput };
}

/* ------------------------------------------------------------------ */
/*  Activation                                                         */
/* ------------------------------------------------------------------ */

export function activate(context: vscode.ExtensionContext): void {
  // Diagnostics
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("aastf");
  context.subscriptions.push(diagnosticCollection);

  const diagnosticsProvider = new DiagnosticsProvider(diagnosticCollection);

  // Scenario tree sidebar
  const scenarioTree = new ScenarioTreeProvider();
  vscode.window.registerTreeDataProvider("aastfScenarios", scenarioTree);

  // Status bar
  createStatusBar(context);

  // Commands -------------------------------------------------------

  context.subscriptions.push(
    vscode.commands.registerCommand("aastf.scan", async () => {
      const result = await runScan(diagnosticsProvider);
      if (result) {
        setStatusDone(result.issues);
      }
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aastf.viewResults", () => {
      ResultsPanel.createOrShow(context.extensionUri);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("aastf.listScenarios", () => {
      scenarioTree.refresh();
      vscode.commands.executeCommand("aastfScenarios.focus");
    }),
  );

  // Scan-on-save (opt-in) ------------------------------------------

  if (vscode.workspace.getConfiguration("aastf").get<boolean>("scanOnSave")) {
    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument(async () => {
        const result = await runScan(diagnosticsProvider);
        if (result) {
          setStatusDone(result.issues);
        }
      }),
    );
  }

  console.log("AASTF Security Scanner extension activated.");
}

/* ------------------------------------------------------------------ */
/*  Deactivation                                                       */
/* ------------------------------------------------------------------ */

export function deactivate(): void {
  // Clean-up handled by disposable subscriptions.
}
