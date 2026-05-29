/**
 * ResultsPanel — Webview panel showing AASTF scan results.
 *
 * Renders an interactive HTML table of findings with severity badges,
 * verdict indicators, and quick-fix actions.
 */

import * as vscode from "vscode";

export class ResultsPanel {
  public static readonly viewType = "aastfResults";

  private static instance: ResultsPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private readonly extensionUri: vscode.Uri;
  private disposed = false;

  /* ---------------------------------------------------------------- */
  /*  Lifecycle                                                        */
  /* ---------------------------------------------------------------- */

  public static createOrShow(extensionUri: vscode.Uri): ResultsPanel {
    const column = vscode.ViewColumn.Two;

    if (ResultsPanel.instance) {
      ResultsPanel.instance.panel.reveal(column);
      return ResultsPanel.instance;
    }

    const panel = vscode.window.createWebviewPanel(
      ResultsPanel.viewType,
      "AASTF Results",
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, "media")],
      },
    );

    const instance = new ResultsPanel(panel, extensionUri);
    ResultsPanel.instance = instance;
    return instance;
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this.panel = panel;
    this.extensionUri = extensionUri;

    this.panel.webview.html = this.buildHtml([]);

    this.panel.onDidDispose(() => {
      this.disposed = true;
      ResultsPanel.instance = undefined;
    });

    // Handle messages from the webview (e.g. quick-fix clicks)
    this.panel.webview.onDidReceiveMessage((msg: WebviewMessage) => {
      this.handleMessage(msg);
    });
  }

  /* ---------------------------------------------------------------- */
  /*  Public API                                                       */
  /* ---------------------------------------------------------------- */

  /**
   * Update the panel with fresh findings.
   */
  public update(findings: Finding[]): void {
    if (this.disposed) return;
    this.panel.webview.html = this.buildHtml(findings);
  }

  /* ---------------------------------------------------------------- */
  /*  Message handling                                                 */
  /* ---------------------------------------------------------------- */

  private handleMessage(msg: WebviewMessage): void {
    switch (msg.command) {
      case "openFile": {
        const uri = vscode.Uri.file(msg.filePath);
        vscode.window.showTextDocument(uri, {
          selection: new vscode.Range(
            new vscode.Position(msg.line - 1, 0),
            new vscode.Position(msg.line - 1, 0),
          ),
        });
        break;
      }
      case "applyFix": {
        vscode.window.showInformationMessage(
          `AASTF: Quick-fix for ${msg.ruleId} is not yet implemented.`,
        );
        break;
      }
    }
  }

  /* ---------------------------------------------------------------- */
  /*  HTML builder                                                     */
  /* ---------------------------------------------------------------- */

  private buildHtml(findings: Finding[]): string {
    const rows = findings
      .map(
        (f) => `
      <tr class="severity-${f.severity.toLowerCase()}">
        <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
        <td>${escapeHtml(f.ruleId)}</td>
        <td>${escapeHtml(f.message)}</td>
        <td><span class="verdict verdict-${f.verdict.toLowerCase()}">${escapeHtml(f.verdict)}</span></td>
        <td>
          <a href="#" onclick="openFile('${escapeAttr(f.file)}', ${f.line})">
            ${escapeHtml(f.file)}:${f.line}
          </a>
        </td>
        <td>
          <button onclick="applyFix('${escapeAttr(f.ruleId)}')">Fix</button>
        </td>
      </tr>`,
      )
      .join("\n");

    return /* html */ `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AASTF Results</title>
  <style>
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --border: var(--vscode-panel-border);
    }
    body { font-family: var(--vscode-font-family); color: var(--fg); background: var(--bg); padding: 16px; }
    h1 { font-size: 1.4em; margin-bottom: 12px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
    th { font-weight: 600; opacity: 0.8; }
    .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
    .badge-critical { background: #dc3545; color: #fff; }
    .badge-high     { background: #fd7e14; color: #fff; }
    .badge-medium   { background: #ffc107; color: #000; }
    .badge-low      { background: #17a2b8; color: #fff; }
    .badge-info     { background: #6c757d; color: #fff; }
    .verdict { font-size: 0.85em; font-weight: 500; }
    .verdict-vulnerable   { color: #dc3545; }
    .verdict-safe         { color: #28a745; }
    .verdict-inconclusive { color: #ffc107; }
    a { color: var(--vscode-textLink-foreground); text-decoration: none; }
    a:hover { text-decoration: underline; }
    button {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none; padding: 4px 10px; border-radius: 3px; cursor: pointer;
    }
    button:hover { background: var(--vscode-button-hoverBackground); }
    .empty { text-align: center; padding: 40px; opacity: 0.6; }
  </style>
</head>
<body>
  <h1>AASTF Security Scan Results</h1>
  ${
    findings.length === 0
      ? '<p class="empty">No results yet. Run <strong>AASTF: Run Security Scan</strong> to get started.</p>'
      : `
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>Message</th>
        <th>Verdict</th>
        <th>Location</th>
        <th>Action</th>
      </tr>
    </thead>
    <tbody>
      ${rows}
    </tbody>
  </table>`
  }
  <script>
    const vscode = acquireVsCodeApi();
    function openFile(filePath, line) {
      vscode.postMessage({ command: 'openFile', filePath, line });
    }
    function applyFix(ruleId) {
      vscode.postMessage({ command: 'applyFix', ruleId });
    }
  </script>
</body>
</html>`;
  }
}

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

export interface Finding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  ruleId: string;
  message: string;
  verdict: string;
  file: string;
  line: number;
}

interface WebviewMessage {
  command: string;
  filePath: string;
  line: number;
  ruleId: string;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(text: string): string {
  return escapeHtml(text).replace(/'/g, "&#39;");
}
