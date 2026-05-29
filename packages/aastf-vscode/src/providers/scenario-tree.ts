/**
 * ScenarioTreeProvider — sidebar tree view of AASTF scenarios.
 *
 * Groups scenarios by ASI category and shows pass/fail status
 * after a scan completes.
 */

import * as vscode from "vscode";

/* ------------------------------------------------------------------ */
/*  Tree item                                                          */
/* ------------------------------------------------------------------ */

export class ScenarioItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly scenarioId: string | undefined,
    public readonly category: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public status: ScenarioStatus = "pending",
  ) {
    super(label, collapsibleState);

    if (scenarioId) {
      this.tooltip = `${scenarioId} — ${statusLabel(status)}`;
      this.description = statusLabel(status);
      this.iconPath = statusIcon(status);
      this.contextValue = "scenario";
    } else {
      // Category node
      this.tooltip = `Category: ${category}`;
      this.contextValue = "category";
    }
  }
}

type ScenarioStatus = "pending" | "pass" | "fail" | "skip" | "error";

function statusLabel(s: ScenarioStatus): string {
  switch (s) {
    case "pass":
      return "SAFE";
    case "fail":
      return "VULNERABLE";
    case "skip":
      return "SKIPPED";
    case "error":
      return "ERROR";
    default:
      return "pending";
  }
}

function statusIcon(
  s: ScenarioStatus,
): vscode.ThemeIcon {
  switch (s) {
    case "pass":
      return new vscode.ThemeIcon(
        "pass-filled",
        new vscode.ThemeColor("testing.iconPassed"),
      );
    case "fail":
      return new vscode.ThemeIcon(
        "error",
        new vscode.ThemeColor("testing.iconFailed"),
      );
    case "skip":
      return new vscode.ThemeIcon(
        "debug-step-over",
        new vscode.ThemeColor("testing.iconSkipped"),
      );
    case "error":
      return new vscode.ThemeIcon(
        "warning",
        new vscode.ThemeColor("testing.iconErrored"),
      );
    default:
      return new vscode.ThemeIcon("circle-outline");
  }
}

/* ------------------------------------------------------------------ */
/*  Scenario data                                                      */
/* ------------------------------------------------------------------ */

interface ScenarioDef {
  id: string;
  title: string;
  category: string;
}

/**
 * Built-in scenario categories and their prefixes.
 */
const CATEGORIES: Record<string, string> = {
  ASI01: "Prompt Injection",
  ASI02: "Sensitive Information Disclosure",
  ASI03: "Supply Chain",
  ASI04: "Output Handling",
  ASI05: "Tool Poisoning",
  ASI06: "Memory Attacks",
  ASI07: "Multi-Agent",
  ASI08: "Cascading Failures",
  MCP: "MCP Protocol",
  CVE: "CVE Reproductions",
  MAS: "Multi-Agent System",
  A2A: "Agent-to-Agent",
};

/**
 * Placeholder scenario list. In a real implementation this would be
 * populated by running `aastf list --json`.
 */
function defaultScenarios(): ScenarioDef[] {
  const defs: ScenarioDef[] = [];
  for (const [prefix, catName] of Object.entries(CATEGORIES)) {
    // Add a few representative entries per category
    for (let i = 1; i <= 3; i++) {
      const id = `${prefix}${prefix.length <= 3 ? "" : "-"}${String(i).padStart(3, "0")}`;
      defs.push({
        id,
        title: `${catName} scenario ${i}`,
        category: prefix,
      });
    }
  }
  return defs;
}

/* ------------------------------------------------------------------ */
/*  Provider                                                           */
/* ------------------------------------------------------------------ */

export class ScenarioTreeProvider
  implements vscode.TreeDataProvider<ScenarioItem>
{
  private _onDidChange = new vscode.EventEmitter<
    ScenarioItem | undefined | void
  >();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private scenarios: ScenarioDef[] = defaultScenarios();
  private results = new Map<string, ScenarioStatus>();

  /* ---- Tree data provider interface ---- */

  getTreeItem(element: ScenarioItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: ScenarioItem): ScenarioItem[] {
    if (!element) {
      // Root: return category nodes
      const categories = [...new Set(this.scenarios.map((s) => s.category))];
      return categories.map(
        (cat) =>
          new ScenarioItem(
            `${cat} — ${CATEGORIES[cat] ?? cat}`,
            undefined,
            cat,
            vscode.TreeItemCollapsibleState.Collapsed,
          ),
      );
    }

    // Children: scenarios within a category
    return this.scenarios
      .filter((s) => s.category === element.category)
      .map(
        (s) =>
          new ScenarioItem(
            `${s.id}: ${s.title}`,
            s.id,
            s.category,
            vscode.TreeItemCollapsibleState.None,
            this.results.get(s.id) ?? "pending",
          ),
      );
  }

  /* ---- Public API ---- */

  /**
   * Replace the scenario list (e.g. after running `aastf list --json`).
   */
  setScenarios(scenarios: ScenarioDef[]): void {
    this.scenarios = scenarios;
    this._onDidChange.fire();
  }

  /**
   * Update pass/fail status for scenarios after a scan.
   */
  setResults(results: Map<string, ScenarioStatus>): void {
    this.results = results;
    this._onDidChange.fire();
  }

  /**
   * Fire a tree-data-changed event to refresh the view.
   */
  refresh(): void {
    this._onDidChange.fire();
  }
}
