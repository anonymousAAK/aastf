/**
 * @aastf/core — TypeScript SDK for the Agentic AI Security Testing Framework.
 *
 * @packageDocumentation
 */

// Types & enums
export {
  Verdict,
  Severity,
  SEVERITY_NUMERIC,
  ASICategory,
  ASI_CATEGORY_NAMES,
  InjectionPoint,
} from "./types.js";

export type {
  AttackScenario,
  ToolResponseConfig,
  MCPResourceConfig,
  DetectionCriteria,
  ToolInvocation,
  AgentTrace,
  TraceMessage,
  EvaluationResult,
  VulnerabilityFinding,
  TestResult,
  EuAiActReadiness,
  ASISummary,
  ScanReport,
  SandboxResponse,
  ToolResponse,
  SARIFLog,
  SARIFRun,
  SARIFRule,
  SARIFResult,
} from "./types.js";

// Sandbox client
export { SandboxClient, SandboxError } from "./sandbox-client.js";
export type { SandboxClientOptions } from "./sandbox-client.js";

// Scenario loader
export {
  loadScenario,
  loadScenarioFile,
  ScenarioLoadError,
} from "./scenario-loader.js";

// Reporter
export { formatConsole, formatJSON, formatSARIF } from "./reporter.js";

// Scenario runner
export {
  ScenarioRunner,
  ScenarioRunError,
  evaluateVerdict,
  buildFinding,
  buildScanReport,
  parseSimpleYAML,
  loadScenarioFromFile,
  discoverScenarioFiles,
  withTimeout,
} from "./scenario-runner.js";
export type { ScenarioRunnerOptions } from "./scenario-runner.js";

// Sandbox server
export { SandboxServer, startFromCLI } from "./sandbox-server.js";
export type {
  SandboxServerConfig,
  ScanRequest,
  ScanResponse,
} from "./sandbox-server.js";

// Adapters
export {
  BaseAdapter,
  OpenAIAgentsAdapter,
  LangChainAdapter,
  MastraAdapter,
  VercelAIAdapter,
} from "./adapters/index.js";
export type {
  AdapterConfig,
  OpenAIAgentsAdapterConfig,
  LangChainAdapterConfig,
  MastraAdapterConfig,
  MastraStepResult,
  VercelAIAdapterConfig,
  VercelAIToolCall,
  VercelAIToolResult,
} from "./adapters/index.js";
