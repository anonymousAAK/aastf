/**
 * Core types for @aastf/core — ported from Python aastf.models.
 *
 * Follows TypeScript idioms: camelCase fields, const enums,
 * interfaces over classes where no runtime logic is needed.
 */

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/** Verdict produced by an evaluator after running a scenario. */
export enum Verdict {
  /** Attack succeeded — agent performed the adversarial action. */
  VULNERABLE = "VULNERABLE",
  /** Agent refused but leaked payload details in refusal text. */
  REFUSAL_ECHO = "REFUSAL_ECHO",
  /** Agent correctly resisted the attack. */
  SAFE = "SAFE",
  /** Could not determine (no evaluator, ambiguous trace). */
  INCONCLUSIVE = "INCONCLUSIVE",
  /** Framework error during scenario execution. */
  ERROR = "ERROR",
  /** Agent executed a tool whose description was maliciously modified. */
  TOOL_POISONING = "TOOL_POISONING",
  /** Agent accepted manipulated tool input schema. */
  SCHEMA_POISONING = "SCHEMA_POISONING",
  /** Agent's tool selection was influenced by metadata. */
  PREFERENCE_MANIPULATION = "PREFERENCE_MANIPULATION",
  /** Malicious instructions propagated through agent memory/context. */
  INFECTION_PROPAGATED = "INFECTION_PROPAGATED",
  /** Two or more agents colluded to bypass controls. */
  COLLUSION = "COLLUSION",
  /** Agent bypassed a watchdog/guardrail agent. */
  WATCHDOG_BYPASS = "WATCHDOG_BYPASS",
}

/** Severity of a scenario or finding, ordered lowest to highest. */
export enum Severity {
  INFO = "INFO",
  LOW = "LOW",
  MEDIUM = "MEDIUM",
  HIGH = "HIGH",
  CRITICAL = "CRITICAL",
}

/** Numeric severity for comparison/sorting. */
export const SEVERITY_NUMERIC: Record<Severity, number> = {
  [Severity.INFO]: 1,
  [Severity.LOW]: 2,
  [Severity.MEDIUM]: 3,
  [Severity.HIGH]: 4,
  [Severity.CRITICAL]: 5,
};

/** OWASP Agentic Security Initiative category. */
export enum ASICategory {
  /** Agent Goal Hijack */
  ASI01 = "ASI01",
  /** Tool Misuse & Exploitation */
  ASI02 = "ASI02",
  /** Identity & Privilege Abuse */
  ASI03 = "ASI03",
  /** Agentic Supply Chain Vulnerabilities */
  ASI04 = "ASI04",
  /** Unexpected Code Execution (RCE) */
  ASI05 = "ASI05",
  /** Memory & Context Poisoning */
  ASI06 = "ASI06",
  /** Insecure Inter-Agent Communication */
  ASI07 = "ASI07",
  /** Cascading Failures */
  ASI08 = "ASI08",
  /** Human-Agent Trust Exploitation */
  ASI09 = "ASI09",
  /** Rogue Agents */
  ASI10 = "ASI10",
}

/** Human-readable display names for ASI categories. */
export const ASI_CATEGORY_NAMES: Record<ASICategory, string> = {
  [ASICategory.ASI01]: "Agent Goal Hijack",
  [ASICategory.ASI02]: "Tool Misuse & Exploitation",
  [ASICategory.ASI03]: "Identity & Privilege Abuse",
  [ASICategory.ASI04]: "Agentic Supply Chain Vulnerabilities",
  [ASICategory.ASI05]: "Unexpected Code Execution (RCE)",
  [ASICategory.ASI06]: "Memory & Context Poisoning",
  [ASICategory.ASI07]: "Insecure Inter-Agent Communication",
  [ASICategory.ASI08]: "Cascading Failures",
  [ASICategory.ASI09]: "Human-Agent Trust Exploitation",
  [ASICategory.ASI10]: "Rogue Agents",
};

/** Where the adversarial payload is injected. */
export enum InjectionPoint {
  USER_MESSAGE = "user_message",
  TOOL_RESPONSE = "tool_response",
  MEMORY = "memory",
  SYSTEM_PROMPT = "system_prompt",
}

// ---------------------------------------------------------------------------
// Scenario types
// ---------------------------------------------------------------------------

/** Configures sandbox tool response behavior for a scenario. */
export interface ToolResponseConfig {
  toolName: string;
  triggerContains?: string;
  responsePayload?: unknown;
  responseMode: "success" | "error" | "malformed" | "delayed";
  delaySeconds: number;
  callCountLimit?: number;
  toolDescription?: string;
  toolInputSchema?: Record<string, unknown>;
}

/** MCP resource served by the sandbox for resource-based attacks. */
export interface MCPResourceConfig {
  uri: string;
  content: string;
  mimeType: string;
}

/** Defines what constitutes a successful attack (VULNERABLE verdict). */
export interface DetectionCriteria {
  toolCalled: string[];
  toolNotCalled: string[];
  toolInputContains: Record<string, string>;
  toolCallCountExceeds?: number;
  outputContains: string[];
  outputNotContains: string[];
  loopIterationsExceed?: number;
  customEvaluator?: string;
}

/** A single OWASP ASI attack scenario loaded from a YAML file. */
export interface AttackScenario {
  id: string;
  name: string;
  category: ASICategory;
  severity: Severity;
  description: string;
  attackVector: string;
  preconditions: string[];

  injectInto: InjectionPoint;
  payload: string;
  payloadVariants: string[];

  toolResponses: ToolResponseConfig[];
  availableTools: string[];
  mcpResources: MCPResourceConfig[];

  detection: DetectionCriteria;

  expectedBehavior: string;
  remediation: string;
  tags: string[];
  references: string[];
  author: string;
  version: string;

  cweIds: string[];
  nistAiRmf: string[];
}

// ---------------------------------------------------------------------------
// Trace types
// ---------------------------------------------------------------------------

/** A single tool invocation captured during scenario execution. */
export interface ToolInvocation {
  toolName: string;
  input: unknown;
  output: unknown;
  timestampMs: number;
  durationMs: number;
}

/** Full execution trace of an agent during a scenario. */
export interface AgentTrace {
  messages: TraceMessage[];
  toolInvocations: ToolInvocation[];
  rawOutput: string;
}

/** A single message in the agent trace. */
export interface TraceMessage {
  role: "system" | "user" | "assistant" | "tool";
  content: string;
  timestampMs?: number;
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/** Intermediate result returned by an evaluator. */
export interface EvaluationResult {
  verdict: Verdict;
  triggeredBy: string;
  confidence: number;
}

/** A confirmed security finding — created when verdict is VULNERABLE. */
export interface VulnerabilityFinding {
  findingId: string;
  scenarioId: string;
  scenarioName: string;
  category: ASICategory;
  severity: Severity;
  verdict: Verdict;
  cvssScore?: number;
  triggeredBy: string;
  evidence: Record<string, unknown>;
  relevantInvocations: ToolInvocation[];
  description: string;
  remediation: string;
  references: string[];
}

/** Result of running a single scenario against the agent. */
export interface TestResult {
  resultId: string;
  scenarioId: string;
  scenarioName: string;
  category: ASICategory;
  severity: Severity;
  verdict: Verdict;
  finding?: VulnerabilityFinding;
  trace: AgentTrace;
  executionTimeMs: number;
}

/** EU AI Act readiness classification. */
export type EuAiActReadiness = "compliant" | "at_risk" | "non_compliant";

/** Per-category breakdown of verdicts. */
export type ASISummary = Record<string, Record<string, number>>;

/** Complete output of an AASTF scan run. */
export interface ScanReport {
  runId: string;
  generatedAt: string;
  aastfVersion: string;
  adapter: string;
  totalScenarios: number;
  vulnerable: number;
  refusalEchoCount: number;
  safe: number;
  inconclusive: number;
  errors: number;
  overallRiskScore: number;
  euAiActReadiness: EuAiActReadiness;
  results: TestResult[];
  findings: VulnerabilityFinding[];
  asiSummary: ASISummary;
}

// ---------------------------------------------------------------------------
// Sandbox types (used by SandboxClient)
// ---------------------------------------------------------------------------

/** Response from the sandbox server's /submit endpoint. */
export interface SandboxResponse {
  agentOutput: string;
  trace: AgentTrace;
  durationMs: number;
}

/** Response from the sandbox server's /tools/:name endpoint. */
export interface ToolResponse {
  toolName: string;
  payload: unknown;
  responseMode: string;
}

// ---------------------------------------------------------------------------
// SARIF types (subset for reporter output)
// ---------------------------------------------------------------------------

/** SARIF v2.1.0 log format (simplified). */
export interface SARIFLog {
  $schema: string;
  version: "2.1.0";
  runs: SARIFRun[];
}

export interface SARIFRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SARIFRule[];
    };
  };
  results: SARIFResult[];
}

export interface SARIFRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" | "none" };
}

export interface SARIFResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  properties?: Record<string, unknown>;
}
