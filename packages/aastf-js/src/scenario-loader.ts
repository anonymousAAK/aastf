/**
 * Scenario loader — converts parsed YAML/JSON into typed AttackScenario objects.
 *
 * This module intentionally avoids bundling a YAML parser to keep the package
 * dependency-free. Consumers either:
 *   1. Pass pre-parsed objects (from `JSON.parse` or their own YAML lib).
 *   2. Use `loadScenarioFile` which reads JSON files from disk (Node only).
 */

import { readFile } from "node:fs/promises";
import type {
  AttackScenario,
  ASICategory,
  Severity,
  InjectionPoint,
  DetectionCriteria,
  ToolResponseConfig,
  MCPResourceConfig,
} from "./types.js";

/**
 * Validate and convert a plain object (e.g. parsed YAML/JSON) into a typed
 * AttackScenario. Applies snake_case → camelCase mapping automatically.
 *
 * @throws {ScenarioLoadError} if required fields are missing or invalid.
 */
export function loadScenario(raw: Record<string, unknown>): AttackScenario {
  assertString(raw, "id");
  assertString(raw, "name");
  assertString(raw, "category");
  assertString(raw, "severity");
  assertString(raw, "description");
  assertString(raw, "attack_vector", "attackVector");
  assertString(raw, "inject_into", "injectInto");
  assertString(raw, "payload");
  assertString(raw, "expected_behavior", "expectedBehavior");
  assertString(raw, "remediation");

  const id = raw.id as string;
  if (!/^(ASI|MCP|CVE|MAS)\d{2}-\d{3}$/.test(id)) {
    throw new ScenarioLoadError(
      `Scenario ID must match ASI##-###, MCP##-###, CVE##-###, or MAS##-### format, got: "${id}"`,
    );
  }

  const detection = parseDetection(
    raw.detection as Record<string, unknown> | undefined,
  );

  return {
    id,
    name: raw.name as string,
    category: raw.category as ASICategory,
    severity: raw.severity as Severity,
    description: raw.description as string,
    attackVector: str(raw, "attack_vector"),
    preconditions: strArray(raw, "preconditions"),

    injectInto: str(raw, "inject_into") as InjectionPoint,
    payload: raw.payload as string,
    payloadVariants: strArray(raw, "payload_variants"),

    toolResponses: parseToolResponses(raw.tool_responses),
    availableTools: strArray(raw, "available_tools"),
    mcpResources: parseMCPResources(raw.mcp_resources),

    detection,

    expectedBehavior: str(raw, "expected_behavior"),
    remediation: raw.remediation as string,
    tags: strArray(raw, "tags"),
    references: strArray(raw, "references"),
    author: (raw.author as string) ?? "aastf-core",
    version: (raw.version as string) ?? "1.0",

    cweIds: strArray(raw, "cwe_ids"),
    nistAiRmf: strArray(raw, "nist_ai_rmf"),
  };
}

/**
 * Load a scenario from a JSON file on disk.
 * For YAML files, pipe through a YAML parser first and use `loadScenario`.
 */
export async function loadScenarioFile(path: string): Promise<AttackScenario> {
  const content = await readFile(path, "utf-8");
  const parsed: unknown = JSON.parse(content);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ScenarioLoadError(
      `Expected a JSON object in ${path}, got ${typeof parsed}`,
    );
  }
  return loadScenario(parsed as Record<string, unknown>);
}

/** Error thrown when a scenario file cannot be parsed or validated. */
export class ScenarioLoadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScenarioLoadError";
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function assertString(
  obj: Record<string, unknown>,
  snakeKey: string,
  _camelKey?: string,
): void {
  const value = obj[snakeKey] ?? obj[_camelKey ?? snakeKey];
  if (typeof value !== "string" || value.length === 0) {
    throw new ScenarioLoadError(
      `Missing or empty required field: "${snakeKey}"`,
    );
  }
}

function str(obj: Record<string, unknown>, snakeKey: string): string {
  return (obj[snakeKey] as string) ?? "";
}

function strArray(obj: Record<string, unknown>, snakeKey: string): string[] {
  const val = obj[snakeKey];
  if (!Array.isArray(val)) return [];
  return val.filter((v): v is string => typeof v === "string");
}

function parseDetection(
  raw: Record<string, unknown> | undefined,
): DetectionCriteria {
  if (!raw) {
    return {
      toolCalled: [],
      toolNotCalled: [],
      toolInputContains: {},
      outputContains: [],
      outputNotContains: [],
    };
  }
  return {
    toolCalled: strArray(raw, "tool_called"),
    toolNotCalled: strArray(raw, "tool_not_called"),
    toolInputContains:
      (raw.tool_input_contains as Record<string, string>) ?? {},
    toolCallCountExceeds: raw.tool_call_count_exceeds as number | undefined,
    outputContains: strArray(raw, "output_contains"),
    outputNotContains: strArray(raw, "output_not_contains"),
    loopIterationsExceed: raw.loop_iterations_exceed as number | undefined,
    customEvaluator: raw.custom_evaluator as string | undefined,
  };
}

function parseToolResponses(raw: unknown): ToolResponseConfig[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((item: Record<string, unknown>) => ({
    toolName: (item.tool_name as string) ?? "",
    triggerContains: item.trigger_contains as string | undefined,
    responsePayload: item.response_payload ?? undefined,
    responseMode:
      (item.response_mode as ToolResponseConfig["responseMode"]) ?? "success",
    delaySeconds: (item.delay_seconds as number) ?? 0,
    callCountLimit: item.call_count_limit as number | undefined,
    toolDescription: item.tool_description as string | undefined,
    toolInputSchema: item.tool_input_schema as
      | Record<string, unknown>
      | undefined,
  }));
}

function parseMCPResources(raw: unknown): MCPResourceConfig[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((item: Record<string, unknown>) => ({
    uri: (item.uri as string) ?? "",
    content: (item.content as string) ?? "",
    mimeType: (item.mime_type as string) ?? "text/plain",
  }));
}
