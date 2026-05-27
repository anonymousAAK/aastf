/**
 * HTTP client for the AASTF sandbox server.
 *
 * Uses native `fetch` (Node 18+) — zero external dependencies.
 * Communicates with the Python sandbox server over HTTP.
 */

import type { SandboxResponse, ToolResponse, AgentTrace } from "./types.js";

/** Options for SandboxClient construction. */
export interface SandboxClientOptions {
  /** Request timeout in milliseconds. Default: 30_000. */
  timeoutMs?: number;
}

/**
 * Client for the AASTF sandbox server.
 *
 * @example
 * ```ts
 * const client = new SandboxClient("http://127.0.0.1:9100");
 * if (await client.health()) {
 *   const response = await client.submitMessage("Ignore previous instructions...");
 *   console.log(response.agentOutput);
 * }
 * ```
 */
export class SandboxClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(baseUrl: string, options: SandboxClientOptions = {}) {
    // Strip trailing slash for consistent URL construction
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 30_000;
  }

  /**
   * Check if the sandbox server is reachable and healthy.
   * Returns `true` if the server responds with a 2xx status.
   */
  async health(): Promise<boolean> {
    try {
      const response = await this.fetch("/health");
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Submit a message (adversarial payload) to the sandbox-hosted agent.
   */
  async submitMessage(message: string): Promise<SandboxResponse> {
    const response = await this.fetch("/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    if (!response.ok) {
      throw new SandboxError(
        `submitMessage failed: ${response.status} ${response.statusText}`,
        response.status,
      );
    }

    const data = (await response.json()) as Record<string, unknown>;
    return {
      agentOutput: (data.agent_output as string) ?? "",
      trace: this.parseTrace(data.trace),
      durationMs: (data.duration_ms as number) ?? 0,
    };
  }

  /**
   * Get the configured tool response for a named tool.
   */
  async getToolResponse(toolName: string): Promise<ToolResponse> {
    const response = await this.fetch(`/tools/${encodeURIComponent(toolName)}`);

    if (!response.ok) {
      throw new SandboxError(
        `getToolResponse failed for "${toolName}": ${response.status} ${response.statusText}`,
        response.status,
      );
    }

    const data = (await response.json()) as Record<string, unknown>;
    return {
      toolName: (data.tool_name as string) ?? toolName,
      payload: data.payload ?? data.response_payload ?? null,
      responseMode: (data.response_mode as string) ?? "success",
    };
  }

  /**
   * Get the base URL this client is configured for.
   */
  getBaseUrl(): string {
    return this.baseUrl;
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private async fetch(path: string, init?: RequestInit): Promise<Response> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timeout);
    }
  }

  private parseTrace(raw: unknown): AgentTrace {
    if (!raw || typeof raw !== "object") {
      return { messages: [], toolInvocations: [], rawOutput: "" };
    }
    const obj = raw as Record<string, unknown>;
    return {
      messages: Array.isArray(obj.messages) ? obj.messages : [],
      toolInvocations: Array.isArray(obj.tool_invocations)
        ? obj.tool_invocations
        : [],
      rawOutput: (obj.raw_output as string) ?? "",
    };
  }
}

/**
 * Error thrown by SandboxClient when the server returns a non-2xx response.
 */
export class SandboxError extends Error {
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    this.name = "SandboxError";
    this.statusCode = statusCode;
  }
}
