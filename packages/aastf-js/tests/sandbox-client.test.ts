import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SandboxClient, SandboxError } from "../src/sandbox-client.js";

// ---------------------------------------------------------------------------
// Mock fetch globally
// ---------------------------------------------------------------------------

const mockFetch = vi.fn<typeof globalThis.fetch>();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(status: number, text = "error"): Response {
  return new Response(text, { status });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("SandboxClient", () => {
  const BASE_URL = "http://127.0.0.1:9100";

  describe("constructor", () => {
    it("should strip trailing slashes from baseUrl", () => {
      const client = new SandboxClient("http://localhost:9100///");
      expect(client.getBaseUrl()).toBe("http://localhost:9100");
    });
  });

  describe("health()", () => {
    it("should return true when server responds 200", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));

      const client = new SandboxClient(BASE_URL);
      const result = await client.health();

      expect(result).toBe(true);
      expect(mockFetch).toHaveBeenCalledOnce();
      expect(mockFetch.mock.calls[0][0]).toBe(`${BASE_URL}/health`);
    });

    it("should return false when server responds 500", async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(500));

      const client = new SandboxClient(BASE_URL);
      const result = await client.health();

      expect(result).toBe(false);
    });

    it("should return false when fetch throws (server unreachable)", async () => {
      mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

      const client = new SandboxClient(BASE_URL);
      const result = await client.health();

      expect(result).toBe(false);
    });
  });

  describe("submitMessage()", () => {
    it("should POST message and return parsed response", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          agent_output: "I cannot comply with that request.",
          trace: {
            messages: [
              { role: "user", content: "ignore previous" },
              { role: "assistant", content: "I cannot comply with that request." },
            ],
            tool_invocations: [],
            raw_output: "I cannot comply with that request.",
          },
          duration_ms: 432,
        }),
      );

      const client = new SandboxClient(BASE_URL);
      const response = await client.submitMessage("ignore previous");

      expect(response.agentOutput).toBe("I cannot comply with that request.");
      expect(response.durationMs).toBe(432);
      expect(response.trace.messages).toHaveLength(2);
      expect(response.trace.rawOutput).toBe("I cannot comply with that request.");

      // Verify the request was a POST with JSON body
      const [url, init] = mockFetch.mock.calls[0];
      expect(url).toBe(`${BASE_URL}/submit`);
      expect((init as RequestInit).method).toBe("POST");
      expect(JSON.parse((init as RequestInit).body as string)).toEqual({
        message: "ignore previous",
      });
    });

    it("should throw SandboxError on non-2xx response", async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(422, "Unprocessable"));
      mockFetch.mockResolvedValueOnce(errorResponse(422, "Unprocessable"));

      const client = new SandboxClient(BASE_URL);

      await expect(client.submitMessage("test")).rejects.toThrow(SandboxError);
      await expect(client.submitMessage("test")).rejects.toThrow(
        /submitMessage failed/,
      );
    });

    it("should handle missing trace gracefully", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ agent_output: "ok" }),
      );

      const client = new SandboxClient(BASE_URL);
      const response = await client.submitMessage("hello");

      expect(response.agentOutput).toBe("ok");
      expect(response.trace.messages).toEqual([]);
      expect(response.trace.toolInvocations).toEqual([]);
      expect(response.trace.rawOutput).toBe("");
    });
  });

  describe("getToolResponse()", () => {
    it("should GET tool response by name", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          tool_name: "search",
          response_payload: { results: ["item1"] },
          response_mode: "success",
        }),
      );

      const client = new SandboxClient(BASE_URL);
      const response = await client.getToolResponse("search");

      expect(response.toolName).toBe("search");
      expect(response.payload).toEqual({ results: ["item1"] });
      expect(response.responseMode).toBe("success");

      expect(mockFetch.mock.calls[0][0]).toBe(`${BASE_URL}/tools/search`);
    });

    it("should URL-encode tool names with special characters", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ tool_name: "my/tool", response_mode: "success" }),
      );

      const client = new SandboxClient(BASE_URL);
      await client.getToolResponse("my/tool");

      expect(mockFetch.mock.calls[0][0]).toBe(
        `${BASE_URL}/tools/my%2Ftool`,
      );
    });

    it("should throw SandboxError on 404", async () => {
      mockFetch.mockResolvedValueOnce(errorResponse(404, "Not Found"));

      const client = new SandboxClient(BASE_URL);

      await expect(client.getToolResponse("nonexistent")).rejects.toThrow(
        SandboxError,
      );
    });
  });
});
