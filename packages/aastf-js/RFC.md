# RFC: asi-scan TypeScript SDK

**Status:** Draft
**Version:** 0.1.0-alpha.1
**Date:** 2026-05-27
**Authors:** AASTF Contributors

---

## 1. Motivation

The Python AASTF package (v0.5.0) provides security testing for agentic AI systems
with adapters for LangGraph, CrewAI, OpenAI Agents, Pydantic AI, and MCP. However,
the JavaScript/TypeScript ecosystem has its own set of agentic frameworks —
OpenAI Agents JS, LangChain.js, Mastra, and Vercel AI SDK — that lack equivalent
security testing tooling.

`asi-scan` brings the same scenario-driven adversarial testing to the JS/TS
ecosystem, reusing the Python sandbox server and 100+ attack scenarios.

## 2. API Surface

### 2.1 Types & Enums

All core types are ported from `aastf.models` with TypeScript idioms:

| Python | TypeScript |
|--------|-----------|
| `Verdict` (StrEnum) | `Verdict` (string enum) |
| `Severity` (StrEnum) | `Severity` (string enum) + `SEVERITY_NUMERIC` map |
| `ASICategory` (StrEnum) | `ASICategory` (string enum) + `ASI_CATEGORY_NAMES` map |
| `InjectionPoint` (StrEnum) | `InjectionPoint` (string enum) |
| `AttackScenario` (Pydantic) | `AttackScenario` (interface) |
| `VulnerabilityFinding` (Pydantic) | `VulnerabilityFinding` (interface) |
| `TestResult` (Pydantic) | `TestResult` (interface) |
| `ScanReport` (Pydantic) | `ScanReport` (interface) |

Field naming follows camelCase convention. Snake_case from YAML/JSON payloads is
mapped automatically by the scenario loader.

### 2.2 SandboxClient

HTTP client for the Python sandbox server. Uses native `fetch` (Node 18+), no
external HTTP dependencies.

```typescript
const client = new SandboxClient("http://127.0.0.1:9100");
await client.health();                         // -> boolean
await client.submitMessage("payload");         // -> SandboxResponse
await client.getToolResponse("tool_name");     // -> ToolResponse
```

### 2.3 Scenario Loader

Parses scenario definitions from JSON (or pre-parsed YAML objects) into typed
`AttackScenario` instances with validation.

```typescript
import { loadScenario, loadScenarioFile } from "asi-scan";

const scenario = loadScenario(parsedYamlObject);
const scenario2 = await loadScenarioFile("./scenarios/ASI01-001.json");
```

### 2.4 Reporter

Formats `ScanReport` objects into three output formats:

- **Console:** Human-readable text for CI/CD logs
- **JSON:** Machine-readable for dashboards and APIs
- **SARIF:** Static Analysis Results Interchange Format v2.1.0 for GitHub Code Scanning

```typescript
import { formatConsole, formatJSON, formatSARIF } from "asi-scan";

console.log(formatConsole(report));
fs.writeFileSync("report.json", formatJSON(report));
const sarif = formatSARIF(report);  // -> SARIFLog object
```

## 3. Adapter Pattern

Adapters bridge between `asi-scan` and specific JS agent frameworks. Each
adapter implements the `AgentAdapter` interface (planned for alpha.2):

```typescript
interface AgentAdapter {
  readonly name: string;
  initialize(config: AdapterConfig): Promise<void>;
  runScenario(scenario: AttackScenario): Promise<TestResult>;
  cleanup(): Promise<void>;
}
```

### Planned Adapters

| Framework | Adapter Package | Priority |
|-----------|----------------|----------|
| Vercel AI SDK | `@aastf/adapter-vercel-ai` | P0 — largest TS agent community |
| LangChain.js | `@aastf/adapter-langchain` | P0 — wide adoption |
| Mastra | `@aastf/adapter-mastra` | P1 — growing agentic framework |
| OpenAI Agents JS | `@aastf/adapter-openai-agents` | P1 — official OpenAI SDK |

Adapters will be published as separate packages with `asi-scan` as a peer
dependency to keep the core lightweight.

## 4. Compatibility with Python Sandbox

The TypeScript SDK operates as a **client** to the existing Python sandbox server:

```
  JS Test Runner                    Python Sandbox
  ┌─────────────┐     HTTP/JSON     ┌──────────────┐
  │ asi-scan │ ───────────────> │ SandboxServer │
  │  + adapter  │ <─────────────── │  (FastAPI)    │
  └─────────────┘                   └──────────────┘
```

- The sandbox server exposes `/health`, `/submit`, `/tools/{name}`, and MCP
  endpoints over HTTP.
- All scenario YAML files are shared between Python and TS (loaded from the
  same `scenarios/builtin/` directory).
- The `SandboxClient` maps snake_case JSON responses to camelCase TypeScript
  interfaces automatically.

### Running the sandbox

```bash
# Start the Python sandbox server (from the aastf Python package)
pip install aastf
aastf serve --port 9100

# Or via Docker
docker run -p 9100:9100 ghcr.io/anonymousaak/aastf-sandbox:latest
```

## 5. Release Plan

| Phase | Version | Scope | Timeline |
|-------|---------|-------|----------|
| Alpha 1 | 0.1.0-alpha.1 | Types, SandboxClient, ScenarioLoader, Reporter | Now |
| Alpha 2 | 0.1.0-alpha.2 | AgentAdapter interface, Vercel AI adapter | +2 weeks |
| Alpha 3 | 0.1.0-alpha.3 | LangChain.js adapter, CLI runner | +4 weeks |
| Beta 1 | 0.1.0-beta.1 | Mastra + OpenAI Agents adapters, full test coverage | +6 weeks |
| GA | 0.1.0 | Stable API, docs, npm publish | +8 weeks |

### Versioning

- Follows semver. Pre-1.0 allows breaking changes in minor versions.
- Alpha releases are tagged on npm with `@alpha` dist-tag.
- The `asi-scan` package version is independent of the Python `aastf` version.

### Breaking Change Policy (Pre-GA)

- Alpha: Breaking changes allowed in any release.
- Beta: Breaking changes only in minor bumps with changelog notice.
- GA: Standard semver guarantees.

## 6. Open Questions

1. **YAML parsing:** Should `asi-scan` bundle a YAML parser (e.g. `yaml` package)
   or keep it as an optional peer dependency? Current decision: keep it out, accept
   pre-parsed objects.

2. **Streaming:** Should `SandboxClient.submitMessage` support streaming responses
   for long-running agent executions?

3. **Browser compatibility:** The current implementation uses `node:fs/promises`
   in `loadScenarioFile`. Should we provide a browser-compatible subset?

4. **Monorepo structure:** Should adapters live in this `packages/` directory
   alongside `aastf-js`, or in a separate `aastf-js-adapters` repo?
