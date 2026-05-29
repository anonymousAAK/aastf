/**
 * Barrel exports for AASTF adapters.
 */

export { BaseAdapter } from "./base.js";
export type { AdapterConfig } from "./base.js";

export { OpenAIAgentsAdapter } from "./openai-agents.js";
export type { OpenAIAgentsAdapterConfig } from "./openai-agents.js";

export { LangChainAdapter } from "./langchainjs.js";
export type { LangChainAdapterConfig } from "./langchainjs.js";

export { MastraAdapter } from "./mastra.js";
export type { MastraAdapterConfig, MastraStepResult } from "./mastra.js";

export { VercelAIAdapter } from "./vercel-ai.js";
export type {
  VercelAIAdapterConfig,
  VercelAIToolCall,
  VercelAIToolResult,
} from "./vercel-ai.js";
