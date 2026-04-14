"""Configuration models for AASTF runs."""

from typing import Literal

from pydantic import BaseModel, Field


class SandboxConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 0  # 0 = auto-assign a free port
    log_all_requests: bool = True
    simulate_latency: bool = False
    default_response_mode: Literal["success", "error"] = "success"


class FrameworkConfig(BaseModel):
    adapter: Literal["langgraph", "openai_agents", "crewai", "pydantic_ai", "generic"]
    agent_factory: str  # dotted path e.g. "myapp.agent:create_agent"
    categories: list[str] = Field(default_factory=list)  # empty = all categories
    scenario_dirs: list[str] = Field(default_factory=list)
    exclude_scenarios: list[str] = Field(default_factory=list)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    output_dir: str = "aastf-results"
    report_formats: list[Literal["json", "sarif", "html", "console"]] = ["console", "json"]
    fail_on_severity: str | None = "HIGH"
    timeout_seconds: float = 30.0
    max_iterations: int = 25
    run_variants: bool = False
    parallel_workers: int = 1  # serial by default; Week 10 adds parallelism
