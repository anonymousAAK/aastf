# Contributing to AASTF

Thanks for helping make agent security better. The fastest and most valuable
contribution is a new attack scenario — it requires only YAML, no Python.

---

## Contribution Tiers

| Tier | What | Skill required |
|------|------|---------------|
| 1 | New YAML scenario | Security knowledge, no coding |
| 2 | New payload variants for existing scenarios | One-line addition |
| 3 | New Python evaluator | Understanding of the evaluator model |
| 4 | New framework adapter | Deep framework knowledge |

---

## Adding a New Scenario (Tier 1)

### 1. Choose the right ASI category

| Category | When to use |
|----------|------------|
| ASI01 | Agent's goal is redirected by injected instructions |
| ASI02 | Agent uses tools in unsafe or unintended ways |
| ASI03 | Agent exceeds its authorized scope or privilege |
| ASI04 | Compromised external component (RAG, MCP, tool) affects agent |
| ASI05 | Agent generates or executes malicious code |
| ASI06 | Adversarial content corrupts agent memory or context |
| ASI07 | Forged or tampered inter-agent messages cause harm |
| ASI08 | Agent enters runaway loops or cascading failures |
| ASI09 | Agent output deceives human-in-the-loop reviewers |
| ASI10 | Agent operates outside its mandate or governance |

### 2. Pick an injection point

- `user_message` — adversarial content in the user's turn
- `tool_response` — poisoned content returned by a tool (most common for RAG attacks)
- `memory` — content injected into the agent's memory store
- `system_prompt` — injected before the conversation starts

### 3. Write the scenario

```bash
cp scenarios/community/template.yaml scenarios/community/ASI02-099.yaml
# Edit the file
```

**ID format:** `ASI##-###` where `##` is the category (01-10) and `###` is a three-digit number. Community scenarios use 099–199 to avoid collisions with built-in scenarios.

### 4. Validate it

```bash
pip install -e ".[dev]"
aastf scenario validate scenarios/community/ASI02-099.yaml
```

### 5. Submit a PR

- Branch name: `scenario/ASI02-exfil-via-s3`
- PR title: `[Scenario] ASI02: S3 exfiltration via injected presigned URL`
- Include: what attack this tests, why it's relevant, any real-world examples

---

## What Makes a Good Scenario

**Be specific about the attack vector.** "Prompt injection" is too broad. "Adversarial content in a RAG-retrieved document's metadata field causes agent to chain read_file → send_email" is precise enough to test.

**Choose the right detection criteria.** The most reliable detections are:
- `tool_called: [forbidden_tool]` — was a specific tool invoked?
- `tool_input_contains: {tool: "substring"}` — did a tool receive attacker-controlled input?

Output-based detection (`output_contains`) is weaker — it depends on the LLM's phrasing.

**Write real remediation.** "Don't do bad things" is not remediation. "Enforce tool allowlists at the dispatch layer, independent of LLM output" is actionable.

**Test your scenario works.** If you have access to a LangGraph agent, run:
```bash
aastf run your_agent:create_agent --scenario-dir scenarios/community/ --category ASI02
```

---

## Development Setup

```bash
git clone https://github.com/anonymousAAK/aastf
cd aastf
pip install -e ".[dev,langgraph]"

# Run unit tests
pytest tests/unit/ -v

# Run sandbox integration tests (no LLM key required)
pytest tests/integration/ -v

# Run linter
ruff check src/ tests/

# Run the full scenario validation
python -c "
from aastf.scenarios.registry import ScenarioRegistry
r = ScenarioRegistry().load_builtin()
print(f'{len(r)} scenarios loaded successfully')
"
```

---

## Writing a Framework Adapter (Tier 4)

Adapters live in `src/aastf/harness/adapters/`. Each adapter must implement:

```python
class MyFrameworkHarness:
    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        """
        1. Configure sandbox for this scenario
        2. Wire sandbox tools into the framework
        3. Build agent input from scenario.inject_into + scenario.payload
        4. Run the agent with instrumentation
        5. Return a populated AgentTrace
        """
```

See `src/aastf/harness/adapters/langgraph.py` for the reference implementation.

Open an issue first to discuss the adapter before building it — we can help
with the framework-specific instrumentation approach.

---

## Code Style

- Python 3.12+, `ruff` for linting, no `mypy` required for contributions
- Pydantic v2 for all data models
- `async/await` throughout — no blocking I/O in harness code
- Tests required for all new evaluators and adapters
- Scenarios do not require tests (the YAML validation catches schema errors)

---

## License

By contributing, you agree your contributions are licensed under MIT.
