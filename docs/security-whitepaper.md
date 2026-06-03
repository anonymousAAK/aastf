# AASTF Security Whitepaper

This document describes the security posture of **AASTF itself** — the tool you
install and run — not the agents it tests. AASTF executes attacker-derived
content (adversarial scenarios, third-party scenario packs) and can be wired to
outbound integrations, so the tool has its own threat model. This whitepaper
states that threat model and documents **only the controls that genuinely exist
in the codebase today**. It does not describe aspirational or planned controls.

> Scope note: this is about the safety of running AASTF. For how AASTF tests the
> *security of your agent*, see the README and the OWASP ASI scenario docs.

---

## 1. Threat model

AASTF processes inputs that are, by design, hostile or untrusted:

- **Adversarial scenario payloads.** Built-in and user/third-party scenarios
  contain attack strings (prompt-injection text, shell commands, URLs). These
  are rendered as templates before being fed to the agent under test.
- **Third-party scenario packs.** Operators can point AASTF at scenario
  directories they did not author (community packs, shared YAML files).
- **Operator-supplied destinations.** Optional integrations accept URLs for
  webhooks, Slack, and SARIF push.

From these inputs we identify the following threats to the **tool**:

| # | Threat | Vector |
|---|--------|--------|
| T1 | Server-Side Template Injection (SSTI) | A malicious scenario payload reaches Python internals during Jinja2 rendering (e.g. `{{ ''.__class__.__mro__... }}`) |
| T2 | Code execution via "custom evaluator" | A scenario names a Python callable that the tool imports and runs |
| T3 | Path traversal / symlink escape | A scenario directory path or a symlinked file reads/loads files outside the intended root |
| T4 | Silent detection-rule loss | Duplicate YAML keys collapse, dropping detection signatures without warning |
| T5 | Data exfiltration / SSRF via outbound integrations | An outbound URL points at `file://`, an internal service, or an unexpected scheme |
| T6 | Unexpected network egress | The tool transmits scan data off-host without operator intent |

The controls below address each of these. AASTF makes **no** claim to defend
against threats outside this list (for example, it does not sandbox the host OS,
and it trusts the agent factory code the operator points it at).

---

## 2. Controls that exist in code

### 2.1 Sandboxed Jinja2 rendering (mitigates T1)

Scenario payloads are rendered with Jinja2's `SandboxedEnvironment`, not a plain
`Environment`. The sandbox blocks access to Python internals and unsafe
attributes, so an attacker-controlled payload cannot pivot from template
rendering into arbitrary attribute traversal / SSTI. `StrictUndefined` is used so
that missing variables fail loudly rather than rendering silently.

- Implementation: `src/aastf/scenarios/loader.py` (`_jinja_env = SandboxedEnvironment(...)`, used by `render_payload`).

### 2.2 Custom evaluators disabled (mitigates T2)

The scenario schema retains a `custom_evaluator` field for forward
compatibility, but **dynamic import of that callable has been removed** because
it is a code-injection vector. At runtime a populated `custom_evaluator` is
ignored and a warning is logged — it can never cause the tool to import or
execute operator/scenario-named code.

- Implementation: `src/aastf/runner.py` (the `custom_evaluator` no-op path).

### 2.3 Path-traversal and symlink-escape guards (mitigates T3)

When loading a scenario directory, AASTF:

- rejects any path containing `..` components before resolution, and
- for each discovered `*.yaml` file, verifies the **resolved** path is still
  inside the resolved root using `Path.is_relative_to`, skipping any file that
  resolves outside it (defeating symlink-escape tricks).

- Implementation: `src/aastf/scenarios/loader.py` (`load_directory`).

### 2.4 Duplicate-key-rejecting YAML loader (mitigates T4)

YAML is parsed with a custom `SafeLoader` subclass that raises a
`ConstructorError` on duplicate mapping keys instead of silently keeping the last
value. This prevents a class of silent data loss where repeated keys (for
example multiple `tool_input_contains` patterns under one tool name) would
collapse and quietly drop detection signatures. It applies to both built-in
scenarios and third-party packs.

- Implementation: `src/aastf/scenarios/loader.py` (`_UniqueKeyLoader`, `_construct_mapping_no_dups`).

### 2.5 http(s)-only outbound URL validation (mitigates T5)

Every operator-supplied outbound destination is passed through
`validate_outbound_url` before any request is made. The validator:

- allows **only** the `http` and `https` schemes, rejecting `file://`,
  `ftp://`, `gopher://` and other handlers that Python's default opener would
  otherwise enable (which would turn "send results to my webhook" into a
  local-file read or SSRF probe against non-web services), and
- rejects URLs with no host.

On a disallowed URL the send is refused (the alerting path logs the error and
returns a non-success status) rather than proceeding.

- Implementation: `src/aastf/netsec.py` (`validate_outbound_url`, `UnsafeURLError`); enforced at the send path in `src/aastf/alerting.py`.

### 2.6 No phone-home by default (mitigates T6)

AASTF performs all scanning locally and does **not** transmit scan data to any
external server unless the operator explicitly configures an outbound
integration (`--webhook-url`, SARIF push, or alerting). There is no default
telemetry. When an integration is configured, the URL validation in §2.5
applies. Agent testing itself runs against a local sandbox, not production
systems.

- Consistent with `SECURITY.md` ("Local by default / no phone-home").

---

## 3. Control-to-threat coverage

| Threat | Control |
|--------|---------|
| T1 — SSTI | §2.1 Sandboxed Jinja2 environment |
| T2 — Custom-evaluator code execution | §2.2 Custom evaluators disabled |
| T3 — Path traversal / symlink escape | §2.3 `..` rejection + `is_relative_to` guard |
| T4 — Silent detection-rule loss | §2.4 Duplicate-key-rejecting YAML loader |
| T5 — Exfiltration / SSRF | §2.5 http(s)-only URL validation |
| T6 — Unexpected egress | §2.6 No phone-home by default |

---

## 4. Non-goals and known limitations

- AASTF does **not** sandbox the host operating system or the agent factory code
  the operator supplies; that code runs with the operator's privileges.
- The sandbox replaces tool backends to avoid real side effects, but it is not a
  general-purpose security boundary for arbitrary agent code.
- Controls here defend the tool against hostile *scenario content and
  configuration*; they are not a substitute for running AASTF in an environment
  appropriate to the secrets (e.g. API keys) it is given.

To report a vulnerability in AASTF, see [SECURITY.md](../SECURITY.md).
