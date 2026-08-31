# BLACKBOX

> **Backend-first security investigation API for analyst review.**

[![Status: active development](https://img.shields.io/badge/status-active%20development-3b82f6)](https://github.com/5dg/blackbox)
[![Domain: SOC automation](https://img.shields.io/badge/domain-SOC%20automation-22c55e)](https://github.com/5dg/blackbox)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-f59e0b)](https://attack.mitre.org/)
[![CI](https://github.com/5dg/blackbox/actions/workflows/ci.yml/badge.svg)](https://github.com/5dg/blackbox/actions/workflows/ci.yml)

## What BLACKBOX is for

**BLACKBOX turns submitted security telemetry into an explainable investigation record that an analyst can review.** It accepts one process-execution alert, normalizes the relevant context, applies deterministic enrichment and ATT&CK mappings, calculates a priority level, and returns a structured investigation result.

The project is built around a SOC-triage problem:

> *When an alert reaches an analyst, can we transform the raw fields into a clear, repeatable explanation of why it may matter and what should be reviewed next?*

BLACKBOX is a portfolio-quality backend foundation for that workflow. It demonstrates strict API contracts, explainable analysis logic, safety-oriented reporting, investigation queues, and analyst-in-the-loop boundaries without claiming to be a complete SOC platform.

> **Read-only analysis boundary:** BLACKBOX analyzes only telemetry submitted to its API. It does not execute scripts, issue endpoint commands, scan hosts, contact indicators, collect credentials, query a live SIEM/EDR, call a threat-intelligence service, or perform containment/remediation.

---

## The investigation model

BLACKBOX uses a **deterministic baseline first** and an optional, bounded LLM layer second. The deterministic result is always preserved; an LLM can add an analyst brief only when the caller explicitly requests it and an approved provider has been configured.

### Accepted telemetry

`POST /api/investigate` accepts a `process_execution` event with:

- an alert identifier and source;
- process name and parent process name;
- user and host context; and
- an optional network indicator.

All fields are length-bounded and validated by Pydantic before analysis begins.

### Deterministic analysis rules

The built-in engine currently evaluates these explainable conditions:

| Observed condition | Result |
|---|---|
| `winword.exe` launches `powershell.exe` | `high` severity, Word → PowerShell risk factors, ATT&CK `T1059.001` mapping |
| Any other supported process chain | `medium` severity, process-chain summary, no PowerShell mapping |
| Indicator equals `malicious-domain.test` | `suspicious` reputation from the deterministic demo catalog |
| Any other/no indicator | `unknown` reputation; BLACKBOX does not perform a lookup |

The explicit rules are deliberate: they make the output testable, reproducible, and safe to use in demos or training. A future intelligence or LLM layer must preserve the same explainability, redaction, and human-approval principles.

### Investigation output

Each created investigation includes:

- original alert context: ID, source, event type, process, parent process, user, and host;
- severity, confidence, and a plain-language summary;
- ATT&CK mappings when the process behavior matches the catalog rule;
- deterministic reputation metadata;
- explainable risk factors;
- creation timestamp and investigation status; and
- a complete non-execution safety contract.

The safety object consistently states:

```json
{
  "analysis_only": true,
  "host_activity_performed": false,
  "network_activity_performed": false
}
```

### Optional LLM analyst harness

When an investigation request includes `"enable_llm": true`, BLACKBOX can invoke an **approved OpenAI-compatible provider** only if the service was configured with that provider at startup. The LLM layer is disabled by default.

The harness is deliberately constrained:

1. **The deterministic baseline runs first.** Severity, ATT&CK mapping, risk factors, and safety fields are never delegated to the model.
2. **Only a minimal evidence package is sent.** It includes `source`, `event_type`, `process`, and `parent_process`. Alert ID, user, host, and network indicator are redacted.
3. **Telemetry is framed as untrusted data.** The provider prompt explicitly instructs the model not to treat evidence as instructions.
4. **The provider endpoint is configuration-only.** A request cannot supply a model URL, key, or arbitrary connector target.
5. **Only strict JSON output is accepted.** The model may return an analyst summary, hypotheses, missing evidence, analyst questions, confidence, and references to allowlisted evidence fields.
6. **Every result carries audit metadata.** BLACKBOX stores provider/model identity, a hash of the sanitized prompt, redacted-field names, and output-schema version—not the raw prompt or provider key.
7. **The model cannot act.** It receives no tools, shell access, endpoint access, network-scanning capability, containment path, or arbitrary URL-fetch capability.

An LLM brief is optional context for a human analyst. It does not change the deterministic finding or authorize any response action.

---

## Typical workflow

```text
Security tool, lab fixture, or test harness
                  │
                  ▼
       POST submitted process telemetry
                  │
                  ▼
     FastAPI validation and field bounds
                  │
                  ▼
    Deterministic investigation engine
      ├── process-chain interpretation
      ├── ATT&CK mapping
      ├── demo-catalog enrichment
      └── risk-factor generation
                  │
                  ▼
      In-memory investigation queue
                  │
                  ▼
   API report for analyst review and prioritization
```

The caller—not BLACKBOX—owns telemetry collection and any decision to investigate or respond. BLACKBOX produces context; an authorized analyst remains responsible for validation and action.

---

## API reference

The service exposes OpenAPI documentation at `/docs`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Returns operational status, analysis-only mode, and connector state. |
| `POST` | `/api/investigate` | Creates one investigation record from submitted process telemetry. |
| `GET` | `/api/investigations` | Returns newest-first queue entries and summary metrics. |
| `GET` | `/api/reports/latest` | Returns the highest-priority investigation and analyst-review recommendations. |

### Submit an investigation

Set `BLACKBOX_URL` to the base URL of the deployment you are using.

```bash
curl -X POST "$BLACKBOX_URL/api/investigate" \
  -H 'content-type: application/json' \
  -d '{
    "alert_id":"ALRT-1001",
    "source":"EDR",
    "event_type":"process_execution",
    "process":"powershell.exe",
    "parent_process":"winword.exe",
    "user":"employee01",
    "host":"WORKSTATION-22",
    "network_indicator":"malicious-domain.test",
    "enable_llm":true
  }'
```

The response represents an analyst-review starting point. It is not proof of compromise and does not instruct or initiate containment.

### Read the queue and priority report

```bash
curl "$BLACKBOX_URL/api/investigations"
curl "$BLACKBOX_URL/api/reports/latest"
```

---

## LLM provider configuration

The LLM harness is **off by default**. To enable the OpenAI-compatible adapter, configure the service environment before startup:

| Variable | Required when enabled | Purpose |
|---|---:|---|
| `BLACKBOX_LLM_PROVIDER` | Yes | Must be `openai_compatible`. Any other value keeps the harness disabled. |
| `BLACKBOX_LLM_BASE_URL` | Yes | Fixed HTTPS base URL for the approved provider. |
| `BLACKBOX_LLM_API_KEY` | Yes | Provider credential; never send it through the investigation API or commit it to Git. |
| `BLACKBOX_LLM_MODEL` | Yes | Model identifier selected by the deployment owner. |

If configuration is missing or invalid, BLACKBOX remains available for deterministic analysis and an opt-in LLM request returns a disabled/unavailable status rather than failing the core investigation flow.

---

## Storage behavior

BLACKBOX stores investigations **in memory**. This keeps the MVP self-contained and makes it suitable for automated tests, demos, disposable lab deployments, and API integration exercises.

It also means:

- data is lost when the process restarts;
- there is no user account, tenant, or case-management layer; and
- it is not appropriate for production retention requirements.

A production implementation would replace the in-memory list with a durable repository, migrations, audit history, access controls, retention policies, and queue/worker infrastructure.

---

## What this project demonstrates

BLACKBOX is meant to show practical backend/security-engineering skills:

- FastAPI endpoint design and OpenAPI documentation;
- typed request validation and bounded user-controlled fields;
- transparent rule-based security analysis;
- ATT&CK-aligned output and analyst-oriented reporting;
- safe handling of submitted telemetry without live collection or response actions;
- an opt-in LLM harness with evidence minimization, prompt-injection boundaries, schema validation, provider isolation, and audit metadata;
- unit/integration API tests;
- deterministic, repeatable test fixtures;
- dependency locking, wheel packaging, Docker configuration, and GitHub Actions CI; and
- clear documentation of what the system does and does not claim to do.

---

## Run and verify

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --dev
uv run uvicorn blackbox_api.main:app
```

Run the quality gates:

```bash
uv run pytest -q
uv run python -m compileall -q blackbox_api
uv build
```

A Dockerfile is included for containerized API deployment.

---

## Roadmap

The next legitimate expansion points are deliberately defensive and analyst-focused:

- PostgreSQL-backed case and investigation storage;
- authenticated analyst workflow and role-based access;
- immutable audit records and retention controls;
- rate limiting, structured logging, and deployment observability;
- approved, read-only SIEM/EDR and threat-intelligence adapters;
- retrieval over approved internal detection documentation; and
- multi-provider LLM support with deployment-level data governance, citations, and mandatory human review.

None of those additions should introduce endpoint control, scanning, live execution, or autonomous response.

---

## Responsible use

BLACKBOX is designed for authorized defensive security operations, education, and controlled lab environments.

It analyzes caller-supplied telemetry only. The maintainer does not authorize misuse, and each operator is responsible for obtaining permission and complying with applicable law, organizational policy, and provider terms. This project does not grant permission to access or test systems, accounts, or data outside the operator’s control.

BLACKBOX is released under the [MIT License](LICENSE).
