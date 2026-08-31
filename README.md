# BLACKBOX

> **Backend-first, AI-assisted security investigation for analyst review — built as a safe, defensive portfolio project.**

[![Status: active development](https://img.shields.io/badge/status-active%20development-3b82f6)](https://github.com/5dg/blackbox)
[![Domain: SOC automation](https://img.shields.io/badge/domain-SOC%20automation-22c55e)](https://github.com/5dg/blackbox)
[![Framework: MITRE ATT&CK](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-f59e0b)](https://attack.mitre.org/)
[![CI](https://github.com/5dg/blackbox/actions/workflows/ci.yml/badge.svg)](https://github.com/5dg/blackbox/actions/workflows/ci.yml)

BLACKBOX turns submitted security telemetry into investigation-ready API records: normalized context, deterministic intelligence enrichment, MITRE ATT&CK mappings, risk factors, analyst recommendations, and priority reporting.

It is intentionally a **read-only analysis MVP**. It never executes scripts, sends endpoint commands, scans a host, contacts indicators, or takes containment actions.

## What it demonstrates

- Typed alert ingestion through FastAPI
- Process-chain analysis for suspicious Office → PowerShell behavior
- MITRE ATT&CK mapping for PowerShell (`T1059.001`)
- Deterministic intelligence enrichment for safe demonstration data
- Investigation queue and analyst-facing reports through an API
- Preserved source, process, user, and host context in investigation output
- Human-in-the-loop boundary repeated in the API contract and reports
- Automated tests, lockfile, wheel packaging, Docker configuration, and GitHub Actions CI

## Architecture

```text
Submitted telemetry
       │
       ▼
FastAPI validation ──► deterministic investigation engine
       │                         │
       │                         ├── process-chain context
       │                         ├── MITRE ATT&CK mapping
       │                         └── demo intelligence catalog
       ▼
In-memory investigation queue ──► analyst report API
```

The MVP deliberately stores investigations **in memory** so it is runnable with no external services. A production evolution would introduce PostgreSQL for durable investigations, Redis for queues/caching, vetted threat-intelligence connectors, and a retrieval layer with approved internal knowledge sources.

## Run locally

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --dev
uv run uvicorn blackbox_api.main:app
```

BLACKBOX is API-only. Use the OpenAPI route exposed by your deployment (`/docs`) or your preferred HTTP client.

Run the test suite:

```bash
uv run pytest -q
```

## API

### `POST /api/investigate`

Submits telemetry for analysis only.

```json
{
  "alert_id": "ALRT-1001",
  "source": "EDR",
  "event_type": "process_execution",
  "process": "powershell.exe",
  "parent_process": "winword.exe",
  "user": "employee01",
  "host": "WORKSTATION-22",
  "network_indicator": "malicious-domain.test"
}
```

An Office-to-PowerShell chain returns a `high` severity assessment, `T1059.001`, explainable risk factors, a `suspicious` **demo-catalog** reputation, preserved event context, and explicit `analysis_only` safety markers.

### Other endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /api/health` | Safe operational mode and connector state |
| `GET /api/investigations` | Newest-first investigation queue and summary metrics |
| `GET /api/reports/latest` | Human-review-oriented prioritization report |
| `GET /docs` | OpenAPI / Swagger interface |

## Safety boundary

BLACKBOX is designed for authorized, defensive security operations and education.

- It analyzes **submitted** telemetry only.
- It does not execute endpoint actions or investigative commands.
- It makes no automated containment or remediation decision.
- Demonstration reputation data is deterministic fixture data, **not** live threat intelligence.
- Every recommendation requires analyst validation and organizational authorization.

## Roadmap

- [x] Typed alert ingestion and explainable investigation output
- [x] MITRE mapping and safe intelligence fixture enrichment
- [x] Investigation queue, report API, and test coverage
- [ ] Persistent PostgreSQL-backed case management
- [ ] Approved, read-only intelligence and SIEM connectors
- [ ] Analyst-authenticated case workflow and audit log
- [ ] Retrieval over approved detection documentation
- [ ] Configurable LLM provider with redaction and data-governance controls

## Development notes

This is a portfolio MVP, not a substitute for a production SOC platform. Production deployment would require authentication, authorization, tenant isolation, durable audit logging, secret management, retention policies, rate limiting, privacy review, and a formal threat model.

## License

MIT. See [LICENSE](LICENSE).
