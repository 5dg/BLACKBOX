"""BLACKBOX: safe, deterministic security investigation API."""

from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, status
from pydantic import BaseModel, Field

app = FastAPI(title="BLACKBOX", version="0.1.0")
_investigations: list[dict] = []
_severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}


class InvestigationRequest(BaseModel):
    alert_id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=64)
    event_type: Literal["process_execution"]
    process: str = Field(min_length=1, max_length=260)
    parent_process: str = Field(min_length=1, max_length=260)
    user: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    network_indicator: str | None = Field(default=None, max_length=255)


@app.get("/api/health")
def health() -> dict:
    """Expose the operational mode without overstating platform capability."""
    return {
        "status": "operational",
        "service": "blackbox",
        "mode": "analysis_only",
        "live_connectors_enabled": False,
    }


@app.post("/api/investigate", status_code=status.HTTP_201_CREATED)
def investigate(alert: InvestigationRequest) -> dict:
    """Analyze submitted telemetry without executing any host or network action."""
    powershell_from_word = (
        alert.process.lower() == "powershell.exe"
        and alert.parent_process.lower() == "winword.exe"
    )
    suspicious_indicator = alert.network_indicator == "malicious-domain.test"

    investigation = {
        "alert_id": alert.alert_id,
        "source": alert.source,
        "event_type": alert.event_type,
        "process": alert.process,
        "parent_process": alert.parent_process,
        "user": alert.user,
        "host": alert.host,
        "severity": "high" if powershell_from_word else "medium",
        "summary": (
            "Microsoft Word spawned PowerShell."
            if powershell_from_word
            else f"{alert.parent_process} spawned {alert.process}."
        ),
        "mitre_mappings": [
            {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "confidence": "high",
            }
        ] if alert.process.lower() == "powershell.exe" else [],
        "intelligence": {
            "indicator": alert.network_indicator,
            "reputation": "suspicious" if suspicious_indicator else "unknown",
            "source": "deterministic-demo-catalog",
        },
        "risk_factors": [
            factor
            for factor, present in [
                ("Unexpected process chain", powershell_from_word),
                ("User-driven execution", powershell_from_word),
                ("Network communication observed", bool(alert.network_indicator)),
            ]
            if present
        ],
        "confidence": 0.89 if powershell_from_word else 0.55,
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "safety": {
            "analysis_only": True,
            "host_activity_performed": False,
            "network_activity_performed": False,
            "note": "BLACKBOX analyzes submitted telemetry only; it never executes endpoint actions.",
        },
    }
    _investigations.append(investigation)
    return investigation


@app.get("/api/investigations")
def list_investigations() -> dict:
    """Return newest-first investigations and analyst-facing queue metrics."""
    items = list(reversed(_investigations))
    return {
        "total": len(items),
        "items": items,
        "summary": {
            "high_severity": sum(item["severity"] == "high" for item in items),
            "open_investigations": sum(item["status"] == "open" for item in items),
            "analysis_mode": "submitted_telemetry_only",
        },
    }


@app.get("/api/reports/latest")
def latest_report() -> dict:
    """Produce an analyst-review report from stored, submitted telemetry."""
    priority_alert = max(
        _investigations,
        key=lambda item: (_severity_rank[item["severity"]], item["created_at"]),
        default=None,
    )
    return {
        "portfolio_status": "analyst_review_required",
        "total_investigations": len(_investigations),
        "priority_alert": priority_alert,
        "recommendations": [
            "Validate the process lineage against approved business activity.",
            "Review related endpoint and network telemetry before containment decisions.",
        ],
        "safety": {
            "analysis_only": True,
            "host_activity_performed": False,
            "network_activity_performed": False,
            "note": "Recommendations require human validation; BLACKBOX does not perform response actions.",
        },
    }
