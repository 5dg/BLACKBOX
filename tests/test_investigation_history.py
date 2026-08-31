from fastapi.testclient import TestClient

from blackbox_api.main import app


client = TestClient(app)


def _alert(alert_id: str, process: str = "powershell.exe") -> dict:
    return {
        "alert_id": alert_id,
        "source": "EDR",
        "event_type": "process_execution",
        "process": process,
        "parent_process": "winword.exe",
        "user": "employee01",
        "host": "WORKSTATION-22",
        "network_indicator": "malicious-domain.test",
    }


def test_investigation_history_is_newest_first_and_returns_summary_metrics():
    client.post("/api/investigate", json=_alert("ALRT-HISTORY-1", "cmd.exe"))
    client.post("/api/investigate", json=_alert("ALRT-HISTORY-2"))

    response = client.get("/api/investigations")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 2
    assert payload["items"][0]["alert_id"] == "ALRT-HISTORY-2"
    assert payload["summary"]["high_severity"] >= 1
    assert payload["summary"]["analysis_mode"] == "submitted_telemetry_only"


def test_report_identifies_the_highest_severity_open_investigation_as_priority():
    client.post("/api/investigate", json=_alert("ALRT-REPORT-LOW", "cmd.exe"))
    client.post("/api/investigate", json=_alert("ALRT-REPORT-HIGH"))

    response = client.get("/api/reports/latest")

    assert response.status_code == 200
    payload = response.json()
    assert payload["portfolio_status"] == "analyst_review_required"
    assert payload["priority_alert"]["alert_id"] == "ALRT-REPORT-HIGH"
    assert payload["safety"]["analysis_only"] is True
