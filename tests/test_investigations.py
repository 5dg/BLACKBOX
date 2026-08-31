from fastapi.testclient import TestClient

from blackbox_api.main import app


client = TestClient(app)


def test_investigate_returns_deterministic_analysis_with_safety_boundary():
    response = client.post(
        "/api/investigate",
        json={
            "alert_id": "ALRT-1001",
            "source": "EDR",
            "event_type": "process_execution",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "user": "employee01",
            "host": "WORKSTATION-22",
            "network_indicator": "malicious-domain.test",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["alert_id"] == "ALRT-1001"
    assert payload["severity"] == "high"
    assert payload["mitre_mappings"] == [
        {
            "technique_id": "T1059.001",
            "technique_name": "Command and Scripting Interpreter: PowerShell",
            "confidence": "high",
        }
    ]
    assert payload["intelligence"]["reputation"] == "suspicious"
    assert payload["safety"]["analysis_only"] is True
    assert payload["safety"]["host_activity_performed"] is False
