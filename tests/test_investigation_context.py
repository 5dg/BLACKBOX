from fastapi.testclient import TestClient

from blackbox_api.main import app


def test_investigation_preserves_alert_identity_fields_for_dashboard_rendering():
    response = TestClient(app).post(
        "/api/investigate",
        json={
            "alert_id": "ALRT-CONTEXT-1",
            "source": "EDR",
            "event_type": "process_execution",
            "process": "cmd.exe",
            "parent_process": "explorer.exe",
            "user": "employee01",
            "host": "WORKSTATION-22",
        },
    )

    assert response.status_code == 201
    investigation = response.json()
    assert investigation["host"] == "WORKSTATION-22"
    assert investigation["source"] == "EDR"
    assert investigation["process"] == "cmd.exe"
