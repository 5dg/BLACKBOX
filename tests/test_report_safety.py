from fastapi.testclient import TestClient

from blackbox_api.main import app


def test_report_repeats_the_complete_non_execution_safety_contract():
    response = TestClient(app).get("/api/reports/latest")

    assert response.status_code == 200
    assert response.json()["safety"] == {
        "analysis_only": True,
        "host_activity_performed": False,
        "network_activity_performed": False,
        "note": "Recommendations require human validation; BLACKBOX does not perform response actions.",
    }
