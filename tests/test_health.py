from fastapi.testclient import TestClient

from blackbox_api.main import app


client = TestClient(app)


def test_health_describes_api_mode_without_claiming_live_connectors():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "operational",
        "service": "blackbox",
        "mode": "analysis_only",
        "live_connectors_enabled": False,
    }
