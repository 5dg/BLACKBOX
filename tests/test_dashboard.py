from fastapi.testclient import TestClient

from blackbox_api.main import app


client = TestClient(app)


def test_dashboard_serves_blackbox_brand_and_visible_analysis_only_boundary():
    response = client.get("/")

    assert response.status_code == 200
    assert "BLACKBOX" in response.text
    assert "ANALYSIS ONLY" in response.text
    assert "No endpoint actions are performed" in response.text
    assert "/api/investigations" in response.text
