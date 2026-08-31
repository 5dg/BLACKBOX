from fastapi.testclient import TestClient

from blackbox_api.main import app


def test_dashboard_escapes_investigation_fields_before_rendering_html():
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "const escapeHtml" in response.text
    assert "${escapeHtml(item.alert_id)}" in response.text
    assert "${escapeHtml(item.host)}" in response.text
    assert "${escapeHtml(item.summary)}" in response.text
