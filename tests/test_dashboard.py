from fastapi.testclient import TestClient

from blackbox_api.main import app


def test_api_root_does_not_serve_a_web_dashboard():
    response = TestClient(app).get("/")

    assert response.status_code == 404
