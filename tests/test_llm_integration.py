from fastapi.testclient import TestClient

from blackbox_api import main
from blackbox_api.llm_harness import LLMHarness, StaticJSONProvider


def test_opt_in_llm_analysis_is_added_to_investigation_with_audit_metadata(monkeypatch):
    provider = StaticJSONProvider(
        {
            "summary": "The process lineage merits validation against expected document workflows.",
            "hypotheses": ["A user-initiated script execution may have occurred."],
            "missing_evidence": ["Command-line telemetry"],
            "analyst_questions": ["Is this parent-child relationship expected?"],
            "confidence": "medium",
            "evidence_refs": ["process", "parent_process"],
        }
    )
    harness = LLMHarness(
        provider=provider,
        provider_name="test-provider",
        model="test-model",
    )
    monkeypatch.setattr(main, "llm_harness", harness)

    response = TestClient(main.app).post(
        "/api/investigate",
        json={
            "alert_id": "ALRT-LLM-1",
            "source": "EDR",
            "event_type": "process_execution",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "user": "employee01",
            "host": "WORKSTATION-22",
            "enable_llm": True,
        },
    )

    assert response.status_code == 201
    assistance = response.json()["llm_assistance"]
    assert assistance["status"] == "completed"
    assert assistance["provider"] == "test-provider"
    assert assistance["analysis"]["confidence"] == "medium"
    assert assistance["audit"]["redacted_fields"] == ["alert_id", "user", "host"]
    assert response.json()["safety"]["provider_network_activity_performed"] is True
    assert "employee01" not in provider.last_prompt
    assert "WORKSTATION-22" not in provider.last_prompt
    assert "ALRT-LLM-1" not in provider.last_prompt
