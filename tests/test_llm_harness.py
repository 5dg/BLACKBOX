from blackbox_api.llm_harness import LLMHarness, StaticJSONProvider


def test_harness_redacts_identity_fields_and_returns_schema_valid_analyst_brief():
    provider = StaticJSONProvider(
        {
            "summary": "The parent-child process relationship warrants analyst review.",
            "hypotheses": ["A document-originated script execution may require validation."],
            "missing_evidence": ["Command-line telemetry"],
            "analyst_questions": ["Is this process chain approved for the user?"],
            "confidence": "medium",
            "evidence_refs": ["event_type", "process", "parent_process"],
        }
    )
    harness = LLMHarness(provider=provider, provider_name="test-provider", model="test-model")

    result = harness.analyze(
        {
            "alert_id": "ALRT-SECRET-42",
            "source": "EDR",
            "event_type": "process_execution",
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "user": "employee01",
            "host": "WORKSTATION-22",
            "network_indicator": "malicious-domain.test",
        },
        {
            "severity": "high",
            "risk_factors": ["Unexpected process chain"],
            "mitre_mappings": [{"technique_id": "T1059.001"}],
        },
    )

    assert result["status"] == "completed"
    assert result["provider"] == "test-provider"
    assert result["model"] == "test-model"
    assert result["analysis"]["confidence"] == "medium"
    assert result["analysis"]["evidence_refs"] == [
        "event_type",
        "process",
        "parent_process",
    ]
    assert result["audit"]["redacted_fields"] == [
        "alert_id",
        "user",
        "host",
        "network_indicator",
    ]
    assert len(result["audit"]["prompt_sha256"]) == 64
    assert "employee01" not in provider.last_prompt
    assert "WORKSTATION-22" not in provider.last_prompt
    assert "malicious-domain.test" not in provider.last_prompt
