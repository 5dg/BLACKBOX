from blackbox_api.llm_harness import build_harness_from_environment


def test_invalid_or_unapproved_provider_configuration_disables_harness(monkeypatch):
    monkeypatch.setenv("BLACKBOX_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("BLACKBOX_LLM_BASE_URL", "http://unapproved.example/v1")
    monkeypatch.setenv("BLACKBOX_LLM_API_KEY", "test-value")
    monkeypatch.setenv("BLACKBOX_LLM_MODEL", "analysis-model")
    monkeypatch.setenv("BLACKBOX_LLM_ALLOWED_HOSTS", "llm.example")

    assert build_harness_from_environment() is None
