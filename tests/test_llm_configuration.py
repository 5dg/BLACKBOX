from blackbox_api.llm_harness import build_harness_from_environment


def test_environment_configuration_creates_an_openai_compatible_harness(monkeypatch):
    monkeypatch.setenv("BLACKBOX_LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("BLACKBOX_LLM_BASE_URL", "https://llm.example/v1")
    monkeypatch.setenv("BLACKBOX_LLM_API_KEY", "test-value")
    monkeypatch.setenv("BLACKBOX_LLM_MODEL", "analysis-model")

    harness = build_harness_from_environment()

    assert harness is not None
    assert harness.provider_name == "openai_compatible"
    assert harness.model == "analysis-model"
