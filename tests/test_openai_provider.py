import json

from blackbox_api.llm_harness import OpenAICompatibleProvider


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, size=None) -> bytes:
        payload = json.dumps(self.payload).encode("utf-8")
        return payload if size is None else payload[:size]


def test_openai_compatible_provider_uses_fixed_endpoint_and_returns_model_content():
    captured = {}

    def transport(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"summary":"ok","hypotheses":["h"],"missing_evidence":[],"analyst_questions":["q"],"confidence":"low","evidence_refs":["process"]}'
                        }
                    }
                ]
            }
        )

    provider = OpenAICompatibleProvider(
        base_url="https://llm.example/v1",
        api_key="test-value",
        model="analysis-model",
        timeout_s=12,
        transport=transport,
        allowed_hosts={"llm.example"},
    )

    content = provider.complete("evidence prompt")

    assert json.loads(content)["summary"] == "ok"
    assert captured["url"] == "https://llm.example/v1/chat/completions"
    assert captured["authorization"] == "Bearer test-value"
    assert captured["payload"]["model"] == "analysis-model"
    assert captured["payload"]["messages"][0]["role"] == "system"
    assert captured["payload"]["messages"][1]["content"] == "evidence prompt"
    assert captured["timeout"] == 12
