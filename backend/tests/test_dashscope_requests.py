"""Exercise real SDK request serialization and provider failure behavior offline."""
import json
import httpx
import openai
import pytest
from utils.ai_provider import call_llm_json, model_context

@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv('LLM_PROVIDER', 'dashscope')
    for key in ('LLM_API_KEY', 'QWEN_API_KEY', 'GEMINI_API_KEY'):
        monkeypatch.setenv(key, 'test-placeholder')
    monkeypatch.setenv('LLM_BASE_URL', 'https://unconfigured.example.invalid/v1')
    monkeypatch.setenv('LLM_MODEL', 'qwen3.6-plus')
    monkeypatch.setenv('DASHSCOPE_API_KEY', 'test-placeholder')
    monkeypatch.setenv('DASHSCOPE_BASE_URL', 'https://provider.example.invalid/v1')
    monkeypatch.setenv('STRICT_LIVE_MODE', 'false')
    requests, settings = [], []
    real_client = openai.OpenAI
    def install(status=200):
        def respond(request):
            requests.append(request)
            if status != 200:
                return httpx.Response(status, json={'error': {'message': 'provider unavailable', 'type': 'server_error'}})
            return httpx.Response(200, json={'id':'test','object':'chat.completion','created':0,'model':'qwen3.6-plus','choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':'{"executive_summary":"Observed headers reviewed."}'}}]})
        def client(**kwargs):
            settings.append(kwargs)
            return real_client(**kwargs, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
        monkeypatch.setattr(openai, 'OpenAI', client)
    return install, requests, settings


def test_dashscope_json_request_has_bounded_non_thinking_output(provider):
    install, requests, settings = provider; install()
    result = call_llm_json('Analyze observed headers. Return JSON.', timeout=30, strict_live=True)
    body = json.loads(requests[0].content)
    assert body['enable_thinking'] is False
    assert body['response_format'] == {'type':'json_object'}
    assert 256 <= body['max_tokens'] <= 2048
    assert settings[0]['max_retries'] == 0
    assert result['_model_used'] == 'qwen3.6-plus'
    assert result['_provenance'] == 'LLM_REASONING'


@pytest.mark.parametrize('strict', [False, True])
def test_dashscope_failure_does_not_retry_or_switch_provider(provider, strict):
    install, requests, settings = provider; install(503)
    if strict:
        with pytest.raises(RuntimeError, match='DashScope'):
            call_llm_json('Return JSON.', timeout=1, strict_live=True)
    else:
        result = call_llm_json('Return JSON.', timeout=1)
        assert result['_provenance'] == 'LLM_REASONING_FAILED'
    assert len(requests) == 1
    assert len(settings) == 1


def test_explicit_model_is_not_silently_substituted(provider):
    install, requests, _ = provider; install()
    with model_context('deepseek-chat'):
        call_llm_json('Return JSON.')
    assert json.loads(requests[0].content)['model'] == 'deepseek-chat'


def test_threat_intelligence_requests_the_json_object_it_consumes(monkeypatch):
    from agents.threat_intel_agent import _query_nvd_ai
    calls = []
    def complete(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return {'cve_matches': [], '_provenance':'LLM_REASONING'}
    monkeypatch.setattr('agents.threat_intel_agent.call_llm_json', complete)
    assert _query_nvd_ai(['Example 1.0']) == []
    assert '"cve_matches"' in calls[0][0]
    assert calls[0][1]['timeout'] == 30
