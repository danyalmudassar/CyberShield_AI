"""
CyberShield AI — Model-Agnostic LLM Provider Module
===================================================
Provides a universal, provider-agnostic interface for executing AI reasoning tasks.

Supports:
- Google Gemini API (gemini-2.5-flash, gemini-2.5-pro, gemini-1.5-flash) via GEMINI_API_KEY
- Ollama / Local Cloud Models (e.g., gemma4:31b-cloud, qwen2.5:7b)
- Cloud LLMs (Groq, OpenRouter, DeepSeek, Qwen, OpenAI)

Default Model: gemma4:31b-cloud
"""

import os
import json
import logging
from contextvars import ContextVar
from contextlib import contextmanager
from typing import Optional, Dict, Any
from dotenv import load_dotenv
from utils.anonymizer import sanitize_text

logger = logging.getLogger(__name__)

_scan_model = ContextVar("scan_model", default=None)
_last_model = ContextVar("last_model", default=None)

def configured_model() -> str:
    return _scan_model.get() or os.getenv("LLM_MODEL", os.getenv("QWEN_MODEL", "gemma4:31b-cloud"))

@contextmanager
def model_context(model: str | None = None):
    """Isolate model selection per worker without changing process environment."""
    token = _scan_model.set(model)
    usage_token = _last_model.set(None)
    try:
        yield
    finally:
        _scan_model.reset(token)
        _last_model.reset(usage_token)



# Project Root & Env Path
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ENV_PATH = os.path.join(_PROJECT_ROOT, "config", ".env")
if os.path.exists(_ENV_PATH):
    load_dotenv(_ENV_PATH)

_MOCK_QWEN_PATH = os.path.join(_PROJECT_ROOT, "mocks", "mock_qwen_response.json")


def _load_mock_json() -> Dict[str, Any]:
    """Load mock analysis from mocks/mock_qwen_response.json as fallback."""
    data = {"status": "mock", "findings": [], "executive_summary": "Mock analysis fallback."}
    try:
        if os.path.exists(_MOCK_QWEN_PATH):
            with open(_MOCK_QWEN_PATH, "r") as f:
                data = json.load(f)
    except Exception as err:
        logger.error("Failed to load mock JSON: %s", err)

    if isinstance(data, dict):
        data["_provenance"] = "MOCK_FALLBACK"
        data["_fallback_triggered"] = True
    return data




def extract_json_payload(raw_text: str) -> Dict[str, Any]:
    """Extract and parse JSON object from LLM response string."""
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [l for l in lines[1:] if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()
    
    # Try parsing direct JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Fallback: search for first { and last }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    raise ValueError("Response does not contain valid JSON")


def get_gemini_api_keys() -> list[str]:
    """Retrieve all available Gemini API keys from environment for load balancing & key rotation."""
    keys = []
    # Primary key
    k_main = os.getenv("GEMINI_API_KEY", "").strip()
    if k_main:
        keys.append(k_main)
    
    # Extra keys (GEMINI_API_KEY0, GEMINI_API_KEY1, GEMINI_API_KEY2...)
    for i in range(10):
        k_extra = os.getenv(f"GEMINI_API_KEY{i}", "").strip()
        if k_extra and k_extra not in keys:
            keys.append(k_extra)
            
    return keys


def call_llm(
    prompt: str,
    system_prompt: Optional[str] = None,
    use_mock: bool = False,
    timeout: int = 5,
    strict_live: bool = False,
    json_mode: bool = False,
) -> str:
    """Execute text generation against configured LLM provider or Gemini API."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    _last_model.set(None)
    if use_mock:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: Cannot use mock mode when strict live mode is enabled.")
        logger.info("Using mock LLM text response (use_mock=True)")
        return "CyberShield AI analysis completed via mock fallback."

    # Load fresh env values dynamically per invocation
    llm_provider = os.getenv("LLM_PROVIDER", os.getenv("AI_PROVIDER", "ollama")).lower()
    llm_api_key = os.getenv("LLM_API_KEY", os.getenv("QWEN_API_KEY", "ollama"))
    llm_base_url = os.getenv("LLM_BASE_URL", os.getenv("QWEN_BASE_URL", "http://localhost:11434/v1"))
    llm_model = configured_model()
    gemini_keys = get_gemini_api_keys()

    default_system = (
        "You are CyberShield AI, an autonomous cybersecurity analysis engine. "
        "Provide precise, professional security analysis."
    )

    # 1. Google Gemini Provider Routing (Supports Multi-Key Rotation)
    if llm_model.startswith("gemini") or llm_provider == "gemini":
        if not gemini_keys:
            if strict:
                raise RuntimeError("STRICT_LIVE_MODE: No GEMINI_API_KEY available in environment.")
            logger.warning("No GEMINI_API_KEY found in environment — utilizing fallback mock.")
            return ""

        for idx, gemini_key in enumerate(gemini_keys):
            try:
                from openai import OpenAI

                client = OpenAI(
                    api_key=gemini_key,
                    base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
                )
                response = client.chat.completions.create(
                    model=llm_model if "gemini" in llm_model else "gemini-2.5-flash",
                    messages=[
                        {"role": "system", "content": system_prompt or default_system},
                        {"role": "user", "content": prompt},
                    ],
                    timeout=timeout,
                )
                content = response.choices[0].message.content
                if content:
                    _last_model.set(llm_model if "gemini" in llm_model else "gemini-2.5-flash")
                    logger.info("Gemini OpenAI-compatible API call succeeded using Key #%d", idx)
                    return content.strip()
            except Exception as err:
                err_msg = sanitize_text(str(err))
                logger.warning("Gemini Key #%d request failed (Error: %s).", idx, err_msg[:120])

        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: All configured Gemini API keys failed.")
        return ""

    # 2. Alibaba Cloud Model Studio (DashScope) Qwen Model Routing
    dashscope_key = os.getenv("DASHSCOPE_API_KEY", os.getenv("QWEN_API_KEY", ""))
    if (llm_model.startswith("qwen") or llm_provider in ("dashscope", "bailian", "qwen")) and dashscope_key:
        try:
            from openai import OpenAI
            ds_base_url = os.getenv("DASHSCOPE_BASE_URL", "https://dashscope-intl.aliyuncs.com/compatible-mode/v1")
            client = OpenAI(api_key=dashscope_key, base_url=ds_base_url, max_retries=0)
            options = {"max_tokens": 1536}
            if llm_model.startswith("qwen3"):
                options["extra_body"] = {"enable_thinking": False}
            if json_mode:
                options["response_format"] = {"type": "json_object"}
            response = client.chat.completions.create(
                model=llm_model,
                messages=[
                    {"role": "system", "content": system_prompt or default_system},
                    {"role": "user", "content": prompt},
                ],
                timeout=timeout,
                **options,
            )
            content = response.choices[0].message.content
            if content:
                _last_model.set(llm_model)
                logger.info("Alibaba Cloud Model Studio (%s) call succeeded via DashScope Intl", llm_model)
                return content.strip()
            raise RuntimeError("DashScope returned empty content")
        except Exception as err:
            detail = sanitize_text(str(err))[:120]
            if strict:
                raise RuntimeError(f"STRICT_LIVE_MODE: DashScope call failed for model '{llm_model}' ({detail}).") from err
            logger.warning("DashScope API call failed for model '%s' (%s).", llm_model, detail)
            return ""

    # 3. Universal OpenAI-Compatible Routing (Ollama, Groq, DeepSeek, OpenRouter, OpenAI)
    if not llm_api_key:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: LLM_API_KEY is unconfigured.")
        logger.info("LLM_API_KEY is unconfigured — using fallback engine.")
        return ""

    try:
        from openai import OpenAI

        client = OpenAI(api_key=llm_api_key, base_url=llm_base_url)
        response = client.chat.completions.create(
            model=llm_model,
            messages=[
                {"role": "system", "content": system_prompt or default_system},
                {"role": "user", "content": prompt},
            ],
            timeout=timeout,
        )

        content = response.choices[0].message.content
        if content:
            _last_model.set(llm_model)
            return content.strip()
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: Model '{llm_model}' returned empty response.")
        return ""

    except Exception as err:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: LLM provider call failed for model '{llm_model}' ({sanitize_text(str(err))[:120]}).")
        logger.warning("LLM provider call failed for model '%s' (%s). Using fallback engine.", llm_model, sanitize_text(str(err))[:120])
        return ""


def call_llm_json(
    prompt: str,
    system_prompt: Optional[str] = None,
    use_mock: bool = False,
    timeout: int = 5,
    strict_live: bool = False,
) -> Dict[str, Any]:
    """Execute JSON generation against the configured LLM provider."""
    strict = strict_live or os.getenv("STRICT_LIVE_MODE", "false").lower() in ("true", "1")
    if use_mock:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: Cannot use mock mode when strict live mode is enabled.")
        return _load_mock_json()

    raw_response = call_llm(prompt, system_prompt=system_prompt, use_mock=use_mock, timeout=timeout, strict_live=strict, json_mode=True)
    if not raw_response:
        if strict:
            raise RuntimeError("STRICT_LIVE_MODE: LLM provider call returned empty response or failed.")
        return {
            "status": "error",
            "executive_summary": "AI analysis unavailable.",
            "findings": [],
            "_provenance": "LLM_REASONING_FAILED",
            "_fallback_triggered": True,
        }

    try:
        payload = extract_json_payload(raw_response)
        if not isinstance(payload, (dict, list)) or (isinstance(payload, list) and any(not isinstance(item, dict) for item in payload)):
            raise ValueError("Expected a JSON object or a list of objects")
        if isinstance(payload, dict):
            payload["_model_used"] = _last_model.get() or configured_model()
            payload["_provenance"] = "LLM_REASONING"
            payload["_fallback_triggered"] = False
        return payload
    except Exception as err:
        if strict:
            raise RuntimeError(f"STRICT_LIVE_MODE: Failed to parse valid JSON payload from LLM response ({err}).")
        logger.warning("Failed to parse valid JSON payload from LLM response (%s).", str(err)[:100])
        return {
            "status": "error",
            "executive_summary": "AI analysis response unparseable.",
            "findings": [],
            "_provenance": "LLM_REASONING_FAILED",
            "_fallback_triggered": True,
        }

