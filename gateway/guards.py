"""
Defense B guard backend: Llama Guard 3-8B served by vLLM.

Defense B sends each user turn to Llama Guard 3-8B (OpenAI-compatible chat API
served by vLLM on GUARD_ENDPOINT, default http://localhost:8003/v1) and blocks
the request if the model classifies it as unsafe.  There is no regex / keyword
fallback — DB is exactly "what the guard LLM decides", so the evaluation
measures the guard model itself, not a hand-written keyword list.

Model name resolution
---------------------
The model id is discovered at runtime from vLLM's ``GET {GUARD_ENDPOINT}/models``
endpoint, which returns ``{"object": "list", "data": [{"id": "<name>", ...}]}``.
We use the first model's id.  Set GUARD_MODEL to pin an explicit name and skip
discovery.
"""

import os
import logging
import requests
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (read once at import time so the values can be overridden in tests)
# ---------------------------------------------------------------------------
GUARD_ENDPOINT: str = os.environ.get("GUARD_ENDPOINT", "http://localhost:8003/v1")
GUARD_API_KEY: str = os.environ.get("GUARD_API_KEY", "token-abc123")
# Optional explicit override; when unset the name is discovered from /models.
GUARD_MODEL: str = os.environ.get("GUARD_MODEL", "")
GUARD_TIMEOUT: int = int(os.environ.get("GUARD_TIMEOUT", "15"))

# Fallback used only when discovery fails and no GUARD_MODEL override is set.
_GUARD_MODEL_FALLBACK = "llama-guard-3-8b"

# ---------------------------------------------------------------------------
# Model name discovery
# ---------------------------------------------------------------------------
_resolved_model: Optional[str] = None


def _resolve_guard_model() -> str:
    """Return the guard model name, discovering it from vLLM's /models endpoint.

    Resolution order:
      1. GUARD_MODEL env var, if explicitly set (cached).
      2. First id from ``GET {GUARD_ENDPOINT}/models`` (cached on success).
      3. ``_GUARD_MODEL_FALLBACK`` if the endpoint is unreachable (NOT cached,
         so a later call retries once the guard server is up).
    """
    global _resolved_model
    if _resolved_model is not None:
        return _resolved_model

    if GUARD_MODEL:
        _resolved_model = GUARD_MODEL
        return _resolved_model

    try:
        resp = requests.get(
            f"{GUARD_ENDPOINT}/models",
            headers={"Authorization": f"Bearer {GUARD_API_KEY}"},
            timeout=GUARD_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if data:
            model_id = data[0]["id"]
            logger.info("Discovered guard model '%s' from %s/models", model_id, GUARD_ENDPOINT)
            _resolved_model = model_id
            return _resolved_model
        logger.warning("%s/models returned no models; using fallback '%s'", GUARD_ENDPOINT, _GUARD_MODEL_FALLBACK)
    except Exception as exc:
        logger.warning(
            "Could not discover guard model from %s/models (%s); using fallback '%s'",
            GUARD_ENDPOINT, exc, _GUARD_MODEL_FALLBACK,
        )
    return _GUARD_MODEL_FALLBACK


# ---------------------------------------------------------------------------
# Llama Guard 3-8B
# ---------------------------------------------------------------------------

def check_llamaguard(text: str) -> Dict:
    """
    Ask Llama Guard 3-8B whether *text* (a single user turn) is safe.

    Returns:
        {"is_safe": bool, "reason": str, "category": str, "backend": "llamaguard"}

    The model returns a plain-text response that starts with "safe" or "unsafe".
    When unsafe it appends a newline and the violated category code, e.g.:
        unsafe\nS1
    """
    url = f"{GUARD_ENDPOINT}/chat/completions"
    payload = {
        "model": _resolve_guard_model(),
        "messages": [{"role": "user", "content": text}],
        "max_tokens": 20,
        "temperature": 0.0,
    }
    try:
        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {GUARD_API_KEY}"},
            timeout=GUARD_TIMEOUT,
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("Llama Guard request failed (%s); defaulting to safe", exc)
        return {"is_safe": True, "reason": f"llamaguard unavailable: {exc}", "category": "unknown", "backend": "llamaguard"}

    verdict = resp.json()["choices"][0]["message"]["content"].strip().lower()
    if verdict.startswith("unsafe"):
        category = verdict.split("\n")[1].strip() if "\n" in verdict else "unknown"
        return {"is_safe": False, "reason": f"Llama Guard: unsafe [{category}]", "category": category, "backend": "llamaguard"}
    return {"is_safe": True, "reason": "Llama Guard: safe", "category": "safe", "backend": "llamaguard"}
