"""
Defense B guard backends.

Three backends are supported and selected via the GUARD_BACKEND environment variable:
  regex       - keyword / regex scan (original stub, very fast, baseline)
  llamaguard  - Llama Guard 3-8B served by vLLM on GUARD_ENDPOINT (default http://localhost:8003/v1)
  promptguard - Llama Prompt Guard 2-86M loaded in-process via transformers
  both        - llamaguard AND promptguard (blocks if either blocks)

Llama Guard 3-8B (chat, OpenAI-compatible):
  Classifies a single user turn as safe / unsafe with a category label.
  Model served at GUARD_ENDPOINT (port 8003).

Prompt Guard 2-86M (transformers text-classification pipeline):
  Lightweight BERT-style classifier. Labels: BENIGN, JAILBREAK, INJECTION.
  Loaded lazily on first call; runs on CPU (tiny model, <0.3 GB).
"""

import os
import logging
import requests
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (read once at import time so the values can be overridden in tests)
# ---------------------------------------------------------------------------
GUARD_BACKEND: str = os.environ.get("GUARD_BACKEND", "regex").lower()
GUARD_ENDPOINT: str = os.environ.get("GUARD_ENDPOINT", "http://localhost:8003/v1")
GUARD_API_KEY: str = os.environ.get("GUARD_API_KEY", "token-abc123")
GUARD_MODEL: str = os.environ.get("GUARD_MODEL", "llama-guard-3-8b")
GUARD_TIMEOUT: int = int(os.environ.get("GUARD_TIMEOUT", "15"))

# Confidence threshold for Prompt Guard (0.5 is the model default).
PROMPT_GUARD_THRESHOLD: float = float(os.environ.get("PROMPT_GUARD_THRESHOLD", "0.5"))

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
        "model": GUARD_MODEL,
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


# ---------------------------------------------------------------------------
# Prompt Guard 2-86M (lazy-loaded)
# ---------------------------------------------------------------------------
_prompt_guard_pipeline: Optional[object] = None


def _get_prompt_guard_pipeline():
    global _prompt_guard_pipeline
    if _prompt_guard_pipeline is None:
        try:
            from transformers import pipeline as hf_pipeline  # type: ignore
            model_id = os.environ.get("PROMPT_GUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M")
            logger.info("Loading Prompt Guard model %s (first call, may take a moment)", model_id)
            _prompt_guard_pipeline = hf_pipeline(
                "text-classification",
                model=model_id,
                device=-1,  # CPU — model is tiny, saves VRAM for the main models
                truncation=True,
            )
            logger.info("Prompt Guard model loaded")
        except Exception as exc:
            logger.warning("Could not load Prompt Guard model: %s", exc)
            _prompt_guard_pipeline = None
    return _prompt_guard_pipeline


def check_promptguard(text: str) -> Dict:
    """
    Run Llama Prompt Guard 2-86M on *text*.

    Labels:  BENIGN  (safe)
             JAILBREAK  (direct jailbreak attempt)
             INJECTION  (indirect prompt injection)

    Returns:
        {"is_safe": bool, "reason": str, "category": str, "backend": "promptguard"}
    """
    pipe = _get_prompt_guard_pipeline()
    if pipe is None:
        logger.warning("Prompt Guard unavailable; defaulting to safe")
        return {"is_safe": True, "reason": "promptguard unavailable", "category": "unknown", "backend": "promptguard"}

    try:
        results = pipe(text[:512])  # model max length
        top = results[0] if isinstance(results, list) else results
        label: str = top["label"].upper()
        score: float = top["score"]
        if label != "BENIGN" and score >= PROMPT_GUARD_THRESHOLD:
            return {
                "is_safe": False,
                "reason": f"Prompt Guard: {label} (score={score:.3f})",
                "category": label.lower(),
                "backend": "promptguard",
            }
        return {"is_safe": True, "reason": f"Prompt Guard: BENIGN (score={score:.3f})", "category": "safe", "backend": "promptguard"}
    except Exception as exc:
        logger.warning("Prompt Guard inference failed (%s); defaulting to safe", exc)
        return {"is_safe": True, "reason": f"promptguard error: {exc}", "category": "unknown", "backend": "promptguard"}
