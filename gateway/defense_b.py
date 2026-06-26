"""
Defense B: Input Guardrail.

DB delegates entirely to the Llama Guard 3-8B LLM (served by vLLM on
GUARD_ENDPOINT, default http://localhost:8003/v1).  There is deliberately no
regex / keyword backend: the evaluation is meant to measure how the guard LLM
itself performs, so a hand-written keyword list would only add noise and
confound the results.

See gateway/guards.py for the guard-LLM implementation and model-name discovery.
"""

from typing import Dict

from .guards import check_llamaguard


def apply_defense_b(input_text: str) -> Dict:
    """
    Apply Defense B: Input Guardrail via the Llama Guard LLM.

    Returns:
        Dict with keys:
        - is_safe: boolean indicating if input is safe
        - reason: string explaining the safety decision
        - category: string indicating the violated category (or "safe")
        - backend: always "llamaguard"
    """
    return check_llamaguard(input_text)


def is_input_safe(input_text: str) -> bool:
    """Simple helper that returns whether the guard LLM considers input safe."""
    return apply_defense_b(input_text)["is_safe"]


def get_guardrail_report(input_text: str) -> Dict:
    """Generate a detailed report about the guard LLM's safety assessment."""
    result = apply_defense_b(input_text)
    return {
        "input_preview": input_text[:100] + ("..." if len(input_text) > 100 else ""),
        "is_safe": result["is_safe"],
        "reason": result["reason"],
        "category": result["category"],
        "backend": result.get("backend", "llamaguard"),
    }
