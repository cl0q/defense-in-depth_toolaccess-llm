#!/usr/bin/env python3
"""Diagnostic: report the installed PyRIT API surface.

PyRIT's public API moves between releases (target/scorer base classes,
orchestrator vs. attack modules, init helpers). This script does NOT assume any
particular version: it probes a range of known import paths and prints what
actually exists, plus the constructor / override signatures we care about, so
the integration code can be written against the real installed API.

Run on the server in whatever venv has pyrit installed:

    python redteam/pyrit_introspect.py

Then paste the full output back.
"""
from __future__ import annotations

import importlib
import inspect
import sys


def hr(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def try_version() -> None:
    hr("1. VERSION + PYTHON")
    print(f"python: {sys.version.split()[0]}")
    try:
        import pyrit  # noqa

        print(f"pyrit.__version__: {getattr(pyrit, '__version__', '<no __version__ attr>')}")
        print(f"pyrit module file: {getattr(pyrit, '__file__', '?')}")
    except Exception as exc:  # noqa: BLE001
        print(f"!! could not import pyrit: {exc!r}")
        print("   -> is the venv active? is pyrit installed? (pip show pyrit)")


def probe_symbol(module_path: str, names: list[str]) -> None:
    """Print which of `names` exist in `module_path`."""
    try:
        mod = importlib.import_module(module_path)
    except Exception as exc:  # noqa: BLE001
        print(f"  [module missing] {module_path}: {exc!r}")
        return
    for name in names:
        obj = getattr(mod, name, None)
        mark = "OK " if obj is not None else "-- "
        print(f"  [{mark}] {module_path}.{name}")


def show_signature(module_path: str, cls_name: str, methods: list[str]) -> None:
    """Print constructor + selected method signatures for a class, if present."""
    try:
        mod = importlib.import_module(module_path)
    except Exception as exc:  # noqa: BLE001
        print(f"  [module missing] {module_path}: {exc!r}")
        return
    cls = getattr(mod, cls_name, None)
    if cls is None:
        print(f"  [class missing] {module_path}.{cls_name}")
        return
    print(f"\n  --- {module_path}.{cls_name} ---")
    try:
        print(f"  __init__{inspect.signature(cls.__init__)}")
    except (ValueError, TypeError) as exc:
        print(f"  __init__: <unreadable: {exc}>")
    # list abstract methods so we know what a subclass must implement
    abstract = sorted(getattr(cls, "__abstractmethods__", set()))
    if abstract:
        print(f"  abstractmethods: {abstract}")
    for m in methods:
        fn = getattr(cls, m, None)
        if fn is None:
            continue
        try:
            print(f"  {m}{inspect.signature(fn)}")
        except (ValueError, TypeError):
            print(f"  {m}(<unreadable signature>)")


def main() -> None:
    try_version()

    hr("2. INIT / MEMORY HELPERS (which boilerplate does this version use?)")
    probe_symbol("pyrit.common", ["initialize_pyrit", "IN_MEMORY", "DUCK_DB"])
    probe_symbol("pyrit.common.initialization", ["initialize_pyrit"])
    probe_symbol("pyrit.memory", ["CentralMemory", "SQLiteMemory", "DuckDBMemory"])

    hr("3. PROMPT TARGET BASE CLASSES (which do we subclass for the gateway?)")
    probe_symbol(
        "pyrit.prompt_target",
        [
            "PromptTarget",
            "PromptChatTarget",
            "OpenAIChatTarget",
            "HTTPTarget",
            "get_http_target_json_response_callback_function",
        ],
    )
    show_signature(
        "pyrit.prompt_target",
        "PromptChatTarget",
        ["send_prompt_async", "_send_prompt_to_target_async", "_validate_request"],
    )
    show_signature(
        "pyrit.prompt_target",
        "PromptTarget",
        ["send_prompt_async", "_send_prompt_to_target_async", "_validate_request"],
    )
    show_signature("pyrit.prompt_target", "OpenAIChatTarget", [])

    hr("4. MESSAGE / RESPONSE MODEL TYPES (what do target methods accept/return?)")
    probe_symbol(
        "pyrit.models",
        [
            "PromptRequestResponse",
            "PromptRequestPiece",
            "Message",
            "MessagePiece",
            "construct_response_from_request",
            "Score",
            "AttackOutcome",
            "AttackResult",
        ],
    )

    hr("5. SCORER BASE CLASSES (which do we subclass for the canary oracle?)")
    probe_symbol(
        "pyrit.score",
        [
            "Scorer",
            "TrueFalseScorer",
            "SubStringScorer",
            "FloatScaleThresholdScorer",
        ],
    )
    for cls_name in ("Scorer", "TrueFalseScorer"):
        show_signature(
            "pyrit.score",
            cls_name,
            ["score_async", "_score_async", "_score_piece_async", "score_text_async"],
        )

    hr("6. ORCHESTRATORS vs ATTACKS (which module holds the multi-turn engines?)")
    probe_symbol(
        "pyrit.orchestrator",
        [
            "CrescendoOrchestrator",
            "PAIROrchestrator",
            "TreeOfAttacksWithPruningOrchestrator",
            "RedTeamingOrchestrator",
        ],
    )
    probe_symbol(
        "pyrit.executor.attack",
        [
            "CrescendoAttack",
            "PAIRAttack",
            "TreeOfAttacksWithPruningAttack",
            "TAPAttack",
            "RedTeamingAttack",
            "AttackAdversarialConfig",
            "AttackScoringConfig",
        ],
    )

    hr("7. CRESCENDO SIGNATURE (whichever module/name exists)")
    for module_path, cls_name in (
        ("pyrit.orchestrator", "CrescendoOrchestrator"),
        ("pyrit.executor.attack", "CrescendoAttack"),
    ):
        show_signature(
            module_path,
            cls_name,
            ["run_attack_async", "execute_async", "apply_attack_strategy_until_completion_async"],
        )

    hr("8. RED-TEAMING / PAIR / TAP SIGNATURES")
    for module_path, cls_name in (
        ("pyrit.orchestrator", "RedTeamingOrchestrator"),
        ("pyrit.executor.attack", "RedTeamingAttack"),
        ("pyrit.orchestrator", "PAIROrchestrator"),
        ("pyrit.executor.attack", "PAIRAttack"),
        ("pyrit.orchestrator", "TreeOfAttacksWithPruningOrchestrator"),
        ("pyrit.executor.attack", "TreeOfAttacksWithPruningAttack"),
    ):
        show_signature(module_path, cls_name, ["run_attack_async", "execute_async"])

    print("\nDONE. Paste everything above this line back to the assistant.")


if __name__ == "__main__":
    main()
