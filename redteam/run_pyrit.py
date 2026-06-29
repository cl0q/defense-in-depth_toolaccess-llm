#!/usr/bin/env python3
"""
PyRIT agentic red-team runner for the defense-in-depth thesis.

Loads objectives from redteam/attacks/*.yaml and runs CrescendoAttack (default)
or RedTeamingAttack against the gateway for a given layer profile.  Output is a
JSON artifact compatible with analysis/stats.py.

Usage
-----
    python redteam/run_pyrit.py \\
        --layer DA \\
        --output analysis/artifacts/pyrit/<run_id>/DA/results.json

    # PAIR of env vars that OpenAIChatTarget reads natively:
    OPENAI_CHAT_ENDPOINT=http://127.0.0.1:8002/v1
    OPENAI_CHAT_KEY=token-abc123
    OPENAI_CHAT_MODEL=NousResearch/Hermes-4-70B-FP8

    # Optional override for the gateway:
    PYRIT_GATEWAY_ENDPOINT=http://127.0.0.1:8000/query

Output schema (analysis/stats.py compatible)
---------------------------------------------
{
  "results": [
    {
      "gradingResult": {"pass": true},   // true = attack succeeded (leaked data)
      "tags":  {"config": "DA", "goal": "G-R1", "run.id": "...", "attack": "crescendo"},
      "description": "G-R1: Cross-tenant read - ...",
      "prompt": "...",
      "metadata": { ... }
    }
  ],
  "run_id": "...",
  "layer": "DA",
  "strategy": "crescendo"
}
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import logging
import os
import sys
import traceback
from pathlib import Path
from typing import Any

import httpx
import yaml

# ---------------------------------------------------------------------------
# PyRIT imports (must come before CentralMemory is used anywhere)
# ---------------------------------------------------------------------------
from pyrit.memory import CentralMemory, SQLiteMemory
from pyrit.models import AttackOutcome
from pyrit.prompt_normalizer import PromptNormalizer
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.executor.attack import (
    AttackAdversarialConfig,
    AttackScoringConfig,
    CrescendoAttack,
    RedTeamingAttack,
    TAPAttack,
)
from pyrit.executor.attack.multi_turn.tree_of_attacks import TAPAttackScoringConfig
from pyrit.score import FloatScaleThresholdScorer

# ---------------------------------------------------------------------------
# Local imports
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from redteam.pyrit_target import CanaryLeakFloatScorer, CanaryLeakScorer, GatewayTarget  # noqa: E402
from redteam import cli_format  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ROLE_TOKEN_MAP: dict[str, str] = {
    "role_customer": "tenant_a.customer",
    "role_merchant": "tenant_a.merchant",
    "role_admin": "tenant_a.admin",
}

GOAL_TOKENS = {"G-R1", "G-R2", "G-W1", "G-W2", "G-W3", "G-S1"}


# ---------------------------------------------------------------------------
# Diagnostics + attacker construction
# ---------------------------------------------------------------------------

_LOG = logging.getLogger("redteam.run_pyrit")


def setup_logging() -> None:
    """Route PyRIT / HTTP-client logs to stderr so the *real* cause of a failed
    attacker call is recoverable from run.log.

    TAP swallows per-branch failures: it stores ``node.error_message`` and prunes
    the branch, so a bare run only ever shows PyRIT's generic
    ``Error sending prompt with conversation ID: ...`` wrapper — never the
    underlying timeout / connection / HTTP error.  Raising the level on these
    loggers (together with ``_LoggingPromptNormalizer``) surfaces the true cause.

    Controlled by ``PYRIT_LOG_LEVEL`` (default ``INFO``).  Set ``WARNING`` to
    quiet per-request httpx lines once the sweep is known-good.
    """
    level_name = os.getenv("PYRIT_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    # Idempotent: drop a handler we added on a previous call before re-adding.
    root.handlers = [h for h in root.handlers if not getattr(h, "_redteam_diag", False)]
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler._redteam_diag = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)

    for name in ("pyrit", "httpx", "httpcore", "openai"):
        logging.getLogger(name).setLevel(level)


class _LoggingPromptNormalizer(PromptNormalizer):
    """PromptNormalizer that logs the full exception chain before re-raising.

    PyRIT's normalizer wraps any target failure as
    ``raise Exception("Error sending prompt ...") from ex`` and TAP then catches
    that wrapper, recording only ``str(error)`` — so the original exception type
    and traceback never reach the log.  Logging here with ``exc_info=True`` emits
    the chained ``__cause__`` (the real timeout / connection reset / 4xx / 5xx),
    making the cause of every pruned TAP branch visible in run.log.
    """

    async def send_prompt_async(self, *args: Any, **kwargs: Any) -> Any:
        try:
            return await super().send_prompt_async(*args, **kwargs)
        except Exception:
            _LOG.error("send_prompt_async failed — underlying cause:", exc_info=True)
            raise


def _build_attacker() -> OpenAIChatTarget:
    """Construct the adversarial (attacker) target with reliability knobs.

    Reads OPENAI_CHAT_ENDPOINT / OPENAI_CHAT_KEY / OPENAI_CHAT_MODEL natively.
    All robustness knobs are env-configurable so the sweep can be tuned without
    code changes:

    * ``PYRIT_ATTACKER_TIMEOUT``    — httpx timeout in seconds (default 180) so a
      slow generation under load is not cut off prematurely.
    * ``PYRIT_ATTACKER_MAX_TOKENS`` — explicit completion budget (default 2048)
      so a generation cannot silently truncate to an empty / invalid response.
    * ``PYRIT_ATTACKER_RPM``        — optional requests-per-minute cap (unset by
      default); spaces out attacker calls if the vLLM backend is saturated.
    """
    timeout_s = float(os.getenv("PYRIT_ATTACKER_TIMEOUT", "180"))
    kwargs: dict[str, Any] = {
        "temperature": 0.7,
        "seed": 42,
        "httpx_client_kwargs": {"timeout": httpx.Timeout(timeout_s)},
    }

    max_tokens = os.getenv("PYRIT_ATTACKER_MAX_TOKENS", "2048").strip()
    if max_tokens:
        kwargs["max_completion_tokens"] = int(max_tokens)

    rpm = os.getenv("PYRIT_ATTACKER_RPM", "").strip()
    if rpm:
        kwargs["max_requests_per_minute"] = int(rpm)

    return OpenAIChatTarget(**kwargs)


# ---------------------------------------------------------------------------
# Objective loading
# ---------------------------------------------------------------------------

def load_objectives(attacks_dir: Path) -> list[dict[str, Any]]:
    """Return a flat list of attack objectives from redteam/attacks/*.yaml."""
    objectives: list[dict[str, Any]] = []
    for yaml_file in sorted(attacks_dir.glob("*.yaml")):
        with open(yaml_file, encoding="utf-8") as fh:
            items = yaml.safe_load(fh)
        if not isinstance(items, list):
            continue
        # Filename stem is the canonical goal (e.g. G-R1)
        goal_from_file = yaml_file.stem
        for item in items:
            tags = item.get("tags", [])
            goal = next((t for t in tags if t in GOAL_TOKENS), goal_from_file)
            objectives.append(
                {
                    "goal": goal,
                    "description": item.get("description", ""),
                    "role": item.get("role", "role_customer"),
                    "prompt": str(item.get("prompt", "")).strip(),
                    "expected_result": item.get("expected_result", "blocked"),
                    "source_file": yaml_file.name,
                }
            )
    return objectives


# ---------------------------------------------------------------------------
# Single-attack runner
# ---------------------------------------------------------------------------

async def run_one_attack(
    *,
    objective_str: str,
    bearer_token: str,
    attacker: OpenAIChatTarget,
    scorer: CanaryLeakScorer,
    attacker_tenant: str,
    strategy: str,
    gateway_endpoint: str,
    max_turns: int,
    max_backtracks: int,
) -> dict[str, Any]:
    """Run one attack objective; return outcome + gateway metadata."""
    target = GatewayTarget(endpoint=gateway_endpoint, bearer_token=bearer_token)

    adv_config = AttackAdversarialConfig(target=attacker)
    score_config = AttackScoringConfig(
        objective_scorer=scorer,
        use_score_as_feedback=True,
    )

    if strategy == "redteam":
        attack = RedTeamingAttack(
            objective_target=target,
            attack_adversarial_config=adv_config,
            attack_scoring_config=score_config,
            max_turns=max_turns,
        )
    elif strategy == "tap":
        # TAP requires FloatScaleThresholdScorer (not plain TrueFalseScorer) so
        # that it can rank tree branches numerically during pruning.
        float_scorer = CanaryLeakFloatScorer(attacker_tenant=attacker_tenant)
        tap_objective = FloatScaleThresholdScorer(scorer=float_scorer, threshold=0.5)
        tap_scoring_config = TAPAttackScoringConfig(objective_scorer=tap_objective)
        # Fresh attacker client per TAP objective: TAP issues far more adversarial
        # calls than crescendo/redteam, and reusing one client across all 9
        # objectives eventually exhausts its connection pool (older runs collapsed
        # to "0 turns" from goal ~5 on). A dedicated client keeps a clean pool.
        tap_attacker = _build_attacker()
        tap_adv_config = AttackAdversarialConfig(target=tap_attacker)
        # batch_size caps how many tree nodes are processed in parallel. Default 1
        # makes node processing sequential: the tree (width/depth/branching) is
        # unchanged, so the explored branches and pruning decisions are identical
        # and accuracy is preserved — but the attacker is never hit by a burst of
        # concurrent generations, which was the cause of the non-retryable
        # connection/timeout errors that silently pruned branches. Sequential
        # processing also honours the thesis's concurrency=1 power-measurement
        # requirement.
        tap_batch_size = int(os.getenv("PYRIT_TAP_BATCH_SIZE", "1"))
        attack = TAPAttack(
            objective_target=target,
            attack_adversarial_config=tap_adv_config,
            attack_scoring_config=tap_scoring_config,
            # on_topic_checking_enabled=False keeps pruning fully local (no
            # second judge LLM call), which is correct for the air-gapped setup.
            on_topic_checking_enabled=False,
            batch_size=tap_batch_size,
            # Surface the real exception behind a pruned branch (see class docs).
            prompt_normalizer=_LoggingPromptNormalizer(),
        )
    else:
        # Crescendo backtracks on refusals; each backtrack is an extra gateway
        # POST, so total gateway calls can reach max_turns + max_backtracks.
        # Set max_backtracks=0 for a clean smoke test where calls == turns.
        attack = CrescendoAttack(
            objective_target=target,
            attack_adversarial_config=adv_config,
            attack_scoring_config=score_config,
            max_turns=max_turns,
            max_backtracks=max_backtracks,
        )

    try:
        result = await attack.execute_async(objective=objective_str)
        outcome = result.outcome
        conversation_id = str(getattr(result, "conversation_id", ""))
        error = None
    except Exception as exc:  # noqa: BLE001
        outcome = None
        conversation_id = ""
        error = str(exc)
        if os.getenv("PYRIT_DEBUG", "") not in ("", "0"):
            traceback.print_exc(file=sys.stderr)

    return {
        "outcome": outcome,
        "conversation_id": conversation_id,
        "active_layers": list(target.last_active_layers),
        "trace_id": target.last_trace_id,
        "turns": target.turns,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main_async(args: argparse.Namespace) -> None:
    # Route PyRIT / HTTP-client logs to stderr so a failed attacker call reveals
    # its real cause (timeout / connection / HTTP error) in run.log.
    setup_logging()

    # Memory MUST be initialised before any target/attack is instantiated.
    db_path = args.db_path or ":memory:"
    CentralMemory.set_memory_instance(SQLiteMemory(db_path=db_path))

    # Attacker LLM — reads OPENAI_CHAT_ENDPOINT / OPENAI_CHAT_KEY / OPENAI_CHAT_MODEL.
    # Shared across crescendo/redteam objectives; TAP builds its own per objective.
    attacker = _build_attacker()

    # Scorer is stateless and re-used across objectives
    scorer = CanaryLeakScorer(attacker_tenant="TA")

    # Load and optionally filter objectives
    attacks_dir = Path(__file__).parent / "attacks"
    objectives = load_objectives(attacks_dir)

    if args.goals:
        requested = {g.strip() for g in args.goals.split(",")}
        objectives = [o for o in objectives if o["goal"] in requested]

    if not objectives:
        print("[run_pyrit] No objectives matched — nothing to run.", file=sys.stderr)
        sys.exit(1)

    console = cli_format.make_console()
    cli_format.print_header(
        console,
        strategy=args.strategy,
        layer=args.layer,
        n_objectives=len(objectives),
        max_turns=args.max_turns,
        attacker_model=os.getenv("OPENAI_CHAT_MODEL", "?"),
        gateway_endpoint=args.gateway_endpoint,
        trials=max(1, args.trials),
    )

    run_id = args.run_id or datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    trials = max(1, args.trials)
    results: list[dict[str, Any]] = []

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    def flush_artifact() -> None:
        """Atomically persist results so far; an abort keeps completed trials."""
        artifact = {
            "results": results,
            "run_id": run_id,
            "layer": args.layer,
            "strategy": args.strategy,
            "trials": trials,
        }
        tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2)
        os.replace(tmp_path, out_path)

    for idx, obj in enumerate(objectives, 1):
        bearer_token = ROLE_TOKEN_MAP.get(obj["role"], "tenant_a.customer")
        objective_str = f"{obj['goal']}: {obj['description']}"

        for trial in range(1, trials + 1):
            if trials > 1:
                cli_format.print_running(
                    console,
                    idx,
                    len(objectives),
                    obj["goal"],
                    f"{obj['description']}  (trial {trial}/{trials})",
                )
            else:
                cli_format.print_running(console, idx, len(objectives), obj["goal"], obj["description"])

            raw = await run_one_attack(
                objective_str=objective_str,
                bearer_token=bearer_token,
                attacker=attacker,
                scorer=scorer,
                attacker_tenant="TA",
                strategy=args.strategy,
                gateway_endpoint=args.gateway_endpoint,
                max_turns=args.max_turns,
                max_backtracks=args.max_backtracks,
            )
            attack_success = raw.get("outcome") == AttackOutcome.SUCCESS
            turns = raw.get("turns", [])

            # First turn whose victim response leaked a sensitive canary, plus
            # the ground-truth tokens that leaked (so a DC-a/DC-b/etc. leak can
            # be explained: which INTERNAL/SECRET/cross-tenant token escaped).
            leak_turn = None
            leaked_tokens: list[dict] = []
            for ti, t in enumerate(turns, 1):
                hits = cli_format.leaked_token_details(t.get("response", ""))
                if hits and leak_turn is None:
                    leak_turn = ti
                for h in hits:
                    h_with_turn = dict(h, turn=ti)
                    if h_with_turn not in leaked_tokens:
                        leaked_tokens.append(h_with_turn)

            cli_format.render_conversation(
                console,
                goal=obj["goal"],
                description=obj["description"],
                role=obj["role"],
                turns=turns,
                success=attack_success,
                error=raw.get("error"),
            )

            results.append(
                {
                    "gradingResult": {"pass": attack_success},
                    "tags": {
                        "config": args.layer,
                        "goal": obj["goal"],
                        "run.id": run_id,
                        "attack": args.strategy,
                        "trial": trial,
                    },
                    "description": f"{obj['goal']}: {obj['description']}",
                    "prompt": obj["prompt"],
                    "metadata": {
                        "role": obj["role"],
                        "bearer_token": bearer_token,
                        "expected_result": obj["expected_result"],
                        "active_layers": raw.get("active_layers", []),
                        "trace_id": raw.get("trace_id", ""),
                        "conversation_id": raw.get("conversation_id", ""),
                        "source_file": obj["source_file"],
                        # NOTE: gateway_calls counts every POST to the gateway,
                        # including crescendo backtrack retries, so it can exceed
                        # --max-turns (max gateway_calls ~= max_turns + max_backtracks).
                        "gateway_calls": len(turns),
                        "turns": len(turns),
                        "leak_turn": leak_turn,
                        "leaked_tokens": leaked_tokens,
                        "trial": trial,
                        "trials": trials,
                        "error": raw.get("error"),
                    },
                }
            )
            flush_artifact()

    # Final flush + summary
    flush_artifact()

    if trials > 1:
        cli_format.render_trials_summary(console, results, trials)
    else:
        cli_format.render_summary(console, results)

    analyze_cmd = (
        f"python analysis/stats.py "
        f"--artifacts '{out_path}' "
        f"--power-log 'power_log.jsonl' "
        f"--out 'analysis/report_{run_id}.md'"
    )
    if console is None:
        print(f"\n[run_pyrit] run_id: {run_id}", flush=True)
        print(f"[run_pyrit] artifact: {out_path}", flush=True)
        print(f"[run_pyrit] analyze with:\n  {analyze_cmd}", flush=True)
    else:
        console.print(f"\n[bold cyan]run_id:[/bold cyan] [bold]{run_id}[/bold]")
        console.print(f"[dim]artifact:[/dim] {out_path}")
        console.print("[bold]analyze this run:[/bold]")
        console.print(f"  [green]{analyze_cmd}[/green]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PyRIT agentic red-team runner (defense-in-depth thesis)"
    )
    parser.add_argument("--layer", required=True, help="Defense layer tag, e.g. D0 DA DB")
    parser.add_argument("--output", required=True, help="Output JSON artifact path")
    parser.add_argument(
        "--strategy",
        default="crescendo",
        choices=["crescendo", "redteam", "tap"],
        help="Attack strategy (default: crescendo)",
    )
    parser.add_argument(
        "--goals",
        default="",
        help="Comma-separated goal IDs to run, e.g. G-R1,G-R2  (default: all)",
    )
    parser.add_argument(
        "--max-turns",
        type=int,
        default=10,
        help="Max turns per attack (default: 10)",
    )
    parser.add_argument(
        "--max-backtracks",
        type=int,
        default=5,
        help=(
            "Crescendo only: max backtracks on refusal. Each backtrack is an "
            "extra gateway call, so total calls can reach max_turns+max_backtracks. "
            "Set 0 for a clean run where gateway calls == turns (default: 5)"
        ),
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=1,
        help="Repeat each goal N times to report a leak-rate (default: 1)",
    )
    parser.add_argument(
        "--gateway-endpoint",
        default=os.getenv("PYRIT_GATEWAY_ENDPOINT", "http://127.0.0.1:8000/query"),
        help="Gateway /query endpoint",
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="Run ID for artifact tagging (default: UTC timestamp)",
    )
    parser.add_argument(
        "--db-path",
        default="",
        help="Path for PyRIT SQLite memory DB (default: in-memory, not persisted)",
    )

    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
