#!/usr/bin/env python3
"""
Statistical analysis for LLM database security evaluation.
Loads real run artifacts and computes ASR + Wilson intervals + baseline comparisons.
"""

import argparse
import glob
import json
import math
import os
from collections import defaultdict
from typing import Dict, List, Tuple, Any


def wilson_score_interval(successes: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    if n == 0:
        return 0.0, 0.0

    phat = successes / n
    denominator = 1 + z**2 / n
    center = (phat + z**2 / (2 * n)) / denominator
    radius = z * math.sqrt(phat * (1 - phat) / n + z**2 / (4 * n**2)) / denominator
    lower = max(0.0, center - radius)
    upper = min(1.0, center + radius)
    return lower, upper


def two_proportion_z_test(x1: int, n1: int, x2: int, n2: int) -> Dict[str, float]:
    if min(n1, n2) == 0:
        return {"z": 0.0, "p_value": 1.0}

    p1 = x1 / n1
    p2 = x2 / n2
    pooled = (x1 + x2) / (n1 + n2)
    variance = pooled * (1 - pooled) * ((1 / n1) + (1 / n2))

    if variance <= 0:
        return {"z": 0.0, "p_value": 1.0}

    z = (p1 - p2) / math.sqrt(variance)
    p_value = math.erfc(abs(z) / math.sqrt(2))
    return {"z": z, "p_value": p_value}


def _extract_tests_from_promptfoo(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    if "results" in payload and isinstance(payload["results"], list):
        return payload["results"]
    if "tests" in payload and isinstance(payload["tests"], list):
        return payload["tests"]
    return []


def _extract_tags(test: Dict[str, Any]) -> Dict[str, str]:
    tags = test.get("tags") or test.get("metadata", {}).get("tags") or {}
    if isinstance(tags, list):
        mapped = {}
        for item in tags:
            if isinstance(item, str) and "=" in item:
                key, value = item.split("=", 1)
                mapped[key] = value
        return mapped
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {}


def _extract_goal(test: Dict[str, Any], tags: Dict[str, str]) -> str:
    if tags.get("goal"):
        return tags["goal"]
    if tags.get("target"):
        return tags["target"]

    candidate_tags = test.get("vars", {}).get("tags")
    if isinstance(candidate_tags, list):
        for item in candidate_tags:
            if isinstance(item, str) and item.startswith("G-"):
                return item

    for key in ["description", "prompt"]:
        value = str(test.get(key, ""))
        match = next((token for token in ["G-R1", "G-R2", "G-W1", "G-W2", "G-W3", "G-S1"] if token in value), None)
        if match:
            return match

    return "UNKNOWN"


def load_experiment_data(artifact_glob: str) -> Dict[str, Any]:
    grouped = defaultdict(lambda: defaultdict(lambda: {"successes": 0, "total": 0}))

    artifact_files = sorted(glob.glob(artifact_glob, recursive=True))
    for path in artifact_files:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        tests = _extract_tests_from_promptfoo(payload)
        for test in tests:
            tags = _extract_tags(test)
            config = tags.get("config") or test.get("config") or "UNKNOWN"
            goal = _extract_goal(test, tags)

            grade = test.get("gradingResult", {})
            pass_field = grade.get("pass")
            successful = bool(pass_field)

            grouped[config][goal]["total"] += 1
            grouped[config][goal]["successes"] += 1 if successful else 0

    return {
        "artifact_files": artifact_files,
        "grouped": grouped,
    }


def calculate_asr_stats(grouped: Dict[str, Any]) -> Dict[str, Any]:
    results: Dict[str, Any] = {}
    for config, targets in grouped.items():
        results[config] = {}
        for target, values in targets.items():
            successes = values["successes"]
            total = values["total"]
            asr = (successes / total) if total else 0.0
            lower, upper = wilson_score_interval(successes, total)
            results[config][target] = {
                "successful_attacks": successes,
                "sample_size": total,
                "mean_asr": asr,
                "lower_ci": lower,
                "upper_ci": upper,
            }
    return results


def add_baseline_significance(results: Dict[str, Any], baseline: str = "D0") -> Dict[str, Any]:
    if baseline not in results:
        return results

    for config, targets in results.items():
        if config == baseline:
            continue

        for target, values in targets.items():
            base = results.get(baseline, {}).get(target)
            if not base:
                continue

            test = two_proportion_z_test(
                values["successful_attacks"],
                values["sample_size"],
                base["successful_attacks"],
                base["sample_size"],
            )

            values["baseline_delta"] = values["mean_asr"] - base["mean_asr"]
            values["baseline_p_value"] = test["p_value"]
            values["baseline_z"] = test["z"]

    return results


def generate_detailed_report(results: Dict[str, Any], artifact_files: List[str]) -> str:
    lines: List[str] = []
    lines.append("# LLM Database Security Analysis Report")
    lines.append("")
    lines.append("## Data Source")
    if artifact_files:
        lines.append(f"Loaded {len(artifact_files)} artifact file(s).")
        for path in sorted(artifact_files):
            lines.append(f"- {path}")
    else:
        lines.append("No artifacts were found. Run promptfoo and oracle export first.")
    lines.append("")

    lines.append("## ASR by Configuration and Goal")
    lines.append("")
    lines.append("| Config | Goal | Successful | Total | ASR | 95% CI | Baseline delta | p-value |")
    lines.append("|---|---|---:|---:|---:|---|---:|---:|")

    for config in sorted(results.keys()):
        for goal in sorted(results[config].keys()):
            data = results[config][goal]
            ci = f"[{data['lower_ci']:.3f}, {data['upper_ci']:.3f}]"
            delta = data.get("baseline_delta")
            p_value = data.get("baseline_p_value")
            lines.append(
                "| {config} | {goal} | {success} | {total} | {asr:.3f} | {ci} | {delta} | {pvalue} |".format(
                    config=config,
                    goal=goal,
                    success=data["successful_attacks"],
                    total=data["sample_size"],
                    asr=data["mean_asr"],
                    ci=ci,
                    delta=(f"{delta:+.3f}" if delta is not None else "n/a"),
                    pvalue=(f"{p_value:.4f}" if p_value is not None else "n/a"),
                )
            )

    lines.append("")
    lines.append("## Notes")
    lines.append("- Conclusions are derived from computed values only.")
    lines.append("- Significance columns compare each configuration against D0 when data is available.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze promptfoo/oracle artifacts")
    parser.add_argument(
        "--artifacts",
        default="analysis/artifacts/**/*.json",
        help="Glob pattern for promptfoo/oracle JSON artifacts",
    )
    parser.add_argument(
        "--out",
        default="analysis/report.md",
        help="Path for markdown report output",
    )
    parser.add_argument(
        "--json-out",
        default="analysis/report.json",
        help="Path for machine-readable output",
    )
    args = parser.parse_args()

    loaded = load_experiment_data(args.artifacts)
    stats = calculate_asr_stats(loaded["grouped"])
    stats = add_baseline_significance(stats)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    report = generate_detailed_report(stats, loaded["artifact_files"])

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(report)

    with open(args.json_out, "w", encoding="utf-8") as handle:
        json.dump(stats, handle, indent=2)

    print(f"Wrote report: {args.out}")
    print(f"Wrote JSON stats: {args.json_out}")


if __name__ == "__main__":
    main()
