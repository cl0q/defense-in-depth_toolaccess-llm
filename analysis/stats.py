#!/usr/bin/env python3
"""
Statistical analysis for LLM database security evaluation.
Loads real run artifacts and computes ASR + Wilson intervals + baseline comparisons.
Also loads power_log.jsonl / idle_baseline.jsonl and computes per-layer energy stats.
"""

import argparse
import glob
import json
import math
import os
from collections import defaultdict
from typing import Dict, List, Tuple, Any, Optional


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


def load_power_data(
    power_log_path: str = "power_log.jsonl",
    idle_baseline_path: str = "idle_baseline.jsonl",
) -> Dict[str, Any]:
    """
    Load power_log.jsonl and idle_baseline.jsonl and compute per-layer, per-role
    energy statistics.

    Returns a dict with keys:
      idle_w       - average idle power in watts (from baseline file), or None
      layers       - dict keyed by layer profile name (str), each containing:
          victim   - {"count", "mean_mj", "std_mj", "mean_net_mj"}
          guard    - same structure (0-filled if no guard data for this layer)
          total    - combined victim+guard mean_net_mj per request
      raw          - list of raw power records (for debugging)
    """
    # -- idle baseline --------------------------------------------------------
    idle_w: Optional[float] = None
    idle_duration_s: float = 0.0
    if os.path.exists(idle_baseline_path):
        with open(idle_baseline_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("type") == "idle_baseline" and rec.get("duration_s", 0) > 0:
                    idle_w = rec["avg_power_w"]
                    idle_duration_s = rec["duration_s"]
                    break  # use first / most recent baseline

    # -- power log ------------------------------------------------------------
    # power_log_path may be a single file OR a glob (e.g. ".../**/power_log.jsonl").
    # All matching files are concatenated; each record self-describes its layer
    # via active_layers, so merging across per-layer files is correct.
    raw: List[Dict] = []
    power_files = sorted(glob.glob(power_log_path, recursive=True))
    if not power_files and os.path.exists(power_log_path):
        power_files = [power_log_path]
    for pf in power_files:
        if not os.path.exists(pf):
            continue
        with open(pf, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    raw.append(json.loads(line))

    # Group records by (layer_profile, role).
    # active_layers is a list like ["DA", "DT"] — normalise to a canonical
    # profile label by matching against known profiles.
    def _layers_to_profile(layers: List[str]) -> str:
        s = set(layers)
        if not s or s == {"D0"}:
            return "D0"
        known = {
            frozenset(["DA"]): "DA",
            frozenset(["DB"]): "DB",
            frozenset(["DC-a"]): "DC-a",
            frozenset(["DC-b"]): "DC-b",
            frozenset(["DC-c"]): "DC-c",
            frozenset(["DT"]): "DT",
            frozenset(["DA", "DB", "DC-a", "DC-b", "DC-c", "DT"]): "D++",
        }
        return known.get(frozenset(s), ",".join(sorted(s)))

    # {profile -> {role -> [energy_mj]}}
    buckets: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for rec in raw:
        profile = _layers_to_profile(rec.get("active_layers", []))
        role = rec.get("role", "unknown")
        energy = rec.get("energy_mj")
        duration = rec.get("duration_s", 0.0)
        if energy is not None and duration > 0:
            buckets[profile][role].append(float(energy))

    def _stats(values: List[float], idle_w: Optional[float] = None) -> Dict[str, Any]:
        if not values:
            return {"count": 0, "mean_mj": 0.0, "std_mj": 0.0, "mean_net_mj": 0.0}
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / max(len(values) - 1, 1)
        std = math.sqrt(variance)
        # Approximate net energy: we don't have per-call duration stored in
        # buckets here, so we use the raw records for net calculation.
        net_mean = mean  # net subtraction happens per-record below
        return {"count": len(values), "mean_mj": round(mean, 1), "std_mj": round(std, 1), "mean_net_mj": round(net_mean, 1)}

    # For net energy we subtract idle*duration per record.
    net_buckets: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
    for rec in raw:
        profile = _layers_to_profile(rec.get("active_layers", []))
        role = rec.get("role", "unknown")
        energy = rec.get("energy_mj")
        duration = rec.get("duration_s", 0.0)
        if energy is None or duration <= 0:
            continue
        if idle_w is not None:
            idle_mj = idle_w * duration * 1000.0
            net = max(0.0, float(energy) - idle_mj)
        else:
            net = float(energy)
        net_buckets[profile][role].append(net)

    layers_out: Dict[str, Any] = {}
    all_profiles = set(buckets.keys()) | set(net_buckets.keys())
    for profile in all_profiles:
        victim_raw = buckets[profile].get("victim", [])
        guard_raw = buckets[profile].get("guard", [])
        victim_net = net_buckets[profile].get("victim", [])
        guard_net = net_buckets[profile].get("guard", [])

        victim_stats = _stats(victim_raw)
        guard_stats = _stats(guard_raw)
        victim_stats["mean_net_mj"] = round(sum(victim_net) / max(len(victim_net), 1), 1) if victim_net else 0.0
        guard_stats["mean_net_mj"] = round(sum(guard_net) / max(len(guard_net), 1), 1) if guard_net else 0.0

        total_net = victim_stats["mean_net_mj"] + guard_stats["mean_net_mj"]
        layers_out[profile] = {
            "victim": victim_stats,
            "guard": guard_stats,
            "total_net_mj": round(total_net, 1),
        }

    return {
        "idle_w": idle_w,
        "idle_duration_s": idle_duration_s,
        "layers": layers_out,
        "raw_count": len(raw),
    }


def generate_power_report_text(power_data: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("## GPU Energy Consumption by Layer")
    lines.append("")
    idle = power_data.get("idle_w")
    if idle is not None:
        lines.append(f"Idle baseline: **{idle:.1f} W** (net energy = gross − idle×duration)")
    else:
        lines.append("Idle baseline: *not measured* (net = gross)")
    lines.append(f"Total power records loaded: {power_data.get('raw_count', 0)}")
    lines.append("")
    lines.append("| Layer | Victim mean (gross mJ) | Victim net mJ | Guard net mJ | Total net mJ/req |")
    lines.append("|---|---:|---:|---:|---:|")
    layer_order = ["D0", "DA", "DB", "DC-a", "DC-b", "DC-c", "DT", "D++"]
    layers = power_data.get("layers", {})
    all_layers = layer_order + [k for k in sorted(layers.keys()) if k not in layer_order]
    for layer in all_layers:
        if layer not in layers:
            continue
        d = layers[layer]
        v = d["victim"]
        g = d["guard"]
        lines.append(
            f"| {layer} | {v['mean_mj']} | {v['mean_net_mj']} | {g['mean_net_mj']} | {d['total_net_mj']} |"
        )
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
        help="Path for machine-readable ASR output",
    )
    parser.add_argument(
        "--power-log",
        default="power_log.jsonl",
        help="Path or glob for gateway power JSONL log(s), e.g. '.../**/power_log.jsonl'",
    )
    parser.add_argument(
        "--idle-baseline",
        default="idle_baseline.jsonl",
        help="Path to idle baseline JSONL",
    )
    parser.add_argument(
        "--power-out",
        default="analysis/power_report.json",
        help="Path for machine-readable power output",
    )
    args = parser.parse_args()

    loaded = load_experiment_data(args.artifacts)
    stats = calculate_asr_stats(loaded["grouped"])
    stats = add_baseline_significance(stats)

    power_data = load_power_data(args.power_log, args.idle_baseline)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    report = generate_detailed_report(stats, loaded["artifact_files"])
    report += "\n\n" + generate_power_report_text(power_data)

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(report)

    with open(args.json_out, "w", encoding="utf-8") as handle:
        json.dump(stats, handle, indent=2)

    with open(args.power_out, "w", encoding="utf-8") as handle:
        json.dump(power_data, handle, indent=2)

    print(f"Wrote report: {args.out}")
    print(f"Wrote JSON stats: {args.json_out}")
    print(f"Wrote power report: {args.power_out}")


if __name__ == "__main__":
    main()
