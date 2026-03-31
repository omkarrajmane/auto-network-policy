#!/usr/bin/env python3
"""V4 MVP Gate: Score existing rulesets with traffic-weighted match depth."""

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path
from typing import TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from data.classbench_to_nft import load_nft_as_rules
from evaluate.weighted_match_depth import (
    ENTERPRISE_TRAFFIC,
    K8S_TRAFFIC,
    TrafficProfile,
    compute_weighted_match_depth,
)
from evaluate.match_depth import _matches_rule, _ip_matches_cidr, _port_in_range


class ScenarioConfig(TypedDict):
    profile: TrafficProfile
    original: str
    baselines: dict[str, str]


SCENARIOS: dict[str, ScenarioConfig] = {
    "k8s": {
        "profile": K8S_TRAFFIC,
        "original": "benchmarks/semantic/k8s_microservices_200.nft",
        "baselines": {
            "static_analysis": "results/semantic/static_analysis_k8s_microservices_200_optimized.nft",
            "simulated_annealing": "results/semantic/simulated_annealing_k8s_microservices_200_optimized.nft",
            "random_reorder": "results/semantic/random_reorder_k8s_microservices_200_optimized.nft",
            "greedy_hitcount": "results/semantic/greedy_hitcount_k8s_microservices_200_optimized.nft",
        },
    },
    "enterprise": {
        "profile": ENTERPRISE_TRAFFIC,
        "original": "benchmarks/semantic/enterprise_departments_500.nft",
        "baselines": {
            "static_analysis": "results/semantic/static_analysis_enterprise_departments_500_optimized.nft",
            "simulated_annealing": "results/semantic/simulated_annealing_enterprise_departments_500_optimized.nft",
            "random_reorder": "results/semantic/random_reorder_enterprise_departments_500_optimized.nft",
            "greedy_hitcount": "results/semantic/greedy_hitcount_enterprise_departments_500_optimized.nft",
        },
    },
}


def _cidr_overlaps(rule_cidr: str | None, flow_cidr: str) -> bool:
    if rule_cidr is None or rule_cidr == "0.0.0.0/0":
        return True
    try:
        rule_network = ipaddress.IPv4Network(rule_cidr, strict=False)
        flow_network = ipaddress.IPv4Network(flow_cidr, strict=False)
    except ValueError:
        return False
    return rule_network.overlaps(flow_network)


def _rule_matches_flow(rule, flow_class) -> bool:
    if not _cidr_overlaps(rule.src_ip, flow_class.src_cidr):
        return False
    if not _cidr_overlaps(rule.dst_ip, flow_class.dst_cidr):
        return False

    sample_src_ip = str(ipaddress.IPv4Network(flow_class.src_cidr, strict=False).network_address)
    if not _ip_matches_cidr(sample_src_ip, rule.src_ip):
        return False
    sample_dst_ip = str(ipaddress.IPv4Network(flow_class.dst_cidr, strict=False).network_address)
    if not _ip_matches_cidr(sample_dst_ip, rule.dst_ip):
        return False

    if rule.protocol != 0 and rule.protocol != flow_class.protocol:
        return False

    if rule.dst_port is None:
        return True
    if flow_class.dst_port is None:
        return True
    return _port_in_range(flow_class.dst_port, rule.dst_port)


def traffic_aware_greedy(rules, profile: TrafficProfile):
    def flow_weight(rule) -> float:
        for flow_class in sorted(profile.flow_classes, key=lambda flow: -flow.weight):
            if _rule_matches_flow(rule, flow_class):
                return flow_class.weight
        return 0.0

    return sorted(rules, key=lambda rule: -flow_weight(rule))


def _score_ruleset(rules, profile: TrafficProfile) -> dict[str, object]:
    score = compute_weighted_match_depth(rules, profile, n_samples=10000, seed=42)
    return {
        "rules": len(rules),
        "weighted_avg_depth": score["weighted_avg_depth"],
        "cpu_cost_estimate": score["cpu_cost_estimate"],
        "per_class_depth": score["per_class_depth"],
    }


def _display_name(scenario_key: str) -> str:
    if scenario_key == "k8s":
        return "K8s Microservices"
    return "Enterprise Departments"


def _find_best_baseline(results: dict[str, dict[str, object]]) -> str:
    baseline_names = [
        "static_analysis",
        "simulated_annealing",
        "random_reorder",
        "greedy_hitcount",
    ]
    return min(
        baseline_names,
        key=lambda name: (results[name]["rules"], results[name]["weighted_avg_depth"]),
    )


def _print_table(
    scenario_key: str, profile: TrafficProfile, results: dict[str, dict[str, object]]
) -> None:
    print(f"=== {_display_name(scenario_key)} (profile: {profile.name}) ===")
    print(f"{'Source':<24}{'Rules':>7}{'Weighted Depth':>16}{'CPU Cost Est':>14}")

    row_order = [
        "original",
        "static_analysis",
        "simulated_annealing",
        "random_reorder",
        "greedy_hitcount",
        "traffic_aware_greedy",
    ]

    for source in row_order:
        entry = results[source]
        print(
            f"{source:<24}{entry['rules']:>7}"
            f"{entry['weighted_avg_depth']:>16.2f}"
            f"{entry['cpu_cost_estimate']:>14.2f}"
        )
    print()


def _load_ruleset(repo_root: Path, relative_path: str):
    absolute_path = repo_root / relative_path
    if not absolute_path.exists():
        raise FileNotFoundError(f"Required ruleset file not found: {absolute_path}")
    return load_nft_as_rules(absolute_path)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    output_path = repo_root / "results" / "v4_gate_results.json"

    all_results: dict[str, dict[str, dict[str, object]]] = {}

    for scenario_key, raw_cfg in SCENARIOS.items():
        scenario_cfg: ScenarioConfig = raw_cfg
        profile = scenario_cfg["profile"]

        scenario_results: dict[str, dict[str, object]] = {}
        original_rules = _load_ruleset(repo_root, scenario_cfg["original"])
        scenario_results["original"] = _score_ruleset(original_rules, profile)

        baseline_rulesets = {}
        for baseline_name, baseline_path in scenario_cfg["baselines"].items():
            rules = _load_ruleset(repo_root, baseline_path)
            baseline_rulesets[baseline_name] = rules
            scenario_results[baseline_name] = _score_ruleset(rules, profile)

        best_baseline_name = _find_best_baseline(scenario_results)
        best_baseline_rules = baseline_rulesets[best_baseline_name]
        traffic_sorted_rules = traffic_aware_greedy(best_baseline_rules, profile)
        scenario_results["traffic_aware_greedy"] = _score_ruleset(traffic_sorted_rules, profile)

        all_results[scenario_key] = scenario_results
        _print_table(scenario_key, profile, scenario_results)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as out_file:
        json.dump(all_results, out_file, indent=4)

    print(f"Saved results to: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
