import pytest

from autonetworkpolicy.data.classbench_to_nft import Rule
from autonetworkpolicy.evaluate.weighted_match_depth import (
    ENTERPRISE_TRAFFIC,
    K8S_TRAFFIC,
    FlowClass,
    TrafficProfile,
    compute_weighted_match_depth,
)


def test_profile_weights_sum_to_one():
    assert isinstance(K8S_TRAFFIC, TrafficProfile)
    assert isinstance(ENTERPRISE_TRAFFIC, TrafficProfile)
    assert all(isinstance(flow, FlowClass) for flow in K8S_TRAFFIC.flow_classes)
    assert all(isinstance(flow, FlowClass) for flow in ENTERPRISE_TRAFFIC.flow_classes)

    k8s_weight = sum(flow.weight for flow in K8S_TRAFFIC.flow_classes)
    enterprise_weight = sum(flow.weight for flow in ENTERPRISE_TRAFFIC.flow_classes)

    assert k8s_weight == pytest.approx(1.0)
    assert enterprise_weight == pytest.approx(1.0)


def test_dns_first_lower_depth_than_dns_last():
    dns_rule = Rule("10.240.0.0/12", "10.241.0.0/24", None, (53, 53), 17, "accept", 0)
    http_rule = Rule("10.243.0.0/24", "10.243.10.0/24", None, (443, 443), 6, "accept", 1)
    catch_all_rule = Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 2)

    rules_dns_first = [
        dns_rule,
        http_rule,
        catch_all_rule,
    ]

    rules_dns_last = [
        http_rule,
        dns_rule,
        catch_all_rule,
    ]

    first_result = compute_weighted_match_depth(
        rules_dns_first,
        K8S_TRAFFIC,
        n_samples=5000,
        seed=42,
    )
    last_result = compute_weighted_match_depth(
        rules_dns_last,
        K8S_TRAFFIC,
        n_samples=5000,
        seed=42,
    )

    assert first_result["weighted_avg_depth"] < last_result["weighted_avg_depth"]


def test_per_class_depth_has_all_classes():
    rules = [Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 0)]
    result = compute_weighted_match_depth(rules, K8S_TRAFFIC, n_samples=500, seed=42)

    expected_classes = {flow_class.name for flow_class in K8S_TRAFFIC.flow_classes}
    assert set(result["per_class_depth"].keys()) == expected_classes


def test_result_keys():
    rules = [Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 0)]
    result = compute_weighted_match_depth(rules, K8S_TRAFFIC, n_samples=100, seed=42)

    assert set(result.keys()) == {
        "weighted_avg_depth",
        "per_class_depth",
        "cpu_cost_estimate",
    }


def test_deterministic_with_seed():
    rules = [
        Rule("10.240.0.0/12", "10.241.0.0/24", None, (53, 53), 17, "accept", 0),
        Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 1),
    ]

    result_a = compute_weighted_match_depth(rules, K8S_TRAFFIC, n_samples=2000, seed=42)
    result_b = compute_weighted_match_depth(rules, K8S_TRAFFIC, n_samples=2000, seed=42)

    assert result_a == result_b


def test_catch_all_gives_zero_depth():
    rules = [Rule("0.0.0.0/0", "0.0.0.0/0", None, None, 0, "accept", 0)]
    result = compute_weighted_match_depth(rules, K8S_TRAFFIC, n_samples=1000, seed=42)

    assert result["weighted_avg_depth"] == 0.0
    assert result["cpu_cost_estimate"] == 0.0
    assert all(depth == 0.0 for depth in result["per_class_depth"].values())
