from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass
from collections.abc import Sequence
from typing import Any, TypedDict

from autonetworkpolicy.evaluate.match_depth import _matches_rule


@dataclass
class FlowClass:
    name: str
    src_cidr: str
    dst_cidr: str
    protocol: int
    dst_port: int | None
    weight: float


@dataclass
class TrafficProfile:
    name: str
    flow_classes: list[FlowClass]

    def __post_init__(self) -> None:
        total_weight = sum(flow.weight for flow in self.flow_classes)
        if abs(total_weight - 1.0) > 1e-9:
            raise ValueError(f"TrafficProfile weights must sum to 1.0, got {total_weight}")


class WeightedMatchDepthResult(TypedDict):
    weighted_avg_depth: float
    per_class_depth: dict[str, float]
    cpu_cost_estimate: float


def _random_ip_in_cidr(rng: random.Random, cidr: str) -> str:
    network = ipaddress.IPv4Network(cidr, strict=False)
    if network.num_addresses == 1:
        return str(network.network_address)
    host_bits = 32 - network.prefixlen
    random_host = rng.randint(0, (1 << host_bits) - 1)
    return str(ipaddress.IPv4Address(int(network.network_address) + random_host))


def _generate_packet_for_flow_class(
    rng: random.Random,
    flow_class: FlowClass,
) -> tuple[str, str, int, int, int]:
    src_ip = _random_ip_in_cidr(rng, flow_class.src_cidr)
    dst_ip = _random_ip_in_cidr(rng, flow_class.dst_cidr)
    src_port = rng.randint(0, 65535)
    dst_port = flow_class.dst_port if flow_class.dst_port is not None else rng.randint(0, 65535)
    protocol = flow_class.protocol if flow_class.protocol != 0 else rng.choice([6, 17, 1])
    return (src_ip, dst_ip, src_port, dst_port, protocol)


def compute_weighted_match_depth(
    rules: Sequence[Any],
    profile: TrafficProfile,
    n_samples: int = 10000,
    seed: int = 42,
) -> WeightedMatchDepthResult:
    if n_samples <= 0:
        raise ValueError("n_samples must be greater than 0")

    rng = random.Random(seed)
    flow_classes = profile.flow_classes
    weights = [flow.weight for flow in flow_classes]

    total_depth = 0
    per_class_total_depth = {flow.name: 0 for flow in flow_classes}
    per_class_count = {flow.name: 0 for flow in flow_classes}

    for _ in range(n_samples):
        flow_class = rng.choices(flow_classes, weights=weights, k=1)[0]
        packet = _generate_packet_for_flow_class(rng, flow_class)
        match_depth = len(rules)

        for idx, rule in enumerate(rules):
            if _matches_rule(packet, rule):
                match_depth = idx
                break

        total_depth += match_depth
        per_class_total_depth[flow_class.name] += match_depth
        per_class_count[flow_class.name] += 1

    per_class_depth = {}
    for flow in flow_classes:
        count = per_class_count[flow.name]
        if count == 0:
            per_class_depth[flow.name] = float(len(rules))
        else:
            per_class_depth[flow.name] = per_class_total_depth[flow.name] / count

    weighted_avg_depth = total_depth / n_samples
    cpu_cost_estimate = sum(flow.weight * per_class_depth[flow.name] for flow in flow_classes)

    return {
        "weighted_avg_depth": weighted_avg_depth,
        "per_class_depth": per_class_depth,
        "cpu_cost_estimate": cpu_cost_estimate,
    }


K8S_TRAFFIC = TrafficProfile(
    "k8s_microservices",
    [
        FlowClass("dns_lookup", "10.240.0.0/12", "10.241.0.0/24", 17, 53, 0.40),
        FlowClass("http_frontend", "10.243.0.0/24", "10.243.10.0/24", 6, 443, 0.20),
        FlowClass("backend_api", "10.243.6.0/24", "10.243.2.0/24", 6, 8080, 0.15),
        FlowClass("db_query", "10.243.3.0/24", "10.243.5.0/24", 6, 5432, 0.10),
        FlowClass("monitoring", "10.243.8.0/24", "10.243.4.0/24", 6, 9090, 0.08),
        FlowClass("cache", "10.243.4.0/24", "10.243.8.0/24", 6, 6379, 0.05),
        FlowClass("background", "0.0.0.0/0", "0.0.0.0/0", 0, None, 0.02),
    ],
)


ENTERPRISE_TRAFFIC = TrafficProfile(
    "enterprise_departments",
    [
        FlowClass("eng_https", "10.3.0.0/16", "10.5.0.0/16", 6, 443, 0.25),
        FlowClass("eng_ssh", "10.3.0.0/16", "10.2.0.0/16", 6, 22, 0.15),
        FlowClass("finance_db", "10.2.0.0/16", "10.2.0.0/16", 6, 1433, 0.12),
        FlowClass("hr_web", "10.1.0.0/16", "10.5.0.0/16", 6, 80, 0.10),
        FlowClass("guest_web", "10.5.0.0/16", "10.4.0.0/16", 6, 80, 0.10),
        FlowClass("exec_https", "10.4.0.0/16", "10.5.0.0/16", 6, 443, 0.08),
        FlowClass("cross_dept", "10.0.0.0/8", "10.0.0.0/8", 6, None, 0.10),
        FlowClass("guest_blocked", "10.5.0.0/16", "10.0.0.0/8", 6, None, 0.05),
        FlowClass("background", "0.0.0.0/0", "0.0.0.0/0", 0, None, 0.05),
    ],
)
