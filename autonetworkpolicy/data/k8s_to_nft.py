#!/usr/bin/env python3
"""Convert Kubernetes NetworkPolicy YAML fixtures into nftables benchmarks."""

from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml

from .classbench_to_nft import Rule, rules_to_nft
from .semantic_generator import (
    CROSS_DEPARTMENT_POLICIES,
    DEPARTMENTS,
    TIERS,
    TIER_POLICIES,
    ZONES,
    ZONE_POLICIES,
    generate_department_ruleset,
    generate_tiered_ruleset,
    generate_zone_ruleset,
    inject_optimization_opportunities,
)


@dataclass
class K8sNetworkPolicy:
    name: str
    namespace: str
    pod_selector: dict[str, str]
    policy_types: list[str]
    ingress: list[dict[str, Any]]
    egress: list[dict[str, Any]]


def _normalized_labels(selector: Optional[dict[str, Any]]) -> dict[str, str]:
    if not selector:
        return {}
    labels = selector.get("matchLabels", selector)
    if not isinstance(labels, dict):
        return {}
    return {str(k): str(v) for k, v in labels.items()}


def _selector_key(namespace: str, labels: dict[str, str]) -> str:
    if not labels:
        return f"ns={namespace};labels=*"
    ordered = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
    return f"ns={namespace};labels={ordered}"


def _label_text(labels: dict[str, str]) -> str:
    if not labels:
        return "all"
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _protocol_number(protocol_name: Optional[str]) -> int:
    if not protocol_name:
        return 0
    proto = str(protocol_name).upper()
    mapping = {"TCP": 6, "UDP": 17, "ICMP": 1}
    return mapping.get(proto, 0)


def _namespace_for_peer(peer: dict[str, Any], default_namespace: str) -> str:
    ns_selector = peer.get("namespaceSelector", {})
    ns_labels = _normalized_labels(ns_selector)
    if "kubernetes.io/metadata.name" in ns_labels:
        return ns_labels["kubernetes.io/metadata.name"]
    return default_namespace


def load_k8s_policies(yaml_path: str) -> list[K8sNetworkPolicy]:
    """Parse multi-document YAML into K8sNetworkPolicy objects."""
    policies: list[K8sNetworkPolicy] = []
    with open(yaml_path, "r") as f:
        documents = yaml.safe_load_all(f)
        for document in documents:
            if not document or document.get("kind") != "NetworkPolicy":
                continue

            metadata = document.get("metadata", {})
            spec = document.get("spec", {})
            policy = K8sNetworkPolicy(
                name=str(metadata.get("name", "unnamed-policy")),
                namespace=str(metadata.get("namespace", "default")),
                pod_selector=_normalized_labels(spec.get("podSelector", {})),
                policy_types=[str(x) for x in spec.get("policyTypes", [])],
                ingress=list(spec.get("ingress", []) or []),
                egress=list(spec.get("egress", []) or []),
            )
            policies.append(policy)
    return policies


def generate_ip_mapping(policies: list[K8sNetworkPolicy]) -> dict[str, str]:
    """Auto-generate label->subnet mapping using namespace /16 and selector /24."""
    selector_pairs: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for policy in policies:
        selector_pairs.add((policy.namespace, tuple(sorted(policy.pod_selector.items()))))

        for ingress_rule in policy.ingress:
            for peer in ingress_rule.get("from", []) or []:
                peer_labels = _normalized_labels(peer.get("podSelector", {}))
                peer_ns = _namespace_for_peer(peer, policy.namespace)
                selector_pairs.add((peer_ns, tuple(sorted(peer_labels.items()))))

        for egress_rule in policy.egress:
            for peer in egress_rule.get("to", []) or []:
                peer_labels = _normalized_labels(peer.get("podSelector", {}))
                peer_ns = _namespace_for_peer(peer, policy.namespace)
                selector_pairs.add((peer_ns, tuple(sorted(peer_labels.items()))))

    namespaces = sorted({namespace for namespace, _ in selector_pairs})
    namespace_blocks: dict[str, ipaddress.IPv4Network] = {}
    for idx, namespace in enumerate(namespaces):
        namespace_blocks[namespace] = ipaddress.IPv4Network(f"10.{240 + idx}.0.0/16")

    grouped: dict[str, list[tuple[str, tuple[tuple[str, str], ...]]]] = {}
    for namespace, labels in selector_pairs:
        grouped.setdefault(namespace, []).append((namespace, labels))

    mapping: dict[str, str] = {}
    for namespace, selectors in grouped.items():
        block = namespace_blocks[namespace]
        subnets = list(block.subnets(new_prefix=24))
        for idx, (_, labels_tuple) in enumerate(sorted(selectors, key=lambda x: x[1])):
            labels = dict(labels_tuple)
            key = _selector_key(namespace, labels)
            mapping[key] = str(subnets[idx % len(subnets)])

    return mapping


def _subnet_for(
    ip_mapping: dict[str, str], namespace: str, labels: dict[str, str], fallback: str = "0.0.0.0/0"
) -> str:
    return ip_mapping.get(_selector_key(namespace, labels), fallback)


def _ports_from_rule(port_entries: list[dict[str, Any]]) -> list[tuple[int, Optional[int]]]:
    if not port_entries:
        return [(0, None)]

    ports: list[tuple[int, Optional[int]]] = []
    for entry in port_entries:
        proto_num = _protocol_number(entry.get("protocol", "TCP"))
        port_value = entry.get("port")
        if isinstance(port_value, int):
            ports.append((proto_num, port_value))
    return ports or [(0, None)]


def k8s_to_rules(policies: list[K8sNetworkPolicy], ip_mapping: dict[str, str]) -> list[Rule]:
    """Convert policies to Rule objects with semantic comments."""
    rules: list[Rule] = []

    for policy in policies:
        dst_labels = policy.pod_selector
        dst_subnet = _subnet_for(ip_mapping, policy.namespace, dst_labels)

        if "Ingress" in policy.policy_types:
            ingress_rules = policy.ingress or [{"from": [{"podSelector": {}}], "ports": []}]
            for ingress_rule in ingress_rules:
                peers = ingress_rule.get("from", []) or [{}]
                for peer in peers:
                    src_labels = _normalized_labels(peer.get("podSelector", {}))
                    src_ns = _namespace_for_peer(peer, policy.namespace)
                    src_subnet = _subnet_for(ip_mapping, src_ns, src_labels)
                    for proto_num, port in _ports_from_rule(ingress_rule.get("ports", []) or []):
                        proto_text = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "ANY"}.get(
                            proto_num, "ANY"
                        )
                        port_text = "any" if port is None else str(port)
                        rules.append(
                            Rule(
                                src_ip=src_subnet,
                                dst_ip=dst_subnet,
                                src_port=None,
                                dst_port=None if port is None else (port, port),
                                protocol=proto_num,
                                action="accept",
                                index=len(rules),
                                comment=(
                                    f"# Policy: {policy.name} (namespace: {policy.namespace}) - "
                                    f"From: {src_ns}[{_label_text(src_labels)}] -> "
                                    f"To: {policy.namespace}[{_label_text(dst_labels)}], port {proto_text}/{port_text}"
                                ),
                            )
                        )

        if "Egress" in policy.policy_types:
            egress_rules = policy.egress or [{"to": [{}], "ports": []}]
            for egress_rule in egress_rules:
                peers = egress_rule.get("to", []) or [{}]
                for peer in peers:
                    dst_peer_labels = _normalized_labels(peer.get("podSelector", {}))
                    dst_ns = _namespace_for_peer(peer, policy.namespace)
                    dst_peer_subnet = _subnet_for(ip_mapping, dst_ns, dst_peer_labels)
                    for proto_num, port in _ports_from_rule(egress_rule.get("ports", []) or []):
                        proto_text = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "ANY"}.get(
                            proto_num, "ANY"
                        )
                        port_text = "any" if port is None else str(port)
                        rules.append(
                            Rule(
                                src_ip=dst_subnet,
                                dst_ip=dst_peer_subnet,
                                src_port=None,
                                dst_port=None if port is None else (port, port),
                                protocol=proto_num,
                                action="accept",
                                index=len(rules),
                                comment=(
                                    f"# Policy: {policy.name} (namespace: {policy.namespace}) - "
                                    f"From: {policy.namespace}[{_label_text(dst_labels)}] -> "
                                    f"To: {dst_ns}[{_label_text(dst_peer_labels)}], port {proto_text}/{port_text}"
                                ),
                            )
                        )

    rules.append(
        Rule(
            src_ip="0.0.0.0/0",
            dst_ip="0.0.0.0/0",
            src_port=None,
            dst_port=None,
            protocol=0,
            action="drop",
            index=len(rules),
            comment="# Default deny: unmatched traffic dropped",
        )
    )

    for idx, rule in enumerate(rules):
        rule.index = idx

    return rules


def k8s_to_nft(
    yaml_path: str, output_path: str, ip_mapping: Optional[dict[str, str]] = None
) -> None:
    """Full pipeline: YAML -> nftables file."""
    policies = load_k8s_policies(yaml_path)
    resolved_mapping = ip_mapping if ip_mapping is not None else generate_ip_mapping(policies)
    rules = k8s_to_rules(policies, resolved_mapping)
    nft_config = rules_to_nft(rules)

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        f.write(nft_config)


def _inflate_k8s_rules(base_rules: list[Rule], target_count: int = 200) -> list[Rule]:
    if len(base_rules) >= target_count:
        return base_rules

    default_drop = base_rules[-1] if base_rules and base_rules[-1].action == "drop" else None
    working = base_rules[:-1] if default_drop else list(base_rules)
    expanded: list[Rule] = [
        Rule(
            src_ip=r.src_ip,
            dst_ip=r.dst_ip,
            src_port=r.src_port,
            dst_port=r.dst_port,
            protocol=r.protocol,
            action=r.action,
            index=r.index,
            comment=r.comment,
        )
        for r in working
    ]

    variant = 0
    target_without_drop = target_count - (1 if default_drop else 0)
    while len(expanded) < target_without_drop:
        template = working[variant % len(working)]
        src = template.src_ip
        dst = template.dst_ip

        try:
            src_net = ipaddress.ip_network(src, strict=False)
            if src_net.prefixlen <= 24:
                src = str(
                    list(src_net.subnets(new_prefix=min(30, src_net.prefixlen + 2)))[variant % 4]
                )
        except ValueError:
            pass

        try:
            dst_net = ipaddress.ip_network(dst, strict=False)
            if dst_net.prefixlen <= 24:
                dst = str(
                    list(dst_net.subnets(new_prefix=min(30, dst_net.prefixlen + 2)))[variant % 4]
                )
        except ValueError:
            pass

        expanded.append(
            Rule(
                src_ip=src,
                dst_ip=dst,
                src_port=template.src_port,
                dst_port=template.dst_port,
                protocol=template.protocol,
                action=template.action,
                index=len(expanded),
                comment=f"{template.comment} [expanded-{variant + 1}]"
                if template.comment
                else None,
            )
        )
        variant += 1

    if default_drop:
        expanded.append(
            Rule(
                src_ip=default_drop.src_ip,
                dst_ip=default_drop.dst_ip,
                src_port=default_drop.src_port,
                dst_port=default_drop.dst_port,
                protocol=default_drop.protocol,
                action=default_drop.action,
                index=len(expanded),
                comment=default_drop.comment,
            )
        )

    for idx, rule in enumerate(expanded):
        rule.index = idx
    return expanded


def generate_semantic_benchmarks(workspace_root: str) -> None:
    """Generate all semantic benchmark nft files used in V3 experiments."""
    root = Path(workspace_root)
    semantic_dir = root / "benchmarks" / "semantic"
    semantic_dir.mkdir(parents=True, exist_ok=True)

    yaml_fixture = semantic_dir / "k8s_source_policies.yaml"
    k8s_policies = load_k8s_policies(str(yaml_fixture))
    k8s_mapping = generate_ip_mapping(k8s_policies)
    k8s_rules = k8s_to_rules(k8s_policies, k8s_mapping)
    k8s_rules = _inflate_k8s_rules(k8s_rules, target_count=200)
    with open(semantic_dir / "k8s_microservices_200.nft", "w") as f:
        f.write(rules_to_nft(k8s_rules))

    department_rules = generate_department_ruleset(
        DEPARTMENTS,
        CROSS_DEPARTMENT_POLICIES,
        rules_per_department=100,
        seed=42,
    )
    department_rules = inject_optimization_opportunities(department_rules, seed=42)
    with open(semantic_dir / "enterprise_departments_500.nft", "w") as f:
        f.write(rules_to_nft(department_rules))

    tier_rules = generate_tiered_ruleset(
        TIERS,
        TIER_POLICIES,
        rules_per_tier=75,
        seed=42,
    )
    tier_rules = inject_optimization_opportunities(tier_rules, seed=43)
    with open(semantic_dir / "three_tier_app_300.nft", "w") as f:
        f.write(rules_to_nft(tier_rules))

    zone_rules = generate_zone_ruleset(
        ZONES,
        ZONE_POLICIES,
        rules_per_zone=100,
        seed=42,
    )
    zone_rules = inject_optimization_opportunities(zone_rules, seed=44)
    with open(semantic_dir / "vlan_segmentation_400.nft", "w") as f:
        f.write(rules_to_nft(zone_rules))


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert K8s policies to nftables")
    parser.add_argument("--yaml", type=str, default=None, help="Input NetworkPolicy YAML file")
    parser.add_argument("--output", type=str, default=None, help="Output nft file")
    parser.add_argument(
        "--generate-semantic-benchmarks",
        action="store_true",
        help="Generate all V3 semantic benchmark files",
    )
    args = parser.parse_args()

    if args.generate_semantic_benchmarks:
        workspace_root = str(Path(__file__).resolve().parent.parent)
        generate_semantic_benchmarks(workspace_root)
        print("Generated semantic benchmarks under benchmarks/semantic")
        return 0

    if not args.yaml or not args.output:
        parser.error("Provide --yaml and --output, or use --generate-semantic-benchmarks")

    k8s_to_nft(args.yaml, args.output)
    print(f"Converted {args.yaml} -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
