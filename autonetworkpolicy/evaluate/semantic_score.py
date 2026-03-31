#!/usr/bin/env python3

from __future__ import annotations

from collections import Counter

from ..data.classbench_to_nft import Rule


def _rule_signature(rule: Rule) -> tuple[object, ...]:
    return (
        rule.src_ip,
        rule.dst_ip,
        rule.src_port,
        rule.dst_port,
        rule.protocol,
        rule.action,
    )


def _group_adjacency_score(required_positions: list[int]) -> float:
    if len(required_positions) <= 1:
        return 1.0

    contiguous_pairs = 0
    for idx in range(len(required_positions) - 1):
        if required_positions[idx + 1] - required_positions[idx] == 1:
            contiguous_pairs += 1
    return contiguous_pairs / (len(required_positions) - 1)


def compute_semantic_preservation(
    original_rules: list[Rule],
    optimized_rules: list[Rule],
    semantic_groups: dict[str, list[int]],
) -> float:
    """Score semantic-group adjacency preservation from 0.0 to 1.0."""
    if not semantic_groups:
        return 1.0

    original_signatures = [_rule_signature(rule) for rule in original_rules]
    optimized_signatures = [_rule_signature(rule) for rule in optimized_rules]

    group_scores: list[float] = []

    for group_indices in semantic_groups.values():
        valid_indices = [i for i in group_indices if 0 <= i < len(original_signatures)]
        if not valid_indices:
            group_scores.append(0.0)
            continue

        required = [original_signatures[i] for i in valid_indices]
        required_counts: Counter[tuple[object, ...]] = Counter(required)

        matched_positions: list[int] = []
        seen_counts: Counter[tuple[object, ...]] = Counter()
        for position, signature in enumerate(optimized_signatures):
            if signature not in required_counts:
                continue
            if seen_counts[signature] >= required_counts[signature]:
                continue
            seen_counts[signature] += 1
            matched_positions.append(position)

        if sum(seen_counts.values()) < len(required):
            group_scores.append(0.0)
            continue

        matched_positions.sort()
        group_scores.append(_group_adjacency_score(matched_positions))

    if not group_scores:
        return 1.0

    return sum(group_scores) / len(group_scores)
