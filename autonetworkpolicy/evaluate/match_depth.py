from __future__ import annotations

import ipaddress
import random
from typing import Protocol


class RuleLike(Protocol):
    src_ip: str | None
    dst_ip: str | None
    src_port: tuple[int, int] | None
    dst_port: tuple[int, int] | None
    protocol: int


def _generate_random_packet(rng: random.Random) -> tuple[str, str, int, int, int]:
    src_ip = str(ipaddress.IPv4Address(rng.getrandbits(32)))
    dst_ip = str(ipaddress.IPv4Address(rng.getrandbits(32)))
    src_port = rng.randint(0, 65535)
    dst_port = rng.randint(0, 65535)
    protocol = rng.choice([6, 17, 1])  # TCP, UDP, ICMP
    return (src_ip, dst_ip, src_port, dst_port, protocol)


def _port_in_range(port: int, port_range: tuple[int, int] | None) -> bool:
    if port_range is None:
        return True
    return port_range[0] <= port <= port_range[1]


def _matches_rule(packet: tuple[str, str, int, int, int], rule: RuleLike) -> bool:
    src_ip, dst_ip, src_port, dst_port, protocol = packet
    if not _ip_matches_cidr(src_ip, rule.src_ip):
        return False
    if not _ip_matches_cidr(dst_ip, rule.dst_ip):
        return False
    if not _port_in_range(src_port, rule.src_port):
        return False
    if not _port_in_range(dst_port, rule.dst_port):
        return False
    if rule.protocol != 0 and rule.protocol != protocol:
        return False
    return True


def _ip_matches_cidr(ip_str: str, cidr: str | None) -> bool:
    if cidr is None or cidr == "0.0.0.0/0":
        return True

    try:
        network = ipaddress.ip_network(cidr, strict=False)
        address = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False

    return bool(address in network)


def compute_match_depth(rules: list[RuleLike], n_samples: int = 1000, seed: int = 42) -> float:
    if n_samples <= 0:
        raise ValueError("n_samples must be greater than 0")

    rng = random.Random(seed)
    total_depth = 0

    for _ in range(n_samples):
        packet = _generate_random_packet(rng)
        match_index = len(rules)

        for idx, rule in enumerate(rules):
            if _matches_rule(packet, rule):
                match_index = idx
                break

        total_depth += match_index

    return total_depth / n_samples
