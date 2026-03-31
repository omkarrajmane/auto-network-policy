"""
Evaluation package for AutoNetworkPolicy.

This package provides tools for evaluating firewall policy performance:
- TrafficSimulator: Generate and measure traffic between containers
- EvaluationPipeline: Orchestrate complete policy evaluation
- CounterReader: Read and analyze nftables counter statistics
- Iperf3Server, Iperf3Client: Interface to iperf3 for throughput testing
"""

from .counter_reader import CounterReader
from .traffic_simulator import TrafficSimulator

try:
    from .pipeline import EvaluationPipeline
except ImportError:
    pass

try:
    from .iperf3_wrapper import Iperf3Server, Iperf3Client
except ImportError:
    pass

__all__ = [
    "CounterReader",
    "TrafficSimulator",
    "EvaluationPipeline",
    "Iperf3Server",
    "Iperf3Client",
]
