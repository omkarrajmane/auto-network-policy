# AutoNetworkPolicy

**AI-guided firewall optimization with formal verification.** Every mutation is mathematically proven to preserve packet-filtering behavior.

An LLM proposes structural mutations to nftables rulesets via a constrained DSL. A BDD verifier proves equivalence. A containerlab measures real throughput. The loop repeats until the firewall is lean.

---

## Why This Exists

Enterprise firewalls accumulate hundreds of rules over years. Nobody removes them because deleting the wrong rule means an outage. AutoNetworkPolicy automates the cleanup — and guarantees correctness.

## How It Works

```
                    ┌─────────────────┐
                    │   Input Ruleset  │
                    │  (nftables .nft) │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │   LLM Proposer   │
                    │  Constrained DSL │
                    │  (swap, merge,   │
                    │   move, remove)  │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
              ┌─────│  BDD Verifier    │─────┐
              │     │  (formal proof)  │     │
              │     └─────────────────┘     │
          equivalent                    not equivalent
              │                              │
     ┌────────▼────────┐                  discard
     │  Containerlab    │                  mutation
     │  (throughput)    │
     └────────┬────────┘
              │
     ┌────────▼────────┐
     │  Accept / Reject │
     │  (score-based)   │
     └─────────────────┘
```

The autoresearch loop (inspired by [Karpathy's autoresearch](https://github.com/karpathy/autoresearch)) iteratively improves the ruleset. The LLM sees past mutations, scores, and failures — learning what works across iterations.

## Key Results

Tested against 4 classical baselines across enterprise-scale rulesets (300-500 rules):

| Algorithm | Strategy | Avg Rule Reduction |
|---|---|---|
| **LLM (Claude Opus)** | Autoresearch loop + DSL mutations | **Up to 85%** |
| Static Analysis | Deterministic shadow removal | ~75% |
| Simulated Annealing | SA metaheuristic | ~76% |
| Greedy Hitcount | Sort by specificity | ~42% |

The LLM doesn't just remove dead rules — it discovers reordering opportunities that classical algorithms miss by reasoning about traffic flow semantics.

## Quick Start

```bash
# Clone
git clone https://github.com/omkarrajmane/auto-network-policy.git
cd auto-network-policy/autonetworkpolicy

# Install dependencies
uv sync

# Deploy test lab (requires Docker + Containerlab)
lab/deploy.sh

# Run the autoresearch loop
python run.py --input data/generated/acl1_500.nft --experiments 10

# Or run baselines for comparison
python scripts/run_baselines.py --all
```

### Requirements

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (package manager)
- Docker + [Containerlab](https://containerlab.dev/)
- Claude CLI or OpenRouter API key (`OPENROUTER_API_KEY` env var)

## Project Structure

```
autonetworkpolicy/
├── run.py                  # Main autoresearch loop
├── config.yaml             # Configuration
├── mutations.py            # Mutation DSL engine (swap/move/merge/remove)
├── agent/
│   ├── provider.py         # LLM provider abstraction (Claude, OpenRouter)
│   └── proposer.py         # Builds prompts, parses mutation responses
├── verify/
│   └── bdd_verify.py       # BDD formal equivalence checker
├── evaluate/
│   ├── pipeline.py         # Apply → verify → measure → score
│   ├── match_depth.py      # Weighted match-depth scoring
│   └── traffic_simulator.py
├── baselines/
│   ├── static_analysis.py  # Deterministic shadow removal
│   ├── simulated_annealing.py
│   ├── greedy_hitcount.py
│   └── random_reorder.py
├── data/
│   ├── classbench_to_nft.py  # ClassBench → nftables parser
│   └── generate_seed.py
├── benchmarks/             # Test scenarios (.nft files)
├── lab/                    # Containerlab topology + Dockerfile
├── utils/                  # Shadow detection, logging, git tracking
├── scripts/                # Experiment runners, report generators
└── results/                # Experiment outputs, figures, comparisons
```

## Mutation DSL

Instead of generating full rulesets, the LLM proposes constrained, verifiable mutations:

| Mutation | Description |
|---|---|
| `swap(i, j)` | Swap rules at positions i and j |
| `move_before(i, j)` | Move rule i before rule j |
| `merge_adjacent(i)` | Merge rule i with i+1 if compatible |
| `remove_shadowed(i)` | Remove rule i if fully shadowed by earlier rules |

Every mutation is verified by the BDD checker before acceptance. Invalid mutations are discarded — the ruleset never breaks.

## Formal Verification

Uses Binary Decision Diagrams (BDDs) to prove that each mutation preserves the original packet-filtering semantics. The verifier checks equivalence across the full 5-tuple space (src IP, dst IP, src port, dst port, protocol).

A mutation is accepted **only** if `BDD(original) ≡ BDD(mutated)` for all possible packets.

## Benchmark Scenarios

| Scenario | Rules | Description |
|---|---|---|
| `over_permissive_legacy_500` | 500 | Legacy rules with overly-broad permits |
| `broken_segmentation_300` | 300 | Segmentation rules allowing unintended traffic |
| `redundant_shadowing_400` | 400 | Extensive shadow relationships between rules |
| `port_heavy_enterprise_500` | 500 | Enterprise ruleset with complex port ranges |
| `mixed_protocol_400` | 400 | Multi-protocol environment |

Plus semantic benchmarks modeling real-world topologies (K8s microservices, enterprise departments, VLAN segmentation).

## Configuration

Edit `autonetworkpolicy/config.yaml`:

```yaml
llm:
  provider: claude_subprocess  # or openrouter
  model: claude-opus-4-20250514
  temperature: 0.2

experiment:
  max_iterations: 100
  auto_branch: true            # Git branch per experiment run
```

## License

MIT
