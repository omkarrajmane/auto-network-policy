# AutoNetworkPolicy v2.1

AI-guided firewall policy optimization using an autoresearch loop.

## Overview

This research system uses an autoresearch loop to optimize nftables firewall policies:
1. LLM proposes mutations via a constrained DSL
2. BDD verifies packet-filtering equivalence
3. Containerlab measures real throughput
4. Git tracks accepted improvements

## Quick Start

```bash
# Install dependencies
uv sync

# Deploy test lab
lab/deploy.sh

# Run autoresearch loop
python run.py --input data/generated/acl1_500.nft --experiments 10

# Run all baselines on all benchmark scenarios
cd scripts && python run_baselines.py --all

# Run with custom SA parameters
python run_baselines.py --all --sa-temperature 150 --sa-cooling 0.98 --iterations 200

# Run a specific algorithm/scenario pair
python run_baselines.py --algorithm static_analysis --scenario redundant_shadowing
```

## Project Structure

```
autonetworkpolicy/
├── config.yaml              # All configuration
├── pyproject.toml           # Python dependencies (uv)
├── README.md
├── results.tsv              # Experiment log (1 header + data rows, no duplicates)
├── lab/                     # Containerlab topology
├── data/                    # ClassBench rulesets
│   ├── classbench_to_nft.py # Rule parsing/serialisation + Rule dataclass
│   └── generate_seed.py     # 500-rule seed ruleset generator
├── verify/                  # BDD verification
│   └── bdd_verify.py        # IP-only BDD equivalence checker (v1)
├── evaluate/                # Performance evaluation
│   ├── pipeline.py          # Orchestration: apply → verify → measure → score
│   ├── iperf3_wrapper.py    # iperf3 subprocess wrapper
│   ├── counter_reader.py    # nftables rule hit-counter reader
│   └── traffic_simulator.py # Synthetic traffic generator for testing
├── agent/                   # LLM integration
│   ├── provider.py          # OpenRouter / LLM provider abstraction
│   └── proposer.py          # Mutation proposer: builds prompt, parses response
├── mutations.py             # Deterministic mutation engine (swap/move/merge/remove)
├── run.py                   # Main autoresearch loop
├── baselines/               # Baseline implementations
│   ├── greedy_hitcount.py   # Sort by hit count / specificity, remove shadowed
│   ├── simulated_annealing.py  # SA metaheuristic with swap+shadow-removal moves
│   ├── random_reorder.py    # Random shuffle baseline
│   └── static_analysis.py  # Deterministic duplicate+shadow removal
├── utils/
│   ├── shadow.py            # Shared shadow-detection utilities (v1.1)
│   ├── results_logger.py    # TSV experiment logger with dedup/idempotency
│   ├── git_tracker.py       # Git commit/diff helpers
│   └── experiment_logger.py # JSON experiment telemetry
├── scripts/
│   ├── run_baselines.py     # Baseline execution suite (all 4 × all 3 scenarios)
│   ├── run_llm_experiments.py  # LLM experiment runner
│   ├── run_phase10_experiments.py  # Phase 10 orchestration
│   ├── generate_benchmarks.py   # Benchmark scenario generator
│   ├── generate_report.py   # Markdown report generator
│   ├── analyze_mutations.py # Mutation effectiveness analysis
│   └── validate_benchmarks.py  # Benchmark file integrity checker
├── benchmarks/              # Benchmark scenario .nft files
│   ├── over_permissive_legacy_500.nft
│   ├── broken_segmentation_300.nft
│   └── redundant_shadowing_400.nft
├── results/                 # Experiment outputs
│   ├── baselines/           # CSV/JSON/NFT outputs per algorithm
│   └── report_v2.1_experiments.md
└── docs/
    └── lessons_learned.md   # Phase 10 findings, failure modes, recommendations
```

## Key Components

### Mutation DSL

Instead of generating full rulesets, the LLM proposes constrained mutations:
- `swap(i, j)`: Swap rules at indices i and j
- `move_before(i, j)`: Move rule i before rule j
- `merge_adjacent(i)`: Merge rule i with i+1 if compatible
- `remove_shadowed(i)`: Remove rule i if fully shadowed

### BDD Verification

Uses Binary Decision Diagrams to verify that mutations preserve packet-filtering behavior:
- **v1**: IP-only mode (deliberate tradeoff for performance)
- **v2**: Full 5-tuple verification (planned for v2.2)

### Shadow Detection (`utils/shadow.py`)

Shared utility used by all 4 baselines. A rule B is shadowed by rule A when:
- Same action
- A's protocol is 0/any OR same protocol as B
- A's src_ip network contains B's src_ip network
- A's dst_ip network contains B's dst_ip network
- A's src_port range contains B's src_port range (None = any = contains all)
- A's dst_port range contains B's dst_port range

**v1.1 added port-range containment.** `random_reorder` previously omitted the
protocol check — this was fixed when the shared utility was introduced.

### Baseline Algorithms

| Algorithm | Strategy | Avg Rule Reduction |
|-----------|----------|--------------------|
| Random Reorder | Shuffle + shadow removal | ~76% |
| Simulated Annealing | SA metaheuristic, swap+shadow moves | ~75.7% |
| Static Analysis | Deterministic duplicate+shadow removal | ~75.3% |
| Greedy Hitcount | Sort by specificity, shadow removal | ~41.6% (high variance) |

Run with `scripts/run_baselines.py`. Results are written to:
- `results/baselines/baselines_comparison.csv`
- `results/baselines/baselines_comparison.json`
- `results.tsv` (idempotent — no duplicate rows appended)

### Experiment Tracking (`utils/results_logger.py`)

Git-native tracking via `results.tsv`:
```
commit	score	throughput_gbps	rule_count	status	description
a1b2c3d	1.234	0.00	500	keep	baseline
e4f5g6h	1.250	0.00	480	keep	swap(5,12) improved hit rate
```

**Note:** `throughput_gbps` is always `0.00` — it is a placeholder column.
Live throughput measurement via iperf3/Containerlab is not yet wired into the
autoresearch loop.

Key methods:
- `log_iteration(...)` — append a row
- `has_entry(description, status)` — idempotency check before appending
- `deduplicate()` — remove exact duplicate rows, rewrite file
- `remove_by_status(status)` — remove all rows with given status (used by `--clean`)

## Benchmark Scenarios

| Scenario | Rules | Description |
|----------|-------|-------------|
| `over_permissive_legacy_500.nft` | 500 | Legacy ruleset with many overly-broad rules |
| `broken_segmentation_300.nft` | 300 | Segmentation rules that allow unintended traffic |
| `redundant_shadowing_400.nft` | 400 | Ruleset with extensive shadow relationships |

## run_baselines.py CLI Reference

```
python scripts/run_baselines.py --all                          # All 4 algorithms × 3 scenarios
python scripts/run_baselines.py --algorithm simulated_annealing --scenario over_permissive
python scripts/run_baselines.py --all --iterations 200         # Custom iteration count
python scripts/run_baselines.py --all --sa-temperature 150 --sa-cooling 0.98
python scripts/run_baselines.py --all --clean                  # Wipe old baseline TSV rows first
python scripts/run_baselines.py --list-scenarios
```

## Configuration

Edit `config.yaml` to customize:
- LLM provider (OpenRouter with Gemini Flash 2.5)
- Verification backend
- Evaluation parameters
- Experiment limits

## Dependencies

- Python 3.10+
- Docker + Containerlab
- uv (Python package manager)

See `pyproject.toml` for Python dependencies.

## Phase History

| Phase | Commit | What was built |
|-------|--------|----------------|
| 1 | `11d7f8c` | Foundation, project layout |
| 2 | `821a17b` – `ef86bb5` | ClassBench parser, seed ruleset generator |
| 3 | `7cba4ed` – `53e1253` | BDD verifier, tests, benchmarks |
| 4 | `27caf78` – `0ffd7da` | Evaluation pipeline, iperf3, counter reader, traffic sim |
| 5 | `118eb31` – `cb15203` | LLM provider, mutation proposer, DSL schema |
| 6 | `105919e` | Mutation engine (swap/move/merge/remove) |
| 7 | `1ff6d36` | All 4 baseline algorithms |
| 8 | `d18b565` – `785c3d4` | `run.py` autoresearch loop, git tracker, results logger |
| 9 | `7b11d06` | Validation and preflight scripts |
| 10 | `0ddbfca` | Phase 10 experiments (Gemini Flash, 12 baseline runs, 10 LLM runs) |
| minor | `246628f` | Shared shadow utils, port-range shadowing, dedup/idempotency, SA CLI args |

## License

MIT
