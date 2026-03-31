# AutoNetworkPolicy v2.1 - Phase 10 Experiment Report

**Generated:** 2026-03-18 01:18:00

---

## Executive Summary

- **Total baseline runs:** 12
- **Scenarios tested:** 3
- **Algorithms compared:** 4
- **Average rule reduction:** 67.1%
- **Best rule reduction:** 82.9%

- **LLM experiments:** 10
- **Successful LLM runs:** 10/10

---

## Baseline Algorithm Comparison


### Over Permissive

| Algorithm | Before | After | Reduced | % | Time (s) |
|-----------|--------|-------|---------|---|----------|
| random_reorder | 499 | 107 | 392 | 78.6% | 9.128s |
| simulated_annealing | 499 | 114 | 385 | 77.2% | 0.982s |
| static_analysis | 499 | 119 | 380 | 76.2% | 0.065s |
| greedy_hitcount | 499 | 245 | 254 | 50.9% | 0.130s |

### Broken Segmentation

| Algorithm | Before | After | Reduced | % | Time (s) |
|-----------|--------|-------|---------|---|----------|
| random_reorder | 299 | 51 | 248 | 82.9% | 2.895s |
| greedy_hitcount | 299 | 84 | 215 | 71.9% | 0.030s |
| static_analysis | 299 | 84 | 215 | 71.9% | 0.017s |
| simulated_annealing | 299 | 84 | 215 | 71.9% | 0.444s |

### Redundant Shadowing

| Algorithm | Before | After | Reduced | % | Time (s) |
|-----------|--------|-------|---------|---|----------|
| static_analysis | 399 | 88 | 311 | 77.9% | 0.044s |
| simulated_annealing | 399 | 88 | 311 | 77.9% | 0.640s |
| random_reorder | 399 | 134 | 265 | 66.4% | 14.089s |
| greedy_hitcount | 399 | 391 | 8 | 2.0% | 0.097s |

---

## LLM-Guided Optimization Results

### llm_trial_over_permissive_run3

- **Scenario:** over_permissive
- **Iterations:** 4
- **Successful mutations:** 4
- **Verification pass rate:** 100%
- **Baseline score:** 499.00
- **Best score:** 950.50
- **Improvement:** 90.5%

### llm_trial_over_permissive_run2

- **Scenario:** over_permissive
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 499.00
- **Best score:** 950.60
- **Improvement:** 90.5%

### llm_trial_broken_segmentation_run2

- **Scenario:** broken_segmentation
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 299.00
- **Best score:** 970.60
- **Improvement:** 224.6%

### llm_trial_over_permissive_run1

- **Scenario:** over_permissive
- **Iterations:** 4
- **Successful mutations:** 4
- **Verification pass rate:** 100%
- **Baseline score:** 499.00
- **Best score:** 950.50
- **Improvement:** 90.5%

### llm_trial_redundant_shadowing_run1

- **Scenario:** redundant_shadowing
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 399.00
- **Best score:** 960.60
- **Improvement:** 140.8%

### llm_trial_broken_segmentation_run1

- **Scenario:** broken_segmentation
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 299.00
- **Best score:** 970.60
- **Improvement:** 224.6%

### llm_cold_start_redundant_shadowing

- **Scenario:** redundant_shadowing
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 399.00
- **Best score:** 960.60
- **Improvement:** 140.8%

### llm_trial_redundant_shadowing_run2

- **Scenario:** redundant_shadowing
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 399.00
- **Best score:** 960.60
- **Improvement:** 140.8%

### llm_trial_redundant_shadowing_run3

- **Scenario:** redundant_shadowing
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 399.00
- **Best score:** 960.60
- **Improvement:** 140.8%

### llm_trial_broken_segmentation_run3

- **Scenario:** broken_segmentation
- **Iterations:** 5
- **Successful mutations:** 5
- **Verification pass rate:** 100%
- **Baseline score:** 299.00
- **Best score:** 970.60
- **Improvement:** 224.6%

---

## Analysis

### Best Algorithm by Scenario

- **Over Permissive:** random_reorder (78.6% reduction)
- **Broken Segmentation:** random_reorder (82.9% reduction)
- **Redundant Shadowing:** static_analysis (77.9% reduction)

### Key Findings

1. **Static Analysis** and **Simulated Annealing** both achieved ~75% rule reduction across scenarios
2. **Random Reorder** achieved ~76% average reduction — competitive with structured approaches
3. **Greedy Hitcount** achieved ~41.6% average reduction (high variance: 2-72% depending on scenario)
4. All 4 baselines produce >0% rule reduction after fixing the greedy reorder-only and SA zero-gradient bugs

---

## Recommendations for v2.2

Based on Phase 10 findings:

1. Combine Static Analysis with LLM guidance for maximum reduction
2. Implement ensemble strategies using multiple algorithms
3. Add full 5-tuple BDD verification (port/protocol aware)
4. Develop mutation effectiveness heuristics from collected data
