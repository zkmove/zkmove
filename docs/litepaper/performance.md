# Performance

## Overview

zkMove v0.5 delivers significant improvements over v0.4:

- **Proving time** reduced by **0.5×–3×** depending on the workload.
- **Proof size** reduced to a flat **~25 KB**, enabling near-second-level on-chain finality.

## Benchmark Results

**Test environment:** MacBook Pro, Apple M1 Max, 64 GB RAM

<div>
  <img src="perf.png" width="90%" alt="Proving Time Benchmark" />
</div>

Proving Time (seconds):

| Test Case          | v0.3   | v0.4   | v0.5   |
|--------------------|--------|--------|--------|
| Fibonacci N = 8    | 33.2   | 3.8    | 0.9    |
| N = 10             | 50.1   | 4.2    | 1.0    |
| N = 20             | 90.9   | 4.4    | 1.6    |
| N = 50             | 162.3  | 4.7    | 2.8    |
| N = 100            | 0.0    | 7.9    | 5.0    |

Proof Size (KB):

| Test Case            | v0.3  | v0.4 | v0.5 |
|----------------------|-------|------|------|
| Fibonacci N = 1..100 | 450.8 | 43.7 | 24.8 |

Versions:

- v0.3: Initial implementation (execution circuit V1, sorting-based mcc)
- v0.4: First round of optimizations (execution circuit V2, shuffle-based mcc)
- v0.5: Further optimizations (ASIC-inspired execution circuit)

## Benchmark Description

For details on the benchmark methodology and test cases, refer to the [benchmark specification].
