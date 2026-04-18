"""
SPHINCS+ Key Generation Benchmark
===================================
Measures wall-clock time for spx_keygen across parameter sets.
Methodology:
  - 1 warm-up run discarded (cold-start / cache effects).
  - time.perf_counter() — highest-resolution clock, unaffected by NTP.
  - Import and object-construction time excluded from the timed region.
  - Reports min, median, mean, max, stdev across N_RUNS iterations.
  - SK and PK sizes reported in bytes.
"""
import statistics

from sphincs.sphincs import SphincsParams
from bench_common import run_keygen_sphincs_default, N_RUNS, N_WARMUP

PARAM_SETS = [
    # label,                          n,  w,  h, d, k,  t
    ("small-dev  (h=6,  d=2, k=4)",  16, 16,  6, 2,  4,   8),
    ("medium-dev (h=12, d=3, k=6)",  16, 16, 12, 3,  6,  16),
]

def run(label: str, params: SphincsParams,
        n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    return run_keygen_sphincs_default(label, params, n_runs, n_warmup)

def print_results(r: dict):
    times = r["times"]
    p     = r["params"]
    print(f"\n{'─' * 56}")
    print(f"  {r['label']}")
    print(f"  n={p.n}, w={p.w}, h={p.h}, d={p.d}, k={p.k}, t={p.t}")
    print(f"{'─' * 56}")
    print(f"  Runs     : {len(times)}  (+ {N_WARMUP} warm-up discarded)")
    print(f"  Min      : {min(times)*1000:8.3f} ms")
    print(f"  Median   : {statistics.median(times)*1000:8.3f} ms")
    print(f"  Mean     : {statistics.mean(times)*1000:8.3f} ms")
    print(f"  Max      : {max(times)*1000:8.3f} ms")
    print(f"  Stdev    : {statistics.stdev(times)*1000:8.3f} ms")
    print(f"  SK size  : {r['sk_size']} bytes  ({r['sk_size'] * 8} bits)")
    print(f"  PK size  : {r['pk_size']} bytes  ({r['pk_size'] * 8} bits)")

if __name__ == "__main__":
    print("SPHINCS+ Key Generation Benchmark")
    print("=" * 56)
    for label, n, w, h, d, k, t in PARAM_SETS:
        params = SphincsParams(n=n, w=w, h=h, d=d, k=k, t=t)
        print_results(run(label, params))
    print(f"\n{'=' * 56}\nDone.")