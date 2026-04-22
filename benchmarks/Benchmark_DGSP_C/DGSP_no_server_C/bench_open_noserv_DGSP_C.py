"""
SPHINCS+ DGSP Open Benchmark (serverless)
===================================
Measures wall-clock time for dgsp_open across parameter sets.
Methodology:
  - 1 warm-up run discarded (cold-start / cache effects).
  - time.perf_counter() — highest-resolution clock, unaffected by NTP.
  - Import and object-construction time excluded from the timed region.
  - Reports min, median, mean, max, stdev across N_RUNS iterations.
  - SK and PK sizes reported in bytes.
"""
import statistics
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from params.sphincs_params_Plus_C import SphincsParamsC
from bench_common_noserv_DGSP_C import run_open_DGSP, N_RUNS, N_WARMUP

PARAM_SETS = [
    # label,                          n,  w,  h, d, k,  t, t_prime, z
    ("small-dev  (h=6,  d=2, k=4)",  16, 16,  6, 2,  4,   8, 8, 0),
    ("medium-dev (h=12, d=3, k=6)",  16, 16, 12, 3,  6,  16, 16, 2),
]

def run(label: str, params: SphincsParamsC,
        n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    return run_open_DGSP(label, params, n_runs, n_warmup)

def print_results(r: dict):
    times = r["times"]
    p     = r["params"]
    print(f"\n{'─' * 56}")
    print(f"  {r['label']}")
    print(f"  n={p.n}, w={p.w}, h={p.h}, d={p.d}, k={p.k}, t={p.t}")
    print(f"  t_prime = {p.t_prime}, z = {p.z}")
    print(f"{'─' * 56}")
    print(f"  Runs     : {len(times)}  (+ {N_WARMUP} warm-up discarded)")
    print(f"  Min      : {min(times)*1000:8.3f} ms")
    print(f"  Median   : {statistics.median(times)*1000:8.3f} ms")
    print(f"  Mean     : {statistics.geometric_mean(times)*1000:8.3f} ms")
    print(f"  Max      : {max(times)*1000:8.3f} ms")
    print(f"  Stdev    : {statistics.stdev(times)*1000:8.3f} ms")
    print(f"  Sig Size  : {r['sig_size']} bytes  ({r['sig_size'] * 8} bits)")
    print(f"  Manager SK size  : {r['man_sk_size']} bytes  ({r['man_sk_size'] * 8} bits)")
    print(f"  Personal PK_size  : {r['personal pk_size']} bytes  ({r['personal pk_size'] * 8} bits)")
    print(f"  Group PK_size  : {r['group pk_size']} bytes  ({r['group pk_size'] * 8} bits)")

if __name__ == "__main__":
    print("SPHINCS+ DGSP Open (Serverless) C Benchmark")
    print("=" * 56)
    for label, n, w, h, d, k, t, t_prime, z in PARAM_SETS:
        params = SphincsParamsC(n=n, w=w, h=h, d=d, k=k, t=t, t_prime=t_prime, z=z)
        print_results(run(label, params))
    print(f"\n{'=' * 56}\nDone.")