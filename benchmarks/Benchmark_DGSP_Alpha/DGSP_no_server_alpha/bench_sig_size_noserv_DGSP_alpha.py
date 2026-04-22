"""
SPHINCS+ DGSP Sig Size Benchmark (serverless)

Reports size of DGSP signature
"""
import statistics
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from params.sphincs_params_Alpha import SphincsParamsAlpha
from bench_common_noserv_DGSP_alpha import run_sig_size_DGSP, N_RUNS, N_WARMUP

PARAM_SETS = [
    # label,                          n,  w,  h, d, k,  t
    ("small-dev  (h=6,  d=2, k=4)",  16, 16,  6, 2,  4,   8),
    ("medium-dev (h=12, d=3, k=6)",  16, 16, 12, 3,  6,  16),
]

def run(label: str, params: SphincsParamsAlpha,
        n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    return run_sig_size_DGSP(label, params, n_runs, n_warmup)

def print_results(r: dict):
    times = r["times"]
    p     = r["params"]
    print(f"\n{'─' * 56}")
    print(f"  {r['label']}")
    print(f"  n={p.n}, w={p.w}, h={p.h}, d={p.d}, k={p.k}, t={p.t}")
    print(f"{'─' * 56}")
    print(f"  Runs     : {len(times)}  (+ {N_WARMUP} warm-up discarded)")
    print(f"  Sig Size  : {r['sig_size']} bytes  ({r['sig_size'] * 8} bits)")


if __name__ == "__main__":
    print("SPHINCS+ DGSP Sig_Size Alpha (Serverless) Benchmark")
    print("=" * 56)
    for label, n, w, h, d, k, t in PARAM_SETS:
        params = SphincsParamsAlpha(n=n, w=w, h=h, d=d, k=k, t=t)
        print_results(run(label, params))
    print(f"\n{'=' * 56}\nDone.")