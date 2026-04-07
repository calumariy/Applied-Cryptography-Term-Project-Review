"""
SPHINCS+ Full Benchmark Suite
===============================
Runs all benchmarks and prints a combined summary table.

Usage:
    python run_all.py
"""

import os
import sys
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from sphincs import Sphincs, SphincsParams
import bench_keygen
import bench_signing
import bench_verification
import bench_sig_size

PARAM_SETS = [
    # label,                          n,  w,  h, d, k,  t
    ("small-dev  (h=6,  d=2, k=4)",  16, 16,  6, 2,  4,   8),
    ("medium-dev (h=12, d=3, k=6)",  16, 16, 12, 3,  6,  16),
]

N_RUNS   = 10
N_WARMUP =  1

SEP = "═" * 80


def run_all():
    print(SEP)
    print("  SPHINCS+ Full Benchmark Suite")
    print(SEP)

    for label, n, w, h, d, k, t in PARAM_SETS:
        params = SphincsParams(n=n, w=w, h=h, d=d, k=k, t=t)

        kg   = bench_keygen.run(label, params, N_RUNS, N_WARMUP)
        sg   = bench_signing.run(label, params, N_RUNS, N_WARMUP)
        vf   = bench_verification.run(label, params, N_RUNS, N_WARMUP)
        sz   = bench_sig_size.run(label, params)

        print(f"\n  {label}")
        print(f"  n={params.n}, w={params.w}, h={params.h}, d={params.d}, "
              f"k={params.k}, t={params.t}")
        print(f"  {'─'*74}")
        print(f"  {'Operation':<12} {'Median (ms)':>12} {'Mean (ms)':>12} "
              f"{'Stdev (ms)':>12} {'Min (ms)':>10} {'Max (ms)':>10}")
        print(f"  {'─'*74}")

        for name, r in [("Keygen", kg), ("Signing", sg), ("Verification", vf)]:
            times = r["times"]
            print(f"  {name:<12} "
                  f"{statistics.median(times)*1000:>12.3f} "
                  f"{statistics.mean(times)*1000:>12.3f} "
                  f"{statistics.stdev(times)*1000:>12.3f} "
                  f"{min(times)*1000:>10.3f} "
                  f"{max(times)*1000:>10.3f}")

        print(f"  {'─'*74}")
        print(f"  SK size       : {kg['sk_size']} bytes")
        print(f"  PK size       : {kg['pk_size']} bytes")
        print(f"  Sig size      : {sz['total_actual']} bytes  "
              f"(R={sz['r_size']} + FORS={sz['sig_fors_size']} + HT={sz['sig_ht_size']})")
        print(f"  Verify result : {'PASS' if vf['all_ok'] else 'FAIL'}")

    print(f"\n{SEP}")
    print("  Done.")
    print(SEP)


if __name__ == "__main__":
    run_all()
