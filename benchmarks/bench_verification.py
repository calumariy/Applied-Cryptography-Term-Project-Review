"""
SPHINCS+ Verification Benchmark
===================================
Measures wall-clock time for spx_verify across parameter sets.

Methodology:
  - 1 warm-up run discarded (cold-start / cache effects).
  - time.perf_counter() — highest-resolution clock, unaffected by NTP.
  - Import and object-construction time excluded from the timed region.
  - Reports min, median, mean, max, stdev across N_RUNS iterations.
  - SK and PK sizes reported in bytes.
"""

import time
import statistics
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sphincs import Sphincs, SphincsParams

PARAM_SETS = [
    # label,                          n,  w,  h, d, k,  t
    ("small-dev  (h=6,  d=2, k=4)",  16, 16,  6, 2,  4,   8),
    ("medium-dev (h=12, d=3, k=6)",  16, 16, 12, 3,  6,  16),
]

N_RUNS   = 10
N_WARMUP =  1
MESSAGE  = b"benchmark message for sphincs+ verifying"


def run(label: str, params: SphincsParams, n_runs: int = N_RUNS, n_warmup: int = N_WARMUP):
    sphincs = Sphincs(params, randomize=False)
    sk, pk = sphincs.spx_keygen()
    sig = sphincs.spx_sign(MESSAGE, sk)

    assert sphincs.spx_verify(MESSAGE, sig, pk), "Verification failed during warm-up"
    for _ in range(n_warmup):
        sphincs.spx_verify(MESSAGE, sig, pk)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        sphincs.spx_verify(MESSAGE, sig, pk)
        t1 = time.perf_counter()
        times.append(t1 - t0)

    sk_size = len(sk.sk_seed) + len(sk.sk_prf) + len(sk.pk_seed) + len(sk.pk_root)
    pk_size = len(pk.pk_seed) + len(pk.pk_root)
    return {
        "label":   label,
        "params":  params,
        "times":   times,
        "sig_size": len(sig),
        "sk_size":  sk_size,
        "pk_size":  pk_size
    }


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
    print(f"  Sig size : {r['sig_size']} bytes  ({r['sig_size'] * 8} bits)")
    print(f"  SK size  : {r['sk_size']} bytes  ({r['sk_size'] * 8} bits)")
    print(f"  PK size  : {r['pk_size']} bytes  ({r['pk_size'] * 8} bits)")

if __name__ == "__main__":
    print("SPHINCS+ Verification Benchmark")
    print("=" * 56)
    for label, n, w, h, d, k, t in PARAM_SETS:
        params = SphincsParams(n=n, w=w, h=h, d=d, k=k, t=t)
        print_results(run(label, params))
    print(f"\n{'=' * 56}\nDone.")