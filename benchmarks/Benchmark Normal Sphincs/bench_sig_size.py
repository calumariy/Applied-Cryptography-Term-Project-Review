"""
SPHINCS+ Signature Size Breakdown
====================================
Reports the byte composition of a SPHINCS+ signature:
  R  ||  SIG_FORS  ||  SIG_HT

No timing — this is purely a size analysis.

Component sizes (from spec):
  R        = n bytes
  SIG_FORS = k * (n + a*n) bytes  =  k*n*(1+a) bytes
  SIG_HT   = d * (len + h/d) * n bytes
"""

import os
import sys
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sphincs import SphincsParams
from bench_common import run_sig_size_sphincs_default

PARAM_SETS = [
    # label,                          n,  w,  h, d, k,  t
    ("small-dev  (h=6,  d=2, k=4)",  16, 16,  6, 2,  4,   8),
    ("medium-dev (h=12, d=3, k=6)",  16, 16, 12, 3,  6,  16),
]


def print_results(r: dict):
    p = r["params"]
    print(f"\n{'─' * 56}")
    print(f"  {r['label']}")
    print(f"  n={p.n}, w={p.w}, h={p.h}, d={p.d}, k={p.k}, t={p.t}, a={r['a']}")
    print(f"  len={p.len} (len1={p.len1}, len2={p.len2})")
    print(f"{'─' * 56}")
    print(f"  R        : {r['r_size']:6d} bytes")
    print(f"  SIG_FORS : {r['sig_fors_size']:6d} bytes  "
          f"(k={p.k} trees × n×(1+a)={p.n}×{1+r['a']})")
    print(f"  SIG_HT   : {r['sig_ht_size']:6d} bytes  "
          f"(d={p.d} layers × (len+h')={p.len}+{p.h//p.d} × n={p.n})")
    print(f"  ─────────────────────────")
    print(f"  Total (theory) : {r['total_theory']:6d} bytes")
    print(f"  Total (actual) : {r['total_actual']:6d} bytes")


if __name__ == "__main__":
    print("SPHINCS+ Signature Size Breakdown")
    print("=" * 56)
    for label, n, w, h, d, k, t in PARAM_SETS:
        params = SphincsParams(n=n, w=w, h=h, d=d, k=k, t=t)
        print_results(run_sig_size_sphincs_default(label, params))
    print(f"\n{'=' * 56}\nDone.")
