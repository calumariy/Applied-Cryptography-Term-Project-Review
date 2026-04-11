"""
SPHINCS+C Parameter Optimisation (using existing benchmark runners)
============================================================
An incredibly extended version of the basic benchmarking setup
that collects data on a wide range of parameter combinations, then ranks them by mean time
and outputs a CSV for further analysis.
"""
import itertools
import statistics
import sys
import os
import csv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))   # so we can import sibling bench files

import bench_common
import bench_keygen
import bench_sig_size
import bench_verification
import bench_signing

from sphincs_params_Plus_C import SphincsParamsC
# constraints
MAX_SIG_BYTES = 20_000 # maximum signature size to consider, filter out anything with too large a sig, moddable.
# change this to param optimise different aspects of the implementation according to the thing:
TARGET_OP     = "sig_size"     # "keygen" | "sign" | "verify" | "sig_size"
CSV_OUTPUT_PATH = f"results_{TARGET_OP}.csv"

# par ranges
N_VALS = [16]
# I wanted a W value to be 256 like in other run_alls, but the proccessing power heavily stalls at that point.
W_VALS = [4, 16, 64]
H_VALS = [6, 10, 12]
D_VALS = [2, 3]
K_VALS = [4, 6, 8]
T_VALS = [8, 16, 32]
T_PRIME_VALS = [8, 16, 32]
# Z val of 4 also causes a huge increase in processing time.
Z_VALS = [0, 2]

# modifiable globals for the sweep
N_RUNS   = 5
N_WARMUP = 1

# map operation name → the run() function from the matching bench file
RUNNERS = {
    "keygen": bench_common.run_verify_sphincs_plus_c,
    "sign":   bench_common.run_sign_sphincs_plus_c,
    "verify": bench_common.run_verify_sphincs_plus_c,
    "sig_size": bench_common.run_sig_size_sphincs_plus_c,
}

# CSV columns emitted for every operation
_BASE_FIELDS = ["rank", "n", "w", "h", "d", "k", "t", "t_prime", "z",
                "sig_bytes", "mean_ms", "median_ms", "min_ms", "max_ms", "stdev_ms"]
 
# Extra columns that only exist for certain operations
_EXTRA_FIELDS = {
    "keygen":   ["sk_bytes", "pk_bytes"],
    "verify":   ["pk_bytes"],
    "sig_size": ["r_bytes", "sig_fors_bytes", "sig_ht_bytes", "total_theory_bytes"],
}


def _csv_fields() -> list[str]:
    return _BASE_FIELDS + _EXTRA_FIELDS.get(TARGET_OP, [])
 
 
def _row(rank: int, result: dict) -> dict:
    """Build a flat CSV row from the results"""
    raw     = result["raw"]
    times   = raw["times"]
    row = {
        "rank":      rank,
        "n":         result["n"],
        "w":         result["w"],
        "h":         result["h"],
        "d":         result["d"],
        "k":         result["k"],
        "t":         result["t"],
        "t_prime":      result["t_prime"],
        "z":              result["z"],
        "sig_bytes": result["sig_bytes"],
        "mean_ms":   round(statistics.mean(times)   * 1000, 6),
        "median_ms": round(statistics.median(times) * 1000, 6),
        "min_ms":    round(min(times)               * 1000, 6),
        "max_ms":    round(max(times)               * 1000, 6),
        "stdev_ms":  round(statistics.stdev(times)  * 1000, 6) if len(times) > 1 else 0.0,
    }
    if TARGET_OP in ("keygen",):
        row["sk_bytes"] = raw.get("sk_size", "")
        row["pk_bytes"] = raw.get("pk_size", "")
    if TARGET_OP == "verify":
        row["pk_bytes"] = raw.get("pk_size", "")
    if TARGET_OP == "sig_size":
        row["r_bytes"]            = raw.get("r_size",        "")
        row["sig_fors_bytes"]     = raw.get("sig_fors_size", "")
        row["sig_ht_bytes"]       = raw.get("sig_ht_size",   "")
        row["total_theory_bytes"] = raw.get("total_theory",  "")
    return row
 
 
def write_csv(results: list, path: str) -> None:
    """Write all results (sorted fastest-first) to a CSV file."""
    ranked = sorted(results, key=lambda r: r["sig_bytes"] if TARGET_OP == "sig_size" else r["mean_ms"])
    fields = _csv_fields()
 
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for rank, result in enumerate(ranked, 1):
            writer.writerow(_row(rank, result))
 
    print(f"\n  CSV written → {path}  ({len(ranked)} rows)")

def sweep():
    run_fn  = RUNNERS[TARGET_OP]
    combos  = list(itertools.product(N_VALS, W_VALS, H_VALS, D_VALS, K_VALS, T_VALS, T_PRIME_VALS, Z_VALS))
    total   = len(combos)
    results = []

    print(f"Sweeping {total} combinations for '{TARGET_OP}'...\n")

    for idx, (n, w, h, d, k, t, t_prime, z) in enumerate(combos, 1):
        if h % d != 0:
            continue
        if (t & (t - 1)) != 0:
            continue

        try:
            params = SphincsParamsC(n=n, w=w, h=h, d=d, k=k, t=t, t_prime=t_prime, z=z)
            label = f"n={n} w={w} h={h} d={d} k={k} t={t} t'={t_prime} z={z}"
            r      = run_fn(label, params, n_runs=N_RUNS, n_warmup=N_WARMUP)
        except Exception as e:
            print(f"[{idx:>4}/{total}] SKIP {label}  ({e})")
            continue

        # sig_size is only present for sign/verify results
        sig_size = r.get("sig_size") or r.get("total_actual", 0)
        if sig_size and sig_size > MAX_SIG_BYTES:
            continue

        mean_ms = statistics.mean(r["times"]) * 1000

        results.append({
            "n": n, "w": w, "h": h, "d": d, "k": k, "t": t,
            "t_prime": t_prime,
            "z": z,
            "sig_bytes": sig_size,
            "mean_ms":   mean_ms,
            "raw":       r,
        })

        print(f"[{idx:>4}/{total}] {label} | "
              f"sig={sig_size:>6}B | {TARGET_OP}={mean_ms:7.3f}ms")

    return results


def print_top(results: list, n: int = 10):
    ranked = sorted(results, key=lambda r: r["sig_bytes"] if TARGET_OP == "sig_size" else r["mean_ms"])
    print(f"\n{'═' * 82}")
    print(f"  Top {n} fastest '{TARGET_OP}' (sig ≤ {MAX_SIG_BYTES}B)")
    print(f"{'═' * 82}")
    print(f"  {'rank':>4}  {'n':>2} {'w':>3} {'h':>2} {'d':>2} "
          f"{'k':>2} {'t':>2} {'t\'':>4} {'z':>4}  {'sig(B)':>7}  {TARGET_OP}(ms)")
    print(f"  {'─' * 74}")
    for i, r in enumerate(ranked[:n], 1):
        raw = r["raw"]
        size_parts = [f"sig={r['sig_bytes']:>6}B"]
        if "sk_size" in raw:
            size_parts.append(f"sk={raw['sk_size']:>5}B")
        if "pk_size" in raw:
            size_parts.append(f"pk={raw['pk_size']:>5}B")
        sizes_str = "  ".join(size_parts)
        print(f"  {i:>4}  {r['n']:>2} {r['w']:>3} {r['h']:>2} {r['d']:>2} "
              f"{r['k']:>2} {r['t']:>2} {r['t_prime']:>4} {r['z']:>4}  "
              f"{sizes_str}  {r['mean_ms']:>9.3f}ms")

    print(f"\n  Full detail for rank 1:")
    bench_keygen.print_results(ranked[0]["raw"])           if TARGET_OP == "keygen" else \
    bench_signing.print_results(ranked[0]["raw"])          if TARGET_OP == "sign"   else \
    bench_verification.print_results(ranked[0]["raw"])     if TARGET_OP == "verify" else \
    bench_sig_size.print_results(ranked[0]["raw"])


if __name__ == "__main__":
    results = sweep()
    if results:
        print_top(results, n=10)
        write_csv(results, CSV_OUTPUT_PATH)
    else:
        print("No valid parameter sets found within constraints.")