"""
SPHINCS+ Parameter Optimisation (using existing benchmark runners)
============================================================
An incredibly extended version of the basic benchmarking setup
that collects data on a wide range of parameter combinations, then ranks them by mean time
and outputs a CSV for further (and easier) analysis.
Note: Means used are geometric means for better data analysis.
"""
import itertools
import statistics
import sys
import os
import csv
# uncomment below if runnig on unix system in order to limit memory usage.
# import resource

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))   # so we can import sibling bench files
script_dir = os.path.dirname(os.path.abspath(__file__))


import bench_common
import bench_keygen
import bench_sig_size
import bench_verification
import bench_signing
from sphincs.sphincs import SphincsParams
# constraints
MAX_SIG_BYTES = 100_000 # maximum signature size to consider, filter out anything with too large a sig, moddable.

# making it all ops to ease uses.
# the 4 ops are the ones that need to be tested anyway
# I think sig_size can technically be removed as other ops inadvertently test it
# but making it its own operation does allow easier result analysis at the cost of a bit more time.
ALL_OPS = ["keygen", "sign", "verify", "sig_size"]

# par ranges
N_VALS = [16, 32]
W_VALS = [4, 16, 64, 256]
H_VALS = [6, 10, 12]
D_VALS = [2, 3]
K_VALS = [4, 6, 8]
T_VALS = [8, 16, 32]

# modifiable globals for the sweep
N_RUNS   = 5
N_WARMUP = 1

# map operation name → the run() function from the matching bench file
RUNNERS = {
    "keygen": bench_common.run_keygen_sphincs_default,
    "sign":   bench_common.run_sign_sphincs_default,
    "verify": bench_common.run_verify_sphincs_default,
    "sig_size": bench_common.run_sig_size_sphincs_default,
}

# CSV columns emitted for every operation
BASE_FIELDS = ["rank", "n", "w", "h", "d", "k", "t",
                "sig_bytes", "mean_ms", "median_ms", "min_ms", "max_ms", "stdev_ms"]
 
# Extra columns that only exist for certain operations
EXTRA_FIELDS = {
    "keygen":   ["sk_bytes", "pk_bytes"],
    "verify":   ["pk_bytes"],
    "sig_size": ["r_bytes", "sig_fors_bytes", "sig_ht_bytes", "total_theory_bytes"],
}

# uncomment below if in unix in order to limit memory usage.
"""
def set_memory_limits(): 
    # edit first digit to adjust memory limits
    limit = int(4 * 1024 **3)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except AttributeError:
        print("  WARNING: resource.setrlimit not available on this OS (non-Linux)")
    except ValueError as e:
        print(f"  WARNING: could not set memory limit: {e}") 
"""
def build_csv_fields(curr_op: str) -> list[str]:
    return BASE_FIELDS + EXTRA_FIELDS.get(curr_op, [])
 
 
def build_row(rank: int, result: dict, curr_op: str) -> dict:
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
        "sig_bytes": result["sig_bytes"],
        "mean_ms":   round(statistics.geometric_mean(times)   * 1000, 6),
        "median_ms": round(statistics.median(times) * 1000, 6),
        "min_ms":    round(min(times)               * 1000, 6),
        "max_ms":    round(max(times)               * 1000, 6),
        "stdev_ms":  round(statistics.stdev(times)  * 1000, 6) if len(times) > 1 else 0.0,
    }
    if curr_op in ("keygen",):
        row["sk_bytes"] = raw.get("sk_size", "")
        row["pk_bytes"] = raw.get("pk_size", "")
    if curr_op == "verify":
        row["pk_bytes"] = raw.get("pk_size", "")
    if curr_op == "sig_size":
        row["r_bytes"]            = raw.get("r_size",        "")
        row["sig_fors_bytes"]     = raw.get("sig_fors_size", "")
        row["sig_ht_bytes"]       = raw.get("sig_ht_size",   "")
        row["total_theory_bytes"] = raw.get("total_theory",  "")
    return row
 
 
def write_csv(results: list, path: str, curr_op: str) -> None:
    CSV_OUTPUT_PATH = f"results_{curr_op}.csv"
    ranked = sorted(results, key=lambda r: r["sig_bytes"] if curr_op == "sig_size" else r["mean_ms"])
    fields = build_csv_fields(curr_op)
 
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for rank, result in enumerate(ranked, 1):
            writer.writerow(build_row(rank, result , curr_op))
 
    print(f"\n  CSV written → {path}  ({len(ranked)} rows)")

# main iterator.
def sweep(curr_op: str):
    run_fn  = RUNNERS[curr_op]
    combos  = list(itertools.product(N_VALS, W_VALS, H_VALS, D_VALS, K_VALS, T_VALS))
    total   = len(combos)
    results = []

    print(f"Sweeping {total} combinations for '{curr_op}'...\n")

    for idx, (n, w, h, d, k, t) in enumerate(combos, 1):
        if h % d != 0:
            continue
        if (t & (t - 1)) != 0:
            continue
        label  = f"n={n} w={w} h={h} d={d} k={k} t={t}"
        try:
            params = SphincsParams(n=n, w=w, h=h, d=d, k=k, t=t)
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
            "sig_bytes": sig_size,
            "mean_ms":   mean_ms,
            "raw":       r,
        })

        print(f"[{idx:>4}/{total}] {label} | "
              f"sig={sig_size:>6}B | {curr_op}={mean_ms:7.3f}ms")

    return results

# top 10 results, can b somewhat configured by passing an n argument.
def print_top(results: list, curr_op: str, n: int = 10):
    ranked = sorted(results, key=lambda r: r["sig_bytes"] if curr_op == "sig_size" else r["mean_ms"])
    print(f"\n{'═' * 70}")
    print(f"  Top {n} fastest '{curr_op}' (sig ≤ {MAX_SIG_BYTES}B)")
    print(f"{'═' * 70}")
    print(f"  {'rank':>4}  {'n':>2} {'w':>3} {'h':>2} {'d':>2} "
          f"{'k':>2} {'t':>2}  {'sig(B)':>7}  {curr_op}(ms)")
    print(f"  {'─' * 62}")
    for i, r in enumerate(ranked[:n], 1):
        raw = r["raw"]
        size_parts = [f"sig={r['sig_bytes']:>6}B"]
        if "sk_size" in raw:
            size_parts.append(f"sk={raw['sk_size']:>5}B")
        if "pk_size" in raw:
            size_parts.append(f"pk={raw['pk_size']:>5}B")
        sizes_str = "  ".join(size_parts)
        print(f"  {i:>4}  {r['n']:>2} {r['w']:>3} {r['h']:>2} {r['d']:>2} "
              f"{r['k']:>2} {r['t']:>2}  {sizes_str}  {r['mean_ms']:>9.3f}ms")

    # also print the full detail for the single best result
    print(f"\n  Full detail for rank 1:")
    bench_keygen.print_results(ranked[0]["raw"])        if curr_op == "keygen" else \
    bench_signing.print_results(ranked[0]["raw"])       if curr_op == "sign"   else \
    bench_verification.print_results(ranked[0]["raw"])  if curr_op == "verify" else \
    bench_sig_size.print_results(ranked[0]["raw"])

def run():
    # uncomment below if OS is unix to memory limit param opt test.
    # set_memory_limits()
    print(f"Welcome to param optimizer: Sphincs+ (unmodified)")
    for op in ALL_OPS:
        print (f"Currently running: {op}")
        results = sweep(op)
        if results:
            print_top(results, op, n=10)
            file_path =  os.path.join(script_dir, f"results_{op}.csv")
            write_csv(results, file_path, op)
        else:
            print("No valid parameter sets found within constraints.")

if __name__ == "__main__":
    run()