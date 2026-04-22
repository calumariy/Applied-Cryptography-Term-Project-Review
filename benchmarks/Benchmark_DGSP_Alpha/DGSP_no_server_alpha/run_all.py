"""
DGSP Parameter Optimisation (using existing benchmark runners)
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
# uncomment below if running on unix system in order to limit memory usage.
# import resource

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
script_dir = os.path.dirname(os.path.abspath(__file__))

import bench_common_noserv_DGSP_alpha as bench_common
import bench_keygen_noserv_DGSP_alpha
import bench_open_noserv_DGSP_alpha
import bench_judge_noserv_DGSP_alpha
import bench_sig_size_noserv_DGSP_alpha
import bench_respM_noserv_DGSP_alpha
import bench_revoke_noserv_DGSP_alpha
from params.sphincs_params_Alpha import SphincsParamsAlpha

# constraints
MAX_SIG_BYTES = 20_000

ALL_OPS = ["keygen", "resp_m", "open", "revoke", "judge", "sig_size"]

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

RUNNERS = {
    "keygen":   bench_common.run_keygen_DGSP,
    "resp_m":   bench_common.run_resp_m_DGSP,
    "open":     bench_common.run_open_DGSP,
    "revoke":   bench_common.run_revoke_DGSP,
    "judge":    bench_common.run_judge_DGSP,
    "sig_size": bench_common.run_sig_size_DGSP,
}

# CSV columns emitted for every operation
BASE_FIELDS = ["rank", "n", "w", "h", "d", "k", "t",
               "sig_bytes", "mean_ms", "median_ms", "min_ms", "max_ms", "stdev_ms"]

EXTRA_FIELDS = {
    "keygen":   ["man_sk_bytes", "personal_pk_bytes", "group_pk_bytes"],
    "resp_m":   ["cert_bytes"],
    "open":     ["sig_bytes", "man_sk_bytes", "personal_pk_bytes", "group_pk_bytes"],
    "revoke":   ["man_sk_bytes", "personal_pk_bytes", "group_pk_bytes"],
    "judge":    ["sig_bytes", "man_sk_bytes", "personal_pk_bytes", "group_pk_bytes"],
    "sig_size": ["r_bytes", "sig_fors_bytes", "sig_ht_bytes", "total_theory_bytes"],
}

# uncomment below if on unix to limit memory usage.
"""
def set_memory_limits():
    limit = int(4 * 1024 ** 3)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except AttributeError:
        print("  WARNING: resource.setrlimit not available on this OS (non-Linux)")
    except ValueError as e:
        print(f"  WARNING: could not set memory limit: {e}")
"""


# ============ CSV HELPERS ==================

def build_csv_fields(curr_op: str) -> list[str]:
    return BASE_FIELDS + EXTRA_FIELDS.get(curr_op, [])


def build_row(rank: int, result: dict, curr_op: str) -> dict:
    raw   = result["raw"]
    times = raw["times"]
    row = {
        "rank":      rank,
        "n":         result["n"],
        "w":         result["w"],
        "h":         result["h"],
        "d":         result["d"],
        "k":         result["k"],
        "t":         result["t"],
        "sig_bytes": result["sig_bytes"],
        "mean_ms":   round(statistics.geometric_mean(times) * 1000, 6),
        "median_ms": round(statistics.median(times)         * 1000, 6),
        "min_ms":    round(min(times)                       * 1000, 6),
        "max_ms":    round(max(times)                       * 1000, 6),
        "stdev_ms":  round(statistics.stdev(times)          * 1000, 6) if len(times) > 1 else 0.0,
    }
    if curr_op in ("keygen", "revoke"):
        row["man_sk_bytes"]      = raw.get("man_sk_size",       "")
        row["personal_pk_bytes"] = raw.get("personal pk_size",  "")
        row["group_pk_bytes"]    = raw.get("group pk_size",      "")
    if curr_op == "resp_m":
        row["cert_bytes"]        = raw.get("cert_size",          "")
    if curr_op in ("open", "judge"):
        row["sig_bytes"]         = raw.get("sig_size",           "")
        row["man_sk_bytes"]      = raw.get("man_sk_size",        "")
        row["personal_pk_bytes"] = raw.get("personal pk_size",   "")
        row["group_pk_bytes"]    = raw.get("group pk_size",       "")
    if curr_op == "sig_size":
        row["r_bytes"]            = raw.get("r_size",        "")
        row["sig_fors_bytes"]     = raw.get("sig_fors_size", "")
        row["sig_ht_bytes"]       = raw.get("sig_ht_size",   "")
        row["total_theory_bytes"] = raw.get("total_theory",  "")
    return row


def write_csv(results: list, path: str, curr_op: str) -> None:
    ranked = sorted(results, key=lambda r: r["sig_bytes"] if curr_op == "sig_size" else r["mean_ms"])
    fields = build_csv_fields(curr_op)

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for rank, result in enumerate(ranked, 1):
            writer.writerow(build_row(rank, result, curr_op))

    print(f"\n  CSV written → {path}  ({len(ranked)} rows)")


def sweep(curr_op: str) -> list:
    run_fn = RUNNERS[curr_op]
    combos = list(itertools.product(N_VALS, W_VALS, H_VALS, D_VALS, K_VALS, T_VALS))
    total  = len(combos)
    results = []

    print(f"Sweeping {total} combinations for '{curr_op}'...\n")

    for idx, (n, w, h, d, k, t) in enumerate(combos, 1):
        if h % d != 0:
            continue
        if (t & (t - 1)) != 0:
            continue

        label = f"n={n} w={w} h={h} d={d} k={k} t={t}"
        try:
            params = SphincsParamsAlpha(n=n, w=w, h=h, d=d, k=k, t=t)
            r      = run_fn(label, params, n_runs=N_RUNS, n_warmup=N_WARMUP)
        except Exception as e:
            print(f"[{idx:>4}/{total}] SKIP {label}  ({e})")
            continue

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


def print_top(results: list, curr_op: str, n: int = 10) -> None:
    ranked = sorted(results, key=lambda r: r["sig_bytes"] if curr_op == "sig_size" else r["mean_ms"])
    superlative = "smallest" if curr_op == "sig_size" else "fastest"
    print(f"\n{'═' * 70}")
    print(f"  Top {n} {superlative} '{curr_op}' (sig ≤ {MAX_SIG_BYTES}B)")
    print(f"{'═' * 70}")
    print(f"  {'rank':>4}  {'n':>2} {'w':>3} {'h':>2} {'d':>2} "
          f"{'k':>2} {'t':>2}  {'sig(B)':>7}  {curr_op}(ms)")
    print(f"  {'─' * 62}")
    for i, r in enumerate(ranked[:n], 1):
        raw = r["raw"]
        size_parts = [f"sig={r['sig_bytes']:>6}B"]
        if "man_sk_size" in raw:
            size_parts.append(f"msk={raw['man_sk_size']:>5}B")
        if "group pk_size" in raw:
            size_parts.append(f"gpk={raw['group pk_size']:>5}B")
        sizes_str = "  ".join(size_parts)
        print(f"  {i:>4}  {r['n']:>2} {r['w']:>3} {r['h']:>2} {r['d']:>2} "
              f"{r['k']:>2} {r['t']:>2}  {sizes_str}  {r['mean_ms']:>9.3f}ms")

    print(f"\n  Full detail for rank 1:")
    if   curr_op == "sig_size": bench_sig_size_noserv_DGSP_alpha.print_results(ranked[0]["raw"])
    elif curr_op == "keygen":   bench_keygen_noserv_DGSP_alpha.print_results(ranked[0]["raw"])
    elif curr_op == "revoke":   bench_revoke_noserv_DGSP_alpha.print_results(ranked[0]["raw"])
    elif curr_op == "resp_m":   bench_respM_noserv_DGSP_alpha.print_results(ranked[0]["raw"])
    elif curr_op == "open":     bench_open_noserv_DGSP_alpha.print_results(ranked[0]["raw"])
    elif curr_op == "judge":    bench_judge_noserv_DGSP_alpha.print_results(ranked[0]["raw"])

    else:
        for k, v in ranked[0]["raw"].items():
            if k not in ("params", "times"):
                print(f"    {k}: {v}")


def run():
    # uncomment below if OS is unix to memory limit param opt test.
    # set_memory_limits()
    print("Welcome to param optimizer: DGSP Alpha (serverless)")
    for op in ALL_OPS:
        print(f"\nCurrently running: {op}")
        results = sweep(op)
        if results:
            print_top(results, op, n=10)
            file_path = os.path.join(script_dir, f"results_{op}_dgsp_noserv_alpha.csv")
            write_csv(results, file_path, op)
        else:
            print(f"  No valid parameter sets found for '{op}'.")


if __name__ == "__main__":
    run()