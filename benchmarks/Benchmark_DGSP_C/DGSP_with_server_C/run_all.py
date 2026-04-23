"""
run_all_server.py — DGSP server-mode parameter sweep
=====================================================
For each parameter combination, spins up server.py as a subprocess,
runs all five benchmark functions against it, then tears it down.
Produces one CSV per operation in the same directory as this script.
"""
import csv
import itertools
import os
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))   # so we can import sibling bench files
script_dir = os.path.dirname(os.path.abspath(__file__))

from DGSP.member import Member
import bench_common_serv_DGSP_C as bench_common
import bench_join_serv_DGSP_C
import bench_keygen_serv_DGSP_C
import bench_respM_serv_DGSP_C as bench_respM_serv_DGSP_C
import bench_judge_serv_DGSP_C
import bench_open_serv_DGSP_C
import bench_verify_serv_DGSP_C
import bench_sign_serv_DGSP_C

from params.sphincs_params_Plus_C import SphincsParamsC

SERVER_PY = os.path.join(os.path.dirname(__file__), "bench_server_C.py")
SERVER_HOST = bench_common.SERVER_HOST
SERVER_PORT = bench_common.SERVER_PORT

MAX_SIG_BYTES = 100_000
N_RUNS        = 5
N_WARMUP      = 1

# par ranges
N_VALS = [16, 32]
# I wanted a W value to be 256 like in other run_alls, but the proccessing power heavily stalls at that point.
W_VALS = [4, 16, 64]
H_VALS = [6, 10, 12]
D_VALS = [2, 3]
K_VALS = [4, 6, 8]
T_VALS = [8, 16, 32]
T_PRIME_VALS = [8, 16, 32]
# Z val of 4 also causes a huge increase in processing time.
Z_VALS = [0, 2]

ALL_OPS = ["keygen", "join", "resp_m", "judge", "open", "sign", "verify"]

RUNNERS = {
    "keygen":   bench_common.run_keygen_server,
    "join":     bench_common.run_join_server,
    "resp_m":   bench_common.run_resp_m_server,
    "judge":    bench_common.run_judge_server,
    "open":     bench_common.run_open_server,
    "sign":     bench_common.run_sign_server,
    "verify":   bench_common.run_verify_server  
}

BASE_FIELDS = ["rank", "n", "w", "h", "d", "k", "t",
               "sig_bytes", "mean_ms", "median_ms", "min_ms", "max_ms", "stdev_ms"]

EXTRA_FIELDS = {
    "get_pk":   ["pk_bytes"],
    "resp_m":   ["cert_size"],
    "judge":    ["sig_size", "pk_size"],
    "open":     ["sig_size", "pk_size"],
    "sign":     ["sig_size", "pk_size"],
    "verify":   ["sig_size", "pk_size"],
}


# =============== SERVER HELPERS =====================

# uses subprocess to run python script to open server.
def start_server(n, w, h, d, k, t) -> subprocess.Popen:
    cmd = [
        sys.executable, SERVER_PY,
        SERVER_HOST, str(SERVER_PORT),
        str(n), str(w), str(h), str(d), str(k), str(t),
    ]
    return subprocess.Popen(cmd)

# wait until server is open and get stuff from it.
def wait_for_server(params: SphincsParamsC, timeout: float = 15.0) -> bool:
    m = Member(params, SERVER_HOST, SERVER_PORT)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            m.fetch_pk()
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


def stop_server(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


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
        "stdev_ms":  round(statistics.stdev(times) * 1000, 6) if len(times) > 1 else 0.0,
    }
    if curr_op == "get_pk":
        row["pk_bytes"]           = raw.get("pk_size",       "")
    if curr_op == "resp_m":
        row["cert_size"]        = raw.get("cert_size",          "")
    if curr_op in ("open", "judge", "verify", "sign"):
        row["sig_bytes"]         = raw.get("sig_size",           "")
        row["pk_size"]    = raw.get("pk_size",       "")
    return row


def write_csv(results: list, path: str, curr_op: str) -> None:

    ranked = sorted(results, key=lambda r: r["sig_bytes"] if curr_op == "sig_size" else r["mean_ms"])
    fields = build_csv_fields(curr_op)

    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for rank, result in enumerate(ranked, 1):
            writer.writerow(build_row(rank, result, curr_op))

    print(f"  CSV written → {path}  ({len(ranked)} rows)")

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

    if curr_op == "get_pk":     bench_keygen_serv_DGSP_C.print_results(ranked[0]["raw"])
    elif curr_op == "join":     bench_join_serv_DGSP_C.print_results(ranked[0]["raw"])
    elif curr_op == "resp_m":   bench_respM_serv_DGSP_C.print_results(ranked[0]["raw"])
    elif curr_op == "judge":    bench_judge_serv_DGSP_C.print_results(ranked[0]["raw"])
    elif curr_op == "open":     bench_open_serv_DGSP_C.print_results(ranked[0]["raw"])
    elif curr_op == "sign":     bench_sign_serv_DGSP_C.print_results(ranked[0]["raw"])
    elif curr_op == "verify":   bench_verify_serv_DGSP_C.print_results(ranked[0]["raw"])
    
    else:
        # resp_m, open, revoke, judge — no dedicated print_results, just dump raw
        for k, v in ranked[0]["raw"].items():
            if k not in ("params", "times"):
                print(f"    {k}: {v}")


# main
def run():
    combos      = list(itertools.product(N_VALS, W_VALS, H_VALS, D_VALS, K_VALS, T_VALS, T_PRIME_VALS, Z_VALS))
    all_results = {op: [] for op in ALL_OPS}

    for idx, (n, w, h, d, k, t, t_prime, z) in enumerate(combos, 1):
        if h % d != 0:
            continue
        if (t & (t - 1)) != 0:
            continue

        label = f"n={n} w={w} h={h} d={d} k={k} t={t}"
        print(f"\n[{idx:>4}/{len(combos)}] {label}")

        proc = start_server(n, w, h, d, k, t)
        server_temp_params = SphincsParamsC(n, w, h, d, k ,t, t_prime, z)
        if not wait_for_server(server_temp_params):
            print(f"  SKIP — server did not start in time")
            stop_server(proc)
            continue
        print(f"  server ready")

        params = SphincsParamsC(n, w, h, d, k ,t, t_prime, z)

        for op in ALL_OPS:
            run_fn = RUNNERS[op]
            try:
                r = run_fn(label, params,
                           n_runs=N_RUNS, n_warmup=N_WARMUP,
                           host=SERVER_HOST, port=SERVER_PORT)
            except Exception as e:
                print(f"  SKIP {op}: {e}")
                continue

            sig_size = r.get("sig_size") or r.get("total_actual", 0)
            if sig_size and sig_size > MAX_SIG_BYTES:
                continue

            mean_ms = statistics.mean(r["times"]) * 1000
            all_results[op].append({
                "n": n, "w": w, "h": h, "d": d, "k": k, "t": t, "t_prime": t_prime, "z": z,
                "sig_bytes": sig_size,
                "mean_ms":   mean_ms,
                "raw":       r,
            })
            print(f"  {op:10s} | sig={sig_size:>6}B | {mean_ms:7.3f}ms")

        stop_server(proc)

    for op, results in all_results.items():
        if results:
            print_top(results, op, n=10)
            path = os.path.join(script_dir, f"results_{op}_server_dgsp_c.csv")
            write_csv(results, path, op)
        else:
            print(f"  No valid results for '{op}'.")


if __name__ == "__main__":
    run()