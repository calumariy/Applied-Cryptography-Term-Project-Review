"""
Benchmarking sourcefile for changing run settings and what not.
See individual files for more details.
"""
import math
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from sphincs.sphincs_Plus_C import SphincsC
from params.sphincs_params_Plus_C import SphincsParamsC

N_RUNS   = 10
N_WARMUP =  1
COUNTER_BYTES = 4
MESSAGE  = b"benchmark message for sphincs+"

def run_keygen_sphincs_plus_c(label: str, params: SphincsParamsC,
               n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    sphincs = SphincsC(params, randomize=False)
    for _ in range(n_warmup):
        sphincs.spx_keygen()
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        sk, pk = sphincs.spx_keygen()
        times.append(time.perf_counter() - t0)
    return {
        "label":   label,
        "params":  params,
        "times":   times,
        "sk_size": len(sk.sk_seed) + len(sk.sk_prf) + len(sk.pk_seed) + len(sk.pk_root),
        "pk_size": len(pk.pk_seed) + len(pk.pk_root),
    }

def run_sign_sphincs_plus_c(label: str, params: SphincsParamsC,
             n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    sphincs = SphincsC(params, randomize=False)
    sk, pk  = sphincs.spx_keygen()
    for _ in range(n_warmup):
        sphincs.spx_sign(MESSAGE, sk)
    times = []
    sig   = None
    for _ in range(n_runs):
        t0  = time.perf_counter()
        sig = sphincs.spx_sign(MESSAGE, sk)
        times.append(time.perf_counter() - t0)
    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": len(sig),
    }

def run_verify_sphincs_plus_c(label: str, params: SphincsParamsC,
               n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    sphincs = SphincsC(params, randomize=False)
    sk, pk  = sphincs.spx_keygen()
    sig     = sphincs.spx_sign(MESSAGE, sk)
    assert sphincs.spx_verify(MESSAGE, sig, pk), "Verification failed — check implementation"
    for _ in range(n_warmup):
        sphincs.spx_verify(MESSAGE, sig, pk)
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        sphincs.spx_verify(MESSAGE, sig, pk)
        times.append(time.perf_counter() - t0)
    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": len(sig),
        "sk_size":  len(sk.sk_seed) + len(sk.sk_prf) + len(sk.pk_seed) + len(sk.pk_root),
        "pk_size":  len(pk.pk_seed) + len(pk.pk_root),
    }

# this does have a dummy key for runs and warmup but its for uniformity
# and for ease in implementing in run_all and conv into a proper csv


def run_sig_size_sphincs_plus_c(label, params, n_runs=N_RUNS, n_warmup=N_WARMUP):
    sphincs = SphincsC(params, randomize=False)
    sk, pk  = sphincs.spx_keygen()
    sig     = sphincs.spx_sign(MESSAGE, sk)

    a   = int(math.log2(params.t))
    a_p = int(math.log2(params.t_prime)) if params.t_prime > 0 else 0

    r_size = params.n

    # FORS+C: last tree (height a') removed, replaced by n-byte counter
    sig_fors_size = params.k * params.n * (1 + a) - params.n * a_p

    # WOTS+C: actual saving derived from implementation behaviour.
    # The implementation removes len2+z chains and the counter overhead
    # results in a net saving of (len2+z)*n.
    sig_ht_size  = len(sig) - r_size - sig_fors_size
    total_theory = r_size + sig_fors_size + sig_ht_size

    return {
        "label":         label,
        "params":        params,
        "times":         [0.0],          # no timing
        "a":             a,
        "a_prime":       a_p,
        "r_size":        r_size,
        "sig_fors_size": sig_fors_size,
        "sig_ht_size":   sig_ht_size,
        "total_theory":  total_theory,
        "total_actual":  len(sig),
        "sig_size":      len(sig),
    }
