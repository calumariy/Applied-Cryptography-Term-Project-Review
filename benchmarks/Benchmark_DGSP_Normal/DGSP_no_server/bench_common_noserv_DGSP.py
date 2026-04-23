"""
Benchmarking sourcefile for measuring DGSP performance across variants.

To benchmark a specific variant, import the corresponding params class
and pass an instance to the run_* functions.
"""
import sys
import os
import time

from params.sphincs_params import SphincsParams
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from helpers import helpers
from helpers.ADRS import ADRS
from DGSP.manager import Manager
from DGSP.judge import judge

N_RUNS   = 10
N_WARMUP =  1
MESSAGE  = b"benchmark message for sphincs+"


# ---------------------------------------------------------------------------
# Helpers — variant-aware, build real DGSP signatures
# ---------------------------------------------------------------------------

def _encode_id(user_id: int) -> bytes:
    return user_id.to_bytes(8, 'big')


def wots_keypair(params: SphincsParams) -> bytes:
    """Generate a WOTS+ public key using whichever variant params dictate."""
    wots = params.make_wots()
    seed = os.urandom(params.n)
    rid  = os.urandom(params.n)
    rho  = helpers.H_simple(rid, params.n)
    sk_seed = helpers.H_simple(seed + rid, params.n)
    return wots.wots_PKgen(sk_seed, rho, ADRS())


def build_signature(params: SphincsParams, manager, user_id, cstar, msg):
    """
    Synthesise a well-formed 6-tuple DGSP signature the way Member.sign() does.
    Returns (sig_tuple, pi, pk_idj, sk_seed, rho).
    """
    n = params.n
    wots = params.make_wots()

    seed = os.urandom(n)
    rid  = os.urandom(n)
    rho  = helpers.H_simple(rid, n)
    sk_seed = helpers.H_simple(seed + rid, n)
    pk_idj = wots.wots_PKgen(sk_seed, rho, ADRS())

    zeta, pi, sigma_s = manager.response_m(user_id, cstar, [pk_idj])[0]

    M = helpers.H_simple(rho + msg, n)
    sigma_w_list  = wots.wots_sign(M, sk_seed, rho, ADRS())
    sigma_w_bytes = b"".join(sigma_w_list)
    counter_bytes = wots.last_counter      # 4 bytes, zero for plain/alpha

    tau = helpers.H_simple(pk_idj + pi + _encode_id(user_id), n)

    sig = (sigma_w_bytes, counter_bytes, rho, zeta, sigma_s, tau)
    return sig, pi, pk_idj, sk_seed, rho


def _sig_tuple_bytes(sig_tuple) -> int:
    """Total on-the-wire size of a DGSP 6-tuple signature in bytes."""
    return sum(len(field) for field in sig_tuple)


def _cert_tuple_bytes(cert_tuple) -> int:
    """Total size of one (zeta, pi, sigma_s) cert tuple in bytes."""
    zeta, pi, sigma_s = cert_tuple
    return len(zeta) + len(pi) + len(sigma_s)


# ---------------------------------------------------------------------------
# Benchmark drivers
# ---------------------------------------------------------------------------

def run_keygen_DGSP(label: str, params: SphincsParams,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    for _ in range(n_warmup):
        m.keygen()
    pk = b""
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        pk = m.keygen()
        times.append(time.perf_counter() - t0)
    return {
        "label":            label,
        "params":           params,
        "times":            times,
        "man_sk_size":      len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size":    len(m.gpk),
    }


def run_resp_m_DGSP(label: str, params: SphincsParams,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    user_id, cstar_id = m.join("alice")

    for _ in range(n_warmup):
        m.response_m(user_id, cstar_id, [wots_keypair(params)])

    times = []
    cert_size = 0
    for _ in range(n_runs):
        pk_ij = wots_keypair(params)   # prep outside the timed region
        t0 = time.perf_counter()
        certs = m.response_m(user_id, cstar_id, [pk_ij])
        times.append(time.perf_counter() - t0)
        cert_size = _cert_tuple_bytes(certs[0])

    return {
        "label":     label,
        "params":    params,
        "times":     times,
        "cert_size": cert_size,
    }


def run_open_DGSP(label: str, params: SphincsParams,
                  n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    user_id, cstar_id = m.join("alice")
    sig, pi, *_ = build_signature(params, m, user_id, cstar_id, MESSAGE)

    # sanity check before timing
    check_user_id, check_pi = m.open(MESSAGE, sig)
    assert user_id == check_user_id
    assert pi == check_pi

    for _ in range(n_warmup):
        m.open(MESSAGE, sig)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        m.open(MESSAGE, sig)
        times.append(time.perf_counter() - t0)

    return {
        "label":            label,
        "params":           params,
        "times":            times,
        "sig_size":         _sig_tuple_bytes(sig),
        "man_sk_size":      len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size":    len(m.gpk),
    }


def run_revoke_DGSP(label: str, params: SphincsParams,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    total_iters = n_warmup + n_runs

    user_ids = []
    for i in range(total_iters):
        uid, _ = m.join(f"user_{i}")
        user_ids.append(uid)

    for i in range(n_warmup):
        m.revoke([user_ids[i]])

    times = []
    for i in range(n_warmup, total_iters):
        t0 = time.perf_counter()
        m.revoke([user_ids[i]])
        times.append(time.perf_counter() - t0)

    return {
        "label":            label,
        "params":           params,
        "times":            times,
        "man_sk_size":      len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size":    len(m.gpk),
    }


def run_judge_DGSP(label: str, params: SphincsParams,
                   n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    user_id, cstar_id = m.join("alice")
    sig, pi, *_ = build_signature(params, m, user_id, cstar_id, MESSAGE)

    assert judge(MESSAGE, sig, user_id, pi, params)

    for _ in range(n_warmup):
        judge(MESSAGE, sig, user_id, pi, params)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        judge(MESSAGE, sig, user_id, pi, params)
        times.append(time.perf_counter() - t0)

    return {
        "label":            label,
        "params":           params,
        "times":            times,
        "sig_size":         _sig_tuple_bytes(sig),
        "man_sk_size":      len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size":    len(m.gpk),
    }


def run_sig_size_DGSP(label: str, params: SphincsParams,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    """
    Dummy-timed benchmark used purely to record signature size.
    `times` is [0.0] so this slots uniformly into any CSV aggregation.
    """
    m = Manager(params)
    m.keygen()
    user_id, cstar_id = m.join("alice")
    sig, *_ = build_signature(params, m, user_id, cstar_id, MESSAGE)

    return {
        "label":    label,
        "params":   params,
        "times":    [0.0],
        "sig_size": _sig_tuple_bytes(sig),
        "sig_field_sizes": {
            "sigma_w": len(sig[0]),
            "counter": len(sig[1]),
            "rho":     len(sig[2]),
            "zeta":    len(sig[3]),
            "sigma_s": len(sig[4]),
            "tau":     len(sig[5]),
        },
    }