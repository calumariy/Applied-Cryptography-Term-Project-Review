"""
Benchmarking sourcefile for changing run settings and what not.
See individual files for more details.
"""
import math
import sys
import os
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from WOTS.WOTSPLUS import WOTSPlus
from helpers import helpers
from sphincs.sphincs import SphincsParams
from DGSP.manager import Manager
from helpers.ADRS import ADRS
from DGSP.judge import judge

N_RUNS   = 10
N_WARMUP =  1
MESSAGE  = b"benchmark message for sphincs+"


# Helpers taken from test.py to help run the benchmarking opts.
def wots_keypair(PARAMS: SphincsParams):
    wots = WOTSPlus(PARAMS)
    seed = os.urandom(PARAMS.n); rid = os.urandom(PARAMS.n)
    rho = helpers.H_simple(rid, PARAMS.n)
    sk_seed = helpers.H_simple(seed + rid, PARAMS.n)
    return wots.wots_PKgen(sk_seed, rho, ADRS())

def build_signature(PARAMS: SphincsParams, manager, user_id, cstar, msg):
    """
    Synthesise a well-formed DGSP signature the way Member.sign() would.
    Returns (sig_tuple, pi, pk_idj, sk_seed, rho).
    """
    N = PARAMS.n
    wots = WOTSPlus(PARAMS)
    seed = os.urandom(N)
    rid  = os.urandom(N)
    rho  = helpers.H_simple(rid, N)
    sk_seed = helpers.H_simple(seed + rid, N)
    pk_idj = wots.wots_PKgen(sk_seed, rho, ADRS())

    zeta, pi, sigma_s = manager.response_m(user_id, cstar, [pk_idj])[0]

    M = helpers.H_simple(rho + msg, N)
    sigma_w = b"".join(wots.wots_sign(M, sk_seed, rho, ADRS()))
    tau = helpers.H_simple(pk_idj + pi + _encode_id(user_id), N)

    return (sigma_w, rho, zeta, sigma_s, tau), pi, pk_idj, sk_seed, rho

def _encode_id(user_id: int) -> bytes:
    """Encode user id as 8-byte big-endian integer."""
    return user_id.to_bytes(8, 'big')



# =============== BENCHMARK FUNCTIONALITYS ========================
def run_keygen_DGSP(label: str, params: SphincsParams,
               n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    for _ in range(n_warmup):
        m.keygen()
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        pk = m.keygen()
        times.append(time.perf_counter() - t0)
    return {
        "label":   label,
        "params":  params,
        "times":   times,
        "man_sk_size": len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size": len(m.gpk)
    }

def run_resp_m_DGSP(label: str, params: SphincsParams,
             n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    sk = m.msk
    user_id, cstar_id = m.join("alice")
    for _ in range(n_warmup):
        m.response_m(user_id, cstar_id, [wots_keypair(params)])
    times = []
    sig   = None
    for _ in range(n_runs):
        t0  = time.perf_counter()
        cert = m.response_m(user_id, cstar_id, [wots_keypair(params)])
        times.append(time.perf_counter() - t0)
    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "cert_size": len(cert),
    }

def run_open_DGSP(label: str, params: SphincsParams,
               n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    sk = m.msk
    user_id, cstar_id = m.join("alice")
    m.response_m(user_id, cstar_id, [wots_keypair(params)])
    sig, pi, *_ = build_signature(params, m, user_id, cstar_id, b"hi")
    check_user_id, check_pi = m.open(b"hi", sig)
    assert user_id == check_user_id
    assert pi == check_pi
    for _ in range(n_warmup):
        m.open(b"hi", sig)
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        m.open(b"hi", sig)
        times.append(time.perf_counter() - t0)
    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": len(sig),
        "man_sk_size": len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size": len(m.gpk)
    }

def run_revoke_DGSP(label: str, params: SphincsParams,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    sk = m.msk
    total_iters = n_warmup + n_runs
    user_ids = []
    # list of users to incrementally join.
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
        "label":    label,
        "params":   params,
        "times":    times,
        "man_sk_size": len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size": len(m.gpk)
    }

def run_judge_DGSP(label: str, params: SphincsParams, 
                   n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    pk = m.keygen()
    sk = m.msk
    user_id, cstar_id = m.join("alice")
    cert = m.response_m(user_id, cstar_id, [wots_keypair(params)])
    sig, pi, *_ = build_signature(params, m, user_id, cstar_id, b"hello")
    assert judge(b"hello", sig, user_id, pi, params)
    for _ in range(n_warmup):
        judge(b"hello", sig, user_id, pi, params)
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        judge(b"hello", sig, user_id, pi, params)
        times.append(time.perf_counter() - t0)
    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": len(sig),
        "man_sk_size": len(m.msk[0]) + len(m.msk[1]),
        "personal pk_size": len(pk),
        "group pk_size": len(m.gpk)
    }


# this does have a dummy key for runs and warmup but its for uniformity
# and for ease in implementing in run_all and conv into a proper csv
def run_sig_size_DGSP(label: str, params: SphincsParams,
                                  n_runs: int = N_RUNS, n_warmup: int = N_WARMUP) -> dict:
    m = Manager(params)
    m.keygen()
    user_id, cstar_id = m.join("alice")
    sig = build_signature(params, m, user_id, cstar_id, b"hi")
    return {
        "label":         label,
        "params":        params,
        "times":         [0.0],
        "sig_size":      len(sig),
    }
