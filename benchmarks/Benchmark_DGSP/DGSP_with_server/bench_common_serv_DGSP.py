"""
bench_common_server.py — DGSP Benchmarks (w/ server)
reminder: must run bench_server first so that this works
======================================================================
Benchmarks the three server-exposed operations:
    GET_PK   → run_keygen_server
    JOIN     → run_join_server
    CERT_REQ → run_resp_m_server

Assumes the server is already running and has completed keygen. (which happens when server is ran in first place)
Each function opens a fresh TCP connection per request
"""
import json
import math
import os
import sys
import socket
import uuid
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from WOTS.WOTSPLUS import WOTSPlus
from helpers import helpers
from sphincs.sphincs import SphincsParams
from helpers.ADRS import ADRS
from DGSP.member import Member
from DGSP.judge import judge
from MemberOpen import MemberOpen

N_RUNS   = 10
N_WARMUP = 1
MESSAGE  = b"benchmark message for sphincs+"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432


# =============== SERVER HELPERS  (done through member) =====================
def new_member(params: SphincsParams, host=SERVER_HOST, 
               port=SERVER_PORT) -> Member:
    m = Member(params, host, port)
    m.fetch_pk()
    return m

def join_member(params: SphincsParams, username: str,
                 host=SERVER_HOST, port=SERVER_PORT) -> Member:
    m = new_member(params, host, port)
    m.join(username)
    return m

def join_member_open(params: SphincsParams, username: str,
                 host=SERVER_HOST, port=SERVER_PORT) -> MemberOpen:
    m = MemberOpen(params, host, port)
    m.fetch_pk()
    m.join(username)
    return m

# ============= HELPERS =======================
def encode_id(user_id: int) -> bytes:
    """Encode user id as 8-byte big-endian integer."""
    return user_id.to_bytes(8, 'big')

def wots_keypair(params: SphincsParams) -> bytes:
    wots    = WOTSPlus(params)
    seed    = os.urandom(params.n)
    rid     = os.urandom(params.n)
    rho     = helpers.H_simple(rid, params.n)
    sk_seed = helpers.H_simple(seed + rid, params.n)
    return wots.wots_PKgen(sk_seed, rho, ADRS())

def build_signature(member: Member, msg):
    st = member.state
    if not st.CertList:
        member.request_certificates(batch_size=1)

    # get the most recently issued certificate
    j    = st.ctr_m
    cert = st.CertList[j]
    rid  = st.R[j]

    n       = member.n
    wots    = WOTSPlus(member.params)
    rho     = helpers.H_simple(rid, n)
    sk_seed = helpers.H_simple(st.seed + rid, n)

    M       = helpers.H_simple(rho + msg, n)
    sigma_w = b"".join(wots.wots_sign(M, sk_seed, rho, ADRS()))
    tau     = helpers.H_simple(
        wots.wots_PKgen(sk_seed, rho, ADRS()) +
        cert.pi +
        st.id.to_bytes(8, "big"),
        n,
    )
    sig = (sigma_w, rho, cert.zeta, cert.sigma_s, tau)
    return sig, cert.pi



# =============== BENCHMARK FUNCTIONALITYS ========================

# Benchmark GET_PK round-trip — one full TCP connect/send/recv per call.

def run_keygen_server(label: str, params: SphincsParams,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                      host=SERVER_HOST, port=SERVER_PORT) -> dict:
    for _ in range(n_warmup):
        new_member(params, host, port)
    times = []
    for _ in range(n_runs):
        m  = Member(params, host, port)
        t0 = time.perf_counter()
        pk = m.fetch_pk()
        times.append(time.perf_counter() - t0)
    return {
        "label":   label,
        "params":  params,
        "times":   times,
        "pk_size": len(pk),
    }

"""
Benchmark JOIN round-trip. Each iteration joins a uniquely named user
so the server's membership list grows as should be.
"""
def run_join_server(label: str, params: SphincsParams,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                    host=SERVER_HOST, port=SERVER_PORT) -> dict:
    
    counter = 0

    for _ in range(n_warmup):
        counter += 1
        # add mutable/random element guranteed to not repeat such as time and counter
        # to ensure uniqueness and not have repeat joins
        username = f"benchjoin_user_{counter}_{uuid.uuid4().hex[:2]}"
        m = new_member(params, host, port)
        m.join(username)

    times = []

    for _ in range(n_runs):
        counter += 1
        m = new_member(params, host, port)
        t0 = time.perf_counter()
        username = f"join_user_{counter}_{uuid.uuid4().hex[:2]}"
        m.join(username)
        times.append(time.perf_counter() - t0)
    
    return {
        "label":  label,
        "params": params,
        "times":  times,
    }

def run_resp_m_server(label: str, params: SphincsParams,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                      host=SERVER_HOST, port=SERVER_PORT) -> dict:
    counter = 0;
    username = f"resp_m_user{counter}_{uuid.uuid4().hex[:2]}"
    m = join_member(params, username, host, port)
    m.request_certificates(batch_size=1)
    sig, pi = build_signature(m, b"hello")
    for _ in range(n_warmup):
        m.request_certificates(batch_size=1)

    times = []
    
    for _ in range(n_runs):
        t0   = time.perf_counter()
        m.request_certificates(batch_size=1)
        times.append(time.perf_counter() - t0)

    last_cert = m.state.CertList[m.state.ctr_m]
    cert_size = len(last_cert.zeta) + len(last_cert.pi) + len(last_cert.sigma_s)    
    return {
        "label":     label,
        "params":    params,
        "times":     times,
        "cert_size": cert_size
    }

def run_judge_server(label: str, params: SphincsParams,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                      host=SERVER_HOST, port=SERVER_PORT) -> dict:
    counter = 0;
    username = f"judge_user_{counter}_{uuid.uuid4().hex[:2]}"
    m = join_member(params, username, host, port)   
    sig, pi = build_signature(m, b"hello")
    assert judge(b"hello", sig, m.state.id, pi, params), \
        "Sanity check: judge() rejected a freshly built signature"

    for _ in range(n_warmup):
        judge(b"hello", sig, m.state.id, pi, params)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        judge(b"hello", sig, m.state.id, pi, params)
        times.append(time.perf_counter() - t0)

    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": len(sig),
        "pk_size":  len(m.pk_bytes),
    }

def run_open_server(label: str, params: SphincsParams,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                    host=SERVER_HOST, port=SERVER_PORT) -> dict:

    counter = 0;
    username = f"open_user_{counter}_{uuid.uuid4().hex[:2]}"
    m = join_member_open(params, username, host, port)
    m.request_certificates(batch_size=1)
    sig, pi = build_signature(m, b"benchmark message")

    # sanity check before timing
    recovered_id, recovered_pi = m.open(b"benchmark message", sig)
    assert recovered_id == m.state.id, \
        f"Sanity check: open() returned wrong id {recovered_id}, expected {m.state.id}"
    assert recovered_pi == pi, \
        "Sanity check: open() returned wrong pi"

    for _ in range(n_warmup):
        m.open(b"benchmark message", sig)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        m.open(b"benchmark message", sig)
        times.append(time.perf_counter() - t0)

    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": len(sig),
        "pk_size":  len(m.pk_bytes),
    }
