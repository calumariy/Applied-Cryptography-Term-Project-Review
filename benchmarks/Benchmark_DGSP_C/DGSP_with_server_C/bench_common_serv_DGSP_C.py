"""
bench_common_server.py — DGSP Benchmarks (w/ server)
reminder: must run bench_server first so that this works
======================================================================
Benchmarks all operations that can affect DGSP functionality.
Essentially all of the individual components that make up DGSP have been somewhat
tested through this common file.

For context, a lot of the functionality is seen as different compared to no server
because no server does not handle any member-side stuff whereas this
must take into consideration that aspect of the program.

For additional context, it also creates and runs two servers for the params through functions
because each bench coding block takes in two hard-coded sets of parameters and this allows for
an ease of comparison between two somewhat different data sets.

Verify is for members
Judge is for managers
"""
import json
import math
import subprocess
import os
import sys
import socket
import uuid
import time
from typing import Tuple
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "src"))

from contextlib import contextmanager
from WOTS.WOTSPLUS import WOTSPlus
from helpers import helpers
from params.sphincs_params_Plus_C import SphincsParamsC
from helpers.ADRS import ADRS
from DGSP.member import Member
from DGSP.judge import judge
from MemberOpen_C import MemberOpen
from DGSP.verify import verify

N_RUNS   = 10
N_WARMUP = 1
MESSAGE  = b"benchmark message for sphincs+"

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432
SERVER_PY   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bench_server_C.py")



# =============== SERVER STARTERS  (done through member) =====================
"""
Start bench_server.py as a subprocess with the given params.
Blocks until the server responds to GET_PK (ready check).
Returns the Popen handle.
"""
def start_server(params: SphincsParamsC,
                 host: str = SERVER_HOST,
                 port: int = SERVER_PORT) -> subprocess.Popen:

    global _server_proc
    cmd = [
        sys.executable, SERVER_PY,
        host, str(port),
        str(params.n), str(params.w), str(params.h),
        str(params.d), str(params.k), str(params.t),
        str(params.t_prime), str(params.z)
    ]
    _server_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if not wait_for_server(host, port):
        _server_proc.kill()
        _server_proc = None
        raise RuntimeError(
            f"Server did not start in time for params "
            f"n={params.n} w={params.w} h={params.h} d={params.d} "
            f"k={params.k} t={params.t}"
        )
    return _server_proc
 
 
def stop_server() -> None:
    """Terminate the managed server subprocess."""
    global _server_proc
    if _server_proc is not None:
        _server_proc.terminate()
        try:
            _server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _server_proc.kill()
        _server_proc = None
        time.sleep(0.3)   # let OS release the port
 
 
# these guys are goated
@contextmanager
def managed_server(params: SphincsParamsC,
                   host: str = SERVER_HOST,
                   port: int = SERVER_PORT):
    start_server(params, host, port)
    try:
        yield
    finally:
        stop_server()
 
# GET_PK poll, similar to run_all
def wait_for_server(host: str = SERVER_HOST,
                     port: int = SERVER_PORT,
                     timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1) as conn:
                conn.sendall((json.dumps({"cmd": "GET_PK"}) + "\n").encode())
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.2)
    return False


# =============== SERVER HELPERS  (done through member) =====================
def new_member(params: SphincsParamsC, host=SERVER_HOST, 
               port=SERVER_PORT) -> Member:
    m = Member(params, host, port)
    m.fetch_pk()
    return m

def join_member(params: SphincsParamsC, username: str,
                 host=SERVER_HOST, port=SERVER_PORT) -> Member:
    m = new_member(params, host, port)
    m.join(username)
    return m

def join_member_open(params: SphincsParamsC, username: str,
                 host=SERVER_HOST, port=SERVER_PORT) -> MemberOpen:
    m = MemberOpen(params, host, port)
    m.fetch_pk()
    m.join(username)
    return m

# ============= HELPERS =======================
def encode_id(user_id: int) -> bytes:
    """Encode user id as 8-byte big-endian integer."""
    return user_id.to_bytes(8, 'big')

def sig_size_getter(sig: tuple) -> int:
    """Total byte size of a DGSP signature tuple."""
    return sum(len(s) for s in sig)

def wots_keypair(params: SphincsParamsC) -> bytes:
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

def run_keygen_server(label: str, params: SphincsParamsC,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                      host=SERVER_HOST, port=SERVER_PORT) -> dict:
    for _ in range(n_warmup):
        new_member(params, host, port)
    pk = b""
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
def run_join_server(label: str, params: SphincsParamsC,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                    host=SERVER_HOST, port=SERVER_PORT) -> dict:
    
    counter = 0
    for _ in range(n_warmup):
        counter += 1
        # add mutable/random element guranteed to not repeat such as time and counter
        # to ensure uniqueness and not have repeat joins
        username = f"benchjoin_user_{counter}_{uuid.uuid4().hex[:8]}"
        m = new_member(params, host, port)
        m.join(username)

    times = []

    for _ in range(n_runs):
        counter += 1
        m = new_member(params, host, port)
        t0 = time.perf_counter()
        username = f"join_user_{counter}_{uuid.uuid4().hex[:8]}"
        m.join(username)
        times.append(time.perf_counter() - t0)
    
    return {
        "label":  label,
        "params": params,
        "times":  times,
    }

def run_resp_m_server(label: str, params: SphincsParamsC,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                      host=SERVER_HOST, port=SERVER_PORT) -> dict:
    counter = 0
    username = f"resp_m_user{counter}_{uuid.uuid4().hex[:8]}"
    m = join_member(params, username, host, port)
    m.request_certificates(batch_size=1)
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

def run_judge_server(label: str, params: SphincsParamsC,
                      n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                      host=SERVER_HOST, port=SERVER_PORT) -> dict:
    counter = 0
    username = f"judge_user_{counter}_{uuid.uuid4().hex[:8]}"
    m = join_member_open(params, username, host, port)
    m.request_certificates(batch_size=1)
    sig = m.sign(b"hello")
    user_id, proof_idj = m.open(b"hello", sig)
    assert judge(b"hello", sig, m.state.id, proof_idj, params)
    for _ in range(n_warmup):
        judge(b"hello", sig, m.state.id, proof_idj, params)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        judge(b"hello", sig, m.state.id, proof_idj, params)
        times.append(time.perf_counter() - t0)

    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": sig_size_getter(sig),
        "pk_size":  len(m.pk_bytes),
    }

def run_open_server(label: str, params: SphincsParamsC,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                    host=SERVER_HOST, port=SERVER_PORT) -> dict:

    counter = 0
    username = f"open_user_{counter}_{uuid.uuid4().hex[:8]}"
    m = join_member_open(params, username, host, port)
    m.request_certificates(batch_size=1)
    sig = m.sign(b"benchmark message")

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
        "sig_size": sig_size_getter(sig),
        "pk_size":  len(m.pk_bytes),
    }


def run_verify_server(label: str, params: SphincsParamsC,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                    host=SERVER_HOST, port=SERVER_PORT) -> dict:
    counter = 0
    username = f"verify_user{counter}_{uuid.uuid4().hex[:8]}"
    m = join_member(params, username, host, port)
    m.request_certificates(batch_size=1)
    sig = m.sign(b"benchmark message")
    pk = m.fetch_pk()
    RL_list = []
    

    assert verify(b"benchmark message", sig, pk, RL_list, params)

    for _ in range(n_warmup):
        verify(b"benchmark message", sig, pk, RL_list, params)

    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        verify(b"benchmark message", sig, pk, RL_list, params)
        times.append(time.perf_counter() - t0)

    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": sig_size_getter(sig),
        "pk_size":  len(m.pk_bytes),
    }

# note you do have to request a new certificate before you sign apparently.
def run_sign_server(label: str, params: SphincsParamsC,
                    n_runs: int = N_RUNS, n_warmup: int = N_WARMUP,
                    host=SERVER_HOST, port=SERVER_PORT) -> dict:
    counter = 0
    username = f"sign_user{counter}_{uuid.uuid4().hex[:8]}"
    m = join_member_open(params, username, host, port)

    for _ in range(n_warmup):
        m.request_certificates(batch_size=1)
        m.sign(b"benchmark message")

    sig: Tuple[bytes, bytes, bytes, bytes, bytes, bytes] = (b"", b"", b"", b"", b"", b"")
    times = []
    for _ in range(n_runs):
        t0 = time.perf_counter()
        m.request_certificates(batch_size=1)
        sig = m.sign(b"benchmark message")
        times.append(time.perf_counter() - t0)

    return {
        "label":    label,
        "params":   params,
        "times":    times,
        "sig_size": sig_size_getter(sig),
        "pk_size":  len(m.pk_bytes),
    }