from __future__ import annotations

import os
import json
import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from helpers.ADRS import ADRS
import helpers.helpers as helpers
from params.sphincs_params import SphincsParams
from WOTS.WOTSPLUS import WOTSPlus


# ---------------------------------------------------------------------------
#                                State types
# ---------------------------------------------------------------------------

@dataclass
class Certificate:
    """Cert_{id,j} for user id and jth certificate"""
    j:       int            # jth certificate for this user (1-indexed)
    zeta:    bytes          # (Used for rapid tracing) zeta_{user_id,j} = Enc(msk2, user_id || j) 
    pi:      bytes          # (Proof that tracing was done honestly) pi_{user_id,j} = H(pk_{user_id, j} || H(msk1, user_id))
    sigma_s: bytes          # (Signature on the certificate) sig = sphincs.sign(SK, pk_{user_id, j} || zeta_{user_id,j} || pi_{user_id,j})


@dataclass
class StateU:
    """User-side state for one user"""
    id:        int
    c_id:      Optional[bytes]        # (The secret credential of user id) c_{user_id} = H(msk1 || user_id)
    cstar_id:  bytes        # (The secret identifier of user id for key request authentication) cstar_id = H(user_id || c_{user_id})
    seed:      bytes        # (The secret seed of user id for generating WOTS+ key pairs) randomly generates
    ctr_u:     int = 0      # (The number of certificates the user currently holds)
    ctr_m:     int = 0      # (user needs to know what index j to start from when generating the next batch of public keys to send the manager)
    R:         Dict[int, bytes] = field(default_factory=dict)   # (The random values rid_j used to generate the WOTS+ key pairs, indexed by j)
    CertList:         Dict[int, Certificate] = field(default_factory=dict)  # (The certificates the user currently holds, indexed by j)


# ---------------------------------------------------------------------------
#                               Networking helpers
# ---------------------------------------------------------------------------

def _send(conn: socket.socket, obj: dict) -> None:
    line = json.dumps(obj) + "\n"
    conn.sendall(line.encode("utf-8"))


def _recv(conn: socket.socket) -> Optional[dict]:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        buf += chunk
    line, _ = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))

def _connect(host: str, port: int) -> socket.socket:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    return conn


# ---------------------------------------------------------------------------
#                               Member
# ---------------------------------------------------------------------------
class Member:
    def __init__(self, params: SphincsParams, host: str, port: int) -> None:
        self.params = params
        self.n      = params.n
        self.host   = host
        self.port   = port
        self.wots   = WOTSPlus(params)

        self.state: StateU
        self.pk_bytes: bytes       # group public key (PK.root ‖ PK.seed) updated later

    # ------------------------------------------------------------------
    # Fetch the group public key from the manager
    # ------------------------------------------------------------------
    def fetch_pk(self) -> bytes:
        """Retrieve DGSP.PP (serialised as PK.root ‖ PK.seed) from the server."""
        conn = _connect(self.host, self.port)
        try:
            _send(conn, {"cmd": "GET_PK"})
            resp = _recv(conn)
        finally:
            conn.close()

        if resp is None or resp.get("cmd") != "PK":
            raise RuntimeError(f"Unexpected response to GET_PK: {resp}")

        # trust me this becomes useful later when we need PK.seed for 
        # WOTS+ signature verification and certificate generation
        self.pk_bytes = bytes.fromhex(resp["pk"])
        self.pk_root  = self.pk_bytes[:self.n]
        self.pk_seed  = self.pk_bytes[self.n:]
        return self.pk_bytes
    # ------------------------------------------------------------------
    # DGSP.Join (user side)
    # ------------------------------------------------------------------
    def join(self, username: str) -> StateU:
        # Step 1 — send join request
        conn = _connect(self.host, self.port)
        try:
            _send(conn, {"cmd": "JOIN", "username": username})
            resp = _recv(conn)
        finally:
            conn.close()

        if resp is None:
            raise RuntimeError("Server closed connection without a response")

        if resp.get("cmd") == "JOIN_ERR":
            raise RuntimeError(f"Join rejected: {resp.get('reason')}")

        if resp.get("cmd") != "JOIN_OK":
            raise RuntimeError(f"Unexpected response: {resp}")

        # Step 2 — receive (id, cstar_id)
        user_id  = int(resp["id"])
        cstar_id = bytes.fromhex(resp["cstar_id"])

        # Step 3 — generate secret seed
        seed = os.urandom(self.n)

        # Step 4 — store state_U  (no c_id — user never learns it)
        self.state = StateU(id= user_id, c_id = None, cstar_id = cstar_id, seed = seed, ctr_u = 0, ctr_m = 0,)

        print(f"[JOIN] Joined as id={user_id}")
        return self.state

    # ------------------------------------------------------------------
    #  DGSP.RequestU  (Certificate Signing Request)
    # ------------------------------------------------------------------
    def request_certificates(self, batch_size: int = 1) -> None:
        # Step 0 - need to have joined first to get state
        if self.state is None:
            raise RuntimeError("Must call join() first")

        st = self.state

        # Step 1: Initialise P* and R*
        new_rids:    Dict[int, bytes] = {}
        new_pubkeys: List[Tuple[int, bytes]] = []   # (j, pk_bytes)

        # Step 2: Generate batch of WOTS+ public keys and corresponding rids
        for i in range(batch_size):
            j = st.ctr_m + i + 1   # 1-indexed

            rid_j = os.urandom(self.n)
            rho_j = helpers.H_simple(rid_j, self.n) 

            # SK.seed for this WOTS+ instance = H(User.seed ‖ rid_j)
            wots_sk_seed = helpers.H_simple(st.seed + rid_j, self.n)

            pk_j = self.wots.wots_PKgen(wots_sk_seed, rho_j, ADRS())

            new_rids[j]          = rid_j
            new_pubkeys.append((j, pk_j))

        # ---- Send request to manager (ResponseM) ----
        conn = _connect(self.host, self.port)
        try:
            _send(conn, {
                "cmd":      "CERT_REQ",
                "id":       st.id,
                "cstar_id": st.cstar_id.hex(),
                "pub_keys": [pk.hex() for (_, pk) in new_pubkeys],
            })
            resp = _recv(conn)
        finally:
            conn.close()

        if resp is None:
            raise RuntimeError("Server closed connection without a response")

        if resp.get("cmd") == "CERT_ERR":
            raise RuntimeError(f"Certificate request rejected: {resp.get('reason')}")

        if resp.get("cmd") != "CERT_OK":
            raise RuntimeError(f"Unexpected response: {resp}")

        # ---- UpdateU: store received certificates ----
        raw_certs = resp["certs"]
        if len(raw_certs) != batch_size:
            raise RuntimeError(
                f"Expected {batch_size} cert(s), got {len(raw_certs)}"
            )

        for i, cert_dict in enumerate(raw_certs):
            j = st.ctr_m + i + 1

            cert = Certificate(
                j       = j,
                zeta    = bytes.fromhex(cert_dict["zeta"]),
                pi      = bytes.fromhex(cert_dict["pi"]),
                sigma_s = bytes.fromhex(cert_dict["sigma_s"]),
            )

            # Store rid_j in R and cert in C
            st.R[j] = new_rids[j]
            st.CertList[j] = cert

        # Update counters  (Algorithm 3 — DGSP.UpdateU)
        st.ctr_u += batch_size
        st.ctr_m += batch_size

        print(f"[CERT] Received {batch_size} certificate(s); "
              f"ctrU={st.ctr_u}, ctrM={st.ctr_m}")
