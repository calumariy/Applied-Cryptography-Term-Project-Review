import os
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

from .verify import verify
from helpers.ADRS import ADRS
import sphincs.sphincs as sphincs
import helpers.helpers as helpers
from params.sphincs_params import SphincsParams

# ---------------------------------------------------------------------------
#                            Small data types
# ---------------------------------------------------------------------------

@dataclass
class StateM:
    """Manager-side state for one user"""
    ctr:  int   = 0             # number of certs issued to user (initially 0 - refer to paper)
    active: bool = True         # Active / Revoked flag for this user (initially Active - refer to paper)

@dataclass
class ManagerRecord:
    """One entry in StatesM"""
    state:    StateM            # state record for this user
    username: str               # username string for this user (for uniqueness checks in Join)

# ---------------------------------------------------------------------------
#                               Manager
# ---------------------------------------------------------------------------
class Manager:
    def __init__(self, params: SphincsParams) -> None:
        self.params   = params
        self.n        = params.n
        self.sphincs = params.make_sphincs()   # variant-specific SPHINCS
        self.wots    = params.make_wots()      # variant-specific WOTS+ for DGSP's sigma_w

        self.spx_sk:  sphincs.SK
        self.spx_pk:  sphincs.PK
        self.gpk:     bytes
        self.msk:     Optional[Tuple[bytes, bytes]] = None   # (msk1, msk2)

        self.RL:      List[bytes]              = []
        self.statesM: Dict[int, ManagerRecord] = {}
        self._next_id: int                     = 1

    # ------------------------------------------------------------------
    # DGSP.KG
    # ------------------------------------------------------------------
    def keygen(self) -> bytes:
        self.msk = (os.urandom(self.n), os.urandom(self.n))   # (msk1, msk2)

        self.spx_sk, self.spx_pk = self.sphincs.spx_keygen()
        self.gpk = self.spx_pk.pk_root

        # Return the raw public-key bytes so the server can hand them to members
        return self._serialise_pk()

    # ------------------------------------------------------------------
    # DGSP.Join  (manager side)
    # ------------------------------------------------------------------
    def join(self, username: str) -> Tuple[int, bytes]:
        # Step 1 — check keygen() was called
        if self.msk is None:
            raise RuntimeError("Manager.keygen() must be called before join()")

        # Step 2 — check uniqueness
        for rec in self.statesM.values():
            if rec.username == username:
                raise ValueError(f"Username '{username}' is already registered")

        # Step 3 — assign id
        user_id = self._next_id
        self._next_id += 1

        # Step 4 — derive credentials
        #   cid      = H(msk1 ‖ id)
        #   cstar_id = H(id  ‖ cid)
        msk1 = self.msk[0]
        id_bytes = helpers._encode_id(user_id)

        cid      = helpers.H_simple(msk1 + id_bytes, self.n)
        cstar_id = helpers.H_simple(id_bytes + cid,  self.n)

        # Step 5 — record manager state
        self.statesM[user_id] = ManagerRecord(
            state    = StateM(ctr=0, active=True),
            username = username,
        )

        # Step 6 — return (id, cstar_id); caller sends these to the user
        return user_id, cstar_id

    # ------------------------------------------------------------------
    # DGSP.ResponseM  (Generate Certificate)
    # ------------------------------------------------------------------
    def response_m(self, user_id: int, cstar_id: bytes, pub_keys: List[bytes]) -> List[Tuple[bytes, bytes, bytes]]:
        # Step 1 — check keygen() was called
        if self.msk is None:
            raise RuntimeError("Manager.keygen() must be called before response_m()")

        # Step 2 — get manager record for this user
        rec = self.statesM.get(user_id)
        if rec is None:
            raise KeyError(f"No user with id {user_id}")

        # Step 3 — check Active flag for user
        msk1 = self.msk[0]
        id_bytes = helpers._encode_id(user_id)

        # Step 4 — compute expected cid and cstar_id for authentication
        cid_expected = helpers.H_simple(msk1 + id_bytes, self.n)
        cstar_expected = helpers.H_simple(id_bytes + cid_expected, self.n)

        # If either the user is revoked or the authentication fails, raise an error
        if rec.state.active is False:
            raise PermissionError(f"User {user_id} is revoked")
        if cstar_id != cstar_expected:
            raise PermissionError(f"Authentication failed for user {user_id}")

        # some intialising
        msk2     = self.msk[1]
        ctr      = rec.state.ctr
        certs    = []

        # Certificate generation
        for i, pk_ij in enumerate(pub_keys):
            j = ctr + i + 1   # 1-indexed counter for this certificate

            # paper uses an SPRP, so we went with AES-128 which is the stock standard
            zeta_ij = helpers.sprp_encrypt(msk2, user_id, j)
            pi_ij = helpers.H_simple(pk_ij + cid_expected, self.n)
            tau_ij = helpers.H_simple(pk_ij + pi_ij + id_bytes, self.n)
            sigma_s_ij = self.sphincs.spx_sign(pk_ij + zeta_ij + tau_ij, self.spx_sk)

            # Append the certificate tuple (zeta_ij, pi_ij, sigma_s_ij) to the list of certs to return
            certs.append((zeta_ij, pi_ij, sigma_s_ij))

        # Update ctrM
        rec.state.ctr += len(pub_keys)

        return certs

    # ------------------------------------------------------------------
    # DGSP.Revoke   (Revoke all certificates for a list of users)
    # ------------------------------------------------------------------
    def revoke(self, ids_to_revoke: List[int]) -> List[bytes]:
        """
        Revoke a list of users.  Appends their ζ values to RL and marks them
        Revoked in StatesM.

        Returns the updated RL so server.py can broadcast it.
        """
        if self.msk is None:
            raise RuntimeError("Manager.keygen() must be called before revoke()")

        msk2 = self.msk[1]

        for user_id in ids_to_revoke:
            # check if user exists or is already inactive — if so, skip them
            rec = self.statesM.get(user_id)
            if rec is None or rec.state.active is False:
                continue
            
            # revoke each certificate issued to this user
            ctr = rec.state.ctr
            for j in range(1, ctr + 1):
                zeta = helpers.sprp_encrypt(msk2, user_id, j)
                if zeta not in self.RL:
                    self.RL.append(zeta)

            rec.state.active = False

        return list(self.RL)   # caller serialises and broadcasts

    # ------------------------------------------------------------------
    # DGSP.Open     (Open a signature to reveal the signer)
    # ------------------------------------------------------------------
    def open(self, msg: bytes, sig: Tuple[bytes, bytes, bytes, bytes, bytes, bytes]) -> Tuple[int, bytes]:
        # Step 0 — check keygen() was called and the signature is valid
        if self.msk is None:
            raise RuntimeError("Manager.keygen() must be called before open()")
        if not verify(msg, sig, self._serialise_pk(), [], self.params):
            raise ValueError("Cannot open an invalid signature")

        msk1, msk2 = self.msk

        # Step 1 — parse sig^DGSP = (sig^W, rho, zeta, sig^S, tau)
        sigma_w, counter, rho, zeta, sigma_s, tau = sig

        # Step 2 — id ‖ j = E^{-1}(msk2, zeta)
        user_id, j = helpers.sprp_decrypt(msk2, zeta)

        # Step 3 — if id > N return None
        if user_id > len(self.statesM):
            raise ValueError(f"Invalid signature: user_id {user_id} is out of range")

        id_bytes = helpers._encode_id(user_id)

        # Step 5 — cid = H(msk1 ‖ id)
        cid      = helpers.H_simple(msk1 + id_bytes, self.n)

        # Step 6 — M = H(rho ‖ msg)
        M        = helpers.H_simple(rho + msg, self.n)

        self.wots.set_counter(counter)  # If we are in Sphincs+C variant

        # Step 7 — pk_{id,j} ← WOTS+.PKRegen(M, sig^W, rho, ADRS=_)
        sigma_w_list = self.wots.sig_from_bytes(sigma_w)
        pk_idj       = self.wots.wots_pkFromSig(sigma_w_list, M, rho, ADRS())

        proof_idj = helpers.H_simple(pk_idj + cid, self.n)

        # proof_idj is for judge
        return user_id, proof_idj

    # ------------------------------------------------------------------
    #                           in-house helpers
    # ------------------------------------------------------------------
    def _serialise_pk(self) -> bytes:
        if not hasattr(self, 'spx_pk'):
            raise RuntimeError("Manager.keygen() must be called before _serialise_pk()")
        return self.spx_pk.pk_root + self.spx_pk.pk_seed
    
    def user_count(self) -> int:
        return len(self.statesM)

    def is_active(self, user_id: int) -> bool:
        rec = self.statesM.get(user_id)
        return rec is not None and rec.state.active is True
