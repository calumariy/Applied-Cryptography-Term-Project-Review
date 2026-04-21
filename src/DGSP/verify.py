from __future__ import annotations
from typing import List, Tuple

import sphincs
from helpers.ADRS import ADRS
from WOTS.WOTSPLUS import WOTSPlus
from params.sphincs_params import SphincsParams
from helpers.helpers import H_simple
import sphincs.sphincs as sphincs

# Verifies that the user is in the group and hasn't been revoked. (is called by manager handle cert req)
def verify(msg: bytes, sig: Tuple[bytes, bytes, bytes, bytes, bytes], pk_bytes: bytes, RL: List[bytes], params: SphincsParams) -> bool:
    try:
        # Step 1 — parse the group signature
        sigma_w, rho, zeta, sigma_s, tau = sig

        # Step 2 — Check whether user has been revoked
        if zeta in RL:
            return False

        # Step 3/4: reconstruct the WOTS+ public key pk_{id,j}
        M = H_simple(rho + msg, params.n)
        wots         = WOTSPlus(params)
        sigma_w_list = wots.sig_from_bytes(sigma_w)
        pk_prime     = wots.wots_pkFromSig(sigma_w_list, M, rho, ADRS())

        # Step 5: Verify the GM's signature on (pk_{id,j} ‖ zeta ‖ committment)
        n       = params.n
        pk_root = pk_bytes[:n]
        pk_seed = pk_bytes[n:]
        spx_pk  = sphincs.PK(pk_root=pk_root, pk_seed=pk_seed)

        spx     = sphincs.Sphincs(params)
        message = pk_prime + zeta + tau
        return bool(spx.spx_verify(message, sigma_s, spx_pk))

    except Exception:
        return False