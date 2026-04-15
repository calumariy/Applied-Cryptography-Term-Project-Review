from __future__ import annotations

from typing import Tuple

from ADRS import ADRS
from WOTSPLUS import WOTSPlus, SphincsParams
from helpers import H_simple


def _encode_id(user_id: int) -> bytes:
    """Encode user id as 8-byte big-endian integer."""
    return user_id.to_bytes(8, 'big')


def judge(msg: bytes, sig: Tuple[bytes, bytes, bytes, bytes, bytes], user_id: int, pi_idj: bytes, params: SphincsParams) -> bool:
    """
    DGSP.Judge — public verification of signature attribution.

    Returns
    -------
    True  if the attribution is correct.
    False otherwise.
    """
    # Step 1 — parse sig^DGSP = (sig^W, rho, zeta, sig^S, tau)
    sigma_w, rho, zeta, sigma_s, tau = sig

    # Step 2 — M = H(rho ‖ msg)
    M = H_simple(rho + msg, params.n)

    # Step 3 — pk_{id,j} ← WOTS+.PKRegen(M, sig^W, rho, ADRS=_)
    wots         = WOTSPlus(params)
    sigma_w_list = wots.sig_from_bytes(sigma_w)
    pk_idj       = wots.wots_pkFromSig(sigma_w_list, M, rho, ADRS())

    # Step 4 — check tau = H(pk_{id,j} ‖ proof_{id,j} ‖ id)
    id_bytes  = _encode_id(user_id)
    tau_check = H_simple(pk_idj + pi_idj + id_bytes, params.n)

    return tau_check == tau