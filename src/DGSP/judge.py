from __future__ import annotations
from typing import Tuple

from helpers.ADRS import ADRS
from helpers.helpers import H_simple
from params.sphincs_params import SphincsParams


def _encode_id(user_id: int) -> bytes:
    return user_id.to_bytes(8, 'big')


def judge(msg: bytes, sig: Tuple[bytes, bytes, bytes, bytes, bytes, bytes], user_id: int,pi_idj: bytes, params: SphincsParams) -> bool:
    # Step 1 — parse sig^DGSP = (sig^W, rho, zeta, sig^S, tau)
    sigma_w, counter, rho, zeta, sigma_s, tau = sig
    
    # Step 2 — M = H(rho ‖ msg)
    M    = H_simple(rho + msg, params.n)

    # Step 3 — pk_{id,j} ← WOTS+.PKRegen(M, sig^W, rho, ADRS=_)
    wots = params.make_wots()  # variant-specific WOTS+ for DGSP's sigma_w
    wots.set_counter(counter)
    sigma_w_list = wots.sig_from_bytes(sigma_w)
    pk_idj       = wots.wots_pkFromSig(sigma_w_list, M, rho, ADRS())

    # Step 4 — check tau = H(pk_{id,j} ‖ proof_{id,j} ‖ id)
    tau_check = H_simple(pk_idj + pi_idj + _encode_id(user_id), params.n)
    return tau_check == tau