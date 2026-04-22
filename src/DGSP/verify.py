from __future__ import annotations
from typing import List, Tuple

from helpers.ADRS import ADRS
from helpers.helpers import H_simple
from params.sphincs_params import SphincsParams


def verify(msg: bytes,
           sig: Tuple[bytes, bytes, bytes, bytes, bytes, bytes],
           pk_bytes: bytes,
           RL: List[bytes],
           params: SphincsParams) -> bool:
    try:
        sigma_w, counter, rho, zeta, sigma_s, tau = sig

        if zeta in RL:
            return False

        M            = H_simple(rho + msg, params.n)
        wots         = params.make_wots()
        wots.set_counter(counter)
        sigma_w_list = wots.sig_from_bytes(sigma_w)
        pk_prime     = wots.wots_pkFromSig(sigma_w_list, M, rho, ADRS())

        n       = params.n
        spx_pk  = params.make_pk(pk_bytes[:n], pk_bytes[n:])
        spx     = params.make_sphincs()
        message = pk_prime + zeta + tau
        return bool(spx.spx_verify(message, sigma_s, spx_pk))

    except Exception:
        return False