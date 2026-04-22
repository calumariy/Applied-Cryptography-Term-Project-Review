from __future__ import annotations
from typing import List
from helpers.ADRS import ADRS

ZERO_COUNTER = b"\x00\x00\x00\x00"


class WOTSAdapter:
    """Uniform interface over plain / alpha / plus-c WOTS. Used for DGSP modularity and to stash the counter for plus-c."""

    def __init__(self, wots, variant: str):
        self._wots = wots
        self._variant = variant   # "plain" | "alpha" | "plus_c"
        self.last_counter: bytes = ZERO_COUNTER

    # --- passthrough methods ---
    def wots_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        return self._wots.wots_PKgen(sk_seed, pk_seed, adrs)

    def sig_from_bytes(self, data: bytes) -> List[bytes]:
        return self._wots.sig_from_bytes(data)

    # --- sign: uniform List[bytes] return, counter stashed on self ---

    def wots_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> List[bytes]:
        if self._variant == "plus_c":
            sig, counter = self._wots.wots_sign(M, sk_seed, pk_seed, adrs)
            self.last_counter = counter.to_bytes(4, "big")
            return sig
        else:
            self.last_counter = ZERO_COUNTER
            return self._wots.wots_sign(M, sk_seed, pk_seed, adrs)

    # --- pk_from_sig: uniform call, counter fetched from self ---

    def set_counter(self, counter_bytes: bytes) -> None:
        self.last_counter = counter_bytes

    def wots_pkFromSig(self, sig: List[bytes], M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        if self._variant == "plus_c":
            counter_int = int.from_bytes(self.last_counter, "big")
            return self._wots.wots_pkFromSig(sig, M, counter_int, pk_seed, adrs)
        else:
            return self._wots.wots_pkFromSig(sig, M, pk_seed, adrs)