import copy
import math
import hashlib
from dataclasses import dataclass
from typing import List
from helpers import H, F, PRF, T_len
from ADRS import ADRS, ADRSType
from sphincs import SphincsParams


# ==============================
# Utility: base_w  (spec r3.1 §2.5, Algorithm 1)
# ==============================

def base_w(X: bytes, w: int, out_len: int) -> List[int]:
    """
    base_w(X, w, out_len) – convert byte string X into out_len base-w digits.
    Spec requires out_len ≤ 8*len(X) / lg(w).
    """
    log_w = int(math.log2(w))
    if 2 ** log_w != w:
        raise ValueError("w must be a power of 2")

    bits   = int.from_bytes(X, "big")
    digits = []
    for _ in range(out_len):
        digits.append(bits & (w - 1))
        bits >>= log_w
    digits.reverse()   # big-endian: most-significant digit first
    return digits


# ==============================
# WOTS+ implementation  (spec r3.1 §3)
# ==============================

class WOTSPlus:

    def __init__(self, params: SphincsParams):
        self.params = params

    # ------------------------------------------------------------------
    # Algorithm 2: chain(X, i, s, PK.seed, ADRS)  (spec r3.1 §3.2)
    # ------------------------------------------------------------------

    def chain(self, X: bytes, i: int, s: int,
              PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        """
        Chaining function: iterate F s times on X starting from position i.
        Returns NULL (raises) if i + s > w - 1.
        """
        n = self.params.n
        w = self.params.w

        if s == 0:
            return X
        if (i + s) > (w - 1):
            raise ValueError("chain: i + s exceeds w - 1")

        tmp = self.chain(X, i, s - 1, PK_seed, ADRS_obj)
        ADRS_obj.set_hash_add(i + s - 1)
        tmp = F(PK_seed, ADRS_obj, tmp, n)
        return tmp

    # ------------------------------------------------------------------
    # Algorithm 3: wots_SKgen(SK.seed, ADRS)  (spec r3.1 §3.3)
    # ------------------------------------------------------------------

    def wots_SKgen(self, SK_seed: bytes, ADRS_obj: ADRS) -> List[bytes]:
        """
        Generate the WOTS+ secret key (len n-byte strings).
        Each sk[i] = PRF(SK.seed, skADRS) where skADRS has type WOTS_PRF.
        """
        n = self.params.n

        skADRS = copy.copy(ADRS_obj)
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())

        sk = []
        for i in range(self.params.len):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk.append(PRF(SK_seed, skADRS, n))
        return sk

    # ------------------------------------------------------------------
    # Algorithm 4: wots_PKgen(SK.seed, PK.seed, ADRS)  (spec r3.1 §3.4)
    # ------------------------------------------------------------------

    def wots_PKgen(self, SK_seed: bytes, PK_seed: bytes,
                   ADRS_obj: ADRS) -> bytes:
        """
        Generate the WOTS+ public key.
        Derives sk internally; compresses all chain ends via T_len.
        Returns a single n-byte public key value.
        """
        n = self.params.n
        w = self.params.w

        wotspkADRS = ADRS_obj.copy()
        skADRS     = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())

        tmp = []
        for i in range(self.params.len):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk_i = PRF(SK_seed, skADRS, n)

            ADRS_obj.set_chain_add(i)
            ADRS_obj.set_hash_add(0)
            tmp.append(self.chain(sk_i, 0, w - 1, PK_seed, ADRS_obj))

        wotspkADRS.set_type(ADRSType.WOTS_PK)
        wotspkADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        return T_len(PK_seed, wotspkADRS, tmp, n)

    # ------------------------------------------------------------------
    # Algorithm 5: wots_sign(M, SK.seed, PK.seed, ADRS)  (spec r3.1 §3.5)
    # ------------------------------------------------------------------

    def wots_sign(self, M: bytes, SK_seed: bytes, PK_seed: bytes,
                  ADRS_obj: ADRS) -> List[bytes]:
        """
        Generate a WOTS+ signature on message digest M.
        Returns a list of len n-byte signature elements.
        """
        n   = self.params.n
        w   = self.params.w
        p   = self.params
        assert len(M) == n, "M must be n bytes"

        # convert message to base w
        msg = base_w(M, w, p.len1)

        # compute checksum
        csum = sum((w - 1) - m for m in msg)

        # convert checksum to base w  (spec r3.1 §3.5)
        log_w = int(math.log2(w))
        if log_w % 8 != 0:
            csum = csum << (8 - (p.len2 * log_w) % 8)
        len2_bytes = math.ceil(p.len2 * log_w / 8)
        msg = msg + base_w(csum.to_bytes(len2_bytes, "big"), w, p.len2)

        # build signature
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())

        sig = []
        for i in range(p.len):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk = PRF(SK_seed, skADRS, n)

            ADRS_obj.set_chain_add(i)
            ADRS_obj.set_hash_add(0)
            sig.append(self.chain(sk, 0, msg[i], PK_seed, ADRS_obj))
        return sig

    # ------------------------------------------------------------------
    # Algorithm 6: wots_pkFromSig(sig, M, PK.seed, ADRS)  (spec r3.1 §3.6)
    # ------------------------------------------------------------------

    def wots_pkFromSig(self, sig: List[bytes], M: bytes,
                       PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        """
        Reconstruct the WOTS+ public key from a signature and message digest.
        Returns a single n-byte value (to be compared against wots_PKgen output).
        """
        n = self.params.n
        w = self.params.w
        p = self.params

        assert len(M)   == n,      "M must be n bytes"
        assert len(sig) == p.len,  "sig must have len elements"

        wotspkADRS = ADRS_obj.copy()

        # convert message to base w
        msg = base_w(M, w, p.len1)

        # compute checksum
        csum = sum((w - 1) - m for m in msg)

        # convert checksum to base w  (spec r3.1 §3.6)
        log_w = int(math.log2(w))
        if log_w % 8 != 0:
            csum = csum << (8 - (p.len2 * log_w) % 8)
        len2_bytes = math.ceil(p.len2 * log_w / 8)
        msg = msg + base_w(csum.to_bytes(len2_bytes, "big"), w, p.len2)

        tmp = []
        for i in range(p.len):
            ADRS_obj.set_chain_add(i)
            tmp.append(self.chain(sig[i], msg[i], w - 1 - msg[i], PK_seed, ADRS_obj))

        wotspkADRS.set_type(ADRSType.WOTS_PK)
        wotspkADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        return T_len(PK_seed, wotspkADRS, tmp, n)
    
    def sig_bytes(self) -> int:
        return self.params.len * self.params.n


# ==============================
# Quick self-test
# ==============================

if __name__ == "__main__":
    params = SphincsParams(
        n=16,        # 128-bit security parameter, placeholder
        w=16,        # Winternitz parameter
        h=60,        # placeholders for later SPHINCS+ integration
        d=12,
        k=15,
        t=2 ** 15,
    )

    wots = WOTSPlus(params)

    SK_seed = b"demo_secret_seed_16b"[:params.n]   # placeholder; use os.urandom(n) in production
    PK_seed = b"demo_public_seed_16b"[:params.n]   # placeholder; use os.urandom(n) in production

    # Generate public key
    pk = wots.wots_PKgen(SK_seed, PK_seed, ADRS())

    # Sign a dummy n-byte digest
    M = hashlib.sha256(b"hello wtf").digest()[:params.n]
    sig = wots.wots_sign(M, SK_seed, PK_seed, ADRS())

    # Reconstruct public key from signature
    pk2 = wots.wots_pkFromSig(sig, M, PK_seed, ADRS())

    assert pk == pk2, "WOTS+ verification failed: pk mismatch"
    print("WOTS+ self-test passed.")
