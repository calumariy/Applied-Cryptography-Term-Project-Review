import math
import hashlib
from typing import List, Tuple
from helpers.helpers import F, PRF, T_len
from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params import SphincsParams

# base_w conversion
def base_w(X: bytes, w: int, out_len: int) -> List[int]:
    log_w = int(math.log2(w))
    if 2 ** log_w != w:
        raise ValueError("w must be a power of 2")
    bits = int.from_bytes(X, "big")
    digits = []
    for _ in range(out_len):
        digits.append(bits & (w - 1))
        bits >>= log_w
    digits.reverse()
    return digits

# fixed target sum S_w,n = floor(len1 * (w-1) / 2)
def compute_target_sum(len1: int, w: int) -> int:
    return (len1 * (w - 1)) // 2

# check digest digits sum to target and first z digits are zero
def check_conditions(digits: List[int], target_sum: int, z: int) -> bool:
    if sum(digits) != target_sum:
        return False
    for i in range(z):
        if digits[i] != 0:
            return False
    return True

class WOTSPlusC:
    # WOTS+C variant from SPHINCS+C paper section 3.
    # instead of an explicit checksum, we search for a counter such that
    # H(counter || M) digits sum to a fixed value, removing checksum chains.
    # z leading digits forced to zero drops those chains too.
    # signature is (sigma_1, ..., sigma_ell, counter) where ell = len1 - z.

    def __init__(self, params: SphincsParams, z: int = 0):
        self.params = params
        self.z = z
        self.ell = params.len1 - z
        self.target_sum = compute_target_sum(params.len1, params.w)

    def chain(self, X: bytes, i: int, s: int, PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        # chaining function, identical to WOTSPlus.chain
        n = self.params.n
        w = self.params.w
        if s == 0:
            return X
        if (i + s) > (w - 1):
            raise ValueError("chain: i + s exceeds w - 1")
        tmp = self.chain(X, i, s - 1, PK_seed, ADRS_obj)
        ADRS_obj.set_hash_add(i + s - 1)
        return F(PK_seed, ADRS_obj, tmp, n)

    def wots_SKgen(self, SK_seed: bytes, ADRS_obj: ADRS) -> List[bytes]:
        # generate secret key, only ell chains, skipping the first z
        n = self.params.n
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        sk = []
        for i in range(self.z, self.params.len1):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk.append(PRF(SK_seed, skADRS, n))
        return sk

    def wots_PKgen(self, SK_seed: bytes, PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        # generate public key, only ell chains
        n = self.params.n
        w = self.params.w
        wotspkADRS = ADRS_obj.copy()
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        tmp = []
        for i in range(self.z, self.params.len1):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk_i = PRF(SK_seed, skADRS, n)
            ADRS_obj.set_chain_add(i)
            ADRS_obj.set_hash_add(0)
            tmp.append(self.chain(sk_i, 0, w - 1, PK_seed, ADRS_obj))
        wotspkADRS.set_type(ADRSType.WOTS_PK)
        wotspkADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        return T_len(PK_seed, wotspkADRS, tmp, n)

    def find_counter(self, M: bytes, PK_seed: bytes, ADRS_obj: ADRS) -> Tuple[int, List[int]]:
        # search for a counter so that H(counter || M) satisfies both conditions
        n = self.params.n
        w = self.params.w
        counter = 0
        while True:
            shake = hashlib.shake_256()
            shake.update(PK_seed)
            shake.update(ADRS_obj.to_bytes())
            shake.update(counter.to_bytes(4, "big"))
            shake.update(M)
            digest = shake.digest(n)
            digits = base_w(digest, w, self.params.len1)
            if check_conditions(digits, self.target_sum, self.z):
                return counter, digits
            counter += 1
            if counter > 0xFFFFFFFF:
                raise RuntimeError("counter search exceeded 2^32, check parameters")

    def wots_sign(self, M: bytes, SK_seed: bytes, PK_seed: bytes, ADRS_obj: ADRS) -> Tuple[List[bytes], int]:
        # find a valid counter then sign only the ell non-zero chains
        n = self.params.n
        w = self.params.w
        assert len(M) == n, "M must be n bytes"
        counter, digits = self.find_counter(M, PK_seed, ADRS_obj)
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        sig = []
        for i in range(self.z, self.params.len1):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk = PRF(SK_seed, skADRS, n)
            ADRS_obj.set_chain_add(i)
            ADRS_obj.set_hash_add(0)
            sig.append(self.chain(sk, 0, digits[i], PK_seed, ADRS_obj))
        return sig, counter

    def wots_pkFromSig(self, sig: List[bytes], M: bytes, counter: int, PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        # recompute digest from counter, verify conditions, reconstruct public key
        n = self.params.n
        w = self.params.w
        assert len(M) == n, "M must be n bytes"
        assert len(sig) == self.ell, f"sig must have {self.ell} elements, got {len(sig)}"
        wotspkADRS = ADRS_obj.copy()
        shake = hashlib.shake_256()
        shake.update(PK_seed)
        shake.update(ADRS_obj.to_bytes())
        shake.update(counter.to_bytes(4, "big"))
        shake.update(M)
        digest = shake.digest(n)
        digits = base_w(digest, w, self.params.len1)
        # if conditions fail return zeros, causes merkle root mismatch and rejection
        if not check_conditions(digits, self.target_sum, self.z):
            return bytes(n)
        tmp = []
        for idx, i in enumerate(range(self.z, self.params.len1)):
            ADRS_obj.set_chain_add(i)
            tmp.append(self.chain(sig[idx], digits[i], w - 1 - digits[i], PK_seed, ADRS_obj))
        wotspkADRS.set_type(ADRSType.WOTS_PK)
        wotspkADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        return T_len(PK_seed, wotspkADRS, tmp, n)

    def sig_bytes(self) -> int:
        # ell chains of n bytes, counter adds 4 bytes on top
        return self.ell * self.params.n + 4
