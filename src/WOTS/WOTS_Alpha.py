import math
from typing import List
from helpers.helpers import F, PRF, T_len
from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params import SphincsParams

# builds D[i][s] = |{c in [w]^i : sum(c) = s}| for 0 <= i <= l, 0 <= s <= l*(w-1)
# recurrence: D[i][s] = sum_{j=0}^{w-1} D[i-1][s-j], base case D[0][0] = 1
def compute_Dls(l: int, w: int) -> List[List[int]]:
    max_sum = l * (w - 1)
    D = [[0] * (max_sum + 1) for _ in range(l + 1)]
    D[0][0] = 1
    for i in range(1, l + 1):
        for s in range(i * (w - 1) + 1):
            D[i][s] = sum(D[i - 1][s - j] for j in range(min(w, s + 1)))
    return D

# algorithm 1 from the paper: maps integer x in [0, D[l][target_sum]) to a codeword in C_s
# C_s = {c in [w]^l : sum(c) = target_sum}
# determines each digit left to right by counting how many completions exist for each candidate
def cs_encode(x: int, l: int, w: int, target_sum: int, D: List[List[int]]) -> List[int]:
    v = [0] * l
    s = target_sum
    for i in range(l, 0, -1):
        for j in range(min(w - 1, s) + 1):
            count = D[i - 1][s - j] if (s - j) >= 0 else 0
            if x < count:
                v[l - i] = j
                s -= j
                break
            x -= count
    return v

# inverse of cs_encode, maps a codeword back to its integer index
# useful for testing round-trips
def cs_decode(v: List[int], l: int, w: int, target_sum: int, D: List[List[int]]) -> int:
    x = 0
    s = target_sum
    for i in range(l, 0, -1):
        j = v[l - i]
        for jj in range(j):
            count = D[i - 1][s - jj] if (s - jj) >= 0 else 0
            x += count
        s -= j
    return x

# finds the minimum l such that |C_s| >= 2^(8n) where s = floor(l*(w-1)/2)
# starts from the standard wots+ length l1+l2 and searches downward
def cs_len(n: int, w: int) -> int:
    l1 = math.ceil(8 * n / math.log2(w))
    l2 = math.floor(math.log2(l1 * (w - 1)) / math.log2(w)) + 1
    wots_len = l1 + l2
    target_messages = 1 << (8 * n)
    for l in range(wots_len, 0, -1):
        D = compute_Dls(l, w)
        target_sum = (l * (w - 1)) // 2
        if D[l][target_sum] >= target_messages:
            continue
        else:
            l += 1
            break
    else:
        l = 1
    return l

class WOTSAlpha:
    # wots+ with constant-sum encoding (paper section 3)
    # replaces the base_w + checksum approach with a single codeword in C_s
    # this removes the l2 checksum chains, reducing total chains from l1+l2 to cs_l

    def __init__(self, params: SphincsParams):
        self.params = params
        self.l = cs_len(params.n, params.w)
        self.target_sum = (self.l * (params.w - 1)) // 2
        # dp table precomputed once and reused across all sign/verify calls
        self._D = compute_Dls(self.l, params.w)

    def chain(self, X: bytes, i: int, s: int, PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
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
        n = self.params.n
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        sk = []
        for i in range(self.l):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk.append(PRF(SK_seed, skADRS, n))
        return sk

    def wots_PKgen(self, SK_seed: bytes, PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        n = self.params.n
        w = self.params.w
        wotspkADRS = ADRS_obj.copy()
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        tmp = []
        for i in range(self.l):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk_i = PRF(SK_seed, skADRS, n)
            ADRS_obj.set_chain_add(i)
            ADRS_obj.set_hash_add(0)
            tmp.append(self.chain(sk_i, 0, w - 1, PK_seed, ADRS_obj))
        wotspkADRS.set_type(ADRSType.WOTS_PK)
        wotspkADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        return T_len(PK_seed, wotspkADRS, tmp, n)

    # interprets M as a big-endian integer, reduces mod |C_s|, encodes to a codeword,
    # then applies chain(sk_i, 0, codeword[i]) for each position
    def wots_sign(self, M: bytes, SK_seed: bytes, PK_seed: bytes, ADRS_obj: ADRS) -> List[bytes]:
        n = self.params.n
        w = self.params.w
        assert len(M) == n, "M must be n bytes"
        x = int.from_bytes(M, "big") % self._D[self.l][self.target_sum]
        codeword = cs_encode(x, self.l, w, self.target_sum, self._D)
        skADRS = ADRS_obj.copy()
        skADRS.set_type(ADRSType.WOTS_PRF)
        skADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        sig = []
        for i in range(self.l):
            skADRS.set_chain_add(i)
            skADRS.set_hash_add(0)
            sk = PRF(SK_seed, skADRS, n)
            ADRS_obj.set_chain_add(i)
            ADRS_obj.set_hash_add(0)
            sig.append(self.chain(sk, 0, codeword[i], PK_seed, ADRS_obj))
        return sig

    # recomputes the codeword from M then finishes each chain from the sig element
    def wots_pkFromSig(self, sig: List[bytes], M: bytes, PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        n = self.params.n
        w = self.params.w
        assert len(M) == n, "M must be n bytes"
        assert len(sig) == self.l, f"sig must have {self.l} elements, got {len(sig)}"
        wotspkADRS = ADRS_obj.copy()
        x = int.from_bytes(M, "big") % self._D[self.l][self.target_sum]
        codeword = cs_encode(x, self.l, w, self.target_sum, self._D)
        tmp = []
        for i in range(self.l):
            ADRS_obj.set_chain_add(i)
            tmp.append(self.chain(sig[i], codeword[i], w - 1 - codeword[i], PK_seed, ADRS_obj))
        wotspkADRS.set_type(ADRSType.WOTS_PK)
        wotspkADRS.set_key_pair_add(ADRS_obj.get_key_pair_add())
        return T_len(PK_seed, wotspkADRS, tmp, n)

    def sig_bytes(self) -> int:
        return self.l * self.params.n
    
    def sig_from_bytes(self, sigma_w: bytes) -> List[bytes]:
        n = self.params.n
        if len(sigma_w) % n != 0:
            raise ValueError(f"sigma_w length {len(sigma_w)} is not a multiple of n={n}")
        return [sigma_w[i:i+n] for i in range(0, len(sigma_w), n)]

