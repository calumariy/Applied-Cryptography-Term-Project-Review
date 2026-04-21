import math
from typing import List

from helpers.ADRS import ADRS, ADRSType
from WOTS.WOTS_Plus_C import WOTSPlusC
from XMSS.XMSS_sig_plus_c import xmss_sig_c
from helpers.helpers import H

# xmss variant using wots+c instead of wots+
# wots_sign returns (sig, counter) so xmss_sign stores both in xmss_sig_c
# wots_pkFromSig takes the counter as an extra argument
class XMSS_C:

    def __init__(self, h: int, n: int, d: int, wots_c: WOTSPlusC, adrs: ADRS):
        self.xmss_h = h // d
        self.n = n
        self.wots_c = wots_c
        self.adrs = adrs

    def TreeHash(self, sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS) -> bytes:
        if s < 0 or z < 0:
            raise ValueError(f"{s} or/and {z} must be positive")
        if s > 0xFFFFFFFF or z > 0xFFFFFFFF:
            raise ValueError(f"values {s} or/and {z} exceed 32-bit limit")
        if s % (1 << z) != 0:
            raise ValueError(f"leaf {s} is not the leftmost leaf of a subtree of height {z}")
        stack = []
        for i in range(pow(2, z)):
            adrs.set_type(ADRSType.WOTS_HASH)
            adrs.set_key_pair_add(s + i)
            node = self.wots_c.wots_PKgen(sk_seed, pk_seed, adrs)
            adrs.set_type(ADRSType.TREE)
            adrs.set_tree_height(1)
            height = 1
            adrs.set_tree_index(s + i)
            while stack and stack[-1][1] == height:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = H(pk_seed, adrs, stack.pop()[0], node, self.n)
                height += 1
                adrs.set_tree_height(height)
            stack.append((node, height))
        return stack.pop()[0]

    def xmss_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        return self.TreeHash(sk_seed, 0, self.xmss_h, pk_seed, adrs)

    def xmss_sign(self, M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> xmss_sig_c:
        AUTH: List[bytes] = [b""] * self.xmss_h
        for j in range(self.xmss_h):
            k = math.floor(idx / pow(2, j)) ^ 1
            AUTH[j] = self.TreeHash(sk_seed, k * pow(2, j), j, pk_seed, adrs)
        adrs.set_type(ADRSType.WOTS_HASH)
        adrs.set_key_pair_add(idx)
        sig, counter = self.wots_c.wots_sign(M, sk_seed, pk_seed, adrs)
        return xmss_sig_c(sig, AUTH, counter)

    def xmss_pkFromSig(self, idx: int, sig: xmss_sig_c, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        adrs.set_type(ADRSType.WOTS_HASH)
        adrs.set_key_pair_add(idx)
        AUTH = sig.get_auth()
        signature = sig.get_sig()
        counter = sig.get_counter()
        node = self.wots_c.wots_pkFromSig(signature, M, counter, pk_seed, adrs)
        adrs.set_type(ADRSType.TREE)
        adrs.set_tree_index(idx)
        for k in range(self.xmss_h):
            adrs.set_tree_height(k + 1)
            if math.floor(idx / pow(2, k)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = H(pk_seed, adrs, node, AUTH[k], self.n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = H(pk_seed, adrs, AUTH[k], node, self.n)
        return node

    # sig_bytes already includes the 4-byte counter from wots_c.sig_bytes()
    def sig_bytes(self) -> int:
        return self.wots_c.sig_bytes() + self.xmss_h * self.n
