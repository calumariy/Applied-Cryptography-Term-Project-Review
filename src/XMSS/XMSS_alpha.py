import math
from typing import List

from helpers.ADRS import ADRS, ADRSType
from WOTS.WOTS_Alpha import WOTSAlpha
from XMSS.XMSS_sig import XmssSig
from helpers.helpers import H


class XMSS_Alpha:

    def __init__(self, h: int, d: int, n: int, wots_alpha: WOTSAlpha, adrs: ADRS):
        self.xmss_h = h // d
        self.n = n
        self.wots_alpha = wots_alpha
        self.adrs = adrs

    def tree_hash(self, sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS) -> bytes:
        if s % (1 << z) != 0:
            raise ValueError(f"leaf {s} is not the leftmost leaf of a subtree of height {z}")
        stack = []
        for i in range(1 << z):
            adrs.set_type(ADRSType.WOTS_HASH)
            adrs.set_key_pair_add(s + i)
            node = self.wots_alpha.wots_PKgen(sk_seed, pk_seed, adrs)
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
        return self.tree_hash(sk_seed, 0, self.xmss_h, pk_seed, adrs)

    def xmss_sign(self, M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> XmssSig:
        auth: List[bytes] = []
        for j in range(self.xmss_h):
            k = math.floor(idx / (1 << j)) ^ 1
            auth.append(self.tree_hash(sk_seed, k * (1 << j), j, pk_seed, adrs))
        adrs.set_type(ADRSType.WOTS_HASH)
        adrs.set_key_pair_add(idx)
        sig = self.wots_alpha.wots_sign(M, sk_seed, pk_seed, adrs)
        return XmssSig(sig, auth)

    def xmss_pkFromSig(self, idx: int, sig_obj: XmssSig, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        adrs.set_type(ADRSType.WOTS_HASH)
        adrs.set_key_pair_add(idx)
        auth = sig_obj.get_auth()
        signature = sig_obj.get_sig()
        node = self.wots_alpha.wots_pkFromSig(signature, M, pk_seed, adrs)
        adrs.set_type(ADRSType.TREE)
        adrs.set_tree_index(idx)
        for k in range(self.xmss_h):
            adrs.set_tree_height(k + 1)
            if math.floor(idx / (1 << k)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = H(pk_seed, adrs, node, auth[k], self.n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = H(pk_seed, adrs, auth[k], node, self.n)
        return node

    def sig_bytes(self) -> int:
        return self.wots_alpha.sig_bytes() + self.xmss_h * self.n
