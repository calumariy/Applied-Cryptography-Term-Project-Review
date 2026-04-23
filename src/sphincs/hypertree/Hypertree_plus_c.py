from helpers.ADRS import ADRS
from WOTS.WOTS_Plus_C import WOTSPlusC
from sphincs.hypertree.Hypertree_sig import HypertreeSig
from XMSS.XMSS_plus_c import XMSS_C
from XMSS.XMSS_sig_plus_c import XmssSigC


class HypertreeC:

    def __init__(self, h: int, d: int, n: int, wots_c: WOTSPlusC, adrs: ADRS):
        if h <= 0 or d <= 0 or n <= 0:
            raise ValueError("h, d and n must be positive integers")
        if h % d != 0:
            raise ValueError("h must be divisible by d")
        self.h = h
        self.d = d
        self.n = n
        self.wots_c = wots_c
        self.adrs = adrs
        self.xmss = XMSS_C(h, n, d, wots_c, adrs)

    def ht_PkGen(self, sk_seed: bytes, pk_seed: bytes) -> bytes:
        self.adrs = ADRS()
        self.adrs.set_layer_add(self.d - 1)
        self.adrs.set_tree_add(0)
        return self.xmss.xmss_PKgen(sk_seed, pk_seed, self.adrs)

    def ht_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, tree_index: int, leaf_index: int) -> HypertreeSig:
        self.adrs = ADRS()
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        sig_tmp = self.xmss.xmss_sign(M, sk_seed, leaf_index, pk_seed, self.adrs)
        xmss_sigs = [sig_tmp]
        root = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, M, pk_seed, self.adrs)
        h_prime = self.h // self.d
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << h_prime) - 1)
            tree_index = tree_index >> h_prime
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            sig_tmp = self.xmss.xmss_sign(root, sk_seed, leaf_index, pk_seed, self.adrs)
            xmss_sigs.append(sig_tmp)
            if i < self.d - 1:
                root = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, root, pk_seed, self.adrs)
        return HypertreeSig(xmss_sigs)

    def ht_verify(self, M: bytes, sig_ht: HypertreeSig, pk_seed: bytes, tree_index: int, leaf_index: int, pk_ht: bytes) -> bool:
        self.adrs = ADRS()
        h_prime = self.h // self.d
        sig_tmp = sig_ht.get_xmss_sigs(0)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        node = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, M, pk_seed, self.adrs)
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << h_prime) - 1)
            tree_index = tree_index >> h_prime
            sig_tmp = sig_ht.get_xmss_sigs(i)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            node = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, node, pk_seed, self.adrs)
        return node == pk_ht

    def sig_bytes(self) -> int:
        return self.d * self.xmss.sig_bytes()
