from helpers.ADRS import ADRS
from WOTS.WOTS_Alpha import WOTSAlpha
from sphincs.hypertree.Hypertree_sig import hypertree_sig
from XMSS.XMSS_alpha import XMSS_Alpha

class HypertreeAlpha:

    def __init__(self, h: int, d: int, n: int, wots_alpha: WOTSAlpha, adrs: ADRS):
        if h % d != 0:
            raise ValueError("h must be divisible by d")
        self.h = h
        self.d = d
        self.n = n
        self.wots_alpha = wots_alpha
        self.adrs = adrs
        self.xmss = XMSS_Alpha(h, d, n, wots_alpha, adrs)

    def ht_PkGen(self, sk_seed: bytes, pk_seed: bytes) -> bytes:
        self.adrs = ADRS()
        self.adrs.set_layer_add(self.d - 1)
        self.adrs.set_tree_add(0)
        return self.xmss.xmss_PKgen(sk_seed, pk_seed, self.adrs)

    def ht_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, tree_index: int, leaf_index: int) -> hypertree_sig:
        self.adrs = ADRS()
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        SIG_tmp = self.xmss.xmss_sign(M, sk_seed, leaf_index, pk_seed, self.adrs)
        SIG_HT = [SIG_tmp]
        root = self.xmss.xmss_pkFromSig(leaf_index, SIG_tmp, M, pk_seed, self.adrs)
        h_prime = self.h // self.d
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << h_prime) - 1)
            tree_index = tree_index >> h_prime
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            SIG_tmp = self.xmss.xmss_sign(root, sk_seed, leaf_index, pk_seed, self.adrs)
            SIG_HT.append(SIG_tmp)
            if i < self.d - 1:
                root = self.xmss.xmss_pkFromSig(leaf_index, SIG_tmp, root, pk_seed, self.adrs)
        return hypertree_sig(SIG_HT)

    def ht_verify(self, M: bytes, SIG_HT: hypertree_sig, pk_seed: bytes, tree_index: int, leaf_index: int, pk_ht: bytes) -> bool:
        self.adrs = ADRS()
        h_prime = self.h // self.d
        SIG_TMP = SIG_HT.get_xmss_sigs(0)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        node = self.xmss.xmss_pkFromSig(leaf_index, SIG_TMP, M, pk_seed, self.adrs)
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << h_prime) - 1)
            tree_index = tree_index >> h_prime
            SIG_TMP = SIG_HT.get_xmss_sigs(i)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            node = self.xmss.xmss_pkFromSig(leaf_index, SIG_TMP, node, pk_seed, self.adrs)
        return node == pk_ht

    def sig_bytes(self) -> int:
        return self.d * self.xmss.sig_bytes()
