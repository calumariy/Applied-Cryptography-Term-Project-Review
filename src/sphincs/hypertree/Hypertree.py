from helpers.ADRS import ADRS
from WOTS.WOTSPLUS import WOTSPlus
from XMSS.XMSS import XMSS
from sphincs.hypertree.Hypertree_sig import HypertreeSig


# ===============
# SPHINCS+ Hypertree Implementation
# ==============
class Hypertree:
    # A hypertree is a form of XMSS, as such it uses some of the functions it does.
    # In addition to having all XMSS parameters, it also has a normal h representing hypertree height
    # and number of tree layers d. The same tree height h/d = h' and winternitz param
    # is used for all layers.
    h: int          # height of tree
    d: int          # number of tree layers; d must divide h without remainder
    w: int          # winternitz param
    n: int          # length in bytes
    wots_plus: WOTSPlus
    adrs: ADRS
    xmss: XMSS

    def __init__(self, h: int, d: int, w: int, n: int, wots_plus: WOTSPlus, adrs: ADRS):
        if h <= 0 or d <= 0 or w <= 0 or n <= 0:
            raise ValueError(f"{h}, {d}, {w} and {n} must be positive integers")
        if h % d != 0:
            raise ValueError(f"{h} must be divisible by {d} without remainder")
        self.wots_plus = wots_plus
        self.adrs = adrs
        self.h = h
        self.n = n
        self.d = d
        self.w = w
        self.xmss = XMSS(self.h, self.n, self.d, self.w, self.wots_plus, self.adrs)

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

        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << (self.h // self.d)) - 1)
            tree_index = tree_index >> (self.h // self.d)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            sig_tmp = self.xmss.xmss_sign(root, sk_seed, leaf_index, pk_seed, self.adrs)
            xmss_sigs.append(sig_tmp)
            if i < self.d - 1:
                root = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, root, pk_seed, self.adrs)

        return HypertreeSig(xmss_sigs)

    def ht_verify(self, M: bytes, sig_ht: HypertreeSig, pk_seed: bytes, tree_index: int, leaf_index: int, pk_ht: bytes) -> bool:
        self.adrs = ADRS()
        sig_tmp = sig_ht.get_xmss_sigs(0)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        node = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, M, pk_seed, self.adrs)
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << (self.h // self.d)) - 1)
            tree_index = tree_index >> (self.h // self.d)
            sig_tmp = sig_ht.get_xmss_sigs(i)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            node = self.xmss.xmss_pkFromSig(leaf_index, sig_tmp, node, pk_seed, self.adrs)
        return node == pk_ht

    def sig_bytes(self) -> int:
        return self.d * self.xmss.sig_bytes()
