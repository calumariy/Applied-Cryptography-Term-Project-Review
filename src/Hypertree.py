from ADRS import ADRS
from WOTSPLUS import WOTSPlus
from XMSS import XMSS
from Hypertree_sig import hypertree_sig

#===============
# SPHINCS+ Hypertree Implementtion
#==============
class Hypertree:
    # A hypertree is a form of XMSS, as such it uses some of the functions it does.
    # In addition to having all XMSS parameters, it also has a normal h representing hypertree height
    # and number of tree layers d. The same tree height h/d = h' and winternitz param
    # is used for all layers
    h: int # height of tree
    d: int # number of tree layers. d must divide h without remainder.
    w: int # winternitz param
    n: int # length in bytes to be passed unto the XMSS constructo
    wots_plus: WOTSPlus
    adrs: ADRS
    xmss: XMSS
    # d-1  contains one xmss tree, d-2 contains 2^(h/d) or basically 2^(h') and so on until
    # layer 0 which contains 2^(h-(h/d)) or 2^(h-h').
    # h/d and w is used for all tree layers. ADRS is a dynamic var anyway.
    def __init__(self, h, d, w, n, wots_plus: WOTSPlus, adrs: ADRS):
        if (h <= 0 or d <= 0 or w <= 0 or n <= 0):
            raise ValueError(f"{h}, {d}, {w} and {n} must be positive integers")
        if (h % d != 0):
            raise ValueError(f"{h} must be divisible by {d} without remainder")
        self.wots_plus = wots_plus
        self.adrs = adrs
        self.h = h
        self.n = n
        self.d = d
        self.w = w
        self.xmss = XMSS(self.h, self.n, self.d, self.w, self.wots_plus, self.adrs)

    """
    Hypertree public key generator
    The public key generation takes as input a private and public seed
    and outputs its own seed.
    """
    def ht_PkGen(self, sk_seed:bytes, pk_seed:bytes) -> bytes:
        # will reset it to 0.
        # types will change in the deeper func call anyway.
        self.adrs = ADRS()
        self.adrs.set_layer_add(self.d - 1)
        self.adrs.set_tree_add(0)
        root = self.xmss.xmss_PKgen(sk_seed, pk_seed, self.adrs)
        return root


    def ht_sign(self, M:bytes, sk_seed: bytes, pk_seed: bytes, tree_index: int, leaf_index: int) -> hypertree_sig:
        self.adrs = ADRS()
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        SIG_tmp = self.xmss.xmss_sign(M, sk_seed, leaf_index, pk_seed, self.adrs)
        # list of xmss signatures btw.
        SIG_HT = [SIG_tmp]
        root = self.xmss.xmss_pkFromSig(leaf_index, SIG_tmp, M, pk_seed, self.adrs)
        
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << (self.h // self.d)) - 1) # least sig bits of tree index.
            tree_index = tree_index >> (self.h // self.d) # most sig bits of tree
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            SIG_tmp = self.xmss.xmss_sign(root, sk_seed, leaf_index, pk_seed, self.adrs)
            SIG_HT.append(SIG_tmp)
            if (i < self.d - 1):
                root = self.xmss.xmss_pkFromSig(leaf_index, SIG_tmp, root, pk_seed, self.adrs)
        
        return hypertree_sig(SIG_HT)
    
    def ht_verify(self, M: bytes, SIG_HT: hypertree_sig, pk_seed: bytes, tree_index: int, leaf_index: int, pk_ht: bytes) -> bool:
        self.adrs = ADRS()
        SIG_TMP = SIG_HT.get_xmss_sigs(0)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        node = self.xmss.xmss_pkFromSig(leaf_index, SIG_TMP,M, pk_seed, self.adrs)
        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << (self.h // self.d)) - 1) # least sig bits of tree index.
            tree_index = tree_index >> (self.h // self.d) # most sig bits of tree
            SIG_TMP = SIG_HT.get_xmss_sigs(i)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            node = self.xmss.xmss_pkFromSig(leaf_index, SIG_TMP, node, pk_seed, self.adrs)
        if (node == pk_ht):
            return True
        else:
            return False
    
    # Total size of hypertree signature.
    def sig_bytes(self) -> int:
        return self.d * self.xmss.sig_bytes()
