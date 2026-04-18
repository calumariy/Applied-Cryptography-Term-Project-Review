import os
import math

from typing import Tuple, List
from dataclasses import dataclass
from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params_Alpha import SphincsParamsAlpha
from WOTS.WOTS_Alpha import WOTSAlpha
from sphincs.hypertree.Hypertree_sig import hypertree_sig
from XMSS.XMSS_sig import xmss_sig
from FORS.FORS import FORS
from FORS.FORS_sig import FORS_sig
from helpers.helpers import PRFmsg, Hmsg, H

@dataclass
class SK:
    sk_seed: bytes
    sk_prf: bytes
    pk_seed: bytes
    pk_root: bytes

@dataclass
class PK:
    pk_seed: bytes
    pk_root: bytes

# single xmss tree layer wired to WOTSAlpha instead of WOTSPlus
class XMSS_Alpha:

    def __init__(self, h: int, d: int, n: int, wots_alpha: WOTSAlpha, adrs: ADRS):
        # h // d gives the per-layer tree height
        self.xmss_h = h // d
        self.n = n
        self.wots_alpha = wots_alpha
        self.adrs = adrs

    def TreeHash(self, sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS) -> bytes:
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
        return self.TreeHash(sk_seed, 0, self.xmss_h, pk_seed, adrs)

    def xmss_sign(self, M: bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> xmss_sig:
        AUTH: List[bytes] = []
        for j in range(self.xmss_h):
            k = math.floor(idx / (1 << j)) ^ 1
            AUTH.append(self.TreeHash(sk_seed, k * (1 << j), j, pk_seed, adrs))
        adrs.set_type(ADRSType.WOTS_HASH)
        adrs.set_key_pair_add(idx)
        sig = self.wots_alpha.wots_sign(M, sk_seed, pk_seed, adrs)
        return xmss_sig(sig, AUTH)

    def xmss_pkFromSig(self, idx: int, sig_obj: xmss_sig, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        adrs.set_type(ADRSType.WOTS_HASH)
        adrs.set_key_pair_add(idx)
        AUTH = sig_obj.get_auth()
        signature = sig_obj.get_sig()
        node = self.wots_alpha.wots_pkFromSig(signature, M, pk_seed, adrs)
        adrs.set_type(ADRSType.TREE)
        adrs.set_tree_index(idx)
        for k in range(self.xmss_h):
            adrs.set_tree_height(k + 1)
            if math.floor(idx / (1 << k)) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node = H(pk_seed, adrs, node, AUTH[k], self.n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = H(pk_seed, adrs, AUTH[k], node, self.n)
        return node

    def sig_bytes(self) -> int:
        return self.wots_alpha.sig_bytes() + self.xmss_h * self.n

# d-layer hypertree using XMSS_Alpha at every level
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

# top-level sphincs-alpha scheme, drop-in replacement for Sphincs
# only difference from plain sphincs+ is WOTSAlpha in every tree layer
class SphincsAlpha:

    def __init__(self, params: SphincsParamsAlpha, randomize: bool = True) -> None:
        self.params = params
        self.a = int(math.log2(params.t))
        self.randomize = randomize
        self.adrs = ADRS()
        self.wots_alpha = WOTSAlpha(params)
        self.fors = FORS(params.n, params.k, params.t, self.adrs)
        self.hypertree = HypertreeAlpha(params.h, params.d, params.n, self.wots_alpha, self.adrs)

    @property
    def n(self): return self.params.n
    @property
    def w(self): return self.params.w
    @property
    def h(self): return self.params.h
    @property
    def d(self): return self.params.d
    @property
    def k(self): return self.params.k
    @property
    def t(self): return self.params.t

    def spx_keygen(self) -> Tuple[SK, PK]:
        sk_seed = os.urandom(self.params.n)
        pk_seed = os.urandom(self.params.n)
        sk_prf = os.urandom(self.params.n)
        pk_root = self.hypertree.ht_PkGen(sk_seed, pk_seed)
        self.sk = SK(sk_seed, sk_prf, pk_seed, pk_root)
        self.pk = PK(pk_seed, pk_root)
        return self.sk, self.pk

    def spx_sign(self, message: bytes, sk: SK) -> bytes:
        optrand = os.urandom(self.params.n) if self.randomize else sk.pk_seed
        R = PRFmsg(sk.sk_prf, optrand, message)
        SIG = bytearray(R)
        digest = Hmsg(R, sk.pk_seed, sk.pk_root, message)
        md_bits = self.params.k * self.a
        tree_bits = self.params.h - (self.params.h // self.params.d)
        leaf_bits = self.params.h // self.params.d
        digest_int = int.from_bytes(digest, "big")
        md = (digest_int >> (tree_bits + leaf_bits)) & ((1 << md_bits) - 1)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)
        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")
        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)
        sig_fors = self.fors.fors_sign(md_bytes, sk.sk_seed, sk.pk_seed, adrs)
        SIG += sig_fors.to_bytes()
        pk_fors = self.fors.fors_pkFromSig(sig_fors, md_bytes, sk.pk_seed, adrs)
        sig_ht = self.hypertree.ht_sign(pk_fors, sk.sk_seed, sk.pk_seed, idx_tree, idx_leaf)
        SIG += sig_ht.to_bytes()
        return bytes(SIG)

    def spx_verify(self, message: bytes, SIG: bytes, pk: PK) -> bool:
        offset = 0
        R = SIG[offset:offset + self.params.n]
        offset += self.params.n
        sig_fors_len = self.fors.sig_bytes()
        sig_ht_len = self.hypertree.sig_bytes()
        SIG_FORS_bytes = SIG[offset:offset + sig_fors_len]
        offset += sig_fors_len
        SIG_HT_bytes = SIG[offset:offset + sig_ht_len]
        sig_fors = FORS_sig.from_bytes(SIG_FORS_bytes, self.params.k, self.a, self.params.n)
        # cs_l (wots_alpha.l) must be passed here, not the standard params.len
        sig_ht = hypertree_sig.from_bytes(SIG_HT_bytes, self.params.h, self.params.n, self.params.d, self.wots_alpha.l)
        digest = Hmsg(R, pk.pk_seed, pk.pk_root, message)
        md_bits = self.params.k * self.a
        tree_bits = self.params.h - (self.params.h // self.params.d)
        leaf_bits = self.params.h // self.params.d
        digest_int = int.from_bytes(digest, "big")
        md = (digest_int >> (tree_bits + leaf_bits)) & ((1 << md_bits) - 1)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)
        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")
        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)
        pk_fors = self.fors.fors_pkFromSig(sig_fors, md_bytes, pk.pk_seed, adrs)
        return self.hypertree.ht_verify(pk_fors, sig_ht, pk.pk_seed, idx_tree, idx_leaf, pk.pk_root)

    def sig_bytes(self) -> int:
        # R || sig_fors || sig_ht
        return self.params.n + self.fors.sig_bytes() + self.hypertree.sig_bytes()
