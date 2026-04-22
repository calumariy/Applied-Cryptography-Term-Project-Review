import os
import math

from typing import Tuple
from dataclasses import dataclass
from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params_Alpha import SphincsParamsAlpha
from WOTS.WOTS_Alpha import WOTSAlpha
from XMSS.XMSS_alpha import XMSS_Alpha
from sphincs.hypertree.Hypertree_alpha import HypertreeAlpha
from sphincs.hypertree.Hypertree_sig import hypertree_sig
from FORS.FORS import FORS
from FORS.FORS_sig import FORS_sig
from helpers.helpers import PRFmsg, Hmsg

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
