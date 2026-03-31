import os

from typing import Tuple
from dataclasses import dataclass
from ADRS import ADRS, ADRSType
from WOTSPLUS import SphincsParams, WOTSPlus
from Hypertree import Hypertree
from Hypertree_sig import hypertree_sig
from FORS import FORS
from FORS_sig import FORS_sig
from helpers import PRFmsg, Hmsg
import math

Randomize = True;

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

class Sphincs:

    """
    n: security parameter (bytes) usually 256
    w: Winternitz parameter
    h: hypertree height
    d: number of layers in hypertree
    k: number of FORS trees
    t: number ofFORS leaves
    """
    def __init__(self, params: SphincsParams) -> None:

        self.params = params

        self.n = params.n
        self.h = params.h
        self.d = params.d
        self.w = params.w
        self.k = params.k
        self.t = params.t
        self.a = int(math.log2(self.t))

        # primitives
        self.adrs = ADRS()
        self.wots = WOTSPlus(self.params)
        self.fors = FORS(self.n, self.k, self.t, self.adrs)
        self.hypertree = Hypertree(self.h, self.d, self.w, self.n, self.wots, self.adrs)


    def spx_keygen(self) -> Tuple[SK, PK]:

        sk_seed = os.urandom(self.n)
        pk_seed = os.urandom(self.n)
        sk_prf = os.urandom(self.n)
        pk_root = self.hypertree.ht_PkGen(sk_seed, pk_seed)

        self.sk = SK(sk_seed, sk_prf, pk_seed, pk_root)
        self.pk = PK(pk_seed, pk_root)

        return (self.sk, self.pk)

    def spx_sign(self, message: bytes, sk: SK) -> bytes:

        if Randomize:
            optrand = os.urandom(self.n)
        else:
            optrand = sk.pk_seed

        R = PRFmsg(sk.sk_prf, optrand, message)

        SIG = bytearray()
        SIG += R

        digest = Hmsg(R, sk.pk_seed, sk.pk_root, message)

        a = int(math.log2(self.t))
        md_bits = self.k * a
        tree_bits = self.h - (self.h // self.d)
        leaf_bits = self.h // self.d

        digest_int = int.from_bytes(digest, "big")

        md = digest_int >> (tree_bits + leaf_bits)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)

        md_bytes = md.to_bytes((md_bits + 7) // 8, "big") # integer overflow....

        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)

        sig_fors = self.fors.fors_sign(md_bytes, sk.sk_seed, sk.pk_seed, adrs)

        SIG += sig_fors.to_bytes()

        pk_fors = self.fors.fors_pkFromSig(sig_fors, md_bytes, sk.pk_seed, adrs)

        sig_ht = self.hypertree.ht_sign(
            pk_fors,
            sk.sk_seed,
            sk.pk_seed,
            idx_tree,
            idx_leaf
        )

        SIG += sig_ht.to_bytes()

        return bytes(SIG)

    def spx_verify(self, message: bytes, SIG: bytes, pk: PK) -> bool:
        offset = 0

        R = SIG[offset:offset + self.n]
        offset += self.n

        sig_fors_len = self.fors.sig_bytes()
        sig_ht_len   = self.hypertree.sig_bytes()

        SIG_FORS_bytes = SIG[offset:offset + sig_fors_len]
        offset += sig_fors_len

        SIG_HT_bytes = SIG[offset:offset + sig_ht_len]

        sig_fors = FORS_sig.from_bytes(SIG_FORS_bytes, self.k, self.a, self.n)
        sig_ht = hypertree_sig.from_bytes(SIG_HT_bytes, self.h, self.n, self.d, self.wots.params.len)

        digest = Hmsg(R, pk.pk_seed, pk.pk_root, message)
        md_bits = self.k * self.a
        tree_bits = self.h - (self.h // self.d)
        leaf_bits = self.h // self.d

        digest_int = int.from_bytes(digest, "big")

        md = digest_int >> (tree_bits + leaf_bits)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)

        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")

        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)

        pk_fors = self.fors.fors_pkFromSig(sig_fors, md_bytes, pk.pk_seed, adrs)

        return self.hypertree.ht_verify(
            pk_fors,
            sig_ht,
            pk.pk_seed,
            idx_tree,
            idx_leaf,
            pk.pk_root
        )
    