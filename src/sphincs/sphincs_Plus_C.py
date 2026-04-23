import os
import math

from typing import Tuple
from dataclasses import dataclass

from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params_Plus_C import SphincsParamsC
from WOTS.WOTS_Plus_C import WOTSPlusC
from XMSS.XMSS_plus_c import XMSS_C
from XMSS.XMSS_sig_plus_c import XmssSigC
from sphincs.hypertree.Hypertree_plus_c import HypertreeC
from sphincs.hypertree.Hypertree_sig import HypertreeSig
from FORS.FORS_Plus_C import FORS_C
from FORS.FORS_sig import ForsSig
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


# top-level sphincs+c scheme
# uses fors+c for the few-time signature and wots+c in all hypertree layers
class SphincsC:

    def __init__(self, params: SphincsParamsC, randomize: bool = True) -> None:
        self.params = params
        self.a       = int(math.log2(self.params.t))
        self.a_prime = int(math.log2(self.params.t_prime))
        self.randomize = randomize
        self.adrs = ADRS()
        self.wots_c = WOTSPlusC(self.params, self.params.z)
        self.fors_c = FORS_C(
            self.params.n,
            self.params.k,
            self.params.t,
            self.params.t_prime,
            self.adrs
        )
        self.hypertree = HypertreeC(
            self.params.h,
            self.params.d,
            self.params.n,
            self.wots_c,
            self.adrs
        )

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

    @property
    def t_prime(self): return self.params.t_prime

    @property
    def z(self): return self.params.z

    def spx_keygen(self) -> Tuple[SK, PK]:
        sk_seed = os.urandom(self.params.n)
        pk_seed = os.urandom(self.params.n)
        sk_prf  = os.urandom(self.params.n)
        pk_root = self.hypertree.ht_PkGen(sk_seed, pk_seed)
        self.sk = SK(sk_seed, sk_prf, pk_seed, pk_root)
        self.pk = PK(pk_seed, pk_root)
        return self.sk, self.pk

    def spx_sign(self, message: bytes, sk: SK) -> bytes:
        optrand = os.urandom(self.params.n) if self.randomize else sk.pk_seed
        r = PRFmsg(sk.sk_prf, optrand, message)
        sig = bytearray(r)
        digest = Hmsg(r, sk.pk_seed, sk.pk_root, message)
        md_bits   = self.params.k * self.a
        tree_bits = self.params.h - (self.params.h // self.params.d)
        leaf_bits = self.params.h // self.params.d
        digest_int = int.from_bytes(digest, "big")
        md       = (digest_int >> (tree_bits + leaf_bits)) & ((1 << md_bits) - 1)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)
        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")
        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)
        # fors+c returns (sig, counter), counter written before the sig bytes
        sig_fors, fors_counter = self.fors_c.fors_sign(md_bytes, sk.sk_seed, sk.pk_seed, adrs)
        sig += fors_counter.to_bytes(4, "big")
        sig += sig_fors.to_bytes()
        pk_fors = self.fors_c.fors_pkFromSig(sig_fors, md_bytes, fors_counter, sk.pk_seed, adrs)
        sig_ht  = self.hypertree.ht_sign(pk_fors, sk.sk_seed, sk.pk_seed, idx_tree, idx_leaf)
        sig += sig_ht.to_bytes()
        return bytes(sig)

    def spx_verify(self, message: bytes, sig: bytes, pk: PK) -> bool:
        offset = 0
        r = sig[offset:offset + self.params.n]
        offset += self.params.n
        # fors counter was written before the fors sig bytes
        fors_counter = int.from_bytes(sig[offset:offset + 4], "big")
        offset += 4
        # subtract 4 from sig_bytes() as the counter is already parsed
        sig_fors_len = self.fors_c.sig_bytes() - 4
        sig_fors_bytes = sig[offset:offset + sig_fors_len]
        offset += sig_fors_len
        sig_ht_len   = self.hypertree.sig_bytes()
        sig_ht_bytes = sig[offset:offset + sig_ht_len]
        fors_n = self.params.n
        fors_a = self.a
        fors_k = self.params.k
        sk_list = []
        auth_list = []
        fors_offset = 0
        for i in range(fors_k - 1):
            sk_list.append(sig_fors_bytes[fors_offset:fors_offset + fors_n])
            fors_offset += fors_n
            auth_layer = []
            for _ in range(fors_a):
                auth_layer.append(sig_fors_bytes[fors_offset:fors_offset + fors_n])
                fors_offset += fors_n
            auth_list.append(auth_layer)
        last_sk = sig_fors_bytes[fors_offset:fors_offset + fors_n]
        fors_offset += fors_n
        sk_list.append(last_sk)
        auth_list.append([])
        last_root = sig_fors_bytes[fors_offset:fors_offset + fors_n]
        sig_fors = ForsSig(sk_list, auth_list, last_root)
        wots_ell    = self.wots_c.ell
        xmss_h_prime = self.params.h // self.params.d
        xmss_sig_c_len = 4 + wots_ell * fors_n + xmss_h_prime * fors_n
        xmss_sigs: list[XmssSigC] = []
        ht_offset = 0
        for _ in range(self.params.d):
            chunk = sig_ht_bytes[ht_offset:ht_offset + xmss_sig_c_len]
            ht_offset += xmss_sig_c_len
            xmss_sigs.append(XmssSigC.from_bytes(chunk, xmss_h_prime, fors_n, wots_ell))
        sig_ht = HypertreeSig(xmss_sigs)
        digest = Hmsg(r, pk.pk_seed, pk.pk_root, message)
        md_bits   = self.params.k * self.a
        tree_bits = self.params.h - (self.params.h // self.params.d)
        leaf_bits = self.params.h // self.params.d
        digest_int = int.from_bytes(digest, "big")
        md       = (digest_int >> (tree_bits + leaf_bits)) & ((1 << md_bits) - 1)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)
        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")
        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)
        pk_fors = self.fors_c.fors_pkFromSig(sig_fors, md_bytes, fors_counter, pk.pk_seed, adrs)
        return self.hypertree.ht_verify(pk_fors, sig_ht, pk.pk_seed, idx_tree, idx_leaf, pk.pk_root)
