import os
import math
from typing import Tuple, List
from dataclasses import dataclass

from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params_Plus_C import SphincsParamsC
from WOTS.WOTS_Plus_C import WOTSPlusC
from sphincs.hypertree.Hypertree_sig import hypertree_sig
from XMSS.XMSS_sig import xmss_sig
from FORS.FORS_Plus_C import FORS_C
from FORS.FORS_sig import FORS_sig
from helpers.helpers import PRFmsg, Hmsg, H

# same sk/pk structure as plain sphincs+
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

# xmss_sig subclass that carries the per-instance wots+c counter
# wire format: counter (4 bytes) || wots sig || auth path
class xmss_sig_c(xmss_sig):

    def __init__(self, sig: List[bytes], auth: List[bytes], counter: int):
        super().__init__(sig, auth)
        self.counter = counter

    def get_counter(self) -> int:
        return self.counter

    def to_bytes(self) -> bytes:
        return self.counter.to_bytes(4, "big") + super().to_bytes()

    @staticmethod
    def from_bytes(sig_bytes: bytes, h: int, n: int, wots_len: int) -> "xmss_sig_c":
        counter = int.from_bytes(sig_bytes[:4], "big")
        base = xmss_sig.from_bytes(sig_bytes[4:], h, n, wots_len)
        return xmss_sig_c(base.get_sig(), base.get_auth(), counter)

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
            # wots_PKgen has the same interface as plain wots+
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

    def sig_bytes(self) -> int:
        # wots_c.sig_bytes() already includes the 4-byte counter
        return self.wots_c.sig_bytes() + self.xmss_h * self.n

# hypertree variant using xmss_c at every layer
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

    def ht_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, tree_index: int, leaf_index: int) -> hypertree_sig:
        self.adrs = ADRS()
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        SIG_tmp = self.xmss.xmss_sign(M, sk_seed, leaf_index, pk_seed, self.adrs)
        SIG_HT = [SIG_tmp]
        root = self.xmss.xmss_pkFromSig(leaf_index, SIG_tmp, M, pk_seed, self.adrs)

        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << (self.h // self.d)) - 1)
            tree_index = tree_index >> (self.h // self.d)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            SIG_tmp = self.xmss.xmss_sign(root, sk_seed, leaf_index, pk_seed, self.adrs)
            SIG_HT.append(SIG_tmp)
            if i < self.d - 1:
                root = self.xmss.xmss_pkFromSig(leaf_index, SIG_tmp, root, pk_seed, self.adrs)

        return hypertree_sig(SIG_HT)

    def ht_verify(self, M: bytes, SIG_HT: hypertree_sig, pk_seed: bytes, tree_index: int, leaf_index: int, pk_ht: bytes) -> bool:
        self.adrs = ADRS()
        SIG_TMP = SIG_HT.get_xmss_sigs(0)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        node = self.xmss.xmss_pkFromSig(leaf_index, SIG_TMP, M, pk_seed, self.adrs)

        for i in range(1, self.d):
            leaf_index = tree_index & ((1 << (self.h // self.d)) - 1)
            tree_index = tree_index >> (self.h // self.d)
            SIG_TMP = SIG_HT.get_xmss_sigs(i)
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            node = self.xmss.xmss_pkFromSig(leaf_index, SIG_TMP, node, pk_seed, self.adrs)

        return node == pk_ht

    def sig_bytes(self) -> int:
        return self.d * self.xmss.sig_bytes()

# top-level sphincs+c scheme
# uses fors+c for the few-time signature and wots+c in all hypertree layers
class SphincsC:

    def __init__(self, params: SphincsParamsC, randomize: bool = True) -> None:
        self.params = params
        self.a = int(math.log2(self.params.t))
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
        if self.randomize:
            optrand = os.urandom(self.params.n)
        else:
            optrand = sk.pk_seed

        R = PRFmsg(sk.sk_prf, optrand, message)
        SIG = bytearray(R)

        digest = Hmsg(R, sk.pk_seed, sk.pk_root, message)

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
        sig_fors, fors_counter = self.fors_c.fors_sign(
            md_bytes, sk.sk_seed, sk.pk_seed, adrs
        )
        SIG += fors_counter.to_bytes(4, "big")
        SIG += sig_fors.to_bytes()

        # recover fors public key without sk_seed for use as hypertree input
        pk_fors = self.fors_c.fors_pkFromSig(
            sig_fors, md_bytes, fors_counter, sk.pk_seed, adrs
        )

        sig_ht = self.hypertree.ht_sign(
            pk_fors, sk.sk_seed, sk.pk_seed, idx_tree, idx_leaf
        )
        SIG += sig_ht.to_bytes()

        return bytes(SIG)

    def spx_verify(self, message: bytes, SIG: bytes, pk: PK) -> bool:
        offset = 0

        R = SIG[offset:offset + self.params.n]
        offset += self.params.n

        # fors counter was written before the fors sig bytes
        fors_counter = int.from_bytes(SIG[offset:offset + 4], "big")
        offset += 4

        # subtract 4 from sig_bytes() as the counter is already parsed
        sig_fors_len = self.fors_c.sig_bytes() - 4
        SIG_FORS_bytes = SIG[offset:offset + sig_fors_len]
        offset += sig_fors_len

        sig_ht_len = self.hypertree.sig_bytes()
        SIG_HT_bytes = SIG[offset:offset + sig_ht_len]

        # parse fors sig: (k-1) normal trees, then last sk, then last root
        fors_n = self.params.n
        fors_a = self.a
        fors_k = self.params.k
        sk_list = []
        auth_list = []
        fors_offset = 0
        for i in range(fors_k - 1):
            sk_list.append(SIG_FORS_bytes[fors_offset:fors_offset + fors_n])
            fors_offset += fors_n
            auth_layer = []
            for _ in range(fors_a):
                auth_layer.append(SIG_FORS_bytes[fors_offset:fors_offset + fors_n])
                fors_offset += fors_n
            auth_list.append(auth_layer)
        last_sk = SIG_FORS_bytes[fors_offset:fors_offset + fors_n]
        fors_offset += fors_n
        sk_list.append(last_sk)
        auth_list.append([])
        last_root = SIG_FORS_bytes[fors_offset:fors_offset + fors_n]
        sig_fors = FORS_sig(sk_list, auth_list, last_root)

        # parse hypertree sig, each layer is an xmss_sig_c with a 4-byte counter prefix
        wots_ell = self.wots_c.ell
        xmss_h_prime = self.params.h // self.params.d
        xmss_sig_c_len = 4 + wots_ell * fors_n + xmss_h_prime * fors_n
        xmss_sigs = []
        ht_offset = 0
        for _ in range(self.params.d):
            chunk = SIG_HT_bytes[ht_offset:ht_offset + xmss_sig_c_len]
            ht_offset += xmss_sig_c_len
            xmss_sigs.append(xmss_sig_c.from_bytes(chunk, xmss_h_prime, fors_n, wots_ell))
        sig_ht = hypertree_sig(xmss_sigs)

        digest = Hmsg(R, pk.pk_seed, pk.pk_root, message)
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

        pk_fors = self.fors_c.fors_pkFromSig(
            sig_fors, md_bytes, fors_counter, pk.pk_seed, adrs
        )

        return self.hypertree.ht_verify(
            pk_fors, sig_ht, pk.pk_seed, idx_tree, idx_leaf, pk.pk_root
        )
