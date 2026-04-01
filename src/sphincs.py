import os

from typing import Tuple
from dataclasses import dataclass
from ADRS import ADRS, ADRSType
from WOTSPLUS import WOTSPlus
from Hypertree import Hypertree
from Hypertree_sig import hypertree_sig
from FORS import FORS
from FORS_sig import FORS_sig
from helpers import PRFmsg, Hmsg
import math

# ===================================================================
# Useful data classes for SPHINCS+ parameters, keys, and signatures
# ===================================================================

@dataclass
class SphincsParams:
    def __init__(self, n, w, h, d, k, t):
        if n <= 0 or w <= 0 or h <= 0 or d <= 0 or k <= 0 or t <= 0:
            raise ValueError("All parameters must be positive")

        if h % d != 0:
            raise ValueError("h must be divisible by d")

        if (t & (t - 1)) != 0:
            raise ValueError("t must be a power of 2")

        self.n = n
        self.w = w
        self.h = h
        self.d = d
        self.k = k
        self.t = t

        self.len1 = math.ceil(8 * self.n / math.log2(self.w))
        self.len2 = math.floor(math.log2(self.len1 * (self.w - 1)) / math.log2(self.w)) + 1
        self.len  = self.len1 + self.len2

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

# ===================================================================
# Sphincs+ class with keygen, sign, and verify methods
# ===================================================================

class Sphincs:
    def __init__(self, params: SphincsParams, randomize: bool = True) -> None:

        # Validate parameters
        self.params = params
        self.a = int(math.log2(self.params.t))

        # boolean to determine Deterministic vs Non-Deterministic randomiser
        self.randomize = randomize

        # primitives
        self.adrs = ADRS()
        self.wots = WOTSPlus(self.params)
        self.fors = FORS(self.params.n, self.params.k, self.params.t, self.adrs)
        self.hypertree = Hypertree(self.params.h, self.params.d, self.params.w, self.params.n, self.wots, self.adrs)

    def spx_keygen(self) -> Tuple[SK, PK]:

        # Randomly generated values for SK and PK
        sk_seed = os.urandom(self.params.n)
        pk_seed = os.urandom(self.params.n)
        sk_prf = os.urandom(self.params.n)

        # Public key from hypertree root
        pk_root = self.hypertree.ht_PkGen(sk_seed, pk_seed)

        # Putting it all together
        self.sk = SK(sk_seed, sk_prf, pk_seed, pk_root)
        self.pk = PK(pk_seed, pk_root)

        return (self.sk, self.pk)

    def spx_sign(self, message: bytes, sk: SK) -> bytes:

        # Randomiser option
        if self.randomize:
            optrand = os.urandom(self.params.n)
        else:
            optrand = sk.pk_seed

        # R is the Nonce value included in the signature for protection against multi-target attacks
        R = PRFmsg(sk.sk_prf, optrand, message)

        SIG = bytearray()
        SIG += R

        # Hash message to derive FORS input + tree indices
        digest = Hmsg(R, sk.pk_seed, sk.pk_root, message)

        # Compute bit lengths of each component of the digest
        md_bits = self.params.k * self.a
        tree_bits = self.params.h - (self.params.h // self.params.d)
        leaf_bits = self.params.h // self.params.d
        digest_int = int.from_bytes(digest, "big")

        # Extract fields from digest
        md = (digest_int >> (tree_bits + leaf_bits)) & ((1 << md_bits) - 1)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)

        # Convert FORS message digest to bytes
        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")

        # FORS signing process
        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)

        # Add FORS signature to the overall signature so far (sig = R || sig_fors)
        sig_fors = self.fors.fors_sign(md_bytes, sk.sk_seed, sk.pk_seed, adrs)
        SIG += sig_fors.to_bytes()

        # Add the hypertree signature to the previous signature so sig = R || sig_fors || sig_ht
        pk_fors = self.fors.fors_pkFromSig(sig_fors, md_bytes, sk.pk_seed, adrs)
        sig_ht = self.hypertree.ht_sign(pk_fors, sk.sk_seed, sk.pk_seed, idx_tree, idx_leaf)
        SIG += sig_ht.to_bytes()

        return bytes(SIG)

    def spx_verify(self, message: bytes, SIG: bytes, pk: PK) -> bool:
        offset = 0

        # Parse the signature into its components: R, sig_fors, and sig_ht
        R = SIG[offset:offset + self.params.n]
        offset += self.params.n

        # Determine expected lengths of signature components based on sphincs parameters
        sig_fors_len = self.fors.sig_bytes()
        sig_ht_len   = self.hypertree.sig_bytes()

        # Extract FORS signature
        SIG_FORS_bytes = SIG[offset:offset + sig_fors_len]
        offset += sig_fors_len

        # Extract hypertree signature
        SIG_HT_bytes = SIG[offset:offset + sig_ht_len]

        # Deserialize signatures
        sig_fors = FORS_sig.from_bytes(SIG_FORS_bytes, self.params.k, self.a, self.params.n)
        sig_ht = hypertree_sig.from_bytes(SIG_HT_bytes, self.params.h, self.params.n, self.params.d, self.wots.params.len)

        # Recompute the message digest to extract FORS input and tree indices
        digest = Hmsg(R, pk.pk_seed, pk.pk_root, message)
        md_bits = self.params.k * self.a
        tree_bits = self.params.h - (self.params.h // self.params.d)
        leaf_bits = self.params.h // self.params.d
        digest_int = int.from_bytes(digest, "big")

        # Extract same fields as in signing
        md = (digest_int >> (tree_bits + leaf_bits)) & ((1 << md_bits) - 1)
        idx_tree = (digest_int >> leaf_bits) & ((1 << tree_bits) - 1)
        idx_leaf = digest_int & ((1 << leaf_bits) - 1)

        md_bytes = md.to_bytes((md_bits + 7) // 8, "big")

        # Reconstruct FORS public key
        adrs = ADRS()
        adrs.set_layer_add(0)
        adrs.set_tree_add(idx_tree)
        adrs.set_type(ADRSType.FORS_TREE)
        adrs.set_key_pair_add(idx_leaf)

        pk_fors = self.fors.fors_pkFromSig(sig_fors, md_bytes, pk.pk_seed, adrs)

        # Finally, verify the hypertree signature using the reconstructed FORS public key and the provided public key
        return self.hypertree.ht_verify(pk_fors, sig_ht, pk.pk_seed, idx_tree, idx_leaf, pk.pk_root)
    