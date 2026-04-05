import hashlib
from math import log
from typing import List, Tuple
from ADRS import ADRS, ADRSType
from helpers import H, F, PRF, T_len
from FORS_sig import FORS_sig


class FORS_C:
    # FORS+C variant from SPHINCS+C paper section 4.
    # searches for a counter so the last FORS tree always opens leaf 0.
    # the auth path for the last tree is replaced by the counter in the signature.
    # the verifier checks the counter forces last index to 0, then uses the
    # precomputed last tree root stored in the signature to reconstruct the pk.
    # saving: a_prime * n bytes (auth path) replaced by 4 bytes (counter) + n bytes (root).
    # t_prime is the leaf count of the last tree, can differ from t to tune tradeoff.

    def __init__(self, n: int, k: int, t: int, t_prime: int, adrs: ADRS):
        if n <= 0 or k <= 0 or t <= 0 or t_prime <= 0:
            raise ValueError("n, k, t and t_prime must be positive integers")
        if (t & (t - 1)) != 0:
            raise ValueError("t must be a power of 2")
        if (t_prime & (t_prime - 1)) != 0:
            raise ValueError("t_prime must be a power of 2")
        if k < 2:
            raise ValueError("k must be at least 2 to remove one tree")
        self.n = n
        self.k = k
        self.t = t
        self.t_prime = t_prime
        self.a = int(log(t, 2))
        self.a_prime = int(log(t_prime, 2))
        self.adrs = adrs

    def fors_SKgen(self, sk_seed: bytes, adrs: ADRS, index: int) -> bytes:
        # identical to FORS.fors_SKgen
        skADRS = adrs.copy()
        skADRS.set_type(ADRSType.FORS_PRF)
        skADRS.set_key_pair_add(adrs.get_key_pair_add())
        skADRS.set_tree_height(0)
        skADRS.set_tree_index(index)
        return PRF(sk_seed, skADRS, self.n)

    def fors_treehash(self, sk_seed: bytes, s: int, z: int,
                      pk_seed: bytes, adrs: ADRS) -> bytes:
        # identical to FORS.fors_treehash
        if s < 0 or z < 0:
            raise ValueError(f"{s} or/and {z} must be a positive integer value")
        if s > 0xFFFFFFFF or z > 0xFFFFFFFF:
            raise ValueError(f"values {s} or/and {z} exceeds 32 bit limit")
        if s % (1 << z) != 0:
            raise ValueError(f"leaf at index {s} is not a leftmost leaf of a sub-tree of height {z}")
        stack = []
        for i in range(pow(2, z)):
            sk = self.fors_SKgen(sk_seed, adrs.copy(), s + i)
            adrs.set_tree_height(0)
            adrs.set_tree_index(s + i)
            node = F(pk_seed, adrs.copy(), sk, self.n)
            adrs.set_tree_height(1)
            height = 1
            while stack and stack[-1][1] == height:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = H(pk_seed, adrs.copy(), stack.pop()[0], node, self.n)
                height += 1
                adrs.set_tree_height(height)
            stack.append((node, height))
        return stack.pop()[0]

    def _hash_with_counter(self, M: bytes, counter: int,
                           pk_seed: bytes, adrs: ADRS) -> bytes:
        # shared helper for counter-based digest
        shake = hashlib.shake_256()
        shake.update(pk_seed)
        shake.update(adrs.to_bytes())
        shake.update(counter.to_bytes(4, "big"))
        shake.update(M)
        return shake.digest(self.n)

    def find_counter(self, M: bytes, pk_seed: bytes,
                     adrs: ADRS) -> Tuple[int, bytes]:
        # search for a counter so the last tree index in the digest is 0
        counter = 0
        while True:
            digest = self._hash_with_counter(M, counter, pk_seed, adrs)
            last_idx = int.from_bytes(digest, "big") & ((1 << self.a_prime) - 1)
            if last_idx == 0:
                return counter, digest
            counter += 1
            if counter > 0xFFFFFFFF:
                raise RuntimeError("counter search exceeded 2^32, check parameters")

    def fors_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        # builds all k roots, first k-1 normal trees then last tree of size t_prime
        forspkADRS = adrs.copy()
        root = [b""] * self.k
        for i in range(self.k - 1):
            root[i] = self.fors_treehash(sk_seed, i * self.t, self.a, pk_seed, adrs)
        root[self.k - 1] = self.fors_treehash(
            sk_seed, (self.k - 1) * self.t, self.a_prime, pk_seed, adrs
        )
        forspkADRS.set_type(ADRSType.FORS_ROOTS)
        forspkADRS.set_key_pair_add(adrs.get_key_pair_add())
        return T_len(pk_seed, forspkADRS, root, self.n)

    def fors_sign(self, M: bytes, sk_seed: bytes,
                  pk_seed: bytes, adrs: ADRS) -> Tuple[FORS_sig, int]:
        # find counter so last tree opens leaf 0, sign first k-1 trees normally.
        # last tree: store sk for leaf 0 only, drop the auth path (replaced by counter).
        # precompute and store the last tree root so the verifier does not need sk_seed.
        counter, _ = self.find_counter(M, pk_seed, adrs)
        M_int = int.from_bytes(M, byteorder="big")
        sk_list = []
        auth_list = []

        # first k-1 trees signed normally using message-derived indices
        for i in range(self.k - 1):
            idx = (M_int >> (self.k - 1 - i) * self.a) % self.t
            sk = self.fors_SKgen(sk_seed, adrs.copy(), i * self.t + idx)
            auth: List[bytes] = [b""] * self.a
            for j in range(self.a):
                s = (idx // (1 << j)) ^ 1
                auth[j] = self.fors_treehash(
                    sk_seed, i * self.t + s * (1 << j), j, pk_seed, adrs.copy()
                )
            sk_list.append(sk)
            auth_list.append(auth)

        # last tree: always opens leaf 0, store sk only, no auth path
        last_sk = self.fors_SKgen(sk_seed, adrs.copy(), (self.k - 1) * self.t)
        sk_list.append(last_sk)
        auth_list.append([])

        # precompute last tree root so verifier can use it without sk_seed
        last_root = self.fors_treehash(
            sk_seed, (self.k - 1) * self.t, self.a_prime, pk_seed, adrs.copy()
        )

        return FORS_sig(sk_list, auth_list, last_root), counter

    def fors_pkFromSig(self, sig: FORS_sig, M: bytes, counter: int,
                       pk_seed: bytes, adrs: ADRS) -> bytes:
        # verify counter is valid, recover first k-1 roots normally,
        # then use the precomputed last tree root stored in the signature.
        # no sk_seed required — this is a fully public verification.
        digest = self._hash_with_counter(M, counter, pk_seed, adrs)
        last_idx = int.from_bytes(digest, "big") & ((1 << self.a_prime) - 1)
        if last_idx != 0:
            # invalid counter, return zeros to cause root mismatch
            return bytes(self.n)

        M_int = int.from_bytes(M, byteorder="big")
        node: List[bytes] = [b"", b""]
        root = [b""] * self.k

        # first k-1 trees recovered normally
        for i in range(self.k - 1):
            idx = (M_int >> (self.k - 1 - i) * self.a) % self.t
            sk = sig.get_sk(i)
            adrs.set_tree_height(0)
            adrs.set_tree_index(i * self.t + idx)
            node[0] = F(pk_seed, adrs.copy(), sk, self.n)
            auth = sig.get_auth(i)
            adrs.set_tree_index(i * self.t + idx)
            for j in range(self.a):
                adrs.set_tree_height(j + 1)
                if (idx // (1 << j)) % 2 == 0:
                    adrs.set_tree_index(adrs.get_tree_index() // 2)
                    node[1] = H(pk_seed, adrs.copy(), node[0], auth[j], self.n)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node[1] = H(pk_seed, adrs.copy(), auth[j], node[0], self.n)
                node[0] = node[1]
            root[i] = node[0]

        # last tree root: taken directly from the signature (precomputed by signer)
        root[self.k - 1] = sig.get_last_root()

        forspkADRS = adrs.copy()
        forspkADRS.set_type(ADRSType.FORS_ROOTS)
        forspkADRS.set_key_pair_add(adrs.get_key_pair_add())
        return T_len(pk_seed, forspkADRS, root, self.n)

    def sig_bytes(self) -> int:
        # (k-1) full trees of (1+a)*n bytes, plus last tree sk only (n bytes),
        # plus last tree root (n bytes), plus counter (4 bytes)
        # saving vs standard FORS: a_prime * n bytes (dropped auth path)
        # minus n bytes (stored root) minus 4 bytes (counter)
        return (self.k - 1) * self.n * (1 + self.a) + self.n + self.n + 4