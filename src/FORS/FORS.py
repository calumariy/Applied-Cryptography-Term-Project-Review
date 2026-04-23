from math import log
from typing import List

from helpers.ADRS import ADRS, ADRSType
from helpers.helpers import H, F, PRF, T_len
from FORS.FORS_sig import ForsSig


class FORS:
    # all three must be positive integers.
    n: int  # security parameter, length of a private/public key element in bytes
    k: int  # number of private key sets, trees and indices computed from the input string
    t: int  # elements per private key set, leaves per hash tree, upper bound on index values; t must be a power of 2
    adrs: ADRS
    a: int  # log base 2 of t

    def __init__(self, n: int, k: int, t: int, adrs: ADRS):
        if n <= 0 or k <= 0 or t <= 0:
            raise ValueError(f"{n}, {k} and {t} must be positive integers")
        if (t & (t - 1)) != 0:
            raise ValueError(f"{t} must be a power of 2")
        self.n = n
        self.adrs = adrs
        self.k = k
        self.t = t
        self.a = int(log(t, 2))

    def fors_SKgen(self, sk_seed: bytes, adrs: ADRS, index: int) -> bytes:
        """
        Generate a FORS private key element using PRF with a FORS key generation address.
        The jth element of the ith set is at index sk[(i*t) + j].
        """
        sk_adrs = adrs.copy()
        sk_adrs.set_type(ADRSType.FORS_PRF)
        sk_adrs.set_key_pair_add(adrs.get_key_pair_add())
        sk_adrs.set_tree_height(0)
        sk_adrs.set_tree_index(index)
        return PRF(sk_seed, sk_adrs, self.n)

    def fors_treehash(self, sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS) -> bytes:
        """
        Tree hash function, similar to the one used in XMSS.
        """
        if s < 0 or z < 0:
            raise ValueError(f"{s} or/and {z} must be positive integers")
        if s > 0xFFFFFFFF or z > 0xFFFFFFFF:
            raise ValueError(f"Values {s} or/and {z} exceed 32-bit limit")
        if s % (1 << z) != 0:
            raise ValueError(f"Leaf at index {s} is not a leftmost leaf of a sub-tree of height {z}")

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

    def fors_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        """
        FORS public key generator.
        Inputs: secret key seed, public key seed, and a FORS address.
        Output: FORS public key.
        """
        forspk_adrs = adrs.copy()
        root = [b""] * self.k
        for i in range(self.k):
            root[i] = self.fors_treehash(sk_seed, i * self.t, self.a, pk_seed, adrs)
        forspk_adrs.set_type(ADRSType.FORS_ROOTS)
        forspk_adrs.set_key_pair_add(adrs.get_key_pair_add())
        return T_len(pk_seed, forspk_adrs, root, self.n)

    def fors_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> ForsSig:
        sk_list = []
        auth_list = []
        msg_int = int.from_bytes(M, byteorder='big')
        for i in range(self.k):
            idx = (msg_int >> (self.k - 1 - i) * self.a) % self.t
            sk = self.fors_SKgen(sk_seed, adrs.copy(), i * self.t + idx)
            auth: List[bytes] = [b""] * self.a
            for j in range(self.a):
                s = (idx // (1 << j)) ^ 1
                auth[j] = self.fors_treehash(sk_seed, i * self.t + s * (1 << j), j, pk_seed, adrs.copy())
            sk_list.append(sk)
            auth_list.append(auth)
        return ForsSig(sk_list, auth_list)

    def fors_pkFromSig(self, sig_fors: ForsSig, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        msg_int = int.from_bytes(M, byteorder='big')
        node: List[bytes] = [b"", b""]
        root = [b""] * self.k
        for i in range(self.k):
            idx = (msg_int >> (self.k - 1 - i) * self.a) % self.t
            sk = sig_fors.get_sk(i)
            adrs.set_tree_height(0)
            adrs.set_tree_index(i * self.t + idx)
            node[0] = F(pk_seed, adrs.copy(), sk, self.n)
            auth = sig_fors.get_auth(i)
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
        forspk_adrs = adrs.copy()
        forspk_adrs.set_type(ADRSType.FORS_ROOTS)
        forspk_adrs.set_key_pair_add(adrs.get_key_pair_add())
        return T_len(pk_seed, forspk_adrs, root, self.n)

    def sig_bytes(self) -> int:
        return self.k * self.n * (1 + self.a)
