from math import log

from ADRS import ADRS, ADRSType
from helpers import H, F, PRF, T_len
from FORS_sig import FORS_sig

class FORS:
    # all three must be positive integers.
    n: int # security parameter, length of a private key, public key or signature key element in bytes.
    k: int # number of private key sets, trees and indices computed from the input string.
    t: int # the number of elements per private key set, number of leaves per hash tree and upper bound
    # on the index values. t must be a power of 2. wherein 2^a and a is the height of the trees.
    # input string is also split into bit strings of length a.
    # all inputs to FORS are bit strings of length k log t.
    adrs: ADRS
    a: int # bonus param log base 2 of t for ease of use.
    def __init__(self, n: int, k: int, t: int, adrs: ADRS):
        if (n <= 0 or k <= 0 or t <= 0):
            raise ValueError(f"{n}, {k} and {t} must be positive integers")
        if (t & (t - 1)) != 0:
            raise ValueError(f"{t} must be a power of 2")
        self.n = n
        self.adrs = adrs
        self.k = k
        self.t = t
        self.a = int(log(t, 2)) # height of the trees. log base 2 of t.
    
    """
      a FORS private key is the single private seed SK.seed contained in the SPHINCS+ private key.
      Generates a kt n-byte private key values using PRF with a FORS key generation address.
      they are logically grouped into a two-dimensional array, for impls, it makes sense
      to assume one dimensional of length kt. The jth element of the ith set is stored at index sk[(i*t) +j]
      skADRS is used, that encodes the position of the FORS key pair within SPHINCS+ 
      and has tree height set to 0 and leaf index set to it + j:
    """
    def fors_SKgen(self, sk_seed: bytes, adrs: ADRS, index: int) -> bytes:
        # sk_seed is a byte string of length n.
        # adrs is the address of the leaf to be generated. The leaf index is derived from the input message.
        # the output is a list of k private keys, each of length n bytes.
       skADRs = adrs.copy()
       skADRs.set_type(ADRSType.FORS_PRF)
       skADRs.set_key_pair_add(adrs.get_key_pair_add())
       skADRs.set_tree_height(0)
       skADRs.set_tree_index(index)
       sk = PRF(sk_seed, skADRs, self.n)
       return sk
    
    """
    it is similar to the treehash used in the XMSS function
    with differences due to the data structure.
    """
    def fors_treehash(self, sk_seed: bytes, s: int, z: int, pk_seed: bytes, adrs: ADRS) -> bytes:
        if (s  < 0 or z < 0):
            raise ValueError(f"{s} or/and {z} must be a positive integer value to be put into a word")
        if (s > 0xFFFFFFFF or z > 0xFFFFFFFF):
            raise ValueError(f"Values {s} or/and {z} exceeds 32 bit limit")
        
        if (s % (1 <<z) != 0): return -1;
        # list impl of stack
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
                node = H(pk_seed, adrs.copy(), (stack.pop()[0]), node,  self.n)
                height += 1
                adrs.set_tree_height(height)
            # mimic stack push
            stack.append((node, height))
        return stack.pop()[0]
    
    """
    fors public key generator
    inputs are a secret key seed, a public key seed and a fors address
    outptus a fors public key
    """
    def fors_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        forspkADRS = adrs.copy() # copy to create FTS public key address
        # roots just shows up. I'll assume its an empty list of k-byte strings considering
        # the for loop after it.
        root = [b""] * (self.k)
        for i in range(self.k):
            root[i] = self.fors_treehash(sk_seed, i * self.t, self.a, pk_seed, adrs)
        forspkADRS.set_type(ADRSType.FORS_ROOTS)
        forspkADRS.set_key_pair_add (adrs.get_key_pair_add())
        pk = T_len(pk_seed, forspkADRS, root, self.n)
        return pk
    
    def fors_sign(self, M: bytes, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> FORS_sig:
        sk_list = []
        auth_list = []
        # to perform bit operations, we need it to be int.
        M_int = int.from_bytes(M, byteorder='big')
        for i in range(self.k):
            # get next index (absolutely disgusting, need to double check this and test this)
            # ok, so we need to extract a certain number of bits from the message
            # specifically the bits that correspond to the range  (i*a) to (i+1) * a -1 of M.
            # self.a = log(t) btw.
            # so we get the lsb then mask that shi.
            # hopefully its correct.
            idx = (M_int >> (self.k - 1 - i) * self.a) % self.t
            sk = self.fors_SKgen(sk_seed, adrs.copy(), i * self.t + idx)
            auth = [None] * self.a
            for j in range(self.a):
                s = (idx // (1 << j)) ^ 1
                auth[j] = self.fors_treehash(sk_seed, i * self.t + s * (1 << j), j, pk_seed, adrs.copy())
            sk_list.append(sk)
            auth_list.append(auth)
        return FORS_sig(sk_list, auth_list)
    
    def fors_pkFromSig(self, SIG_FORS: FORS_sig, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
        M_int = int.from_bytes(M, byteorder='big')
        node = [b""] * 2
        root = [b""] * self.k
        # compute from the roots.
        for i in range(self.k):
            # next index
            idx = (M_int >> (self.k - 1 - i) * self.a) % self.t
            # compute leaf
            sk = SIG_FORS.get_sk(i)
            adrs.set_tree_height(0)
            adrs.set_tree_index((i* self.t) + idx)
            node[0] = F(pk_seed, adrs.copy(), sk, self.n)
            node[1] = 0

            # compute root from leaf to auth
            auth = SIG_FORS.get_auth(i)
            adrs.set_tree_index((i * self.t) + idx)
            for j in range(self.a):
                adrs.set_tree_height(j + 1)
                if (idx // (1 << j)) % 2 == 0:
                    adrs.set_tree_index((adrs.get_tree_index() // 2))
                    node[1] = H(pk_seed, adrs.copy(), node[0], auth[j], self.n)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node[1] = H(pk_seed, adrs.copy(), auth[j], node[0], self.n)
                node[0] = node[1]
            root[i] = node[0]
        forspkADRS = adrs.copy() # copy to create FTS public key address
        forspkADRS.set_type(ADRSType.FORS_ROOTS)
        forspkADRS.set_key_pair_add (adrs.get_key_pair_add())
        pk = T_len(pk_seed, forspkADRS, root, self.n)
        return pk
    
    # Total size of a FORS signature in bytes.
    def sig_bytes(self) -> int:
        return self.k * self.n * (1 + self.a)
    
    def tobytes(self, sig_fors: FORS_sig) -> bytes:
        return sig_fors.to_bytes()


        