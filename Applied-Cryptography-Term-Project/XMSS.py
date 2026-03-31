import math
from ADRS import ADRSType, ADRS
from WOTSPLUS import WOTSPlus
from XMSS_sig import xmss_sig
from helpers import H

class XMSS:
        xmss_h: int # height of the tree (number of levels - 1) (h')
        n: int # the length in bytes of messages as well as of each node.
        w: int # the Winternitz parameter
        # some leaves parameter which is defined as 2^h
        wots_plus: WOTSPlus
        adrs: ADRS
        def __init__(self, h: int, n: int,d:int, w: int, wots_plus: WOTSPlus, adrs: ADRS):
            # the parameters are checked in hypertree init anyway.
            # nothing should be calling or using this class unless its related to the hypertree or through
            # the hypertree
            self.xmss_h = h // d
            self.n = n
            self.w = w
            self.wots_plus = wots_plus
            self.adrs = adrs

        """
            Tree hash function
            sk_seed = secret key seed
            pk_seed = public key seed
            s = start index (unsigned integer)
            z = end idnex (unsigned int)
            ADDR = address.
        """
        def TreeHash(self, sk_seed: bytes, s: int, z:int, pk_seed:bytes, adrs: ADRS) -> bytes:
            # ensure s and z are unsigned integers.
            if (s  < 0 or z < 0):
                raise ValueError(f"{s} or/and {z} must be a positive integer value to be put into a word")
            if (s > 0xFFFFFFFF or z > 0xFFFFFFFF):
                raise ValueError(f"Values {s} or/and {z} exceeds 32 bit limit")
            
            if (s % (1 <<z) != 0): return 1
            # list impl of stack
            stack = []

            for i in range(pow(2, z)):
                adrs.set_type(ADRSType.WOTS_HASH)
                adrs.set_key_pair_add(s + i)
                node = self.wots_plus.wots_PKgen(sk_seed, pk_seed, adrs)
                adrs.set_type(ADRSType.TREE)
                adrs.set_tree_height(1)
                height = 1
                adrs.set_tree_index(s + i)
                while stack and stack[-1][1] == height:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node = H(pk_seed, adrs, (stack.pop()[0]), node, self.n)
                    height += 1
                    adrs.set_tree_height(height)
                # mimic stack push
                stack.append((node, height))
            return stack.pop()[0]
        
        """
        xmss public key generator 
        """
        def xmss_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
            pk = self.TreeHash(sk_seed, 0, self.xmss_h, pk_seed, adrs)
            return pk
        """
            XMSS signature generator with variables:
            M - n-byte message
            sk seed - secret key seed
            index - index number.
            pk seed - public key seed
            adrs - address
        """
        def xmss_sign(self, M:bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> xmss_sig:
            AUTH = [None] * self.xmss_h
            for j in range(self.xmss_h):
                k = math.floor(idx / (pow(2,j))) ^ 1
                AUTH[j] = self.TreeHash(sk_seed, k * pow(2,j), j, pk_seed, adrs)
            
            adrs.set_type(ADRSType.WOTS_HASH)
            adrs.set_key_pair_add(idx)
            sig = self.wots_plus.wots_sign(M, sk_seed, pk_seed, adrs)
            return xmss_sig(sig, AUTH)
        
        def xmss_pkFromSig(self, idx: int, sig:xmss_sig, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
            adrs.set_type(ADRSType.WOTS_HASH)
            adrs.set_key_pair_add(idx)
            # get components of the xmss_sig sig
            AUTH = sig.get_auth()
            sig = sig.get_sig()
            node = self.wots_plus.wots_pkFromSig(sig, M, pk_seed, adrs)

            adrs.set_type(ADRSType.TREE)
            adrs.set_tree_index(idx)
            for k in range(self.xmss_h):
                adrs.set_tree_height(k + 1)
                if ( (math.floor(idx/ pow(2,k)) % 2) == 0):
                    adrs.set_tree_index((adrs.get_tree_index() // 2))
                    node = H(pk_seed, adrs, node, AUTH[k], self.n)
                else:
                    adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                    node = H(pk_seed, adrs, AUTH[k], node, self.n)
            return node
        
        def sig_bytes(self) -> int:
            return self.wots_plus.sig_bytes() + self.xmss_h * self.n