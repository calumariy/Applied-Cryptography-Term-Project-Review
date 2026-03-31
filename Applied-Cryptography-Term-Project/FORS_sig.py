from typing import List
"""
k log t-bit string M
has two components: SK and AUTH
both are essentially lists of bytes of up to k-1 elements
Each auth is composed of log t * n bytes
Each SK is composed of n bytes
This will be checked in sig gen
"""

class FORS_sig:
    sk: List[bytes]
    auth: List[bytes]
    
    def __init__(self, sk: List[bytes], auth: List[bytes]):
        self.sk = sk
        self.auth = auth

    def get_sk(self, layer: int) -> bytes:
        return self.sk[layer]
    
    def get_auth(self, layer: int) -> bytes:
        return self.auth[layer]
    
    def get_self(self) -> "FORS_sig":
        return self
    
    def to_bytes(self) -> bytes:
        sig_bytes = bytearray()
        for i in range(len(self.sk)):
            sig_bytes += self.sk[i]
            for j in range(len(self.auth[i])):
                sig_bytes += self.auth[j]
        return bytes(sig_bytes)
    
    def from_bytes(self, sig_bytes: bytes, k: int, a: int, n: int) -> "FORS_sig":
        sk = []
        auth = []
        offset = 0
        for i in range(k):
            sk.append(sig_bytes[offset:offset + n])
            offset += n
            auth_layer = []
            for j in range(a):
                auth_layer.append(sig_bytes[offset:offset + n])
                offset += n
            auth.append(auth_layer)
        return FORS_sig(sk, auth)