from typing import List

"""
An XMSS signature is a ((len + h') * n)-byte signature consisting of:
A WOTS+ signature sig taking len * n bytes
for more info on len, see sphinc+ parameters.
The authentication path AUTH for the leaf associated with the used WOTS+ key pair taking h' * n bytes
Auth path - array of h' n-byte strings ontains the siblings of the nodes in on the path from the used leaf to the root
"""
class xmss_sig:
    sig: List[bytes]
    auth: List[bytes]
    def __init__(self, sig: List[bytes], auth: List[bytes]):
        self.sig = sig
        self.auth = auth

    def get_sig(self) -> List[bytes]:
        return self.sig
    
    def get_auth(self) -> List[bytes]:
        return self.auth; 
    
    def get_self(self) -> "xmss_sig":
        return self
    
    def to_bytes(self) -> bytes:
        sig_bytes = bytearray()
        for part in self.sig:
            sig_bytes += part
        for node in self.auth:
            sig_bytes += node
        return bytes(sig_bytes)
    
    @staticmethod
    def from_bytes(sig_bytes: bytes, h: int, n: int, wots_len: int) -> "xmss_sig":
        sig = []
        offset = 0
        for _ in range(wots_len):
            sig.append(sig_bytes[offset:offset + n])
            offset += n
        auth = []
        for _ in range(h):
            auth.append(sig_bytes[offset:offset + n])
            offset += n

        return xmss_sig(sig, auth)