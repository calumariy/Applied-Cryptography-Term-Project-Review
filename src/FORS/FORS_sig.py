from typing import List, Optional

"""
k log t-bit string M
has two components: SK and AUTH
both are essentially lists of bytes of up to k-1 elements
Each auth is composed of log t * n bytes
Each SK is composed of n bytes
This will be checked in sig gen

last_root is used by FORS+C only: the precomputed root of the last tree,
stored by the signer so the verifier does not need sk_seed.
Plain FORS leaves this as None.
"""

class FORS_sig:
    sk: List[bytes]
    auth: List[List[bytes]]
    last_root: Optional[bytes]

    def __init__(self, sk: List[bytes], auth: List[List[bytes]],
                 last_root: Optional[bytes] = None):
        self.sk = sk
        self.auth = auth
        self.last_root = last_root

    def get_sk(self, layer: int) -> bytes:
        return self.sk[layer]

    def get_auth(self, layer: int) -> List[bytes]:
        return self.auth[layer]

    def get_last_root(self) -> Optional[bytes]:
        return self.last_root

    def get_self(self) -> "FORS_sig":
        return self

    def to_bytes(self) -> bytes:
        sig_bytes = bytearray()
        for i in range(len(self.sk)):
            sig_bytes += self.sk[i]
            for j in range(len(self.auth[i])):
                sig_bytes += self.auth[i][j]
        # append last_root if present (used by fors+c)
        if self.last_root is not None:
            sig_bytes += self.last_root
        return bytes(sig_bytes)

    @staticmethod
    def from_bytes(sig_bytes: bytes, k: int, a: int, n: int) -> "FORS_sig":
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