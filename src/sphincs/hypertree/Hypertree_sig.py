from typing import List, TypeVar, Generic

from XMSS.XMSS_sig import XmssSig

T = TypeVar("T", bound=XmssSig)

"""
A hypertree signature (SIG_HT) is a byte string of length (h + d * len)) * n bytes.
It consists of d XMSS signatures (each of length (h/d) + len * n bytes each)
for more info on len, see sphincs+ parameters.
"""


class HypertreeSig(Generic[T]):

    def __init__(self, xmss_sigs: List[T]):
        self.xmss_sigs = xmss_sigs

    def get_xmss_sigs(self, layer: int) -> T:
        return self.xmss_sigs[layer]

    def to_bytes(self) -> bytes:
        sig_bytes = bytearray()
        for sig in self.xmss_sigs:
            sig_bytes += sig.to_bytes()
        return bytes(sig_bytes)

    @staticmethod
    def from_bytes(sig_bytes: bytes, h: int, n: int, d: int, len_wots: int) -> "HypertreeSig[XmssSig]":
        xmss_sigs = []
        offset = 0
        xmss_sig_len = (h // d + len_wots) * n
        for _ in range(d):
            chunk = sig_bytes[offset:offset + xmss_sig_len]
            offset += xmss_sig_len
            xmss_sigs.append(XmssSig.from_bytes(chunk, h // d, n, len_wots))
        return HypertreeSig(xmss_sigs)
