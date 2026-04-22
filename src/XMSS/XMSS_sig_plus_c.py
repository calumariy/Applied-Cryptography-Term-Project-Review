from typing import List
from XMSS.XMSS_sig import xmss_sig

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
