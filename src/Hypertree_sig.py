from typing import List
from XMSS_sig import xmss_sig

"""
A hypertree signature (SIG_HT) is a byte string of length (h + d * len)) * n bytes.
It consits of d XMSS signatures (each of length (h/d) + len * n bytes each)
for more info on len, see sphincs+ parameters.
"""
class hypertree_sig:
  xmss_sigs: List[xmss_sig]

  def __init__(self, xmss_sigs: List[xmss_sig]):
    self.xmss_sigs = xmss_sigs

  def get_xmss_sigs(self, layer:int) -> xmss_sig:
    return self.xmss_sigs[layer]
  
  def to_bytes(self) -> bytes:
    sig_bytes = bytearray()
    for sig in self.xmss_sigs:
        sig_bytes += sig.to_bytes()
    return bytes(sig_bytes)
  
  @staticmethod
  def from_bytes(sig_bytes: bytes, h: int, n: int, d: int, len_wots: int) -> "hypertree_sig":
      xmss_sigs = []
      offset = 0
      xmss_sig_len = (h // d + len_wots) * n
      for _ in range(d):
          chunk = sig_bytes[offset:offset + xmss_sig_len]
          offset += xmss_sig_len

          xmss_sigs.append(
              xmss_sig.from_bytes(chunk, h // d, n, len_wots)
          )

      return hypertree_sig(xmss_sigs)
    