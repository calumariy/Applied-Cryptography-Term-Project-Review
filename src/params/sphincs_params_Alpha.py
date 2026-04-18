from params.sphincs_params import SphincsParams
from WOTS.WOTS_Alpha import cs_len

# extends SphincsParams with cs_l, the reduced chain count under constant-sum encoding
# cs_l is always strictly less than the standard len = l1 + l2 (see table 1 of the paper)
class SphincsParamsAlpha(SphincsParams):

    def __init__(self, n: int, w: int, h: int, d: int, k: int, t: int):
        super().__init__(n, w, h, d, k, t)
        self.cs_l = cs_len(n, w)
