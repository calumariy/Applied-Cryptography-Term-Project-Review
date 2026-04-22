from params.sphincs_params import SphincsParams
from WOTS.WOTS_Alpha import cs_len

# extends SphincsParams with cs_l, the reduced chain count under constant-sum encoding
# cs_l is always strictly less than the standard len = l1 + l2 (see table 1 of the paper)
class SphincsParamsAlpha(SphincsParams):
    def __init__(self, n, w, h, d, k, t):
        super().__init__(n, w, h, d, k, t)
        self.cs_l = cs_len(n, w)

    def make_sphincs(self):
        from sphincs.sphincs_Alpha import SphincsAlpha   # adjust path
        return SphincsAlpha(self)

    def make_wots(self):
        from WOTS.WOTS_Alpha import WOTSAlpha
        from WOTS.WOTS_adapter import WOTSAdapter
        return WOTSAdapter(WOTSAlpha(self), variant="alpha")
    
    def make_pk(self, pk_root: bytes, pk_seed: bytes):
        from sphincs.sphincs_Alpha import PK             # adjust path
        return PK(pk_seed=pk_seed, pk_root=pk_root)