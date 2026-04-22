from params.sphincs_params import SphincsParams

class SphincsParamsC(SphincsParams):
    def __init__(self, n, w, h, d, k, t, t_prime, z=0):
        super().__init__(n, w, h, d, k, t)
        if t_prime <= 0:
            raise ValueError("t_prime must be positive")
        if (t_prime & (t_prime - 1)) != 0:
            raise ValueError("t_prime must be a power of 2")
        if z < 0:
            raise ValueError("z must be non-negative")
        if z >= self.len1:
            raise ValueError("z must be less than len1")
        self.t_prime = t_prime
        self.z = z

    def make_sphincs(self):
        from sphincs.sphincs_Plus_C import SphincsC
        return SphincsC(self)

    def make_wots(self):
        from WOTS.WOTS_Plus_C import WOTSPlusC
        from WOTS.WOTS_adapter import WOTSAdapter
        return WOTSAdapter(WOTSPlusC(self, self.z), variant="plus_c")

    def make_pk(self, pk_root: bytes, pk_seed: bytes):
        from sphincs.sphincs_Plus_C import PK
        return PK(pk_seed=pk_seed, pk_root=pk_root)