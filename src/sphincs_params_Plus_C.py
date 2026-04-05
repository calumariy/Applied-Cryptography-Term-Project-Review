from sphincs_params import SphincsParams

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