import math
from dataclasses import dataclass


@dataclass
class SphincsParams:
    def __init__(self, n, w, h, d, k, t):
        if n <= 0 or w <= 0 or h <= 0 or d <= 0 or k <= 0 or t <= 0:
            raise ValueError("All parameters must be positive")

        if h % d != 0:
            raise ValueError("h must be divisible by d")

        if (t & (t - 1)) != 0:
            raise ValueError("t must be a power of 2")

        self.n = n
        self.w = w
        self.h = h
        self.d = d
        self.k = k
        self.t = t

        self.len1 = math.ceil(8 * self.n / math.log2(self.w))
        self.len2 = math.floor(math.log2(self.len1 * (self.w - 1)) / math.log2(self.w)) + 1
        self.len  = self.len1 + self.len2
