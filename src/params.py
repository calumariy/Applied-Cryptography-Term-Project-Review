from __future__ import annotations
import math
from dataclasses import dataclass, field

@dataclass
class SphincsParams:
    n: int
    w: int
    h: int
    d: int
    k: int
    t: int

    # computed in __post_init__
    a:    int = field(init=False)
    len1: int = field(init=False)
    len2: int = field(init=False)
    len:  int = field(init=False)

    def __post_init__(self) -> None:
        # ---- validation ----
        if self.n <= 0:
            raise ValueError(f"n must be positive, got {self.n}")
        if self.w <= 1 or (self.w & (self.w - 1)) != 0:
            raise ValueError(f"w must be a power of 2 > 1, got {self.w}")
        if self.h <= 0:
            raise ValueError(f"h must be positive, got {self.h}")
        if self.d <= 0:
            raise ValueError(f"d must be positive, got {self.d}")
        if self.h % self.d != 0:
            raise ValueError(f"h ({self.h}) must be divisible by d ({self.d})")
        if self.k <= 0:
            raise ValueError(f"k must be positive, got {self.k}")
        if self.t <= 1 or (self.t & (self.t - 1)) != 0:
            raise ValueError(f"t must be a power of 2 > 1, got {self.t}")

        # ---- derived values ----
        log_w = int(math.log2(self.w))
        self.a    = int(math.log2(self.t))
        self.len1 = math.ceil(8 * self.n / log_w)
        self.len2 = math.floor(math.log2(self.len1 * (self.w - 1)) / log_w) + 1
        self.len  = self.len1 + self.len2

DGSP_PARAMS = SphincsParams(n=16, w=16, h=6, d=2, k=4, t=8)