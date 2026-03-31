import hashlib
from ADRS import ADRS, ADRSType
from typing import List

def toByte(x: int, y: int) -> bytes:
    return x.to_bytes(y, byteorder='big')


# ==============================
# Simple shake 256 impl of the hash functions for testing use.
# ==============================

def thash(PK_seed: bytes, ADRS_obj: ADRS, M: bytes, n: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(PK_seed)
    shake.update(ADRS_obj.to_bytes())
    shake.update(M)
    return shake.digest(n)


def F(PK_seed: bytes, ADRS_obj: ADRS, M: bytes, n: int) -> bytes:
    return thash(PK_seed, ADRS_obj, M, n)


def base_w(X: bytes, w: int, out_len: int) -> List[int]:
    log_w = int(w).bit_length() - 1
    if 2 ** log_w != w:
        raise ValueError("w must be a power of 2")

    basew = [0] * out_len
    total = 0
    bits = 0
    in_index = 0

    for out_index in range(out_len):
        if bits == 0:
            if in_index >= len(X):
                raise ValueError("Not enough input bytes for base_w conversion")
            total = X[in_index]
            in_index += 1
            bits += 8
        bits -= log_w
        basew[out_index] = (total >> bits) & (w - 1)

    return basew
    
def H(PK_seed: bytes, ADRS_obj: ADRS,
      M1: bytes, M2: bytes, n: int) -> bytes:
    return thash(PK_seed, ADRS_obj, M1 + M2, n)

def T_len(PK_seed: bytes, ADRS_obj: ADRS, M: List[bytes], n: int) -> bytes:
    ADRS_obj = ADRS_obj.copy()
    assert isinstance(M, list)
    assert all(len(x) == n for x in M)
    buf = b"".join(M)
    return thash(PK_seed, ADRS_obj, buf, n)

def PRF(SK_seed: bytes, ADRS_obj: ADRS, n: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(SK_seed)
    shake.update(ADRS_obj.to_bytes())
    return shake.digest(n)

def PRFmsg(SK_prf: bytes, optrand: bytes, message: bytes) -> bytes:
    shake = hashlib.shake_256()
    shake.update(SK_prf)
    shake.update(optrand)
    shake.update(message)
    return shake.digest(len(SK_prf))

def Hmsg(randomizer: bytes, PK_seed: bytes, PK_root: bytes, message: bytes) -> bytes:
    shake = hashlib.shake_256()
    shake.update(randomizer)
    shake.update(PK_seed)
    shake.update(PK_root)
    shake.update(message)
    return shake.digest(len(PK_seed))