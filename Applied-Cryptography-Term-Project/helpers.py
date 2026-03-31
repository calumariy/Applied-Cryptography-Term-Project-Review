import hashlib
from ADRS import ADRS
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

    
def H(PK_seed: bytes, ADRS_obj: ADRS,
      M1: bytes, M2: bytes, n: int) -> bytes:
    return thash(PK_seed, ADRS_obj, M1 + M2, n)


def T_len(PK_seed: bytes, ADRS_obj: ADRS, M:bytes , n: int) -> bytes:
    M = b"".join(M) if isinstance(M, list) else M
    return thash(PK_seed, ADRS_obj, M, n)


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