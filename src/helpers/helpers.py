import hashlib
from helpers.ADRS import ADRS
from typing import List, Tuple
from Cryptodome.Cipher import AES  # pip install pycryptodomex


def to_byte(x: int, y: int) -> bytes:
    return x.to_bytes(y, byteorder='big')


# ==============================
# Simple SHAKE-256 implementations of the SPHINCS+ hash functions.
# ==============================

def thash(pk_seed: bytes, adrs: ADRS, M: bytes, n: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(pk_seed)
    shake.update(adrs.to_bytes())
    shake.update(M)
    return shake.digest(n)


def F(pk_seed: bytes, adrs: ADRS, M: bytes, n: int) -> bytes:
    return thash(pk_seed, adrs, M, n)


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


def H(pk_seed: bytes, adrs: ADRS, M1: bytes, M2: bytes, n: int) -> bytes:
    return thash(pk_seed, adrs, M1 + M2, n)


def T_len(pk_seed: bytes, adrs: ADRS, M: List[bytes], n: int) -> bytes:
    adrs = adrs.copy()
    assert isinstance(M, list)
    assert all(len(x) == n for x in M)
    buf = b"".join(M)
    return thash(pk_seed, adrs, buf, n)


def PRF(sk_seed: bytes, adrs: ADRS, n: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(sk_seed)
    shake.update(adrs.to_bytes())
    return shake.digest(n)


def PRFmsg(sk_prf: bytes, optrand: bytes, message: bytes) -> bytes:
    shake = hashlib.shake_256()
    shake.update(sk_prf)
    shake.update(optrand)
    shake.update(message)
    return shake.digest(len(sk_prf))


def Hmsg(randomizer: bytes, pk_seed: bytes, pk_root: bytes, message: bytes) -> bytes:
    shake = hashlib.shake_256()
    shake.update(randomizer)
    shake.update(pk_seed)
    shake.update(pk_root)
    shake.update(message)
    return shake.digest(len(pk_seed))


def H_simple(data: bytes, n: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(data)
    return shake.digest(n)


# ==============================
# SPRP (AES-128) for ζ_{id,j} = E(msk2, id ‖ j)
# Used by the manager in ResponseM, Revoke, and Open.
# ==============================

def _encode_id(user_id: int) -> bytes:
    """Encode a user id as an 8-byte big-endian integer (supports 2^64 users)."""
    return user_id.to_bytes(8, 'big')


def _encode_j(j: int) -> bytes:
    """Encode a certificate index j as an 8-byte big-endian integer."""
    return j.to_bytes(8, 'big')


def sprp_encrypt(msk2: bytes, user_id: int, j: int) -> bytes:
    key       = msk2[:16]
    plaintext = _encode_id(user_id) + _encode_j(j)
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def sprp_decrypt(msk2: bytes, ciphertext: bytes) -> Tuple[int, int]:
    key       = msk2[:16]
    plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
    user_id   = int.from_bytes(plaintext[:8], 'big')
    j         = int.from_bytes(plaintext[8:], 'big')
    return user_id, j
