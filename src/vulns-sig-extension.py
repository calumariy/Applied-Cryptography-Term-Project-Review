from params.sphincs_params import SphincsParams
from params.sphincs_params_Alpha import SphincsParamsAlpha
from params.sphincs_params_Plus_C import SphincsParamsC
from sphincs.sphincs import Sphincs
from sphincs.sphincs_Alpha import SphincsAlpha
from sphincs.sphincs_Plus_C import SphincsC
import time
from DGSP.verify import verify
from DGSP.judge import judge
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

MESSAGE = b"hello world"

def divider():
    print("-" * 55)

def header(title: str):
    divider()
    print(f"  {title}")
    divider()

header("SPHINCS+  (base scheme) -- confirming correctness")

params = SphincsParams(n=16, w=16, h=6, d=2, k=4, t=8)
scheme = Sphincs(params, randomize=False)

print(f"  params:  n={params.n}, w={params.w}, h={params.h}, d={params.d}, k={params.k}, t={params.t}")
print(f"  standard chain length (l): {params.len}")
print()

sk, pk = scheme.spx_keygen()
print("  keygen done")

sig = scheme.spx_sign(MESSAGE, sk)
print(f"  signed '{MESSAGE.decode()}'")
print(f"  signature size: {len(sig)} bytes")

valid = scheme.spx_verify(MESSAGE, sig, pk)
print(f"  verify (correct message):  {valid}")

tampered = scheme.spx_verify(b"hello world!", sig, pk)
print(f"  verify (tampered message): {tampered}")

header("SPHINCS+  (base scheme) -- signature tampering test")
sig = scheme.spx_sign(MESSAGE, sk)
print(f"  signed '{MESSAGE.decode()}'")
print(f"  signature size: {len(sig)} bytes")

sig_tampered = sig + b"tamper"
print("  tampered signature created")

valid = scheme.spx_verify(MESSAGE, sig_tampered, pk)
print(f"  verify (correct message, tampered sig):  {valid}")

tampered = scheme.spx_verify(b"hello world!", sig_tampered, pk)
print(f"  verify (tampered message, tampered sig): {tampered}")

# sphincs-alpha

header("SPHINCS-alpha  (constant-sum encoding)")

params_a = SphincsParamsAlpha(n=16, w=16, h=6, d=2, k=4, t=8)
scheme_a = SphincsAlpha(params_a, randomize=False)

print(f"  params:  n={params_a.n}, w={params_a.w}, h={params_a.h}, d={params_a.d}, k={params_a.k}, t={params_a.t}")
print(f"  standard chain length (l): {params_a.len}")
print(f"  constant-sum chain length (cs_l): {params_a.cs_l}  <- one fewer chain per wots+ call")
print()

sk_a, pk_a = scheme_a.spx_keygen()
print("  keygen done")

sig_a = scheme_a.spx_sign(MESSAGE, sk_a)
print(f"  signed '{MESSAGE.decode()}'")

valid_a = scheme_a.spx_verify(MESSAGE, sig_a, pk_a)
print(f"  verify (correct message):  {valid_a}")

tampered_a = scheme_a.spx_verify(b"hello world!", sig_a, pk_a)
print(f"  verify (tampered message): {tampered_a}")

header("SPHINCS+alpha -- signature tampering test")
sig = scheme_a.spx_sign(MESSAGE, sk_a)
print(f"  signed '{MESSAGE.decode()}'")
print(f"  signature size: {len(sig)} bytes")

sig_tampered = sig + b"tamper"
print("  tampered signature created")

valid = scheme_a.spx_verify(MESSAGE, sig_tampered, pk_a)
print(f"  verify (correct message, tampered sig):  {valid}")

tampered = scheme_a.spx_verify(b"hello world!", sig_tampered, pk_a)
print(f"  verify (tampered message, tampered sig): {tampered}")


# sphincs+c  (z=0, no counter search overhead)

header("SPHINCS+C  z=0  (fixed-sum only, no zero-digit condition)")

params_c0 = SphincsParamsC(n=16, w=16, h=6, d=2, k=4, t=8, t_prime=8, z=0)
scheme_c0 = SphincsC(params_c0, randomize=False)

print(f"  params:  n={params_c0.n}, w={params_c0.w}, h={params_c0.h}, d={params_c0.d}, k={params_c0.k}, t={params_c0.t}, z={params_c0.z}")
print()

sk_c0, pk_c0 = scheme_c0.spx_keygen()
print("  keygen done")

sig_c0 = scheme_c0.spx_sign(MESSAGE, sk_c0)
print(f"  signed '{MESSAGE.decode()}'")

valid_c0 = scheme_c0.spx_verify(MESSAGE, sig_c0, pk_c0)
print(f"  verify (correct message):  {valid_c0}")

tampered_c0 = scheme_c0.spx_verify(b"hello world!", sig_c0, pk_c0)
print(f"  verify (tampered message): {tampered_c0}")
header("SPHINCS+C -- signature tampering test")
sig = scheme_c0.spx_sign(MESSAGE, sk_c0)
print(f"  signed '{MESSAGE.decode()}'")
print(f"  signature size: {len(sig)} bytes")

sig_tampered = sig + b"tamper"
print("  tampered signature created")

valid = scheme_c0.spx_verify(MESSAGE, sig_tampered, pk_c0)
print(f"  verify (correct message, tampered sig):  {valid}")

tampered = scheme_c0.spx_verify(b"hello world!", sig_tampered, pk_c0)
print(f"  verify (tampered message, tampered sig): {tampered}")
