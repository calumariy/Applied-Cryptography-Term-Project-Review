# runs through sphincs+, sphincs-alpha, and sphincs+c showing keygen,
# sign, verify, and signature size for each variant side by side.

from params.sphincs_params import SphincsParams
from params.sphincs_params_Alpha import SphincsParamsAlpha
from params.sphincs_params_Plus_C import SphincsParamsC
from sphincs.sphincs import Sphincs
from sphincs.sphincs_Alpha import SphincsAlpha
from sphincs.sphincs_Plus_C import SphincsC


MESSAGE = b"hello world"

def divider():
    print("-" * 55)

def header(title: str):
    divider()
    print(f"  {title}")
    divider()


# base sphincs+

header("SPHINCS+  (base scheme)")

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

base_sig_size = len(sig)


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
print(f"  signature size: {len(sig_a)} bytes  (saving: {base_sig_size - len(sig_a)} bytes vs base)")

valid_a = scheme_a.spx_verify(MESSAGE, sig_a, pk_a)
print(f"  verify (correct message):  {valid_a}")

tampered_a = scheme_a.spx_verify(b"hello world!", sig_a, pk_a)
print(f"  verify (tampered message): {tampered_a}")


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
print(f"  signature size: {len(sig_c0)} bytes  (saving: {base_sig_size - len(sig_c0)} bytes vs base)")

valid_c0 = scheme_c0.spx_verify(MESSAGE, sig_c0, pk_c0)
print(f"  verify (correct message):  {valid_c0}")

tampered_c0 = scheme_c0.spx_verify(b"hello world!", sig_c0, pk_c0)
print(f"  verify (tampered message): {tampered_c0}")


# sphincs+c  (z=2, zero-digit condition active)

header("SPHINCS+C  z=2  (fixed-sum + 2 leading zero digits)")

params_c2 = SphincsParamsC(n=16, w=16, h=6, d=2, k=4, t=8, t_prime=8, z=2)
scheme_c2 = SphincsC(params_c2, randomize=False)

print(f"  params:  n={params_c2.n}, w={params_c2.w}, h={params_c2.h}, d={params_c2.d}, k={params_c2.k}, t={params_c2.t}, z={params_c2.z}")
print(f"  note: signing will be slower due to counter search (~w^z = {params_c2.w**params_c2.z} expected iterations)")
print()

sk_c2, pk_c2 = scheme_c2.spx_keygen()
print("  keygen done")

import time
t0 = time.perf_counter()
sig_c2 = scheme_c2.spx_sign(MESSAGE, sk_c2)
t1 = time.perf_counter()

print(f"  signed '{MESSAGE.decode()}'  ({(t1 - t0) * 1000:.1f} ms)")
print(f"  signature size: {len(sig_c2)} bytes  (saving: {base_sig_size - len(sig_c2)} bytes vs base)")

valid_c2 = scheme_c2.spx_verify(MESSAGE, sig_c2, pk_c2)
print(f"  verify (correct message):  {valid_c2}")

tampered_c2 = scheme_c2.spx_verify(b"hello world!", sig_c2, pk_c2)
print(f"  verify (tampered message): {tampered_c2}")


# side by side summary

header("summary")

print(f"  {'scheme':<20} {'sig size':>10} {'vs base':>10}")
print(f"  {'-'*42}")
print(f"  {'sphincs+':<20} {base_sig_size:>9}B {'—':>10}")
print(f"  {'sphincs-alpha':<20} {len(sig_a):>9}B {f'-{base_sig_size - len(sig_a)}B':>10}")
print(f"  {'sphincs+c (z=0)':<20} {len(sig_c0):>9}B {f'-{base_sig_size - len(sig_c0)}B':>10}")
print(f"  {'sphincs+c (z=2)':<20} {len(sig_c2):>9}B {f'-{base_sig_size - len(sig_c2)}B':>10}")
divider()


# dgsp

header("DGSP  (group signature scheme)")

# needs filling in
print("  [ dgsp demo to be added ]")

divider()