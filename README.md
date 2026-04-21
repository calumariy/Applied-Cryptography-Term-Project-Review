# Applied Cryptography Term Project

A Python implementation of the SPHINCS+ stateless hash-based signature scheme, extended with two size-reducing optimisations (SPHINCS+C and SPHINCS-alpha), and adapted into a group signature scheme (DGSP).

## Installing Requirements

```bash
pip install -r requirements.txt
```

## Project Structure

```
├── benchmarks/
│   ├── Benchmark Normal Sphincs/   # benchmarks for base SPHINCS+
│   ├── Benchmark Sphincs Alpha/    # benchmarks for SPHINCS-alpha
│   └── Benchmark Sphincs+C/        # benchmarks for SPHINCS+C
└── src/
    ├── DGSP/                   # distributed group signature scheme built on SPHINCS+
    ├── FORS/                   # FORS few-time signature scheme
    ├── helpers/                # hash functions, ADRS, shared utilities
    ├── params/                 # parameter classes for all scheme variants
    ├── sphincs/
    │   ├── hypertree/          # hypertree and xmss layer implementations
    │   ├── sphincs.py          # base SPHINCS+ scheme
    │   ├── sphincs_Plus_C.py   # SPHINCS+C optimisation
    │   └── sphincs_Alpha.py    # SPHINCS-alpha optimisation
    ├── WOTS/                   # WOTS+, WOTS+C, and WOTS-alpha implementations
    ├── XMSS/                   # XMSS layer implementations
    └── test.py                 # test suite
```

## Usage

### base SPHINCS+

```python
from params.sphincs_params import SphincsParams
from sphincs.sphincs import Sphincs

params = SphincsParams(n=16, w=16, h=6, d=2, k=4, t=8)
scheme = Sphincs(params)

sk, pk = scheme.spx_keygen()
sig    = scheme.spx_sign(b"my message", sk)
valid  = scheme.spx_verify(b"my message", sig, pk)
print(valid)  # True
```

### SPHINCS+C

SPHINCS+C replaces the WOTS+ checksum chains with a counter search so the digest always sums to a fixed target, removing the `len2` checksum chains. An optional `z` parameter forces the first `z` digits to zero, dropping those chains too.

```python
from params.sphincs_params_Plus_C import SphincsParamsC
from sphincs.sphincs_Plus_C import SphincsC

params = SphincsParamsC(n=16, w=16, h=6, d=2, k=4, t=8, t_prime=8, z=0)
scheme = SphincsC(params)

sk, pk = scheme.spx_keygen()
sig    = scheme.spx_sign(b"my message", sk)
valid  = scheme.spx_verify(b"my message", sig, pk)
print(valid)  # True
```

### SPHINCS-alpha

SPHINCS-alpha replaces the base_w + checksum encoding in WOTS+ with constant-sum encoding, reducing the codeword length from `l1+l2` to `cs_l` and removing one chain per WOTS+ call with no overhead added back.

```python
from params.sphincs_params_Alpha import SphincsParamsAlpha
from sphincs.sphincs_Alpha import SphincsAlpha

params = SphincsParamsAlpha(n=16, w=16, h=6, d=2, k=4, t=8)
scheme = SphincsAlpha(params)

sk, pk = scheme.spx_keygen()
sig    = scheme.spx_sign(b"my message", sk)
valid  = scheme.spx_verify(b"my message", sig, pk)
print(valid)  # True
```

### comparing signature sizes

```python
from params.sphincs_params import SphincsParams
from params.sphincs_params_Plus_C import SphincsParamsC
from params.sphincs_params_Alpha import SphincsParamsAlpha
from sphincs.sphincs import Sphincs
from sphincs.sphincs_Plus_C import SphincsC
from sphincs.sphincs_Alpha import SphincsAlpha

p  = SphincsParams(n=16, w=16, h=6, d=2, k=4, t=8)
pc = SphincsParamsC(n=16, w=16, h=6, d=2, k=4, t=8, t_prime=8, z=0)
pa = SphincsParamsAlpha(n=16, w=16, h=6, d=2, k=4, t=8)

base   = Sphincs(p, randomize=False)
plus_c = SphincsC(pc, randomize=False)
alpha  = SphincsAlpha(pa, randomize=False)

msg = b"hello world"

sk,  _ = base.spx_keygen();   sig   = base.spx_sign(msg, sk)
skc, _ = plus_c.spx_keygen(); sig_c = plus_c.spx_sign(msg, skc)
ska, _ = alpha.spx_keygen();  sig_a = alpha.spx_sign(msg, ska)

print(f"base:          {len(sig)} bytes")
print(f"SPHINCS+C:     {len(sig_c)} bytes")
print(f"SPHINCS-alpha: {len(sig_a)} bytes")
```

### group signature scheme (DGSP)

DGSP is a distributed group signature scheme built on top of SPHINCS+. It allows members of a group to sign messages on behalf of the group, with a manager controlling membership and a judge able to open signatures and identify the signer if required. There are four roles:

- **manager**: runs the server, controls membership, issues certificates, and can open signatures to reveal the signer
- **member**: joins the group, requests certificates, and signs messages anonymously on behalf of the group
- **verifier**: anyone can verify a group signature against the group public key and the revocation list
- **judge**: given a proof from the manager, can publicly confirm the attribution of a signature to a specific member

```
# usage instructions to be added
```

## Running the Tests

Run the full test suite from the `src/` directory:

```bash
cd src
pytest test.py -v
```

To run with print output visible:

```bash
pytest test.py -v -s
```

To run a specific test class:

```bash
pytest test.py::TestSphincsAlpha -v
```

## Benchmarks

```
# benchmarking instructions to be added
```
