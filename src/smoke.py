from params.sphincs_params_Plus_C import SphincsParamsC
from helpers.ADRS import ADRS
import os

p = SphincsParamsC(n=16, w=16, h=6, d=2, k=4, t=8, t_prime=16, z=0)
w = p.make_wots()

print("Adapter:", type(w).__name__)
print("Inner:  ", type(w._wots).__name__)
print("Inner module:", type(w._wots).__module__)

# Call the inner wots_sign directly
result = w._wots.wots_sign(
    M=os.urandom(16),
    SK_seed=os.urandom(16),
    PK_seed=os.urandom(16),
    ADRS_obj=ADRS(),
)
print("Inner wots_sign returned:", type(result).__name__, "with", len(result), "elements")
print("Element types:", [type(x).__name__ for x in result])