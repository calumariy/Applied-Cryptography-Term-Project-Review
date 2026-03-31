from dataclasses import dataclass
import os
from typing import List, Tuple

from ADRS import ADRS
from WOTSPLUS import SphincsParams
from XMSS import XMSS
from Hypertree import Hypertree
from FORS import FORS
from FORS_sig import FORS_sig
from Hypertree_sig import hypertree_sig
import sphincs

# Group managers secret key
@dataclass
class MSK:
    msk1: bytes # used for generating a unique secret credentials for users
    msk2: bytes # used for generating the encrypted values used to construct certificates, open signatures, and revocation tokens

# Secret key of DGSP
@dataclass
class DGSP_SK:
    msk: MSK
    spx_sk: sphincs.SK

# Group public parameters of DGSP
@dataclass
class DGSP_PP: 
    spx_pk: sphincs.PK  # group public key
    RL: List[bytes]     # Revocation List (list of revoked user public keys)

class DGSP:

    def __init__(self, params: SphincsParams) -> None:
        self.params = params

        self.n = params.n   # security parameter (represented as lambda in the paper)
        self.h = params.h
        self.d = params.d
        self.k = params.k
        self.t = params.t
        
        self.sphincs = sphincs.Sphincs(params)
        self.RL: List[bytes] = []  # Revocation List (empty to begin with)

    # =========================
    # Key Generation (Manager)
    # =========================
    def keygen_manager(self) -> Tuple[DGSP_SK, DGSP_PP]:

        msk = MSK(os.urandom(self.n), os.urandom(self.n)) # Is urandom secure???? investigate...
        
        (spx_sk, spx_pk) = self.sphincs.spx_keygen()

        self.gpk = spx_pk.pk_root

        groupsk = DGSP_SK(msk, spx_sk)
        groupp = DGSP_PP(spx_pk, self.RL)

        return (groupsk, groupp)
    