from typing import List, Tuple

from ADRS import ADRS
from WOTSPLUS import WOTSPlus
from XMSS import XMSS
from Hypertree import Hypertree
from FORS import FORS
from FORS_sig import FORS_sig
from Hypertree_sig import hypertree_sig


class DGSP:

    def __init__(self, hypertree: Hypertree, fors: FORS, n: int, h: int, d: int, k: int, t: int) -> None:
        """
        Initialize DGSP scheme parameters and primitives.

        Inputs:
            hypertree : Hypertree instance
            fors      : FORS instance
            n         : security parameter (bytes)
            h         : hypertree height
            d         : number of layers
            k         : FORS trees
            t         : FORS leaves per tree
        """
        self.hypertree = hypertree
        self.fors = fors

        self.n = n
        self.h = h
        self.d = d
        self.k = k
        self.t = t

        self.RL: List[bytes] = []  # Revocation List

    # =========================
    # Key Generation (Manager)
    # =========================
    def keygen_manager(self):
        """
        Returns:
            pk, sk as dictionaries (Pythonic and flexible)
        """

        spx_pk, spx_sk = self.sphincs_keygen()

        sk = {
            "spx_sk": spx_sk,
            "hash_secret": os.urandom(self.n),
            "aes_key": os.urandom(self.n),
        }

        pk = {
            "spx_pk": spx_pk
        }

        return pk, sk
    # =========================
    # Join Protocol
    # =========================
    def join_request(self, user_id: bytes) -> bytes:
        """
        User → Manager: Join request.

        Inputs:
            user_id : identifier

        Output:
            request message (bytes)
        """
        pass

    def join_response(
        self,
        request: bytes,
        sk_m: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Manager → User: Issue credentials.

        Inputs:
            request : join request
            sk_m    : manager secret key

        Outputs:
            sk_u : user secret key
            pk_u : user public key
        """
        pass

    def join_finalize(
        self,
        sk_u: bytes,
        pk_u: bytes
    ) -> None:
        """
        Finalize join and register user.

        Inputs:
            sk_u : user secret key
            pk_u : user public key
        """
        pass

    # =========================
    # Signing
    # =========================
    def sign(
        self,
        message: bytes,
        sk_u: bytes,
        pk_seed: bytes,
        sk_seed: bytes,
        tree_idx: int,
        leaf_idx: int
    ) -> Tuple[FORS_sig, hypertree_sig]:
        """
        Generate DGSP signature.

        Inputs:
            message   : message to sign
            sk_u      : user secret key
            pk_seed   : public seed
            sk_seed   : secret seed
            tree_idx  : hypertree index
            leaf_idx  : leaf index

        Outputs:
            (SIG_FORS, SIG_HT)
        """
        pass

    # =========================
    # Verification
    # =========================
    def verify(
        self,
        message: bytes,
        signature: Tuple[FORS_sig, hypertree_sig],
        pk_seed: bytes,
        pk_root: bytes,
        tree_idx: int,
        leaf_idx: int
    ) -> bool:
        """
        Verify DGSP signature.

        Inputs:
            message   : message
            signature : (FORS_sig, hypertree_sig)
            pk_seed   : public seed
            pk_root   : hypertree public key
            tree_idx  : tree index
            leaf_idx  : leaf index

        Output:
            True / False
        """
        pass

    # =========================
    # Open (Tracing)
    # =========================
    def open(
        self,
        signature: Tuple[FORS_sig, hypertree_sig],
        sk_m: bytes
    ) -> bytes:
        """
        Trace signer identity.

        Inputs:
            signature : DGSP signature
            sk_m      : manager secret key

        Output:
            user identity (bytes)
        """
        pass

    # =========================
    # Revocation
    # =========================
    def revoke(self, pk_u: bytes) -> None:
        """
        Add user to revocation list.

        Input:
            pk_u : user public key
        """
        self.RL.append(pk_u)

    def is_revoked(self, pk_u: bytes) -> bool:
        """
        Check if user is revoked.

        Input:
            pk_u : user public key

        Output:
            True / False
        """
        return pk_u in self.RL