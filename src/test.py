import pytest
import os
import math
from helpers.ADRS import ADRS, ADRSType
from params.sphincs_params import SphincsParams
from WOTS.WOTSPLUS import WOTSPlus
from XMSS.XMSS import XMSS
from XMSS.XMSS_sig import xmss_sig
from sphincs.hypertree.Hypertree import Hypertree
from sphincs.hypertree.Hypertree_sig import hypertree_sig
from FORS.FORS import FORS
from FORS.FORS_sig import FORS_sig
from sphincs.sphincs import Sphincs, SK, PK
from DGSP.manager import Manager
from DGSP.judge import judge, _encode_id
from DGSP.member import Member, Certificate, StateU
from DGSP.verify import verify
import helpers.helpers as helpers
from WOTS.WOTS_Plus_C import WOTSPlusC, compute_target_sum, check_conditions
from FORS.FORS_Plus_C import FORS_C
from WOTS.WOTS_Alpha import WOTSAlpha, compute_Dls, cs_encode, cs_decode, cs_len
from params.sphincs_params_Alpha import SphincsParamsAlpha
from sphincs.sphincs_Alpha import SphincsAlpha, SK, PK

# ================================================================
# Test Parameters
# ================================================================a

N = 16
W = 16
H = 6
D = 2       # h/d = 3
K = 4
T = 8       # t = 2^3, a = 3

PARAMS = SphincsParams(n=N, w=W, h=H, d=D, k=K, t=T)
ALPHA_PARAMS = SphincsParamsAlpha(n=N, w=W, h=H, d=D, k=K, t=T)

def make_fors_adrs() -> ADRS:
    # fors requires a specific ADRS type to be parsed unto it for usage.
    adrs = ADRS()
    adrs.set_layer_add(0)
    adrs.set_tree_add(0)
    adrs.set_type(ADRSType.FORS_TREE)
    adrs.set_key_pair_add(0)
    return adrs


# ================================================================
# Fixtures
# ================================================================

@pytest.fixture
def adrs():
    return ADRS()

@pytest.fixture
def sk_seed():
    return os.urandom(N)

@pytest.fixture
def pk_seed():
    return os.urandom(N)

@pytest.fixture
def skprf():
    return os.urandom(N)

@pytest.fixture
def wots():
    return WOTSPlus(PARAMS)

@pytest.fixture
def xmss(wots):
    return XMSS(H, N, D, W, wots, ADRS())

@pytest.fixture
def ht(wots):
    return Hypertree(H, D, W, N, wots, ADRS())

@pytest.fixture
def fors():
    return FORS(N, K, T, make_fors_adrs())

@pytest.fixture
def message():
    return os.urandom(N)

# randomly generated message according for proper testing.
@pytest.fixture
def fors_message():
    bits = K * int(math.log2(T))
    return os.urandom((bits + 7) // 8)

@pytest.fixture
def sphincs():
    return Sphincs(PARAMS)

@pytest.fixture
def wots_c():
    return WOTSPlusC(PARAMS, z=0)
 
@pytest.fixture
def wots_c_z1():
    return WOTSPlusC(PARAMS, z=1)

@pytest.fixture
def fors_c():
    return FORS_C(N, K, T, T, make_fors_adrs())
 
@pytest.fixture
def fors_c_message():
    bits = K * int(math.log2(T))
    return os.urandom((bits + 7) // 8)

@pytest.fixture
def wots_alpha():
    return WOTSAlpha(PARAMS)

@pytest.fixture
def scheme():
    return SphincsAlpha(ALPHA_PARAMS, randomize=False)
 
@pytest.fixture
def scheme_randomized():
    return SphincsAlpha(ALPHA_PARAMS, randomize=True)
 
@pytest.fixture
def keypair(scheme):
    return scheme.spx_keygen()

@pytest.fixture
def manager():
    m = Manager(PARAMS)
    m.keygen()
    return m

@pytest.fixture
def joined_user(manager):
    return manager.join("alice")

@pytest.fixture
def wots_keypair():
    wots = WOTSPlus(PARAMS)
    seed = os.urandom(N); rid = os.urandom(N)
    rho = helpers.H_simple(rid, N)
    sk_seed = helpers.H_simple(seed + rid, N)
    return wots.wots_PKgen(sk_seed, rho, ADRS())

@pytest.fixture
def fresh_member(manager, joined_user):
    """A Member whose state is populated via join, with no certs yet."""
    user_id, cstar = joined_user
    m = Member(PARAMS, host="unused", port=0)
    m.pk_bytes = manager._serialise_pk()
    m.pk_root  = m.pk_bytes[:N]
    m.pk_seed  = m.pk_bytes[N:]
    m.state = StateU(
        id=user_id, c_id=None, cstar_id=cstar,
        seed=os.urandom(N), ctr_u=0, ctr_m=0,
    )
    return m




def _make_member(manager, username: str, n_certs: int = 1) -> Member:
    user_id, cstar = manager.join(username)

    m = Member(PARAMS, host="unused", port=0)
    m.pk_bytes = manager._serialise_pk()
    m.pk_root  = m.pk_bytes[:N]
    m.pk_seed  = m.pk_bytes[N:]

    seed = os.urandom(N)
    m.state = StateU(
        id=user_id, c_id=None, cstar_id=cstar,
        seed=seed, ctr_u=0, ctr_m=0,
    )

    if n_certs == 0:
        return m

    new_rids = {}
    pub_keys = []
    for i in range(n_certs):
        j     = m.state.ctr_m + i + 1
        rid_j = os.urandom(N)
        rho_j = helpers.H_simple(rid_j, N)
        sk_seed = helpers.H_simple(seed + rid_j, N)
        pk_j  = m.wots.wots_PKgen(sk_seed, rho_j, ADRS())
        new_rids[j] = rid_j
        pub_keys.append(pk_j)

    certs_raw = manager.response_m(user_id, cstar, pub_keys)

    new_certs = []
    for i, (zeta, pi, sigma_s) in enumerate(certs_raw):
        j = m.state.ctr_m + i + 1
        new_certs.append(Certificate(j=j, zeta=zeta, pi=pi, sigma_s=sigma_s))

    for j, rid_j in new_rids.items():
        m.state.R[j] = rid_j

    m.updateState(new_certs)
    return m


# ================================================================
# XMSS Tests
# ================================================================

class TestXMSS:

    # Test pkgen to see if it returns specific amount of bytes
    def test_pkgen_returns_n_bytes(self, xmss, sk_seed, pk_seed):
        pk = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        assert isinstance(pk, bytes)
        assert len(pk) == N

    # test pkgen to see if the hash is deterministic. Same input will always lead to same output
    def test_pkgen_deterministic(self, xmss, sk_seed, pk_seed):
        pk1 = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        pk2 = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        assert pk1 == pk2

    # test pkgen to see if different seeds leads to different keys.
    def test_pkgen_differs_for_different_sk(self, xmss, pk_seed):
        pk1 = xmss.xmss_PKgen(os.urandom(N), pk_seed, ADRS())
        pk2 = xmss.xmss_PKgen(os.urandom(N), pk_seed, ADRS())
        assert pk1 != pk2

    # test sign to see if it returns correctly constructed XMSS_SIG
    def test_sign_returns_xmss_sig(self, xmss, message, sk_seed, pk_seed):
        sig = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        assert isinstance(sig, xmss_sig)

    # byte test
    def test_sign_auth_nodes_are_n_bytes(self, xmss, message, sk_seed, pk_seed):
        sig = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        for node in sig.get_auth():
            assert len(node) == N

    # deterministic teset
    def test_sign_deterministic(self, xmss, message, sk_seed, pk_seed):
        sig1 = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        sig2 = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        assert sig1.get_sig() == sig2.get_sig()
        assert sig1.get_auth() == sig2.get_auth()

    # diff result test
    def test_sign_different_idx_gives_different_auth(self, xmss, message, sk_seed, pk_seed):
        sig0 = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        sig1 = xmss.xmss_sign(message, sk_seed, 1, pk_seed, ADRS())
        assert sig0.get_auth() != sig1.get_auth()

    # byte test
    def test_pkfromsig_returns_n_bytes(self, xmss, message, sk_seed, pk_seed):
        sig = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        root = xmss.xmss_pkFromSig(0, sig, message, pk_seed, ADRS())
        assert isinstance(root, bytes)
        assert len(root) == N

    # match test. pkFromSig must recover same stuff that pkGen produces for the same seed and index.
    def test_pkfromsig_matches_pkgen(self, xmss, message, sk_seed, pk_seed):
        """Core consistency: root recovered from sig must equal real public key."""
        pk  = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        sig = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        recovered = xmss.xmss_pkFromSig(0, sig, message, pk_seed, ADRS())
        assert recovered == pk

    # match test should always be different because of different seeds.
    def test_pkfromsig_fails_on_wrong_message(self, xmss, message, sk_seed, pk_seed):
        pk  = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        sig = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        recovered = xmss.xmss_pkFromSig(0, sig, os.urandom(N), pk_seed, ADRS())
        assert recovered != pk
    
    # match test should always be different because of different index.
    def test_pkfromsig_fails_on_wrong_idx(self, xmss, message, sk_seed, pk_seed):
        pk  = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        sig = xmss.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        recovered = xmss.xmss_pkFromSig(1, sig, message, pk_seed, ADRS())
        assert recovered != pk

    # match test. pkFromSig must recover same stuff that pkGen produces for the same seed and index.
    # Essentially exhaustive version of the proper check test wherein we want to check for
    # every part of the sig that the stuff we get is the same.
    def test_pkfromsig_all_indices(self, xmss, sk_seed, pk_seed):
        pk = xmss.xmss_PKgen(sk_seed, pk_seed, ADRS())
        for idx in range(2 ** xmss.xmss_h):
            msg = os.urandom(N)
            sig = xmss.xmss_sign(msg, sk_seed, idx, pk_seed, ADRS())
            recovered = xmss.xmss_pkFromSig(idx, sig, msg, pk_seed, ADRS())
            assert recovered == pk, f"Failed at idx={idx}"


# ================================================================
# Hypertree Tests
# ================================================================

class TestHypertree:

    # simple check tests, see if if statement gets through.
    def test_invalid_h_raises(self, wots):
        with pytest.raises(ValueError):
            Hypertree(0, D, W, N, wots, ADRS())

    def test_h_not_divisible_by_d_raises(self, wots):
        with pytest.raises(ValueError):
            Hypertree(7, D, W, N, wots, ADRS())

    def test_invalid_n_raises(self, wots):
        with pytest.raises(ValueError):
            Hypertree(H, D, W, 0, wots, ADRS())

    # byte test
    def test_pkgen_returns_n_bytes(self, ht, sk_seed, pk_seed):
        pk = ht.ht_PkGen(sk_seed, pk_seed)
        assert isinstance(pk, bytes)
        assert len(pk) == N

    # deterministic test
    def test_pkgen_deterministic(self, ht, sk_seed, pk_seed):
        pk1 = ht.ht_PkGen(sk_seed, pk_seed)
        pk2 = ht.ht_PkGen(sk_seed, pk_seed)
        assert pk1 == pk2

    # different test because of different seeds.
    def test_pkgen_differs_for_different_seeds(self, ht, pk_seed):
        pk1 = ht.ht_PkGen(os.urandom(N), pk_seed)
        pk2 = ht.ht_PkGen(os.urandom(N), pk_seed)
        assert pk1 != pk2

    # check test if returns correct type of sig
    def test_sign_returns_hypertree_sig(self, ht, message, sk_seed, pk_seed):
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert isinstance(sig, hypertree_sig)

    # check test if the sig contains d xmss sigs
    def test_sign_contains_d_xmss_sigs(self, ht, message, sk_seed, pk_seed):
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert len(sig.xmss_sigs) == D

    # check test to see if every sig in the sig is an xmss sig
    def test_sign_each_layer_is_xmss_sig(self, ht, message, sk_seed, pk_seed):
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        for s in sig.xmss_sigs:
            assert isinstance(s, xmss_sig)

    # deterministic test
    def test_sign_deterministic(self, ht, message, sk_seed, pk_seed):
        sig1 = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        sig2 = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        for s1, s2 in zip(sig1.xmss_sigs, sig2.xmss_sigs):
            assert s1.get_sig() == s2.get_sig()
            assert s1.get_auth() == s2.get_auth()

    # fundamental test that checks the functionality of the impleementation.
    def test_verify_valid_signature(self, ht, message, sk_seed, pk_seed):
        pk  = ht.ht_PkGen(sk_seed, pk_seed)
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht.ht_verify(message, sig, pk_seed, 0, 0, pk) is True

    # check test to see if wrong message fails verification.
    def test_verify_wrong_message_fails(self, ht, message, sk_seed, pk_seed):
        pk  = ht.ht_PkGen(sk_seed, pk_seed)
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht.ht_verify(os.urandom(N), sig, pk_seed, 0, 0, pk) is False

    # check test to see if wrong pk fails verification.
    def test_verify_wrong_pk_fails(self, ht, message, sk_seed, pk_seed):
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht.ht_verify(message, sig, pk_seed, 0, 0, os.urandom(N)) is False

    # check test to see if wrong index fails verification.
    def test_verify_wrong_leaf_index_fails(self, ht, message, sk_seed, pk_seed):
        pk  = ht.ht_PkGen(sk_seed, pk_seed)
        sig = ht.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht.ht_verify(message, sig, pk_seed, 0, 1, pk) is False

    # check test to see if wrong layer index fails verification.
    def test_verify_all_leaf_indices(self, ht, sk_seed, pk_seed):
        """Sign and verify at every valid leaf position."""
        pk = ht.ht_PkGen(sk_seed, pk_seed)
        for idx_leaf in range(2 ** (H // D)):
            msg = os.urandom(N)
            sig = ht.ht_sign(msg, sk_seed, pk_seed, 0, idx_leaf)
            assert ht.ht_verify(msg, sig, pk_seed, 0, idx_leaf, pk), \
                f"Failed at idx_leaf={idx_leaf}"

# ================================================================
# FORS Tests
# ================================================================

class TestFORS:
    # simple check tests, see if if statement gets through.
    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            FORS(0, K, T, make_fors_adrs())

    def test_t_not_power_of_2_raises(self):
        with pytest.raises(ValueError):
            FORS(N, K, 7, make_fors_adrs())

    def test_a_computed_correctly(self, fors):
        assert fors.a == int(math.log2(T))

    # byte test
    def test_skgen_returns_n_bytes(self, fors, sk_seed):
        sk = fors.fors_SKgen(sk_seed, make_fors_adrs(), 0)
        assert isinstance(sk, bytes)
        assert len(sk) == N

    # deterministic test
    def test_skgen_deterministic(self, fors, sk_seed):
        sk1 = fors.fors_SKgen(sk_seed, make_fors_adrs(), 0)
        sk2 = fors.fors_SKgen(sk_seed, make_fors_adrs(), 0)
        assert sk1 == sk2

    # different test because of different index.
    def test_skgen_different_indices_differ(self, fors, sk_seed):
        sk0 = fors.fors_SKgen(sk_seed, make_fors_adrs(), 0)
        sk1 = fors.fors_SKgen(sk_seed, make_fors_adrs(), 1)
        assert sk0 != sk1

    # byte test
    def test_treehash_returns_n_bytes(self, fors, sk_seed, pk_seed):
        root = fors.fors_treehash(sk_seed, 0, fors.a, pk_seed, make_fors_adrs())
        assert isinstance(root, bytes)
        assert len(root) == N

    # invalid start test
    def test_treehash_invalid_start_raises(self, fors, sk_seed, pk_seed):
        with pytest.raises(ValueError):
            fors.fors_treehash(sk_seed, -1, fors.a, pk_seed, make_fors_adrs())

    # invalid test (following the spec)
    def test_treehash_misaligned_start_returns_error(self, fors, sk_seed, pk_seed):
        with pytest.raises(ValueError):
            fors.fors_treehash(sk_seed, 1, 1, pk_seed, make_fors_adrs())

    # deterministic test
    def test_treehash_deterministic(self, fors, sk_seed, pk_seed):
        r1 = fors.fors_treehash(sk_seed, 0, fors.a, pk_seed, make_fors_adrs())
        r2 = fors.fors_treehash(sk_seed, 0, fors.a, pk_seed, make_fors_adrs())
        assert r1 == r2

    # byte test
    def test_pkgen_returns_n_bytes(self, fors, sk_seed, pk_seed):
        pk = fors.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        assert isinstance(pk, bytes)
        assert len(pk) == N

    # deterministic test
    def test_pkgen_deterministic(self, fors, sk_seed, pk_seed):
        pk1 = fors.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        pk2 = fors.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        assert pk1 == pk2

    # different test because of different seeds.
    def test_pkgen_differs_for_different_seeds(self, fors, pk_seed):
        pk1 = fors.fors_PKgen(os.urandom(N), pk_seed, make_fors_adrs())
        pk2 = fors.fors_PKgen(os.urandom(N), pk_seed, make_fors_adrs())
        assert pk1 != pk2

    # check test if returns correct type of sig
    def test_sign_returns_fors_sig(self, fors, fors_message, sk_seed, pk_seed):
        sig = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        assert isinstance(sig, FORS_sig)

    # byte test
    def test_sign_sk_elements_are_n_bytes(self, fors, fors_message, sk_seed, pk_seed):
        sig = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        for i in range(K):
            assert len(sig.get_sk(i)) == N

    # deterministic test
    def test_sign_deterministic(self, fors, fors_message, sk_seed, pk_seed):
        sig1 = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        sig2 = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        for i in range(K):
            assert sig1.get_sk(i) == sig2.get_sk(i)
            assert sig1.get_auth(i) == sig2.get_auth(i)

    # byte test
    def test_pkfromsig_returns_n_bytes(self, fors, fors_message, sk_seed, pk_seed):
        sig = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        pk  = fors.fors_pkFromSig(sig, fors_message, pk_seed, make_fors_adrs())
        assert isinstance(pk, bytes)
        assert len(pk) == N

    # match test/impl test. output pk and recovered must match.
    def test_pkfromsig_matches_pkgen(self, fors, fors_message, sk_seed, pk_seed):
        pk        = fors.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        sig       = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        recovered = fors.fors_pkFromSig(sig, fors_message, pk_seed, make_fors_adrs())
        assert recovered == pk

    # different test because of wrong message. pkFromSig should not recover the same pk if the message is wrong.
    def test_pkfromsig_fails_on_wrong_message(self, fors, fors_message, sk_seed, pk_seed):
        pk        = fors.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        sig       = fors.fors_sign(fors_message, sk_seed, pk_seed, make_fors_adrs())
        wrong_msg = os.urandom(len(fors_message))
        recovered = fors.fors_pkFromSig(sig, wrong_msg, pk_seed, make_fors_adrs())
        assert recovered != pk

    # match test/impl test. pkFromSig must recover the same pk for any valid message.
    # exhaustive version.
    def test_pkfromsig_multiple_messages(self, fors, sk_seed, pk_seed):
        """pkFromSig must recover the same pk for any valid message."""
        pk        = fors.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        msg_bytes = (K * fors.a + 7) // 8
        for _ in range(5):
            msg       = os.urandom(msg_bytes)
            sig       = fors.fors_sign(msg, sk_seed, pk_seed, make_fors_adrs())
            recovered = fors.fors_pkFromSig(sig, msg, pk_seed, make_fors_adrs())
            assert recovered == pk

# ================================================================
# Sphincs+ Tests
# ================================================================
class TestSphincs:
    # simple check tests, see if if statement gets through.
    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            SphincsParams(n=0, w=W, h=H, d=D, k=K, t=T)

    def test_a_computed_correctly(self, sphincs):
        assert sphincs.fors.a == int(math.log2(T))

    def test_invalid_h_raises(self):
        with pytest.raises(ValueError):
            SphincsParams(n=N, w=W, h=0, d=D, k=K, t=T)

    def test_h_not_divisible_by_d_raises(self):
        with pytest.raises(ValueError):
            SphincsParams(n=N, w=W, h=7, d=D, k=K, t=T)

    def test_invalid_d_raises(self):
        with pytest.raises(ValueError):
            SphincsParams(n=N, w=W, h=H, d=0, k=K, t=T)

    def test_invalid_t_raises(self):
        with pytest.raises(ValueError):
            SphincsParams(n=N, w=W, h=H, d=D, k=K, t=7)

    # Test underlying primitives to see if they are properly initialized and have the right parameters.
    def test_fors_section_corruption_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = bytearray(sphincs.spx_sign(message, sk))

        start = sphincs.params.n
        sig[start] ^= 0xFF  # corrupt FORS part

        assert sphincs.spx_verify(message, bytes(sig), pk) is False
    
    def test_hypertree_section_corruption_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = bytearray(sphincs.spx_sign(message, sk))

        start = sphincs.params.n + sphincs.fors.sig_bytes()
        sig[start] ^= 0xFF  # corrupt HT part

        assert sphincs.spx_verify(message, bytes(sig), pk) is False

    # Testing message randomization. Same message should lead to different signatures because of randomization.
    def test_empty_message(self, sphincs):
        (sk, pk) = sphincs.spx_keygen()
        sig = sphincs.spx_sign(b"", sk)
        assert sphincs.spx_verify(b"", sig, pk) is True
    
    def test_same_message_different_keys(self, sphincs, message):
        (sk1, pk1) = sphincs.spx_keygen()
        (sk2, pk2) = sphincs.spx_keygen()

        sig1 = sphincs.spx_sign(message, sk1)
        sig2 = sphincs.spx_sign(message, sk2)

        assert sig1 != sig2
        assert pk1 != pk2
    
    def test_deterministic_mode_reproducibility(self, message):
        sphincs = Sphincs(PARAMS, randomize=False)

        (sk, pk) = sphincs.spx_keygen()
        sig1 = sphincs.spx_sign(message, sk)
        sig2 = sphincs.spx_sign(message, sk)

        assert sig1 == sig2
        assert sphincs.spx_verify(message, sig1, pk)

    # Test Signing and verifying
    def test_signature_length_correct(self, sphincs, message):
        sk = sphincs.spx_keygen()[0]
        sig = sphincs.spx_sign(message, sk)
        expected_len = (
            sphincs.params.n +
            sphincs.fors.sig_bytes() +
            sphincs.hypertree.sig_bytes()
        )
        assert len(sig) == expected_len

    def test_truncated_signature_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = sphincs.spx_sign(message, sk)

        truncated = sig[:-10]
        assert sphincs.spx_verify(message, truncated, pk) is False

    def test_sign_then_verify_is_successful(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = sphincs.spx_sign(message, sk)
        assert sphincs.spx_verify(message, sig, pk) is True
    
    def test_forged_signature_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = sphincs.spx_sign(message, sk)
        forged_sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])  # Flip last byte to forge
        assert sphincs.spx_verify(message, forged_sig, pk) is False
    
    def test_wrong_message_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = sphincs.spx_sign(message, sk)
        wrong_message = os.urandom(len(message))
        assert sphincs.spx_verify(wrong_message, sig, pk) is False
    
    def test_wrong_public_key_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = sphincs.spx_sign(message, sk)
        wrong_pk = PK(os.urandom(len(pk.pk_seed)), os.urandom(len(pk.pk_root)))
        assert sphincs.spx_verify(message, sig, wrong_pk) is False

# ================================================================
# DGSP Tests
# ================================================================

# ---------- Shared helper for Sign-like signature construction ----------

def _build_signature(manager, user_id, cstar, msg):
    """
    Synthesise a well-formed DGSP signature the way Member.sign() would.
    Returns (sig_tuple, pi, pk_idj, sk_seed, rho).
    """
    wots = WOTSPlus(PARAMS)
    seed = os.urandom(N)
    rid  = os.urandom(N)
    rho  = helpers.H_simple(rid, N)
    sk_seed = helpers.H_simple(seed + rid, N)
    pk_idj = wots.wots_PKgen(sk_seed, rho, ADRS())

    zeta, pi, sigma_s = manager.response_m(user_id, cstar, [pk_idj])[0]

    M = helpers.H_simple(rho + msg, N)
    sigma_w = b"".join(wots.wots_sign(M, sk_seed, rho, ADRS()))
    tau = helpers.H_simple(pk_idj + pi + _encode_id(user_id), N)

    return (sigma_w, rho, zeta, sigma_s, tau), pi, pk_idj, sk_seed, rho

# class DGSP:

class TestDGSP:

        # ---------- Fixtures ---------
    # ================================================================
    #                           KeyGen
    # ================================================================

    def test_keygen_sets_msk(self, manager):
        assert manager.msk is not None
        assert len(manager.msk) == 2
        assert len(manager.msk[0]) == N
        assert len(manager.msk[1]) == N

    def test_keygen_msk_halves_independent(self, manager):
        """msk1 and msk2 should be drawn independently — collision is essentially impossible."""
        assert manager.msk[0] != manager.msk[1]

    def test_keygen_sets_sphincs_keys(self, manager):
        assert hasattr(manager, "spx_sk")
        assert hasattr(manager, "spx_pk")
        assert manager.gpk == manager.spx_pk.pk_root

    def test_keygen_serialised_pk_length(self, manager):
        pk_bytes = manager._serialise_pk()
        assert len(pk_bytes) == 2 * N

    def test_keygen_serialised_pk_structure(self, manager):
        """First half is pk_root, second half is pk_seed."""
        pk_bytes = manager._serialise_pk()
        assert pk_bytes[:N] == manager.spx_pk.pk_root
        assert pk_bytes[N:] == manager.spx_pk.pk_seed

    def test_keygen_empty_revocation_list(self, manager):
        assert manager.RL == []

    def test_keygen_empty_state(self, manager):
        assert manager.statesM == {}
        assert manager.user_count() == 0

    def test_keygen_distinct_runs_distinct_keys(self):
        """Two managers should generate completely independent key material."""
        m1 = Manager(PARAMS); m1.keygen()
        m2 = Manager(PARAMS); m2.keygen()
        assert m1.msk != m2.msk
        assert m1.gpk != m2.gpk

    def test_serialise_pk_before_keygen_raises(self):
        m = Manager(PARAMS)
        with pytest.raises(RuntimeError):
            m._serialise_pk()

    # ================================================================
#                               Join
    # ================================================================

    def test_join_assigns_sequential_ids(self, manager):
        id1, _ = manager.join("alice")
        id2, _ = manager.join("bob")
        id3, _ = manager.join("carol")
        assert (id1, id2, id3) == (1, 2, 3)

    def test_join_first_id_is_one(self, joined_user):
        user_id, _ = joined_user
        assert user_id == 1

    def test_join_returns_n_byte_cstar(self, joined_user):
        _, cstar = joined_user
        assert isinstance(cstar, bytes)
        assert len(cstar) == N

    def test_join_duplicate_username_rejected(self, manager):
        manager.join("alice")
        with pytest.raises(ValueError):
            manager.join("alice")

    def test_join_duplicate_after_revoke_still_rejected(self, manager):
        """Revoking a user shouldn't free their username — record persists."""
        uid, _ = manager.join("alice")
        manager.revoke([uid])
        with pytest.raises(ValueError):
            manager.join("alice")

    def test_join_case_sensitive_usernames(self, manager):
        """'Alice' and 'alice' are distinct."""
        manager.join("alice")
        manager.join("Alice")  # should not raise
        assert manager.user_count() == 2

    def test_join_empty_username_allowed_or_documented(self, manager):
        """Whatever the policy is, behaviour should be deterministic."""
        # current implementation allows empty string — server.py rejects it at the wire layer
        uid, cstar = manager.join("")
        assert uid == 1 and len(cstar) == N

    def test_join_records_active_user(self, manager, joined_user):
        user_id, _ = joined_user
        assert manager.is_active(user_id)
        assert manager.statesM[user_id].state.ctr == 0

    def test_join_username_stored(self, manager, joined_user):
        user_id, _ = joined_user
        assert manager.statesM[user_id].username == "alice"

    def test_join_before_keygen_raises(self):
        m = Manager(PARAMS)
        with pytest.raises(RuntimeError):
            m.join("alice")

    def test_cstar_deterministic_from_msk(self, manager):
        user_id, cstar = manager.join("alice")
        msk1 = manager.msk[0]
        cid_expected   = helpers.H_simple(msk1 + _encode_id(user_id), N)
        cstar_expected = helpers.H_simple(_encode_id(user_id) + cid_expected, N)
        assert cstar == cstar_expected

    def test_cstar_different_for_different_users(self, manager):
        _, cstar1 = manager.join("alice")
        _, cstar2 = manager.join("bob")
        assert cstar1 != cstar2

    def test_user_count_grows(self, manager):
        assert manager.user_count() == 0
        manager.join("a"); assert manager.user_count() == 1
        manager.join("b"); assert manager.user_count() == 2
        manager.join("c"); assert manager.user_count() == 3

    def test_is_active_unknown_user_is_false(self, manager):
        assert manager.is_active(999) is False

    def test_many_joins_unique_ids_and_cstars(self, manager):
        results = [manager.join(f"user_{i}") for i in range(50)]
        ids   = [r[0] for r in results]
        stars = [r[1] for r in results]
        assert len(set(ids))   == 50
        assert len(set(stars)) == 50

    # ================================================================
    #                   ResponseM (cert issuance)
    # ================================================================

    def test_response_m_returns_certs(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        certs = manager.response_m(user_id, cstar, [wots_keypair])
        assert len(certs) == 1

    def test_response_m_cert_structure(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        certs = manager.response_m(user_id, cstar, [wots_keypair])
        zeta, pi, sigma_s = certs[0]
        assert len(zeta) == 16  # AES-128 block
        assert len(pi)   == N
        assert isinstance(sigma_s, bytes)
        assert len(sigma_s) > 0

    def test_response_m_batch(self, manager, joined_user):
        user_id, cstar = joined_user
        pks = [os.urandom(N) for _ in range(5)]
        certs = manager.response_m(user_id, cstar, pks)
        assert len(certs) == 5

    def test_response_m_large_batch(self, manager, joined_user):
        user_id, cstar = joined_user
        pks = [os.urandom(N) for _ in range(50)]
        certs = manager.response_m(user_id, cstar, pks)
        assert len(certs) == 50
        assert manager.statesM[user_id].state.ctr == 50

    def test_response_m_increments_ctr(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair, wots_keypair])
        assert manager.statesM[user_id].state.ctr == 2

    def test_response_m_ctr_persists_across_calls(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair])
        manager.response_m(user_id, cstar, [wots_keypair, wots_keypair])
        manager.response_m(user_id, cstar, [wots_keypair])
        assert manager.statesM[user_id].state.ctr == 4

    def test_response_m_zeta_uniqueness_within_batch(self, manager, joined_user):
        user_id, cstar = joined_user
        pks = [os.urandom(N) for _ in range(10)]
        certs = manager.response_m(user_id, cstar, pks)
        zetas = [c[0] for c in certs]
        assert len(set(zetas)) == len(zetas)

    def test_response_m_zeta_uniqueness_across_batches(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        c1 = manager.response_m(user_id, cstar, [wots_keypair])
        c2 = manager.response_m(user_id, cstar, [wots_keypair])
        assert c1[0][0] != c2[0][0]

    def test_response_m_zeta_uniqueness_across_users(self, manager, wots_keypair):
        id1, c1 = manager.join("alice")
        id2, c2 = manager.join("bob")
        cert1 = manager.response_m(id1, c1, [wots_keypair])[0]
        cert2 = manager.response_m(id2, c2, [wots_keypair])[0]
        assert cert1[0] != cert2[0]

    def test_response_m_pi_depends_on_pk(self, manager, joined_user):
        """Different public keys → different pi values."""
        user_id, cstar = joined_user
        pk_a = os.urandom(N)
        pk_b = os.urandom(N)
        certs = manager.response_m(user_id, cstar, [pk_a, pk_b])
        assert certs[0][1] != certs[1][1]

    def test_response_m_pi_deterministic_for_same_pk(self, manager):
        """Same pk for same user → same pi (since cid is fixed per user)."""
        id1, c1 = manager.join("alice")
        pk = os.urandom(N)
        cert_a = manager.response_m(id1, c1, [pk])[0]
        cert_b = manager.response_m(id1, c1, [pk])[0]
        # zeta differs (j increments) but pi only depends on pk + cid
        assert cert_a[1] == cert_b[1]

    def test_response_m_bad_cstar_rejected(self, manager, joined_user, wots_keypair):
        user_id, _ = joined_user
        bad = os.urandom(N)
        with pytest.raises(PermissionError):
            manager.response_m(user_id, bad, [wots_keypair])

    def test_response_m_cstar_from_other_user_rejected(self, manager, wots_keypair):
        """Alice's cstar shouldn't authenticate Bob."""
        _, cstar_a = manager.join("alice")
        id_b, _    = manager.join("bob")
        with pytest.raises(PermissionError):
            manager.response_m(id_b, cstar_a, [wots_keypair])

    def test_response_m_unknown_user_rejected(self, manager, wots_keypair):
        with pytest.raises(KeyError):
            manager.response_m(999, os.urandom(N), [wots_keypair])

    def test_response_m_revoked_user_rejected(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.revoke([user_id])
        with pytest.raises(PermissionError):
            manager.response_m(user_id, cstar, [wots_keypair])

    def test_response_m_before_keygen_raises(self, wots_keypair):
        m = Manager(PARAMS)
        with pytest.raises(RuntimeError):
            m.response_m(1, os.urandom(N), [wots_keypair])

    def test_response_m_does_not_increment_ctr_on_failure(self, manager, joined_user, wots_keypair):
        user_id, _ = joined_user
        ctr_before = manager.statesM[user_id].state.ctr
        with pytest.raises(PermissionError):
            manager.response_m(user_id, os.urandom(N), [wots_keypair])
        assert manager.statesM[user_id].state.ctr == ctr_before

    # ================================================================
#                               Revoke
    # ================================================================

    def test_revoke_marks_inactive(self, manager, joined_user):
        user_id, _ = joined_user
        manager.revoke([user_id])
        assert not manager.is_active(user_id)

    def test_revoke_adds_zetas_to_RL(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair, wots_keypair])
        rl = manager.revoke([user_id])
        assert len(rl) == 2

    def test_revoke_RL_contains_correct_zetas(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        certs = manager.response_m(user_id, cstar, [wots_keypair, wots_keypair])
        expected_zetas = {c[0] for c in certs}
        manager.revoke([user_id])
        assert expected_zetas.issubset(set(manager.RL))

    def test_revoke_no_certs_yields_empty_addition(self, manager, joined_user):
        user_id, _ = joined_user
        rl_before = list(manager.RL)
        manager.revoke([user_id])
        assert manager.RL == rl_before

    def test_revoke_idempotent(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair])
        rl1 = manager.revoke([user_id])
        rl2 = manager.revoke([user_id])
        assert rl1 == rl2

    def test_revoke_unknown_user_skipped(self, manager):
        rl = manager.revoke([999])
        assert rl == []

    def test_revoke_mixed_known_unknown(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair])
        rl = manager.revoke([user_id, 999, 1000])
        assert len(rl) == 1
        assert not manager.is_active(user_id)

    def test_revoke_empty_list_noop(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair])
        rl_before = list(manager.RL)
        rl = manager.revoke([])
        assert rl == rl_before
        assert manager.is_active(user_id)

    def test_revoke_multiple_users(self, manager):
        id1, c1 = manager.join("alice")
        id2, c2 = manager.join("bob")
        manager.response_m(id1, c1, [os.urandom(N)])
        manager.response_m(id2, c2, [os.urandom(N)])
        rl = manager.revoke([id1, id2])
        assert len(rl) == 2
        assert not manager.is_active(id1)
        assert not manager.is_active(id2)

    def test_revoke_does_not_affect_other_users(self, manager, wots_keypair):
        id1, c1 = manager.join("alice")
        id2, c2 = manager.join("bob")
        manager.response_m(id1, c1, [wots_keypair])
        manager.response_m(id2, c2, [wots_keypair])
        manager.revoke([id1])
        assert not manager.is_active(id1)
        assert manager.is_active(id2)
        # bob can still get certs
        manager.response_m(id2, c2, [wots_keypair])

    def test_revoke_RL_has_no_duplicates(self, manager, joined_user, wots_keypair):
        user_id, cstar = joined_user
        manager.response_m(user_id, cstar, [wots_keypair, wots_keypair])
        manager.revoke([user_id])
        # second revoke shouldn't add anything
        manager.revoke([user_id])
        assert len(manager.RL) == len(set(manager.RL))

    def test_revoke_before_keygen_raises(self):
        m = Manager(PARAMS)
        with pytest.raises(RuntimeError):
            m.revoke([1])

    # ================================================================
#                               Open
    # ================================================================

    def test_open_recovers_signer_id(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        recovered_id, recovered_pi = manager.open(b"hello", sig)
        assert recovered_id == user_id
        assert recovered_pi == pi

    def test_open_distinguishes_signers(self, manager):
        """Each user's signature opens to their own id."""
        id_a, c_a = manager.join("alice")
        id_b, c_b = manager.join("bob")
        sig_a, _, *_ = _build_signature(manager, id_a, c_a, b"msg")
        sig_b, _, *_ = _build_signature(manager, id_b, c_b, b"msg")
        opened_a, _ = manager.open(b"msg", sig_a)
        opened_b, _ = manager.open(b"msg", sig_b)
        assert opened_a == id_a
        assert opened_b == id_b
        assert opened_a != opened_b

    def test_open_invalid_user_id_raises(self, manager, joined_user):
        """Forged zeta decoding to out-of-range id should raise."""
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"msg")
        # replace zeta with garbage that decrypts to id > user_count
        sigma_w, rho, _zeta, sigma_s, tau = sig
        # craft a zeta that decrypts to id=999
        bad_zeta = helpers.sprp_encrypt(manager.msk[1], 999, 1)
        bad_sig = (sigma_w, rho, bad_zeta, sigma_s, tau)
        with pytest.raises(ValueError):
            manager.open(b"msg", bad_sig)

    def test_open_before_keygen_raises(self):
        m = Manager(PARAMS)
        dummy_sig = (b"", b"", b"", b"", b"")
        with pytest.raises(RuntimeError):
            m.open(b"msg", dummy_sig)

    # ================================================================
    #                               Judge
    # ================================================================

    def test_judge_accepts_honest_attribution(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        assert judge(b"hello", sig, user_id, pi, PARAMS) is True

    def test_judge_rejects_wrong_user_id(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        assert judge(b"hello", sig, user_id + 1, pi, PARAMS) is False

    def test_judge_rejects_tampered_message(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        assert judge(b"tampered", sig, user_id, pi, PARAMS) is False

    def test_judge_rejects_wrong_pi(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, _pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        assert judge(b"hello", sig, user_id, os.urandom(N), PARAMS) is False

    def test_judge_rejects_tampered_tau(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        sigma_w, rho, zeta, sigma_s, tau = sig
        bad_tau = bytes([tau[0] ^ 0xFF]) + tau[1:]
        bad_sig = (sigma_w, rho, zeta, sigma_s, bad_tau)
        assert judge(b"hello", bad_sig, user_id, pi, PARAMS) is False

    def test_judge_rejects_tampered_rho(self, manager, joined_user):
        """Different rho → different M → different reconstructed pk → tau mismatch."""
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        sigma_w, rho, zeta, sigma_s, tau = sig
        bad_rho = bytes([rho[0] ^ 0x01]) + rho[1:]
        bad_sig = (sigma_w, bad_rho, zeta, sigma_s, tau)
        assert judge(b"hello", bad_sig, user_id, pi, PARAMS) is False

    def test_judge_rejects_tampered_sigma_w(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        sigma_w, rho, zeta, sigma_s, tau = sig
        bad_w = bytes([sigma_w[0] ^ 0xFF]) + sigma_w[1:]
        bad_sig = (bad_w, rho, zeta, sigma_s, tau)
        assert judge(b"hello", bad_sig, user_id, pi, PARAMS) is False

    def test_judge_consistent_across_calls(self, manager, joined_user):
        """Judge is a pure function — same inputs, same output."""
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"hello")
        results = [judge(b"hello", sig, user_id, pi, PARAMS) for _ in range(5)]
        assert all(r is True for r in results)

    # ================================================================
    #                   Open + Judge integration
    # ================================================================

    def test_open_then_judge_round_trip(self, manager, joined_user):
        user_id, cstar = joined_user
        sig, _pi, *_ = _build_signature(manager, user_id, cstar, b"round trip")
        opened_id, opened_pi = manager.open(b"round trip", sig)
        assert judge(b"round trip", sig, opened_id, opened_pi, PARAMS) is True

    def test_open_then_judge_multiple_users(self, manager):
        """Round-trip works for many distinct users."""
        for i in range(5):
            uid, cstar = manager.join(f"user_{i}")
            sig, _, *_ = _build_signature(manager, uid, cstar, f"msg_{i}".encode())
            oid, opi = manager.open(f"msg_{i}".encode(), sig)
            assert oid == uid
            assert judge(f"msg_{i}".encode(), sig, oid, opi, PARAMS) is True

    def test_open_then_judge_after_many_certs(self, manager, joined_user):
        """Round-trip survives high cert counters."""
        user_id, cstar = joined_user
        # Issue 20 certs first to advance ctr
        manager.response_m(user_id, cstar, [os.urandom(N) for _ in range(20)])
        sig, _, *_ = _build_signature(manager, user_id, cstar, b"late msg")
        oid, opi = manager.open(b"late msg", sig)
        assert oid == user_id
        assert judge(b"late msg", sig, oid, opi, PARAMS) is True

    # ================================================================
    #                   End-to-end protocol scenarios
    # ================================================================

    def test_e2e_full_lifecycle(self, manager):
        """Join → certs → sign → open → judge → revoke."""
        uid, cstar = manager.join("alice")
        manager.response_m(uid, cstar, [os.urandom(N) for _ in range(3)])
        sig, _, *_ = _build_signature(manager, uid, cstar, b"e2e")
        oid, opi = manager.open(b"e2e", sig)
        assert oid == uid
        assert judge(b"e2e", sig, oid, opi, PARAMS)
        manager.revoke([uid])
        assert not manager.is_active(uid)

    def test_e2e_revoked_user_cannot_get_new_certs(self, manager, joined_user, wots_keypair):
        uid, cstar = joined_user
        manager.response_m(uid, cstar, [wots_keypair])
        manager.revoke([uid])
        with pytest.raises(PermissionError):
            manager.response_m(uid, cstar, [wots_keypair])

    def test_e2e_multiple_users_independent(self, manager):
        """Operations on one user don't disturb another."""
        ids_cstars = [manager.join(f"u{i}") for i in range(3)]
        # Each gets some certs
        for uid, cstar in ids_cstars:
            manager.response_m(uid, cstar, [os.urandom(N), os.urandom(N)])
        # Revoke middle user
        manager.revoke([ids_cstars[1][0]])
        # First and third still active and functional
        for i in (0, 2):
            uid, cstar = ids_cstars[i]
            assert manager.is_active(uid)
            manager.response_m(uid, cstar, [os.urandom(N)])
        # Middle user blocked
        uid_mid, cstar_mid = ids_cstars[1]
        with pytest.raises(PermissionError):
            manager.response_m(uid_mid, cstar_mid, [os.urandom(N)])

    # =============================================================================
    #                               TestUpdateState 
    # =============================================================================

    def _fake_certs(self, start_j: int, count: int):
        return [
            Certificate(j=start_j + i, zeta=os.urandom(16),
                        pi=os.urandom(N), sigma_s=os.urandom(32))
            for i in range(count)
        ]

    def test_increments_both_counters_by_batch_size(self, fresh_member):
        fresh_member.updateState(self._fake_certs(1, 5))
        assert fresh_member.state.ctr_u == 5
        assert fresh_member.state.ctr_m == 5

    def test_adds_certs_to_cert_list(self, fresh_member):
        certs = self._fake_certs(1, 3)
        fresh_member.updateState(certs)
        for c in certs:
            assert fresh_member.state.CertList[c.j] is c

    def test_preserves_existing_certs(self, fresh_member):
        fresh_member.updateState(self._fake_certs(1, 2))
        fresh_member.updateState(self._fake_certs(3, 2))
        assert set(fresh_member.state.CertList.keys()) == {1, 2, 3, 4}
        assert fresh_member.state.ctr_u == 4
        assert fresh_member.state.ctr_m == 4

    def test_empty_batch_is_noop(self, fresh_member):
        fresh_member.updateState([])
        assert fresh_member.state.ctr_u == 0
        assert fresh_member.state.ctr_m == 0
        assert fresh_member.state.CertList == {}

    def test_does_not_touch_R(self, fresh_member):
        """Per Algorithm 3, UpdateU updates only counters and C, not R."""
        fresh_member.state.R[1] = b"existing_rid"
        fresh_member.updateState(self._fake_certs(1, 2))
        assert fresh_member.state.R == {1: b"existing_rid"}

    def test_before_join_raises(self):
        m = Member(PARAMS, "unused", 0)
        with pytest.raises((RuntimeError, AttributeError)):
            m.updateState([])

# =============================================================================
#                                   TestSign
# =============================================================================

class TestSign:

    def test_returns_five_tuple(self, manager):
        m = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"hello")
        assert isinstance(sig, tuple) and len(sig) == 5
        for part in sig:
            assert isinstance(part, bytes)

    def test_consumes_one_certificate(self, manager):
        m = _make_member(manager, "alice", n_certs=3)
        assert m.state.ctr_u == 3
        m.sign(b"msg")
        assert m.state.ctr_u == 2
        assert len(m.state.CertList) == 2
        assert len(m.state.R) == 2

    def test_forward_anonymity_deletes_rid(self, manager):
        """After signing, the rid used must be gone from state.R."""
        m = _make_member(manager, "alice", n_certs=1)
        used_j = next(iter(m.state.CertList))
        m.sign(b"msg")
        assert used_j not in m.state.R
        assert used_j not in m.state.CertList

    def test_without_certs_raises(self, manager):
        m = _make_member(manager, "alice", n_certs=0)
        with pytest.raises(RuntimeError):
            m.sign(b"msg")

    def test_exhausts_all_certs(self, manager):
        m = _make_member(manager, "alice", n_certs=3)
        for _ in range(3):
            m.sign(b"msg")
        assert m.state.ctr_u == 0
        with pytest.raises(RuntimeError):
            m.sign(b"one more")

    def test_ctr_m_unchanged_by_sign(self, manager):
        """ctr_m tracks manager-issued certs; sign() shouldn't touch it."""
        m = _make_member(manager, "alice", n_certs=2)
        ctr_m_before = m.state.ctr_m
        m.sign(b"msg")
        assert m.state.ctr_m == ctr_m_before

    def test_successive_signatures_differ(self, manager):
        """Two signatures use different certs → resulting sigs differ."""
        m = _make_member(manager, "alice", n_certs=2)
        sig1 = m.sign(b"msg")
        sig2 = m.sign(b"msg")
        assert sig1[2] != sig2[2]

    def test_tau_has_correct_structure(self, manager):
        """τ = H(pk ‖ π ‖ id) — check by re-deriving and comparing."""
        m = _make_member(manager, "alice", n_certs=1)
        uid = m.state.id
        j     = next(iter(m.state.CertList))
        cert  = m.state.CertList[j]
        rid_j = m.state.R[j]

        rho_j   = helpers.H_simple(rid_j, N)
        sk_seed = helpers.H_simple(m.state.seed + rid_j, N)
        pk_j    = m.wots.wots_PKgen(sk_seed, rho_j, ADRS())
        expected_tau = helpers.H_simple(
            pk_j + cert.pi + helpers._encode_id(uid), N
        )

        sig = m.sign(b"msg")
        _, _, _, _, tau = sig
        assert tau == expected_tau


    # =============================================================================
    #                            TestVerify
    # =============================================================================

    def test_accepts_honest_signature(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"hello")
        assert verify(b"hello", sig, m.pk_bytes, manager.RL, PARAMS) is True

    def test_rejects_tampered_message(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"hello")
        assert verify(b"tampered", sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_revoked_signature(self, manager):
        """The whole point of RL distribution — revoked sigs fail verify."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"hello")
        # pre-revocation: valid
        assert verify(b"hello", sig, m.pk_bytes, manager.RL, PARAMS) is True
        # post-revocation: invalid
        manager.revoke([m.state.id])
        assert verify(b"hello", sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_tampered_sigma_w(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        sw, rho, zeta, ss, tau = sig
        bad_sw  = bytes([sw[0] ^ 0xFF]) + sw[1:]
        bad_sig = (bad_sw, rho, zeta, ss, tau)
        assert verify(b"msg", bad_sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_tampered_rho(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        sw, rho, zeta, ss, tau = sig
        bad_rho = bytes([rho[0] ^ 0x01]) + rho[1:]
        bad_sig = (sw, bad_rho, zeta, ss, tau)
        assert verify(b"msg", bad_sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_tampered_zeta(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        sw, rho, zeta, ss, tau = sig
        bad_zeta = bytes([zeta[0] ^ 0xFF]) + zeta[1:]
        bad_sig  = (sw, rho, bad_zeta, ss, tau)
        # SPHINCS+ verification will fail because σ^S was over the *real* zeta
        assert verify(b"msg", bad_sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_tampered_sigma_s(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        sw, rho, zeta, ss, tau = sig
        bad_ss  = bytes([ss[0] ^ 0xFF]) + ss[1:]
        bad_sig = (sw, rho, zeta, bad_ss, tau)
        assert verify(b"msg", bad_sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_tampered_tau(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        sw, rho, zeta, ss, tau = sig
        bad_tau = bytes([tau[0] ^ 0xFF]) + tau[1:]
        bad_sig = (sw, rho, zeta, ss, bad_tau)
        assert verify(b"msg", bad_sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_garbage_signature(self, manager):
        m = _make_member(manager, "alice", n_certs=0)
        garbage = (os.urandom(64), os.urandom(N),
                   os.urandom(16), os.urandom(64), os.urandom(N))
        assert verify(b"msg", garbage, m.pk_bytes, manager.RL, PARAMS) is False

    def test_rejects_wrong_pk(self, manager):
        """Signature verified against the wrong group public key must fail."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        # fresh manager → fresh PK, unrelated to sig
        other = Manager(PARAMS); other.keygen()
        assert verify(b"msg", sig, other._serialise_pk(),
                      other.RL, PARAMS) is False

    def test_uses_no_secrets(self, manager):
        """verify() is callable with just DGSP.PP — no msk, no SK."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        # We pass only pk_bytes and RL, which are public
        assert verify(b"msg", sig, m.pk_bytes, list(manager.RL), PARAMS) is True

    def test_rl_is_queried_not_captured(self, manager):
        """verify(..., RL, ...) should reflect the RL passed *at call time*."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        snapshot_rl_empty = list(manager.RL)  # empty
        manager.revoke([m.state.id])
        # Old RL snapshot still says "not revoked"
        assert verify(b"msg", sig, m.pk_bytes, snapshot_rl_empty, PARAMS) is True
        # Fresh RL says "revoked"
        assert verify(b"msg", sig, m.pk_bytes, manager.RL, PARAMS) is False

    def test_deterministic(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"msg")
        results = [verify(b"msg", sig, m.pk_bytes, manager.RL, PARAMS)
                   for _ in range(5)]
        assert all(results)

    # =============================================================================
    #                   Test Sign -> Verify -> Open -> Judge
    # =============================================================================

    def test_sign_verify_round_trip(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"round trip")
        assert verify(b"round trip", sig, m.pk_bytes, manager.RL, PARAMS)

    def test_sign_open_judge_round_trip(self, manager):
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"trace me")
        uid, pi = manager.open(b"trace me", sig)
        assert uid == m.state.id
        assert judge(b"trace me", sig, uid, pi, PARAMS) is True

    def test_all_four_algorithms_agree(self, manager):
        """Sign → Verify → Open → Judge on the same signature."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"everybody")
        assert verify(b"everybody", sig, m.pk_bytes, manager.RL, PARAMS)
        uid, pi = manager.open(b"everybody", sig)
        assert uid == m.state.id
        assert judge(b"everybody", sig, uid, pi, PARAMS)

    def test_two_users_sign_same_message_distinguishable_by_open(self, manager):
        a = _make_member(manager, "alice", n_certs=1)
        b = _make_member(manager, "bob",   n_certs=1)
        sig_a = a.sign(b"same text")
        sig_b = b.sign(b"same text")
        # Both verify
        assert verify(b"same text", sig_a, a.pk_bytes, manager.RL, PARAMS)
        assert verify(b"same text", sig_b, b.pk_bytes, manager.RL, PARAMS)
        # But open distinguishes them
        uid_a, _ = manager.open(b"same text", sig_a)
        uid_b, _ = manager.open(b"same text", sig_b)
        assert uid_a == a.state.id
        assert uid_b == b.state.id
        assert uid_a != uid_b

    def test_signature_survives_other_users_joining(self, manager):
        """Enrolling new users after signing must not affect verification."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"still valid")
        # More users show up later
        for i in range(5):
            manager.join(f"latecomer_{i}")
        assert verify(b"still valid", sig, m.pk_bytes, manager.RL, PARAMS)

    def test_revoked_user_past_signatures_invalidated(self, manager):
        """Once revoked, every past signature from that user fails verify."""
        m = _make_member(manager, "alice", n_certs=3)
        sigs = [m.sign(f"msg_{i}".encode()) for i in range(3)]
        for i, sig in enumerate(sigs):
            assert verify(f"msg_{i}".encode(), sig,
                          m.pk_bytes, manager.RL, PARAMS) is True
        manager.revoke([m.state.id])
        for i, sig in enumerate(sigs):
            assert verify(f"msg_{i}".encode(), sig,
                          m.pk_bytes, manager.RL, PARAMS) is False

    def test_revoking_one_user_does_not_affect_another(self, manager):
        a = _make_member(manager, "alice", n_certs=1)
        b = _make_member(manager, "bob",   n_certs=1)
        sig_a = a.sign(b"alice's msg")
        sig_b = b.sign(b"bob's msg")
        manager.revoke([a.state.id])
        assert verify(b"alice's msg", sig_a, a.pk_bytes, manager.RL, PARAMS) is False
        assert verify(b"bob's msg",   sig_b, b.pk_bytes, manager.RL, PARAMS) is True

    def test_open_still_works_after_revoke(self, manager):
        """Attribution must survive revocation (already tested, but with real sign())."""
        m   = _make_member(manager, "alice", n_certs=1)
        sig = m.sign(b"attributable")
        manager.revoke([m.state.id])
        uid, pi = manager.open(b"attributable", sig)
        assert uid == m.state.id
        assert judge(b"attributable", sig, uid, pi, PARAMS) is True

    def test_many_signatures_all_round_trip(self, manager):
        m = _make_member(manager, "alice", n_certs=10)
        for i in range(10):
            msg = f"signature_{i}".encode()
            sig = m.sign(msg)
            assert verify(msg, sig, m.pk_bytes, manager.RL, PARAMS)
            uid, pi = manager.open(msg, sig)
            assert uid == m.state.id
            assert judge(msg, sig, uid, pi, PARAMS)


# ================================================================
# WOTS+C Tests
# ================================================================

class TestWOTSPlusC:
 
    # check target sum formula is correct
    def test_target_sum_is_correct(self):
        result = compute_target_sum(PARAMS.len1, W)
        assert result == (PARAMS.len1 * (W - 1)) // 2
 
    # check conditions passes when sum matches and leading digits are zero
    def test_check_conditions_passes_valid(self):
        target = compute_target_sum(PARAMS.len1, W)
        digits = [0] * PARAMS.len1
        digits[-1] = target
        assert check_conditions(digits, target, z=0) is True
 
    # check conditions fails when sum is wrong
    def test_check_conditions_fails_wrong_sum(self):
        target = compute_target_sum(PARAMS.len1, W)
        digits = [1] * PARAMS.len1
        assert check_conditions(digits, target, z=0) is False
 
    # check conditions fails when leading digit is nonzero with z=1
    def test_check_conditions_fails_nonzero_leading(self):
        target = compute_target_sum(PARAMS.len1, W)
        digits = [0] * PARAMS.len1
        digits[0] = 1
        digits[-1] = target - 1
        assert check_conditions(digits, target, z=1) is False
 
    # pkgen returns n bytes
    def test_pkgen_returns_n_bytes(self, wots_c, sk_seed, pk_seed):
        pk = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        assert isinstance(pk, bytes)
        assert len(pk) == N
 
    # same inputs always give same pk
    def test_pkgen_deterministic(self, wots_c, sk_seed, pk_seed):
        pk1 = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        pk2 = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        assert pk1 == pk2
 
    # different sk seeds produce different keys
    def test_pkgen_differs_for_different_sk(self, wots_c, pk_seed):
        pk1 = wots_c.wots_PKgen(os.urandom(N), pk_seed, ADRS())
        pk2 = wots_c.wots_PKgen(os.urandom(N), pk_seed, ADRS())
        assert pk1 != pk2
 
    # sign returns a list and a counter
    def test_sign_returns_correct_types(self, wots_c, message, sk_seed, pk_seed):
        sig, counter = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert isinstance(sig, list)
        assert isinstance(counter, int)
 
    # sign returns ell elements, not len
    def test_sign_returns_ell_elements(self, wots_c, message, sk_seed, pk_seed):
        sig, _ = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert len(sig) == wots_c.ell
        assert len(sig) < PARAMS.len
 
    # each signature element is n bytes
    def test_sign_elements_are_n_bytes(self, wots_c, message, sk_seed, pk_seed):
        sig, _ = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        for elem in sig:
            assert len(elem) == N
 
    # same inputs always give same signature and counter
    def test_sign_deterministic(self, wots_c, message, sk_seed, pk_seed):
        sig1, counter1 = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        sig2, counter2 = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert sig1 == sig2
        assert counter1 == counter2
 
    # z=1 produces one fewer element than z=0
    def test_sign_z1_has_fewer_elements(self, wots_c, wots_c_z1, message, sk_seed, pk_seed):
        sig0, _ = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        sig1, _ = wots_c_z1.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert len(sig1) == len(sig0) - 1
 
    # core correctness test, recovered pk must match generated pk
    def test_pkfromsig_matches_pkgen(self, wots_c, message, sk_seed, pk_seed):
        pk = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig, counter = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_c.wots_pkFromSig(sig, message, counter, pk_seed, ADRS())
        assert recovered == pk
 
    # same correctness check for z=1
    def test_pkfromsig_matches_pkgen_z1(self, wots_c_z1, message, sk_seed, pk_seed):
        pk = wots_c_z1.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig, counter = wots_c_z1.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_c_z1.wots_pkFromSig(sig, message, counter, pk_seed, ADRS())
        assert recovered == pk
 
    # wrong message should not recover the correct pk
    def test_pkfromsig_fails_on_wrong_message(self, wots_c, message, sk_seed, pk_seed):
        pk = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig, counter = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_c.wots_pkFromSig(sig, os.urandom(N), counter, pk_seed, ADRS())
        assert recovered != pk
 
    # wrong counter should not recover the correct pk
    def test_pkfromsig_fails_on_wrong_counter(self, wots_c, message, sk_seed, pk_seed):
        pk = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig, counter = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_c.wots_pkFromSig(sig, message, counter + 1, pk_seed, ADRS())
        assert recovered != pk
 
    # tampered signature should not recover the correct pk
    def test_pkfromsig_fails_on_tampered_sig(self, wots_c, message, sk_seed, pk_seed):
        pk = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig, counter = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        tampered = [bytes([b ^ 0xFF for b in sig[0]])] + sig[1:]
        recovered = wots_c.wots_pkFromSig(tampered, message, counter, pk_seed, ADRS())
        assert recovered != pk
 
    # check correctness across several random messages
    def test_pkfromsig_multiple_messages(self, wots_c, sk_seed, pk_seed):
        pk = wots_c.wots_PKgen(sk_seed, pk_seed, ADRS())
        for _ in range(5):
            msg = os.urandom(N)
            sig, counter = wots_c.wots_sign(msg, sk_seed, pk_seed, ADRS())
            recovered = wots_c.wots_pkFromSig(sig, msg, counter, pk_seed, ADRS())
            assert recovered == pk
 
    # sig_bytes should match actual signature size
    def test_sig_bytes_matches_actual_sig(self, wots_c, message, sk_seed, pk_seed):
        sig, _ = wots_c.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert wots_c.sig_bytes() == len(sig) * N + 4
 
    # wots+c signature should be smaller than standard wots+
    def test_sig_bytes_smaller_than_standard(self):
        wc = WOTSPlusC(PARAMS, z=0)
        assert wc.sig_bytes() < PARAMS.len * N
        
# ================================================================
# FORS+C Tests
# ================================================================

class TestFORSC:
 
    # invalid parameter tests
    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            FORS_C(0, K, T, T, make_fors_adrs())
 
    def test_invalid_k_raises(self):
        with pytest.raises(ValueError):
            FORS_C(N, 0, T, T, make_fors_adrs())
 
    def test_k_less_than_2_raises(self):
        with pytest.raises(ValueError):
            FORS_C(N, 1, T, T, make_fors_adrs())
 
    def test_t_not_power_of_2_raises(self):
        with pytest.raises(ValueError):
            FORS_C(N, K, 7, T, make_fors_adrs())
 
    def test_t_prime_not_power_of_2_raises(self):
        with pytest.raises(ValueError):
            FORS_C(N, K, T, 7, make_fors_adrs())
 
    # pkgen tests
    def test_pkgen_returns_n_bytes(self, fors_c, sk_seed, pk_seed):
        pk = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        assert isinstance(pk, bytes)
        assert len(pk) == N
 
    def test_pkgen_deterministic(self, fors_c, sk_seed, pk_seed):
        pk1 = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        pk2 = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        assert pk1 == pk2
 
    def test_pkgen_differs_for_different_seeds(self, fors_c, pk_seed):
        pk1 = fors_c.fors_PKgen(os.urandom(N), pk_seed, make_fors_adrs())
        pk2 = fors_c.fors_PKgen(os.urandom(N), pk_seed, make_fors_adrs())
        assert pk1 != pk2
 
    # sign tests
    def test_sign_returns_correct_types(self, fors_c, fors_c_message, sk_seed, pk_seed):
        sig, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        assert isinstance(sig, FORS_sig)
        assert isinstance(counter, int)
 
    def test_sign_counter_is_non_negative(self, fors_c, fors_c_message, sk_seed, pk_seed):
        _, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        assert counter >= 0
 
    def test_sign_deterministic(self, fors_c, fors_c_message, sk_seed, pk_seed):
        sig1, counter1 = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        sig2, counter2 = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        assert counter1 == counter2
        for i in range(K):
            assert sig1.get_sk(i) == sig2.get_sk(i)
 
    def test_sign_sk_elements_are_n_bytes(self, fors_c, fors_c_message, sk_seed, pk_seed):
        sig, _ = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        for i in range(K):
            assert len(sig.get_sk(i)) == N
 
    def test_sign_last_tree_has_no_auth_path(self, fors_c, fors_c_message, sk_seed, pk_seed):
        # auth path for last tree is dropped, replaced by counter
        sig, _ = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        assert sig.get_auth(K - 1) == []

    def test_sign_stores_last_root(self, fors_c, fors_c_message, sk_seed, pk_seed):
        # last_root must be stored in the signature for public verification
        sig, _ = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        assert sig.get_last_root() is not None
        assert len(sig.get_last_root()) == N

    # pkfromsig tests
    def test_pkfromsig_returns_n_bytes(self, fors_c, fors_c_message, sk_seed, pk_seed):
        sig, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        pk = fors_c.fors_pkFromSig(sig, fors_c_message, counter, pk_seed, make_fors_adrs())
        assert isinstance(pk, bytes)
        assert len(pk) == N
 
    def test_pkfromsig_matches_pkgen(self, fors_c, fors_c_message, sk_seed, pk_seed):
        # core correctness test
        pk = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        sig, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        recovered = fors_c.fors_pkFromSig(sig, fors_c_message, counter, pk_seed, make_fors_adrs())
        assert recovered == pk
 
    def test_pkfromsig_fails_on_wrong_message(self, fors_c, fors_c_message, sk_seed, pk_seed):
        pk = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        sig, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        wrong_msg = os.urandom(len(fors_c_message))
        recovered = fors_c.fors_pkFromSig(sig, wrong_msg, counter, pk_seed, make_fors_adrs())
        assert recovered != pk
 
    def test_pkfromsig_fails_on_invalid_counter(self, fors_c, fors_c_message, sk_seed, pk_seed):
        pk = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        sig, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        bad_counter = counter + 1
        while True:
            digest = fors_c._hash_with_counter(fors_c_message, bad_counter, pk_seed, make_fors_adrs())
            last_idx = int.from_bytes(digest, "big") & ((1 << fors_c.a_prime) - 1)
            if last_idx != 0:
                break
            bad_counter += 1
        recovered = fors_c.fors_pkFromSig(sig, fors_c_message, bad_counter, pk_seed, make_fors_adrs())
        assert recovered != pk
 
    def test_pkfromsig_fails_on_tampered_sig(self, fors_c, fors_c_message, sk_seed, pk_seed):
        pk = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        sig, counter = fors_c.fors_sign(fors_c_message, sk_seed, pk_seed, make_fors_adrs())
        tampered_sk = [bytes([b ^ 0xFF for b in sig.get_sk(0)])] + [sig.get_sk(i) for i in range(1, K)]
        # preserve last_root so the test isolates sk tampering, not a missing root
        tampered = FORS_sig(tampered_sk, [sig.get_auth(i) for i in range(K)], sig.get_last_root())
        recovered = fors_c.fors_pkFromSig(tampered, fors_c_message, counter, pk_seed, make_fors_adrs())
        assert recovered != pk
 
    def test_pkfromsig_multiple_messages(self, fors_c, sk_seed, pk_seed):
        pk = fors_c.fors_PKgen(sk_seed, pk_seed, make_fors_adrs())
        msg_bytes = (K * fors_c.a + 7) // 8
        for _ in range(5):
            msg = os.urandom(msg_bytes)
            sig, counter = fors_c.fors_sign(msg, sk_seed, pk_seed, make_fors_adrs())
            recovered = fors_c.fors_pkFromSig(sig, msg, counter, pk_seed, make_fors_adrs())
            assert recovered == pk
 
    def test_sig_bytes_smaller_than_standard_fors(self, fors_c):
        # dropping last tree auth path saves a_prime * n bytes, counter costs only 4
        # storing last root costs n bytes, so net saving is (a_prime - 1) * n - 4
        standard_sig_bytes = K * N * (1 + fors_c.a)
        assert fors_c.sig_bytes() < standard_sig_bytes

# ================================================================
# SphincsC imports and fixtures
# ================================================================

from params.sphincs_params_Plus_C import SphincsParamsC
from sphincs.sphincs_Plus_C import SphincsC, SK as SKC, PK as PKC, xmss_sig_c, XMSS_C, HypertreeC

# small parameters to keep tests fast
PARAMS_C = SphincsParamsC(n=N, w=W, h=H, d=D, k=K, t=T, t_prime=T, z=0)
PARAMS_C_Z1 = SphincsParamsC(n=N, w=W, h=H, d=D, k=K, t=T, t_prime=T, z=1)


# ================================================================
# xmss_sig_c Tests
# ================================================================

class TestXMSSSigC:

    def test_stores_counter(self):
        sig = xmss_sig_c([b"\x00" * N], [b"\x00" * N], 42)
        assert sig.get_counter() == 42

    def test_to_bytes_prepends_counter(self):
        sig = xmss_sig_c([b"\xab" * N], [b"\xcd" * N], 7)
        raw = sig.to_bytes()
        assert raw[:4] == (7).to_bytes(4, "big")

    def test_from_bytes_roundtrip(self):
        sig = xmss_sig_c([b"\xab" * N] * 2, [b"\xcd" * N] * 3, 99)
        raw = sig.to_bytes()
        recovered = xmss_sig_c.from_bytes(raw, 3, N, 2)
        assert recovered.get_counter() == 99
        assert recovered.get_sig() == sig.get_sig()
        assert recovered.get_auth() == sig.get_auth()


# ================================================================
# XMSS_C Tests
# ================================================================

class TestXMSSC:

    @pytest.fixture
    def wots_c_inst(self):
        return WOTSPlusC(PARAMS_C, z=0)

    @pytest.fixture
    def xmss_c(self, wots_c_inst):
        return XMSS_C(H, N, D, wots_c_inst, ADRS())

    # pkgen returns n bytes
    def test_pkgen_returns_n_bytes(self, xmss_c, sk_seed, pk_seed):
        pk = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        assert isinstance(pk, bytes)
        assert len(pk) == N

    # same inputs always give same pk
    def test_pkgen_deterministic(self, xmss_c, sk_seed, pk_seed):
        pk1 = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        pk2 = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        assert pk1 == pk2

    # different sk seeds produce different keys
    def test_pkgen_differs_for_different_sk(self, xmss_c, pk_seed):
        pk1 = xmss_c.xmss_PKgen(os.urandom(N), pk_seed, ADRS())
        pk2 = xmss_c.xmss_PKgen(os.urandom(N), pk_seed, ADRS())
        assert pk1 != pk2

    # sign returns an xmss_sig_c
    def test_sign_returns_xmss_sig_c(self, xmss_c, message, sk_seed, pk_seed):
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        assert isinstance(sig, xmss_sig_c)

    # counter is stored in the sig
    def test_sign_counter_is_non_negative(self, xmss_c, message, sk_seed, pk_seed):
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        assert sig.get_counter() >= 0

    # auth nodes are n bytes each
    def test_sign_auth_nodes_are_n_bytes(self, xmss_c, message, sk_seed, pk_seed):
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        for node in sig.get_auth():
            assert len(node) == N

    # same inputs always give same sig and counter
    def test_sign_deterministic(self, xmss_c, message, sk_seed, pk_seed):
        sig1 = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        sig2 = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        assert sig1.get_sig() == sig2.get_sig()
        assert sig1.get_auth() == sig2.get_auth()
        assert sig1.get_counter() == sig2.get_counter()

    # core correctness: recovered root must match pkgen output
    def test_pkfromsig_matches_pkgen(self, xmss_c, message, sk_seed, pk_seed):
        pk = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        recovered = xmss_c.xmss_pkFromSig(0, sig, message, pk_seed, ADRS())
        assert recovered == pk

    # wrong message should not recover the correct root
    def test_pkfromsig_fails_on_wrong_message(self, xmss_c, message, sk_seed, pk_seed):
        pk = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        recovered = xmss_c.xmss_pkFromSig(0, sig, os.urandom(N), pk_seed, ADRS())
        assert recovered != pk

    # wrong index should not recover the correct root
    def test_pkfromsig_fails_on_wrong_idx(self, xmss_c, message, sk_seed, pk_seed):
        pk = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        recovered = xmss_c.xmss_pkFromSig(1, sig, message, pk_seed, ADRS())
        assert recovered != pk

    # check correctness at every valid leaf index
    def test_pkfromsig_all_indices(self, xmss_c, sk_seed, pk_seed):
        pk = xmss_c.xmss_PKgen(sk_seed, pk_seed, ADRS())
        for idx in range(2 ** xmss_c.xmss_h):
            msg = os.urandom(N)
            sig = xmss_c.xmss_sign(msg, sk_seed, idx, pk_seed, ADRS())
            recovered = xmss_c.xmss_pkFromSig(idx, sig, msg, pk_seed, ADRS())
            assert recovered == pk, f"failed at idx={idx}"

    # sig_bytes includes the 4-byte counter
    def test_sig_bytes_includes_counter(self, xmss_c, message, sk_seed, pk_seed):
        sig = xmss_c.xmss_sign(message, sk_seed, 0, pk_seed, ADRS())
        assert xmss_c.sig_bytes() == len(sig.to_bytes())


# ================================================================
# HypertreeC Tests
# ================================================================

class TestHypertreeC:

    @pytest.fixture
    def ht_c(self):
        wots_c = WOTSPlusC(PARAMS_C, z=0)
        return HypertreeC(H, D, N, wots_c, ADRS())

    # invalid params raise
    def test_invalid_h_raises(self):
        wots_c = WOTSPlusC(PARAMS_C, z=0)
        with pytest.raises(ValueError):
            HypertreeC(0, D, N, wots_c, ADRS())

    def test_h_not_divisible_by_d_raises(self):
        wots_c = WOTSPlusC(PARAMS_C, z=0)
        with pytest.raises(ValueError):
            HypertreeC(7, D, N, wots_c, ADRS())

    # pkgen returns n bytes
    def test_pkgen_returns_n_bytes(self, ht_c, sk_seed, pk_seed):
        pk = ht_c.ht_PkGen(sk_seed, pk_seed)
        assert isinstance(pk, bytes)
        assert len(pk) == N

    # same inputs always give same pk
    def test_pkgen_deterministic(self, ht_c, sk_seed, pk_seed):
        pk1 = ht_c.ht_PkGen(sk_seed, pk_seed)
        pk2 = ht_c.ht_PkGen(sk_seed, pk_seed)
        assert pk1 == pk2

    # different seeds produce different keys
    def test_pkgen_differs_for_different_seeds(self, ht_c, pk_seed):
        pk1 = ht_c.ht_PkGen(os.urandom(N), pk_seed)
        pk2 = ht_c.ht_PkGen(os.urandom(N), pk_seed)
        assert pk1 != pk2

    # sign returns a hypertree_sig with d layers
    def test_sign_returns_hypertree_sig(self, ht_c, message, sk_seed, pk_seed):
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert isinstance(sig, hypertree_sig)

    def test_sign_contains_d_layers(self, ht_c, message, sk_seed, pk_seed):
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert len(sig.xmss_sigs) == D

    # each layer is an xmss_sig_c carrying a counter
    def test_sign_each_layer_is_xmss_sig_c(self, ht_c, message, sk_seed, pk_seed):
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        for s in sig.xmss_sigs:
            assert isinstance(s, xmss_sig_c)
            assert s.get_counter() >= 0

    # same inputs always give same sig
    def test_sign_deterministic(self, ht_c, message, sk_seed, pk_seed):
        sig1 = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        sig2 = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        for s1, s2 in zip(sig1.xmss_sigs, sig2.xmss_sigs):
            assert s1.get_sig() == s2.get_sig()
            assert s1.get_auth() == s2.get_auth()
            assert s1.get_counter() == s2.get_counter()

    # core correctness: valid sig verifies
    def test_verify_valid_signature(self, ht_c, message, sk_seed, pk_seed):
        pk = ht_c.ht_PkGen(sk_seed, pk_seed)
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht_c.ht_verify(message, sig, pk_seed, 0, 0, pk) is True

    # wrong message fails verification
    def test_verify_wrong_message_fails(self, ht_c, message, sk_seed, pk_seed):
        pk = ht_c.ht_PkGen(sk_seed, pk_seed)
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht_c.ht_verify(os.urandom(N), sig, pk_seed, 0, 0, pk) is False

    # wrong pk fails verification
    def test_verify_wrong_pk_fails(self, ht_c, message, sk_seed, pk_seed):
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht_c.ht_verify(message, sig, pk_seed, 0, 0, os.urandom(N)) is False

    # wrong leaf index fails verification
    def test_verify_wrong_leaf_index_fails(self, ht_c, message, sk_seed, pk_seed):
        pk = ht_c.ht_PkGen(sk_seed, pk_seed)
        sig = ht_c.ht_sign(message, sk_seed, pk_seed, 0, 0)
        assert ht_c.ht_verify(message, sig, pk_seed, 0, 1, pk) is False

    # check correctness at every valid leaf index
    def test_verify_all_leaf_indices(self, ht_c, sk_seed, pk_seed):
        pk = ht_c.ht_PkGen(sk_seed, pk_seed)
        for idx_leaf in range(2 ** (H // D)):
            msg = os.urandom(N)
            sig = ht_c.ht_sign(msg, sk_seed, pk_seed, 0, idx_leaf)
            assert ht_c.ht_verify(msg, sig, pk_seed, 0, idx_leaf, pk), \
                f"failed at idx_leaf={idx_leaf}"


# ================================================================
# SphincsC Tests
# ================================================================

class TestSphincsC:

    @pytest.fixture
    def sphincs_c(self):
        return SphincsC(PARAMS_C)

    @pytest.fixture
    def sphincs_c_z1(self):
        return SphincsC(PARAMS_C_Z1)

    @pytest.fixture
    def sphincs_c_det(self):
        return SphincsC(PARAMS_C, randomize=False)

    # invalid params raise at the params level
    def test_invalid_n_raises(self):
        with pytest.raises(ValueError):
            SphincsParamsC(n=0, w=W, h=H, d=D, k=K, t=T, t_prime=T)

    def test_invalid_t_prime_raises(self):
        with pytest.raises(ValueError):
            SphincsParamsC(n=N, w=W, h=H, d=D, k=K, t=T, t_prime=0)

    def test_t_prime_not_power_of_2_raises(self):
        with pytest.raises(ValueError):
            SphincsParamsC(n=N, w=W, h=H, d=D, k=K, t=T, t_prime=7)

    def test_invalid_z_raises(self):
        with pytest.raises(ValueError):
            SphincsParamsC(n=N, w=W, h=H, d=D, k=K, t=T, t_prime=T, z=-1)

    # keygen returns correct types and sizes
    def test_keygen_returns_correct_types(self, sphincs_c):
        sk, pk = sphincs_c.spx_keygen()
        assert isinstance(sk, SKC)
        assert isinstance(pk, PKC)

    def test_keygen_seeds_are_n_bytes(self, sphincs_c):
        sk, pk = sphincs_c.spx_keygen()
        assert len(sk.sk_seed) == N
        assert len(sk.pk_seed) == N
        assert len(sk.sk_prf) == N
        assert len(pk.pk_seed) == N
        assert len(pk.pk_root) == N

    # different keygens produce different keys
    def test_keygen_produces_different_keys(self, sphincs_c):
        _, pk1 = sphincs_c.spx_keygen()
        _, pk2 = sphincs_c.spx_keygen()
        assert pk1.pk_root != pk2.pk_root

    # sign and verify roundtrip
    def test_sign_then_verify(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(message, sk)
        assert sphincs_c.spx_verify(message, sig, pk) is True

    # same test with z=1 zero chains
    def test_sign_then_verify_z1(self, sphincs_c_z1, message):
        sk, pk = sphincs_c_z1.spx_keygen()
        sig = sphincs_c_z1.spx_sign(message, sk)
        assert sphincs_c_z1.spx_verify(message, sig, pk) is True

    # deterministic mode produces the same sig twice
    def test_deterministic_mode_reproducible(self, sphincs_c_det, message):
        sk, pk = sphincs_c_det.spx_keygen()
        sig1 = sphincs_c_det.spx_sign(message, sk)
        sig2 = sphincs_c_det.spx_sign(message, sk)
        assert sig1 == sig2
        assert sphincs_c_det.spx_verify(message, sig1, pk) is True

    # randomized mode produces different sigs for the same message
    def test_randomized_mode_differs(self, sphincs_c, message):
        sk, _ = sphincs_c.spx_keygen()
        sig1 = sphincs_c.spx_sign(message, sk)
        sig2 = sphincs_c.spx_sign(message, sk)
        assert sig1 != sig2

    # wrong message fails verification
    def test_wrong_message_fails(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(message, sk)
        assert sphincs_c.spx_verify(os.urandom(len(message)), sig, pk) is False

    # wrong public key fails verification
    def test_wrong_pk_fails(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(message, sk)
        wrong_pk = PKC(os.urandom(N), os.urandom(N))
        assert sphincs_c.spx_verify(message, sig, wrong_pk) is False

    # forged signature fails verification
    def test_forged_signature_fails(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(message, sk)
        forged = sig[:-1] + bytes([sig[-1] ^ 0xFF])
        assert sphincs_c.spx_verify(message, forged, pk) is False

    # empty message still works
    def test_empty_message(self, sphincs_c):
        sk, pk = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(b"", sk)
        assert sphincs_c.spx_verify(b"", sig, pk) is True

    # corrupting the fors section fails verification
    def test_fors_section_corruption_fails(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = bytearray(sphincs_c.spx_sign(message, sk))
        # fors bytes start after R (n bytes) and fors counter (4 bytes)
        start = sphincs_c.n + 4
        sig[start] ^= 0xFF
        assert sphincs_c.spx_verify(message, bytes(sig), pk) is False

    # corrupting the hypertree section fails verification
    def test_hypertree_section_corruption_fails(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = bytearray(sphincs_c.spx_sign(message, sk))
        # ht bytes start after R + fors counter + fors sig
        start = sphincs_c.n + 4 + sphincs_c.fors_c.sig_bytes() - 4
        sig[start] ^= 0xFF
        assert sphincs_c.spx_verify(message, bytes(sig), pk) is False

    # truncated signature fails verification
    def test_truncated_signature_fails(self, sphincs_c, message):
        sk, pk = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(message, sk)
        assert sphincs_c.spx_verify(message, sig[:-10], pk) is False

    # signature from one keypair fails under a different keypair's pk
    def test_cross_key_verify_fails(self, sphincs_c, message):
        sk1, _ = sphincs_c.spx_keygen()
        _, pk2 = sphincs_c.spx_keygen()
        sig = sphincs_c.spx_sign(message, sk1)
        assert sphincs_c.spx_verify(message, sig, pk2) is False

    # signature is smaller than the equivalent plain sphincs+ would be
    def test_sig_smaller_than_plain_sphincs(self, sphincs_c):
        sphincs_plain = Sphincs(PARAMS)
        sk_c, _ = sphincs_c.spx_keygen()
        sk_p, _ = sphincs_plain.spx_keygen()
        msg = os.urandom(N)
        sig_c = sphincs_c.spx_sign(msg, sk_c)
        sig_p = sphincs_plain.spx_sign(msg, sk_p)
        assert len(sig_c) < len(sig_p)
        
# ================================================================
# compute_Dls tests
# ================================================================
 
class TestComputeDls:
 
    # base case: D[0][0] must be 1, everything else in row 0 must be 0
    def test_base_case(self):
        D = compute_Dls(3, 4)
        assert D[0][0] == 1
        assert all(D[0][s] == 0 for s in range(1, 10))
 
    # for l=1 each digit j in [0, w-1] has exactly one vector, so D[1][j] = 1
    def test_single_element_row(self):
        w = 4
        D = compute_Dls(1, w)
        for j in range(w):
            assert D[1][j] == 1
 
    # for w=2 (binary case) D[l][s] == C(l, s), i.e. binomial coefficients
    def test_binary_case_matches_binomial(self):
        from math import comb
        l, w = 6, 2
        D = compute_Dls(l, w)
        for s in range(l + 1):
            assert D[l][s] == comb(l, s)
 
    # the sum of all D[l][s] for s in 0..l*(w-1) must equal w^l
    def test_total_count_equals_w_power_l(self):
        l, w = 4, 3
        D = compute_Dls(l, w)
        assert sum(D[l][s] for s in range(l * (w - 1) + 1)) == w ** l
 
    # the distribution is symmetric: D[l][s] == D[l][l*(w-1)-s]
    def test_symmetry(self):
        l, w = 5, 4
        D = compute_Dls(l, w)
        max_s = l * (w - 1)
        for s in range(max_s + 1):
            assert D[l][s] == D[l][max_s - s]
 
 
# ================================================================
# cs_encode / cs_decode tests
# ================================================================
 
class TestCsEncodeDecode:
 
    # every codeword produced by cs_encode must sum to target_sum
    def test_encode_sum_is_target(self):
        l, w = 3, 4
        target_sum = (l * (w - 1)) // 2
        D = compute_Dls(l, w)
        size = D[l][target_sum]
        for x in range(size):
            v = cs_encode(x, l, w, target_sum, D)
            assert sum(v) == target_sum
 
    # every digit in the codeword must be in [0, w-1]
    def test_encode_digits_in_range(self):
        l, w = 3, 4
        target_sum = (l * (w - 1)) // 2
        D = compute_Dls(l, w)
        size = D[l][target_sum]
        for x in range(size):
            v = cs_encode(x, l, w, target_sum, D)
            assert all(0 <= d <= w - 1 for d in v)
 
    # cs_encode must be injective: no two distinct x map to the same codeword
    def test_encode_is_injective(self):
        l, w = 3, 4
        target_sum = (l * (w - 1)) // 2
        D = compute_Dls(l, w)
        size = D[l][target_sum]
        codewords = [tuple(cs_encode(x, l, w, target_sum, D)) for x in range(size)]
        assert len(set(codewords)) == size
 
    # cs_decode must invert cs_encode exactly
    def test_decode_inverts_encode(self):
        l, w = 3, 4
        target_sum = (l * (w - 1)) // 2
        D = compute_Dls(l, w)
        size = D[l][target_sum]
        for x in range(size):
            v = cs_encode(x, l, w, target_sum, D)
            assert cs_decode(v, l, w, target_sum, D) == x
 
    # the number of distinct codewords must equal D[l][target_sum] (exhaustive check for small params)
    def test_encode_covers_full_antichain(self):
        l, w = 3, 4
        target_sum = (l * (w - 1)) // 2
        D = compute_Dls(l, w)
        size = D[l][target_sum]
        expected = {
            tuple(v) for v in
            (cs_encode(x, l, w, target_sum, D) for x in range(size))
        }
        assert len(expected) == size
 
 
# ================================================================
# cs_len tests
# ================================================================
 
class TestCsLen:
 
    # cs_len must return a value strictly less than the standard wots+ length l1+l2
    def test_shorter_than_wots_len(self):
        params = PARAMS
        l = cs_len(params.n, params.w)
        assert l < params.len
 
    # the antichain at the returned l must be large enough to cover 2^(8n) messages
    def test_antichain_covers_message_space(self):
        n, w = N, W
        l = cs_len(n, w)
        D = compute_Dls(l, w)
        target_sum = (l * (w - 1)) // 2
        assert D[l][target_sum] >= (1 << (8 * n))
 
    # check that l-1 would not be sufficient, confirming cs_len is minimal
    def test_is_minimal(self):
        n, w = N, W
        l = cs_len(n, w)
        if l > 1:
            D_smaller = compute_Dls(l - 1, w)
            target_sum = ((l - 1) * (w - 1)) // 2
            assert D_smaller[l - 1][target_sum] < (1 << (8 * n))
 
    # spot-check against table 1 from the paper: n=16, w=16 should give l=34
    def test_known_value_128bit_w16(self):
        assert cs_len(16, 16) == 34
 
    # spot-check: n=32, w=16 should give l=66
    def test_known_value_256bit_w16(self):
        assert cs_len(32, 16) == 66
 
 
# ================================================================
# WOTSAlpha tests
# ================================================================
 
class TestWOTSAlpha:
 
    # cs_l must be one less than the standard wots+ len for these params
    def test_l_is_shorter_than_standard(self, wots_alpha):
        assert wots_alpha.l == PARAMS.len - 1
 
    # target_sum must equal floor(l*(w-1)/2)
    def test_target_sum_value(self, wots_alpha):
        expected = (wots_alpha.l * (W - 1)) // 2
        assert wots_alpha.target_sum == expected
 
    # pkgen must return exactly n bytes
    def test_pkgen_returns_n_bytes(self, wots_alpha, sk_seed, pk_seed):
        pk = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        assert isinstance(pk, bytes)
        assert len(pk) == N
 
    # pkgen must be deterministic for the same inputs
    def test_pkgen_deterministic(self, wots_alpha, sk_seed, pk_seed):
        pk1 = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        pk2 = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        assert pk1 == pk2
 
    # different sk_seeds must produce different public keys
    def test_pkgen_differs_for_different_sk(self, wots_alpha, pk_seed):
        pk1 = wots_alpha.wots_PKgen(os.urandom(N), pk_seed, ADRS())
        pk2 = wots_alpha.wots_PKgen(os.urandom(N), pk_seed, ADRS())
        assert pk1 != pk2
 
    # sign must return exactly l signature elements each of length n
    def test_sign_returns_correct_length(self, wots_alpha, message, sk_seed, pk_seed):
        sig = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert len(sig) == wots_alpha.l
        assert all(len(s) == N for s in sig)
 
    # sign must be deterministic for the same inputs
    def test_sign_deterministic(self, wots_alpha, message, sk_seed, pk_seed):
        sig1 = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        sig2 = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        assert sig1 == sig2
 
    # different messages must produce different signatures
    def test_sign_differs_for_different_messages(self, wots_alpha, sk_seed, pk_seed):
        sig1 = wots_alpha.wots_sign(os.urandom(N), sk_seed, pk_seed, ADRS())
        sig2 = wots_alpha.wots_sign(os.urandom(N), sk_seed, pk_seed, ADRS())
        assert sig1 != sig2
 
    # pkfromsig must return exactly n bytes
    def test_pkfromsig_returns_n_bytes(self, wots_alpha, message, sk_seed, pk_seed):
        sig = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        pk = wots_alpha.wots_pkFromSig(sig, message, pk_seed, ADRS())
        assert isinstance(pk, bytes)
        assert len(pk) == N
 
    # core consistency: recovered pk must match the real pk
    def test_pkfromsig_matches_pkgen(self, wots_alpha, message, sk_seed, pk_seed):
        pk = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_alpha.wots_pkFromSig(sig, message, pk_seed, ADRS())
        assert recovered == pk
 
    # wrong message must cause pk recovery to fail
    def test_pkfromsig_fails_on_wrong_message(self, wots_alpha, message, sk_seed, pk_seed):
        pk = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_alpha.wots_pkFromSig(sig, os.urandom(N), pk_seed, ADRS())
        assert recovered != pk
 
    # wrong pk_seed must cause pk recovery to fail
    def test_pkfromsig_fails_on_wrong_pk_seed(self, wots_alpha, message, sk_seed, pk_seed):
        pk = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        sig = wots_alpha.wots_sign(message, sk_seed, pk_seed, ADRS())
        recovered = wots_alpha.wots_pkFromSig(sig, message, os.urandom(N), ADRS())
        assert recovered != pk
 
    # sig_bytes must equal l * n
    def test_sig_bytes(self, wots_alpha):
        assert wots_alpha.sig_bytes() == wots_alpha.l * N
 
    # sig_bytes must be strictly smaller than the standard wots+ sig size
    def test_sig_bytes_smaller_than_standard(self, wots_alpha):
        standard_sig_bytes = PARAMS.len * N
        assert wots_alpha.sig_bytes() < standard_sig_bytes
 
    # verify the codeword used during signing actually sums to target_sum
    def test_sign_codeword_sums_to_target(self, wots_alpha, message):
        from WOTS.WOTS_Alpha import cs_encode, compute_Dls
        x = int.from_bytes(message, "big") % wots_alpha._D[wots_alpha.l][wots_alpha.target_sum]
        codeword = cs_encode(x, wots_alpha.l, W, wots_alpha.target_sum, wots_alpha._D)
        assert sum(codeword) == wots_alpha.target_sum
 
    # run sign+verify for several random messages to catch any edge cases
    def test_sign_verify_multiple_messages(self, wots_alpha, sk_seed, pk_seed):
        pk = wots_alpha.wots_PKgen(sk_seed, pk_seed, ADRS())
        for _ in range(10):
            m = os.urandom(N)
            sig = wots_alpha.wots_sign(m, sk_seed, pk_seed, ADRS())
            recovered = wots_alpha.wots_pkFromSig(sig, m, pk_seed, ADRS())
            assert recovered == pk
            
# ================================================================
# SphincsAlpha tests
# ================================================================
 
class TestSphincsAlpha:
 
    # keygen must return sk and pk with correct types
    def test_keygen_returns_correct_types(self, scheme):
        sk, pk = scheme.spx_keygen()
        assert isinstance(sk, SK)
        assert isinstance(pk, PK)
 
    # all key fields must be n bytes
    def test_keygen_field_sizes(self, scheme):
        sk, pk = scheme.spx_keygen()
        assert len(sk.sk_seed) == N
        assert len(sk.sk_prf) == N
        assert len(sk.pk_seed) == N
        assert len(sk.pk_root) == N
        assert len(pk.pk_seed) == N
        assert len(pk.pk_root) == N
 
    # different keygens must produce different keys
    def test_keygen_produces_unique_keys(self, scheme):
        _, pk1 = scheme.spx_keygen()
        _, pk2 = scheme.spx_keygen()
        assert pk1.pk_root != pk2.pk_root
 
    # sign must return bytes
    def test_sign_returns_bytes(self, scheme, keypair):
        sk, pk = keypair
        sig = scheme.spx_sign(b"test message", sk)
        assert isinstance(sig, bytes)
 
    # signature length must match sig_bytes()
    def test_sign_correct_length(self, scheme, keypair):
        sk, pk = keypair
        sig = scheme.spx_sign(b"test message", sk)
        assert len(sig) == scheme.sig_bytes()
 
    # deterministic mode must produce the same signature each time
    def test_sign_deterministic(self, scheme, keypair):
        sk, pk = keypair
        msg = b"same message"
        sig1 = scheme.spx_sign(msg, sk)
        sig2 = scheme.spx_sign(msg, sk)
        assert sig1 == sig2
 
    # randomized mode must produce different signatures each time
    def test_sign_randomized_differs(self, scheme_randomized):
        sk, pk = scheme_randomized.spx_keygen()
        msg = b"same message"
        sig1 = scheme_randomized.spx_sign(msg, sk)
        sig2 = scheme_randomized.spx_sign(msg, sk)
        assert sig1 != sig2
 
    # verify must accept a valid signature
    def test_verify_accepts_valid_sig(self, scheme, keypair):
        sk, pk = keypair
        msg = b"valid message"
        sig = scheme.spx_sign(msg, sk)
        assert scheme.spx_verify(msg, sig, pk)
 
    # verify must reject a tampered message
    def test_verify_rejects_wrong_message(self, scheme, keypair):
        sk, pk = keypair
        sig = scheme.spx_sign(b"original", sk)
        assert not scheme.spx_verify(b"tampered", sig, pk)
 
    # verify must reject a signature under the wrong public key
    def test_verify_rejects_wrong_pk(self, scheme, keypair):
        sk, pk = keypair
        msg = b"test message"
        sig = scheme.spx_sign(msg, sk)
        _, other_pk = scheme.spx_keygen()
        assert not scheme.spx_verify(msg, sig, other_pk)
 
    # verify must reject a bitflipped signature
    def test_verify_rejects_corrupted_sig(self, scheme, keypair):
        sk, pk = keypair
        msg = b"test message"
        sig = bytearray(scheme.spx_sign(msg, sk))
        sig[N] ^= 0xFF
        assert not scheme.spx_verify(msg, bytes(sig), pk)
 
    # alpha signature must be strictly smaller than the standard sphincs+ signature for the same params
    def test_sig_bytes_smaller_than_standard(self, scheme):
        standard = Sphincs(SphincsParams(n=N, w=W, h=H, d=D, k=K, t=T))
        _, standard_pk = standard.spx_keygen()
        standard_sig = standard.spx_sign(b"test", standard.sk)
        assert scheme.sig_bytes() < len(standard_sig)
    
    # as above just tested differently for sanity
    def test_sig_smaller_than_standard(self, scheme, keypair):
        sk, pk = keypair
        alpha_sig = scheme.spx_sign(b"test", sk)
        standard = Sphincs(SphincsParams(n=N, w=W, h=H, d=D, k=K, t=T), randomize=False)
        standard_sk, _ = standard.spx_keygen()
        standard_sig = standard.spx_sign(b"test", standard_sk)
        assert len(alpha_sig) < len(standard_sig)
 
    # run sign+verify for several random messages
    def test_sign_verify_multiple_messages(self, scheme, keypair):
        sk, pk = keypair
        for _ in range(5):
            msg = os.urandom(32)
            sig = scheme.spx_sign(msg, sk)
            assert scheme.spx_verify(msg, sig, pk)
