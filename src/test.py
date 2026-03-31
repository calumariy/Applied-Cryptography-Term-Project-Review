import pytest
import os
import math
from ADRS import ADRS, ADRSType
from WOTSPLUS import WOTSPlus, SphincsParams
from XMSS import XMSS
from XMSS_sig import xmss_sig
from Hypertree import Hypertree
from Hypertree_sig import hypertree_sig
from FORS import FORS
from FORS_sig import FORS_sig
from sphincs import Sphincs, SK, PK

# ================================================================
# Test Parameters
# ================================================================

N = 16
W = 16
H = 6
D = 2       # h/d = 3
K = 4
T = 8       # t = 2^3, a = 3

PARAMS = SphincsParams(n=N, w=W, h=H, d=D, k=K, t=T)

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

    # def test_sign_then_verify(self, sphincs, message):
    #     (sk, pk) = sphincs.spx_keygen()
    #     sig = sphincs.spx_sign(message, sk)
    #     assert sphincs.spx_verify(message, sig, pk) is True


# ================================================================
# DGSP Tests
# ================================================================

# class DGSP: