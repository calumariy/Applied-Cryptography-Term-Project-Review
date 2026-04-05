import pytest
import os
import math
from ADRS import ADRS, ADRSType
from sphincs_params import SphincsParams
from WOTSPLUS import WOTSPlus
from XMSS import XMSS
from XMSS_sig import xmss_sig
from Hypertree import Hypertree
from Hypertree_sig import hypertree_sig
from FORS import FORS
from FORS_sig import FORS_sig
from sphincs import Sphincs, SK, PK
from WOTS_Plus_C import WOTSPlusC, compute_target_sum, check_conditions
from FORS_Plus_C import FORS_C

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

        start = sphincs.n
        sig[start] ^= 0xFF  # corrupt FORS part

        assert sphincs.spx_verify(message, bytes(sig), pk) is False
    
    def test_hypertree_section_corruption_fails(self, sphincs, message):
        (sk, pk) = sphincs.spx_keygen()
        sig = bytearray(sphincs.spx_sign(message, sk))

        start = sphincs.n + sphincs.fors.sig_bytes()
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
            sphincs.n +
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

# class DGSP:

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

from sphincs_params_Plus_C import SphincsParamsC
from sphincs_Plus_C import SphincsC, SK as SKC, PK as PKC, xmss_sig_c, XMSS_C, HypertreeC

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
        
    def test_debug_exact_sizes(self, sphincs_c):
        sphincs_plain = Sphincs(PARAMS)
        print(f"\nplain fors sig_bytes: {sphincs_plain.fors.sig_bytes()}")
        print(f"plain ht sig_bytes: {sphincs_plain.hypertree.sig_bytes()}")
        print(f"plain total: {sphincs_plain.n + sphincs_plain.fors.sig_bytes() + sphincs_plain.hypertree.sig_bytes()}")
        print(f"\nc fors sig_bytes: {sphincs_c.fors_c.sig_bytes()}")
        print(f"c ht sig_bytes: {sphincs_c.hypertree.sig_bytes()}")
        print(f"c wots ell: {sphincs_c.wots_c.ell}")
        print(f"c len1: {sphincs_c.params.len1}")
        print(f"c len (plain): {sphincs_c.params.len}")