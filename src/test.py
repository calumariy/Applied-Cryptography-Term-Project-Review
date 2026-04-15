import pytest
import os
import math
from ADRS import ADRS, ADRSType
from WOTSPLUS import WOTSPlus
from XMSS import XMSS
from XMSS_sig import xmss_sig
from Hypertree import Hypertree
from Hypertree_sig import hypertree_sig
from FORS import FORS
from FORS_sig import FORS_sig
from sphincs import Sphincs, SK, PK
from params import SphincsParams
from DGSP.manager import Manager
from DGSP.judge import judge, _encode_id
import helpers

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

        # ---------- Fixtures ----------

    @pytest.fixture
    def manager(self):
        m = Manager(PARAMS)
        m.keygen()
        return m

    @pytest.fixture
    def joined_user(self, manager):
        return manager.join("alice")

    @pytest.fixture
    def wots_keypair(self):
        wots = WOTSPlus(PARAMS)
        seed = os.urandom(N); rid = os.urandom(N)
        rho = helpers.H_simple(rid, N)
        sk_seed = helpers.H_simple(seed + rid, N)
        return wots.wots_PKgen(sk_seed, rho, ADRS())

    # ---------- KeyGen ----------

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
    # Join
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
    # ResponseM (cert issuance)
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
    # Revoke
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
    # Open
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

    def test_open_works_after_revocation(self, manager, joined_user):
        """Revocation shouldn't break attribution of past signatures."""
        user_id, cstar = joined_user
        sig, pi, *_ = _build_signature(manager, user_id, cstar, b"msg")
        manager.revoke([user_id])
        opened_id, opened_pi = manager.open(b"msg", sig)
        assert opened_id == user_id
        assert opened_pi == pi

    # ================================================================
    # Judge
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
    # Open ↔ Judge integration
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
    # End-to-end protocol scenarios
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