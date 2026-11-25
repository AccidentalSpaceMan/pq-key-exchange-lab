import os

import pytest
from cryptography.hazmat.primitives.asymmetric import mlkem

from pqlab import cli, kem


def test_shared_secrets_match():
    w = kem.run()
    assert w.secrets_match
    assert len(w.alice_secret) == 32


def test_sizes_match_fips203():
    w = kem.run()
    for name, got in w.sizes.items():
        assert got == kem.FIPS203_MLKEM768[name], name


def test_every_check_step_passes():
    w = kem.run()
    checks = [s for s in w.steps if s.ok is not None]
    assert len(checks) == 2
    assert all(s.ok for s in checks)


def test_tampered_ciphertext_gives_different_secret():
    w = kem.run()
    assert len(w.tampered_secret) == 32
    assert w.tampered_secret != w.alice_secret


def test_secret_is_fresh_each_run():
    # Same key pair, two encapsulations: the randomness in Encaps makes the secrets differ.
    seed = os.urandom(64)
    a, b = kem.run(seed), kem.run(seed)
    assert a.steps[0].values == b.steps[0].values   # same public key from the same seed
    assert a.alice_secret != b.alice_secret


def test_wrong_private_key_cannot_recover_secret():
    bob = mlkem.MLKEM768PrivateKey.generate()
    eve = mlkem.MLKEM768PrivateKey.generate()
    secret, ct = bob.public_key().encapsulate()
    assert eve.decapsulate(ct) != secret


def test_malformed_public_key_is_rejected():
    with pytest.raises(ValueError):
        mlkem.MLKEM768PublicKey.from_public_bytes(b"\x00" * 100)


def test_preview():
    assert kem.preview(bytes(range(20)), 4) == "00010203... (20 bytes)"
    assert kem.preview(b"\xab", 4) == "ab (1 bytes)"


def test_cli_kem(capsys):
    assert cli.main(["kem"]) == 0
    out = capsys.readouterr().out
    assert "Decaps" in out
    assert out.count("PASS") == 2
    assert "MISMATCH" not in out
