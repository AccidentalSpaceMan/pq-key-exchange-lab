"""The certificate and handshake inspector (local servers only)."""
import datetime as dt
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, rsa
from cryptography.x509.oid import NameOID

from pqlab import certs, cli, inspector, tls_lab


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    return certs.make_lab_certs(tmp_path_factory.mktemp("certs"))


def _self_signed_rsa(days_valid: int) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "old-server")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now - dt.timedelta(days=30))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_inspect_hybrid_server(lab):
    with tls_lab.LabServer(lab) as server:
        r = inspector.inspect("127.0.0.1", server.port, lab.ca_cert)
    assert r.error is None
    assert r.tls_version == "TLSv1.3"
    assert r.group_from_openssl == r.group_from_wire == "X25519MLKEM768"
    assert r.hybrid_proven
    c = r.certificate
    assert c.subject == "localhost" and c.issuer == "pqlab throwaway CA" and not c.self_signed
    assert c.key_type == "EC (secp256r1)" and c.key_bits == 256
    assert c.signature_algorithm == "ecdsa-with-SHA256"
    assert "127.0.0.1" in c.ip_addresses and "localhost" in c.dns_names
    assert 0 <= c.days_left <= 7
    verdicts = {q.item: q.quantum_safe for q in r.quantum}
    assert verdicts == {"Key exchange": True, "Bulk cipher": True, "Certificate signature": False}


def test_inspect_classical_server_flags_key_exchange(lab):
    with tls_lab.LabServer(lab, "X25519") as server:
        r = inspector.inspect("127.0.0.1", server.port, lab.ca_cert, "X25519")
    assert r.group_from_wire == "x25519"
    assert not r.hybrid_proven
    kx = next(q for q in r.quantum if q.item == "Key exchange")
    assert not kx.quantum_safe
    assert "VULNERABLE Key exchange" in "\n".join(inspector.render(r))


def test_inspect_failed_handshake_reports_error(lab):
    with tls_lab.LabServer(lab, "X25519MLKEM768") as server:
        r = inspector.inspect("127.0.0.1", server.port, lab.ca_cert, "X25519")
    assert r.error and r.certificate is None
    assert "handshake FAILED" in "\n".join(inspector.render(r))


def test_describe_cert_rsa_self_signed_and_expired():
    expired = inspector.describe_cert(_self_signed_rsa(days_valid=-1))
    assert expired.self_signed
    assert (expired.key_type, expired.key_bits) == ("RSA", 2048)
    assert expired.signature_algorithm == "sha256WithRSAEncryption"
    assert expired.days_left < 0
    assert expired.dns_names == [] and expired.ip_addresses == []


@pytest.mark.parametrize("key, expected", [
    (ed25519.Ed25519PrivateKey.generate().public_key(), ("Ed25519", 256)),
    (mldsa.MLDSA65PrivateKey.generate().public_key(), ("ML-DSA-65", None)),
])
def test_describe_key(key, expected):
    assert inspector.describe_key(key) == expected


def test_ml_dsa_certificate_counts_as_quantum_safe():
    cert = inspector.CertInfo("x", "x", True, [], [], "1", "ML-DSA-65", None, "ML-DSA-65",
                              "", "", 10, "")
    sig = next(q for q in inspector.quantum_checks(None, None, cert) if q.item == "Certificate signature")
    assert sig.quantum_safe


def test_refuses_remote_host(lab):
    with pytest.raises(tls_lab.NotLoopbackError):
        inspector.inspect("example.com", 443, lab.ca_cert)
    with pytest.raises(tls_lab.NotLoopbackError):
        inspector.openssl_second_opinion("example.com", 443, lab.ca_cert, "X25519MLKEM768")


def test_openssl_second_opinion_agrees(lab):
    with tls_lab.LabServer(lab) as server:
        o = inspector.openssl_second_opinion("127.0.0.1", server.port, lab.ca_cert, "X25519MLKEM768")
    if o is None:
        pytest.skip("openssl 3.5+ command-line tool not on PATH")
    assert o["group"] == "X25519MLKEM768"
    assert o["protocol"] == "TLSv1.3"
    assert o["verification"] == "OK"
    assert o["exit_code"] == "0"


def test_cli_inspect_json(capsys):
    assert cli.main(["inspect", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hybrid_proven"] is True
    assert data["certificate"]["key_type"] == "EC (secp256r1)"
