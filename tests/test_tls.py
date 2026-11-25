"""Part 2: hybrid TLS between a local server and client, proven from the wire bytes."""
import ssl
import struct

import pytest
from cryptography import x509

from pqlab import certs, cli, hybrid, tls_lab, wire


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    return certs.make_lab_certs(tmp_path_factory.mktemp("certs"))


def via_relay(lab, server_groups, client_groups):
    with tls_lab.LabServer(lab, server_groups) as server:
        result = hybrid.handshake_via_relay("127.0.0.1", server.port, lab.ca_cert, client_groups)
    return result, server.log


# ---------------------------------------------------------------- certificates


def test_certs_are_for_localhost_and_signed_by_the_ca(lab):
    ca = x509.load_pem_x509_certificate(lab.ca_cert.read_bytes())
    leaf = x509.load_pem_x509_certificate(lab.server_cert.read_bytes())
    assert leaf.issuer == ca.subject
    leaf.verify_directly_issued_by(ca)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    # The CA's private key is never written to disk.
    assert sorted(p.name for p in lab.ca_cert.parent.iterdir()) == ["ca.pem", "server-key.pem", "server.pem"]


# ---------------------------------------------------------------- the main proof


def test_hybrid_is_negotiated_and_proven_on_the_wire(lab):
    result, log = via_relay(lab, "X25519MLKEM768", "X25519MLKEM768:X25519")
    hs, ev = result.handshake, result.evidence
    # Witness 1: OpenSSL, on both ends.
    assert hs.group == "X25519MLKEM768"
    assert log.groups == ["X25519MLKEM768"]
    assert hs.version == "TLSv1.3"
    # Witness 2: our own decoding of the bytes.
    sh = ev.final_server_hello
    assert sh.selected_group == 0x11EC
    assert sh.key_share_length == 1120
    assert sh.selected_version == 0x0304
    assert ev.client_hellos[0].key_shares[0x11EC] == 1216
    assert not ev.hello_retry
    assert result.proven
    assert "VERDICT: PROVEN" in "\n".join(hybrid.explain(result))


def test_classical_client_is_refused_by_hybrid_only_server(lab):
    result, log = via_relay(lab, "X25519MLKEM768", "X25519")
    assert result.handshake is None
    assert result.error and "HANDSHAKE_FAILURE" in result.error
    assert result.evidence.server_hellos == []
    assert not result.proven
    assert any("NO_SUITABLE_KEY_SHARE" in e for e in log.errors)


def test_classical_fallback_is_detected_not_proven(lab):
    # A server that also accepts X25519, and a client that only offers X25519.
    result, _ = via_relay(lab, "X25519MLKEM768:X25519", "X25519")
    assert result.handshake.group == "x25519"
    assert result.evidence.negotiated_group == "x25519"
    assert result.evidence.final_server_hello.key_share_length == 32
    assert not result.proven
    assert "NOT HYBRID" in "\n".join(hybrid.explain(result))


def test_hello_retry_request_then_hybrid(lab):
    # The client prefers X25519 and only sends an X25519 key share; the hybrid-only server
    # answers with a HelloRetryRequest asking for X25519MLKEM768, and the retry succeeds.
    result, _ = via_relay(lab, "X25519MLKEM768", "X25519:X25519MLKEM768")
    ev = result.evidence
    assert ev.hello_retry
    assert len(ev.client_hellos) == 2
    assert ev.server_hellos[0].is_hello_retry_request and ev.server_hellos[0].selected_group == 0x11EC
    assert result.proven


def test_client_rejects_untrusted_certificate(lab, tmp_path):
    other = certs.make_lab_certs(tmp_path / "other")   # a different CA the client doesn't trust
    with tls_lab.LabServer(lab) as server:
        with pytest.raises(ssl.SSLCertVerificationError):
            tls_lab.connect("127.0.0.1", server.port, other.ca_cert)


# ---------------------------------------------------------------- safety


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "192.168.1.10", "10.0.0.1"])
def test_refuses_non_loopback_hosts(host, lab):
    with pytest.raises(tls_lab.NotLoopbackError):
        tls_lab.connect(host, 443, lab.ca_cert)
    with pytest.raises(tls_lab.NotLoopbackError):
        wire.RecordingRelay(host, 443)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "127.5.5.5", "::1"])
def test_allows_loopback_hosts(host):
    tls_lab.require_loopback(host)


def test_cli_refuses_remote_host(capsys):
    assert cli.main(["connect", "--host", "example.com"]) == 2
    assert "not this machine" in capsys.readouterr().err


# ---------------------------------------------------------------- parser details


def _record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def test_handshake_message_split_across_records():
    msg = bytes([1]) + (6).to_bytes(3, "big") + b"abcdef"
    stream = _record(22, msg[:4]) + _record(22, msg[4:]) + _record(23, b"encrypted")
    assert wire.handshake_messages(stream) == [(1, b"abcdef")]


def test_truncated_capture_does_not_crash():
    assert wire.handshake_messages(b"\x16\x03\x01\x10") == []
    with pytest.raises(wire.ParseError):
        wire.analyse(b"", b"")


def test_group_names():
    assert wire.group_name(0x11EC) == "X25519MLKEM768"
    assert wire.group_name(0x001D) == "x25519"
    assert wire.group_name(0xABCD) == "unknown(0xabcd)"


def test_cli_demo(capsys):
    assert cli.main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "VERDICT: PROVEN" in out
    assert "refused, as it should be" in out
    assert "TLSv1.3" in out
