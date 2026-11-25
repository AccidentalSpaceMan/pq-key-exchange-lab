"""Make a throwaway certificate authority and a ``localhost`` certificate at run time.

A TLS server proves who it is with a *certificate*: a signed note saying "the key below belongs
to localhost". A *certificate authority* (CA) is whoever signs that note; clients trust the CA,
so they trust the note. Browsers trust a few hundred public CAs. This lab makes its own tiny CA
every time it runs, and only our own client is told to trust it.

Nothing here is ever committed: the files go to a temporary folder (or a folder you name, which
``.gitignore`` already blocks) and the keys are new on every run.

Note the split this lab is about: the *key exchange* in our TLS handshake is post-quantum
(X25519MLKEM768), but these certificates are signed with ECDSA P-256, which a large quantum
computer could forge. That is the state of the web today: key exchange moved first because
traffic recorded now could be decrypted later ("harvest now, decrypt later"), while forging a
signature only matters once such a computer exists. Moving certificates to ML-DSA comes next.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class LabCerts:
    """Paths to the files ``ssl`` needs. The private keys never leave this folder."""

    ca_cert: Path          # give this to the client so it trusts the server
    server_cert: Path
    server_key: Path


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "pqlab (throwaway, local only)"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),   # throwaway key in a temp folder; deleted after the run
    ))


def make_lab_certs(folder: Path, days: int = 7) -> LabCerts:
    """Create a CA and a server certificate for localhost / 127.0.0.1 / ::1 in ``folder``."""
    folder.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    start, end = now - dt.timedelta(minutes=5), now + dt.timedelta(days=days)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name("pqlab throwaway CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address("::1")),
        ]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    paths = LabCerts(folder / "ca.pem", folder / "server.pem", folder / "server-key.pem")
    paths.ca_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths.server_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    _write_key(paths.server_key, server_key)
    return paths
