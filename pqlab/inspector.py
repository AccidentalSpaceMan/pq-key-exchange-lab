"""Inspect a LOCAL TLS server: its certificate and the handshake it negotiates.

Think of it as reading the ID card and the handshake style of a server you run yourself:

* **Handshake:** TLS version, cipher suite (the fast cipher that encrypts the data), and the
  key-exchange group, which is checked from the wire bytes as well as from OpenSSL (see ``wire.py``).
* **Certificate:** who it names, who signed it, what kind of key it holds and how big, how it was
  signed, and when it expires.
* **Quantum check:** for each piece, whether a large quantum computer would break it.

Like the rest of the lab it only connects to loopback addresses (this machine).
Optionally it asks the ``openssl`` command-line tool for a second opinion on the group.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
import shutil
import subprocess
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography import x509
# The key types below are only *recognised* in certificates (isinstance checks), never used,
# so those lines carry "cryptoinv: ignore" for the crypto-inventory-scanner self-scan.
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa  # cryptoinv: ignore
from cryptography.x509.oid import NameOID

from . import hybrid, tls_lab


@dataclass
class CertInfo:
    subject: str
    issuer: str
    self_signed: bool
    dns_names: list[str]
    ip_addresses: list[str]
    serial: str
    key_type: str              # e.g. "EC (secp256r1)", "RSA", "Ed25519", "ML-DSA-65"
    key_bits: int | None
    signature_algorithm: str   # e.g. "ecdsa-with-SHA256"
    not_before: str            # ISO 8601, UTC
    not_after: str
    days_left: int
    sha256_fingerprint: str


@dataclass
class QuantumCheck:
    item: str
    value: str
    quantum_safe: bool
    note: str


@dataclass
class InspectReport:
    host: str
    port: int
    tls_version: str | None
    cipher_suite: str | None
    cipher_bits: int | None
    group_from_openssl: str | None
    group_from_wire: str | None
    hybrid_proven: bool
    hello_retry: bool
    certificate: CertInfo | None
    quantum: list[QuantumCheck] = field(default_factory=list)
    openssl_cli: dict[str, str] | None = None     # second opinion, if the tool is available
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- certificate


def _cn(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else name.rfc4514_string()


def describe_key(key) -> tuple[str, int | None]:
    if isinstance(key, ec.EllipticCurvePublicKey):  # cryptoinv: ignore
        return f"EC ({key.curve.name})", key.curve.key_size
    if isinstance(key, rsa.RSAPublicKey):  # cryptoinv: ignore
        return "RSA", key.key_size
    if isinstance(key, dsa.DSAPublicKey):  # cryptoinv: ignore
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):  # cryptoinv: ignore
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):  # cryptoinv: ignore
        return "Ed448", 456
    name = type(key).__name__                       # e.g. MLDSA65PublicKey
    m = re.match(r"(MLDSA)(\d+)", name)
    if m:
        return f"ML-DSA-{m.group(2)}", None
    return name.replace("PublicKey", ""), None


def describe_cert(der: bytes, now: dt.datetime | None = None) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns = san.get_values_for_type(x509.DNSName)
        ips = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns, ips = [], []
    key_type, bits = describe_key(cert.public_key())
    sig = cert.signature_algorithm_oid
    sig_name = getattr(sig, "_name", None) or sig.dotted_string
    return CertInfo(
        subject=_cn(cert.subject),
        issuer=_cn(cert.issuer),
        self_signed=cert.subject == cert.issuer,
        dns_names=dns,
        ip_addresses=ips,
        serial=f"{cert.serial_number:x}",
        key_type=key_type,
        key_bits=bits,
        signature_algorithm=sig_name,
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        days_left=(cert.not_valid_after_utc - now).days,
        sha256_fingerprint=hashlib.sha256(der).hexdigest(),
    )


# ---------------------------------------------------------------- quantum check


def quantum_checks(group: str | None, cipher: str | None, cert: CertInfo | None) -> list[QuantumCheck]:
    out = []
    if group:
        pq = "MLKEM" in group.upper()
        out.append(QuantumCheck(
            "Key exchange", group, pq,
            "hybrid: safe if either X25519 or ML-KEM holds" if pq and "X25519" in group.upper() else
            "post-quantum" if pq else
            "Shor's algorithm breaks it; recorded traffic could be decrypted later",
        ))
    if cipher:
        strong = "AES_256" in cipher or "CHACHA20" in cipher
        out.append(QuantumCheck(
            "Bulk cipher", cipher, True,
            "256-bit key keeps a wide margin against Grover's algorithm" if strong else
            "128-bit key: still considered fine by NIST, though 256-bit gives more margin",
        ))
    if cert:
        sig_pq = cert.key_type.startswith(("ML-DSA", "SLH-DSA"))
        out.append(QuantumCheck(
            "Certificate signature", f"{cert.signature_algorithm} ({cert.key_type})", sig_pq,
            "post-quantum signature" if sig_pq else
            "a quantum computer could forge it, but only from the day it exists (no 'harvest now' risk); "
            "the fix is ML-DSA certificates",
        ))
    return out


# ---------------------------------------------------------------- openssl second opinion


def openssl_second_opinion(host: str, port: int, ca_cert: Path, groups: str, timeout: float = 20) -> dict[str, str] | None:
    """Ask ``openssl s_client`` what it negotiated. Returns None if OpenSSL 3.5+ isn't installed."""
    tls_lab.require_loopback(host)
    exe = shutil.which("openssl")
    if not exe:
        return None
    ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=timeout).stdout
    m = re.search(r"OpenSSL (\d+)\.(\d+)(?:\.\d+)?", ver)
    if not m or (int(m.group(1)), int(m.group(2))) < (3, 5):
        return None
    p = subprocess.run(
        [exe, "s_client", "-connect", f"{host}:{port}", "-servername", "localhost", "-groups", groups,
         "-CAfile", str(ca_cert), "-verify_return_error", "-brief"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout,
    )
    text = p.stdout + p.stderr
    found = {"openssl_version": f"OpenSSL {m.group(0).split()[1]}", "exit_code": str(p.returncode)}
    for key, pattern in (
        ("protocol", r"Protocol version:\s*(\S+)"),
        ("cipher_suite", r"Ciphersuite:\s*(\S+)"),
        ("verification", r"Verification:\s*(.+)"),
        ("group", r"Negotiated TLS1\.3 group:\s*(\S+)"),
    ):
        mm = re.search(pattern, text)
        if mm:
            found[key] = mm.group(1).strip()
    return found


# ---------------------------------------------------------------- the inspection


def inspect(host: str, port: int, ca_cert: Path, groups: str = f"{tls_lab.HYBRID}:X25519",
            use_openssl: bool = False) -> InspectReport:
    tls_lab.require_loopback(host)
    result = hybrid.handshake_via_relay(host, port, ca_cert, groups)
    hs, ev = result.handshake, result.evidence
    cert = describe_cert(hs.server_cert_der) if hs else None
    report = InspectReport(
        host=host,
        port=port,
        tls_version=hs.version if hs else None,
        cipher_suite=hs.cipher_suite if hs else None,
        cipher_bits=hs.cipher_bits if hs else None,
        group_from_openssl=hs.group if hs else None,
        group_from_wire=ev.negotiated_group,
        hybrid_proven=result.proven,
        hello_retry=ev.hello_retry,
        certificate=cert,
        quantum=quantum_checks(hs.group if hs else None, hs.cipher_suite if hs else None, cert),
        error=result.error,
    )
    if use_openssl:
        report.openssl_cli = openssl_second_opinion(host, port, ca_cert, groups)
    return report


def render(r: InspectReport) -> list[str]:
    out = [f"TLS inspection of {r.host}:{r.port}", ""]
    if r.error:
        out += [f"    handshake FAILED: {r.error}"]
        return out
    out.append("Handshake")
    out.append(f"    TLS version          {r.tls_version}")
    out.append(f"    cipher suite         {r.cipher_suite} ({r.cipher_bits}-bit key)")
    out.append(f"    key exchange group   {r.group_from_openssl}  (OpenSSL)")
    wire_note = "  (decoded from the ServerHello bytes)"
    if r.hello_retry:
        wire_note += ", after a HelloRetryRequest"
    out.append(f"                         {r.group_from_wire}{wire_note}")
    if r.openssl_cli is not None:
        o = r.openssl_cli
        out.append(f"                         {o.get('group', '?')}  (openssl s_client: {o.get('openssl_version', '')})")
    out.append(f"    hybrid proven        {'yes' if r.hybrid_proven else 'NO'}")
    out.append("")

    c = r.certificate
    if c:
        out.append("Certificate")
        out.append(f"    subject              {c.subject}")
        out.append(f"    issued by            {c.issuer}{'  (self-signed)' if c.self_signed else ''}")
        names = c.dns_names + c.ip_addresses
        out.append(f"    valid for            {', '.join(names) if names else '(no subject alternative names)'}")
        out.append(f"    public key           {c.key_type}" + (f", {c.key_bits} bits" if c.key_bits else ""))
        out.append(f"    signature algorithm  {c.signature_algorithm}")
        out.append(f"    valid from           {c.not_before}")
        status = "EXPIRED" if c.days_left < 0 else f"{c.days_left} days left"
        out.append(f"    expires              {c.not_after}  ({status})")
        out.append(f"    SHA-256 fingerprint  {c.sha256_fingerprint[:32]}...")
        out.append("")

    out.append("Quantum check")
    for q in r.quantum:
        mark = "safe      " if q.quantum_safe else "VULNERABLE"
        out.append(f"    {mark} {q.item:<22} {q.value}")
        for line in textwrap.wrap(q.note, 62):
            out.append(f"               {'':<22} {line}")
    return out


def inspect_own_server(server_groups: str = tls_lab.HYBRID, client_groups: str = f"{tls_lab.HYBRID}:X25519",
                       use_openssl: bool = False) -> InspectReport:
    """Start a throwaway local server and inspect it (used by ``pqlab inspect`` with no --port)."""
    import tempfile

    from . import certs

    with tempfile.TemporaryDirectory(prefix="pqlab-") as folder:
        lab = certs.make_lab_certs(Path(folder))
        with tls_lab.LabServer(lab, server_groups) as server:
            return inspect("127.0.0.1", server.port, lab.ca_cert, client_groups, use_openssl)

