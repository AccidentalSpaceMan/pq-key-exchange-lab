"""Part 2 glue: run a handshake through the recording relay and explain the result in words.

Used by ``pqlab demo`` (everything in one process) and ``pqlab connect`` (against a
``pqlab serve`` running in another terminal).
"""
from __future__ import annotations

import ssl
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import certs, tls_lab, wire

VERSIONS = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2"}


@dataclass
class Result:
    handshake: tls_lab.Handshake | None
    evidence: wire.WireEvidence
    error: str | None = None

    @property
    def library_says_hybrid(self) -> bool:
        return bool(self.handshake and self.handshake.group == tls_lab.HYBRID)

    @property
    def proven(self) -> bool:
        """Both witnesses agree: OpenSSL reports the hybrid AND the wire bytes show it."""
        return self.library_says_hybrid and self.evidence.proves_hybrid


def handshake_via_relay(host: str, port: int, ca_cert: Path, client_groups: str) -> Result:
    """Connect to ``host:port`` through a recording relay and decode what crossed the wire."""
    with wire.RecordingRelay(host, port) as relay:
        try:
            hs = tls_lab.connect("127.0.0.1", relay.port, ca_cert, client_groups)
            err = None
        except (ssl.SSLError, OSError) as e:
            hs, err = None, f"{type(e).__name__}: {getattr(e, 'reason', None) or e}"
    return Result(hs, relay.evidence(), err)


def _share_note(group: int, length: int | None, side: str) -> str:
    if group == wire.X25519MLKEM768:
        want = wire.HYBRID_CLIENT_SHARE if side == "client" else wire.HYBRID_SERVER_SHARE
        parts = ("1184 ML-KEM-768 encapsulation key + 32 X25519 public key" if side == "client"
                 else "1088 ML-KEM-768 ciphertext + 32 X25519 public key")
        mark = "matches" if length == want else f"EXPECTED {want}"
        return f"{length} bytes = {parts} ({mark})"
    return f"{length} bytes"


def explain(result: Result) -> list[str]:
    """Plain-language report of one handshake."""
    out: list[str] = []
    hs, ev = result.handshake, result.evidence

    out.append("What the client's ssl module reports")
    if hs:
        out.append(f"    TLS version      {hs.version}")
        out.append(f"    cipher suite     {hs.cipher_suite} ({hs.cipher_bits}-bit key)")
        out.append(f"    key exchange     {hs.group}")
        out.append(f"    server said      \"{hs.server_message}\"")
    else:
        out.append(f"    handshake FAILED: {result.error}")
    out.append("")

    out.append("What the bytes on the wire show (decoded independently from the captured handshake)")
    for i, ch in enumerate(ev.client_hellos, 1):
        label = "ClientHello" if len(ev.client_hellos) == 1 else f"ClientHello #{i}"
        out.append(f"    {label}")
        out.append("        offers groups    " + ", ".join(f"{wire.group_name(g)} (0x{g:04x})" for g in ch.supported_groups))
        for g, n in ch.key_shares.items():
            out.append(f"        key share        {wire.group_name(g)}: {_share_note(g, n, 'client')}")
    for sh in ev.server_hellos:
        if sh.is_hello_retry_request:
            out.append("    HelloRetryRequest  (the server wants a key share it wasn't sent: one extra round trip)")
            out.append(f"        asks for         {wire.group_name(sh.selected_group)} (0x{sh.selected_group:04x})")
            continue
        out.append("    ServerHello")
        out.append(f"        version          {VERSIONS.get(sh.selected_version, sh.selected_version)}")
        out.append(f"        cipher suite     {wire.CIPHER_SUITES.get(sh.cipher_suite, hex(sh.cipher_suite))}")
        if sh.selected_group is not None:
            out.append(f"        picked group     {wire.group_name(sh.selected_group)} (0x{sh.selected_group:04x})")
            out.append(f"        key share        {_share_note(sh.selected_group, sh.key_share_length, 'server')}")
    if not ev.server_hellos:
        out.append("    ServerHello      none: the server refused the connection")
    out.append("")

    if result.proven:
        out.append("VERDICT: PROVEN. The client and server agreed on X25519MLKEM768: OpenSSL reports it,")
        out.append("and the ServerHello on the wire picks group 0x11EC with a 1120-byte key share that only")
        out.append("the hybrid produces. The session keys depend on both X25519 and ML-KEM-768.")
    elif hs and ev.negotiated_group:
        out.append(f"VERDICT: NOT HYBRID. The connection used {ev.negotiated_group}, a classical key exchange")
        out.append("that a large quantum computer could break (and recorded traffic could be decrypted later).")
    else:
        out.append("VERDICT: NO CONNECTION. The two sides had no key exchange group in common.")
    return out


def run_demo(client_groups: str = "X25519MLKEM768:X25519", server_groups: str = tls_lab.HYBRID) -> tuple[Result, Result]:
    """Start a hybrid-only server, connect a modern client, then a classical-only client."""
    with tempfile.TemporaryDirectory(prefix="pqlab-") as folder:
        lab = certs.make_lab_certs(Path(folder))
        with tls_lab.LabServer(lab, server_groups) as server:
            modern = handshake_via_relay("127.0.0.1", server.port, lab.ca_cert, client_groups)
            classical = handshake_via_relay("127.0.0.1", server.port, lab.ca_cert, "X25519")
    return modern, classical
