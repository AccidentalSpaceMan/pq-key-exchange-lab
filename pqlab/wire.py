"""Prove which key exchange was used by reading the handshake bytes off the wire.

``SSLSocket.group()`` tells us what OpenSSL *says* it negotiated. To check that independently,
this module puts a small relay between the client and the server (like a post office that
photocopies every envelope before passing it on) and then decodes the first messages of the
TLS 1.3 handshake itself:

* **ClientHello**: the client's opening message. Its ``supported_groups`` extension lists the
  key exchanges it accepts, and its ``key_share`` extension carries actual public keys for one
  or more of them.
* **ServerHello**: the server's reply. Its ``key_share`` extension names the ONE group the server
  picked and carries the server's half of the exchange.

These two messages are sent before encryption starts, so anyone on the network path can read
them; everything after is encrypted with keys derived from the exchange.

For X25519MLKEM768 (codepoint 0x11EC) the key shares have fixed sizes that nothing else matches:
client 1216 bytes (ML-KEM-768 encapsulation key 1184 + X25519 public key 32) and server 1120
bytes (ML-KEM-768 ciphertext 1088 + X25519 public key 32). Seeing 0x11EC with those lengths in
the ServerHello is the proof.

This is a *parser* for public handshake bytes, not cryptography: it decodes lengths and type
codes, and never touches keys or secrets.
"""
from __future__ import annotations

import hashlib
import socket
import struct
import threading
from dataclasses import dataclass, field

from .tls_lab import require_loopback

# IANA "TLS Supported Groups" registry (the ones this lab may see)
GROUP_NAMES = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0200: "MLKEM512",
    0x0201: "MLKEM768",
    0x0202: "MLKEM1024",
    0x11EB: "SecP256r1MLKEM768",
    0x11EC: "X25519MLKEM768",
    0x11ED: "SecP384r1MLKEM1024",
}
X25519MLKEM768 = 0x11EC
HYBRID_CLIENT_SHARE = 1184 + 32
HYBRID_SERVER_SHARE = 1088 + 32

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}

EXT_SUPPORTED_GROUPS = 10
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

# RFC 8446 section 4.1.3: a ServerHello with this "random" value is really a HelloRetryRequest,
# the server's way of saying "send me a key share for a different group, please".
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()


def group_name(code: int) -> str:
    return GROUP_NAMES.get(code, f"unknown(0x{code:04x})")


class ParseError(ValueError):
    pass


# ------------------------------------------------------------------ decoding


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ParseError(f"truncated: wanted {n} bytes at offset {self.pos}, have {len(self.data) - self.pos}")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec(self, len_bytes: int) -> bytes:
        n = {1: self.u8, 2: self.u16, 3: self.u24}[len_bytes]()
        return self.take(n)

    def done(self) -> bool:
        return self.pos >= len(self.data)


def handshake_messages(stream: bytes) -> list[tuple[int, bytes]]:
    """Split one direction of a TLS byte stream into handshake messages (type, body).

    Only plaintext handshake records (content type 22) are read; once encryption starts
    (content type 23) we stop, since everything after that is unreadable by design.
    A handshake message may be split across several records, so record payloads are
    joined first.
    """
    payload = bytearray()
    r = _Reader(stream)
    while not r.done():
        if len(r.data) - r.pos < 5:
            break                                 # partial record header at the end
        content_type = r.u8()
        r.take(2)                                 # legacy record version
        length = r.u16()
        if len(r.data) - r.pos < length:
            break                                 # partial record at the end of the capture
        body = r.take(length)
        if content_type == 22:
            payload += body
        elif content_type == 23:
            break                                 # encrypted from here on
        # 20 = ChangeCipherSpec (a compatibility no-op in TLS 1.3); 21 = alert: skip
    msgs = []
    h = _Reader(bytes(payload))
    while len(h.data) - h.pos >= 4:
        msg_type = h.u8()
        n = h.u24()
        if len(h.data) - h.pos < n:
            break
        msgs.append((msg_type, h.take(n)))
    return msgs


def _extensions(r: _Reader) -> dict[int, bytes]:
    exts: dict[int, bytes] = {}
    if r.done():
        return exts
    e = _Reader(r.vec(2))
    while not e.done():
        ext_type = e.u16()
        exts[ext_type] = e.vec(2)
    return exts


@dataclass
class ClientHello:
    cipher_suites: list[int]
    supported_groups: list[int]
    key_shares: dict[int, int]        # group -> key share length in bytes
    supported_versions: list[int]


@dataclass
class ServerHello:
    cipher_suite: int
    selected_group: int | None
    key_share_length: int | None      # None in a HelloRetryRequest (it names a group, no key)
    selected_version: int | None
    is_hello_retry_request: bool


def parse_client_hello(body: bytes) -> ClientHello:
    r = _Reader(body)
    r.take(2 + 32)                                # legacy_version, random
    r.vec(1)                                      # legacy_session_id
    suites_raw = r.vec(2)
    suites = [int.from_bytes(suites_raw[i:i + 2], "big") for i in range(0, len(suites_raw), 2)]
    r.vec(1)                                      # legacy_compression_methods
    exts = _extensions(r)

    groups = []
    if EXT_SUPPORTED_GROUPS in exts:
        g = _Reader(exts[EXT_SUPPORTED_GROUPS]).vec(2)
        groups = [int.from_bytes(g[i:i + 2], "big") for i in range(0, len(g), 2)]

    shares: dict[int, int] = {}
    if EXT_KEY_SHARE in exts:
        ks = _Reader(_Reader(exts[EXT_KEY_SHARE]).vec(2))
        while not ks.done():
            grp = ks.u16()
            shares[grp] = len(ks.vec(2))

    versions = []
    if EXT_SUPPORTED_VERSIONS in exts:
        v = _Reader(exts[EXT_SUPPORTED_VERSIONS]).vec(1)
        versions = [int.from_bytes(v[i:i + 2], "big") for i in range(0, len(v), 2)]
    return ClientHello(suites, groups, shares, versions)


def parse_server_hello(body: bytes) -> ServerHello:
    r = _Reader(body)
    r.take(2)                                     # legacy_version
    random = r.take(32)
    r.vec(1)                                      # legacy_session_id_echo
    suite = r.u16()
    r.u8()                                        # legacy_compression_method
    exts = _extensions(r)
    hrr = random == HRR_RANDOM

    group = length = None
    if EXT_KEY_SHARE in exts:
        ks = _Reader(exts[EXT_KEY_SHARE])
        group = ks.u16()
        if not hrr:
            length = len(ks.vec(2))
    version = None
    if EXT_SUPPORTED_VERSIONS in exts:
        version = _Reader(exts[EXT_SUPPORTED_VERSIONS]).u16()
    return ServerHello(suite, group, length, version, hrr)


# ------------------------------------------------------------------ the proof


@dataclass
class WireEvidence:
    """Everything decoded from the captured handshake, plus a verdict."""

    client_hellos: list[ClientHello]
    server_hellos: list[ServerHello]          # a HelloRetryRequest (if any) comes first
    client_bytes: int
    server_bytes: int

    @property
    def final_server_hello(self) -> ServerHello | None:
        real = [s for s in self.server_hellos if not s.is_hello_retry_request]
        return real[-1] if real else None

    @property
    def hello_retry(self) -> bool:
        return any(s.is_hello_retry_request for s in self.server_hellos)

    @property
    def negotiated_group(self) -> str | None:
        sh = self.final_server_hello
        return group_name(sh.selected_group) if sh and sh.selected_group is not None else None

    @property
    def proves_hybrid(self) -> bool:
        """True only if the bytes on the wire show a full X25519MLKEM768 exchange."""
        sh = self.final_server_hello
        if sh is None or sh.selected_group != X25519MLKEM768 or sh.selected_version != 0x0304:
            return False
        if sh.key_share_length != HYBRID_SERVER_SHARE:
            return False
        last_ch = self.client_hellos[-1] if self.client_hellos else None
        return bool(last_ch and last_ch.key_shares.get(X25519MLKEM768) == HYBRID_CLIENT_SHARE)


def analyse(client_to_server: bytes, server_to_client: bytes) -> WireEvidence:
    chs = [parse_client_hello(b) for t, b in handshake_messages(client_to_server) if t == 1]
    shs = [parse_server_hello(b) for t, b in handshake_messages(server_to_client) if t == 2]
    if not chs:
        raise ParseError("no ClientHello found in the captured client bytes")
    return WireEvidence(chs, shs, len(client_to_server), len(server_to_client))


# ------------------------------------------------------------------ the recording relay


@dataclass
class Capture:
    client_to_server: bytearray = field(default_factory=bytearray)
    server_to_client: bytearray = field(default_factory=bytearray)


class RecordingRelay:
    """A loopback TCP relay that forwards bytes unchanged and keeps a copy of the first
    ``limit`` bytes in each direction. Only ever forwards to a loopback address.

    Use as a context manager; connect the client to ``relay.port`` instead of the server.
    Handles one connection at a time; ``captures`` keeps one entry per connection.
    """

    def __init__(self, target_host: str, target_port: int, limit: int = 64 * 1024):
        require_loopback(target_host)
        self.target = (target_host, target_port)
        self.limit = limit
        self.captures: list[Capture] = []
        self._sock = socket.create_server(("127.0.0.1", 0))
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="pqlab-relay", daemon=True)

    def __enter__(self) -> "RecordingRelay":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._sock.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            cap = Capture()
            self.captures.append(cap)
            try:
                upstream = socket.create_connection(self.target, timeout=10)
            except OSError:
                client.close()
                continue
            a = threading.Thread(target=self._pump, args=(client, upstream, cap.client_to_server), daemon=True)
            b = threading.Thread(target=self._pump, args=(upstream, client, cap.server_to_client), daemon=True)
            a.start(); b.start()
            a.join(); b.join()
            client.close(); upstream.close()

    def _pump(self, src: socket.socket, dst: socket.socket, record: bytearray) -> None:
        try:
            while chunk := src.recv(65536):
                if len(record) < self.limit:
                    record += chunk[: self.limit - len(record)]
                dst.sendall(chunk)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)   # pass the "I'm done sending" signal along
            except OSError:
                pass

    def evidence(self, index: int = -1) -> WireEvidence:
        cap = self.captures[index]
        return analyse(bytes(cap.client_to_server), bytes(cap.server_to_client))
