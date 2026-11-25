"""Part 2: a local TLS 1.3 server and client that use the X25519MLKEM768 hybrid.

Everything uses Python's built-in ``ssl`` module (OpenSSL underneath). Two Python 3.15 calls do
the post-quantum part:

* ``SSLContext.set_groups("X25519MLKEM768")`` chooses which key-exchange *groups* a side is
  willing to use. (A "group" is TLS's name for a key-exchange algorithm plus its parameters.)
* ``SSLSocket.group()`` reports which group the handshake actually picked.

Safety: the server only listens on loopback (127.0.0.1 or ::1), and the client refuses to connect
anywhere else, so this lab can't be pointed at someone else's server.
"""
from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .certs import LabCerts

HYBRID = "X25519MLKEM768"
LOOPBACK_NAMES = {"localhost"}


class NotLoopbackError(ValueError):
    """Raised when asked to talk to anything other than this machine."""


def require_loopback(host: str) -> None:
    if host.lower() in LOOPBACK_NAMES:
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise NotLoopbackError(
        f"{host!r} is not this machine. pqlab only talks to servers it starts locally "
        "(localhost, 127.0.0.1 or ::1)."
    )


def server_context(certs: LabCerts, groups: str = HYBRID) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3   # hybrid groups only exist in TLS 1.3
    ctx.load_cert_chain(certs.server_cert, certs.server_key)
    ctx.set_groups(groups)
    return ctx


def client_context(ca_cert: Path, groups: str = f"{HYBRID}:X25519") -> ssl.SSLContext:
    """A strict client: checks the certificate and host name, TLS 1.3 only."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)     # verifies cert + host name by default
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(ca_cert))
    ctx.set_groups(groups)
    return ctx


@dataclass
class ServerLog:
    """What the server saw, one entry per connection (for tests and the demo)."""

    groups: list[str | None] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class LabServer:
    """A tiny TLS server on a background thread. Use it as a context manager.

    Each connection gets one line back, naming the group the server negotiated, then the
    connection closes.
    """

    def __init__(self, certs: LabCerts, groups: str = HYBRID, host: str = "127.0.0.1", port: int = 0):
        require_loopback(host)
        self.context = server_context(certs, groups)
        self.groups = groups
        self.log = ServerLog()
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self._sock = socket.create_server((host, port), family=family)
        self._sock.settimeout(0.2)
        self.host, self.port = self._sock.getsockname()[:2]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="pqlab-server", daemon=True)

    def __enter__(self) -> "LabServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._sock.close()

    def serve_forever(self) -> None:
        """Run in the foreground (for ``pqlab serve``) until Ctrl+C."""
        self._serve()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        raw.settimeout(10)
        try:
            with self.context.wrap_socket(raw, server_side=True) as tls:
                group = tls.group()
                self.log.groups.append(group)
                tls.sendall(f"hello from the pqlab server, key exchange group = {group}\n".encode())
        except (ssl.SSLError, OSError) as e:
            self.log.errors.append(f"{type(e).__name__}: {e}")


@dataclass(frozen=True)
class Handshake:
    """What the client learned from one connection."""

    version: str
    cipher_suite: str
    cipher_bits: int
    group: str | None
    server_cert_der: bytes
    server_message: str


def connect(host: str, port: int, ca_cert: Path, groups: str = f"{HYBRID}:X25519",
            server_name: str = "localhost", timeout: float = 10) -> Handshake:
    """Do one TLS handshake with a local server and report what was negotiated."""
    require_loopback(host)
    ctx = client_context(ca_cert, groups)
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            # Read everything about the session before the server closes the connection.
            name, _, bits = tls.cipher()
            version, group = tls.version(), tls.group()
            der = tls.getpeercert(binary_form=True)
            message = b""
            while chunk := tls.recv(4096):
                message += chunk
            return Handshake(version, name, bits, group, der, message.decode().strip())
