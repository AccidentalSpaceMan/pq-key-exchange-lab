"""Check what this machine's Python can do before running the lab.

Two separate pieces of software are involved, a bit like two different toolboxes:

* The ``cryptography`` package brings its own copy of OpenSSL. Part 1 (ML-KEM on
  its own) uses it.
* Python's built-in ``ssl`` module uses whatever OpenSSL Python was built with.
  Part 2 (TLS) uses it, and it needs OpenSSL 3.5 or newer for X25519MLKEM768,
  plus Python 3.15 or newer for the calls that pick and report the group.
"""
from __future__ import annotations

import ssl
import sys
from dataclasses import dataclass

HYBRID_GROUP = "X25519MLKEM768"


@dataclass(frozen=True)
class EnvReport:
    python: str
    ssl_openssl: str
    cryptography_version: str | None
    cryptography_mlkem: bool
    ssl_group_api: bool
    ssl_hybrid_group: bool

    @property
    def part1_ready(self) -> bool:
        return self.cryptography_mlkem

    @property
    def part2_ready(self) -> bool:
        return self.ssl_group_api and self.ssl_hybrid_group


def _cryptography_info() -> tuple[str | None, bool]:
    try:
        import cryptography
    except ImportError:
        return None, False
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem

        mlkem.MLKEM768PrivateKey.generate()
        has_mlkem = True
    except Exception:  # ImportError, or UnsupportedAlgorithm on an older OpenSSL build
        has_mlkem = False
    return cryptography.__version__, has_mlkem


def ssl_supports_hybrid() -> bool:
    """True if Python's ssl module can offer the X25519MLKEM768 group."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not hasattr(ctx, "get_groups"):
        return False
    try:
        return HYBRID_GROUP in ctx.get_groups()
    except (ssl.SSLError, NotImplementedError):
        return False


def check() -> EnvReport:
    crypto_version, has_mlkem = _cryptography_info()
    has_api = hasattr(ssl.SSLContext, "set_groups") and hasattr(ssl.SSLSocket, "group")
    return EnvReport(
        python=sys.version.split()[0],
        ssl_openssl=ssl.OPENSSL_VERSION,
        cryptography_version=crypto_version,
        cryptography_mlkem=has_mlkem,
        ssl_group_api=has_api,
        ssl_hybrid_group=ssl_supports_hybrid(),
    )
