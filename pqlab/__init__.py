"""pqlab: a post-quantum key exchange lab.

Part 1 walks through ML-KEM-768 (FIPS 203) and measures it against X25519.
Part 2 runs a local TLS 1.3 server and client that negotiate the X25519MLKEM768
hybrid, and proves it by reading the handshake bytes.
"""

__version__ = "1.0.0"
