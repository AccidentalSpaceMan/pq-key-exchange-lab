"""Part 1: the ML-KEM-768 flow (FIPS 203), one step at a time.

What is a KEM?
    A *key encapsulation mechanism* is a way for two people to end up with the same secret
    key over an open channel. Think of a padlock-box:

    1. Bob makes a matching pair: an open padlock he hands out freely (the *encapsulation
       key*, public) and the only key that opens it (the *decapsulation key*, private).
    2. Alice puts a fresh random secret in a box, snaps Bob's padlock shut on it, and sends
       the locked box (the *ciphertext*). She keeps a copy of the secret.
    3. Bob unlocks the box with his private key. Now both hold the same 32-byte secret,
       and anyone who only watched the padlock and the box go by learns nothing.

    Unlike X25519 (where both sides mix their keys together), only Alice chooses the secret
    in a KEM; Bob just recovers it. The secret then keys a fast cipher such as AES-GCM.

Why ML-KEM?
    ML-KEM (the standardised form of "Kyber") is built on lattice problems ("module learning
    with errors"), which no known quantum algorithm solves efficiently. X25519 relies on
    elliptic-curve discrete logs, which Shor's algorithm on a large quantum computer would break.

All the maths is done by the ``cryptography`` package (OpenSSL underneath); this module only
calls it and explains what happens. Nothing here is hand-written cryptography.
"""
from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import mlkem

# Sizes fixed by FIPS 203, Table 3 (ML-KEM-768). We check the library's output against them.
FIPS203_MLKEM768 = {
    "encapsulation_key": 1184,   # public key Bob sends
    "decapsulation_key": 2400,   # private key in the standard's expanded form
    "seed": 64,                  # the compact private key form (d || z) libraries store
    "ciphertext": 1088,          # the "locked box" Alice sends back
    "shared_secret": 32,         # the key both sides end up with
}


@dataclass
class Step:
    """One step of the walkthrough, ready to print or test."""

    actor: str          # "Bob", "Alice", "Network" or "Check"
    title: str
    explanation: str
    values: dict[str, bytes] = field(default_factory=dict)
    ok: bool | None = None   # set on the check steps


@dataclass
class Walkthrough:
    steps: list[Step]
    alice_secret: bytes
    bob_secret: bytes
    tampered_secret: bytes
    sizes: dict[str, int]

    @property
    def secrets_match(self) -> bool:
        return hmac.compare_digest(self.alice_secret, self.bob_secret)


def run(seed: bytes | None = None) -> Walkthrough:
    """Run the full ML-KEM-768 flow between Bob and Alice and record every step.

    ``seed`` (64 bytes) makes Bob's key pair repeatable for tests. Encapsulation always uses
    fresh randomness, as the standard requires, so the shared secret differs on every run.
    """
    steps: list[Step] = []

    # 1. Key generation (FIPS 203 ML-KEM.KeyGen)
    if seed is None:
        bob_private = mlkem.MLKEM768PrivateKey.generate()
    else:
        bob_private = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    bob_public_bytes = bob_private.public_key().public_bytes_raw()
    bob_seed = bob_private.private_bytes_raw()
    steps.append(Step(
        "Bob", "KeyGen: make a key pair",
        "Bob generates an encapsulation key (public, like an open padlock) and a decapsulation "
        "key (private). Libraries store the private key as a 64-byte seed and re-expand it to "
        "the standard's 2400-byte form when needed.",
        {"encapsulation key (public)": bob_public_bytes, "private seed (secret, stays with Bob)": bob_seed},
    ))

    # 2. Bob -> Alice: only bytes cross the network.
    steps.append(Step(
        "Network", "Bob sends his encapsulation key to Alice",
        "Anyone can see this. It is safe to publish, like handing out open padlocks.",
        {"bytes on the wire": bob_public_bytes},
    ))
    alice_view_of_bob = mlkem.MLKEM768PublicKey.from_public_bytes(bob_public_bytes)

    # 3. Encapsulation (FIPS 203 ML-KEM.Encaps)
    alice_secret, ciphertext = alice_view_of_bob.encapsulate()
    steps.append(Step(
        "Alice", "Encaps: lock a fresh secret in a box",
        "Alice's library picks 32 random bytes, derives the shared secret from them, and "
        "\"locks\" them with Bob's public key into a ciphertext. She keeps the shared secret.",
        {"shared secret (Alice keeps)": alice_secret, "ciphertext (to send)": ciphertext},
    ))

    # 4. Alice -> Bob
    steps.append(Step(
        "Network", "Alice sends the ciphertext to Bob",
        "Also public. Without Bob's private key it reveals nothing about the secret.",
        {"bytes on the wire": ciphertext},
    ))

    # 5. Decapsulation (FIPS 203 ML-KEM.Decaps)
    bob_secret = bob_private.decapsulate(ciphertext)
    steps.append(Step(
        "Bob", "Decaps: unlock the box",
        "Bob uses his private key to recover the shared secret from the ciphertext.",
        {"shared secret (Bob recovered)": bob_secret},
    ))

    # 6. Check (constant-time comparison, so timing doesn't leak where they differ)
    match = hmac.compare_digest(alice_secret, bob_secret)
    steps.append(Step(
        "Check", "Do both sides hold the same secret?",
        "In real use neither side shows the secret; they just start encrypting with it. "
        "Here we compare them to prove the flow worked.",
        ok=match,
    ))

    # 7. Tampering: flip one bit of the ciphertext.
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    tampered_secret = bob_private.decapsulate(bytes(tampered))
    rejected = not hmac.compare_digest(tampered_secret, alice_secret)
    steps.append(Step(
        "Check", "What if an attacker changes one bit of the ciphertext?",
        "ML-KEM uses \"implicit rejection\": decapsulation does not raise an error, it quietly "
        "returns an unrelated random-looking secret. The connection then fails later, and the "
        "attacker learns nothing from how or when Bob reacted.",
        {"secret from the tampered box": tampered_secret},
        ok=rejected,
    ))

    sizes = {
        "encapsulation_key": len(bob_public_bytes),
        "seed": len(bob_seed),
        "ciphertext": len(ciphertext),
        "shared_secret": len(alice_secret),
    }
    return Walkthrough(steps, alice_secret, bob_secret, tampered_secret, sizes)


def preview(data: bytes, width: int = 16) -> str:
    """Hex of the first ``width`` bytes, plus the total length."""
    head = data[:width].hex()
    more = "..." if len(data) > width else ""
    return f"{head}{more} ({len(data)} bytes)"
