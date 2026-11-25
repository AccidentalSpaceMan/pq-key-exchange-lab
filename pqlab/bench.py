"""Part 1: measure ML-KEM-768 against X25519 (and the two combined, as TLS does).

Two kinds of numbers:

* **Sizes** are exact. They are read from real keys and ciphertexts this module creates,
  not typed in from a table.
* **Speeds** are measured on the machine running the benchmark, so they change from computer
  to computer. To keep them fair:
    - every operation is timed in a loop of many calls, and the loop is repeated several times;
      we report the *median* repeat (the middle value), which ignores one-off hiccups such as
      the operating system pausing the program;
    - the three schemes are timed in the same run, on the same machine, with the same library.

The three operations, named from the KEM point of view so the schemes line up:

========  ============================================  ==========================================
step      ML-KEM-768                                    X25519 (Diffie-Hellman)
========  ============================================  ==========================================
keygen    Bob: KeyGen                                   Bob: make a key pair
encaps    Alice: Encaps(Bob's public key)               Alice: make her own key pair + exchange
decaps    Bob: Decaps(ciphertext)                       Bob: exchange(Alice's public key)
========  ============================================  ==========================================

"hybrid" does both, the way X25519MLKEM768 does in TLS 1.3.
"""
from __future__ import annotations

import json
import platform
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable

import cryptography
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

SCHEMES = ("X25519", "ML-KEM-768", "X25519MLKEM768")
OPERATIONS = ("keygen", "encaps", "decaps")


# ---------------------------------------------------------------- sizes


@dataclass(frozen=True)
class Sizes:
    public_key: int        # what Bob sends (ClientHello key share in TLS)
    private_key: int       # what Bob stores
    ciphertext: int        # what Alice sends back (ServerHello key share in TLS)
    shared_secret: int

    @property
    def on_the_wire(self) -> int:
        """Bytes both sides send for one key exchange."""
        return self.public_key + self.ciphertext


def measure_sizes() -> dict[str, Sizes]:
    """Read sizes off real objects, so the numbers can't drift from the library."""
    # X25519: the "ciphertext" is Alice's public key.
    xb = x25519.X25519PrivateKey.generate()
    xa = x25519.X25519PrivateKey.generate()
    x_pub = xb.public_key().public_bytes_raw()
    x_reply = xa.public_key().public_bytes_raw()
    x_secret = xa.exchange(xb.public_key())
    x = Sizes(len(x_pub), len(xb.private_bytes_raw()), len(x_reply), len(x_secret))

    mb = mlkem.MLKEM768PrivateKey.generate()
    m_pub = mb.public_key().public_bytes_raw()
    m_secret, m_ct = mb.public_key().encapsulate()
    m = Sizes(len(m_pub), len(mb.private_bytes_raw()), len(m_ct), len(m_secret))

    # X25519MLKEM768 (draft-ietf-tls-ecdhe-mlkem): the two key shares are simply concatenated,
    # ML-KEM first, and the two shared secrets are concatenated into one 64-byte secret.
    h = Sizes(
        m.public_key + x.public_key,
        m.private_key + x.private_key,
        m.ciphertext + x.ciphertext,
        m.shared_secret + x.shared_secret,
    )
    return {"X25519": x, "ML-KEM-768": m, "X25519MLKEM768": h}


# ---------------------------------------------------------------- speed


def _x25519_ops() -> dict[str, Callable[[], object]]:
    bob = x25519.X25519PrivateKey.generate()
    bob_pub = bob.public_key()
    alice_pub = x25519.X25519PrivateKey.generate().public_key()

    def encaps():
        alice = x25519.X25519PrivateKey.generate()
        return alice.public_key().public_bytes_raw(), alice.exchange(bob_pub)

    return {
        "keygen": lambda: x25519.X25519PrivateKey.generate().public_key().public_bytes_raw(),
        "encaps": encaps,
        "decaps": lambda: bob.exchange(alice_pub),
    }


def _mlkem_ops() -> dict[str, Callable[[], object]]:
    bob = mlkem.MLKEM768PrivateKey.generate()
    bob_pub = bob.public_key()
    _, ct = bob_pub.encapsulate()
    return {
        "keygen": lambda: mlkem.MLKEM768PrivateKey.generate().public_key().public_bytes_raw(),
        "encaps": bob_pub.encapsulate,
        "decaps": lambda: bob.decapsulate(ct),
    }


def _hybrid_ops() -> dict[str, Callable[[], object]]:
    x, m = _x25519_ops(), _mlkem_ops()
    return {op: (lambda a=x[op], b=m[op]: (b(), a())) for op in OPERATIONS}


def _ops() -> dict[str, dict[str, Callable[[], object]]]:
    return {"X25519": _x25519_ops(), "ML-KEM-768": _mlkem_ops(), "X25519MLKEM768": _hybrid_ops()}


def time_op(fn: Callable[[], object], iterations: int, repeats: int) -> float:
    """Median microseconds per call over ``repeats`` loops of ``iterations`` calls."""
    fn()  # warm up (first call may load code or fill caches)
    per_call = []
    for _ in range(repeats):
        start = time.perf_counter_ns()
        for _ in range(iterations):
            fn()
        per_call.append((time.perf_counter_ns() - start) / iterations / 1000)
    return statistics.median(per_call)


# ---------------------------------------------------------------- run + save


def cpu_name() -> str:
    try:
        if sys.platform == "win32":
            import winreg

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        if sys.platform == "darwin":
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True)
            if out.stdout.strip():
                return out.stdout.strip()
        if Path("/proc/cpuinfo").exists():
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or platform.machine() or "unknown"


@dataclass
class BenchResult:
    sizes: dict[str, dict[str, int]]
    microseconds: dict[str, dict[str, float]]     # scheme -> op -> median us per call
    iterations: int
    repeats: int
    environment: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, text: str) -> "BenchResult":
        return cls(**json.loads(text))


def environment() -> dict[str, str]:
    from cryptography.hazmat.backends.openssl import backend

    return {
        "cpu": cpu_name(),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "openssl (cryptography)": backend.openssl_version_text(),
    }


def run(iterations: int = 2000, repeats: int = 7) -> BenchResult:
    sizes = measure_sizes()
    timings = {
        scheme: {op: round(time_op(fn, iterations, repeats), 2) for op, fn in ops.items()}
        for scheme, ops in _ops().items()
    }
    return BenchResult(
        sizes={k: {**asdict(v), "on_the_wire": v.on_the_wire} for k, v in sizes.items()},
        microseconds=timings,
        iterations=iterations,
        repeats=repeats,
        environment=environment(),
    )
