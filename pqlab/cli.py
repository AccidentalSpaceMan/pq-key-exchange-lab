"""The ``pqlab`` command line."""
from __future__ import annotations

import argparse
import sys
import textwrap

from . import __version__, env


def _yes_no(ok: bool) -> str:
    return "yes" if ok else "NO"


def cmd_env(_args: argparse.Namespace) -> int:
    r = env.check()
    print(f"Python                       {r.python}")
    print(f"ssl module built with        {r.ssl_openssl}")
    print(f"cryptography package         {r.cryptography_version or 'not installed'}")
    print()
    print(f"ML-KEM-768 (cryptography)    {_yes_no(r.cryptography_mlkem)}")
    print(f"ssl set_groups()/group()     {_yes_no(r.ssl_group_api)}")
    print(f"ssl offers {env.HYBRID_GROUP:<17} {_yes_no(r.ssl_hybrid_group)}")
    print()
    print(f"Part 1 (ML-KEM flow) ready:  {_yes_no(r.part1_ready)}")
    print(f"Part 2 (hybrid TLS) ready:   {_yes_no(r.part2_ready)}")
    return 0 if (r.part1_ready and r.part2_ready) else 1


def cmd_kem(args: argparse.Namespace) -> int:
    from . import kem

    w = kem.run()
    width = 64 if args.full else 16
    print("ML-KEM-768 (FIPS 203): Bob receives a secret from Alice\n")
    for n, step in enumerate(w.steps, 1):
        print(f"[{n}] {step.actor}: {step.title}")
        for line in textwrap.wrap(step.explanation, 88):
            print(f"    {line}")
        for label, value in step.values.items():
            print(f"    - {label}: {kem.preview(value, width)}")
        if step.ok is not None:
            print(f"    => {'PASS' if step.ok else 'FAIL'}")
        print()
    print("Sizes vs FIPS 203:")
    for name, got in w.sizes.items():
        want = kem.FIPS203_MLKEM768[name]
        print(f"    {name:<18} {got:>5} bytes  (standard: {want}) {'ok' if got == want else 'MISMATCH'}")
    ok = w.secrets_match and all(s.ok is not False for s in w.steps)
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqlab",
        description="Post-quantum key exchange lab: ML-KEM-768 and hybrid X25519MLKEM768 TLS.",
    )
    parser.add_argument("--version", action="version", version=f"pqlab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_env = sub.add_parser("env", help="check that this Python can run both parts of the lab")
    p_env.set_defaults(func=cmd_env)

    p_kem = sub.add_parser("kem", help="walk through the ML-KEM-768 flow step by step")
    p_kem.add_argument("--full", action="store_true", help="show 64 bytes of each value instead of 16")
    p_kem.set_defaults(func=cmd_kem)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
