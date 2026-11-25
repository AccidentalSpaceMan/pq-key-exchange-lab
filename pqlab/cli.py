"""The ``pqlab`` command line."""
from __future__ import annotations

import argparse
import sys

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqlab",
        description="Post-quantum key exchange lab: ML-KEM-768 and hybrid X25519MLKEM768 TLS.",
    )
    parser.add_argument("--version", action="version", version=f"pqlab {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_env = sub.add_parser("env", help="check that this Python can run both parts of the lab")
    p_env.set_defaults(func=cmd_env)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
