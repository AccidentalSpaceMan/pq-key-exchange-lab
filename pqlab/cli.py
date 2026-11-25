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


def print_bench(r) -> None:
    from .bench import OPERATIONS, SCHEMES

    print("Sizes (bytes)")
    print(f"    {'scheme':<16}{'public key':>11}{'private':>9}{'reply':>8}{'secret':>8}{'on wire':>9}")
    for s in SCHEMES:
        z = r.sizes[s]
        print(f"    {s:<16}{z['public_key']:>11}{z['private_key']:>9}{z['ciphertext']:>8}"
              f"{z['shared_secret']:>8}{z['on_the_wire']:>9}")
    print()
    print(f"Speed (microseconds per call, median of {r.repeats} x {r.iterations} calls)")
    print(f"    {'scheme':<16}" + "".join(f"{op:>10}" for op in OPERATIONS) + f"{'total':>10}")
    for s in SCHEMES:
        t = r.microseconds[s]
        print(f"    {s:<16}" + "".join(f"{t[op]:>10.1f}" for op in OPERATIONS) + f"{sum(t.values()):>10.1f}")
    print()
    for k, v in r.environment.items():
        print(f"    {k}: {v}")


def cmd_bench(args: argparse.Namespace) -> int:
    from pathlib import Path

    from . import bench, chart

    if args.from_json:
        r = bench.BenchResult.from_json(Path(args.from_json).read_text(encoding="utf-8"))
    else:
        iterations, repeats = (200, 3) if args.quick else (args.iterations, args.repeats)
        print(f"Timing {len(bench.SCHEMES)} schemes x {len(bench.OPERATIONS)} operations "
              f"({repeats} x {iterations} calls each)...\n")
        r = bench.run(iterations, repeats)
    print_bench(r)
    for path, text in ((args.json, r.to_json()), (args.svg, chart.render(r))):
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
            print(f"\nwrote {p}")
    return 0


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

    p_bench = sub.add_parser("bench", help="measure sizes and speed: X25519 vs ML-KEM-768 vs the hybrid")
    p_bench.add_argument("--iterations", type=int, default=2000, help="calls per timing loop (default 2000)")
    p_bench.add_argument("--repeats", type=int, default=7, help="timing loops per operation; the median is kept (default 7)")
    p_bench.add_argument("--quick", action="store_true", help="a fast, rougher run (200 calls x 3)")
    p_bench.add_argument("--json", default="results/bench.json", help="where to save the numbers ('' to skip)")
    p_bench.add_argument("--svg", default="results/bench.svg", help="where to save the chart ('' to skip)")
    p_bench.add_argument("--from-json", metavar="PATH", help="redraw from saved numbers instead of measuring")
    p_bench.set_defaults(func=cmd_bench)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
