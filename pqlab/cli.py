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


def cmd_demo(args: argparse.Namespace) -> int:
    from . import hybrid

    print("Hybrid TLS demo: everything runs on 127.0.0.1 and stops when the demo ends.")
    print(f"  server accepts:  {args.server_groups}")
    print(f"  client offers:   {args.client_groups}")
    print("  certificates:    a throwaway CA + localhost certificate, made now, deleted afterwards\n")
    modern, classical = hybrid.run_demo(args.client_groups, args.server_groups)
    print("\n".join(hybrid.explain(modern)))
    print("\n" + "-" * 88)
    print("Control test: a classical-only client (offers only X25519) against the same server\n")
    if classical.handshake:
        print(f"    connected with {classical.handshake.group}")
    else:
        print(f"    refused, as it should be: {classical.error}")
    return 0 if modern.proven else 1


def cmd_serve(args: argparse.Namespace) -> int:
    from pathlib import Path

    from . import certs, tls_lab

    lab = certs.make_lab_certs(Path(args.cert_dir))
    server = tls_lab.LabServer(lab, args.groups, args.host, args.port)
    print(f"pqlab TLS server on {args.host}:{server.port}, accepting groups: {args.groups}")
    print(f"Throwaway CA certificate for clients: {lab.ca_cert}")
    print(f"In another terminal:  python -m pqlab connect --port {server.port} --cafile {lab.ca_cert}")
    print("Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.close()
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    from pathlib import Path

    from . import hybrid

    result = hybrid.handshake_via_relay(args.host, args.port, Path(args.cafile), args.groups)
    print("\n".join(hybrid.explain(result)))
    return 0 if result.proven else 1


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

    groups_help = "colon-separated TLS groups, most preferred first"
    p_demo = sub.add_parser("demo", help="hybrid TLS: local server + client, and prove the group from the wire")
    p_demo.add_argument("--client-groups", default="X25519MLKEM768:X25519", help=groups_help)
    p_demo.add_argument("--server-groups", default="X25519MLKEM768", help=groups_help)
    p_demo.set_defaults(func=cmd_demo)

    p_serve = sub.add_parser("serve", help="run the local hybrid TLS server until Ctrl+C")
    p_serve.add_argument("--host", default="127.0.0.1", help="loopback address to listen on")
    p_serve.add_argument("--port", type=int, default=8443)
    p_serve.add_argument("--groups", default="X25519MLKEM768", help=groups_help)
    p_serve.add_argument("--cert-dir", default="certs", help="where to write the throwaway certificates (git-ignored)")
    p_serve.set_defaults(func=cmd_serve)

    p_connect = sub.add_parser("connect", help="connect to a local `pqlab serve` and prove the group from the wire")
    p_connect.add_argument("--host", default="127.0.0.1", help="loopback address of the server")
    p_connect.add_argument("--port", type=int, default=8443)
    p_connect.add_argument("--cafile", default="certs/ca.pem", help="the CA certificate `pqlab serve` printed")
    p_connect.add_argument("--groups", default="X25519MLKEM768:X25519", help=groups_help)
    p_connect.set_defaults(func=cmd_connect)
    return parser


def main(argv: list[str] | None = None) -> int:
    from .tls_lab import NotLoopbackError

    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except NotLoopbackError as e:
        print(f"pqlab: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"pqlab: {e}", file=sys.stderr)
        return 2
    except ConnectionRefusedError:
        print("pqlab: nothing is listening there. Start `python -m pqlab serve` first.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
