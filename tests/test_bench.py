import xml.etree.ElementTree as ET

from pqlab import bench, chart, cli, kem


def test_sizes_are_read_from_real_objects():
    s = bench.measure_sizes()
    assert (s["X25519"].public_key, s["X25519"].ciphertext, s["X25519"].shared_secret) == (32, 32, 32)
    m = s["ML-KEM-768"]
    assert m.public_key == kem.FIPS203_MLKEM768["encapsulation_key"]
    assert m.ciphertext == kem.FIPS203_MLKEM768["ciphertext"]
    # The TLS hybrid key shares: 1216 bytes from the client, 1120 from the server.
    h = s["X25519MLKEM768"]
    assert (h.public_key, h.ciphertext, h.shared_secret) == (1216, 1120, 64)
    assert h.on_the_wire == 2336


def test_hybrid_ops_do_both_halves():
    ops = bench._hybrid_ops()
    mlkem_part, x25519_part = ops["encaps"]()
    secret, ct = mlkem_part
    assert len(secret) == 32 and len(ct) == 1088
    pub, x_secret = x25519_part
    assert len(pub) == 32 and len(x_secret) == 32


def test_time_op_is_positive():
    assert bench.time_op(lambda: None, iterations=10, repeats=3) >= 0


def test_run_and_json_round_trip():
    r = bench.run(iterations=5, repeats=2)
    assert set(r.microseconds) == set(bench.SCHEMES)
    for scheme in bench.SCHEMES:
        assert set(r.microseconds[scheme]) == set(bench.OPERATIONS)
        assert all(v > 0 for v in r.microseconds[scheme].values())
    again = bench.BenchResult.from_json(r.to_json())
    assert again == r
    assert "cpu" in r.environment and "python" in r.environment


def test_chart_is_valid_svg_with_every_number():
    r = bench.run(iterations=5, repeats=2)
    svg = chart.render(r)
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    for scheme in bench.SCHEMES:
        assert f"{r.sizes[scheme]['on_the_wire']:,} B" in svg
        for op in bench.OPERATIONS:
            assert f"{r.microseconds[scheme][op]:,.1f}" in svg
    # 3 size bars + 9 timing bars, each with a hover tooltip
    assert svg.count('class="bar ') == 12
    assert svg.count("<title>") == 12


def test_nice_scale():
    assert chart._nice_scale(2336) == (2500, 500)
    assert chart._nice_scale(208.3) == (250, 50)
    assert chart._nice_scale(7) == (8, 2)


def test_cli_bench_writes_files(tmp_path, capsys):
    j, s = tmp_path / "b.json", tmp_path / "b.svg"
    assert cli.main(["bench", "--quick", "--json", str(j), "--svg", str(s)]) == 0
    assert j.exists() and s.exists()
    assert "X25519MLKEM768" in capsys.readouterr().out
    # Redraw from the saved numbers without measuring again
    s.unlink()
    assert cli.main(["bench", "--from-json", str(j), "--json", "", "--svg", str(s)]) == 0
    assert s.exists()
