import pytest

from pqlab import __version__, cli, env


def test_report_fields():
    r = env.check()
    assert r.python.startswith("3.")
    assert "OpenSSL" in r.ssl_openssl or "LibreSSL" in r.ssl_openssl


def test_part1_ready():
    # The cryptography wheel ships its own OpenSSL with ML-KEM, so this holds everywhere we test.
    assert env.check().part1_ready


def test_part2_ready():
    # CI runs on Python 3.15 builds linked to OpenSSL 3.5+, which offer the hybrid group.
    # If this fails locally, run `pqlab env` to see which piece is missing.
    assert env.check().part2_ready


def test_cli_env_exit_code(capsys):
    assert cli.main(["env"]) == 0
    assert "Part 2 (hybrid TLS) ready:   yes" in capsys.readouterr().out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out
