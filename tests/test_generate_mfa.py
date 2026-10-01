import json
import stat
import sys

import pytest

from api.mfa import MFA_STATE, totp_code, verify_mfa
from scripts import generate_mfa


def test_generator_outputs_private_usable_files_without_console_secrets(
    monkeypatch, tmp_path, capsys
):
    output = tmp_path / "enrollment"
    monkeypatch.setattr(
        sys,
        "argv",
        ["generate_mfa", "--username", "admin", "--output-dir", str(output)],
    )
    generate_mfa.main()
    console = capsys.readouterr()
    raw = (output / "mfa-users.json").read_text()
    config = json.loads(raw)["admin"]
    codes = (output / "recovery-codes.txt").read_text().splitlines()
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert len(codes) == 8
    for path in output.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert config["totp_secret"] not in console.out + console.err
    assert "otpauth://" not in console.out + console.err
    assert not any(code in console.out + console.err for code in codes)
    assert all(
        value.startswith("$argon2id$") for value in config["recovery_code_hashes"]
    )
    assert not any(code in raw for code in codes)
    monkeypatch.setenv("MFA_USERS_JSON", raw)
    monkeypatch.setenv("MFA_REQUIRED_ROLES_JSON", '["admin"]')
    monkeypatch.setenv("MFA_STATE_BACKEND", "memory")
    MFA_STATE.clear()
    assert verify_mfa("admin", "admin", codes[0])
    assert not verify_mfa("admin", "admin", codes[0])
    secret = generate_mfa._decode_totp_secret(config["totp_secret"])
    assert verify_mfa("admin", "admin", totp_code(secret))
    MFA_STATE.clear()


def test_generator_preserves_existing_totp_secret(tmp_path):
    secret_file = tmp_path / "existing-totp"
    secret = generate_mfa.base64.b32encode(b"m" * 20).decode()
    secret_file.write_text(secret)
    secret_file.chmod(0o600)
    output = tmp_path / "rotated"
    generate_mfa.generate_enrollment(
        "Admin", "Service", output, totp_secret_file=secret_file
    )
    assert (
        json.loads((output / "mfa-users.json").read_text())["admin"]["totp_secret"]
        == secret
    )


def test_generator_never_overwrites_existing_directory(tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "marker"
    marker.write_text("preserve")
    with pytest.raises(FileExistsError):
        generate_mfa.generate_enrollment("admin", "Service", output)
    assert marker.read_text() == "preserve"
    assert list(output.iterdir()) == [marker]


def test_generator_rejects_public_existing_secret(tmp_path):
    secret = tmp_path / "existing-totp"
    secret.write_text("unused")
    secret.chmod(0o644)
    with pytest.raises(ValueError, match="permisos privados"):
        generate_mfa.generate_enrollment(
            "admin", "Service", tmp_path / "new", totp_secret_file=secret
        )
    assert not (tmp_path / "new").exists()


def test_generator_cleans_up_partial_output(monkeypatch, tmp_path):
    output = tmp_path / "partial"
    write = generate_mfa._write_private_file

    def fail_after_first(path, value):
        if path.name == "enrollment.txt":
            raise OSError("write failed")
        write(path, value)

    monkeypatch.setattr(generate_mfa, "_write_private_file", fail_after_first)
    with pytest.raises(OSError):
        generate_mfa.generate_enrollment("admin", "Service", output)
    assert not output.exists()
