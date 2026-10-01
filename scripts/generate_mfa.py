"""Create private MFA enrollment files without sending secrets to stdout."""

import argparse
import base64
import json
import os
import secrets
import shutil
import sys
from pathlib import Path
from urllib.parse import quote

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.mfa import _decode_totp_secret, recovery_code_hash


def recovery_code() -> str:
    raw = secrets.token_hex(12).upper()
    return "-".join(raw[index : index + 4] for index in range(0, len(raw), 4))


def _write_private_file(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(value)


def generate_enrollment(
    username: str,
    issuer: str,
    output_dir: Path,
    *,
    totp_secret_file: Path | None = None,
) -> None:
    if os.name != "posix":
        raise ValueError("Ejecutar en un host POSIX con permisos privados")
    username = username.strip().lower()
    if not username or any(ord(char) < 32 for char in username + issuer):
        raise ValueError("Usuario o emisor inválido")

    if totp_secret_file is None:
        secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    else:
        if totp_secret_file.stat().st_mode & 0o077:
            raise ValueError("El archivo TOTP existente debe tener permisos privados")
        if not totp_secret_file.is_file() or totp_secret_file.stat().st_size > 128:
            raise ValueError("Archivo TOTP existente inválido")
        secret_bytes = _decode_totp_secret(totp_secret_file.read_text(encoding="utf-8"))
        secret = base64.b32encode(secret_bytes).decode("ascii").rstrip("=")

    codes = [recovery_code() for _ in range(8)]
    hashes = [recovery_code_hash(code) for code in codes]
    label = quote(f"{issuer}:{username}", safe="")
    uri = (
        f"otpauth://totp/{label}?secret={secret}"
        f"&issuer={quote(issuer, safe='')}&digits=6&period=30"
    )
    configuration = {username: {"totp_secret": secret, "recovery_code_hashes": hashes}}

    # A fresh 0700 directory and O_EXCL files prevent overwrites and symlink writes.
    output_dir.mkdir(mode=0o700)
    try:
        _write_private_file(
            output_dir / "mfa-users.json", json.dumps(configuration) + "\n"
        )
        _write_private_file(
            output_dir / "enrollment.txt", f"TOTP_SECRET={secret}\nOTPAUTH_URI={uri}\n"
        )
        _write_private_file(output_dir / "recovery-codes.txt", "\n".join(codes) + "\n")
    except Exception:
        shutil.rmtree(output_dir)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate private TOTP enrollment files and one-time recovery codes."
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--issuer", default="Anti-Grooming Alert System")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--totp-secret-file", type=Path, help="Preserve an existing private TOTP secret"
    )
    args = parser.parse_args()

    try:
        generate_enrollment(
            args.username,
            args.issuer,
            args.output_dir,
            totp_secret_file=args.totp_secret_file,
        )
    except (OSError, ValueError, RuntimeError):
        parser.exit(
            1,
            "No se generó MFA: revisar usuario, archivo TOTP y directorio nuevo privado.\n",
        )
    print("MFA: archivos privados creados; no se muestran secretos en la consola.")


if __name__ == "__main__":
    main()
