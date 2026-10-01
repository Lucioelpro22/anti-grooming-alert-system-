import argparse
import base64
import hashlib
import json
import secrets
from urllib.parse import quote


def recovery_code() -> str:
    raw = secrets.token_hex(12).upper()
    return "-".join(raw[index : index + 4] for index in range(0, len(raw), 4))


def recovery_hash(code: str) -> str:
    normalized = code.replace("-", "").replace(" ", "").upper()
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate TOTP MFA material and one-time recovery codes."
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--issuer", default="Anti-Grooming Alert System")
    args = parser.parse_args()

    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    codes = [recovery_code() for _ in range(8)]
    hashes = [recovery_hash(code) for code in codes]
    label = quote(f"{args.issuer}:{args.username}")
    issuer = quote(args.issuer)

    print("TOTP_SECRET=" + secret)
    print(
        "OTPAUTH_URI="
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&digits=6&period=30"
    )
    print("RECOVERY_CODES=")
    for code in codes:
        print(code)
    print("MFA_USERS_JSON_FRAGMENT=")
    print(
        json.dumps(
            {
                args.username.strip().lower(): {
                    "totp_secret": secret,
                    "recovery_code_hashes": hashes,
                }
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
