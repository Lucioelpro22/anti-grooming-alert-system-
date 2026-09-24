import base64
import secrets


def generate_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


print(f"EVIDENCE_ENCRYPTION_KEY={generate_key()}")
print(f"AUDIT_HMAC_KEY={generate_key()}")
