"""Production security preflight.

Run this on the deployment host/container with the real environment injected.
It validates configuration and both trusted audit checkpoints without printing
secret material.
"""

from api import report_generator, security_audit
from api.auth import validate_configuration
from api.production_security import is_production
from api.runtime_secrets import load_runtime_secrets


def main() -> None:
    load_runtime_secrets()
    if not is_production():
        raise SystemExit("APP_ENV debe ser production para ejecutar este preflight")
    validate_configuration()
    report_generator.verificar_auditoria()
    security_audit.verify_security_audit()
    print("production security preflight: OK")


if __name__ == "__main__":
    main()
