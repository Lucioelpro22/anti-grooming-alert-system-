"""Pin a reviewed legacy audit tip before starting the upgraded service.

Run with the API stopped: python -m scripts.migrate_audit --entries N --head HASH
The expected values must come from an independently reviewed backup/checkpoint.
"""

import argparse
import hmac

from api import audit_state, report_generator


def migrate(entries: int, head: str) -> None:
    folder = report_generator.CARPETA_INFORMES
    with audit_state.transaction(folder) as connection:
        if connection.execute("SELECT id FROM checkpoint").fetchone() is not None:
            raise audit_state.EvidenceSecurityError("Ya existe un punto de control")
        history = report_generator._read_verified_audit(check_checkpoint=False)
        actual_head = history[-1]["entry_hash"] if history else "0" * 64
        if entries != len(history) or not hmac.compare_digest(head, actual_head):
            raise audit_state.EvidenceSecurityError(
                "El historial no coincide con el revisado"
            )
        if not history and any(folder.glob("informe_*")):
            raise audit_state.EvidenceSecurityError(
                "Informes sin historial de auditoría"
            )
        audit_state.advance(folder, entries, head)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=int, required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()
    migrate(args.entries, args.head)
    print("Punto de control registrado")
