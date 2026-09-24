import ipaddress
from datetime import datetime, timezone


def analizar_ip(ip_str: str) -> dict:
    try:
        ip = ipaddress.ip_address(ip_str)
        es_privada = ip.is_private
        es_reservada = ip.is_reserved
        version = ip.version

        return {
            "ip": ip_str,
            "valida": True,
            "version": f"IPv{version}",
            "ambito": "Red local/privada" if es_privada else "Internet pública",
            "reservada_sistema": es_reservada,
            "analisis_fecha": datetime.now(timezone.utc).isoformat(),
            "nota": "Para ubicación precisa consultar base del proveedor mediante mandamiento judicial"
            if not es_privada
            else "Dirección de red interna — requiere seguimiento local",
        }
    except ValueError:
        return {
            "ip": ip_str,
            "valida": False,
            "mensaje": "Formato de IP inválido",
            "analisis_fecha": datetime.now(timezone.utc).isoformat(),
        }
