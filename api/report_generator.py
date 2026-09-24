import uuid
import re
import json
from datetime import datetime
from pathlib import Path

CARPETA_INFORMES = Path("informes_generados")
CARPETA_INFORMES.mkdir(exist_ok=True)

def crear_informe(mensaje, analisis, ip_info, perfil, owner: str) -> str:
    informe_id = str(uuid.uuid4())[:8]
    fecha_emision = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    
    contenido = f"""
======================================================================
                    INFORME TÉCNICO DE DETECCIÓN
                SISTEMA DE ALERTA TEMPRANA — ANTI-GROOMING
======================================================================
ID INFORME: {informe_id}
FECHA EMISIÓN: {fecha_emision}
PLATAFORMA: {mensaje.plataforma or "No especificada"}
----------------------------------------------------------------------
DATOS DE LA COMUNICACIÓN
----------------------------------------------------------------------
Remitente: {mensaje.remitente_id}
Destinatario: {mensaje.destinatario_id}
Fecha mensaje: {mensaje.fecha_hora}
IP origen: {mensaje.ip_origen or "No registrada"}

----------------------------------------------------------------------
ANÁLISIS DE RIESGO
----------------------------------------------------------------------
Nivel de riesgo: {analisis['nivel_riesgo']}
Puntaje: {analisis['puntaje']}

INDICADORES DETECTADOS:
{chr(10).join(f'- {i}' for i in analisis['indicadores']) if analisis['indicadores'] else '- Ninguno'}

PERFIL IDENTIFICADO: {perfil}

----------------------------------------------------------------------
ANÁLISIS DE IP
----------------------------------------------------------------------
IP válida: {ip_info.get('valida', 'No disponible')}
{ip_info.get('ambito', '')}
Nota: {ip_info.get('nota', 'Sin observaciones')}

----------------------------------------------------------------------
CONCLUSIONES
----------------------------------------------------------------------
"""
    if "AGRESOR" in perfil:
        contenido += """⚠️ RIESGO ELEVADO — ACCIONES RECOMENDADAS:
- Preservar toda la evidencia sin modificar
- Bloquear al usuario inmediatamente
- Presentar denuncia ante autoridad competente
- Solicitar datos reales del titular por mandamiento judicial
- Acompañar a la persona menor con adultos de confianza
"""
    elif analisis['puntaje'] > 0:
        contenido += """ℹ️ Señales de riesgo — mantener vigilancia y conversar con la persona menor"""
    else:
        contenido += """✅ Sin indicadores de riesgo detectados"""

    contenido += """
----------------------------------------------------------------------
Documento generado por Sistema Anti-Grooming
NO SUSTITUYE DENUNCIA FORMAL ANTE AUTORIDADES
======================================================================
"""
    
    archivo = CARPETA_INFORMES / f"informe_{informe_id}.txt"
    archivo.write_text(contenido, encoding="utf-8")
    metadata = CARPETA_INFORMES / f"informe_{informe_id}.json"
    metadata.write_text(
        json.dumps({"id": informe_id, "owner": owner}, ensure_ascii=False),
        encoding="utf-8",
    )
    return informe_id

def leer_informe(informe_id: str, requester: str, can_read_all: bool = False) -> dict:
    if not re.fullmatch(r"[0-9a-f]{8}", informe_id):
        return {}
    archivo = CARPETA_INFORMES / f"informe_{informe_id}.txt"
    metadata = CARPETA_INFORMES / f"informe_{informe_id}.json"
    if not archivo.is_file() or not metadata.is_file():
        return {}
    try:
        datos = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if datos.get("id") != informe_id:
        return {}
    if not can_read_all and datos.get("owner") != requester:
        return {}
    return {"id": informe_id, "contenido": archivo.read_text(encoding="utf-8")}
