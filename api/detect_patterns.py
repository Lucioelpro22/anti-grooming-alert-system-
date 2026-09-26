import re
import unicodedata
from typing import TypedDict


def _normalize_text(texto: str) -> str:
    """Normalize text: Unicode decomposition, lowercase, collapse whitespace."""
    # Decompose accented characters (estás → estas)
    normalized = unicodedata.normalize("NFKD", texto)
    # Keep only ASCII-like characters (remove diacritics)
    normalized = "".join(
        c for c in normalized if unicodedata.category(c) != "Mn"
    )
    # Convert to lowercase
    normalized = normalized.lower()
    # Collapse multiple spaces into one
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized.strip()


PALABRAS_RIESGO = {
    "alta": [
        "dime tu edad",
        "cuantos anos tienes",
        "donde vives",
        "estas sola",
        "secreto entre nosotros",
        "no le cuentes a nadie",
        "nos vemos",
        "te voy a buscar",
        "manda foto",
        "foto tuya",
        "vestida",
        "sin ropa",
        "te quiero conocer",
        "eres especial",
        "muy madura para tu edad",
        "nadie te va a querer como yo",
        "confia en mi",
        "somos novios",
    ],
    "media": [
        "que haces",
        "con quien estas",
        "tus papas saben",
        "tu habitacion",
        "te regalo",
        "te compro",
        "dinero",
        "premio",
        "juego privado",
        "amigos solo nosotros",
        "me cuentas todo",
        "eres linda",
        "guapa",
    ],
    "baja": [
        "hola guapa",
        "que bonita",
        "me caes bien",
        "hablamos mas tarde",
        "me gustas",
        "quiero saber mas de ti",
    ],
}

PESOS = {"alta": 1.0, "media": 0.5, "baja": 0.2}


class RiskAnalysis(TypedDict):
    puntaje: float
    nivel_riesgo: str
    indicadores: list[str]


def evaluar_texto(texto: str) -> RiskAnalysis:
    """Evaluate text for grooming risk indicators with Unicode normalization."""
    # Store original for reporting
    texto_original = texto
    # Normalize for analysis
    texto_normalizado = _normalize_text(texto)
    
    puntaje = 0.0
    indicadores: list[str] = []
    
    # Sort by length descending to match longer phrases first
    candidatos = sorted(
        ((palabra, nivel) for nivel, palabras in PALABRAS_RIESGO.items() for palabra in palabras),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    
    spans_ocupados: list[tuple[int, int]] = []
    for palabra, nivel in candidatos:
        for coincidencia in re.finditer(r"\b" + re.escape(palabra) + r"\b", texto_normalizado):
            inicio, fin = coincidencia.span()
            if any(inicio < fin_ocupado and fin > inicio_ocupado for inicio_ocupado, fin_ocupado in spans_ocupados):
                continue
            spans_ocupados.append((inicio, fin))
            puntaje += PESOS[nivel]
            indicadores.append(f"[{nivel.upper()}] {palabra}")

    if puntaje >= 2.0:
        nivel = "CRÍTICO"
    elif puntaje >= 1.0:
        nivel = "ALTO"
    elif puntaje >= 0.5:
        nivel = "MEDIO"
    elif puntaje > 0:
        nivel = "BAJO"
    else:
        nivel = "SIN INDICADORES DETECTADOS"

    return {"puntaje": round(puntaje, 2), "nivel_riesgo": nivel, "indicadores": indicadores}


def identificar_perfil(analisis: RiskAnalysis) -> str:
    """Identify user profile based on risk analysis."""
    puntaje = analisis["puntaje"]
    indicadores = analisis["indicadores"]
    
    if puntaje >= 1.0 and any(
        "dime tu edad" in indicador.lower()
        or "foto" in indicador.lower()
        or "secreto" in indicador.lower()
        for indicador in indicadores
    ):
        return "PROBABLE AGRESOR (adulto/perfil de riesgo)"
    if puntaje <= 0:
        return "SIN INDICADORES DE RIESGO"
    return "REQUIERE SEGUIMIENTO"
