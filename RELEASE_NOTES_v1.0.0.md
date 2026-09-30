# v1.0.0 — Primera versión estable etiquetada

Esta versión consolida el sistema principal de alerta temprana contra grooming y la serie educativa de crecimiento y protección incluida en el repositorio.

## Sistema principal

- API FastAPI.
- Autenticación OAuth2/JWT con roles.
- Hash de contraseñas con Argon2.
- Cifrado de informes con AES-GCM.
- Auditoría encadenada con HMAC-SHA256.
- Controles HTTP defensivos y CORS restringido.
- Motor de jurisdicciones configurable.
- Migración y recuperación de estado de auditoría documentadas.
- CI con Ruff, mypy, pytest, Bandit, pip-audit y detect-secrets.

## Serie educativa original — 6/6

1. Cuaderno de Seguridad Digital para Chicos.
2. Organizador de Emociones.
3. Mi Rincón de Metas y Crecimiento.
4. Mi Espacio Seguro.
5. Libro de Recuerdos y Sueños.
6. Mi Primera Comunidad de Ayuda.

## Herramientas educativas complementarias

- Semáforo de Conversaciones Digitales.
- Escudo de Privacidad Digital.
- Laboratorio de Huella Digital.

## Instalación desde la raíz

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

La fuente canónica de versiones de dependencias continúa siendo `api/requirements.txt`.

## Seguridad

Las vulnerabilidades deben reportarse de forma privada siguiendo `SECURITY.md`. No publicar credenciales, datos de menores ni evidencia real en issues o Pull Requests.

Esta versión no implica que la herramienta sustituya procedimientos legales, institucionales o profesionales aplicables a cada jurisdicción.
