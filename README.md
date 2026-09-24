# 🛡️ Sistema de Alerta Temprana contra Grooming

Software de ciberseguridad diseñado para detectar, identificar y documentar conductas de grooming en entornos digitales. Genera informes técnicos formales para presentar ante plataformas digitales, justicia y organismos de protección infantil.

---

## 🎯 Funcionalidades
- ✅ Detección de patrones de riesgo en lenguaje y comportamiento
- ✅ Análisis de direcciones IP y datos de conexión
- ✅ Identificación de perfiles: probable agresor / en seguimiento / sin riesgo
- ✅ Generación automática de informes técnicos con ID único
- ✅ Conjunto completo de casos de prueba para validación
- ✅ Guía de presentación ante organismos públicos y privados

## ⚙️ Tecnología
- API construida con **FastAPI**
- Análisis de patrones por expresiones regulares
- Informes en formato texto estructurado
- Compatible con normativa vigente en Argentina

## ⚖️ Marco Legal — Argentina
- 📜 Ley 26.388 — Delitos informáticos
- 📜 Ley 26.061 — Protección Integral de los Derechos de Niñas, Niños y Adolescentes
- 📜 Convención sobre los Derechos del Niño — ONU

## ⚠️ Aviso Importante
> Esta herramienta es de apoyo y soporte. **No sustituye la denuncia formal** ante autoridades competentes. Ante cualquier sospecha real:
> - Preservá toda la evidencia
> - Denunciá de inmediato en la comisaría más cercana o al **102**
> - Toda información por IP requiere mandamiento judicial para identificar al titular

---

🔗 Autor: @Lucioelpro22
📅 Versión: 1.0.0

## Seguridad V3.2

La API usa OAuth2 con tokens JWT de corta duración, contraseñas Argon2 y roles
`admin`, `analyst` y `auditor`. Los informes quedan vinculados a su creador; solo
su propietario, un administrador o un auditor pueden consultarlos.

Los informes se almacenan cifrados con AES-256-GCM. Sus metadatos están
autenticados y cada creación, lectura o acceso denegado se registra en una
cadena de auditoría firmada con HMAC-SHA256. Las escrituras son atómicas y el
servicio falla de forma segura si detecta una alteración o una clave inválida.

El perímetro HTTP limita el tamaño real de las solicitudes y su frecuencia por
cliente, valida el encabezado `Host`, agrega identificadores de solicitud y
cabeceras defensivas, y mantiene CORS cerrado salvo los orígenes declarados.

Antes de iniciar la API:

1. Copiá `.env.example` a un archivo local `.env` que nunca debe subirse.
2. Generá `JWT_SECRET` con `openssl rand -hex 32`.
3. Generá hashes con `python scripts/hash_password.py`.
4. Definí los usuarios en `AUTH_USERS_JSON` usando únicamente hashes Argon2.
5. Ejecutá `python scripts/generate_security_keys.py` y guardá las dos claves
   generadas en `EVIDENCE_ENCRYPTION_KEY` y `AUDIT_HMAC_KEY`. Deben ser distintas.
6. Configurá `ALLOWED_HOSTS_JSON` con los dominios reales del servicio. Solo si
   existe un frontend web, agregá sus orígenes exactos a `ALLOWED_ORIGINS_JSON`.

Cada push a `main` o a una rama de seguridad, y cada Pull Request hacia `main`,
ejecuta automáticamente las pruebas, formato, lint, tipos, Bandit, pip-audit,
detect-secrets y revisión de dependencias mediante GitHub Actions.

No hay credenciales predeterminadas y el servicio falla de forma segura si la
configuración de autenticación está ausente o es inválida.
