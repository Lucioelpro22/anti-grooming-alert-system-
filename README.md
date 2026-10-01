# 🛡️ Sistema de Alerta Temprana contra Grooming

Software de ciberseguridad diseñado para detectar, identificar y documentar conductas de grooming en entornos digitales. Genera informes técnicos formales para presentar ante plataformas digitales, justicia y organismos de protección infantil.

---

## 🌱 Serie educativa — 6 Herramientas de Crecimiento y Protección

Este repositorio también contiene una serie educativa local-first pensada para acompañar a niñas, niños y adolescentes. Para evitar confusiones, la **serie original** y las **herramientas complementarias** se muestran por separado.

### Serie original

| Nº | Proyecto original | Estado |
|---:|---|---|
| 1 | 📱 [Cuaderno de Seguridad Digital para Chicos](cuaderno-seguridad-digital/) | ✅ Implementado |
| 2 | 🧠 [Organizador de Emociones](organizador-emociones/) | ✅ Implementado |
| 3 | 🌱 [Mi Rincón de Metas y Crecimiento](rincon-metas-crecimiento/) | ✅ Implementado |
| 4 | 🛡️ [Mi Espacio Seguro](mi-espacio-seguro/) | ✅ Implementado |
| 5 | 📖 [Libro de Recuerdos y Sueños](libro-recuerdos-suenos/) | ✅ Implementado |
| 6 | 🤝 [Mi Primera Comunidad de Ayuda](primera-comunidad-ayuda/) | ✅ Implementado |

### Herramientas complementarias ya desarrolladas

Estas aplicaciones **no reemplazan** a los Proyectos 2, 3 y 4 originales; quedan visibles como módulos extra de seguridad digital:

- 🚦 [Semáforo de Conversaciones Digitales](semaforo-conversaciones-digitales/)
- 🛡️ [Escudo de Privacidad Digital](escudo-privacidad-digital/)
- 👣 [Laboratorio de Huella Digital](laboratorio-huella-digital/)

➡️ [Ver el mapa completo de la serie y los proyectos complementarios](SERIE_6_HERRAMIENTAS.md)

## 🎯 Funcionalidades
- ✅ Detección de patrones de riesgo en lenguaje y comportamiento
- ✅ Análisis de direcciones IP y datos de conexión
- ✅ Priorización neutral de indicadores para revisión humana
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
📅 Versión: 3.6.0

El sistema no identifica agresores ni determina culpabilidad. Sus resultados son
indicadores automatizados de apoyo y siempre requieren revisión humana.

## Seguridad V3.2

La API usa OAuth2 con tokens JWT de corta duración, contraseñas Argon2 y roles
`admin`, `analyst` y `auditor`. Los informes quedan vinculados a su creador; solo
su propietario, un administrador o un auditor pueden consultarlos.

`POST /logout` revoca inmediatamente el JWT actual hasta su expiración. El modo
`memory` es seguro únicamente para un proceso; en despliegues con varios workers
debe configurarse `TOKEN_REVOCATION_BACKEND=redis` junto con `REDIS_URL`.
Si el backend distribuido de revocación no está disponible, la validación de
tokens falla cerrada en lugar de aceptar un JWT cuya revocación no pueda comprobarse.

### Rotación de la clave de firma JWT

La API admite un key-ring versionado para rotar la clave HS256 sin invalidar de
golpe todas las sesiones activas. Los tokens nuevos incluyen un encabezado
`kid`; los tokens anteriores a este mecanismo, que no tienen `kid`, usan el ID
reservado `legacy`.

Para rotar desde una instalación que usa `JWT_SECRET`:

1. Generá un secreto nuevo con `python scripts/generate_jwt_secret.py`.
2. Configurá `JWT_SECRETS_JSON` con el secreto actual bajo `legacy` y el nuevo
   bajo otro ID, por ejemplo
   `{"legacy":"SECRETO_ANTERIOR","v2":"SECRETO_NUEVO"}`.
3. Configurá `JWT_CURRENT_KEY_ID=v2`. Desde ese momento los tokens nuevos salen
   firmados con `v2`, mientras los anteriores siguen verificándose con `legacy`.
4. Conservá la clave anterior al menos durante el TTL máximo de los tokens emitidos
   con ella. En la configuración actual los access tokens duran 15 minutos.
5. Pasada esa ventana, podés retirar `legacy` si ya no necesitás verificar tokens
   antiguos. Un token que referencia un `kid` retirado se rechaza con 401.
6. No reutilices el mismo secreto bajo varios IDs. Una key-ring inválida o sin
   clave activa hace que la autenticación falle cerrada con 503.

En rotaciones posteriores, agregá un nuevo ID, cambialo en
`JWT_CURRENT_KEY_ID` y conservá temporalmente las claves anteriores hasta que
caduquen todos los tokens firmados con ellas.

### Sesiones y refresh tokens de un solo uso

El login entrega un access token de corta duración y un refresh token opaco.
El refresh token contiene 256 bits de aleatoriedad y el servidor almacena
únicamente su hash SHA-256. Cada uso de `POST /token/refresh` consume el token
anterior y entrega uno nuevo: un refresh token usado no vuelve a ser válido.

Si un refresh token ya consumido aparece otra vez, se considera una posible
reutilización/robo de sesión. El sistema incrementa la versión de sesión del
usuario y revoca la familia completa: los access tokens y refresh tokens emitidos
con la versión anterior dejan de ser aceptados.

`POST /logout-all` aplica la misma invalidación global voluntariamente. Los
access tokens incluyen una versión de sesión firmada (`sv`), por lo que no es
necesario esperar sus 15 minutos de expiración para cerrar todas las sesiones.

`SESSION_BACKEND=memory` está pensado para desarrollo o un único proceso. En
producción con varios workers debe usarse `SESSION_BACKEND=redis` con
`REDIS_URL`; si el backend compartido no puede consultarse, la autenticación
falla cerrada. `REFRESH_TOKEN_DAYS` controla la vida máxima del refresh entre
1 y 30 días y vale 7 por defecto.

### Rate limiting distribuido de login y MFA

Los fallos de contraseña y de MFA se evalúan en tres dimensiones simultáneas,
todas con claves opacas SHA-256 para no exponer IP ni nombre de usuario en Redis:

- **pair**: mismo cliente + misma cuenta, para fuerza bruta focalizada;
- **account**: misma cuenta desde clientes distintos, para credential stuffing;
- **client**: mismo cliente rotando cuentas, para password spraying.

Los valores predeterminados son 5 fallos/300 s para `pair`, 10/900 s para
`account` y 20/300 s para `client`. Se configuran con
`LOGIN_PAIR_*`, `LOGIN_ACCOUNT_*` y `LOGIN_CLIENT_*`. Las variables antiguas
`LOGIN_RATE_LIMIT_ATTEMPTS` y `LOGIN_RATE_LIMIT_WINDOW_SECONDS` siguen
funcionando como fallback del scope `pair`.

Cuando un scope alcanza su umbral, el bloqueo usa backoff progresivo: comienza en
`LOGIN_BACKOFF_BASE_SECONDS` (30 s) y se duplica con reincidencias hasta
`LOGIN_BACKOFF_MAX_SECONDS` (900 s). El cliente siempre recibe el mismo 429
genérico con `Retry-After`; no se revela qué scope disparó la defensa.

Un login válido limpia el estado de la cuenta y del par cliente+cuenta, pero no
borra el historial global del cliente. Así una IP que está probando muchas
cuentas no puede limpiar el patrón con un único acceso válido.

`LOGIN_RATE_LIMIT_BACKEND=memory` es adecuado para desarrollo o un único
proceso. En producción con varios workers debe usarse
`LOGIN_RATE_LIMIT_BACKEND=redis` junto con `REDIS_URL`; todos los workers
comparten el mismo estado y no es posible repartir intentos entre procesos.

La respuesta de credenciales inválidas permanece genérica tanto para usuarios
existentes como inexistentes, y las cuentas inexistentes pasan por una
verificación Argon2 dummy para reducir account enumeration por diferencias de
flujo. La bitácora interna distingue `credential_stuffing_suspected`,
`password_spraying_suspected` y `login_rate_limited` sin exponer ese detalle
al cliente.

Si Redis no puede consultarse, el login falla cerrado con 503 y la bitácora de
seguridad registra `auth_backend_error` con severidad `critical`.

### MFA/2FA para roles sensibles

Por defecto, las cuentas con rol `admin`, `supervisor` y `auditor` deben
completar un segundo factor al iniciar sesión. El login acepta `mfa_code` en el
mismo formulario OAuth2: puede ser un código TOTP de 6 dígitos o un código de
recuperación de un solo uso.

El TOTP implementa RFC 6238 con período de 30 segundos, secreto Base32 de al menos
160 bits y una ventana temporal limitada. El backend registra el último contador
aceptado por usuario, por lo que el mismo TOTP no puede reutilizarse dentro de su
ventana.

Los códigos de recuperación se generan con alta entropía y solo se guardan como
hash SHA-256 en `MFA_USERS_JSON`. Cada código válido puede consumirse una sola
vez. Para generar el material de enrolamiento:

`python scripts/generate_mfa.py --username admin`

El comando muestra el secreto Base32, una URI `otpauth://` compatible con
aplicaciones autenticadoras y ocho códigos de recuperación. Guardá los códigos
en un lugar separado y seguro; el repositorio solo debe recibir sus hashes dentro
de la configuración.

`MFA_REQUIRED_ROLES_JSON` controla qué roles exigen MFA. El valor recomendado y
predeterminado es `["admin","supervisor","auditor"]`. Si un usuario de uno de
esos roles está activo pero no tiene entrada válida en `MFA_USERS_JSON`, la API
no inicia.

`MFA_STATE_BACKEND=memory` sirve para desarrollo o un solo proceso. En producción
multi-worker debe usarse `MFA_STATE_BACKEND=redis` con `REDIS_URL` para que la
protección contra replay y el consumo de recovery codes sean compartidos. Si ese
estado no puede consultarse, la autenticación falla cerrada.


### Bitácora de seguridad de autenticación

Los eventos de autenticación se registran en una bitácora separada de la cadena
de evidencias. Incluye login exitoso/fallido, fallos MFA, rate limiting, refresh
exitoso o inválido, detección de reutilización de refresh tokens, `logout`,
`logout-all` y errores de backends de autenticación.

Cada evento queda enlazado mediante `previous_hash` y firmado con el key-ring
HMAC de auditoría. La bitácora tiene además un checkpoint SQLite independiente:
si se modifica, trunca, borra o retrocede el historial sin actualizar ese
checkpoint confiable, el servicio detecta la inconsistencia y falla cerrado.

La bitácora no recibe contraseñas, JWT, refresh tokens, secretos o códigos MFA ni
recovery codes. Usuario, IP y User-Agent se convierten en referencias HMAC
estables antes de escribirse. Se conservan el rol, tipo de evento, motivo,
severidad y `request_id` para correlación operativa.

Los eventos `warning` y `critical` llevan `alert=true`. La reutilización de
refresh tokens y los fallos de backends de autenticación se marcan como
`critical`, dejando el formato listo para integrarlo luego con un SIEM o un
pipeline de notificaciones sin exponer credenciales.

Configurá `SECURITY_AUDIT_DIR` y `SECURITY_AUDIT_STATE_DB` en ubicaciones
separadas y protegidas; el checkpoint no puede estar dentro del directorio del
log. Ambos deben respaldarse de forma independiente.


Los informes se almacenan cifrados con AES-256-GCM. Sus metadatos están
autenticados y cada creación, lectura o acceso denegado se registra en una
cadena de auditoría firmada con HMAC-SHA256. Las escrituras son atómicas y el
servicio falla de forma segura si detecta una alteración o una clave inválida.

El perímetro HTTP limita el tamaño real de las solicitudes y su frecuencia por
cliente, valida el encabezado `Host`, agrega identificadores de solicitud y
cabeceras defensivas, y mantiene CORS cerrado salvo los orígenes declarados.

Antes de iniciar la API:

1. Copiá `.env.example` a un archivo local `.env` que nunca debe subirse.
2. Generá `JWT_SECRET` con `openssl rand -hex 32` o
   `python scripts/generate_jwt_secret.py`. Para rotación sin corte de sesiones,
   usá `JWT_SECRETS_JSON` y `JWT_CURRENT_KEY_ID`.
3. Generá hashes con `python scripts/hash_password.py`.
4. Definí los usuarios en `AUTH_USERS_JSON` usando únicamente hashes Argon2.
5. Ejecutá `python scripts/generate_security_keys.py` y guardá las tres claves
   generadas en `EVIDENCE_ENCRYPTION_KEY`, `AUDIT_HMAC_KEY` y
   `PSEUDONYMIZATION_HMAC_KEY`. Las tres deben ser distintas. Conservá la clave
   de seudonimización para mantener identificadores estables entre informes.
6. Configurá `SECURITY_AUDIT_DIR` y `SECURITY_AUDIT_STATE_DB` en
   ubicaciones separadas con permisos y respaldos independientes.
7. Configurá `ALLOWED_HOSTS_JSON` con los dominios reales del servicio. Solo si
   existe un frontend web, agregá sus orígenes exactos a `ALLOWED_ORIGINS_JSON`.

Cada push a `main` o a una rama de seguridad, y cada Pull Request hacia `main`,
ejecuta automáticamente las pruebas, formato, lint, tipos, Bandit, pip-audit,
detect-secrets y auditoría de dependencias mediante GitHub Actions.

La capa de jurisdicciones permite adaptar idioma, canales de reporte, retención
operativa y revisión transfronteriza sin mezclar reglas de un país con otro.
Incluye perfiles iniciales para Argentina, Estados Unidos, Brasil, Reino Unido
y un perfil regional europeo. Estos valores son configuración operativa y deben
ser revisados por asesoría legal local antes de usarse en producción.

No hay credenciales predeterminadas y el servicio falla de forma segura si la
configuración de autenticación está ausente o es inválida.

## Actualización de evidencia y auditoría

Antes de iniciar, exportá las variables del entorno: la aplicación no carga `.env`
automáticamente. Se verifican el secreto JWT, hashes de usuarios, claves Base64 de
32 bytes distintas y `AUDIT_STATE_DB`. Los ejemplos no son valores operativos.

`AUDIT_STATE_DB` debe apuntar a una base SQLite fuera de `informes_generados`, en
un directorio con permisos y copias de seguridad independientes. Todos los workers
de una instalación deben compartir esa misma base en disco local. La transacción
serializa las operaciones entre procesos y conserva el contador y hash final de
la auditoría. No usar este diseño sobre NFS ni para réplicas con discos separados.

Los informes nuevos usan esquema 2 y conservan exactamente el texto recibido.
Se siguen leyendo los informes de esquema 1, tanto texto como JSON. La respuesta
conserva `contenido` y añade `report_text`, `original_message_content` y
`analysis_result`. En informes antiguos sin texto original, ese campo es `null`:
no puede reconstruirse evidencia que nunca se guardó.

Para una instalación nueva no hace falta migración. Para una existente:

1. Detené todos los workers y respaldá las evidencias, claves y auditoría.
2. Contrastá el historial HMAC con un respaldo independiente confiable y obtené
   su cantidad de entradas y hash final revisados. La firma por sí sola no prueba
   que el historial antiguo no haya sido truncado.
3. Configurá `AUDIT_STATE_DB` y ejecutá desde la raíz del repositorio:
   `python -m scripts.migrate_audit --entries CANTIDAD --head HASH_REVISADO`.
4. Iniciá la API. Una discrepancia o historial ausente impide su arranque.

Un fallo entre la escritura del historial y la confirmación del checkpoint deja
el servicio bloqueado de forma segura. Requiere reconciliar ambos respaldos con
revisión operativa; no borrar la base ni aceptar automáticamente el historial actual.
La protección detecta cambios en los informes/auditoría mientras el checkpoint es
confiable. Un atacante que controle ambos destinos o el proceso con sus claves
requiere protección adicional, como un registro externo inmutable.

### Rotación de la clave HMAC de auditoría

La cadena de auditoría admite un key-ring versionado sin volver a firmar el
historial. Las entradas nuevas incluyen `audit_key_id`; las entradas históricas
anteriores a este mecanismo se verifican con el ID reservado `legacy`.

Para rotar desde una instalación que usa `AUDIT_HMAC_KEY`:

1. Detené todos los workers y respaldá el historial, el checkpoint y la
   configuración de claves.
2. Conservá la clave actual: seguirá siendo necesaria para verificar las entradas
   históricas. Generá una nueva con `python scripts/generate_audit_key.py`.
3. Configurá `AUDIT_HMAC_KEYS_JSON` con la clave anterior bajo el ID literal
   `legacy` y la nueva con un ID nuevo, por ejemplo
   `{"legacy":"CLAVE_ANTERIOR","v2":"CLAVE_NUEVA"}`.
4. Configurá `AUDIT_HMAC_CURRENT_KEY_ID=v2` y reiniciá el servicio.
5. Verificá la cadena completa antes de reanudar operación. Las nuevas entradas
   quedarán firmadas con `v2`, enlazadas al mismo `previous_hash` del historial.
6. No elimines una clave histórica del key-ring mientras existan entradas firmadas
   con ese ID. Si falta una clave requerida, la verificación falla cerrada.

En rotaciones posteriores, conservá todos los IDs todavía referenciados por el
historial y agregá el nuevo ID como clave activa. La rotación cambia la clave que
firma entradas futuras; no modifica ni resigna entradas anteriores.

## Segunda etapa de operación

Los estados de evidencia se cambian mediante `PATCH /informe/{id}/estado` y
requieren rol `admin` o `supervisor`. Un informe en `LEGAL_HOLD` no puede pasar a
eliminación. Para despliegues con varios workers, definí `RATE_LIMIT_BACKEND=redis`,
`LOGIN_RATE_LIMIT_BACKEND=redis`, `TOKEN_REVOCATION_BACKEND=redis`,
`SESSION_BACKEND=redis`, `MFA_STATE_BACKEND=redis` y `REDIS_URL`; si Redis
no responde, los controles
distribuidos fallan cerrados. Para persistencia
centralizada, configurá un `DATABASE_URL` PostgreSQL y desplegá explícitamente el
repositorio SQLAlchemy; la aplicación no migra ni cambia de almacenamiento sola.
