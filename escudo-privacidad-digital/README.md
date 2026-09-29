# 🛡️ Escudo de Privacidad Digital

**Proyecto Nº 3 de 6 — Serie de Herramientas de Crecimiento y Protección**  
Autor: **Lucioelpro22** · Licencia: **MIT** · Idioma: Español (Argentina)

Aplicación web progresiva para que niñas, niños y adolescentes aprendan a proteger datos personales, cuentas, dispositivos y permisos sin ingresar contraseñas reales ni conectar servicios externos.

## Objetivos

- Reconocer qué datos conviene proteger.
- Entender que contraseñas y códigos de verificación son llaves privadas.
- Practicar decisiones sobre permisos de cámara, micrófono, ubicación y archivos.
- Frenar la urgencia ante mensajes que intentan robar acceso.
- Crear hábitos de actualización, bloqueo de pantalla, 2FA y recuperación segura.

## Módulos

### 🔐 Mis datos
12 ejemplos para distinguir entre datos que se protegen, datos que conviene revisar con una persona de confianza y datos generales menos sensibles.

### 🗝️ Mis llaves
Generador local de **frases de práctica inventadas**. Nunca solicita ni almacena una contraseña real.

### 📱 Permisos
Simulador educativo de permisos. No cambia permisos reales del dispositivo.

### 🕵️ Verifico primero
10 situaciones inventadas para practicar cómo detectar urgencia, enlaces dudosos, falsos soportes y pedidos de códigos.

### ✅ Mi escudo
Checklist de hábitos, persona adulta de recuperación y progreso local.

## Privacidad

La app guarda únicamente progreso educativo, elecciones del simulador y el nombre/relación de una persona de recuperación si el usuario decide ingresarlos.

No contiene:
- formularios de contraseña;
- conexión con cuentas;
- lectura de correos o chats;
- analítica;
- publicidad;
- trackers;
- recursos remotos.

## Seguridad técnica

- CSP restrictiva.
- `Referrer-Policy: no-referrer`.
- `X-Content-Type-Options: nosniff`.
- Permissions Policy que deshabilita cámara, micrófono, geolocalización, pagos y USB.
- PWA offline.
- Tests automatizados, Ruff y Gitleaks.

## Instalación

~~~bash
cd escudo-privacidad-digital
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn api.main:app --reload --port 8002
~~~

Abrir: `http://127.0.0.1:8002`

## Pruebas

~~~bash
pytest -q
~~~

## Principio central

**La app enseña a proteger credenciales; nunca debe convertirse en un lugar donde se escriban credenciales reales.**

## Licencia

MIT, conforme al repositorio principal.
