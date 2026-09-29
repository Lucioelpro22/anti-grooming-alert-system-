# 👣 Laboratorio de Huella Digital

**Proyecto Nº 4 de 6 — Serie de Herramientas de Crecimiento y Protección**  
Autor: **Lucioelpro22** · Licencia: **MIT** · Idioma: Español (Argentina)

Aplicación web progresiva para que niñas, niños y adolescentes practiquen cómo pensar antes de publicar, reconocer información indirecta, respetar el consentimiento de otras personas y revisar su huella digital.

## Objetivos

- Entender que una publicación puede revelar más de lo que parece.
- Distinguir datos directos, indirectos y compartidos.
- Pensar en audiencia, ubicación, rutinas y capturas.
- Pedir permiso antes de publicar a otras personas.
- Revisar publicaciones, etiquetas y cuentas antiguas.
- Saber qué hacer si se quiere retirar algo de internet.

## Módulos

### 👣 Mi huella
Explica huella directa, indirecta y compartida.

### 📣 Antes de publicar
12 situaciones ficticias con tres decisiones: publicar, revisar o no publicar.

### 📷 Fotos y permiso
8 situaciones sobre consentimiento, audiencia, etiquetas y cambios de decisión.

### 🧪 Simulador
Permite marcar qué información aparece en una publicación ficticia y muestra qué conviene revisar. No permite subir imágenes reales.

### 🧹 Reviso mi huella
Checklist local para revisar biografía, publicaciones antiguas, etiquetas, audiencia, ubicación y cuentas viejas.

## Privacidad por diseño

La app no incluye:
- carga de fotos;
- nombres de usuario reales;
- conexión con redes sociales;
- búsqueda de perfiles;
- analítica;
- publicidad;
- recursos remotos.

El progreso se guarda únicamente en `localStorage`.

## Seguridad

- CSP restrictiva.
- `Referrer-Policy: no-referrer`.
- `X-Content-Type-Options: nosniff`.
- Cámara, micrófono, geolocalización, pagos y USB deshabilitados.
- PWA offline.
- Tests, Ruff y Gitleaks.

## Instalación

~~~bash
cd laboratorio-huella-digital
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn api.main:app --reload --port 8003
~~~

Abrir: `http://127.0.0.1:8003`

## Pruebas

~~~bash
pytest -q
~~~

## Principio central

**Pensar antes de publicar es más fácil que intentar recuperar el control después.** Borrar contenido puede ayudar, pero no garantiza que no existan copias o capturas.

## Licencia

MIT, conforme al repositorio principal.
