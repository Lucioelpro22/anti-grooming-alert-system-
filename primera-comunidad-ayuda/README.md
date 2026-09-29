# 🤝 Mi Primera Comunidad de Ayuda

**Proyecto Nº 6 de 6 — Serie de Herramientas de Crecimiento y Protección**  
Autor: **Lucioelpro22** · Licencia: **MIT** · Idioma: Español (Argentina)

Aplicación web progresiva y local-first para que niñas, niños y adolescentes practiquen solidaridad, gratitud, empatía y ayuda responsable.

## Objetivos

- Registrar buenas acciones sin convertirlas en una competencia.
- Proponer desafíos solidarios pequeños y alcanzables.
- Reconocer la ayuda que recibimos.
- Aprender que ayudar también requiere límites.
- Saber cuándo un problema necesita una persona adulta de confianza.
- Reforzar que nunca hace falta compartir contraseñas, dinero, datos privados o contenido íntimo para demostrar bondad.

## Módulos

### 💚 Buenas acciones
Registro local de gestos de ayuda y cómo hicieron sentir al usuario.

### 🌱 Desafíos
8 desafíos integrados más desafíos personalizados. No existen premios competitivos ni rankings.

### 🌟 Gratitud
Frasco local para registrar cosas por las que el usuario siente agradecimiento.

### 🧭 Ayudar con límites
6 reglas personales y 10 situaciones prácticas sobre ayuda segura, secretos peligrosos, contraseñas, dinero, presión y búsqueda de apoyo adulto.

### 📘 Mi recorrido
Resumen de acciones, desafíos y gratitudes, progreso personal y una frase propia de comunidad.

## Lo que NO es

No es una red social.

No incluye:
- cuentas públicas;
- perfiles visibles;
- chat;
- seguidores;
- ranking de menores;
- mapa;
- ubicación;
- publicación de fotos;
- contacto entre desconocidos;
- mensajería privada;
- publicidad;
- telemetría.

## Privacidad

Los datos se guardan únicamente en `localStorage` del navegador y pueden borrarse desde la interfaz.

Los textos deberían mantenerse generales y no incluir direcciones, teléfonos, escuela, nombres completos ni otra información sensible.

## Seguridad

- CSP limitada a `self`.
- `Referrer-Policy: no-referrer`.
- `X-Content-Type-Options: nosniff`.
- Cámara, micrófono, geolocalización, pagos y USB deshabilitados.
- Sin recursos remotos.
- PWA offline.
- Tests, Ruff y Gitleaks.

## Instalación

~~~bash
cd primera-comunidad-ayuda
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn api.main:app --reload --port 8005
~~~

Abrir `http://127.0.0.1:8005`.

## Pruebas

~~~bash
pytest -q
~~~

## Principio central

**Ayudar no significa resolver todo, competir por ser “mejor” ni exponerse a riesgos.** Escuchar, poner límites y pedir apoyo también son formas de solidaridad.

## Licencia

MIT, conforme al repositorio principal.
