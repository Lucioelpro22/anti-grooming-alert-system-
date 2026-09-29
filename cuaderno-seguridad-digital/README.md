# 📘 Cuaderno de Seguridad Digital para Niñas, Niños y Adolescentes

**Proyecto Nº 1 de 6 — Serie de Herramientas de Crecimiento y Protección**  
Autor: **Lucioelpro22** · Licencia: **MIT** · Idioma: Español (Argentina)

Aplicación web progresiva, educativa, liviana y **local-first**. Ayuda a niñas, niños y adolescentes a practicar hábitos de privacidad, reconocer situaciones incómodas y pedir ayuda sin miedo ni castigos.

## Principios

- Lenguaje cercano, no alarmista.
- Móvil primero y accesible.
- Funciona sin cuentas, publicidad, analítica ni redes sociales.
- Los datos personales del cuaderno permanecen en el almacenamiento local del navegador.
- El botón de ayuda **no denuncia ni envía información automáticamente**.
- Código abierto y auditable.

## Funciones

- 📘 **Mi Cuaderno**: privacidad, reglas, personas de confianza y Línea 102.
- 🎮 **Aprendo Jugando**: 10 situaciones con retroalimentación positiva, sin puntajes.
- 🛡️ **Botón de Calma y Acción**: guía inmediata, registro local y compartir aviso mediante funciones del dispositivo.
- 📱 **Mi Espacio**: nombre/apodo, color, avatar, progreso, PIN local y reinicio.
- 📦 **PWA/offline**: manifest + service worker.

## Instalación

Requiere Python 3.11+.

~~~bash
cd cuaderno-seguridad-digital
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn api.main:app --reload
~~~

Abrir: `http://127.0.0.1:8000`

## Pruebas

~~~bash
cd cuaderno-seguridad-digital
pytest -q
~~~

## Privacidad y seguridad

La app no requiere base de datos. Notas, personas de confianza, preferencias, progreso, registro del botón de ayuda y hash del PIN se almacenan con `localStorage` en el dispositivo.

El PIN es un **bloqueo de conveniencia**, no una medida criptográfica equivalente al bloqueo del sistema operativo. No debe utilizarse para guardar secretos de alto riesgo.

No se cargan fuentes, scripts, trackers ni recursos remotos desde la interfaz principal.

## Estructura

~~~text
cuaderno-seguridad-digital/
├── api/
│   └── main.py
├── static/
│   ├── app.css
│   ├── app.js
│   ├── icon.svg
│   ├── manifest.webmanifest
│   └── sw.js
├── templates/
│   └── index.html
├── docs/
│   ├── guia-padres.md
│   ├── guia-legal.md
│   └── plan-futuro.md
├── tests/
│   └── test_app.py
├── .env.example
├── requirements.txt
└── README.md
~~~

## Uso en familias y escuelas

Se recomienda presentar el cuaderno acompañado por una persona adulta, docente u orientador/a. La herramienta sirve para iniciar conversaciones y practicar respuestas; no reemplaza el diálogo, la asistencia profesional ni los canales oficiales de protección.

## Contribuir

1. Crear una rama.
2. Mantener lenguaje simple y respetuoso.
3. No agregar telemetría ni recolección de datos sin una revisión específica de privacidad.
4. Agregar o actualizar pruebas.
5. Abrir un Pull Request explicando el cambio y su impacto para niñas, niños y adolescentes.

## Licencia

MIT. Ver la licencia del repositorio base.
