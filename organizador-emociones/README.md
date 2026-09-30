# 🧠 Organizador de Emociones

**Proyecto Nº 2 de 6 — Serie original de Herramientas de Crecimiento y Protección**

Aplicación PWA local-first para registrar emociones, observar el mes en colores, guardar recursos personales y compartir un resumen únicamente cuando el usuario lo decide.

## Principios
- Sin diagnóstico automático.
- Sin puntuación de emociones como buenas o malas.
- Sin cuentas, publicidad, telemetría ni recursos externos.
- Datos en el navegador del dispositivo.
- Compartir es siempre una acción explícita del usuario.

## Ejecutar
~~~bash
cd organizador-emociones
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8006
~~~

## Privacidad
Los registros pueden ser sensibles. En dispositivos compartidos se recomienda usar perfiles separados y borrar los datos locales cuando corresponda.

MIT · Lucioelpro22
