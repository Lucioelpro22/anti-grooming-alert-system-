# 🛡️ Mi Espacio Seguro

**Proyecto Nº 4 de 6 — Serie original**

PWA local-first para detenerse, recibir una guía de calma, registrar una situación de forma cifrada y pedir acompañamiento a una persona de confianza.

## Privacidad
- IndexedDB local.
- PBKDF2-SHA-256, 250.000 iteraciones.
- AES-GCM por registro.
- La contraseña no se guarda.
- Contacto y registros cifrados.
- Sin nube, ubicación, telemetría ni reportes automáticos.

## Avisos
El botón para avisar prepara un mensaje genérico mediante la función Compartir del dispositivo o SMS si hay teléfono guardado. **Nunca envía nada sin una acción explícita del usuario.**

## Ejecutar
~~~bash
cd mi-espacio-seguro
pip install -r requirements.txt
uvicorn api.main:app --reload --port 8008
~~~

MIT · Lucioelpro22
