# 🚦 Semáforo de Conversaciones Digitales

**Proyecto Nº 2 de 6 — Serie de Herramientas de Crecimiento y Protección**  
Autor: **Lucioelpro22** · Licencia: **MIT** · Idioma: Español (Argentina)

Aplicación web progresiva y educativa para que niñas, niños y adolescentes practiquen cómo reconocer señales verdes, amarillas y rojas en conversaciones digitales, poner límites y pedir ayuda.

## Qué NO hace

- No analiza chats reales.
- No lee mensajes de otras aplicaciones.
- No vigila al niño/a.
- No usa IA para perfilar conversaciones.
- No envía denuncias, alertas ni datos automáticamente.
- No requiere cuentas, publicidad ni servicios externos.

## Módulos

### 🚦 Mi semáforo
Explica señales verdes, amarillas y rojas con lenguaje simple y acciones sugeridas.

### 💬 Practico
Incluye 12 situaciones inventadas para reconocer el color de una interacción. No hay puntajes ni castigos.

### 🧭 Mis límites
Permite marcar límites personales y practicar frases cortas para cortar una conversación o pedir apoyo.

### 🛟 Plan de salida
Guía paso a paso: parar, salir, conservar evidencia con apoyo adulto, contar y pedir ayuda.

## Privacidad

Los únicos datos editables —límites seleccionados, progreso, personas de confianza y registro de uso del botón de ayuda— quedan en `localStorage` del dispositivo.

La aplicación no incluye campos para pegar conversaciones reales. Esta decisión reduce el riesgo de almacenar contenido sensible.

## Seguridad técnica

- Content Security Policy restrictiva.
- Sin scripts, fuentes ni recursos remotos.
- `Referrer-Policy: no-referrer`.
- `X-Content-Type-Options: nosniff`.
- Cámara, micrófono y geolocalización deshabilitados mediante Permissions Policy.
- Workflow independiente con tests, Ruff y Gitleaks.

## Instalar y ejecutar

~~~bash
cd semaforo-conversaciones-digitales
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn api.main:app --reload --port 8001
~~~

Abrir `http://127.0.0.1:8001`.

## Pruebas

~~~bash
pytest -q
~~~

## Contribuciones

Los cambios deben mantener:
1. lenguaje no alarmista;
2. ausencia de vigilancia o análisis oculto;
3. minimización de datos;
4. accesibilidad;
5. pruebas automatizadas;
6. explicación clara de cualquier nueva transferencia de datos.

## Licencia

MIT, conforme a la licencia del repositorio principal.
