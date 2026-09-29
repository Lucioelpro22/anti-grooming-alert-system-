# 📖 Libro de Recuerdos y Sueños

**Proyecto Nº 5 de 6 — Serie de Herramientas de Crecimiento y Protección**  
Autor: **Lucioelpro22** · Licencia: **MIT** · Idioma: Español (Argentina)

Libro digital personal para guardar recuerdos, fotos opcionales, sueños y cartas al futuro. Funciona localmente y cifra el contenido con una contraseña propia del libro.

## Qué permite

- 📸 Guardar recuerdos con título, fecha, texto y foto opcional.
- 🌈 Registrar sueños: aprender, crear, ser, conocer, viajar o ayudar.
- 💌 Escribir cartas para abrir a partir de una fecha futura.
- 🎨 Personalizar portada con nombre/apodo, frase y color.
- 💾 Descargar e importar un respaldo cifrado.
- 🔒 Cerrar el libro manualmente y bloqueo automático por inactividad.
- 📱 Instalarlo como PWA y utilizarlo sin conexión.

## Privacidad y cifrado

El contenido se guarda en **IndexedDB** del navegador.

La contraseña:
- se usa para derivar una clave con **PBKDF2-SHA-256**;
- cifra el contenido con **AES-GCM**;
- no se almacena;
- no se envía al servidor;
- no debe reutilizarse de correo, redes sociales o juegos.

Las fotos se reducen de tamaño en el dispositivo antes de cifrarse.

### Importante

Si se pierde la contraseña, el proyecto no incluye una puerta trasera para recuperar el contenido. Esto es una consecuencia intencional del cifrado local.

Un usuario con control completo del dispositivo o malware local queda fuera del modelo de protección de esta app.

## Sin nube por defecto

No hay:
- cuentas externas;
- sincronización;
- telemetría;
- publicidad;
- trackers;
- servicios de fotos;
- APIs de terceros.

FastAPI únicamente entrega los archivos de la aplicación.

## Respaldo

El botón **Descargar respaldo cifrado** genera un JSON con los datos ya cifrados. Para abrirlo en otro dispositivo se necesita la misma contraseña.

Conviene guardar el archivo en un lugar seguro, porque borrar los datos del navegador también puede borrar el libro local.

## Instalación

~~~bash
cd libro-recuerdos-suenos
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
uvicorn api.main:app --reload --port 8004
~~~

Abrir `http://127.0.0.1:8004`.

## Pruebas

~~~bash
pytest -q
~~~

## Límites

Este proyecto no pretende reemplazar un gestor profesional de contraseñas, una solución de respaldo del sistema operativo ni un servicio de almacenamiento seguro administrado.

## Licencia

MIT, conforme al repositorio principal.
