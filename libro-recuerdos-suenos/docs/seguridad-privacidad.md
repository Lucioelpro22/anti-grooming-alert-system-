# Seguridad y privacidad

## Arquitectura

- FastAPI sirve HTML, CSS, JavaScript, manifest e icono.
- Los recuerdos no se envían a FastAPI.
- IndexedDB contiene metadatos de bóveda y registros cifrados.
- La clave de cifrado existe solo en memoria mientras el libro está abierto.

## Derivación y cifrado

La contraseña se transforma en una clave AES de 256 bits mediante PBKDF2 con SHA-256, una sal aleatoria y 250.000 iteraciones.

Cada objeto se cifra por separado con AES-GCM y un IV aleatorio de 96 bits.

La base guarda:
- sal de derivación;
- verificador cifrado;
- IV y ciphertext de cada entrada.

No guarda la contraseña.

## Bloqueo

- Botón manual “Cerrar libro”.
- Bloqueo automático tras aproximadamente 10 minutos sin interacción.
- Recargar la página vuelve a requerir contraseña.

## Cabeceras

- Content Security Policy limitada a `self`.
- Imágenes locales `data:` y `blob:` para recuerdos.
- `Referrer-Policy: no-referrer`.
- `X-Content-Type-Options: nosniff`.
- Cámara, micrófono, geolocalización, pagos y USB deshabilitados.

## Límites de seguridad

El cifrado protege principalmente datos en reposo frente a lectura casual de la base del navegador. No protege contra:
- malware ejecutándose con los permisos del usuario;
- una extensión maliciosa con acceso suficiente;
- captura de pantalla mientras el libro está abierto;
- una persona que conozca la contraseña.

No se debe describir como una bóveda de seguridad de nivel forense.
