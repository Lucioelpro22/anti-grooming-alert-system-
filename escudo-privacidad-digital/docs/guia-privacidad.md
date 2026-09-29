# Guía de privacidad del proyecto

## Minimización

El diseño evita recopilar la información que pretende enseñar a proteger. No existe un campo para contraseñas reales, códigos de verificación, correos completos ni documentos.

## Datos locales

El progreso se guarda en `localStorage`:
- avance de prácticas;
- checklist educativo;
- selecciones del simulador de permisos;
- nombre y relación opcional de una persona de recuperación.

No se envían a un servidor.

## Permisos del navegador

La aplicación no necesita cámara, micrófono, ubicación, pagos ni USB. Las cabeceras HTTP los deshabilitan mediante Permissions Policy.

## Recursos de terceros

La interfaz no carga fuentes, imágenes, scripts ni analítica de terceros. Esto reduce rastreo y dependencias externas.

## Futuras funciones

Cualquier sincronización deberá ser opcional, tener propósito claro, minimizar datos y pasar por una revisión específica de privacidad infantil antes de incorporarse.
