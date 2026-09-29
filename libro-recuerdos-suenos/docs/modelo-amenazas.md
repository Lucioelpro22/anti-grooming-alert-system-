# Modelo de amenazas

## Activos

- Textos personales.
- Fotos de recuerdos.
- Sueños.
- Cartas al futuro.
- Nombre/apodo y frase de portada.

## Amenazas consideradas

### Lectura directa del almacenamiento del navegador
**Mitigación:** contenido cifrado con AES-GCM; la contraseña no se guarda.

### Robo del archivo de respaldo
**Mitigación:** el respaldo conserva los registros cifrados.

### Carga accidental a terceros
**Mitigación:** la aplicación no implementa sincronización, telemetría ni APIs de almacenamiento remoto.

### Foto excesivamente grande
**Mitigación:** validación de tamaño y reducción local antes de cifrar.

### Sesión abierta olvidada
**Mitigación:** cierre manual y bloqueo automático por inactividad.

### Dispositivo compartido
**Mitigación:** el contenido vuelve a quedar bloqueado tras cerrar o recargar.

## Fuera de alcance

- dispositivo comprometido por malware;
- keyloggers;
- extensiones maliciosas;
- extracción forense avanzada mientras la sesión está desbloqueada;
- recuperación de contraseña perdida.
