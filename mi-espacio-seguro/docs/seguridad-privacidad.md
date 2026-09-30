# Seguridad y privacidad

Los registros y el contacto de confianza se cifran localmente con AES-GCM. La clave se deriva de la contraseña mediante PBKDF2-SHA-256 y una sal aleatoria.

La clave existe solo en memoria mientras el espacio está abierto. Hay cierre manual y bloqueo por inactividad.

Límites: no protege contra malware, keyloggers, extensiones maliciosas o una persona que conozca la contraseña.
