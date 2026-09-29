# Modelo de amenazas

## Activos

- Progreso educativo.
- Preferencias del simulador.
- Nombre opcional de persona de recuperación.
- Privacidad del dispositivo y del navegador.

## Amenazas

### Captura accidental de credenciales
Un usuario podría creer que debe probar una contraseña real.

**Mitigación:** no existe campo de contraseña; la interfaz repite que solo se usan ejemplos inventados.

### Exposición por recursos externos
Un script o tracker podría observar actividad.

**Mitigación:** CSP `self`, sin recursos remotos ni analítica.

### Uso de permisos innecesarios
La app podría solicitar sensores del dispositivo.

**Mitigación:** no utiliza esas APIs y las bloquea por Permissions Policy.

### Dispositivo compartido
Otra persona con acceso al mismo perfil del navegador podría ver progreso o el nombre de recuperación.

**Mitigación:** minimización de datos, reinicio local y recomendación de bloqueo/perfiles del sistema.

### Falsa sensación de seguridad
Completar el proyecto no garantiza que una cuenta o dispositivo sea invulnerable.

**Mitigación:** el contenido presenta hábitos y prácticas, no certificaciones ni promesas de seguridad.

## Fuera de alcance

- gestión real de contraseñas;
- almacenamiento de secretos;
- recuperación automática de cuentas;
- análisis de malware;
- administración remota del dispositivo.
