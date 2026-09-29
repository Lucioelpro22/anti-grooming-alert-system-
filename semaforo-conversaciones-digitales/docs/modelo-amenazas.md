# Modelo de amenazas básico

## Activos a proteger

- Lista local de personas de confianza.
- Preferencias y progreso.
- Registro local de uso del botón de ayuda.
- Privacidad del dispositivo.

## Amenazas consideradas

### Dispositivo compartido
Otra persona con acceso al mismo perfil del navegador podría leer datos locales.

**Mitigación:** minimizar datos y recomendar bloqueo del dispositivo. No guardar chats reales.

### Recursos externos
Una dependencia web externa podría rastrear actividad.

**Mitigación:** interfaz sin recursos remotos y CSP `self`.

### Permisos innecesarios
Cámara, micrófono o ubicación podrían exponer información.

**Mitigación:** la app no los solicita y la respuesta HTTP los deshabilita por política.

### Envío involuntario
Un botón podría transmitir información sin comprenderlo.

**Mitigación:** ninguna acción de red transmite contenido personal. El aviso externo solo se inicia tras una acción explícita del usuario.

### Contenido sensible
Pegar conversaciones reales podría generar almacenamiento de material privado o ilegal.

**Mitigación:** la interfaz no ofrece captura ni análisis de chats reales.

## Fuera de alcance

El proyecto no sustituye las medidas de seguridad del sistema operativo ni pretende resistir a una persona con control físico completo del dispositivo.
