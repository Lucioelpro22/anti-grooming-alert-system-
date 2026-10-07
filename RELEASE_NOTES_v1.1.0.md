# v1.1.0 — Autenticación y despliegue endurecidos

Esta versión consolida los cambios de seguridad integrados después de v1.0.0.
La versión de distribución del repositorio es 1.1.0; la API conserva su versión
3.5.0, que identifica un componente distinto.

## Cambios integrados

- Revocación JWT, logout, rotación versionada de claves JWT y HMAC de auditoría.
- Sesiones refresh de un solo uso, detección de reutilización y cierre global.
- MFA TOTP para roles sensibles y códigos de recuperación con derivación
  resistente a intentos de adivinación.
- Auditoría de eventos de autenticación sin credenciales ni material MFA.
- Límites compartidos de login y MFA, controles de credential stuffing y
  backoff progresivo.
- Perfil de producción que rechaza controles críticos en memoria y exige
  transporte y autenticación seguros para Redis.
- Identificación de clientes mediante proxies y CIDRs expresamente confiables.
- Contenedor no root, código de aplicación inmutable, secretos montados,
  preflight, health/readiness y perfil Compose endurecido.
- Dependencias revisadas, Actions fijadas por SHA, análisis de workflows,
  Scorecard y controles de dependencias para las aplicaciones complementarias.

## Validación y publicación

La publicación exige que los workflows de seguridad, contenedor, CodeQL,
análisis de Actions, Scorecard y las nueve aplicaciones complementarias
finalicen correctamente para el mismo SHA de main que se publica. Las notas
no implican que se hayan desplegado servicios ni publicado imágenes GHCR.

## Migración y límites

Antes de un despliegue, revisar `docs/PRODUCTION_SECURITY.md`, configurar los
backends Redis, TLS, claves independientes, roles/MFA, proxies, copias de
seguridad y recuperación. Ejecutar el preflight y verificar los flujos de
login, refresh, logout y recuperación en el entorno de destino.

Los análisis automatizados reducen riesgos; no constituyen una certificación
externa ni garantizan ausencia de vulnerabilidades. El sistema requiere
revisión humana y procedimientos de protección, privacidad y jurisdicción.
No publicar datos reales de menores, credenciales ni evidencia sensible en
issues, logs o documentación.
