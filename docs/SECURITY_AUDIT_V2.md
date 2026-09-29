# Auditoría de seguridad V2 — estado de remediación

## Alcance

Revisión del código, API, autenticación, almacenamiento de evidencia, entrada,
dependencias, tests y GitHub Actions sobre `main` antes de esta rama.

## Correcciones aplicadas

- Se eliminaron etiquetas que acusaban automáticamente a una persona y se
  añadieron categorías neutrales con revisión humana obligatoria.
- Se validan `datetime`, IP, límites de texto y una enumeración de procedencia
  de IP; el informe distingue IP declarada, fuente y verificación.
- Se añadió pseudonimización HMAC para remitente y destinatario.
- Los informes nuevos usan UUID4 canónico; los identificadores legacy seguros
  siguen siendo legibles.
- Se agregó el rol `SUPERVISOR`.
- Se limitaron las claves retenidas por los limitadores en memoria para reducir
  abuso de memoria.
- Se corrigió el marco legal argentino y se añadió `SECURITY.md`.
- Se agregaron CodeQL y Dependabot.
- Se agregó un key ring versionado para rotación de claves sin perder lectura
  de informes históricos.
- Se definieron estados de retención y la regla de que `LEGAL_HOLD` no puede
  pasar a eliminación.
- Se agregó una interfaz de backend Redis para despliegues multi-worker; el
  backend solo se activa cuando la infraestructura lo provee explícitamente.

## Verificación

En la rama de remediación: 99 tests pasan; Ruff, mypy, Bandit y pip-audit no
reportan errores. El escaneo detect-secrets solo encuentra marcadores de
caché excluidos por el workflow.

## Riesgos pendientes

- Para producción se recomienda rate limiting distribuido, no solo memoria de
  proceso.
- La persistencia sigue siendo filesystem cifrado; PostgreSQL y un almacén de
  evidencia inmutable requieren infraestructura adicional.
- La rotación de claves y el legal hold necesitan un diseño operativo antes de
  manejar evidencia real; esta rama aporta la validación criptográfica y las
  reglas de transición, pero no inventa un almacén externo de secretos ni una
  tarea automática de borrado.
- Las GitHub Actions deben fijarse por SHA en una siguiente iteración.
