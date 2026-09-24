# 📋 CONJUNTO DE CASOS DE PRUEBA
## Sistema de Detección de Grooming — Versión 1.0

---

## 🟢 RIESGO ALTO — DEBE DETECTARSE
| ID | Mensaje de prueba | Riesgo esperado | Perfil |
|---|---|---|---|
| PA-001 | "Hola, cuántos años tienes? No le cuentes a nadie" | CRÍTICO | Agresor |
| PA-002 | "Estás sola? Mándame una foto tuya" | CRÍTICO | Agresor |
| PA-003 | "Es nuestro secreto, no se lo digas a tus papás" | ALTO | Agresor |
| PA-004 | "Dime dónde vives, paso por ti" | CRÍTICO | Agresor |
| PA-005 | "Eres muy madura, nadie te va a querer así" | ALTO | Agresor |

## 🟡 RIESGO MEDIO / BAJO
| ID | Mensaje de prueba | Riesgo esperado | Acción |
|---|---|---|---|
| PB-001 | "Con quién estás? Tus papás saben?" | MEDIO | Seguimiento |
| PB-002 | "Te regalo algo si me mandas foto" | MEDIO | Agresor |
| PB-003 | "Me gustas, quiero saber más de ti" | BAJO | Vigilancia |

## 🔵 SIN RIESGO
| ID | Mensaje de prueba | Riesgo esperado |
|---|---|---|
| PC-001 | "Hola, qué tal estás?" | SIN RIESGO |
| PC-002 | "Me caes muy bien, amiga" | SIN RIESGO |
| PC-003 | "Nos vemos en la escuela" | SIN RIESGO |

## 🔴 PRUEBAS DE IP
| ID | IP de prueba | Resultado esperado |
|---|---|---|
| IP-001 | 192.168.1.1 | Válida / Privada |
| IP-002 | 8.8.8.8 | Válida / Pública |
| IP-003 | 999.999.999.999 | Inválida |

---

## ✅ CRITERIOS DE ACEPTACIÓN
- [ ] Frases de riesgo alto → Nivel ALTO o CRÍTICO
- [ ] Solicitud de edad/foto/secreto → Perfil "Agresor"
- [ ] Mensajes neutros → Sin riesgo
- [ ] Informe con ID único generado
- [ ] IP pública/privada clasificada correctamente
