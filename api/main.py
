from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import detect_patterns
import ip_analysis
import report_generator

app = FastAPI(
    title="Sistema de Alerta Temprana — Anti-Grooming",
    description="API de detección y documentación de conductas de grooming",
    version="1.0.0"
)

class Mensaje(BaseModel):
    remitente_id: str
    destinatario_id: str
    contenido: str
    fecha_hora: Optional[str] = None
    ip_origen: Optional[str] = None
    plataforma: Optional[str] = None

class AnalisisRespuesta(BaseModel):
    nivel_riesgo: str
    puntaje: float
    indicadores_detectados: List[str]
    perfil_identificado: str
    informe_id: str

@app.post("/analizar-mensaje", response_model=AnalisisRespuesta)
async def analizar_mensaje(mensaje: Mensaje):
    if not mensaje.fecha_hora:
        mensaje.fecha_hora = datetime.now().isoformat()
    
    resultado_patrones = detect_patterns.evaluar_texto(mensaje.contenido)
    
    datos_ip = {}
    if mensaje.ip_origen:
        datos_ip = ip_analysis.analizar_ip(mensaje.ip_origen)
    
    perfil = detect_patterns.identificar_perfil(resultado_patrones)
    informe_id = report_generator.crear_informe(mensaje, resultado_patrones, datos_ip, perfil)
    
    return AnalisisRespuesta(
        nivel_riesgo=resultado_patrones["nivel_riesgo"],
        puntaje=resultado_patrones["puntaje"],
        indicadores_detectados=resultado_patrones["indicadores"],
        perfil_identificado=perfil,
        informe_id=informe_id
    )

@app.get("/informe/{informe_id}")
async def obtener_informe(informe_id: str):
    informe = report_generator.leer_informe(informe_id)
    if not informe:
        raise HTTPException(status_code=404, detail="Informe no encontrado")
    return informe

@app.get("/estado")
async def estado():
    return {"estado": "activo", "sistema": "anti-grooming", "version": "1.0.0"}
