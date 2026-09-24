from typing import Annotated
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field

from api import detect_patterns, ip_analysis, report_generator
from api.auth import (
    LOGIN_LIMITER,
    Role,
    User,
    authenticate_user,
    create_access_token,
    get_current_user,
    require_roles,
)

app = FastAPI(
    title="Sistema de Alerta Temprana — Anti-Grooming",
    description="API de detección y documentación de conductas de grooming",
    version="3.1.0",
)


class Mensaje(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    remitente_id: str = Field(min_length=1, max_length=128)
    destinatario_id: str = Field(min_length=1, max_length=128)
    contenido: str = Field(min_length=1, max_length=10_000)
    fecha_hora: str | None = Field(default=None, max_length=64)
    ip_origen: str | None = Field(default=None, max_length=45)
    plataforma: str | None = Field(default=None, max_length=100)


class AnalisisRespuesta(BaseModel):
    nivel_riesgo: str
    puntaje: float
    indicadores_detectados: list[str]
    perfil_identificado: str
    informe_id: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@app.post("/token", response_model=TokenResponse)
async def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
):
    LOGIN_LIMITER.check(request, form.username)
    user = authenticate_user(form.username, form.password)
    if user is None:
        LOGIN_LIMITER.failure(request, form.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña inválidos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    LOGIN_LIMITER.success(request, form.username)
    token, expires_in = create_access_token(user)
    return TokenResponse(access_token=token, expires_in=expires_in)


@app.post("/analizar-mensaje", response_model=AnalisisRespuesta)
async def analizar_mensaje(
    mensaje: Mensaje,
    user: Annotated[User, Depends(require_roles(Role.ADMIN, Role.ANALYST))],
):
    if not mensaje.fecha_hora:
        mensaje.fecha_hora = datetime.now().isoformat()

    resultado_patrones = detect_patterns.evaluar_texto(mensaje.contenido)

    datos_ip = {}
    if mensaje.ip_origen:
        datos_ip = ip_analysis.analizar_ip(mensaje.ip_origen)

    perfil = detect_patterns.identificar_perfil(resultado_patrones)
    try:
        informe_id = report_generator.crear_informe(
            mensaje, resultado_patrones, datos_ip, perfil, owner=user.username
        )
    except report_generator.EvidenceSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Almacenamiento seguro no disponible",
        ) from exc

    return AnalisisRespuesta(
        nivel_riesgo=resultado_patrones["nivel_riesgo"],
        puntaje=resultado_patrones["puntaje"],
        indicadores_detectados=resultado_patrones["indicadores"],
        perfil_identificado=perfil,
        informe_id=informe_id,
    )


@app.get("/informe/{informe_id}")
async def obtener_informe(
    informe_id: str,
    user: Annotated[User, Depends(get_current_user)],
):
    try:
        informe = report_generator.leer_informe(
            informe_id,
            requester=user.username,
            can_read_all=user.role in {Role.ADMIN, Role.AUDITOR},
        )
    except report_generator.EvidenceSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Almacenamiento seguro no disponible",
        ) from exc
    if not informe:
        raise HTTPException(status_code=404, detail="Informe no encontrado")
    return informe


@app.get("/estado")
async def estado():
    return {"estado": "activo", "sistema": "anti-grooming", "version": "3.1.0"}
