import unicodedata
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.middleware.cors import CORSMiddleware

from api import detect_patterns, ip_analysis, report_generator, security_audit
from api.auth import (
    LOGIN_LIMITER,
    Role,
    User,
    authenticate_mfa,
    authenticate_user,
    create_access_token,
    create_refresh_session,
    get_current_user,
    require_roles,
    revoke_access_token,
    revoke_all_user_sessions,
    rotate_refresh_session,
    validate_configuration,
)
from api.jurisdictions import JurisdictionNotConfiguredError, get_policy
from api.retention import EvidenceStatus
from api.runtime_secrets import load_runtime_secrets
from api.security import (
    REPORT_LIMITER,
    ApiShieldMiddleware,
    RateLimitBackendUnavailable,
    env_list,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.ready = False
    load_runtime_secrets()
    validate_configuration()
    report_generator.verificar_auditoria()
    security_audit.verify_security_audit()
    app.state.ready = True
    try:
        yield
    finally:
        app.state.ready = False


app = FastAPI(
    lifespan=lifespan,
    title="Sistema de Alerta Temprana — Anti-Grooming",
    description="API de detección y documentación de conductas de grooming",
    version="3.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=env_list("ALLOWED_ORIGINS_JSON", []),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    max_age=600,
)
app.add_middleware(ApiShieldMiddleware)


class IpSource(str, Enum):
    CLIENT_DECLARED = "CLIENT_DECLARED"
    PLATFORM_EXPORT = "PLATFORM_EXPORT"
    SERVER_OBSERVED = "SERVER_OBSERVED"
    PROVIDER_RECORD = "PROVIDER_RECORD"
    OTHER = "OTHER"


class Mensaje(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remitente_id: str = Field(min_length=1, max_length=128)
    destinatario_id: str = Field(min_length=1, max_length=128)
    contenido: str = Field(min_length=1, max_length=10_000)
    fecha_hora: datetime | None = None
    ip_origen: IPv4Address | IPv6Address | None = None
    ip_source: IpSource = IpSource.CLIENT_DECLARED
    ip_verified: bool = False
    plataforma: str | None = Field(default=None, max_length=100)

    @field_validator("remitente_id", "destinatario_id", "contenido", "plataforma")
    @classmethod
    def reject_blank_text(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("El campo no puede estar vacío")
        return value

    @field_validator("remitente_id", "destinatario_id", "plataforma", "ip_source")
    @classmethod
    def limit_to_single_line(cls, value: str | None) -> str | None:
        if value is not None and any(
            unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in value
        ):
            raise ValueError("El campo no puede contener saltos de línea")
        return value


class AnalisisRespuesta(BaseModel):
    nivel_riesgo: str
    puntaje: float
    indicadores_detectados: list[str]
    perfil_identificado: str
    informe_id: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_expires_in: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(min_length=32, max_length=256)


class EstadoInforme(BaseModel):
    estado: EvidenceStatus


def _record_security_event_or_503(
    event: str,
    *,
    request: Request,
    username: str | None = None,
    role: str | None = None,
    severity: str = "info",
    reason: str | None = None,
) -> None:
    try:
        security_audit.record_security_event(
            event,
            request=request,
            username=username,
            role=role,
            severity=severity,
            reason=reason,
        )
    except security_audit.SecurityAuditError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auditoría de seguridad no disponible",
        ) from exc


@app.post("/token", response_model=TokenResponse)
def login(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    mfa_code: Annotated[str | None, Form()] = None,
):
    try:
        LOGIN_LIMITER.check(request, form.username)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_429_TOO_MANY_REQUESTS:
            scope = getattr(exc, "rate_limit_scope", "pair")
            if scope == "account":
                event = "credential_stuffing_suspected"
                severity = "critical"
                reason = "account_scope"
            elif scope == "client":
                event = "password_spraying_suspected"
                severity = "critical"
                reason = "client_scope"
            else:
                event = "login_rate_limited"
                severity = "warning"
                reason = "pair_scope"
            _record_security_event_or_503(
                event,
                request=request,
                username=form.username,
                severity=severity,
                reason=reason,
            )
        else:
            _record_security_event_or_503(
                "auth_backend_error",
                request=request,
                username=form.username,
                severity="critical",
                reason="login_rate_limit_backend",
            )
        raise

    user = authenticate_user(form.username, form.password)
    if user is None:
        try:
            LOGIN_LIMITER.failure(request, form.username)
        except HTTPException:
            _record_security_event_or_503(
                "auth_backend_error",
                request=request,
                username=form.username,
                severity="critical",
                reason="login_rate_limit_backend",
            )
            raise
        _record_security_event_or_503(
            "login_failed",
            request=request,
            username=form.username,
            severity="warning",
            reason="credentials",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario, contraseña o MFA inválidos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        mfa_valid = authenticate_mfa(user, mfa_code)
    except HTTPException:
        _record_security_event_or_503(
            "auth_backend_error",
            request=request,
            username=user.username,
            role=user.role.value,
            severity="critical",
            reason="mfa_backend",
        )
        raise

    if not mfa_valid:
        try:
            LOGIN_LIMITER.failure(request, form.username)
        except HTTPException:
            _record_security_event_or_503(
                "auth_backend_error",
                request=request,
                username=user.username,
                role=user.role.value,
                severity="critical",
                reason="login_rate_limit_backend",
            )
            raise
        _record_security_event_or_503(
            "login_failed",
            request=request,
            username=user.username,
            role=user.role.value,
            severity="warning",
            reason="mfa",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario, contraseña o MFA inválidos",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        LOGIN_LIMITER.success(request, form.username)
    except HTTPException:
        _record_security_event_or_503(
            "auth_backend_error",
            request=request,
            username=user.username,
            role=user.role.value,
            severity="critical",
            reason="login_rate_limit_backend",
        )
        raise

    try:
        refresh_token, refresh_expires_in, session_version = create_refresh_session(
            user
        )
        access_token, expires_in = create_access_token(user, session_version)
    except HTTPException:
        _record_security_event_or_503(
            "auth_backend_error",
            request=request,
            username=user.username,
            role=user.role.value,
            severity="critical",
            reason="session_issue",
        )
        raise

    try:
        _record_security_event_or_503(
            "login_success",
            request=request,
            username=user.username,
            role=user.role.value,
        )
    except HTTPException:
        try:
            revoke_all_user_sessions(user)
        except HTTPException:
            pass
        raise

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        refresh_expires_in=refresh_expires_in,
    )


@app.post("/token/refresh", response_model=TokenResponse)
def refresh_token(request: Request, payload: RefreshTokenRequest):
    try:
        user, next_refresh, refresh_expires_in, session_version = (
            rotate_refresh_session(payload.refresh_token)
        )
        access_token, expires_in = create_access_token(user, session_version)
    except HTTPException as exc:
        detail = str(exc.detail)
        if "reutilizado" in detail:
            event = "refresh_reuse_detected"
            severity = "critical"
            reason = "replay"
        elif exc.status_code == status.HTTP_503_SERVICE_UNAVAILABLE:
            event = "auth_backend_error"
            severity = "critical"
            reason = "refresh_backend"
        else:
            event = "refresh_failed"
            severity = "warning"
            reason = "invalid_refresh"
        _record_security_event_or_503(
            event,
            request=request,
            severity=severity,
            reason=reason,
        )
        raise

    try:
        _record_security_event_or_503(
            "refresh_success",
            request=request,
            username=user.username,
            role=user.role.value,
        )
    except HTTPException:
        try:
            revoke_all_user_sessions(user)
        except HTTPException:
            pass
        raise

    return TokenResponse(
        access_token=access_token,
        refresh_token=next_refresh,
        expires_in=expires_in,
        refresh_expires_in=refresh_expires_in,
    )


@app.post("/logout")
def logout(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
):
    revoke_access_token(user)
    _record_security_event_or_503(
        "logout",
        request=request,
        username=user.username,
        role=user.role.value,
    )
    return {"estado": "sesión revocada"}


@app.post("/logout-all")
def logout_all(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
):
    revoke_all_user_sessions(user)
    _record_security_event_or_503(
        "logout_all",
        request=request,
        username=user.username,
        role=user.role.value,
        severity="warning",
        reason="user_requested",
    )
    return {"estado": "todas las sesiones revocadas"}


@app.post("/analizar-mensaje", response_model=AnalisisRespuesta)
def analizar_mensaje(
    request: Request,
    mensaje: Mensaje,
    user: Annotated[
        User, Depends(require_roles(Role.ADMIN, Role.ANALYST, Role.SUPERVISOR))
    ],
):
    try:
        rate = REPORT_LIMITER.check(user.username)
    except RateLimitBackendUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Control de tráfico no disponible",
        ) from exc
    if not rate.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados análisis; probá más tarde",
            headers={"Retry-After": str(rate.retry_after)},
        )

    if not mensaje.fecha_hora:
        mensaje.fecha_hora = datetime.now(timezone.utc)

    resultado_patrones = detect_patterns.evaluar_texto(mensaje.contenido)
    datos_ip = (
        ip_analysis.analizar_ip(str(mensaje.ip_origen)) if mensaje.ip_origen else {}
    )
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
def obtener_informe(
    informe_id: str,
    user: Annotated[User, Depends(get_current_user)],
):
    try:
        informe = report_generator.leer_informe(
            informe_id,
            requester=user.username,
            can_read_all=user.role in {Role.ADMIN, Role.AUDITOR, Role.SUPERVISOR},
        )
    except report_generator.EvidenceSecurityError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Almacenamiento seguro no disponible",
        ) from exc
    if not informe:
        raise HTTPException(status_code=404, detail="Informe no encontrado")
    return informe


@app.get("/jurisdiccion/{country_code}", dependencies=[Depends(get_current_user)])
async def obtener_jurisdiccion(country_code: str):
    try:
        policy = get_policy(country_code)
    except JurisdictionNotConfiguredError as exc:
        raise HTTPException(
            status_code=404, detail="Jurisdicción no configurada"
        ) from exc
    return {
        "code": policy.code,
        "name": policy.name,
        "languages": policy.languages,
        "recommended_retention_days": policy.recommended_retention_days,
        "reporting_channels": policy.reporting_channels,
        "cross_border_review_required": policy.cross_border_review_required,
    }


@app.patch("/informe/{informe_id}/estado", response_model=EstadoInforme)
def cambiar_estado_informe(
    informe_id: str,
    cambio: EstadoInforme,
    user: Annotated[User, Depends(require_roles(Role.ADMIN, Role.SUPERVISOR))],
):
    try:
        estado = report_generator.actualizar_estado_informe(
            informe_id, cambio.estado, user.username
        )
    except report_generator.EvidenceSecurityError as exc:
        raise HTTPException(
            status_code=409, detail="Cambio de estado no permitido"
        ) from exc
    return EstadoInforme(estado=estado)


@app.get("/health/live")
async def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
async def health_ready(request: Request):
    if not getattr(request.app.state, "ready", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio no listo",
        )
    return {"status": "ready"}


@app.get("/estado")
async def estado():
    return {"estado": "activo", "sistema": "anti-grooming", "version": "3.5.0"}
