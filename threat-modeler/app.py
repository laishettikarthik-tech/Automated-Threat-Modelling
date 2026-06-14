"""Threat Modeler — FastAPI app with RBAC.

Architecture (POC):
  - SQLite via db/__init__.py
  - JWT access tokens + opaque refresh tokens (auth/auth.py)
  - Role-based permission checks via @require_permission decorators
  - Resource-access checks via ensure_can_access_threat_model
  - Hierarchy: Release → Feature → ThreatModel → Threats (with per-threat status)

Run locally:
  export INITIAL_ADMIN_EMAIL=admin@example.com
  export INITIAL_ADMIN_PASSWORD=changeme123
  export JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
  python app.py
  # Open http://127.0.0.1:8000
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

# Initialize DB before anything else imports from it
from db import init_db, db_conn, audit
init_db()

from db import domain
from auth import (
    register_user, login as auth_login, get_user_by_id, list_users,
    update_user_role, deactivate_user,
    consume_refresh_token, create_access_token, revoke_all_refresh_tokens,
    get_current_user, require_permission,
    ensure_can_access_threat_model, can_access_feature, get_role_permissions,
)
from threat_engine import analyze_system, METHODOLOGIES, render_dfd_svg, auto_layout_for_frontend
from threat_engine.report import to_markdown, to_pdf
from threat_engine.html_report import to_html


app = FastAPI(title="Threat Modeler", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)


# ===========================================================================
# SECURITY — headers, rate limiting, CORS tightening
# ===========================================================================
from fastapi import Request as _Req
from fastapi.responses import Response as _Resp
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to every response."""
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


# Simple in-memory rate limiter (replace with Redis-backed for production)
import time as _time
from collections import defaultdict as _defaultdict
_rate_store: dict = _defaultdict(list)

def _rate_limit(key: str, limit: int, window: int) -> bool:
    """Return True if request is allowed, False if rate limited."""
    now = _time.time()
    _rate_store[key] = [t for t in _rate_store[key] if now - t < window]
    if len(_rate_store[key]) >= limit:
        return False
    _rate_store[key].append(now)
    return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limit sensitive auth endpoints."""
    LIMITS = {
        "/api/auth/login":    (10, 60),   # 10 req/min
        "/api/auth/register": (5,  60),   # 5  req/min
        "/api/auth/refresh":  (20, 60),   # 20 req/min
    }
    async def dispatch(self, request, call_next):
        path = request.url.path
        if path in self.LIMITS:
            limit, window = self.LIMITS[path]
            ip = request.client.host if request.client else "unknown"
            key = f"rl:{path}:{ip}"
            if not _rate_limit(key, limit, window):
                return _Resp(
                    content='{"detail":"Too many requests. Please try again later."}',
                    status_code=429,
                    media_type="application/json",
                )
        return await call_next(request)


BASE_DIR = Path(__file__).resolve().parent
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ===========================================================================
# AUTH ENDPOINTS — public
# ===========================================================================
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=120)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


@app.post("/api/auth/register")
async def auth_register(req: RegisterRequest, request: Request):
    """Self-registration creates a User-role account.
    To create Management or Admin accounts, an Admin uses POST /api/users."""
    try:
        u = register_user(req.email, req.password, req.full_name, role="user")
    except ValueError as e:
        raise HTTPException(400, str(e))
    access, refresh, _ = auth_login(
        req.email, req.password,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", ""),
    )
    return {
        "user": u,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "permissions": list(get_role_permissions(u["role"])),
    }


@app.post("/api/auth/login")
async def auth_login_endpoint(req: LoginRequest, request: Request):
    try:
        access, refresh, user = auth_login(
            req.email, req.password,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", ""),
        )
    except ValueError as e:
        raise HTTPException(401, str(e))
    return {
        "user": user,
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "Bearer",
        "permissions": list(get_role_permissions(user["role"])),
    }


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/api/auth/refresh")
async def auth_refresh(req: RefreshRequest):
    uid = consume_refresh_token(req.refresh_token)
    if not uid:
        raise HTTPException(401, "Invalid or expired refresh token")
    user = get_user_by_id(uid)
    if not user or not user["is_active"]:
        raise HTTPException(401, "User unavailable")
    new_access = create_access_token(uid, user["email"], user["role"])
    from auth.auth import create_refresh_token
    new_refresh = create_refresh_token(uid)
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
    }


@app.post("/api/auth/logout")
async def auth_logout(user: dict = Depends(get_current_user)):
    revoke_all_refresh_tokens(user["id"])
    audit(user["id"], user["email"], "user.logout", "grant",
          ip_address=user.get("_ip"), user_agent=user.get("_user_agent"))
    return {"ok": True}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return {
        "user": {k: v for k, v in user.items() if not k.startswith("_")},
        "permissions": list(get_role_permissions(user["role"])),
    }


# ===========================================================================
# USER MANAGEMENT — admin only
# ===========================================================================
class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str
    role: str = Field(pattern="^(user|management|admin)$")
    feature_ids: list[int] = []


@app.post("/api/users")
async def admin_create_user(
    req: CreateUserRequest,
    actor: dict = Depends(require_permission("user.create")),
):
    try:
        u = register_user(req.email, req.password, req.full_name, role=req.role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    for fid in req.feature_ids:
        domain.grant_feature_access(u["id"], fid, granted_by=actor["id"])
    audit(actor["id"], actor["email"], "user.create", "grant", "user", u["id"],
          ip_address=actor.get("_ip"),
          detail=f"role={req.role} feature_ids={req.feature_ids}")
    return u


@app.get("/api/users")
async def admin_list_users(actor: dict = Depends(require_permission("user.read.all"))):
    return list_users()


class UpdateUserRoleRequest(BaseModel):
    role: str = Field(pattern="^(user|management|admin)$")


@app.put("/api/users/{uid}/role")
async def admin_update_user_role(
    uid: int,
    req: UpdateUserRoleRequest,
    actor: dict = Depends(require_permission("user.update.all")),
):
    if uid == actor["id"]:
        raise HTTPException(400, "Cannot change your own role")
    try:
        update_user_role(uid, req.role, by_user_id=actor["id"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    return get_user_by_id(uid)


@app.delete("/api/users/{uid}")
async def admin_deactivate_user(
    uid: int,
    actor: dict = Depends(require_permission("user.delete.all")),
):
    if uid == actor["id"]:
        raise HTTPException(400, "Cannot deactivate yourself")
    deactivate_user(uid, by_user_id=actor["id"])
    return {"ok": True, "deactivated": uid}


class GrantFeatureAccessRequest(BaseModel):
    feature_ids: list[int]


@app.put("/api/users/{uid}/feature-access")
async def admin_set_user_feature_access(
    uid: int,
    req: GrantFeatureAccessRequest,
    actor: dict = Depends(require_permission("user.feature_access.grant")),
):
    current = {f["id"] for f in domain.list_user_feature_access(uid)}
    target = set(req.feature_ids)
    for fid in target - current:
        domain.grant_feature_access(uid, fid, granted_by=actor["id"])
    for fid in current - target:
        domain.revoke_feature_access(uid, fid)
    audit(actor["id"], actor["email"], "user.feature_access.grant", "grant",
          "user", uid, ip_address=actor.get("_ip"),
          detail=f"granted={sorted(target - current)} revoked={sorted(current - target)}")
    return {"feature_ids": sorted(target)}


@app.get("/api/users/{uid}/feature-access")
async def admin_list_user_feature_access(
    uid: int,
    actor: dict = Depends(require_permission("user.read.all")),
):
    return [{"feature_id": f["id"], "feature_name": f["name"]}
            for f in domain.list_user_feature_access(uid)]


# ===========================================================================
# RELEASES (admin manages)
# ===========================================================================
class ReleaseCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    target_date: str | None = None
    status: str = Field(default="planned",
                        pattern="^(planned|in_progress|released|cancelled)$")


@app.post("/api/releases")
async def create_release(
    req: ReleaseCreateRequest,
    actor: dict = Depends(require_permission("release.create")),
):
    return domain.create_release(
        req.name, req.description, req.target_date,
        created_by=actor["id"], status=req.status
    )


@app.get("/api/releases")
async def list_releases(actor: dict = Depends(require_permission("release.read.all"))):
    return domain.list_releases()


@app.put("/api/releases/{rid}")
async def update_release(
    rid: int,
    req: ReleaseCreateRequest,
    actor: dict = Depends(require_permission("release.update.all")),
):
    rel = domain.update_release(rid, **req.model_dump())
    if not rel:
        raise HTTPException(404)
    return rel


@app.delete("/api/releases/{rid}")
async def delete_release(
    rid: int,
    actor: dict = Depends(require_permission("release.delete.all")),
):
    domain.delete_release(rid)
    return {"ok": True}


# ===========================================================================
# FEATURES
# ===========================================================================
class FeatureCreateRequest(BaseModel):
    release_id: int
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    status: str = Field(default="draft",
                        pattern="^(draft|in_review|in_sprint|released|cancelled)$")
    target_date: str | None = None   # ISO YYYY-MM-DD


@app.post("/api/features")
async def create_feature(
    req: FeatureCreateRequest,
    actor: dict = Depends(require_permission("feature.create")),
):
    try:
        return domain.create_feature(
            req.release_id, req.name, req.description,
            created_by=actor["id"], status=req.status,
            target_date=req.target_date,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/features")
async def list_features(
    release_id: int | None = None,
    user: dict = Depends(get_current_user),
):
    """Filter by role:
       - admin/management: see all features
       - user: see ones they created or were granted access to
    """
    return domain.list_features(
        release_id=release_id,
        visible_to_user_id=user["id"],
        visible_to_role=user["role"],
    )


@app.get("/api/features/{fid}")
async def get_feature(fid: int, user: dict = Depends(get_current_user)):
    f = domain.get_feature(fid)
    if not f:
        raise HTTPException(404)
    if not can_access_feature(user, f, "read"):
        audit(user["id"], user["email"], "feature.read", "deny", "feature", fid,
              ip_address=user.get("_ip"))
        raise HTTPException(404)
    return f


@app.put("/api/features/{fid}")
async def update_feature(
    fid: int,
    req: FeatureCreateRequest,
    actor: dict = Depends(require_permission("feature.update.all")),
):
    f = domain.update_feature(fid, **req.model_dump(exclude={"release_id"}))
    if not f:
        raise HTTPException(404)
    return f


@app.delete("/api/features/{fid}")
async def delete_feature(
    fid: int,
    actor: dict = Depends(require_permission("feature.delete.all")),
):
    domain.delete_feature(fid)
    return {"ok": True}


# ===========================================================================
# THREAT MODELS
# ===========================================================================
class ThreatModelCreateRequest(BaseModel):
    feature_id: int
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    system: dict
    methodologies: list[str] = ["stride"]


@app.post("/api/threat-models")
async def create_threat_model(
    req: ThreatModelCreateRequest,
    actor: dict = Depends(require_permission("threat_model.create")),
):
    feature = domain.get_feature(req.feature_id)
    if not feature:
        raise HTTPException(400, "Feature not found")
    if not can_access_feature(actor, feature, "read"):
        raise HTTPException(403, "No access to this feature")
    try:
        return domain.create_threat_model(
            req.feature_id, owner_id=actor["id"],
            name=req.name, description=req.description,
            system=req.system, methodologies=req.methodologies,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/threat-models")
async def list_threat_models(
    feature_id: int | None = None,
    user: dict = Depends(get_current_user),
):
    return domain.list_threat_models(
        visible_to_user_id=user["id"],
        visible_to_role=user["role"],
        feature_id=feature_id,
    )


@app.get("/api/threat-models/{tid}")
async def get_threat_model(tid: int, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    tm["threat_statuses"] = domain.list_threat_statuses(tid)
    return tm


class ThreatModelUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    system: dict | None = None
    methodologies: list[str] | None = None
    feature_id: int | None = None


@app.put("/api/threat-models/{tid}")
async def update_threat_model(
    tid: int,
    req: ThreatModelUpdateRequest,
    user: dict = Depends(get_current_user),
):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "update")
    fields = {k: v for k, v in req.model_dump().items() if v is not None}
    return domain.update_threat_model(tid, **fields)


@app.delete("/api/threat-models/{tid}")
async def delete_threat_model(tid: int, user: dict = Depends(get_current_user)):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "delete")
    domain.delete_threat_model(tid)
    return {"ok": True}


class AnalyzeRequest(BaseModel):
    methodologies: list[str] = ["stride"]
    use_llm: bool = False


@app.post("/api/threat-models/{tid}/analyze")
async def analyze_threat_model(
    tid: int,
    req: AnalyzeRequest,
    user: dict = Depends(get_current_user),
):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "update")
    result = analyze_system(tm["system"], req.methodologies, use_llm=req.use_llm)
    domain.update_threat_model(tid, methodologies=req.methodologies, analysis=result)
    audit(user["id"], user["email"], "threat_model.analyze", "grant",
          "threat_model", tid, ip_address=user.get("_ip"),
          detail=f"methodologies={req.methodologies} threats={result['summary']['total']}")
    return result


class ThreatStatusUpdate(BaseModel):
    status: str = Field(pattern="^(open|in_progress|mitigated|accepted_risk|false_positive)$")
    notes: str | None = None


@app.put("/api/threat-models/{tid}/threats/{threat_id}/status")
async def update_threat_status(
    tid: int,
    threat_id: str,
    req: ThreatStatusUpdate,
    user: dict = Depends(get_current_user),
):
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    # Status updates require WRITE access — only owner (user) or admin.
    # Management can READ but not change anything.
    ensure_can_access_threat_model(user, tm, "update")
    return domain.set_threat_status(
        tid, threat_id, req.status, req.notes, updated_by=user["id"]
    )


@app.get("/api/threat-models/{tid}/threats/{threat_id}/history")
async def threat_status_history(
    tid: int,
    threat_id: str,
    user: dict = Depends(get_current_user),
):
    """Full status-change history for a single threat. Read-access only."""
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    return domain.get_threat_status_history(tid, threat_id)


# ===========================================================================
# REPORTS
# ===========================================================================
@app.get("/api/threat-models/{tid}/report/{fmt}")
async def threat_model_report(
    tid: int,
    fmt: str,
    user: dict = Depends(get_current_user),
):
    if fmt not in ("markdown", "html", "pdf"):
        raise HTTPException(400, "Format must be markdown, html, or pdf")
    tm = domain.get_threat_model(tid)
    if not tm:
        raise HTTPException(404)
    ensure_can_access_threat_model(user, tm, "read")
    if not tm.get("analysis"):
        raise HTTPException(400, "Run analysis before generating a report")
    analysis = tm["analysis"]
    fname = f"threat_model_{tid}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "markdown":
        return Response(to_markdown(analysis), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})
    if fmt == "html":
        return Response(to_html(analysis), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
    return Response(to_pdf(analysis), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.pdf"'})


# Ad-hoc analysis (no DB write) — kept for the canvas UI when not yet saved
class AdhocAnalyzeRequest(BaseModel):
    system: dict
    methodologies: list[str] = ["stride"]
    use_llm: bool = False


@app.post("/api/analyze")
async def analyze_adhoc(
    req: AdhocAnalyzeRequest,
    user: dict = Depends(require_permission("threat_model.create")),
):
    return analyze_system(req.system, req.methodologies, use_llm=req.use_llm)


@app.post("/api/report/{fmt}")
async def adhoc_report(
    fmt: str,
    analysis: dict,
    user: dict = Depends(get_current_user),
):
    if fmt not in ("markdown", "html", "pdf"):
        raise HTTPException(400)
    fname = f"threat_model_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    if fmt == "markdown":
        return Response(to_markdown(analysis), media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})
    if fmt == "html":
        return Response(to_html(analysis), media_type="text/html",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.html"'})
    return Response(to_pdf(analysis), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.pdf"'})


# ===========================================================================
# MANAGEMENT VIEW + AUDIT LOG
# ===========================================================================
@app.get("/api/management/overview")
async def management_overview(
    actor: dict = Depends(require_permission("view.management")),
):
    return domain.management_overview()


@app.get("/api/audit-log")
async def admin_audit_log(
    limit: int = 200,
    actor: dict = Depends(require_permission("audit.read")),
):
    limit = min(max(limit, 1), 1000)
    with db_conn() as c:
        rows = c.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


# ===========================================================================
# UTILITY (used by canvas UI)
# ===========================================================================
@app.get("/api/methodologies")
async def list_methodologies():
    return {k: {"name": m["name"], "categories": list(m["categories"].keys())}
            for k, m in METHODOLOGIES.items()}


@app.post("/api/extract-from-text")
async def extract_from_text(payload: dict, user: dict = Depends(get_current_user)):
    from threat_engine.analyzer import extract_components_from_text
    from threat_engine.trust_boundaries import infer_trust_boundaries

    text = (payload or {}).get("text", "")
    use_llm = bool((payload or {}).get("use_llm", False))

    result = extract_components_from_text(text)

    # If LLM mode requested AND key configured, replace heuristic boundaries
    # with LLM-inferred ones (falls back to heuristic on any failure).
    if use_llm:
        better = infer_trust_boundaries(
            {"components": result["components"], "data_flows": result["data_flows"]},
            source_text=text,
            use_llm=True,
        )
        if better:
            result["trust_boundaries"] = better
            result["boundary_inference_mode"] = "llm"
        else:
            result["boundary_inference_mode"] = "heuristic"
    else:
        result["boundary_inference_mode"] = "heuristic"

    return result


@app.post("/api/extract-from-diagram")
async def extract_from_diagram(
    request: Request,
    file: "UploadFile" = None,
    user: dict = Depends(get_current_user),
):
    """Extract system components from an uploaded architecture diagram image.
    Accepts multipart/form-data with fields: file (image), description (text).
    Uses Claude vision if ANTHROPIC_API_KEY is configured, else returns a stub.
    """
    from fastapi import UploadFile, Form
    from threat_engine.diagram_extractor import extract_from_diagram as _extract
from threat_engine.notifications import diff_threats, notify_all

    # Parse multipart manually since FastAPI needs type annotations on path functions
    form = await request.form()
    upload = form.get("file")
    description = (form.get("description") or "")

    if not upload:
        raise HTTPException(400, "No file uploaded")

    # Validate content type
    ct = upload.content_type or "image/png"
    ALLOWED = {"image/png", "image/jpeg", "image/jpg", "image/webp", "image/gif"}
    if ct not in ALLOWED:
        raise HTTPException(400, f"Unsupported image type: {ct}. Use PNG, JPG, or WebP.")

    image_bytes = await upload.read()
    if len(image_bytes) > 20 * 1024 * 1024:  # 20MB
        raise HTTPException(400, "Image too large (max 20MB)")

    # Normalize media type
    media_type = ct if ct != "image/jpg" else "image/jpeg"
    result = _extract(image_bytes, media_type, description)
    return result


@app.post("/api/infer-trust-boundaries")
async def infer_trust_boundaries_endpoint(
    payload: dict,
    user: dict = Depends(get_current_user),
):
    """Re-infer trust boundaries on an existing system.
    Body: { system: {...}, source_text?: str, use_llm?: bool }
    """
    from threat_engine.trust_boundaries import infer_trust_boundaries

    system = (payload or {}).get("system") or {}
    source_text = (payload or {}).get("source_text", "")
    use_llm = bool((payload or {}).get("use_llm", False))

    boundaries = infer_trust_boundaries(system, source_text=source_text, use_llm=use_llm)
    return {
        "trust_boundaries": boundaries,
        "mode": "llm" if (use_llm and os.getenv("ANTHROPIC_API_KEY")) else "heuristic",
    }


@app.post("/api/auto-layout")
async def auto_layout(payload: dict, user: dict = Depends(get_current_user)):
    return auto_layout_for_frontend(payload)


@app.post("/api/dfd-svg")
async def dfd_svg(payload: dict, user: dict = Depends(get_current_user)):
    svg = render_dfd_svg(
        payload.get("system", {}),
        animated=payload.get("animated", True),
        positions=payload.get("layout"),
    )
    return Response(svg, media_type="image/svg+xml")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": app.version,
        "llm_configured": bool(os.getenv("ANTHROPIC_API_KEY")),
        "methodologies": list(METHODOLOGIES.keys()),
    }


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    # Minimal transparent 1x1 SVG — silences favicon 404s in logs
    svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>'
    return Response(svg, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    """Public landing page — login form. JS redirects logged-in users to their role page."""
    return templates.TemplateResponse(request, "login.html", {})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """Admin console. Page itself is public HTML — JS calls /api/auth/me to verify
    role and redirects unauthenticated/wrong-role users. The actual data calls
    enforce server-side role checks."""
    return templates.TemplateResponse(request, "admin.html", {})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Developer dashboard — list of threat models the user can see."""
    return templates.TemplateResponse(request, "dashboard.html", {})


@app.get("/management", response_class=HTMLResponse)
async def management_page(request: Request):
    """Management overview — feature × severity rollup."""
    return templates.TemplateResponse(request, "management.html", {})


@app.get("/canvas", response_class=HTMLResponse)
async def canvas_page(request: Request):
    """Legacy canvas UI — the threat-modeling interface from before Stage 1.
    Still has the old API calls hard-coded; will need rewiring in a follow-up."""
    methodologies_ctx = {
        k: {
            "name": m["name"],
            "description": m.get("description", ""),
            "categories": list(m["categories"].keys()),
        }
        for k, m in METHODOLOGIES.items()
    }
    return templates.TemplateResponse(
        request, "index.html",
        {
            "methodologies": methodologies_ctx,
            "llm_available": bool(os.getenv("ANTHROPIC_API_KEY")),
        }
    )



# ===========================================================================
# THREAT STATUS — remediation tracking
# ===========================================================================
class ThreatStatusUpdate(BaseModel):
    threat_id: str
    threat_model_id: int
    status: str  # open | in_progress | mitigated | accepted_risk | false_positive
    notes: str | None = None
    owner: str | None = None
    due_date: str | None = None


@app.post("/api/threat-status")
async def update_threat_status_endpoint(
    req: ThreatStatusUpdate,
    user: dict = Depends(get_current_user),
):
    """Update per-threat remediation status, owner, and due date."""
    tm = domain.get_threat_model(req.threat_model_id)
    if not tm:
        raise HTTPException(404, "Threat model not found")
    ensure_can_access_threat_model(user, tm)
    try:
        result = domain.upsert_threat_status(
            req.threat_model_id, req.threat_id, req.status,
            notes=req.notes, updated_by=user["id"],
            owner=req.owner, due_date=req.due_date
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return result


@app.get("/api/threat-status/{threat_model_id}")
async def get_all_threat_statuses(
    threat_model_id: int,
    user: dict = Depends(get_current_user),
):
    """Get all threat statuses for a threat model."""
    tm = domain.get_threat_model(threat_model_id)
    if not tm:
        raise HTTPException(404, "Threat model not found")
    ensure_can_access_threat_model(user, tm)
    return domain.list_threat_statuses(threat_model_id)


@app.get("/api/threat-status/{threat_model_id}/{threat_id}/history")
async def get_threat_status_history_endpoint(
    threat_model_id: int,
    threat_id: str,
    user: dict = Depends(get_current_user),
):
    """Get full status change history for a specific threat."""
    tm = domain.get_threat_model(threat_model_id)
    if not tm:
        raise HTTPException(404, "Threat model not found")
    ensure_can_access_threat_model(user, tm)
    return domain.get_threat_status_history(threat_model_id, threat_id)



# ===========================================================================
# TICKET EXPORT — push threats to GitHub Issues / Jira
# ===========================================================================
class CreateTicketRequest(BaseModel):
    threat: dict
    system_name: str
    provider: str  # "github" | "jira"


@app.post("/api/create-ticket")
async def create_ticket(req: CreateTicketRequest, user: dict = Depends(get_current_user)):
    """Create a GitHub Issue or Jira ticket for a single threat."""
    from threat_engine.ticket_export import create_github_issue, create_jira_issue
    try:
        if req.provider == "github":
            result = create_github_issue(req.threat, req.system_name)
        elif req.provider == "jira":
            result = create_jira_issue(req.threat, req.system_name)
        else:
            raise HTTPException(400, f"Unknown provider: {req.provider!r}. Use 'github' or 'jira'.")
        return result
    except RuntimeError as e:
        raise HTTPException(400, str(e))

# ===========================================================================
# REPORT: Risk register CSV export
# ===========================================================================
@app.post("/api/report/csv")
async def report_csv(request: Request, user: dict = Depends(get_current_user)):
    """Export threat analysis as a risk register CSV."""
    body = await request.json()
    threats = body.get("threats", [])
    system_name = body.get("system", {}).get("name", "System")
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Title", "Severity", "Methodology", "Component", "Category",
                     "CVSS3.1", "DREAD", "Cross-boundary", "Status", "Owner", "Due date", "Description"])
    for i, t in enumerate(threats):
        writer.writerow([
            t.get("id", f"T{i+1:03d}"),
            t.get("title", ""),
            t.get("severity", ""),
            t.get("methodology", "").upper(),
            t.get("component_name", ""),
            t.get("category", ""),
            t.get("cvss31", {}).get("score", ""),
            t.get("dread", {}).get("total", "") if t.get("dread") else "",
            "Yes" if t.get("cross_boundary") else "No",
            "open", "", "",
            t.get("description", ""),
        ])
    csv_bytes = buf.getvalue().encode("utf-8")
    return Response(
        content=csv_bytes,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="risk_register_{system_name.replace(" ","_")}.csv"'}
    )



# ===========================================================================
# EXECUTIVE REPORT — Claude-narrated PDF/HTML summary
# ===========================================================================
@app.post("/api/report/executive")
async def report_executive(request: Request, user: dict = Depends(get_current_user)):
    """Generate an executive threat model report (HTML or PDF).
    Query param: ?format=html (default) | ?format=pdf (requires WeasyPrint).
    """
    from threat_engine.executive_report import generate_executive_report, html_to_pdf
    body   = await request.json()
    fmt    = request.query_params.get("format", "html")
    api_key = os.getenv("ANTHROPIC_API_KEY")
    html   = generate_executive_report(body, api_key=api_key)

    if fmt == "pdf":
        pdf = html_to_pdf(html)
        if pdf:
            name = body.get("system", {}).get("name", "System").replace(" ", "_")
            return Response(content=pdf, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="exec_report_{name}.pdf"'})
        # WeasyPrint not installed — fall back to HTML download
    name = body.get("system", {}).get("name", "System").replace(" ", "_")
    return Response(content=html.encode(), media_type="text/html",
                    headers={"Content-Disposition": f'attachment; filename="exec_report_{name}.html"'})

# ===========================================================================
# TEMPLATES — serve static templates.json
# ===========================================================================
@app.get("/api/templates")
async def get_templates():
    """Return built-in system templates."""
    import json as _json
    tpl_path = BASE_DIR / "static" / "templates.json"
    if not tpl_path.exists():
        return []
    return _json.loads(tpl_path.read_text())



# ===========================================================================
# E5: Custom threat rule CRUD endpoints
# ===========================================================================
class CustomRuleIn(BaseModel):
    name: str
    description: str = ""
    category: str = "Custom"
    title: str
    severity: str = "Medium"
    applies_to: list[str] = []
    mitigations: list[str] = []
    tags: list[str] = []

@app.post("/api/custom-rules")
async def create_rule(body: CustomRuleIn, user: dict = Depends(get_current_user)):
    return domain.create_custom_rule(user["id"], body.dict())

@app.get("/api/custom-rules")
async def list_rules(user: dict = Depends(get_current_user)):
    return domain.list_custom_rules(user["id"])

@app.put("/api/custom-rules/{rule_id}")
async def update_rule(rule_id: int, body: dict, user: dict = Depends(get_current_user)):
    r = domain.update_custom_rule(rule_id, user["id"], body)
    if not r: raise HTTPException(404, "Rule not found")
    return r

@app.delete("/api/custom-rules/{rule_id}")
async def delete_rule(rule_id: int, user: dict = Depends(get_current_user)):
    domain.delete_custom_rule(rule_id, user["id"])
    return {"deleted": True}


# ===========================================================================
# U2: Bulk threat status update
# ===========================================================================
class BulkStatusItem(BaseModel):
    threat_id: str
    status: str
    owner: str | None = None
    due_date: str | None = None

class BulkStatusRequest(BaseModel):
    threat_model_id: int
    updates: list[BulkStatusItem]

@app.post("/api/threat-status/bulk")
async def bulk_update_status(req: BulkStatusRequest, user: dict = Depends(get_current_user)):
    """Update multiple threat statuses in one call."""
    tm = domain.get_threat_model(req.threat_model_id)
    if not tm: raise HTTPException(404, "Threat model not found")
    ensure_can_access_threat_model(user, tm)
    updated = []
    for item in req.updates:
        try:
            r = domain.upsert_threat_status(
                req.threat_model_id, item.threat_id, item.status,
                updated_by=user["id"], owner=item.owner, due_date=item.due_date
            )
            updated.append(r)
        except Exception as e:
            updated.append({"threat_id": item.threat_id, "error": str(e)})
    return {"updated": len(updated), "results": updated}


# ===========================================================================
# U3: Share-link for read-only threat model
# ===========================================================================
import secrets as _secrets
from datetime import datetime as _dt, timedelta as _td

@app.post("/api/share/{threat_model_id}")
async def create_share_link(
    threat_model_id: int,
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Generate a time-limited shareable URL for a threat model report."""
    tm = domain.get_threat_model(threat_model_id)
    if not tm: raise HTTPException(404, "Threat model not found")
    ensure_can_access_threat_model(user, tm)
    body = await request.json()
    expires_days = int(body.get("expires_days", 7))
    token = _secrets.token_urlsafe(24)
    expires_at = (_dt.utcnow() + _td(days=expires_days)).isoformat()
    # Store in DB (idempotent - create table if not exists)
    with domain.db_conn(write=True) as c:
        try:
            c.execute("""CREATE TABLE IF NOT EXISTS share_tokens (
                token TEXT PRIMARY KEY, threat_model_id INTEGER NOT NULL,
                created_by INTEGER NOT NULL, expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )""")
        except Exception:
            pass
        c.execute(
            "INSERT INTO share_tokens (token, threat_model_id, created_by, expires_at) VALUES (?,?,?,?)",
            (token, threat_model_id, user["id"], expires_at)
        )
    base_url = str(request.base_url).rstrip("/")
    return {"url": f"{base_url}/share/{token}", "expires_at": expires_at, "token": token}


@app.get("/share/{token}", include_in_schema=False)
async def view_shared_report(token: str):
    """Serve a read-only HTML report for a share token (no auth required)."""
    from threat_engine.html_report import generate_html_report
    with domain.db_conn() as c:
        row = c.execute(
            "SELECT * FROM share_tokens WHERE token=?", (token,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Share link not found or expired")
    row = dict(row)
    from datetime import datetime as _dt2
    if _dt2.utcnow().isoformat() > row["expires_at"]:
        raise HTTPException(410, "Share link has expired")
    tm = domain.get_threat_model(row["threat_model_id"])
    if not tm:
        raise HTTPException(404, "Threat model not found")
    html = generate_html_report(tm)
    return HTMLResponse(content=html)


# ===========================================================================
# D3: Health check + readiness endpoints
# ===========================================================================
@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"status": "ok", "version": "2.1"}

@app.get("/readyz", include_in_schema=False)
async def readyz():
    try:
        with domain.db_conn() as c:
            c.execute("SELECT 1")
        return {"status": "ready", "db": "ok"}
    except Exception as e:
        raise HTTPException(503, f"DB not ready: {e}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "127.0.0.1")
    print(f"\n  Threat Modeler v2.0 running on {host}:{port}")
    print(f"  LLM enhancement: {'ENABLED' if os.getenv('ANTHROPIC_API_KEY') else 'disabled'}")
    print(f"  JWT_SECRET:      {'set' if os.getenv('JWT_SECRET') else 'NOT SET (sessions reset on restart)'}")
    print(f"  Initial admin:   {'configured' if os.getenv('INITIAL_ADMIN_EMAIL') else 'not configured'}\n")
    uvicorn.run("app:app", host=host, port=port, reload=False)
