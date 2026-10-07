import asyncio
import io
import re
import secrets
import time
import json
import zipfile
from collections import defaultdict, deque

import pandas as pd
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.db import init_db, conn, set_setting, get_setting, set_runtime, get_runtime, log_event
from app.security import encrypt_secret, decrypt_secret
from app.clients.cloudiway import CloudiwayClient
from app.diagnostics import log_info, log_error, tail_log, redact
from app.service import (
    launch_next_batch,
    refresh_status,
    rotate_user_password,
    _rackspace_client,
    _cloudiway_client,
    _cloudiway_client_ready,
)

app = FastAPI(title="JCF Mail Migration Console")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=settings.session_https_only,
    same_site="strict",
)
templates = Jinja2Templates(directory="app/templates")
_poller_task: asyncio.Task | None = None
_login_attempts: dict[str, deque[float]] = defaultdict(deque)
EMAIL_RE = re.compile(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$", re.I)

@app.middleware("http")
async def diagnostic_request_log(request: Request, call_next):
    started = time.monotonic()
    try:
        response = await call_next(request)
        log_info(
            "http_request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
        )
        return response
    except Exception as exc:
        log_error(
            "http_exception",
            method=request.method,
            path=request.url.path,
            error=exc,
        )
        raise


def _validate_runtime_secrets():
    bad = {
        "change-this-now",
        "change-this-too",
        "CHANGE-ME-TO-A-STRONG-ADMIN-PASSWORD",
        "CHANGE-ME-TO-A-LONG-RANDOM-ENCRYPTION-SECRET",
        "CHANGE-ME-TO-A-LONG-RANDOM-SESSION-SECRET",
        "",
    }
    values = {
        "APP_ADMIN_PASSWORD": settings.app_admin_password,
        "APP_ENCRYPTION_KEY": settings.app_encryption_key,
        "SESSION_SECRET": settings.session_secret,
    }
    weak = [name for name, value in values.items() if value in bad or len(value) < 12]
    if weak:
        raise RuntimeError("Unsafe default/weak application secret(s): " + ", ".join(weak))


def require_admin(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(status_code=401, detail="Administrator session required")


def _page_auth(request: Request):
    if not request.session.get("admin"):
        return RedirectResponse("/", 303)
    return None


def _clean_cell(value) -> str:
    if value is None or pd.isna(value):
        return ""
    return str(value).strip()


def _normalize_cloudiway_projects(payload) -> list[dict]:
    projects: list[dict] = []

    def walk(value):
        if isinstance(value, list):
            for item in value:
                walk(item)
            return
        if not isinstance(value, dict):
            return
        if isinstance(value.get("id"), (int, str)) and value.get("name"):
            pid = str(value.get("id")).strip()
            name = str(value.get("name")).strip()
            if pid and name and pid.isdigit():
                projects.append({"id": pid, "name": name})
        for child in value.values():
            if isinstance(child, (dict, list)):
                walk(child)

    walk(payload)
    dedup = {}
    for p in projects:
        dedup[p["id"]] = p
    return list(dedup.values())


def _resolve_cloudiway_project(projects: list[dict], requested: str) -> dict | None:
    wanted = (requested or "").strip().lower()
    for p in projects:
        if p["name"].strip().lower() == wanted:
            return p
    if wanted.isdigit():
        for p in projects:
            if p["id"] == wanted:
                return p
    if len(projects) == 1:
        return projects[0]
    return None


def _normalize_cloudiway_pools(payload) -> list[dict]:
    """Flatten Cloudiway connector-pool responses into dropdown choices."""
    choices: dict[str, dict] = {}

    def walk(value, context_name=""):
        if isinstance(value, list):
            for item in value:
                walk(item, context_name)
            return
        if not isinstance(value, dict):
            return

        name = ""
        for key in (
            "poolName", "connectorPoolName", "displayName", "name",
            "connectorName", "description", "label"
        ):
            v = value.get(key)
            if isinstance(v, str) and v.strip():
                name = v.strip()
                break
        if not name:
            name = context_name

        pool_id = None
        for key in ("poolId", "connectorPoolId", "id"):
            v = value.get(key)
            if isinstance(v, (int, str)) and str(v).strip().isdigit():
                pool_id = str(v).strip()
                break

        type_text = " ".join(
            str(value.get(k) or "")
            for k in ("type", "connectorType", "technology", "platform", "kind", "provider")
        ).strip()

        if pool_id:
            label_parts = [p for p in (name, type_text) if p]
            label = " - ".join(dict.fromkeys(label_parts)) or f"Pool {pool_id}"
            choices[pool_id] = {
                "id": pool_id,
                "label": label,
                "raw_name": name,
                "type": type_text,
            }

        for key, child in value.items():
            if isinstance(child, (dict, list)):
                walk(child, name or context_name)

    walk(payload)
    return sorted(choices.values(), key=lambda x: x["label"].lower())


async def status_poller():
    while True:
        try:
            if get_runtime("automation_running", "0") == "1" and get_setting("cloudiway_token"):
                await refresh_status()
        except Exception as exc:
            log_event(None, "background_refresh_failed", str(exc))
        await asyncio.sleep(max(10, settings.status_poll_seconds))


@app.on_event("startup")
async def startup():
    global _poller_task
    _validate_runtime_secrets()
    init_db()
    log_info("application_startup", database=settings.db_name)
    # Recover from an interrupted process so a stale 'preparing' row never blocks the app.
    with conn() as db:
        db.execute(
            "UPDATE users SET migration_status='failed',error_message='Recovered after interrupted preparation; retry this user.' "
            "WHERE migration_status='preparing'"
        )
    _poller_task = asyncio.create_task(status_poller())


@app.on_event("shutdown")
async def shutdown():
    if _poller_task:
        _poller_task.cancel()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if request.session.get("admin"):
        return RedirectResponse("/dashboard", 303)
    return templates.TemplateResponse(request=request, name="login.html", context={"request": request})


@app.post("/login")
async def login(request: Request, admin_password: str = Form(...)):
    key = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _login_attempts[key]
    while q and now - q[0] > settings.login_window_seconds:
        q.popleft()
    password_ok = secrets.compare_digest(admin_password, settings.app_admin_password)
    if password_ok:
        q.clear()
        if settings.session_https_only and request.url.scheme != "https":
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "request": request,
                    "error": "HTTPS is required for sign-in because secure session cookies are enabled. Use HTTPS or set SESSION_HTTPS_ONLY=false only for a temporary local trial.",
                },
                status_code=400,
            )
        request.session["admin"] = True
        return RedirectResponse("/dashboard", 303)
    if len(q) >= settings.login_max_attempts:
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"request": request, "error": "Too many failed sign-in attempts. Try again later."},
            status_code=429,
        )
    q.append(now)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request, "error": "Invalid administrator password"},
        status_code=401,
    )


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    redirect = _page_auth(request)
    if redirect:
        return redirect
    pools = request.session.pop("cloudiway_pools", None)
    if pools is None and get_setting("cloudiway_token"):
        try:
            client = await _cloudiway_client_ready()
            pools = _normalize_cloudiway_pools(await client.connector_pools())
        except Exception:
            pools = []
    pools = pools or []

    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={
            "request": request,
            "cloudiway_connected": bool(get_setting("cloudiway_token")),
            "rackspace_auth_mode": get_setting("rackspace_auth_mode") or "api_key",
            "rackspace_configured": bool(
                get_setting("rackspace_secret_key") or get_setting("rackspace_password")
            ),
            "rackspace_user_key": get_setting("rackspace_user_key") or "",
            "rackspace_username": get_setting("rackspace_username") or "",
            "rackspace_customer_id": get_setting("rackspace_customer_id") or "",
            "project_header": get_setting("cloudiway_project_name") or get_setting("cloudiway_project_header") or settings.cloudiway_project_header,
            "source_pool": get_setting("cloudiway_source_pool_id") or "",
            "target_pool": get_setting("cloudiway_target_pool_id") or "",
            "cloudiway_pools": pools,
            "error": request.session.pop("settings_error", None),
            "notice": request.session.pop("settings_notice", None),
        },
    )


@app.post("/settings/rackspace")
async def save_rackspace(
    request: Request,
    auth_mode: str = Form("api_key"),
    user_key: str = Form(""),
    secret_key: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    customer_id: str = Form(""),
):
    require_admin(request)
    mode = auth_mode.strip() or "api_key"
    if mode not in ("api_key", "username_password"):
        request.session["settings_error"] = "Invalid Rackspace authentication mode."
        return RedirectResponse("/settings", 303)

    set_setting("rackspace_auth_mode", mode)
    set_setting("rackspace_customer_id", customer_id.strip())

    if mode == "username_password":
        if not username.strip() or not password:
            request.session["settings_error"] = "Rackspace username and password are required."
            return RedirectResponse("/settings", 303)
        set_setting("rackspace_username", username.strip())
        set_setting("rackspace_password", encrypt_secret(password), True)
        request.session["settings_notice"] = (
            "Rackspace username/password saved. Use Test Rackspace Access to verify "
            "Identity authentication and whether mailbox password administration is permitted."
        )
    else:
        if not user_key.strip() or not secret_key or not customer_id.strip():
            request.session["settings_error"] = (
                "Rackspace Email API User Key, Secret Key and Customer Account Number are required."
            )
            return RedirectResponse("/settings", 303)
        set_setting("rackspace_user_key", user_key.strip())
        set_setting("rackspace_secret_key", encrypt_secret(secret_key), True)
        request.session["settings_notice"] = "Rackspace Email API settings saved."

    return RedirectResponse("/settings", 303)


@app.post("/settings/rackspace/test")
async def test_rackspace(request: Request):
    require_admin(request)
    try:
        result = await _rackspace_client().test_connection()
        log_info("rackspace_capability_test", result=result)
        return JSONResponse(result)
    except Exception as exc:
        log_error("rackspace_capability_test_failed", error=exc)
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)


@app.post("/settings/cloudiway/login")
async def cloudiway_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    project_header: str = Form("JCF"),
):
    require_admin(request)
    client = CloudiwayClient(project_header=project_header.strip() or "JCF")
    try:
        data = await client.login(username.strip(), password)
        token = data.get("token")
        if not token:
            raise RuntimeError("Cloudiway login succeeded but no access token was returned")
        set_setting("cloudiway_token", encrypt_secret(token), True)
        if data.get("refreshToken"):
            set_setting("cloudiway_refresh_token", encrypt_secret(data["refreshToken"]), True)
        if data.get("expiration"):
            set_setting("cloudiway_token_expiration", data["expiration"])

        requested_project = project_header.strip() or "JCF"
        set_setting("cloudiway_project_name", requested_project)

        try:
            project_payload = await client.projects(include_project_header=False)
            projects = _normalize_cloudiway_projects(project_payload)
            selected_project = _resolve_cloudiway_project(projects, requested_project)
            if not selected_project:
                names = ", ".join(p["name"] for p in projects[:10]) or "none returned"
                raise RuntimeError(
                    f"Could not resolve Cloudiway project '{requested_project}'. Accessible projects: {names}"
                )

            # Connector endpoints expect the actual projectId, not the display name.
            client.project_header = selected_project["id"]
            set_setting("cloudiway_project_header", selected_project["id"])
            set_setting("cloudiway_project_id", selected_project["id"])
            set_setting("cloudiway_project_name", selected_project["name"])

            pools_payload = await client.connector_pools()
            pools = _normalize_cloudiway_pools(pools_payload)
            request.session["cloudiway_pools"] = pools
            request.session["settings_notice"] = (
                f"Cloudiway connection successful. Project '{selected_project['name']}' "
                f"(ID {selected_project['id']}) selected. Found {len(pools)} connector pool(s)."
            )
            log_info("cloudiway_connected", project_name=selected_project["name"], project_id=selected_project["id"], pool_count=len(pools))
        except Exception as pool_exc:
            request.session["settings_notice"] = "Cloudiway authentication successful."
            request.session["settings_error"] = (
                "Authenticated, but project/connector discovery failed: "
                + str(pool_exc)[:500]
            )
            log_error("cloudiway_discovery_failed", requested_project=requested_project, error=pool_exc)
    except Exception as exc:
        request.session["settings_error"] = str(exc)[:500]
        log_error("cloudiway_login_failed", error=exc)
    return RedirectResponse("/settings", 303)


@app.post("/settings/cloudiway/pools")
async def save_pools(
    request: Request,
    source_pool_id: int = Form(...),
    target_pool_id: int = Form(...),
):
    require_admin(request)
    set_setting("cloudiway_source_pool_id", str(source_pool_id))
    set_setting("cloudiway_target_pool_id", str(target_pool_id))
    request.session["settings_notice"] = "Cloudiway connector pool IDs saved."
    return RedirectResponse("/settings", 303)


@app.get("/api/cloudiway/projects")
async def api_projects(request: Request):
    require_admin(request)
    try:
        return await _cloudiway_client().projects()
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)


@app.get("/api/cloudiway/connectors")
async def api_connectors(request: Request):
    require_admin(request)
    try:
        client = await _cloudiway_client_ready()
        raw_pools = await client.connector_pools()
        return {
            "connectors": await client.connectors(),
            "pools": raw_pools,
            "choices": _normalize_cloudiway_pools(raw_pools),
        }
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)


@app.get("/api/cloudiway/pools")
async def api_cloudiway_pools(request: Request):
    require_admin(request)
    try:
        client = await _cloudiway_client_ready()
        return {"choices": _normalize_cloudiway_pools(await client.connector_pools())}
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc), "choices": []}, status_code=400)


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    redirect = _page_auth(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(request=request, name="upload.html", context={"request": request})


@app.post("/upload")
async def upload_users(request: Request, file: UploadFile = File(...)):
    require_admin(request)
    raw = await file.read()
    try:
        if file.filename.lower().endswith(".csv"):
            df = pd.read_csv(io.BytesIO(raw))
        else:
            df = pd.read_excel(io.BytesIO(raw))
    except Exception as exc:
        return templates.TemplateResponse(request=request, name="upload.html", context={"request": request, "error": f"Could not read file: {exc}"}, status_code=400)

    df.columns = [str(c).strip().lower() for c in df.columns]
    aliases = {
        "email": "source_email",
        "source email": "source_email",
        "target email": "target_email",
        "firstname": "first_name",
        "lastname": "last_name",
        "first name": "first_name",
        "last name": "last_name",
    }
    df.rename(columns={c: aliases.get(c, c) for c in df.columns}, inplace=True)
    if "source_email" not in df.columns:
        return templates.TemplateResponse(request=request, name="upload.html", context={"request": request, "error": "The file must include source_email (or Email)."}, status_code=400)

    imported = skipped = protected = 0
    with conn() as db:
        for _, row in df.iterrows():
            src = _clean_cell(row.get("source_email")).lower()
            tgt = _clean_cell(row.get("target_email")).lower() if "target_email" in df.columns else ""
            if not tgt:
                tgt = src
            if not EMAIL_RE.fullmatch(src) or not EMAIL_RE.fullmatch(tgt):
                skipped += 1
                continue
            first = _clean_cell(row.get("first_name"))
            last = _clean_cell(row.get("last_name"))

            existing = db.execute(
                "SELECT migration_status FROM users WHERE source_email=?", (src,)
            ).fetchone()
            if existing and existing["migration_status"] in ("preparing", "ready", "migrating", "completed"):
                protected += 1
                continue

            db.execute(
                """INSERT INTO users(source_email,target_email,first_name,last_name)
                   VALUES(?,?,?,?)
                   ON DUPLICATE KEY UPDATE
                     target_email=VALUES(target_email),
                     first_name=VALUES(first_name),
                     last_name=VALUES(last_name)""",
                (src, tgt, first, last),
            )
            imported += 1

    log_event(
        None,
        "file_upload",
        f"Imported/updated {imported}; skipped invalid {skipped}; protected active/completed {protected}; file={file.filename}",
    )
    request.session["upload_notice"] = (
        f"Upload complete: {imported} imported/updated, {skipped} invalid skipped, "
        f"{protected} active/completed users left unchanged."
    )
    return RedirectResponse("/dashboard", 303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, q: str = ""):
    redirect = _page_auth(request)
    if redirect:
        return redirect
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "request": request,
            "q": q,
            "pilot_size": settings.pilot_size,
            "batch_size": settings.batch_size,
            "upload_notice": request.session.pop("upload_notice", None),
        },
    )


@app.get("/api/dashboard")
async def dashboard_data(request: Request, q: str = ""):
    require_admin(request)
    with conn() as db:
        counts = {
            r["migration_status"]: r["c"]
            for r in db.execute(
                "SELECT migration_status,COUNT(*) c FROM users GROUP BY migration_status"
            ).fetchall()
        }
        if q:
            values = tuple([f"%{q}%"] * 4)
            rows = db.execute(
                """SELECT id,source_email,target_email,first_name,last_name,rackspace_status,
                          cloudiway_status,migration_status,progress_percent,error_message,batch_number,updated_at
                   FROM users WHERE source_email LIKE ? OR target_email LIKE ? OR first_name LIKE ? OR last_name LIKE ?
                   ORDER BY id DESC LIMIT 1000""",
                values,
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT id,source_email,target_email,first_name,last_name,rackspace_status,
                          cloudiway_status,migration_status,progress_percent,error_message,batch_number,updated_at
                   FROM users ORDER BY id DESC LIMIT 1000"""
            ).fetchall()
    return {
        "counts": counts,
        "users": [dict(r) for r in rows],
        "paused": get_runtime("automation_paused", "0") == "1",
        "pause_reason": get_runtime("pause_reason", ""),
    }


@app.post("/automation/start")
async def automation_start(request: Request):
    require_admin(request)
    set_runtime("automation_paused", "0")
    set_runtime("pause_reason", "")
    set_runtime("automation_running", "1")
    return JSONResponse(await launch_next_batch(force=True))


@app.post("/automation/pause")
async def automation_pause(request: Request):
    require_admin(request)
    set_runtime("automation_paused", "1")
    set_runtime("pause_reason", "Paused manually by administrator")
    return {"ok": True}


@app.post("/automation/continue")
async def automation_continue(request: Request):
    require_admin(request)
    set_runtime("automation_paused", "0")
    set_runtime("pause_reason", "")
    return await launch_next_batch(force=True)


@app.post("/status/refresh")
async def status_refresh(request: Request):
    require_admin(request)
    return await refresh_status()


@app.get("/users/{user_id}/password")
async def reveal_password(request: Request, user_id: int):
    require_admin(request)
    with conn() as db:
        row = db.execute(
            "SELECT source_email,generated_password_enc FROM users WHERE id=?", (user_id,)
        ).fetchone()
    if not row or not row["generated_password_enc"]:
        raise HTTPException(status_code=404, detail="No generated password is stored for this user")
    log_event(user_id, "password_revealed", "Administrator revealed the stored temporary password")
    return {"source_email": row["source_email"], "password": decrypt_secret(row["generated_password_enc"])}


@app.post("/users/{user_id}/rotate-password")
async def rotate_password(request: Request, user_id: int):
    require_admin(request)
    try:
        password = await rotate_user_password(user_id)
        return {"ok": True, "password": password}
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)


@app.post("/users/{user_id}/retry")
async def retry_user(request: Request, user_id: int):
    require_admin(request)
    with conn() as db:
        db.execute(
            "UPDATE users SET migration_status='waiting',error_message=NULL,progress_percent=NULL,batch_number=NULL,batch_started_at=NULL WHERE id=?",
            (user_id,),
        )
    return {"ok": True}


@app.get("/diagnostics/download")
async def download_diagnostics(request: Request):
    require_admin(request)

    with conn() as db:
        status_counts = [
            dict(r) for r in db.execute(
                "SELECT migration_status,COUNT(*) AS count FROM users GROUP BY migration_status"
            ).fetchall()
        ]
        recent_users = [
            dict(r) for r in db.execute(
                """SELECT id,cloudiway_object_id,rackspace_status,cloudiway_status,
                          migration_status,progress_percent,batch_number,error_message,updated_at
                   FROM users ORDER BY updated_at DESC LIMIT 100"""
            ).fetchall()
        ]
        recent_events = [
            dict(r) for r in db.execute(
                """SELECT id,user_id,event_type,message,created_at
                   FROM events ORDER BY id DESC LIMIT 200"""
            ).fetchall()
        ]

    summary = {
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "application": "JCF Cloudiway Migration Manager",
        "configuration": {
            "cloudiway_base_url": settings.cloudiway_base_url,
            "cloudiway_project_name": get_setting("cloudiway_project_name"),
            "cloudiway_project_id": get_setting("cloudiway_project_id"),
            "cloudiway_source_pool_id": get_setting("cloudiway_source_pool_id"),
            "cloudiway_target_pool_id": get_setting("cloudiway_target_pool_id"),
            "cloudiway_token_configured": bool(get_setting("cloudiway_token")),
            "rackspace_base_url": settings.rackspace_base_url,
            "rackspace_auth_mode": get_setting("rackspace_auth_mode") or "api_key",
            "rackspace_credentials_configured": bool(
                get_setting("rackspace_secret_key") or get_setting("rackspace_password")
            ),
        },
        "runtime": {
            "automation_running": get_runtime("automation_running", "0"),
            "automation_paused": get_runtime("automation_paused", "0"),
            "pause_reason": get_runtime("pause_reason", ""),
        },
        "migration_status_counts": status_counts,
        "recent_users": recent_users,
        "recent_events": recent_events,
    }

    summary_text = redact(json.dumps(summary, default=str, indent=2))
    log_text = tail_log()

    import io as _io
    buffer = _io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("diagnostic-summary.json", summary_text)
        zf.writestr("application.log", log_text)
    buffer.seek(0)

    filename = "cloudiway-diagnostics-" + time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + ".zip"
    log_info("diagnostics_downloaded", filename=filename)
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/health")
async def health():
    return {"ok": True, "service": "cloudiway-migration-manager"}
