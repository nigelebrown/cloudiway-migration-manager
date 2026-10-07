import asyncio
import io
import secrets
import pandas as pd
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings
from app.db import init_db, conn, set_setting, get_setting, set_runtime, get_runtime, log_event
from app.security import encrypt_secret, decrypt_secret
from app.clients.cloudiway import CloudiwayClient
from app.service import (
    launch_next_batch,
    refresh_status,
    rotate_user_password,
    _rackspace_client,
    _cloudiway_client,
)

app = FastAPI(title="JCF Mail Migration Console")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, https_only=False)
templates = Jinja2Templates(directory="app/templates")
_poller_task: asyncio.Task | None = None


def require_admin(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(status_code=401, detail="Administrator session required")


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
    init_db()
    _poller_task = asyncio.create_task(status_poller())


@app.on_event("shutdown")
async def shutdown():
    if _poller_task:
        _poller_task.cancel()


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if request.session.get("admin"):
        return RedirectResponse("/dashboard", 303)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login(request: Request, admin_password: str = Form(...)):
    if not secrets.compare_digest(admin_password, settings.app_admin_password):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid administrator password"},
            status_code=401,
        )
    request.session["admin"] = True
    return RedirectResponse("/dashboard", 303)


@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    require_admin(request)
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "cloudiway_connected": bool(get_setting("cloudiway_token")),
            "rackspace_configured": bool(get_setting("rackspace_secret_key")),
            "rackspace_user_key": get_setting("rackspace_user_key") or "",
            "rackspace_customer_id": get_setting("rackspace_customer_id") or "",
            "project_header": get_setting("cloudiway_project_header") or settings.cloudiway_project_header,
            "source_pool": get_setting("cloudiway_source_pool_id") or "",
            "target_pool": get_setting("cloudiway_target_pool_id") or "",
        },
    )


@app.post("/settings/rackspace")
async def save_rackspace(
    request: Request,
    user_key: str = Form(...),
    secret_key: str = Form(...),
    customer_id: str = Form(...),
):
    require_admin(request)
    set_setting("rackspace_user_key", user_key.strip())
    set_setting("rackspace_secret_key", encrypt_secret(secret_key.strip()), True)
    set_setting("rackspace_customer_id", customer_id.strip())
    return RedirectResponse("/settings", 303)


@app.post("/settings/rackspace/test")
async def test_rackspace(request: Request):
    require_admin(request)
    try:
        await _rackspace_client().test_connection()
        return JSONResponse({"ok": True, "message": "Rackspace API connection successful"})
    except Exception as exc:
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
        set_setting("cloudiway_project_header", project_header.strip() or "JCF")
        if data.get("refreshToken"):
            set_setting("cloudiway_refresh_token", encrypt_secret(data["refreshToken"]), True)
        if data.get("expiration"):
            set_setting("cloudiway_token_expiration", data["expiration"])
        return RedirectResponse("/settings", 303)
    except Exception as exc:
        return RedirectResponse(f"/settings?error={str(exc)[:200]}", 303)


@app.post("/settings/cloudiway/pools")
async def save_pools(
    request: Request,
    source_pool_id: int = Form(...),
    target_pool_id: int = Form(...),
):
    require_admin(request)
    set_setting("cloudiway_source_pool_id", str(source_pool_id))
    set_setting("cloudiway_target_pool_id", str(target_pool_id))
    return RedirectResponse("/settings", 303)


@app.get("/api/cloudiway/projects")
async def api_projects(request: Request):
    require_admin(request)
    return await _cloudiway_client().projects()


@app.get("/api/cloudiway/connectors")
async def api_connectors(request: Request):
    require_admin(request)
    client = _cloudiway_client()
    return {
        "connectors": await client.connectors(),
        "pools": await client.connector_pools(),
    }


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    require_admin(request)
    return templates.TemplateResponse("upload.html", {"request": request})


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
        return templates.TemplateResponse(
            "upload.html", {"request": request, "error": f"Could not read file: {exc}"}, status_code=400
        )

    df.columns = [str(c).strip().lower() for c in df.columns]
    aliases = {
        "email": "source_email",
        "source email": "source_email",
        "target email": "target_email",
        "firstname": "first_name",
        "lastname": "last_name",
    }
    df.rename(columns={c: aliases.get(c, c) for c in df.columns}, inplace=True)
    if "source_email" not in df.columns:
        return templates.TemplateResponse(
            "upload.html", {"request": request, "error": "The file must include source_email (or Email)."}, status_code=400
        )
    if "target_email" not in df.columns:
        df["target_email"] = df["source_email"]

    imported = skipped = 0
    with conn() as db:
        for _, row in df.iterrows():
            src = str(row.get("source_email", "")).strip().lower()
            tgt = str(row.get("target_email", "")).strip().lower()
            if "@" not in src or "@" not in tgt:
                skipped += 1
                continue
            first = str(row.get("first_name", "") or "").strip()
            last = str(row.get("last_name", "") or "").strip()
            db.execute(
                """INSERT INTO users(source_email,target_email,first_name,last_name)
                   VALUES(?,?,?,?)
                   ON CONFLICT(source_email) DO UPDATE SET
                     target_email=excluded.target_email,
                     first_name=excluded.first_name,
                     last_name=excluded.last_name""",
                (src, tgt, first, last),
            )
            imported += 1
    log_event(None, "file_upload", f"Imported/updated {imported}; skipped {skipped}; file={file.filename}")
    return RedirectResponse("/dashboard", 303)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, q: str = ""):
    require_admin(request)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "q": q,
            "pilot_size": settings.pilot_size,
            "batch_size": settings.batch_size,
            "paused": get_runtime("automation_paused", "0") == "1",
            "pause_reason": get_runtime("pause_reason", ""),
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
    result = await launch_next_batch(force=True)
    return JSONResponse(result)


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
            "UPDATE users SET migration_status='waiting',error_message=NULL,progress_percent=NULL WHERE id=?",
            (user_id,),
        )
    set_runtime("automation_paused", "0")
    set_runtime("pause_reason", "")
    return {"ok": True}


@app.get("/health")
async def health():
    return {"ok": True, "service": "cloudiway-migration-manager"}
