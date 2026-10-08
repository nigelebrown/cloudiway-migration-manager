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
from app.security import encrypt_secret, decrypt_secret, generate_password
from app.clients.cloudiway import CloudiwayClient
from app.diagnostics import log_info, log_error, tail_log, redact
from app.rackspace_template import RACKSPACE_MAILBOX_HEADERS, rackspace_row
from app.service import (
    launch_next_batch,
    refresh_status,
    rotate_user_password,
    _rackspace_client,
    _cloudiway_client,
    _cloudiway_client_ready,
    start_manual_migrations,
    launch_next_confirmed_manual_batch,
    ensure_upload_cloudiway_batch,
    prepare_manual_upload_batch,
    start_upload_batch,
    ensure_migration_cloudiway_batch,
    prepare_migration_batch,
    start_migration_batch,
    advance_upload_workflows,
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


def _build_rackspace_password_package(migration_batch_id: int) -> tuple[io.BytesIO, str]:
    import csv as _csv

    with conn() as db:
        batch = db.execute(
            """SELECT mb.id,mb.batch_name,mb.upload_batch_id,ub.batch_name AS upload_batch_name
               FROM migration_batches mb
               JOIN upload_batches ub ON ub.id=mb.upload_batch_id
               WHERE mb.id=?""",
            (migration_batch_id,),
        ).fetchone()
        rows = db.execute(
            """SELECT u.*
               FROM migration_batch_members m
               JOIN users u ON u.id=m.user_id
               WHERE m.migration_batch_id=?
               ORDER BY u.id""",
            (migration_batch_id,),
        ).fetchall()

    if not batch:
        raise RuntimeError("Migration batch not found")
    if not rows:
        raise RuntimeError("Migration batch has no users")

    generated = []
    for row in rows:
        user = dict(row)
        if not user.get("generated_password_enc"):
            raise RuntimeError(
                f"No generated password exists for {user['source_email']} in this migration batch."
            )
        generated.append((user, decrypt_secret(user["generated_password_enc"])))

    rackspace_output = io.StringIO()
    writer = _csv.writer(rackspace_output, lineterminator="\n")
    writer.writerow(RACKSPACE_MAILBOX_HEADERS)
    for user, password in generated:
        writer.writerow(rackspace_row(user, password))
    rackspace_payload = rackspace_output.getvalue().encode("utf-8")

    rackspace_df = pd.DataFrame(
        [rackspace_row(user, password) for user, password in generated],
        columns=RACKSPACE_MAILBOX_HEADERS,
    )
    rackspace_xlsx = io.BytesIO()
    with pd.ExcelWriter(rackspace_xlsx, engine="openpyxl") as rack_writer:
        rackspace_df.to_excel(rack_writer, index=False, sheet_name="Mailboxes")
    rackspace_xlsx.seek(0)

    admin_rows = []
    for user, password in generated:
        admin_rows.append(
            {
                "email": user["source_email"],
                "password": password,
                "source_email": user["source_email"],
                "target_email": user["target_email"],
                "first_name": user.get("first_name") or "",
                "last_name": user.get("last_name") or "",
                "computer_number": user.get("computer_number") or "",
                "upload_batch": batch["upload_batch_name"],
                "migration_batch": batch["batch_name"],
            }
        )
    admin_df = pd.DataFrame(admin_rows)
    workbook = io.BytesIO()
    with pd.ExcelWriter(workbook, engine="openpyxl") as writer_xlsx:
        admin_df.to_excel(writer_xlsx, index=False, sheet_name="Password Map")
    workbook.seek(0)

    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", batch["batch_name"]).strip("-") or f"batch-{migration_batch_id}"
    archive_name = f"{safe_name}-rackspace-password-package.zip"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{safe_name}-rackspace-password-update.csv", rackspace_payload)
        zf.writestr(f"{safe_name}-rackspace-password-update.xlsx", rackspace_xlsx.getvalue())
        zf.writestr(f"{safe_name}-migration-password-map.xlsx", workbook.getvalue())
    archive.seek(0)
    return archive, archive_name


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
            token_present = bool(get_setting("cloudiway_token"))
            keep_connected = get_setting("cloudiway_keep_connected") == "1"

            # Keep the Cloudiway API session healthy independently of the web
            # administrator login session.
            if token_present and keep_connected:
                await _cloudiway_client_ready()

            if token_present:
                await advance_upload_workflows()

            if get_runtime("automation_running", "0") == "1" and token_present:
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
            "cloudiway_username": get_setting("cloudiway_username") or "",
            "cloudiway_keep_connected": get_setting("cloudiway_keep_connected") == "1",
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
    keep_connected: str = Form(""),
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

        if keep_connected:
            set_setting("cloudiway_keep_connected", "1")
            set_setting("cloudiway_username", username.strip())
            set_setting("cloudiway_password", encrypt_secret(password), True)
        else:
            set_setting("cloudiway_keep_connected", "0")
            set_setting("cloudiway_username", "")
            set_setting("cloudiway_password", "", True)

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
                f"(ID {selected_project['id']}) selected. Found {len(pools)} connector pool(s). "
                + ("Background reconnect is enabled." if keep_connected else "Background reconnect is disabled.")
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


@app.post("/settings/cloudiway/disconnect")
async def cloudiway_disconnect(request: Request):
    require_admin(request)
    set_setting("cloudiway_token", "", True)
    set_setting("cloudiway_refresh_token", "", True)
    set_setting("cloudiway_token_expiration", "")
    set_setting("cloudiway_keep_connected", "0")
    set_setting("cloudiway_username", "")
    set_setting("cloudiway_password", "", True)
    request.session["settings_notice"] = (
        "Cloudiway disconnected from this application. Existing Cloudiway migration jobs continue on Cloudiway."
    )
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
async def upload_users(
    request: Request,
    file: UploadFile = File(...),
    workflow_mode: str = Form("manual_bulk"),
):
    require_admin(request)

    if workflow_mode not in ("manual_bulk", "automatic"):
        workflow_mode = "manual_bulk"

    raw = await file.read()
    try:
        if file.filename.lower().endswith(".csv"):
            df = pd.read_csv(io.BytesIO(raw))
        else:
            df = pd.read_excel(io.BytesIO(raw))
    except Exception as exc:
        return templates.TemplateResponse(
            request=request,
            name="upload.html",
            context={"request": request, "error": f"Could not read file: {exc}"},
            status_code=400,
        )

    df.columns = [str(col).strip().lower() for col in df.columns]
    aliases = {
        "email": "source_email",
        "source email": "source_email",
        "target email": "target_email",
        "firstname": "first_name",
        "lastname": "last_name",
        "first name": "first_name",
        "last name": "last_name",
        "username": "source_email",
        "sourceemail": "source_email",
        "source email address": "source_email",
        "targetemail": "target_email",
        "destinationemail": "target_email",
        "destination email": "target_email",
        "destination email address": "target_email",
        "computer number": "computer_number",
        "computernumber": "computer_number",
        "computer_no": "computer_number",
        "computer no": "computer_number",
    }
    df.rename(columns={col: aliases.get(col, col) for col in df.columns}, inplace=True)
    if "source_email" not in df.columns:
        return templates.TemplateResponse(
            request=request,
            name="upload.html",
            context={"request": request, "error": "The file must include source_email (or Email)."},
            status_code=400,
        )

    total_rows = len(df.index)
    skipped = protected = imported = 0
    member_ids: list[int] = []

    with conn() as db:
        pending_name = "PENDING-" + time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + secrets.token_hex(3)
        cursor = db.execute(
            """INSERT INTO upload_batches(
                   batch_name,original_filename,workflow_mode,workflow_status,
                   auto_start,total_rows
               ) VALUES(?,?,?,?,?,?)""",
            (
                pending_name,
                file.filename,
                workflow_mode,
                "staged",
                0,
                total_rows,
            ),
        )
        upload_batch_id = int(cursor.lastrowid)
        batch_name = f"JCF-{time.strftime('%Y%m%d', time.gmtime())}-U{upload_batch_id:05d}"
        db.execute(
            "UPDATE upload_batches SET batch_name=?,cloudiway_batch_name=NULL WHERE id=?",
            (batch_name, upload_batch_id),
        )

        row_order = 0
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
            computer_number = _clean_cell(row.get("computer_number"))

            existing = db.execute(
                """SELECT u.id,u.migration_status,
                          (SELECT COUNT(*) FROM migration_batch_members mbm WHERE mbm.user_id=u.id) AS assigned
                   FROM users u WHERE u.source_email=?""",
                (src,),
            ).fetchone()
            if existing and (
                existing["migration_status"] in ("preparing", "ready", "migrating", "completed")
                or int(existing.get("assigned") or 0) > 0
            ):
                protected += 1
                continue

            db.execute(
                """INSERT INTO users(
                       source_email,target_email,first_name,last_name,computer_number,
                       password_reset_method
                   )
                   VALUES(?,?,?,?,?,?)
                   ON DUPLICATE KEY UPDATE
                     target_email=VALUES(target_email),
                     first_name=VALUES(first_name),
                     last_name=VALUES(last_name),
                     computer_number=VALUES(computer_number),
                     password_reset_method=VALUES(password_reset_method)""",
                (src, tgt, first, last, computer_number, workflow_mode),
            )
            user_row = db.execute(
                "SELECT id FROM users WHERE source_email=?",
                (src,),
            ).fetchone()
            user_id = int(user_row["id"])
            row_order += 1
            db.execute(
                """INSERT IGNORE INTO upload_batch_members(upload_batch_id,user_id,row_order)
                   VALUES(?,?,?)""",
                (upload_batch_id, user_id, row_order),
            )

            # Staging an upload does not generate passwords. The admin chooses
            # the next quantity (or exact users) before a migration batch is created.
            db.execute(
                """UPDATE users
                   SET generated_password_enc=NULL,
                       password_reset_method=?,
                       manual_password_generated_at=NULL,
                       manual_password_confirmed_at=NULL,
                       rackspace_status=?,
                       cloudiway_status='not_submitted',
                       migration_status='waiting',
                       progress_percent=NULL,
                       progress_detail=NULL,
                       error_message=NULL,
                       batch_number=NULL,
                       batch_started_at=NULL,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (
                    workflow_mode,
                    "not_generated" if workflow_mode == "manual_bulk" else "pending",
                    user_id,
                ),
            )

            member_ids.append(user_id)
            imported += 1

        if not member_ids:
            db.execute("DELETE FROM upload_batches WHERE id=?", (upload_batch_id,))
            return templates.TemplateResponse(
                request=request,
                name="upload.html",
                context={
                    "request": request,
                    "error": f"No eligible users were imported. Invalid: {skipped}; active/already assigned protected: {protected}.",
                },
                status_code=400,
            )

        db.execute(
            """UPDATE upload_batches
               SET imported_rows=?,skipped_rows=?,protected_rows=?,workflow_status='staged'
               WHERE id=?""",
            (imported, skipped, protected, upload_batch_id),
        )

    log_event(
        None,
        "file_upload_staged",
        f"Upload {upload_batch_id} ({batch_name}) staged {imported} user(s); invalid {skipped}; protected {protected}; file={file.filename}",
    )
    request.session["workflow_notice"] = (
        f"Upload {batch_name} staged with {imported} user(s). "
        "Choose how many users to process next; passwords will only be generated for that selection."
    )
    return RedirectResponse(f"/workflow/{upload_batch_id}", 303)


def _workflow_context(upload_batch_id: int | None = None) -> dict:
    with conn() as db:
        uploads = [
            dict(r) for r in db.execute(
                """SELECT ub.*,
                          COUNT(ubm.user_id) AS member_count,
                          SUM(mbm.user_id IS NOT NULL) AS assigned_count,
                          SUM(mbm.user_id IS NULL
                              AND u.migration_status='waiting'
                              AND u.cloudiway_object_id IS NULL
                              AND u.generated_password_enc IS NULL) AS available_count,
                          SUM(u.migration_status='migrating') AS migrating_count,
                          SUM(u.migration_status='completed') AS completed_count,
                          SUM(u.migration_status IN ('failed','attention','timed_out')) AS problem_count
                   FROM upload_batches ub
                   LEFT JOIN upload_batch_members ubm ON ubm.upload_batch_id=ub.id
                   LEFT JOIN users u ON u.id=ubm.user_id
                   LEFT JOIN migration_batch_members mbm
                          ON mbm.user_id=u.id
                         AND mbm.migration_batch_id IN (
                             SELECT id FROM migration_batches WHERE upload_batch_id=ub.id
                         )
                   GROUP BY ub.id
                   ORDER BY ub.id DESC
                   LIMIT 100"""
            ).fetchall()
        ]

        if upload_batch_id is None and uploads:
            upload_batch_id = int(uploads[0]["id"])

        upload = None
        members = []
        available_members = []
        migration_batches = []

        if upload_batch_id is not None:
            row = db.execute(
                """SELECT ub.*,
                          COUNT(ubm.user_id) AS member_count,
                          SUM(mbm.user_id IS NOT NULL) AS assigned_count,
                          SUM(mbm.user_id IS NULL
                              AND u.migration_status='waiting'
                              AND u.cloudiway_object_id IS NULL
                              AND u.generated_password_enc IS NULL) AS available_count,
                          SUM(u.migration_status='migrating') AS migrating_count,
                          SUM(u.migration_status='completed') AS completed_count,
                          SUM(u.migration_status IN ('failed','attention','timed_out')) AS problem_count
                   FROM upload_batches ub
                   LEFT JOIN upload_batch_members ubm ON ubm.upload_batch_id=ub.id
                   LEFT JOIN users u ON u.id=ubm.user_id
                   LEFT JOIN migration_batch_members mbm
                          ON mbm.user_id=u.id
                         AND mbm.migration_batch_id IN (
                             SELECT id FROM migration_batches WHERE upload_batch_id=ub.id
                         )
                   WHERE ub.id=?
                   GROUP BY ub.id""",
                (upload_batch_id,),
            ).fetchone()
            upload = dict(row) if row else None

            if upload:
                members = [
                    dict(r) for r in db.execute(
                        """SELECT u.id,u.source_email,u.target_email,u.first_name,u.last_name,
                                  u.computer_number,u.rackspace_status,u.cloudiway_status,
                                  u.migration_status,u.progress_percent,u.error_message,
                                  u.cloudiway_object_id,u.updated_at,ubm.row_order,
                                  mb.id AS migration_batch_id,mb.batch_name AS migration_batch_name,
                                  mb.cloudiway_batch_id
                           FROM upload_batch_members ubm
                           JOIN users u ON u.id=ubm.user_id
                           LEFT JOIN migration_batch_members mbm2
                                  ON mbm2.user_id=u.id
                                 AND mbm2.migration_batch_id IN (
                                     SELECT id FROM migration_batches
                                     WHERE upload_batch_id=ubm.upload_batch_id
                                 )
                           LEFT JOIN migration_batches mb ON mb.id=mbm2.migration_batch_id
                           WHERE ubm.upload_batch_id=?
                           ORDER BY ubm.row_order,u.id""",
                        (upload_batch_id,),
                    ).fetchall()
                ]
                available_members = [
                    m for m in members
                    if not m.get("migration_batch_id")
                    and m.get("migration_status") == "waiting"
                    and not m.get("cloudiway_object_id")
                    and m.get("rackspace_status") in ("not_generated", "pending")
                ]
                migration_batches = [
                    dict(r) for r in db.execute(
                        """SELECT mb.*,
                                  COUNT(mbm.user_id) AS member_count,
                                  SUM(u.rackspace_status='manual_confirmed') AS confirmed_count,
                                  SUM(u.migration_status='migrating') AS migrating_count,
                                  SUM(u.migration_status='completed') AS completed_count,
                                  SUM(u.migration_status IN ('failed','attention','timed_out')) AS problem_count
                           FROM migration_batches mb
                           LEFT JOIN migration_batch_members mbm ON mbm.migration_batch_id=mb.id
                           LEFT JOIN users u ON u.id=mbm.user_id
                           WHERE mb.upload_batch_id=?
                           GROUP BY mb.id
                           ORDER BY mb.sequence_number DESC""",
                        (upload_batch_id,),
                    ).fetchall()
                ]

    return {
        "batches": uploads,
        "batch": upload,
        "members": members,
        "available_members": available_members,
        "migration_batches": migration_batches,
    }


@app.get("/workflow", response_class=HTMLResponse)
async def workflow_page(request: Request):
    redirect = _page_auth(request)
    if redirect:
        return redirect
    context = _workflow_context()
    context.update(
        {
            "request": request,
            "notice": request.session.pop("workflow_notice", None),
            "error": request.session.pop("workflow_error", None),
        }
    )
    return templates.TemplateResponse(request=request, name="workflow.html", context=context)


@app.get("/workflow/{upload_batch_id}", response_class=HTMLResponse)
async def workflow_batch_page(request: Request, upload_batch_id: int):
    redirect = _page_auth(request)
    if redirect:
        return redirect
    context = _workflow_context(upload_batch_id)
    if not context["batch"]:
        raise HTTPException(status_code=404, detail="Upload batch not found")
    context.update(
        {
            "request": request,
            "notice": request.session.pop("workflow_notice", None),
            "error": request.session.pop("workflow_error", None),
        }
    )
    return templates.TemplateResponse(request=request, name="workflow.html", context=context)


@app.post("/workflow/{upload_batch_id}/generate")
async def workflow_generate_batch(
    request: Request,
    upload_batch_id: int,
    quantity: int = Form(0),
    user_ids: list[int] = Form(default=[]),
    auto_start: str = Form(""),
):
    require_admin(request)

    if not get_setting("cloudiway_token"):
        request.session["workflow_error"] = (
            "Connect Cloudiway first. Every generated migration batch must receive a Cloudiway batch number."
        )
        return RedirectResponse(f"/workflow/{upload_batch_id}", 303)

    with conn() as db:
        upload = db.execute(
            "SELECT * FROM upload_batches WHERE id=?",
            (upload_batch_id,),
        ).fetchone()
        if not upload:
            raise HTTPException(status_code=404, detail="Upload batch not found")

        available = db.execute(
            """SELECT u.id,u.source_email
               FROM upload_batch_members ubm
               JOIN users u ON u.id=ubm.user_id
               WHERE ubm.upload_batch_id=?
                 AND u.migration_status='waiting'
                 AND u.cloudiway_object_id IS NULL
                 AND u.generated_password_enc IS NULL
                 AND NOT EXISTS (
                     SELECT 1
                     FROM migration_batch_members mbm
                     JOIN migration_batches mb ON mb.id=mbm.migration_batch_id
                     WHERE mb.upload_batch_id=? AND mbm.user_id=u.id
                 )
               ORDER BY ubm.row_order,u.id""",
            (upload_batch_id, upload_batch_id),
        ).fetchall()

        available_ids = [int(r["id"]) for r in available]
        available_set = set(available_ids)

        if user_ids:
            selected_ids = []
            seen = set()
            for uid in user_ids:
                uid = int(uid)
                if uid in available_set and uid not in seen:
                    selected_ids.append(uid)
                    seen.add(uid)
            if not selected_ids:
                request.session["workflow_error"] = "None of the selected users are available for a new migration batch."
                return RedirectResponse(f"/workflow/{upload_batch_id}", 303)
        else:
            if quantity <= 0:
                request.session["workflow_error"] = "Enter a quantity greater than zero or select individual users."
                return RedirectResponse(f"/workflow/{upload_batch_id}", 303)
            if quantity > len(available_ids):
                request.session["workflow_error"] = (
                    f"Only {len(available_ids)} user(s) remain available in this upload."
                )
                return RedirectResponse(f"/workflow/{upload_batch_id}", 303)
            selected_ids = available_ids[:quantity]

        seq = int(
            db.execute(
                "SELECT COALESCE(MAX(sequence_number),0) n FROM migration_batches WHERE upload_batch_id=?",
                (upload_batch_id,),
            ).fetchone()["n"]
            or 0
        ) + 1
        batch_name = f"{upload['batch_name']}-B{seq:03d}"

        cursor = db.execute(
            """INSERT INTO migration_batches(
                   upload_batch_id,sequence_number,batch_name,workflow_status,
                   auto_start,cloudiway_batch_name,selected_count
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                upload_batch_id,
                seq,
                batch_name,
                "selected",
                1 if auto_start else 0,
                batch_name,
                len(selected_ids),
            ),
        )
        migration_batch_id = int(cursor.lastrowid)

        for uid in selected_ids:
            db.execute(
                """INSERT INTO migration_batch_members(migration_batch_id,user_id)
                   VALUES(?,?)""",
                (migration_batch_id, uid),
            )

        if upload["workflow_mode"] == "manual_bulk":
            for uid in selected_ids:
                password = generate_password()
                db.execute(
                    """UPDATE users
                       SET generated_password_enc=?,
                           password_reset_method='manual_bulk',
                           rackspace_status='manual_file_generated',
                           manual_password_generated_at=CURRENT_TIMESTAMP,
                           manual_password_confirmed_at=NULL,
                           cloudiway_status='not_submitted',
                           migration_status='waiting',
                           progress_percent=NULL,
                           progress_detail=NULL,
                           error_message=NULL,
                           batch_number=?,
                           batch_started_at=NULL,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE id=?""",
                    (encrypt_secret(password), migration_batch_id, uid),
                )
            db.execute(
                "UPDATE migration_batches SET workflow_status='passwords_generated' WHERE id=?",
                (migration_batch_id,),
            )
        else:
            for uid in selected_ids:
                db.execute(
                    """UPDATE users
                       SET password_reset_method='automatic',
                           rackspace_status='pending',
                           cloudiway_status='not_submitted',
                           migration_status='waiting',
                           error_message=NULL,
                           batch_number=?,
                           batch_started_at=NULL,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE id=?""",
                    (migration_batch_id, uid),
                )
            db.execute(
                "UPDATE migration_batches SET workflow_status='ready_for_automatic' WHERE id=?",
                (migration_batch_id,),
            )

    try:
        cloud_batch_id = await ensure_migration_cloudiway_batch(migration_batch_id)
    except Exception as exc:
        request.session["workflow_error"] = (
            f"Local batch {batch_name} was created, but Cloudiway batch creation failed: {exc}. "
            "Use Retry Cloudiway Batch on the workflow page."
        )
        return RedirectResponse(f"/workflow/{upload_batch_id}", 303)

    log_event(
        None,
        "migration_batch_generated",
        f"{batch_name}: selected {len(selected_ids)} user(s); Cloudiway batch {cloud_batch_id}",
    )

    if upload["workflow_mode"] == "manual_bulk":
        archive, archive_name = _build_rackspace_password_package(migration_batch_id)
        return StreamingResponse(
            archive,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{archive_name}"'},
        )

    if auto_start:
        try:
            await start_migration_batch(migration_batch_id)
        except Exception as exc:
            request.session["workflow_error"] = str(exc)
    else:
        request.session["workflow_notice"] = (
            f"{batch_name} created with {len(selected_ids)} user(s). "
            f"Cloudiway batch ID {cloud_batch_id} is ready."
        )
    return RedirectResponse(f"/workflow/{upload_batch_id}", 303)


@app.get("/migration-batch/{migration_batch_id}/download")
async def migration_batch_download(request: Request, migration_batch_id: int):
    require_admin(request)
    try:
        archive, archive_name = _build_rackspace_password_package(migration_batch_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    log_event(
        None,
        "migration_batch_package_downloaded",
        f"Migration batch {migration_batch_id}: {archive_name}",
    )
    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{archive_name}"'},
    )


@app.post("/migration-batch/{migration_batch_id}/retry-cloudiway")
async def migration_batch_retry_cloudiway(request: Request, migration_batch_id: int):
    require_admin(request)
    with conn() as db:
        batch = db.execute(
            "SELECT upload_batch_id FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()
    if not batch:
        raise HTTPException(status_code=404, detail="Migration batch not found")
    try:
        cloud_batch_id = await ensure_migration_cloudiway_batch(migration_batch_id)
        request.session["workflow_notice"] = f"Cloudiway batch ID {cloud_batch_id} is ready."
    except Exception as exc:
        request.session["workflow_error"] = str(exc)
    return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)


@app.post("/migration-batch/{migration_batch_id}/confirm")
async def migration_batch_confirm(
    request: Request,
    migration_batch_id: int,
    file: UploadFile = File(...),
):
    require_admin(request)

    with conn() as db:
        batch = db.execute(
            """SELECT mb.*,ub.workflow_mode
               FROM migration_batches mb
               JOIN upload_batches ub ON ub.id=mb.upload_batch_id
               WHERE mb.id=?""",
            (migration_batch_id,),
        ).fetchone()
    if not batch:
        raise HTTPException(status_code=404, detail="Migration batch not found")
    if batch["workflow_mode"] != "manual_bulk":
        request.session["workflow_error"] = "Confirmation upload is only required for manual Rackspace batches."
        return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)

    raw = await file.read()
    try:
        if file.filename.lower().endswith(".csv"):
            df = pd.read_csv(io.BytesIO(raw), dtype=str).fillna("")
        else:
            df = pd.read_excel(io.BytesIO(raw), dtype=str).fillna("")
    except Exception as exc:
        request.session["workflow_error"] = f"Could not read confirmation file: {exc}"
        return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)

    columns = {str(col).strip().lower(): col for col in df.columns}
    username_col = (
        columns.get("username")
        or columns.get("email")
        or columns.get("source_email")
        or columns.get("sourceemail")
    )
    password_col = columns.get("password")
    if not username_col or not password_col:
        request.session["workflow_error"] = "Confirmation file must contain Username/Email and Password columns."
        return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)

    with conn() as db:
        member_rows = db.execute(
            """SELECT u.id,u.source_email,u.generated_password_enc,u.password_reset_method
               FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=?""",
            (migration_batch_id,),
        ).fetchall()

    by_full = {str(r["source_email"]).lower(): r for r in member_rows}
    by_local: dict[str, list] = {}
    for r in member_rows:
        local = str(r["source_email"]).split("@", 1)[0].lower()
        by_local.setdefault(local, []).append(r)

    confirmed_ids: set[int] = set()
    mismatches: list[str] = []
    missing: list[str] = []

    for _, row in df.iterrows():
        identity = str(row.get(username_col, "")).strip().lower()
        supplied_password = str(row.get(password_col, "")).strip()
        if not identity or not supplied_password:
            continue

        user = by_full.get(identity)
        if not user and "@" not in identity:
            candidates = by_local.get(identity, [])
            if len(candidates) == 1:
                user = candidates[0]

        if not user:
            missing.append(identity)
            continue
        if user["password_reset_method"] != "manual_bulk" or not user["generated_password_enc"]:
            mismatches.append(identity)
            continue

        expected = decrypt_secret(user["generated_password_enc"])
        if not secrets.compare_digest(expected, supplied_password):
            mismatches.append(identity)
            continue
        confirmed_ids.add(int(user["id"]))

    if confirmed_ids:
        placeholders = ",".join("?" for _ in confirmed_ids)
        with conn() as db:
            db.execute(
                f"""UPDATE users
                    SET rackspace_status='manual_confirmed',
                        manual_password_confirmed_at=CURRENT_TIMESTAMP,
                        migration_status='waiting',
                        error_message=NULL,
                        updated_at=CURRENT_TIMESTAMP
                    WHERE id IN ({placeholders})""",
                tuple(confirmed_ids),
            )

    member_count = len(member_rows)
    confirmed_total = 0
    with conn() as db:
        confirmed_total = int(
            db.execute(
                """SELECT COUNT(*) c
                   FROM migration_batch_members mbm
                   JOIN users u ON u.id=mbm.user_id
                   WHERE mbm.migration_batch_id=? AND u.rackspace_status='manual_confirmed'""",
                (migration_batch_id,),
            ).fetchone()["c"]
        )
        all_confirmed = member_count > 0 and confirmed_total == member_count
        db.execute(
            """UPDATE migration_batches
               SET confirmed_count=?,workflow_status=?,last_error=?,updated_at=CURRENT_TIMESTAMP
               WHERE id=?""",
            (
                confirmed_total,
                "passwords_confirmed" if all_confirmed else "confirmation_partial",
                None if all_confirmed else f"{confirmed_total}/{member_count} users confirmed",
                migration_batch_id,
            ),
        )

    message = (
        f"Confirmed {confirmed_total}/{member_count} user(s). "
        f"Password mismatches: {len(mismatches)}; not found in this batch: {len(missing)}."
    )

    if all_confirmed:
        try:
            prepared = await prepare_migration_batch(migration_batch_id)
            if prepared.get("ready"):
                message += (
                    f" Cloudiway preparation complete; {prepared.get('users', 0)} user(s) assigned "
                    f"to Cloudiway batch {prepared.get('cloudiway_batch_id')}."
                )
                if int(batch["auto_start"] or 0) == 1:
                    started = await start_migration_batch(migration_batch_id)
                    if started.get("started"):
                        message += " Migration started automatically."
                    else:
                        message += " Automatic start is waiting: " + str(started.get("reason") or "review required")
            else:
                message += " Cloudiway preparation is waiting: " + str(prepared.get("reason") or "review required")
        except Exception as exc:
            request.session["workflow_error"] = message + " Preparation failed: " + str(exc)
            return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)

    request.session["workflow_notice"] = message
    return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)


@app.post("/migration-batch/{migration_batch_id}/prepare")
async def migration_batch_prepare(request: Request, migration_batch_id: int):
    require_admin(request)
    with conn() as db:
        batch = db.execute(
            "SELECT upload_batch_id FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()
    if not batch:
        raise HTTPException(status_code=404, detail="Migration batch not found")
    try:
        result = await prepare_migration_batch(migration_batch_id)
        if result.get("ready"):
            request.session["workflow_notice"] = (
                f"Cloudiway preparation complete for {result.get('users', 0)} user(s); "
                f"batch ID {result.get('cloudiway_batch_id')}."
            )
        else:
            request.session["workflow_error"] = str(result.get("reason") or "Batch is not ready")
    except Exception as exc:
        request.session["workflow_error"] = str(exc)
    return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)


@app.post("/migration-batch/{migration_batch_id}/start")
async def migration_batch_start(request: Request, migration_batch_id: int):
    require_admin(request)
    with conn() as db:
        batch = db.execute(
            "SELECT upload_batch_id FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()
    if not batch:
        raise HTTPException(status_code=404, detail="Migration batch not found")
    try:
        result = await start_migration_batch(migration_batch_id)
        if result.get("started"):
            request.session["workflow_notice"] = (
                f"Migration started for {result.get('users_started', 0)} user(s) in "
                f"Cloudiway batch {result.get('cloudiway_batch_id')}."
            )
        else:
            request.session["workflow_error"] = str(result.get("reason") or "Batch could not be started")
    except Exception as exc:
        request.session["workflow_error"] = str(exc)
    return RedirectResponse(f"/workflow/{batch['upload_batch_id']}", 303)


@app.get("/manual-rackspace", response_class=HTMLResponse)
async def manual_rackspace_page(request: Request):
    redirect = _page_auth(request)
    if redirect:
        return redirect

    with conn() as db:
        rows = db.execute(
            """SELECT id,source_email,target_email,first_name,last_name,computer_number,
                      password_reset_method,rackspace_status,migration_status,
                      manual_password_generated_at,manual_password_confirmed_at,
                      error_message,updated_at
               FROM users
               ORDER BY id DESC LIMIT 2000"""
        ).fetchall()

    return templates.TemplateResponse(
        request=request,
        name="manual_rackspace.html",
        context={
            "request": request,
            "users": [dict(r) for r in rows],
            "notice": request.session.pop("manual_notice", None),
            "error": request.session.pop("manual_error", None),
        },
    )


@app.post("/manual-rackspace/generate")
async def manual_rackspace_generate(
    request: Request,
    user_ids: list[int] = Form(default=[]),
):
    require_admin(request)
    if not user_ids:
        request.session["manual_error"] = "Select at least one user."
        return RedirectResponse("/manual-rackspace", 303)

    generated = []
    with conn() as db:
        placeholders = ",".join("?" for _ in user_ids)
        rows = db.execute(
            f"""SELECT * FROM users
                WHERE id IN ({placeholders})
                  AND migration_status NOT IN ('migrating','completed')
                ORDER BY id""",
            tuple(user_ids),
        ).fetchall()

        for row in rows:
            user = dict(row)
            password = generate_password()
            db.execute(
                """UPDATE users
                   SET generated_password_enc=?,
                       password_reset_method='manual_bulk',
                       rackspace_status='manual_file_generated',
                       manual_password_generated_at=CURRENT_TIMESTAMP,
                       manual_password_confirmed_at=NULL,
                       migration_status='waiting',
                       cloudiway_status='not_submitted',
                       error_message=NULL,
                       progress_percent=NULL,
                       batch_number=NULL,
                       batch_started_at=NULL,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (encrypt_secret(password), user["id"]),
            )
            generated.append((user, password))

    if not generated:
        request.session["manual_error"] = "No eligible users were selected."
        return RedirectResponse("/manual-rackspace", 303)

    import csv as _csv

    # Exact Rackspace import CSV.
    rackspace_output = io.StringIO()
    writer = _csv.writer(rackspace_output, lineterminator="\n")
    writer.writerow(RACKSPACE_MAILBOX_HEADERS)
    for user, password in generated:
        writer.writerow(rackspace_row(user, password))
    # Rackspace's legacy parser is strict; emit plain UTF-8 without BOM.
    rackspace_payload = rackspace_output.getvalue().encode("utf-8")

    # Also provide an Excel version of the exact Rackspace template.
    rackspace_df = pd.DataFrame(
        [rackspace_row(user, password) for user, password in generated],
        columns=RACKSPACE_MAILBOX_HEADERS,
    )
    rackspace_xlsx = io.BytesIO()
    with pd.ExcelWriter(rackspace_xlsx, engine="openpyxl") as rack_writer:
        rackspace_df.to_excel(rack_writer, index=False, sheet_name="Mailboxes")
    rackspace_xlsx.seek(0)

    # Administrative mapping workbook requested by ICTD.
    admin_rows = []
    for user, password in generated:
        admin_rows.append(
            {
                "email": user["source_email"],
                "password": password,
                "source_email": user["source_email"],
                "target_email": user["target_email"],
                "first_name": user.get("first_name") or "",
                "last_name": user.get("last_name") or "",
                "computer_number": user.get("computer_number") or "",
            }
        )
    admin_df = pd.DataFrame(
        admin_rows,
        columns=[
            "email",
            "password",
            "source_email",
            "target_email",
            "first_name",
            "last_name",
            "computer_number",
        ],
    )
    workbook = io.BytesIO()
    with pd.ExcelWriter(workbook, engine="openpyxl") as writer_xlsx:
        admin_df.to_excel(writer_xlsx, index=False, sheet_name="Password Map")
    workbook.seek(0)

    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    archive_name = f"rackspace-password-package-{stamp}.zip"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"rackspace-password-update-{stamp}.csv", rackspace_payload)
        zf.writestr(f"rackspace-password-update-{stamp}.xlsx", rackspace_xlsx.getvalue())
        zf.writestr(f"migration-password-map-{stamp}.xlsx", workbook.getvalue())
    archive.seek(0)

    for user, _ in generated:
        log_event(
            user["id"],
            "manual_password_file_generated",
            "Password generated for Rackspace bulk update file",
        )
    log_info("manual_rackspace_file_generated", user_count=len(generated), filename=archive_name)

    return StreamingResponse(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{archive_name}"'},
    )


@app.post("/manual-rackspace/confirm-upload")
async def manual_rackspace_confirm_upload(
    request: Request,
    file: UploadFile = File(...),
    auto_start: str = Form(""),
):
    require_admin(request)
    raw = await file.read()
    try:
        if file.filename.lower().endswith(".csv"):
            df = pd.read_csv(io.BytesIO(raw), dtype=str).fillna("")
        else:
            df = pd.read_excel(io.BytesIO(raw), dtype=str).fillna("")
    except Exception as exc:
        request.session["manual_error"] = f"Could not read confirmation file: {exc}"
        return RedirectResponse("/manual-rackspace", 303)

    columns = {str(col).strip().lower(): col for col in df.columns}
    username_col = (
        columns.get("username")
        or columns.get("email")
        or columns.get("source_email")
        or columns.get("sourceemail")
    )
    password_col = columns.get("password")
    if not username_col or not password_col:
        request.session["manual_error"] = (
            "Confirmation file must contain Username and Password columns."
        )
        return RedirectResponse("/manual-rackspace", 303)

    confirmed_ids = []
    mismatches = []
    missing = []

    with conn() as db:
        for _, row in df.iterrows():
            email = str(row.get(username_col, "")).strip().lower()
            supplied_password = str(row.get(password_col, "")).strip()
            if not email or not supplied_password:
                continue

            user = db.execute(
                """SELECT id,source_email,generated_password_enc,password_reset_method
                   FROM users WHERE LOWER(source_email)=?""",
                (email,),
            ).fetchone()

            # Rackspace's own import file contains only the mailbox local-part
            # in Username because the domain is selected in the control panel.
            # Allow that exact generated file to be uploaded back as confirmation.
            if not user and "@" not in email:
                candidates = db.execute(
                    """SELECT id,source_email,generated_password_enc,password_reset_method
                       FROM users
                       WHERE LOWER(SUBSTRING_INDEX(source_email,'@',1))=?""",
                    (email,),
                ).fetchall()
                if len(candidates) == 1:
                    user = candidates[0]

            if not user:
                missing.append(email)
                continue
            if user["password_reset_method"] != "manual_bulk" or not user["generated_password_enc"]:
                mismatches.append(email)
                continue

            expected = decrypt_secret(user["generated_password_enc"])
            if not secrets.compare_digest(expected, supplied_password):
                mismatches.append(email)
                continue

            db.execute(
                """UPDATE users
                   SET rackspace_status='manual_confirmed',
                       manual_password_confirmed_at=CURRENT_TIMESTAMP,
                       migration_status='waiting',
                       error_message=NULL,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (user["id"],),
            )
            confirmed_ids.append(int(user["id"]))

    if not confirmed_ids:
        request.session["manual_error"] = (
            f"No users were confirmed. Password mismatches/not generated: {len(mismatches)}; "
            f"users not found: {len(missing)}."
        )
        return RedirectResponse("/manual-rackspace", 303)

    for uid in confirmed_ids:
        log_event(
            uid,
            "manual_password_confirmed",
            "Rackspace bulk file was uploaded back and password application was confirmed",
        )

    summary = (
        f"Confirmed {len(confirmed_ids)} user(s) as updated in Rackspace. "
        f"Mismatches: {len(mismatches)}; not found: {len(missing)}."
    )

    if auto_start:
        try:
            result = await start_manual_migrations(confirmed_ids)
            summary += (
                f" Migration start requested: {result.get('users_started', 0)} user(s) started; "
                f"{len(result.get('failed', []))} failed."
            )
        except Exception as exc:
            request.session["manual_error"] = summary + f" Cloudiway start failed: {exc}"
            return RedirectResponse("/manual-rackspace", 303)

    request.session["manual_notice"] = summary
    return RedirectResponse("/manual-rackspace", 303)


@app.post("/manual-rackspace/start")
async def manual_rackspace_start(
    request: Request,
    user_ids: list[int] = Form(default=[]),
):
    require_admin(request)
    if not user_ids:
        request.session["manual_error"] = "Select at least one confirmed user to start."
        return RedirectResponse("/manual-rackspace", 303)
    try:
        result = await start_manual_migrations(user_ids)
        request.session["manual_notice"] = (
            f"Migration requested for {result.get('users_started', 0)} user(s). "
            f"Failures: {len(result.get('failed', []))}."
        )
    except Exception as exc:
        request.session["manual_error"] = str(exc)
    return RedirectResponse("/manual-rackspace", 303)


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
                """SELECT u.id,u.source_email,u.target_email,u.first_name,u.last_name,u.rackspace_status,
                          u.cloudiway_status,u.migration_status,u.progress_percent,u.error_message,u.batch_number,u.updated_at,
                          u.password_reset_method,u.manual_password_generated_at,u.manual_password_confirmed_at,u.computer_number,
                          mb.batch_name AS migration_batch_name,mb.cloudiway_batch_id
                   FROM users u
                   LEFT JOIN migration_batches mb ON mb.id=u.batch_number
                   WHERE u.source_email LIKE ? OR u.target_email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?
                   ORDER BY u.id DESC LIMIT 1000""",
                values,
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT u.id,u.source_email,u.target_email,u.first_name,u.last_name,u.rackspace_status,
                          u.cloudiway_status,u.migration_status,u.progress_percent,u.error_message,u.batch_number,u.updated_at,
                          u.password_reset_method,u.manual_password_generated_at,u.manual_password_confirmed_at,u.computer_number,
                          mb.batch_name AS migration_batch_name,mb.cloudiway_batch_id
                   FROM users u
                   LEFT JOIN migration_batches mb ON mb.id=u.batch_number
                   ORDER BY u.id DESC LIMIT 1000"""
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

    with conn() as db:
        row = db.execute(
            """SELECT id FROM migration_batches
               WHERE workflow_status IN ('ready_to_migrate','ready_for_automatic')
               ORDER BY id LIMIT 1"""
        ).fetchone()
    if not row:
        return JSONResponse({
            "started": False,
            "reason": "No prepared migration batch is ready. Use Migration Workflow to select the next quantity/users first."
        })
    return JSONResponse(await start_migration_batch(int(row["id"])))


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

    with conn() as db:
        row = db.execute(
            """SELECT id FROM migration_batches
               WHERE workflow_status IN ('ready_to_migrate','ready_for_automatic')
               ORDER BY id LIMIT 1"""
        ).fetchone()
    if not row:
        return {
            "started": False,
            "reason": "No prepared migration batch is ready. Use Migration Workflow to create or prepare the next batch."
        }
    return await start_migration_batch(int(row["id"]))


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


@app.get("/users/{user_id}/cloudiway-logs")
async def user_cloudiway_logs(request: Request, user_id: int):
    require_admin(request)

    with conn() as db:
        row = db.execute(
            """SELECT id,source_email,target_email,cloudiway_object_id,
                      migration_status,cloudiway_status,error_message
               FROM users WHERE id=?""",
            (user_id,),
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if not row["cloudiway_object_id"]:
        raise HTTPException(status_code=400, detail="This user does not yet have a Cloudiway object ID")

    client = await _cloudiway_client_ready()
    object_id = int(row["cloudiway_object_id"])

    result = {
        "user_id": user_id,
        "source_email": row["source_email"],
        "target_email": row["target_email"],
        "object_id": object_id,
        "migration_status": row["migration_status"],
        "cloudiway_status": row["cloudiway_status"],
    }

    try:
        result["mail_user"] = await client.get_mail_user(object_id)
    except Exception as exc:
        result["mail_user_error"] = str(exc)

    try:
        result["logs"] = await client.logs(object_id)
    except Exception as exc:
        result["logs_error"] = str(exc)

    try:
        result["audit"] = await client.audit(object_id)
    except Exception as exc:
        result["audit_error"] = str(exc)

    try:
        result["progress"] = await client.progress(
            object_id,
            max(1, settings.progress_window_minutes),
        )
    except Exception as exc:
        result["progress_error"] = str(exc)

    from app.service import classify_cloudiway_issue
    status_override, issue_code, friendly = classify_cloudiway_issue(
        result.get("progress"),
        result.get("logs"),
    )
    if status_override:
        result["diagnosis"] = {
            "status": status_override,
            "code": issue_code,
            "message": friendly,
        }
        with conn() as db:
            db.execute(
                """UPDATE users
                   SET migration_status=?,cloudiway_status=?,error_message=?,
                       updated_at=CURRENT_TIMESTAMP
                   WHERE id=?""",
                (status_override, issue_code or status_override, friendly, user_id),
            )
        log_event(
            user_id,
            issue_code or "cloudiway_diagnosed",
            friendly + " Raw logs: " + json.dumps(result.get("logs"), default=str)[:2200],
        )

    return result


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


@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, level: str = "", q: str = ""):
    redirect = _page_auth(request)
    if redirect:
        return redirect

    with conn() as db:
        event_rows = db.execute(
            """SELECT e.id,e.user_id,e.event_type,e.message,e.created_at,
                      u.source_email,u.target_email
               FROM events e
               LEFT JOIN users u ON u.id=e.user_id
               ORDER BY e.id DESC
               LIMIT 500"""
        ).fetchall()

    events = [dict(r) for r in event_rows]
    if q:
        needle = q.lower()
        events = [
            e for e in events
            if needle in str(e.get("event_type") or "").lower()
            or needle in str(e.get("message") or "").lower()
            or needle in str(e.get("source_email") or "").lower()
            or needle in str(e.get("target_email") or "").lower()
        ]

    raw_log = tail_log(max_bytes=512 * 1024)
    lines = [line for line in raw_log.splitlines() if line.strip()]
    if level:
        level_upper = level.upper()
        lines = [line for line in lines if f" {level_upper} " in line]
    if q:
        needle = q.lower()
        lines = [line for line in lines if needle in line.lower()]
    lines = lines[-500:]

    with conn() as db:
        issue_counts = {
            "failed_users": db.execute(
                "SELECT COUNT(*) c FROM users WHERE migration_status='failed'"
            ).fetchone()["c"],
            "attention_users": db.execute(
                "SELECT COUNT(*) c FROM users WHERE migration_status='attention'"
            ).fetchone()["c"],
            "timed_out_users": db.execute(
                "SELECT COUNT(*) c FROM users WHERE migration_status='timed_out'"
            ).fetchone()["c"],
            "users_with_errors": db.execute(
                "SELECT COUNT(*) c FROM users WHERE error_message IS NOT NULL AND error_message<>''"
            ).fetchone()["c"],
        }

    return templates.TemplateResponse(
        request=request,
        name="logs.html",
        context={
            "request": request,
            "events": events,
            "log_lines": lines,
            "level": level,
            "q": q,
            "issue_counts": issue_counts,
            "pause_reason": get_runtime("pause_reason", ""),
            "automation_paused": get_runtime("automation_paused", "0") == "1",
        },
    )


@app.get("/api/logs/issues")
async def logs_issue_summary(request: Request):
    require_admin(request)
    with conn() as db:
        issues = [
            dict(r) for r in db.execute(
                """SELECT id,source_email,target_email,rackspace_status,cloudiway_status,
                          migration_status,error_message,updated_at
                   FROM users
                   WHERE migration_status IN ('failed','attention','timed_out')
                      OR (error_message IS NOT NULL AND error_message<>'')
                   ORDER BY updated_at DESC
                   LIMIT 200"""
            ).fetchall()
        ]
    return {
        "paused": get_runtime("automation_paused", "0") == "1",
        "pause_reason": get_runtime("pause_reason", ""),
        "issues": issues,
    }


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
