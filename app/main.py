import io
import secrets
import pandas as pd
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from app.config import settings
from app.db import init_db, conn, log_event

app = FastAPI(title="Cloudiway Migration Manager")
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, https_only=False)
templates = Jinja2Templates(directory="app/templates")

def require_admin(request: Request):
    if not request.session.get("admin"):
        raise HTTPException(status_code=401)

@app.on_event("startup")
async def startup():
    init_db()

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if request.session.get("admin"):
        return RedirectResponse("/dashboard", 303)
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, admin_password: str = Form(...)):
    if not secrets.compare_digest(admin_password, settings.app_admin_password):
        return templates.TemplateResponse("login.html", {"request": request, "error":"Invalid administrator password"}, status_code=401)
    request.session["admin"] = True
    return RedirectResponse("/dashboard", 303)

@app.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    require_admin(request)
    return templates.TemplateResponse("upload.html", {"request": request})

@app.post("/upload")
async def upload_users(request: Request, file: UploadFile = File(...)):
    require_admin(request)
    raw = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(raw)) if file.filename.lower().endswith(".csv") else pd.read_excel(io.BytesIO(raw))
    except Exception as exc:
        return templates.TemplateResponse("upload.html", {"request": request, "error":f"Could not read file: {exc}"}, status_code=400)

    df.columns=[str(c).strip().lower() for c in df.columns]
    if not {"source_email","target_email"}.issubset(df.columns):
        return templates.TemplateResponse("upload.html", {"request": request, "error":"Required columns: source_email, target_email"}, status_code=400)

    imported=0
    with conn() as db:
        for _, row in df.iterrows():
            src=str(row.get("source_email","")).strip().lower()
            tgt=str(row.get("target_email","")).strip().lower()
            if "@" not in src or "@" not in tgt:
                continue
            first=str(row.get("first_name","") or "").strip()
            last=str(row.get("last_name","") or "").strip()
            db.execute("""INSERT INTO users(source_email,target_email,first_name,last_name)
                          VALUES(?,?,?,?)
                          ON CONFLICT(source_email) DO UPDATE SET
                          target_email=excluded.target_email,first_name=excluded.first_name,last_name=excluded.last_name""",
                       (src,tgt,first,last))
            imported += 1
    log_event(None,"file_upload",f"Imported/updated {imported} users from {file.filename}")
    return RedirectResponse("/dashboard",303)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, q: str=""):
    require_admin(request)
    with conn() as db:
        counts={r["migration_status"]:r["c"] for r in db.execute("SELECT migration_status,COUNT(*) c FROM users GROUP BY migration_status").fetchall()}
        if q:
            vals=tuple([f"%{q}%"]*4)
            rows=db.execute("""SELECT * FROM users WHERE source_email LIKE ? OR target_email LIKE ?
                               OR first_name LIKE ? OR last_name LIKE ? ORDER BY id DESC LIMIT 500""", vals).fetchall()
        else:
            rows=db.execute("SELECT * FROM users ORDER BY id DESC LIMIT 500").fetchall()
    return templates.TemplateResponse("dashboard.html", {"request":request,"users":[dict(r) for r in rows],"counts":counts,"q":q})
