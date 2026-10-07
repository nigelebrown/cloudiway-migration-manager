from pathlib import Path
from fastapi.testclient import TestClient
from app.config import settings
from app.db import init_db
from app.main import app

def setup_function():
    path = Path("/tmp/cloudiway-test.db")
    if path.exists():
        path.unlink()
    settings.database_path = str(path)
    init_db()

def test_health():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True

def test_admin_login_and_upload_csv():
    with TestClient(app) as client:
        r = client.post("/login", data={"admin_password": "test-admin-password"}, follow_redirects=False)
        assert r.status_code == 303
        csv = b"source_email,target_email,first_name,last_name\na@example.com,a@jcf.gov.jm,A,User\n"
        r = client.post("/upload", files={"file": ("users.csv", csv, "text/csv")}, follow_redirects=False)
        assert r.status_code == 303
        r = client.get("/api/dashboard")
        body = r.json()
        assert body["counts"]["waiting"] == 1
        assert body["users"][0]["source_email"] == "a@example.com"
