from fastapi.testclient import TestClient
from app.db import init_db, reset_test_data, set_setting
from app.main import app
from app.security import encrypt_secret

def setup_function():
    init_db()
    reset_test_data()

def test_health():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["ok"] is True

def test_admin_login_and_upload_csv(monkeypatch):
    from app import main as main_module

    async def fake_cloud_batch(batch_id):
        return 77

    set_setting("cloudiway_token", encrypt_secret("test-token"), True)
    monkeypatch.setattr(main_module, "ensure_upload_cloudiway_batch", fake_cloud_batch)

    with TestClient(app) as client:
        r = client.post("/login", data={"admin_password": "test-admin-password"}, follow_redirects=False)
        assert r.status_code == 303
        csv = b"computer_number,source_email,target_email,first_name,middle_name,last_name\n14323,a@example.com,a@jcf.gov.jm,A,,User\n"
        r = client.post("/upload", files={"file": ("users.csv", csv, "text/csv")}, follow_redirects=False)
        assert r.status_code == 303
        r = client.get("/api/dashboard")
        body = r.json()
        assert body["counts"]["waiting"] == 1
        assert body["users"][0]["source_email"] == "a@example.com"
