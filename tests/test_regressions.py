import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import service
from app.config import settings
from app.db import conn, init_db, reset_test_data, set_setting, get_setting
from app.main import app
from app.security import encrypt_secret


@pytest.fixture(autouse=True)
def isolated_db():
    init_db()
    reset_test_data()
    service.set_runtime("automation_paused", "0")
    service.set_runtime("pause_reason", "")
    service.set_runtime("automation_running", "0")
    yield


def test_progress_one_percent_is_not_complete():
    status, pct, _ = service.parse_progress({"status": "Running", "percentage": 1})
    assert status == "migrating"
    assert pct == 1


def test_progress_incomplete_requires_attention():
    status, pct, _ = service.parse_progress({"status": "Incomplete", "percentage": 40})
    assert status == "attention"
    assert pct == 40


def test_progress_noerror_is_not_failure():
    status, _, _ = service.parse_progress(
        {"status": "Running", "lastResult": "NoError", "percentage": 30}
    )
    assert status == "migrating"


def test_failed_item_does_not_fail_mailbox():
    status, _, _ = service.parse_progress(
        {"status": "Running", "percentage": 60, "failedItems": 1, "migratedItems": 48000}
    )
    assert status == "migrating"


def test_unconfigured_start_does_not_leave_preparing():
    with conn() as db:
        db.execute(
            "INSERT INTO users(source_email,target_email) VALUES(?,?)",
            ("a@example.com", "a@jcf.gov.jm"),
        )

    import asyncio
    result = asyncio.run(service.launch_next_batch(force=True))
    assert result["started"] is False
    with conn() as db:
        status = db.execute(
            "SELECT migration_status FROM users WHERE source_email=?",
            ("a@example.com",),
        ).fetchone()["migration_status"]
    assert status == "waiting"


def test_browser_page_redirects_when_anonymous():
    with TestClient(app) as client:
        r = client.get("/dashboard", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/"


def test_session_cookie_is_secure():
    with TestClient(app) as client:
        r = client.post(
            "/login",
            data={"admin_password": "test-admin-password"},
            follow_redirects=False,
        )
        assert "secure" in r.headers["set-cookie"].lower()


def test_login_rate_limit():
    with TestClient(app) as client:
        # Successful login clears any prior attempt state for this test host.
        client.post("/login", data={"admin_password": "test-admin-password"})
        client.post("/logout")
        codes = [
            client.post("/login", data={"admin_password": f"bad-{i}"}).status_code
            for i in range(settings.login_max_attempts + 2)
        ]
        assert 429 in codes


def test_reupload_does_not_change_inflight_target():
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        with conn() as db:
            db.execute(
                """INSERT INTO users(source_email,target_email,migration_status)
                   VALUES(?,?,?)""",
                ("u1@rack.example", "u1@jcf.gov.jm", "migrating"),
            )
        csv = b"source_email,target_email\nu1@rack.example,someone.else@jcf.gov.jm\n"
        r = client.post(
            "/upload",
            files={"file": ("users.csv", csv, "text/csv")},
            follow_redirects=False,
        )
        assert r.status_code == 303
        with conn() as db:
            target = db.execute(
                "SELECT target_email FROM users WHERE source_email=?",
                ("u1@rack.example",),
            ).fetchone()["target_email"]
        assert target == "u1@jcf.gov.jm"


def test_blank_target_and_spaced_name_headers_are_normalized():
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        csv = (
            b"Email,Target Email,First Name,Last Name\n"
            b"a@x.com,,Ann,Lee\n"
        )
        r = client.post(
            "/upload",
            files={"file": ("users.csv", csv, "text/csv")},
            follow_redirects=False,
        )
        assert r.status_code == 303
        with conn() as db:
            row = db.execute(
                "SELECT target_email,first_name,last_name FROM users WHERE source_email=?",
                ("a@x.com",),
            ).fetchone()
        assert row["target_email"] == "a@x.com"
        assert row["first_name"] == "Ann"
        assert row["last_name"] == "Lee"


def test_blank_names_do_not_become_nan():
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        csv = b"source_email,target_email,first_name,last_name\na@x.com,a@y.com,,\n"
        client.post("/upload", files={"file": ("users.csv", csv, "text/csv")})
        with conn() as db:
            row = db.execute(
                "SELECT first_name,last_name FROM users WHERE source_email=?",
                ("a@x.com",),
            ).fetchone()
        assert row["first_name"] == ""
        assert row["last_name"] == ""


def test_progress_window_uses_minutes(monkeypatch):
    class FakeCloud:
        def __init__(self):
            self.seen = None

        async def progress(self, object_id, since_minutes):
            self.seen = since_minutes
            return {"status": "Running", "percentage": 10}

    fake = FakeCloud()

    async def fake_ready():
        return fake

    monkeypatch.setattr(service, "_cloudiway_client_ready", fake_ready)
    with conn() as db:
        db.execute(
            """INSERT INTO users(source_email,target_email,cloudiway_object_id,migration_status)
               VALUES(?,?,?,?)""",
            ("a@x.com", "a@y.com", 123, "migrating"),
        )

    import asyncio
    asyncio.run(service.refresh_status())
    assert fake.seen == settings.progress_window_minutes
    assert fake.seen != settings.status_poll_seconds


def test_unknown_cloudiway_status_requires_attention():
    status, pct, _ = service.parse_progress({"status": "Stopped", "percentage": 42})
    assert status == "attention"
    assert pct == 42


def test_completed_with_warnings_requires_attention():
    status, _, _ = service.parse_progress({"status": "Completed with warnings", "percentage": 100})
    assert status == "attention"


def test_numeric_status_stays_active_until_100():
    status, pct, _ = service.parse_progress({"status": 3, "percentage": 1})
    assert status == "migrating"
    assert pct == 1
    status, pct, _ = service.parse_progress({"status": 3, "percentage": 100})
    assert status == "completed"
    assert pct == 100


def test_correct_password_bypasses_failed_attempt_limit():
    with TestClient(app) as client:
        for i in range(settings.login_max_attempts + 2):
            client.post("/login", data={"admin_password": f"wrong-{i}"})
        r = client.post(
            "/login",
            data={"admin_password": "test-admin-password"},
            follow_redirects=False,
        )
        assert r.status_code == 303


def test_http_login_explains_secure_cookie_requirement():
    with TestClient(app, base_url="http://testserver") as client:
        r = client.post(
            "/login",
            data={"admin_password": "test-admin-password"},
            follow_redirects=False,
        )
        assert r.status_code == 400
        assert "HTTPS is required" in r.text


def test_batch_timeout_marks_user_for_review(monkeypatch):
    class FakeCloud:
        async def progress(self, object_id, since_minutes):
            return {"status": "Running", "percentage": 50}

    async def fake_ready():
        return FakeCloud()

    monkeypatch.setattr(service, "_cloudiway_client_ready", fake_ready)
    old_timeout = settings.batch_timeout_minutes
    settings.batch_timeout_minutes = 1
    try:
        with conn() as db:
            db.execute(
                """INSERT INTO users(
                       source_email,target_email,cloudiway_object_id,migration_status,
                       batch_number,batch_started_at
                   ) VALUES(?,?,?,?,?,DATE_SUB(UTC_TIMESTAMP(), INTERVAL 2 MINUTE))""",
                ("timeout@x.com", "timeout@y.com", 999, "migrating", 1),
            )
        import asyncio
        result = asyncio.run(service.refresh_status())
        assert result["timed_out"] == 1
        with conn() as db:
            row = db.execute(
                "SELECT migration_status,error_message FROM users WHERE source_email=?",
                ("timeout@x.com",),
            ).fetchone()
        assert row["migration_status"] == "timed_out"
        assert "timeout" in row["error_message"].lower()
    finally:
        settings.batch_timeout_minutes = old_timeout


def test_cloudiway_pool_normalization():
    from app.main import _normalize_cloudiway_pools
    payload = {
        "responseData": [
            {"id": 11, "name": "Rackspace IMAP", "platform": "IMAP"},
            {"poolId": 22, "poolName": "JCF Microsoft 365", "technology": "Microsoft365"},
        ]
    }
    choices = _normalize_cloudiway_pools(payload)
    assert [x["id"] for x in choices] == ["22", "11"] or [x["id"] for x in choices] == ["11", "22"]
    by_id = {x["id"]: x for x in choices}
    assert "Rackspace IMAP" in by_id["11"]["label"]
    assert "Microsoft 365" in by_id["22"]["label"]


def test_cloudiway_pool_dropdown_page(monkeypatch):
    from app import main as main_module

    async def fake_ready():
        class FakeCloud:
            async def connector_pools(self):
                return [
                    {"id": 11, "name": "Rackspace IMAP"},
                    {"id": 22, "name": "JCF Microsoft 365"},
                ]
        return FakeCloud()

    monkeypatch.setattr(main_module, "_cloudiway_client_ready", fake_ready)
    set_setting("cloudiway_token", encrypt_secret("token"), True)
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        r = client.get("/settings")
        assert r.status_code == 200
        assert 'value="11"' in r.text
        assert 'Rackspace IMAP' in r.text
        assert 'value="22"' in r.text
        assert 'JCF Microsoft 365' in r.text


def test_cloudiway_project_resolution_uses_numeric_id():
    from app.main import _normalize_cloudiway_projects, _resolve_cloudiway_project
    payload = {"responseData": [{"id": 14780, "name": "JCF"}, {"id": 99, "name": "Other"}]}
    projects = _normalize_cloudiway_projects(payload)
    chosen = _resolve_cloudiway_project(projects, "JCF")
    assert chosen == {"id": "14780", "name": "JCF"}


def test_diagnostic_redaction_hides_secrets():
    from app.diagnostics import redact
    text = "Authorization: Bearer abc123 password=Secret123 token=tok123 secret_key=mysecret"
    safe = redact(text)
    assert "abc123" not in safe
    assert "Secret123" not in safe
    assert "tok123" not in safe
    assert "mysecret" not in safe
    assert "[REDACTED]" in safe


def test_diagnostics_download_requires_admin():
    with TestClient(app) as client:
        r = client.get("/diagnostics/download")
        assert r.status_code == 401


def test_upload_accepts_rackspace_template_with_target_email():
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        csv_data = (
            b"Username,Password,Enabled,FirstName,LastName,TargetEmail\n"
            b"user@rack.example,,TRUE,Test,User,user@jcf.gov.jm\n"
        )
        response = client.post(
            "/upload",
            files={"file": ("rackspace.csv", csv_data, "text/csv")},
            follow_redirects=False,
        )
        assert response.status_code == 303
        with conn() as db:
            row = db.execute(
                "SELECT source_email,target_email,first_name,last_name FROM users WHERE source_email=?",
                ("user@rack.example",),
            ).fetchone()
        assert row["target_email"] == "user@jcf.gov.jm"
        assert row["first_name"] == "Test"
        assert row["last_name"] == "User"


def test_manual_rackspace_generate_and_confirm_round_trip():
    import io
    import zipfile
    import pandas as pd
    from app.security import decrypt_secret

    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        with conn() as db:
            db.execute(
                """INSERT INTO users(
                       source_email,target_email,first_name,last_name,computer_number
                   ) VALUES(?,?,?,?,?)""",
                ("manual@rack.example", "manual@jcf.gov.jm", "Manual", "User", "14323"),
            )
            uid = db.execute(
                "SELECT id FROM users WHERE source_email=?",
                ("manual@rack.example",),
            ).fetchone()["id"]

        generated = client.post(
            "/manual-rackspace/generate",
            data={"user_ids": str(uid)},
        )
        assert generated.status_code == 200
        assert "application/zip" in generated.headers["content-type"]

        archive = zipfile.ZipFile(io.BytesIO(generated.content))
        names = archive.namelist()
        rackspace_name = next(n for n in names if n.endswith(".csv"))
        map_name = next(n for n in names if n.startswith("migration-password-map-") and n.endswith(".xlsx"))
        rackspace_csv = archive.read(rackspace_name)
        password_map = pd.read_excel(io.BytesIO(archive.read(map_name)))

        with conn() as db:
            row = db.execute(
                "SELECT generated_password_enc,password_reset_method,rackspace_status FROM users WHERE id=?",
                (uid,),
            ).fetchone()
        generated_value = decrypt_secret(row["generated_password_enc"])
        assert row["password_reset_method"] == "manual_bulk"
        assert row["rackspace_status"] == "manual_file_generated"
        assert generated_value in rackspace_csv.decode("utf-8-sig")
        assert password_map.iloc[0]["source_email"] == "manual@rack.example"
        assert password_map.iloc[0]["target_email"] == "manual@jcf.gov.jm"
        assert str(password_map.iloc[0]["computer_number"]) == "14323"

        confirmed = client.post(
            "/manual-rackspace/confirm-upload",
            files={"file": ("confirm.csv", rackspace_csv, "text/csv")},
            follow_redirects=False,
        )
        assert confirmed.status_code == 303
        with conn() as db:
            row = db.execute(
                "SELECT rackspace_status,manual_password_confirmed_at FROM users WHERE id=?",
                (uid,),
            ).fetchone()
        assert row["rackspace_status"] == "manual_confirmed"
        assert row["manual_password_confirmed_at"] is not None


def test_logs_page_is_available_to_admin():
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin-password"})
        r = client.get("/logs")
        assert r.status_code == 200
        assert "Logs &amp; Issues" in r.text or "Logs & Issues" in r.text
        assert "Application Events" in r.text


def test_manual_confirmed_user_is_eligible_for_manual_start(monkeypatch):
    from app import service as svc

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,password_reset_method,rackspace_status,
                   migration_status,generated_password_enc
               ) VALUES(?,?,?,?,?,?)""",
            (
                "confirmed@rack.example",
                "confirmed@jcf.gov.jm",
                "manual_bulk",
                "manual_confirmed",
                "waiting",
                encrypt_secret("SafePass123!"),
            ),
        )
        uid = db.execute(
            "SELECT id FROM users WHERE source_email=?",
            ("confirmed@rack.example",),
        ).fetchone()["id"]

    class FakeCloud:
        async def get_self_service_token(self, object_id):
            return "token"
        async def register_source_credentials(self, token, username, password):
            return {}
        async def start_migration(self, object_ids):
            return {"ok": True}

    async def fake_ready():
        return FakeCloud()

    async def fake_ensure(user):
        with conn() as db:
            db.execute(
                "UPDATE users SET cloudiway_object_id=? WHERE id=?",
                (1234, user["id"]),
            )
        return 1234

    monkeypatch.setattr(svc, "_cloudiway_client_ready", fake_ready)
    monkeypatch.setattr(svc, "ensure_cloudiway_user", fake_ensure)
    monkeypatch.setattr(svc, "_cloudiway_preflight", lambda: None)

    import asyncio
    result = asyncio.run(svc.launch_next_confirmed_manual_batch())
    assert result["started"] is True
    assert result["users_started"] == 1

    with conn() as db:
        row = db.execute(
            "SELECT migration_status FROM users WHERE id=?",
            (uid,),
        ).fetchone()
    assert row["migration_status"] == "migrating"


def test_invalid_cloudiway_refresh_token_clears_session_and_pauses(monkeypatch):
    from app import service as svc
    from datetime import datetime, timedelta, timezone
    import asyncio

    class FakeCloud:
        def __init__(self):
            self.token = "expired-access-token"

        async def refresh_token(self, token, refresh_token):
            raise RuntimeError('Cloudiway token refresh failed (400): "Invalid refresh token"')

    monkeypatch.setattr(svc, "_cloudiway_client", lambda: FakeCloud())
    set_setting("cloudiway_token", encrypt_secret("expired-access-token"), True)
    set_setting("cloudiway_refresh_token", encrypt_secret("invalid-refresh"), True)
    set_setting(
        "cloudiway_token_expiration",
        (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
    )

    with pytest.raises(RuntimeError, match="sign in to Cloudiway again"):
        asyncio.run(svc._cloudiway_client_ready())

    assert get_setting("cloudiway_token") == ""
    assert get_setting("cloudiway_refresh_token") == ""
    assert service.get_runtime("automation_paused", "0") == "1"
    assert "Reconnect Cloudiway" in service.get_runtime("pause_reason", "")
