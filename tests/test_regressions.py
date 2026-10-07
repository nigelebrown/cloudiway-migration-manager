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
