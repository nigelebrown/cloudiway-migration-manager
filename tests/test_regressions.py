import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import service
from app.config import settings
from app.db import conn, init_db, set_setting, get_setting
from app.main import app
from app.security import encrypt_secret


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    settings.database_path = str(tmp_path / "regression.db")
    init_db()
    service.set_runtime("automation_paused", "0")
    service.set_runtime("pause_reason", "")
    service.set_runtime("automation_running", "0")
    yield


def test_progress_one_percent_is_not_complete():
    status, pct, _ = service.parse_progress({"status": "Running", "percentage": 1})
    assert status == "migrating"
    assert pct == 1


def test_progress_incomplete_is_not_complete():
    status, pct, _ = service.parse_progress({"status": "Incomplete", "percentage": 40})
    assert status == "migrating"
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
            data={"admin_password": "test-admin"},
            follow_redirects=False,
        )
        assert "secure" in r.headers["set-cookie"].lower()


def test_login_rate_limit():
    with TestClient(app) as client:
        # Successful login clears any prior attempt state for this test host.
        client.post("/login", data={"admin_password": "test-admin"})
        client.post("/logout")
        codes = [
            client.post("/login", data={"admin_password": f"bad-{i}"}).status_code
            for i in range(settings.login_max_attempts + 2)
        ]
        assert 429 in codes


def test_reupload_does_not_change_inflight_target():
    with TestClient(app) as client:
        client.post("/login", data={"admin_password": "test-admin"})
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
        client.post("/login", data={"admin_password": "test-admin"})
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
        client.post("/login", data={"admin_password": "test-admin"})
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
