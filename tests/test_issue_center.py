import pytest
from fastapi.testclient import TestClient

from app import service
from app.db import conn, init_db, reset_test_data, set_setting
from app.main import app
from app.security import decrypt_secret, encrypt_secret


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    reset_test_data()
    set_setting("issue_auto_recovery_enabled", "1")
    set_setting("issue_credential_retry_delay_minutes", "1")
    set_setting("issue_credential_retry_max", "2")
    yield


def login(client):
    r = client.post(
        "/login",
        data={"admin_password": "test-admin-password"},
        follow_redirects=False,
    )
    assert r.status_code == 303


class IssueCloud:
    def __init__(self, status="Failed", log_text="Authentication failed: invalid credentials"):
        self.status = status
        self.log_text = log_text
        self.credentials = []
        self.restarts = []

    async def progress(self, object_id, since_minutes=1):
        return {"status": self.status, "percentage": 2}

    async def logs(self, object_id):
        return {"logs": [self.log_text]}

    async def get_self_service_token(self, object_id):
        return f"token-{object_id}"

    async def register_source_credentials(self, token, username, password):
        self.credentials.append((token, username, password))
        return {"ok": True}

    async def restart_migration(self, object_id):
        self.restarts.append(object_id)
        return {"ok": True}


def configure_cloud(monkeypatch, cloud):
    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("test-cloud-token"), True)


def seed_user(state="failed", password="Known#Password2026"):
    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,first_name,last_name,
                   password_reset_method,source_credential_username,
                   source_credential_password_enc,source_credential_origin,
                   cloudiway_object_id,cloudiway_status,migration_status,error_message
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "member@jcf.gov.jm",
                "member@jcf.gov.jm",
                "Test",
                "Member",
                "existing_password",
                "member@jcf.gov.jm",
                encrypt_secret(password),
                "uploaded_excel",
                45821,
                "mailbox_authentication_failed",
                state,
                "Mailbox authentication failed.",
            ),
        )
        return int(
            db.execute(
                "SELECT id FROM users WHERE source_email='member@jcf.gov.jm'"
            ).fetchone()["id"]
        )


def make_due(user_id):
    with conn() as db:
        db.execute(
            """UPDATE users
               SET auto_recovery_next_at=DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 MINUTE)
               WHERE id=?""",
            (user_id,),
        )


def test_issue_is_classified_and_scheduled_for_background_recovery():
    uid = seed_user()
    service.record_user_issue(
        uid,
        "mailbox_authentication_failed",
        "Mailbox authentication failed.",
    )
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["issue_category"] == "credentials"
    assert row["issue_status"] == "open"
    assert row["manual_action_required"] == 0
    assert row["auto_recovery_status"] == "scheduled"
    assert row["auto_recovery_next_at"] is not None


@pytest.mark.asyncio
async def test_background_recovery_repushes_stored_credential_and_restarts_same_object(monkeypatch):
    cloud = IssueCloud()
    configure_cloud(monkeypatch, cloud)
    uid = seed_user()
    service.record_user_issue(
        uid,
        "mailbox_authentication_failed",
        "Mailbox authentication failed.",
    )
    make_due(uid)

    result = await service.process_background_issues()
    assert result["recovered"] == 1
    assert cloud.credentials == [
        ("token-45821", "member@jcf.gov.jm", "Known#Password2026")
    ]
    assert cloud.restarts == [45821]

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["cloudiway_object_id"] == 45821
    assert row["migration_status"] == "migrating"
    assert row["issue_status"] == "recovering"
    assert row["auto_recovery_attempts"] == 1
    assert row["auto_recovery_status"] == "restarted"


@pytest.mark.asyncio
async def test_repeated_credential_failure_stops_after_retry_limit(monkeypatch):
    cloud = IssueCloud()
    configure_cloud(monkeypatch, cloud)
    uid = seed_user()

    service.record_user_issue(uid, "mailbox_authentication_failed", "Auth failed")
    make_due(uid)
    first = await service.process_background_issues()
    assert first["recovered"] == 1

    # Simulate Cloudiway reporting the same failure again after the first restart.
    with conn() as db:
        db.execute(
            "UPDATE users SET migration_status='failed' WHERE id=?",
            (uid,),
        )
    service.record_user_issue(uid, "mailbox_authentication_failed", "Auth failed again")
    make_due(uid)
    second = await service.process_background_issues()
    assert second["recovered"] == 1
    assert cloud.restarts == [45821, 45821]

    # The next detection is no longer eligible for an automatic third restart.
    with conn() as db:
        db.execute(
            "UPDATE users SET migration_status='failed' WHERE id=?",
            (uid,),
        )
    service.record_user_issue(uid, "mailbox_authentication_failed", "Auth failed third time")
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["auto_recovery_attempts"] == 2
    assert row["issue_status"] == "manual_required"
    assert row["manual_action_required"] == 1
    assert row["auto_recovery_status"] == "manual_required"


@pytest.mark.asyncio
async def test_background_recovery_does_not_restart_job_that_is_now_running(monkeypatch):
    cloud = IssueCloud(status="Migrating")
    configure_cloud(monkeypatch, cloud)
    uid = seed_user()
    service.record_user_issue(uid, "mailbox_authentication_failed", "Old auth failure")
    make_due(uid)

    result = await service.process_background_issues()
    assert result["resolved"] == 1
    assert cloud.credentials == []
    assert cloud.restarts == []

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["migration_status"] == "migrating"
    assert row["issue_status"] == "resolved"
    assert row["issue_code"] is None


def test_uncategorized_failed_submission_appears_in_issue_center():
    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,migration_status,error_message
               ) VALUES(?,?,?,?)""",
            (
                "submit.fail@jcf.gov.jm",
                "submit.fail@jcf.gov.jm",
                "failed",
                "Cloudiway submit request failed before an object ID was returned.",
            ),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='submit.fail@jcf.gov.jm'"
        ).fetchone()["id"])

    service.sync_local_issue_states()
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["issue_code"] == "cloudiway_submission_failed"
    assert row["issue_category"] == "cloudiway"
    assert row["issue_status"] == "manual_required"


def test_issue_center_drills_into_password_users():
    uid = seed_user()
    service.record_user_issue(uid, "mailbox_authentication_failed", "Auth failed")

    with TestClient(app) as client:
        login(client)
        page = client.get("/issues?category=credentials")
        assert page.status_code == 200
        assert "Migration Issue Center" in page.text
        assert "member@jcf.gov.jm" in page.text
        assert "Password / Credentials" in page.text
        assert "Save Password &amp; Retry" in page.text or "Save Password & Retry" in page.text


def test_dashboard_api_returns_issue_counts():
    uid = seed_user()
    service.record_user_issue(uid, "mailbox_authentication_failed", "Auth failed")

    with TestClient(app) as client:
        login(client)
        r = client.get("/api/dashboard")
        assert r.status_code == 200
        payload = r.json()
    assert payload["issue_counts"]["credentials"] == 1
    assert payload["issue_labels"]["credentials"] == "Password / Credentials"


def test_manual_password_entry_encrypts_new_value_and_restarts(monkeypatch):
    cloud = IssueCloud()
    configure_cloud(monkeypatch, cloud)
    uid = seed_user(password="Old#Password2026")
    service.record_user_issue(uid, "mailbox_authentication_failed", "Auth failed")

    with TestClient(app) as client:
        login(client)
        r = client.post(
            f"/issues/user/{uid}/password-retry",
            data={"new_password": "New#Password2026"},
            follow_redirects=False,
        )
        assert r.status_code == 303

    assert cloud.credentials == [
        ("token-45821", "member@jcf.gov.jm", "New#Password2026")
    ]
    assert cloud.restarts == [45821]

    with conn() as db:
        row = db.execute(
            "SELECT source_credential_password_enc,source_credential_origin FROM users WHERE id=?",
            (uid,),
        ).fetchone()
    assert decrypt_secret(row["source_credential_password_enc"]) == "New#Password2026"
    assert row["source_credential_origin"] == "issue_manual_update"


def test_ambiguous_imap_connectivity_is_not_auto_recovered():
    uid = seed_user()
    service.record_user_issue(
        uid,
        "source_imap_connection_failed",
        "Cannot connect IMAP client.",
    )
    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["issue_category"] == "source_connectivity"
    assert row["issue_status"] == "manual_required"
    assert row["manual_action_required"] == 1
