import io

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app import service
from app.db import conn, init_db, reset_test_data, set_setting, get_setting
from app.main import app
from app.security import decrypt_secret, encrypt_secret


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    reset_test_data()
    yield


def login(client):
    r = client.post(
        "/login",
        data={"admin_password": "test-admin-password"},
        follow_redirects=False,
    )
    assert r.status_code == 303


class RecoveryCloud:
    def __init__(self, progress_status="Failed", existing_id=45821):
        self.progress_status = progress_status
        self.existing_id = existing_id
        self.created = []
        self.credentials = []
        self.restarted = []
        self.started = []
        self.batch_members = []
        self.batch_id = 88123

    async def create_mail_batch(self, name):
        return {"id": self.batch_id, "name": name}

    async def mail_batches(self):
        return []

    async def add_mail_batch_members(self, batch_id, object_ids):
        self.batch_members.append((batch_id, list(object_ids)))
        return {"ok": True}

    async def verify_mail_user(self, email):
        if self.existing_id is None:
            return {}
        return {"id": self.existing_id}

    async def get_mail_user(self, object_id):
        assert object_id == self.existing_id
        return {
            "id": object_id,
            "sourceEmail": "member@jcf.gov.jm",
            "targetEmail": "member@jcf.gov.jm",
        }

    async def create_mail_user(self, payload):
        self.created.append(dict(payload))
        raise AssertionError("Recovery workflow must not create a new Cloudiway user")

    async def progress(self, object_id, since_minutes=15):
        assert object_id == self.existing_id
        return {"status": self.progress_status, "percentage": 4}

    async def get_self_service_token(self, object_id):
        assert object_id == self.existing_id
        return "existing-token"

    async def register_source_credentials(self, token, username, password):
        self.credentials.append((token, username, password))
        return {"ok": True}

    async def restart_migration(self, object_id):
        self.restarted.append(object_id)
        return {"ok": True}

    async def start_migration(self, object_ids):
        self.started.append(list(object_ids))
        return {"ok": True}


def configure(monkeypatch, cloud):
    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")
    set_setting("direct_email_domain", "jcf.gov.jm")


def seed_failed_local_user():
    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,first_name,last_name,
                   password_reset_method,cloudiway_object_id,cloudiway_status,
                   migration_status,error_message
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "member@jcf.gov.jm",
                "member@jcf.gov.jm",
                "Old",
                "Name",
                "existing_password",
                45821,
                "failed",
                "failed",
                "old Cloudiway error",
            ),
        )
        return int(
            db.execute(
                "SELECT id FROM users WHERE source_email='member@jcf.gov.jm'"
            ).fetchone()["id"]
        )


def test_direct_domain_setting_is_saved():
    with TestClient(app) as client:
        login(client)
        r = client.post(
            "/settings/direct-migration",
            data={"email_domain": "@example.jcf.gov.jm"},
            follow_redirects=False,
        )
        assert r.status_code == 303
    assert get_setting("direct_email_domain") == "example.jcf.gov.jm"


def test_recovery_template_uses_username_and_password():
    with TestClient(app) as client:
        login(client)
        r = client.get("/upload/recovery-template.xlsx")
        assert r.status_code == 200
        frame = pd.read_excel(
            io.BytesIO(r.content),
            sheet_name="Cloudiway Error Recovery",
            dtype=str,
        )
    assert list(frame.columns) == [
        "username",
        "password",
        "first_name",
        "middle_name",
        "last_name",
        "computer_number",
    ]


def test_direct_username_without_domain_resolves_source_and_target_same():
    set_setting("direct_email_domain", "jcf.gov.jm")
    csv_data = (
        "username,password,first_name,middle_name,last_name,computer_number\n"
        "member,Current#Password2026,Test,,Member,14323\n"
    ).encode()

    with TestClient(app) as client:
        login(client)
        r = client.post(
            "/upload",
            files={"file": ("direct.csv", csv_data, "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        assert r.status_code == 303

    with conn() as db:
        row = db.execute(
            "SELECT * FROM users WHERE source_email='member@jcf.gov.jm'"
        ).fetchone()
    assert row is not None
    assert row["source_email"] == "member@jcf.gov.jm"
    assert row["target_email"] == "member@jcf.gov.jm"
    assert decrypt_secret(row["source_credential_password_enc"]) == "Current#Password2026"


@pytest.mark.asyncio
async def test_recovery_service_repushes_password_and_marks_same_object_for_restart(monkeypatch):
    cloud = RecoveryCloud(progress_status="Failed")
    configure(monkeypatch, cloud)
    uid = seed_failed_local_user()

    with conn() as db:
        db.execute(
            """UPDATE users
               SET password_reset_method='existing_password_retry',
                   source_credential_username='member@jcf.gov.jm',
                   source_credential_password_enc=?,
                   source_credential_origin='uploaded_recovery'
               WHERE id=?""",
            (encrypt_secret("Fresh#Password2026"), uid),
        )

    oid = await service.prepare_existing_password_user(uid)
    assert oid == 45821
    assert cloud.created == []
    assert cloud.credentials == [
        ("existing-token", "member@jcf.gov.jm", "Fresh#Password2026")
    ]

    with conn() as db:
        row = db.execute(
            "SELECT cloudiway_object_id,cloudiway_status,migration_status FROM users WHERE id=?",
            (uid,),
        ).fetchone()
    assert row["cloudiway_object_id"] == 45821
    assert row["cloudiway_status"] == "restart_required"
    assert row["migration_status"] == "ready"


@pytest.mark.asyncio
async def test_recovery_missing_cloudiway_object_does_not_create_one(monkeypatch):
    cloud = RecoveryCloud(progress_status="Failed", existing_id=None)
    configure(monkeypatch, cloud)

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,password_reset_method,
                   source_credential_username,source_credential_password_enc,
                   source_credential_origin,migration_status
               ) VALUES(?,?,?,?,?,?,?)""",
            (
                "missing@jcf.gov.jm",
                "missing@jcf.gov.jm",
                "existing_password_retry",
                "missing@jcf.gov.jm",
                encrypt_secret("Fresh#Password2026"),
                "uploaded_recovery",
                "failed",
            ),
        )
        uid = int(
            db.execute(
                "SELECT id FROM users WHERE source_email='missing@jcf.gov.jm'"
            ).fetchone()["id"]
        )

    with pytest.raises(RuntimeError, match="No existing Cloudiway mail user"):
        await service.prepare_existing_password_user(uid)
    assert cloud.created == []
    assert cloud.credentials == []
    assert cloud.restarted == []


@pytest.mark.asyncio
async def test_recovery_does_not_touch_running_cloudiway_job(monkeypatch):
    cloud = RecoveryCloud(progress_status="Migrating")
    configure(monkeypatch, cloud)
    uid = seed_failed_local_user()

    with conn() as db:
        db.execute(
            """UPDATE users
               SET password_reset_method='existing_password_retry',
                   source_credential_username='member@jcf.gov.jm',
                   source_credential_password_enc=?,
                   source_credential_origin='uploaded_recovery'
               WHERE id=?""",
            (encrypt_secret("Fresh#Password2026"), uid),
        )

    oid = await service.prepare_existing_password_user(uid)
    assert oid == 45821
    assert cloud.credentials == []
    assert cloud.restarted == []
    with conn() as db:
        row = db.execute(
            "SELECT cloudiway_status,migration_status FROM users WHERE id=?",
            (uid,),
        ).fetchone()
    assert row["cloudiway_status"] == "existing_migrating"
    assert row["migration_status"] == "migrating"


def test_full_recovery_upload_repushes_password_and_restarts_same_object(monkeypatch):
    cloud = RecoveryCloud(progress_status="Failed")
    configure(monkeypatch, cloud)
    uid = seed_failed_local_user()

    csv_data = (
        "username,password,first_name,middle_name,last_name,computer_number\n"
        "member,NewKnown#Pass2026,Correct,,Member,14323\n"
    ).encode()

    with TestClient(app) as client:
        login(client)

        upload = client.post(
            "/upload",
            files={"file": ("recovery.csv", csv_data, "text/csv")},
            data={"workflow_mode": "existing_password_retry"},
            follow_redirects=False,
        )
        assert upload.status_code == 303

        with conn() as db:
            staged = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            upload_batch = db.execute(
                "SELECT * FROM upload_batches ORDER BY id DESC LIMIT 1"
            ).fetchone()
            upload_id = int(upload_batch["id"])

        assert staged["password_reset_method"] == "existing_password_retry"
        assert staged["source_email"] == "member@jcf.gov.jm"
        assert staged["target_email"] == "member@jcf.gov.jm"
        assert staged["cloudiway_object_id"] == 45821
        assert decrypt_secret(staged["source_credential_password_enc"]) == "NewKnown#Pass2026"

        generate = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "1", "auto_start": "1"},
            follow_redirects=False,
        )
        assert generate.status_code == 303

    assert cloud.created == []
    assert cloud.credentials == [
        ("existing-token", "member@jcf.gov.jm", "NewKnown#Pass2026")
    ]
    assert cloud.restarted == [45821]
    assert cloud.started == []
    assert cloud.batch_members == [(cloud.batch_id, [45821])]

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        mb = db.execute(
            "SELECT * FROM migration_batches ORDER BY id DESC LIMIT 1"
        ).fetchone()
        events = [
            e["event_type"]
            for e in db.execute(
                "SELECT event_type FROM events WHERE user_id=? ORDER BY id",
                (uid,),
            ).fetchall()
        ]

    assert row["cloudiway_object_id"] == 45821
    assert row["migration_status"] == "starting"
    assert row["cloudiway_status"] == "restart_requested"
    assert mb["cloudiway_batch_id"] == cloud.batch_id
    assert mb["workflow_status"] == "starting"
    assert "credentials_refreshed_restart_required" in events
    assert "cloudiway_existing_migration_restart_requested" in events


def test_recovery_upload_protects_locally_running_and_completed_users():
    with conn() as db:
        for email, state, oid in (
            ("run@jcf.gov.jm", "migrating", 10),
            ("done@jcf.gov.jm", "completed", 11),
        ):
            db.execute(
                """INSERT INTO users(
                       source_email,target_email,password_reset_method,
                       cloudiway_object_id,cloudiway_status,migration_status
                   ) VALUES(?,?,?,?,?,?)""",
                (email, email, "existing_password", oid, state, state),
            )

    csv_data = (
        "username,password\n"
        "run,Run#Pass2026\n"
        "done,Done#Pass2026\n"
    ).encode()

    with TestClient(app) as client:
        login(client)
        r = client.post(
            "/upload",
            files={"file": ("recovery.csv", csv_data, "text/csv")},
            data={"workflow_mode": "existing_password_retry"},
        )
    assert r.status_code == 400
    assert "protected" in r.text.lower()


def test_upload_page_exposes_explicit_recovery_option():
    with TestClient(app) as client:
        login(client)
        r = client.get("/upload")
    assert r.status_code == 200
    assert 'value="existing_password_retry"' in r.text
    assert "push password again" in r.text.lower() or "error recovery" in r.text.lower()
