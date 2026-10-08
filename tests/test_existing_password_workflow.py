import io

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.db import conn, init_db, reset_test_data, set_setting
from app.main import app
from app.security import decrypt_secret, encrypt_secret


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    reset_test_data()
    yield


def login(client):
    response = client.post(
        "/login",
        data={"admin_password": "test-admin-password"},
        follow_redirects=False,
    )
    assert response.status_code == 303


class FakeCloud:
    def __init__(self):
        self.next_id = 2000
        self.users = {}
        self.credentials = []
        self.batch_members = []
        self.started = []

    async def create_mail_batch(self, name):
        return {"id": 99001, "name": name}

    async def mail_batches(self):
        return []

    async def verify_mail_user(self, email):
        for object_id, payload in self.users.items():
            if payload["sourceEmail"] == email:
                return {"id": object_id}
        return {}

    async def create_mail_user(self, payload):
        self.next_id += 1
        self.users[self.next_id] = dict(payload)
        return {"id": self.next_id}

    async def get_mail_user(self, object_id):
        return self.users[object_id]

    async def get_self_service_token(self, object_id):
        return f"token-{object_id}"

    async def register_source_credentials(self, token, username, password):
        self.credentials.append((token, username, password))
        return {"ok": True}

    async def add_mail_batch_members(self, batch_id, object_ids):
        self.batch_members.append((batch_id, list(object_ids)))
        return {"ok": True}

    async def start_migration(self, object_ids):
        self.started.append(list(object_ids))
        return {"ok": True}


def configure_cloudiway(monkeypatch):
    from app import service

    cloud = FakeCloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("test-cloudiway-token"), True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")
    return cloud


def existing_password_csv():
    return (
        "source_email,target_email,password,first_name,last_name,computer_number\n"
        "one@rack.example,one@jcf.gov.jm,0012A#$,One,User,10001\n"
        "two@rack.example,two@jcf.gov.jm,P@ss-Two-2026,Two,User,10002\n"
        "three@rack.example,three@jcf.gov.jm,Third!Pass9,Three,User,10003\n"
    ).encode()


def test_existing_password_template_contains_password_column():
    with TestClient(app) as client:
        login(client)
        response = client.get("/upload/existing-password-template.xlsx")
        assert response.status_code == 200
        frame = pd.read_excel(
            io.BytesIO(response.content),
            sheet_name="Cloudiway Existing Password",
            dtype=str,
        )
        assert list(frame.columns) == [
            "source_email",
            "target_email",
            "password",
            "first_name",
            "middle_name",
            "last_name",
            "computer_number",
        ]


def test_existing_password_upload_needs_no_ad_profile_and_encrypts_passwords():
    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    with conn() as db:
        upload = db.execute("SELECT * FROM upload_batches").fetchone()
        assert upload["workflow_mode"] == "existing_password"
        assert upload["provisioning_profile_id"] is None
        assert upload["imported_rows"] == 3

        rows = db.execute(
            "SELECT * FROM users ORDER BY source_email"
        ).fetchall()

    assert len(rows) == 3
    one = next(row for row in rows if row["source_email"] == "one@rack.example")
    assert one["password_reset_method"] == "existing_password"
    assert one["rackspace_status"] == "existing_password"
    assert one["provisioning_status"] == "bypassed"
    assert one["ad_match_status"] == "bypassed"
    assert one["generated_password_enc"] is None
    assert one["source_credential_username"] == "one@rack.example"
    assert one["source_credential_origin"] == "uploaded_excel"
    assert one["source_credential_password_enc"] != "0012A#$"
    assert decrypt_secret(one["source_credential_password_enc"]) == "0012A#$"


def test_existing_password_group_skips_ad_and_pushes_excel_passwords_to_cloudiway(monkeypatch):
    cloud = configure_cloudiway(monkeypatch)

    from app import main as main_module

    def forbidden_ad_assessment(*args, **kwargs):
        raise AssertionError("AD assessment must not run in existing-password mode")

    monkeypatch.setattr(main_module, "assess_migration_batch", forbidden_ad_assessment)

    with TestClient(app) as client:
        login(client)
        upload_response = client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        assert upload_response.status_code == 303

        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        batch_response = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "2"},
            follow_redirects=False,
        )
        assert batch_response.status_code == 303

    assert len(cloud.credentials) == 2
    pushed = {(username, password) for _, username, password in cloud.credentials}
    assert pushed == {
        ("one@rack.example", "0012A#$"),
        ("two@rack.example", "P@ss-Two-2026"),
    }
    assert cloud.batch_members
    assert cloud.started == []

    with conn() as db:
        batch = db.execute("SELECT * FROM migration_batches").fetchone()
        assert batch["selected_count"] == 2
        assert batch["cloudiway_batch_id"] == 99001
        assert batch["workflow_status"] == "ready_to_migrate"

        rows = db.execute(
            """SELECT u.source_email,u.cloudiway_status,u.migration_status,
                      u.provisioning_status,u.ad_match_status
               FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=?
               ORDER BY u.source_email""",
            (batch["id"],),
        ).fetchall()

    assert all(row["cloudiway_status"] == "credentials_set" for row in rows)
    assert all(row["migration_status"] == "ready" for row in rows)
    assert all(row["provisioning_status"] == "bypassed" for row in rows)
    assert all(row["ad_match_status"] == "bypassed" for row in rows)


def test_existing_password_auto_start_starts_selected_cloudiway_batch(monkeypatch):
    cloud = configure_cloudiway(monkeypatch)

    with TestClient(app) as client:
        login(client)
        client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        response = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "1", "auto_start": "1"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.credentials) == 1
    assert len(cloud.started) == 1
    assert len(cloud.started[0]) == 1

    with conn() as db:
        batch = db.execute("SELECT * FROM migration_batches").fetchone()
        user = db.execute(
            """SELECT u.*
               FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=?""",
            (batch["id"],),
        ).fetchone()
    assert batch["workflow_status"] == "migrating"
    assert user["migration_status"] == "migrating"


def test_existing_password_mode_requires_password_column():
    csv_data = (
        "source_email,target_email\n"
        "one@rack.example,one@jcf.gov.jm\n"
    ).encode()

    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/upload",
            files={"file": ("missing-password.csv", csv_data, "text/csv")},
            data={"workflow_mode": "existing_password"},
        )

    assert response.status_code == 400
    assert "password" in response.text.lower()


@pytest.mark.asyncio
async def test_existing_password_cloudiway_batch_retry_restores_ready_state(monkeypatch):
    from app import service

    with conn() as db:
        up = db.execute(
            """INSERT INTO upload_batches(
                   batch_name,workflow_mode,workflow_status,total_rows,imported_rows
               ) VALUES(?,?,?,?,?)""",
            ("JCF-TEST-U00001", "existing_password", "partially_batched", 1, 1),
        )
        upload_id = up.lastrowid
        mb = db.execute(
            """INSERT INTO migration_batches(
                   upload_batch_id,sequence_number,batch_name,workflow_status,selected_count
               ) VALUES(?,?,?,?,?)""",
            (upload_id, 1, "JCF-TEST-U00001-B001", "cloudiway_batch_error", 1),
        )
        migration_batch_id = mb.lastrowid

    class RetryCloud:
        async def create_mail_batch(self, name):
            return {"id": 99123, "name": name}

        async def mail_batches(self):
            return []

    async def ready():
        return RetryCloud()

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    cloud_id = await service.ensure_migration_cloudiway_batch(migration_batch_id)
    assert cloud_id == 99123

    with conn() as db:
        row = db.execute(
            "SELECT workflow_status,cloudiway_batch_id FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()
    assert row["workflow_status"] == "ready_for_cloudiway"
    assert row["cloudiway_batch_id"] == 99123


def test_existing_password_credential_payload_is_exact_source_email_and_exact_excel_password(monkeypatch):
    cloud = configure_cloudiway(monkeypatch)
    csv_data = (
        "source_email,target_email,password\n"
        "Exact.User@rack.example,exact.user@jcf.gov.jm,AbC#123$xyZ\n"
    ).encode()

    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/upload",
            files={"file": ("exact.csv", csv_data, "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        assert response.status_code == 303

        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        response = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "1"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.credentials) == 1
    _, username, password = cloud.credentials[0]
    assert username == "exact.user@rack.example"
    assert password == "AbC#123$xyZ"


def test_existing_password_dedicated_credential_username_mismatch_is_rejected():
    from app.service import _source_credentials_for_cloudiway

    user = {
        "source_email": "correct@rack.example",
        "source_credential_username": "wrong@rack.example",
        "source_credential_password_enc": encrypt_secret("CorrectPassword123!"),
        "generated_password_enc": None,
        "password_reset_method": "existing_password",
    }
    with pytest.raises(RuntimeError, match="does not match source email"):
        _source_credentials_for_cloudiway(user)


def test_admin_reveal_shows_exact_username_sent_to_cloudiway_and_uploaded_password():
    with TestClient(app) as client:
        login(client)
        response = client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        assert response.status_code == 303

        with conn() as db:
            user_id = db.execute(
                "SELECT id FROM users WHERE source_email='one@rack.example'"
            ).fetchone()["id"]

        response = client.get(f"/users/{user_id}/password")
        assert response.status_code == 200
        payload = response.json()

    assert payload["username_sent_to_cloudiway"] == "one@rack.example"
    assert payload["password"] == "0012A#$"
    assert payload["password_source"] == "uploaded_excel"
