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
        self.mail_start_requests = []

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

    async def start_mail_migration(self, object_ids, batch_ids=None):
        object_ids = list(object_ids)
        batch_ids = list(batch_ids or [])
        self.started.append(object_ids)
        self.mail_start_requests.append((object_ids, batch_ids))
        return {
            "isSuccess": True,
            "message": "StartMailJobs done",
            "responseData": None,
            "error": [],
        }


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
    assert batch["workflow_status"] == "starting"
    assert user["migration_status"] == "starting"
    assert user["cloudiway_status"] == "start_requested"


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



def test_individual_push_button_creates_one_user_cloudiway_group(monkeypatch):
    cloud = configure_cloudiway(monkeypatch)

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
            upload_id = int(db.execute("SELECT id FROM upload_batches").fetchone()["id"])
            user_id = int(
                db.execute(
                    "SELECT id FROM users WHERE source_email='two@rack.example'"
                ).fetchone()["id"]
            )

        page = client.get(f"/workflow/{upload_id}")
        assert page.status_code == 200
        assert f'/workflow/{upload_id}/push-user/{user_id}' in page.text
        assert "Push Only" in page.text
        assert "Push &amp; Start" in page.text or "Push & Start" in page.text

        response = client.post(
            f"/workflow/{upload_id}/push-user/{user_id}",
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.credentials) == 1
    _, username, password = cloud.credentials[0]
    assert username == "two@rack.example"
    assert password == "P@ss-Two-2026"
    assert cloud.started == []

    with conn() as db:
        batch = db.execute("SELECT * FROM migration_batches").fetchone()
        member = db.execute(
            """SELECT u.source_email,u.migration_status,u.cloudiway_status
               FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=?""",
            (batch["id"],),
        ).fetchone()
        remaining = db.execute(
            """SELECT COUNT(*) c
               FROM upload_batch_members ubm
               JOIN users u ON u.id=ubm.user_id
               WHERE ubm.upload_batch_id=?
                 AND NOT EXISTS (
                     SELECT 1 FROM migration_batch_members mbm
                     JOIN migration_batches mb ON mb.id=mbm.migration_batch_id
                     WHERE mb.upload_batch_id=? AND mbm.user_id=u.id
                 )""",
            (upload_id, upload_id),
        ).fetchone()["c"]

    assert batch["selected_count"] == 1
    assert batch["cloudiway_batch_id"] == 99001
    assert batch["workflow_status"] == "ready_to_migrate"
    assert member["source_email"] == "two@rack.example"
    assert member["migration_status"] == "ready"
    assert member["cloudiway_status"] == "credentials_set"
    assert remaining == 2


def test_workflow_does_not_require_preexisting_access_token_when_service_can_reauthenticate(monkeypatch):
    from app import service

    cloud = FakeCloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", "", True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")

    with TestClient(app) as client:
        login(client)
        client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = int(db.execute("SELECT id FROM upload_batches").fetchone()["id"])

        response = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "1"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.credentials) == 1
    with conn() as db:
        assert db.execute("SELECT COUNT(*) c FROM migration_batches").fetchone()["c"] == 1



def test_individual_push_and_start_requests_cloudiway_start(monkeypatch):
    cloud = configure_cloudiway(monkeypatch)

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
            upload_id = int(db.execute("SELECT id FROM upload_batches").fetchone()["id"])
            user_id = int(
                db.execute(
                    "SELECT id FROM users WHERE source_email='two@rack.example'"
                ).fetchone()["id"]
            )

        page = client.get(f"/workflow/{upload_id}")
        assert f'/workflow/{upload_id}/push-start-user/{user_id}' in page.text

        response = client.post(
            f"/workflow/{upload_id}/push-start-user/{user_id}",
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.credentials) == 1
    assert len(cloud.started) == 1
    assert len(cloud.started[0]) == 1

    with conn() as db:
        batch = db.execute("SELECT * FROM migration_batches").fetchone()
        member = db.execute(
            """SELECT u.source_email,u.migration_status,u.cloudiway_status
               FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=?""",
            (batch["id"],),
        ).fetchone()

    assert batch["selected_count"] == 1
    assert batch["workflow_status"] == "starting"
    assert member["source_email"] == "two@rack.example"
    assert member["migration_status"] == "starting"
    assert member["cloudiway_status"] == "start_requested"



def test_new_controlled_group_uses_documented_startjobs_api(monkeypatch):
    from app import service

    class BatchStartCloud(FakeCloud):
        def __init__(self):
            super().__init__()
            self.batch_starts = []

        async def start_batch_migration(self, batch_id):
            self.batch_starts.append(int(batch_id))
            return {
                "isSuccess": True,
                "message": "StartBatch done",
                "count": 0,
                "responseData": None,
                "error": [],
            }

    cloud = BatchStartCloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("test-cloudiway-token"), True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")

    with TestClient(app) as client:
        login(client)
        client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = int(db.execute("SELECT id FROM upload_batches").fetchone()["id"])

        response = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "2", "auto_start": "1"},
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.started) == 1
    assert len(cloud.started[0]) == 2
    assert cloud.mail_start_requests == []
    with conn() as db:
        batch = db.execute("SELECT * FROM migration_batches").fetchone()
        users = db.execute(
            """SELECT u.migration_status,u.cloudiway_status
               FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=?""",
            (batch["id"],),
        ).fetchall()
    assert batch["workflow_status"] == "starting"
    assert all(u["migration_status"] == "starting" for u in users)
    assert all(u["cloudiway_status"] == "start_requested" for u in users)


def test_individual_push_and_start_uses_documented_startjobs_api(monkeypatch):
    from app import service

    class BatchStartCloud(FakeCloud):
        def __init__(self):
            super().__init__()
            self.batch_starts = []

        async def start_batch_migration(self, batch_id):
            self.batch_starts.append(int(batch_id))
            return {
                "isSuccess": True,
                "message": "StartBatch done",
                "count": 0,
                "responseData": None,
                "error": [],
            }

    cloud = BatchStartCloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("test-cloudiway-token"), True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")

    with TestClient(app) as client:
        login(client)
        client.post(
            "/upload",
            files={"file": ("existing.csv", existing_password_csv(), "text/csv")},
            data={"workflow_mode": "existing_password"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = int(db.execute("SELECT id FROM upload_batches").fetchone()["id"])
            user_id = int(
                db.execute(
                    "SELECT id FROM users WHERE source_email='two@rack.example'"
                ).fetchone()["id"]
            )

        response = client.post(
            f"/workflow/{upload_id}/push-start-user/{user_id}",
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert len(cloud.started) == 1
    assert len(cloud.started[0]) == 1
    assert cloud.mail_start_requests == []



def test_per_user_start_restart_reuses_existing_cloudiway_object(monkeypatch):
    from app import service

    class RestartCloud(FakeCloud):
        def __init__(self):
            super().__init__()
            self.mail_start_requests = []

        async def start_mail_migration(self, object_ids, batch_ids=None):
            self.mail_start_requests.append((list(object_ids), list(batch_ids or [])))
            return {
                "isSuccess": True,
                "message": "StartMailJobs done",
                "responseData": None,
                "error": [],
            }

    cloud = RestartCloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("test-cloudiway-token"), True)

    with conn() as db:
        up = db.execute(
            """INSERT INTO upload_batches(
                   batch_name,workflow_mode,workflow_status,total_rows,imported_rows
               ) VALUES(?,?,?,?,?)""",
            ("RESTART-U1", "existing_password", "fully_batched", 1, 1),
        )
        upload_id = int(up.lastrowid)
        mb = db.execute(
            """INSERT INTO migration_batches(
                   upload_batch_id,sequence_number,batch_name,workflow_status,
                   cloudiway_batch_id,selected_count
               ) VALUES(?,?,?,?,?,?)""",
            (upload_id, 1, "RESTART-U1-B001", "ready_to_migrate", 77, 1),
        )
        batch_id = int(mb.lastrowid)
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,cloudiway_object_id,cloudiway_status,
                   migration_status,batch_number
               ) VALUES(?,?,?,?,?,?)""",
            (
                "stuck@jcf.gov.jm",
                "stuck@jcf.gov.jm",
                429,
                "not_started",
                "ready",
                batch_id,
            ),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='stuck@jcf.gov.jm'"
        ).fetchone()["id"])
        db.execute(
            "INSERT INTO upload_batch_members(upload_batch_id,user_id,row_order) VALUES(?,?,?)",
            (upload_id, uid, 1),
        )
        db.execute(
            "INSERT INTO migration_batch_members(migration_batch_id,user_id) VALUES(?,?)",
            (batch_id, uid),
        )

    with TestClient(app) as client:
        login(client)
        page = client.get(f"/workflow/{upload_id}")
        assert "Start / Restart" in page.text
        response = client.post(
            f"/cloudiway/user/{uid}/start-again",
            follow_redirects=False,
        )
        assert response.status_code == 303

    assert cloud.started == [[429]]
    assert cloud.mail_start_requests == []
    assert cloud.users == {}

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        batch = db.execute("SELECT * FROM migration_batches WHERE id=?", (batch_id,)).fetchone()

    assert row["cloudiway_object_id"] == 429
    assert row["migration_status"] == "starting"
    assert row["cloudiway_status"] == "manual_start_requested"
    assert batch["workflow_status"] == "starting"


def test_per_user_start_restart_protects_only_cloudiway_confirmed_running_and_completed(monkeypatch):
    from app import service

    class Cloud:
        def __init__(self):
            self.started = []

        async def job_status(self, object_id):
            if object_id == 500:
                return {"isSuccess": True, "responseData": {"status": "Working"}, "error": []}
            if object_id == 501:
                return {"isSuccess": True, "responseData": {"status": "Success"}, "error": []}
            return {"isSuccess": True, "responseData": {"status": "NotStarted"}, "error": []}

        async def progress(self, object_id, since_minutes):
            return {
                "isSuccess": True,
                "responseData": {
                    "blockId": object_id,
                    "migratedEmails": 10 if object_id == 500 else 0,
                    "errorEmails": 0,
                    "ignoredEmails": 0,
                    "totalEmails": 100 if object_id == 500 else 0,
                    "startDateTime": "2026-10-12T15:00:00Z" if object_id == 500 else None,
                    "lastActivityDateTime": "2026-10-12T15:05:00Z" if object_id == 500 else None,
                    "error": [],
                },
                "error": [],
            }

        async def start_migration(self, object_ids):
            self.started.append(list(object_ids))
            return {"isSuccess": True, "error": []}

    cloud = Cloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)

    with conn() as db:
        for email, status, oid in [
            ("running@jcf.gov.jm", "migrating", 500),
            ("done@jcf.gov.jm", "completed", 501),
        ]:
            db.execute(
                """INSERT INTO users(
                       source_email,target_email,cloudiway_object_id,cloudiway_status,migration_status
                   ) VALUES(?,?,?,?,?)""",
                (email, email, oid, status, status),
            )
        running_id = int(db.execute(
            "SELECT id FROM users WHERE source_email='running@jcf.gov.jm'"
        ).fetchone()["id"])
        done_id = int(db.execute(
            "SELECT id FROM users WHERE source_email='done@jcf.gov.jm'"
        ).fetchone()["id"])

    import asyncio
    running = asyncio.run(service.restart_stuck_cloudiway_user(running_id))
    done = asyncio.run(service.restart_stuck_cloudiway_user(done_id))

    assert running["started"] is False
    assert running["confirmed"] is True
    assert running["state"] == "migrating"
    assert done["started"] is False
    assert done["confirmed"] is True
    assert done["state"] == "completed"
    assert cloud.started == []


def test_start_restart_button_visible_for_locally_migrating_cloudiway_record(monkeypatch):
    with conn() as db:
        up = db.execute(
            """INSERT INTO upload_batches(
                   batch_name,workflow_mode,workflow_status,total_rows,imported_rows
               ) VALUES(?,?,?,?,?)""",
            ("VISIBLE-U1", "existing_password", "fully_batched", 1, 1),
        )
        upload_id = int(up.lastrowid)
        mb = db.execute(
            """INSERT INTO migration_batches(
                   upload_batch_id,sequence_number,batch_name,workflow_status,
                   cloudiway_batch_id,selected_count
               ) VALUES(?,?,?,?,?,?)""",
            (upload_id, 1, "VISIBLE-U1-B001", "migrating", 88, 1),
        )
        batch_id = int(mb.lastrowid)
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,cloudiway_object_id,cloudiway_status,
                   migration_status,batch_number
               ) VALUES(?,?,?,?,?,?)""",
            (
                "visible@jcf.gov.jm",
                "visible@jcf.gov.jm",
                430,
                "migrating",
                "migrating",
                batch_id,
            ),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='visible@jcf.gov.jm'"
        ).fetchone()["id"])
        db.execute(
            "INSERT INTO upload_batch_members(upload_batch_id,user_id,row_order) VALUES(?,?,?)",
            (upload_id, uid, 1),
        )
        db.execute(
            "INSERT INTO migration_batch_members(migration_batch_id,user_id) VALUES(?,?)",
            (batch_id, uid),
        )

    with TestClient(app) as client:
        login(client)
        page = client.get(f"/workflow/{upload_id}")

    assert page.status_code == 200
    assert "Cloudiway #430" in page.text
    assert "Start / Restart" in page.text
    assert f'/cloudiway/user/{uid}/start-again' in page.text



def test_manual_restart_does_not_trust_local_migrating_when_cloudiway_state_is_unknown_and_progress_is_zero(monkeypatch):
    from app import service

    class Cloud:
        def __init__(self):
            self.started = []

        async def job_status(self, object_id):
            # Simulates a Cloudiway response whose numeric/opaque state cannot
            # be translated by Swagger into a named enum.
            return {"isSuccess": True, "responseData": {"jobStatus": 0}, "error": []}

        async def progress(self, object_id, since_minutes):
            return {
                "isSuccess": True,
                "message": "GetMailProgress done",
                "responseData": {
                    "blockId": object_id,
                    "migratedEmails": 0,
                    "errorEmails": 0,
                    "ignoredEmails": 0,
                    "totalEmails": 0,
                    "recentMigratedEmails": 0,
                    "windowMinutes": 1,
                    "startDateTime": None,
                    "lastActivityDateTime": None,
                    "error": [],
                },
                "error": [],
            }

        async def start_migration(self, object_ids):
            self.started.append(list(object_ids))
            return {"isSuccess": True, "message": "StartJobs done", "error": []}

    cloud = Cloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,cloudiway_object_id,
                   cloudiway_status,migration_status
               ) VALUES(?,?,?,?,?)""",
            (
                "false.running@jcf.gov.jm",
                "false.running@jcf.gov.jm",
                427,
                "migrating",
                "migrating",
            ),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='false.running@jcf.gov.jm'"
        ).fetchone()["id"])

    import asyncio
    result = asyncio.run(service.restart_stuck_cloudiway_user(uid))

    assert result["started"] is True
    assert result["action"] == "StartJobs"
    assert result["live_state"] is None
    assert result["progress_has_activity"] is False
    assert cloud.started == [[427]]

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    assert row["migration_status"] == "starting"
    assert row["cloudiway_status"] == "manual_start_requested"


def test_manual_restart_blocks_only_confirmed_running_with_real_progress_activity(monkeypatch):
    from app import service

    class Cloud:
        def __init__(self):
            self.started = []

        async def job_status(self, object_id):
            return {"isSuccess": True, "responseData": {"status": "Working"}, "error": []}

        async def progress(self, object_id, since_minutes):
            return {
                "isSuccess": True,
                "responseData": {
                    "blockId": object_id,
                    "migratedEmails": 10,
                    "errorEmails": 0,
                    "ignoredEmails": 0,
                    "totalEmails": 100,
                    "startDateTime": "2026-10-12T15:00:00Z",
                    "lastActivityDateTime": "2026-10-12T15:05:00Z",
                    "error": [],
                },
                "error": [],
            }

        async def start_migration(self, object_ids):
            self.started.append(list(object_ids))
            return {"isSuccess": True, "error": []}

    cloud = Cloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,cloudiway_object_id,
                   cloudiway_status,migration_status
               ) VALUES(?,?,?,?,?)""",
            ("real.running@jcf.gov.jm","real.running@jcf.gov.jm",500,"migrating","migrating"),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='real.running@jcf.gov.jm'"
        ).fetchone()["id"])

    import asyncio
    result = asyncio.run(service.restart_stuck_cloudiway_user(uid))

    assert result["started"] is False
    assert "actively running" in result["reason"]
    assert cloud.started == []


def test_job_status_parser_does_not_treat_arbitrary_name_field_as_state():
    from app import service
    state, _ = service.parse_cloudiway_job_status(
        {
            "isSuccess": True,
            "responseData": {
                "name": "migrating",
                "jobStatus": 0,
            },
            "error": [],
        }
    )
    assert state is None



def test_manual_start_checks_notstarted_then_triggers_start_and_confirms_running(monkeypatch):
    from app import service

    class Cloud:
        def __init__(self):
            self.started = []
            self.status_calls = 0

        async def job_status(self, object_id):
            self.status_calls += 1
            status = "NotStarted" if self.status_calls == 1 else "Working"
            return {"isSuccess": True, "responseData": {"status": status}, "error": []}

        async def progress(self, object_id, since_minutes):
            active = self.status_calls > 1
            return {
                "isSuccess": True,
                "responseData": {
                    "blockId": object_id,
                    "migratedEmails": 1 if active else 0,
                    "errorEmails": 0,
                    "ignoredEmails": 0,
                    "totalEmails": 100 if active else 0,
                    "startDateTime": "2026-10-12T16:00:00Z" if active else None,
                    "lastActivityDateTime": "2026-10-12T16:00:01Z" if active else None,
                    "error": [],
                },
                "error": [],
            }

        async def start_migration(self, object_ids):
            self.started.append(list(object_ids))
            return {"isSuccess": True, "message": "StartJobs done", "error": []}

    cloud = Cloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,cloudiway_object_id,cloudiway_status,migration_status
               ) VALUES(?,?,?,?,?)""",
            ("verify.start@jcf.gov.jm","verify.start@jcf.gov.jm",427,"not_started","ready"),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='verify.start@jcf.gov.jm'"
        ).fetchone()["id"])

    import asyncio
    result = asyncio.run(service.restart_stuck_cloudiway_user(uid))

    assert cloud.started == [[427]]
    assert result["started"] is True
    assert result["confirmed"] is True
    assert result["confirmed_running"] is True
    assert result["state"] == "migrating"

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["migration_status"] == "migrating"
    assert row["cloudiway_status"] == "migrating"


def test_manual_start_does_not_claim_running_when_cloudiway_stays_notstarted(monkeypatch):
    from app import service

    class Cloud:
        def __init__(self):
            self.started = []

        async def job_status(self, object_id):
            return {"isSuccess": True, "responseData": {"status": "NotStarted"}, "error": []}

        async def progress(self, object_id, since_minutes):
            return {
                "isSuccess": True,
                "responseData": {
                    "blockId": object_id,
                    "migratedEmails": 0,
                    "errorEmails": 0,
                    "ignoredEmails": 0,
                    "totalEmails": 0,
                    "startDateTime": None,
                    "lastActivityDateTime": None,
                    "error": [],
                },
                "error": [],
            }

        async def start_migration(self, object_ids):
            self.started.append(list(object_ids))
            return {"isSuccess": True, "message": "StartJobs done", "error": []}

    cloud = Cloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)

    # Avoid slowing the unit test while preserving the verification loop.
    async def no_sleep(seconds):
        return None
    monkeypatch.setattr(service.asyncio, "sleep", no_sleep)

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,cloudiway_object_id,cloudiway_status,migration_status
               ) VALUES(?,?,?,?,?)""",
            ("still.stuck@jcf.gov.jm","still.stuck@jcf.gov.jm",429,"not_started","ready"),
        )
        uid = int(db.execute(
            "SELECT id FROM users WHERE source_email='still.stuck@jcf.gov.jm'"
        ).fetchone()["id"])

    import asyncio
    result = asyncio.run(service.restart_stuck_cloudiway_user(uid))

    assert cloud.started == [[429]]
    assert result["started"] is True
    assert result["confirmed"] is False
    assert result["confirmed_running"] is False
    assert result["state"] == "not_started"

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    assert row["migration_status"] == "starting"
    assert row["cloudiway_status"] == "manual_start_requested"
