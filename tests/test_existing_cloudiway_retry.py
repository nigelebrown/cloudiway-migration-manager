import pytest

from app import service
from app.db import conn, init_db, reset_test_data, set_setting
from app.security import encrypt_secret


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    reset_test_data()
    yield


class ExistingFailedCloud:
    def __init__(self):
        self.created = 0
        self.credentials = []
        self.restarted = []
        self.started = []

    async def verify_mail_user(self, email):
        assert email == "member@jcf.gov.jm"
        return {"id": 45821}

    async def get_mail_user(self, object_id):
        assert object_id == 45821
        return {
            "id": 45821,
            "sourceEmail": "member@jcf.gov.jm",
            "targetEmail": "member@jcf.gov.jm",
        }

    async def create_mail_user(self, payload):
        self.created += 1
        raise AssertionError("Existing Cloudiway user must not be duplicated")

    async def progress(self, object_id, since_minutes=1):
        assert object_id == 45821
        return {"status": "Failed", "percentage": 3}

    async def get_self_service_token(self, object_id):
        assert object_id == 45821
        return "existing-object-token"

    async def register_source_credentials(self, token, username, password):
        self.credentials.append((token, username, password))
        return {}

    async def restart_migration(self, object_id):
        self.restarted.append(object_id)
        return {"ok": True}

    async def start_migration(self, object_ids):
        self.started.append(list(object_ids))
        return {}


@pytest.mark.asyncio
async def test_failed_existing_cloudiway_user_gets_password_repush_and_same_object_restart(monkeypatch):
    cloud = ExistingFailedCloud()

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("token"), True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,first_name,last_name,
                   password_reset_method,source_credential_username,
                   source_credential_password_enc,source_credential_origin,
                   rackspace_status,cloudiway_status,cloudiway_object_id,
                   migration_status
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "member@jcf.gov.jm",
                "member@jcf.gov.jm",
                "Test",
                "Member",
                "existing_password",
                "member@jcf.gov.jm",
                encrypt_secret("FreshPassword#2026"),
                "uploaded_excel",
                "existing_password",
                "failed",
                45821,
                "failed",
            ),
        )
        user_id = int(
            db.execute(
                "SELECT id FROM users WHERE source_email='member@jcf.gov.jm'"
            ).fetchone()["id"]
        )

        up = db.execute(
            """INSERT INTO upload_batches(
                   batch_name,workflow_mode,workflow_status,total_rows,imported_rows
               ) VALUES(?,?,?,?,?)""",
            ("DIRECT-U00001", "existing_password", "staged", 1, 1),
        )
        upload_id = int(up.lastrowid)
        mb = db.execute(
            """INSERT INTO migration_batches(
                   upload_batch_id,sequence_number,batch_name,workflow_status,
                   cloudiway_batch_id,selected_count
               ) VALUES(?,?,?,?,?,?)""",
            (upload_id, 1, "DIRECT-U00001-B001", "selected", 88001, 1),
        )
        migration_batch_id = int(mb.lastrowid)
        db.execute(
            "INSERT INTO migration_batch_members(migration_batch_id,user_id) VALUES(?,?)",
            (migration_batch_id, user_id),
        )

    oid = await service.prepare_existing_password_user(user_id)
    assert oid == 45821
    assert cloud.created == 0
    assert cloud.credentials == [
        ("existing-object-token", "member@jcf.gov.jm", "FreshPassword#2026")
    ]

    with conn() as db:
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        assert row["cloudiway_object_id"] == 45821
        assert row["cloudiway_status"] == "restart_required"
        db.execute(
            "UPDATE migration_batches SET workflow_status='ready_to_migrate' WHERE id=?",
            (migration_batch_id,),
        )

    result = await service.start_migration_batch(migration_batch_id)
    assert result["users_restarted"] == 1
    assert result["users_started"] == 0
    assert cloud.restarted == [45821]
    assert cloud.started == []
    assert cloud.created == 0


@pytest.mark.asyncio
async def test_running_existing_cloudiway_user_is_not_restarted_or_duplicated(monkeypatch):
    cloud = ExistingFailedCloud()

    async def running_progress(object_id, since_minutes=1):
        return {"status": "Migrating", "percentage": 42}

    cloud.progress = running_progress

    async def ready():
        return cloud

    monkeypatch.setattr(service, "_cloudiway_client_ready", ready)
    set_setting("cloudiway_token", encrypt_secret("token"), True)
    set_setting("cloudiway_source_pool_id", "4")
    set_setting("cloudiway_target_pool_id", "3")

    with conn() as db:
        db.execute(
            """INSERT INTO users(
                   source_email,target_email,password_reset_method,
                   source_credential_username,source_credential_password_enc,
                   source_credential_origin,cloudiway_object_id,
                   cloudiway_status,migration_status
               ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "member@jcf.gov.jm",
                "member@jcf.gov.jm",
                "existing_password",
                "member@jcf.gov.jm",
                encrypt_secret("FreshPassword#2026"),
                "uploaded_excel",
                45821,
                "existing",
                "attention",
            ),
        )
        user_id = int(db.execute(
            "SELECT id FROM users WHERE source_email='member@jcf.gov.jm'"
        ).fetchone()["id"])

    oid = await service.prepare_existing_password_user(user_id)
    assert oid == 45821
    assert cloud.created == 0
    assert cloud.restarted == []
    with conn() as db:
        row = db.execute("SELECT cloudiway_status,migration_status FROM users WHERE id=?", (user_id,)).fetchone()
        assert row["cloudiway_status"] == "existing_migrating"
        assert row["migration_status"] == "migrating"
