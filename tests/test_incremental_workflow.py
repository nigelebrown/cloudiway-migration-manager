import io
import zipfile

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from app.db import conn, init_db, reset_test_data, set_setting
from app.main import app
from app.security import encrypt_secret


@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    reset_test_data()
    yield


def _login(client):
    r = client.post(
        "/login",
        data={"admin_password": "test-admin-password"},
        follow_redirects=False,
    )
    assert r.status_code == 303


def _master_csv(count=1000):
    lines = ["source_email,target_email,first_name,last_name,computer_number"]
    for i in range(1, count + 1):
        lines.append(
            f"user{i:04d}@jcf.gov.jm,user{i:04d}@jcf.gov.jm,Test,User{i:04d},{10000+i}"
        )
    return ("\n".join(lines) + "\n").encode()


def _fake_cloud_batch_creator(main_module, monkeypatch):
    async def fake_ensure(migration_batch_id):
        cloud_id = 50000 + int(migration_batch_id)
        with conn() as db:
            db.execute(
                """UPDATE migration_batches
                   SET cloudiway_batch_id=?,cloudiway_batch_name=batch_name,last_error=NULL
                   WHERE id=?""",
                (cloud_id, migration_batch_id),
            )
        return cloud_id

    monkeypatch.setattr(main_module, "ensure_migration_cloudiway_batch", fake_ensure)


def test_1000_user_upload_stages_without_generating_passwords():
    with TestClient(app) as client:
        _login(client)
        r = client.post(
            "/upload",
            files={"file": ("1000-users.csv", _master_csv(1000), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        assert r.status_code == 303

    with conn() as db:
        batch = db.execute("SELECT * FROM upload_batches").fetchone()
        assert batch["imported_rows"] == 1000
        assert batch["workflow_status"] == "staged"
        member_count = db.execute(
            "SELECT COUNT(*) c FROM upload_batch_members WHERE upload_batch_id=?",
            (batch["id"],),
        ).fetchone()["c"]
        assert member_count == 1000
        generated = db.execute(
            "SELECT COUNT(*) c FROM users WHERE generated_password_enc IS NOT NULL"
        ).fetchone()["c"]
        assert generated == 0


def test_choose_20_generates_only_20_and_creates_cloudiway_batch(monkeypatch):
    from app import main as main_module

    _fake_cloud_batch_creator(main_module, monkeypatch)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)

    with TestClient(app) as client:
        _login(client)
        client.post(
            "/upload",
            files={"file": ("1000-users.csv", _master_csv(1000), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        r = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "20"},
        )
        assert r.status_code == 200
        assert "application/zip" in r.headers["content-type"]

        zf = zipfile.ZipFile(io.BytesIO(r.content))
        csv_name = next(n for n in zf.namelist() if n.endswith("rackspace-password-update.csv"))
        password_map_name = next(n for n in zf.namelist() if n.endswith("migration-password-map.xlsx"))
        rackspace_df = pd.read_csv(io.BytesIO(zf.read(csv_name)))
        password_map = pd.read_excel(io.BytesIO(zf.read(password_map_name)))
        assert len(rackspace_df) == 20
        assert len(password_map) == 20
        assert list(password_map.columns)[:7] == [
            "email",
            "password",
            "source_email",
            "target_email",
            "first_name",
            "last_name",
            "computer_number",
        ]

    with conn() as db:
        mb = db.execute("SELECT * FROM migration_batches").fetchone()
        assert mb["selected_count"] == 20
        assert mb["cloudiway_batch_id"] == 50000 + mb["id"]
        selected = db.execute(
            "SELECT COUNT(*) c FROM migration_batch_members WHERE migration_batch_id=?",
            (mb["id"],),
        ).fetchone()["c"]
        assert selected == 20
        generated = db.execute(
            "SELECT COUNT(*) c FROM users WHERE generated_password_enc IS NOT NULL"
        ).fetchone()["c"]
        assert generated == 20
        remaining = db.execute(
            """SELECT COUNT(*) c
               FROM upload_batch_members ubm
               WHERE ubm.upload_batch_id=?
                 AND NOT EXISTS (
                     SELECT 1 FROM migration_batch_members mbm
                     JOIN migration_batches mb ON mb.id=mbm.migration_batch_id
                     WHERE mb.upload_batch_id=? AND mbm.user_id=ubm.user_id
                 )""",
            (upload_id, upload_id),
        ).fetchone()["c"]
        assert remaining == 980


def test_incremental_20_then_30_has_no_overlap(monkeypatch):
    from app import main as main_module

    _fake_cloud_batch_creator(main_module, monkeypatch)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)

    with TestClient(app) as client:
        _login(client)
        client.post(
            "/upload",
            files={"file": ("users.csv", _master_csv(100), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        r1 = client.post(f"/workflow/{upload_id}/generate", data={"quantity": "20"})
        assert r1.status_code == 200
        r2 = client.post(f"/workflow/{upload_id}/generate", data={"quantity": "30"})
        assert r2.status_code == 200

    with conn() as db:
        batches = db.execute(
            "SELECT id,sequence_number,selected_count FROM migration_batches ORDER BY sequence_number"
        ).fetchall()
        assert [b["selected_count"] for b in batches] == [20, 30]
        ids1 = {
            r["user_id"]
            for r in db.execute(
                "SELECT user_id FROM migration_batch_members WHERE migration_batch_id=?",
                (batches[0]["id"],),
            ).fetchall()
        }
        ids2 = {
            r["user_id"]
            for r in db.execute(
                "SELECT user_id FROM migration_batch_members WHERE migration_batch_id=?",
                (batches[1]["id"],),
            ).fetchall()
        }
        assert ids1.isdisjoint(ids2)
        assert len(ids1 | ids2) == 50
        generated = db.execute(
            "SELECT COUNT(*) c FROM users WHERE generated_password_enc IS NOT NULL"
        ).fetchone()["c"]
        assert generated == 50


def test_exact_user_selection_overrides_quantity(monkeypatch):
    from app import main as main_module

    _fake_cloud_batch_creator(main_module, monkeypatch)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)

    with TestClient(app) as client:
        _login(client)
        client.post(
            "/upload",
            files={"file": ("users.csv", _master_csv(25), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]
            rows = db.execute(
                """SELECT u.id FROM upload_batch_members ubm
                   JOIN users u ON u.id=ubm.user_id
                   WHERE ubm.upload_batch_id=? ORDER BY ubm.row_order""",
                (upload_id,),
            ).fetchall()
            chosen = [rows[2]["id"], rows[7]["id"], rows[19]["id"]]

        r = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "20", "user_ids": [str(x) for x in chosen]},
        )
        assert r.status_code == 200

    with conn() as db:
        mb = db.execute("SELECT id,selected_count FROM migration_batches").fetchone()
        assert mb["selected_count"] == 3
        actual = {
            r["user_id"]
            for r in db.execute(
                "SELECT user_id FROM migration_batch_members WHERE migration_batch_id=?",
                (mb["id"],),
            ).fetchall()
        }
        assert actual == set(chosen)


def test_download_reupload_confirm_prepare_and_start(monkeypatch):
    from app import main as main_module

    _fake_cloud_batch_creator(main_module, monkeypatch)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)

    async def fake_prepare(migration_batch_id):
        with conn() as db:
            mb = db.execute(
                "SELECT cloudiway_batch_id FROM migration_batches WHERE id=?",
                (migration_batch_id,),
            ).fetchone()
            count = db.execute(
                "SELECT COUNT(*) c FROM migration_batch_members WHERE migration_batch_id=?",
                (migration_batch_id,),
            ).fetchone()["c"]
            db.execute(
                "UPDATE migration_batches SET workflow_status='ready_to_migrate' WHERE id=?",
                (migration_batch_id,),
            )
        return {
            "ready": True,
            "users": count,
            "cloudiway_batch_id": mb["cloudiway_batch_id"],
            "object_ids": list(range(1, count + 1)),
        }

    async def fake_start(migration_batch_id):
        with conn() as db:
            mb = db.execute(
                "SELECT cloudiway_batch_id FROM migration_batches WHERE id=?",
                (migration_batch_id,),
            ).fetchone()
            ids = [
                r["user_id"]
                for r in db.execute(
                    "SELECT user_id FROM migration_batch_members WHERE migration_batch_id=?",
                    (migration_batch_id,),
                ).fetchall()
            ]
            placeholders = ",".join("?" for _ in ids)
            db.execute(
                f"UPDATE users SET migration_status='migrating' WHERE id IN ({placeholders})",
                tuple(ids),
            )
            db.execute(
                "UPDATE migration_batches SET workflow_status='migrating' WHERE id=?",
                (migration_batch_id,),
            )
        return {
            "started": True,
            "users_started": len(ids),
            "cloudiway_batch_id": mb["cloudiway_batch_id"],
        }

    monkeypatch.setattr(main_module, "prepare_migration_batch", fake_prepare)
    monkeypatch.setattr(main_module, "start_migration_batch", fake_start)

    with TestClient(app) as client:
        _login(client)
        client.post(
            "/upload",
            files={"file": ("users.csv", _master_csv(20), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        package = client.post(
            f"/workflow/{upload_id}/generate",
            data={"quantity": "20"},
        )
        assert package.status_code == 200
        zf = zipfile.ZipFile(io.BytesIO(package.content))
        rackspace_name = next(n for n in zf.namelist() if n.endswith("rackspace-password-update.csv"))
        rackspace_csv = zf.read(rackspace_name)

        with conn() as db:
            mb = db.execute("SELECT * FROM migration_batches").fetchone()
            migration_batch_id = mb["id"]
            assert mb["cloudiway_batch_id"] is not None

        confirm = client.post(
            f"/migration-batch/{migration_batch_id}/confirm",
            files={"file": ("rackspace-confirm.csv", rackspace_csv, "text/csv")},
            follow_redirects=False,
        )
        assert confirm.status_code == 303

        with conn() as db:
            confirmed = db.execute(
                """SELECT COUNT(*) c FROM migration_batch_members mbm
                   JOIN users u ON u.id=mbm.user_id
                   WHERE mbm.migration_batch_id=? AND u.rackspace_status='manual_confirmed'""",
                (migration_batch_id,),
            ).fetchone()["c"]
            state = db.execute(
                "SELECT workflow_status FROM migration_batches WHERE id=?",
                (migration_batch_id,),
            ).fetchone()["workflow_status"]
        assert confirmed == 20
        assert state == "ready_to_migrate"

        start = client.post(
            f"/migration-batch/{migration_batch_id}/start",
            follow_redirects=False,
        )
        assert start.status_code == 303

    with conn() as db:
        state = db.execute(
            "SELECT workflow_status FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()["workflow_status"]
        migrating = db.execute(
            """SELECT COUNT(*) c FROM migration_batch_members mbm
               JOIN users u ON u.id=mbm.user_id
               WHERE mbm.migration_batch_id=? AND u.migration_status='migrating'""",
            (migration_batch_id,),
        ).fetchone()["c"]
        assert state == "migrating"
        assert migrating == 20


@pytest.mark.asyncio
async def test_cloudiway_batch_api_is_used_for_each_migration_batch(monkeypatch):
    from app import service

    with conn() as db:
        u = db.execute(
            """INSERT INTO upload_batches(
                   batch_name,workflow_mode,workflow_status,total_rows,imported_rows
               ) VALUES(?,?,?,?,?)""",
            ("JCF-TEST-U00001", "manual_bulk", "staged", 2, 2),
        )
        upload_id = u.lastrowid
        m = db.execute(
            """INSERT INTO migration_batches(
                   upload_batch_id,sequence_number,batch_name,workflow_status,selected_count
               ) VALUES(?,?,?,?,?)""",
            (upload_id, 1, "JCF-TEST-U00001-B001", "passwords_generated", 2),
        )
        migration_batch_id = m.lastrowid

    calls = {"create": 0}

    class FakeCloud:
        async def create_mail_batch(self, name):
            calls["create"] += 1
            assert name == "JCF-TEST-U00001-B001"
            return {"id": 88001, "name": name}

        async def mail_batches(self):
            return []

    async def fake_ready():
        return FakeCloud()

    monkeypatch.setattr(service, "_cloudiway_client_ready", fake_ready)
    cloud_id = await service.ensure_migration_cloudiway_batch(migration_batch_id)
    assert cloud_id == 88001
    assert calls["create"] == 1

    with conn() as db:
        row = db.execute(
            "SELECT cloudiway_batch_id FROM migration_batches WHERE id=?",
            (migration_batch_id,),
        ).fetchone()
        assert row["cloudiway_batch_id"] == 88001


def test_workflow_page_shows_quantity_selection_and_remaining_users(monkeypatch):
    from app import main as main_module

    _fake_cloud_batch_creator(main_module, monkeypatch)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)

    with TestClient(app) as client:
        _login(client)
        client.post(
            "/upload",
            files={"file": ("users.csv", _master_csv(40), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        page = client.get(f"/workflow/{upload_id}")
        assert page.status_code == 200
        assert "Next quantity" in page.text
        assert "40" in page.text
        assert "Generate Passwords, Create Cloudiway Batch &amp; Download" in page.text or "Generate Passwords, Create Cloudiway Batch & Download" in page.text

        client.post(f"/workflow/{upload_id}/generate", data={"quantity": "20"})
        page2 = client.get(f"/workflow/{upload_id}")
        assert page2.status_code == 200
        assert "20" in page2.text
        assert "Cloudiway Batch" in page2.text
        assert "B001" in page2.text


def test_dashboard_exposes_migration_batch_name_and_cloudiway_batch(monkeypatch):
    from app import main as main_module

    _fake_cloud_batch_creator(main_module, monkeypatch)
    set_setting("cloudiway_token", encrypt_secret("test-token"), True)

    with TestClient(app) as client:
        _login(client)
        client.post(
            "/upload",
            files={"file": ("users.csv", _master_csv(5), "text/csv")},
            data={"workflow_mode": "manual_bulk"},
            follow_redirects=False,
        )
        with conn() as db:
            upload_id = db.execute("SELECT id FROM upload_batches").fetchone()["id"]

        client.post(f"/workflow/{upload_id}/generate", data={"quantity": "5"})
        api = client.get("/api/dashboard")
        assert api.status_code == 200
        users = api.json()["users"]
        batched = [u for u in users if u.get("migration_batch_name")]
        assert len(batched) == 5
        assert all(u["cloudiway_batch_id"] for u in batched)
        assert all("-B001" in u["migration_batch_name"] for u in batched)
