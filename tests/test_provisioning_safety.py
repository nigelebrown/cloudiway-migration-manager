import pytest
from fastapi.testclient import TestClient

from app.db import conn, init_db, reset_test_data
from app.main import app
from app.security import decrypt_secret


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


def profile_form(name="JCF TEST", environment_type="TEST"):
    return {
        "profile_id": "0",
        "name": name,
        "environment_type": environment_type,
        "production_max_batch": "25",
        "ad_host": "dc01.test.local",
        "ad_port": "636",
        "ad_use_ssl": "1",
        "ad_tls_validate": "1",
        "ad_ca_cert_path": "/etc/ssl/certs/jcf-root-ca.pem",
        "ad_base_dn": "DC=test,DC=local",
        "ad_bind_username": "TEST\\svc_migration",
        "ad_bind_password": "BindPassword123!",
        "ad_target_ou": "OU=M365-Migration,DC=test,DC=local",
        "ad_license_group_dn": "CN=JCF-M365-E3,OU=Groups,DC=test,DC=local",
        "ad_computer_number_attribute": "extensionAttribute7",
        "ad_upn_suffix": "jcf.gov.jm",
        "ad_default_password": "TemporaryAD123!",
        "ad_force_password_change": "1",
        "ad_allow_user_creation": "1",
        "ad_allow_group_changes": "1",
        "graph_tenant_id": "tenant",
        "graph_client_id": "client",
        "graph_client_secret": "GraphSecret123!",
        "graph_required_sku": "SPE_E3",
        "sync_agent_url": "https://sync.test.local",
        "sync_agent_token": "SyncToken123!",
        "sql_host": "sql.test.local",
        "sql_port": "1433",
        "sql_database": "HRIS",
        "sql_username": "migration_reader",
        "sql_password": "SqlReadOnly123!",
        "sql_source_view": "dbo.vw_M365MigrationIdentity",
        "vpn_profile_name": "JCF-TEST-VPN",
        "network_notes": "Test network only",
    }


def test_profile_secrets_are_encrypted_at_rest():
    with TestClient(app) as client:
        login(client)
        r = client.post(
            "/settings/provisioning/save",
            data=profile_form(),
            follow_redirects=False,
        )
        assert r.status_code == 303

    with conn() as db:
        row = db.execute("SELECT * FROM environment_profiles").fetchone()

    assert row["ad_bind_password_enc"] != "BindPassword123!"
    assert row["ad_default_password_enc"] != "TemporaryAD123!"
    assert row["graph_client_secret_enc"] != "GraphSecret123!"
    assert row["sync_agent_token_enc"] != "SyncToken123!"
    assert row["sql_password_enc"] != "SqlReadOnly123!"
    assert decrypt_secret(row["ad_bind_password_enc"]) == "BindPassword123!"
    assert decrypt_secret(row["ad_default_password_enc"]) == "TemporaryAD123!"
    assert row["ad_tls_validate"] == 1
    assert row["ad_ca_cert_path"] == "/etc/ssl/certs/jcf-root-ca.pem"


def test_production_activation_and_write_enable_require_confirmations():
    with TestClient(app) as client:
        login(client)
        client.post(
            "/settings/provisioning/save",
            data=profile_form("JCF PRODUCTION", "PRODUCTION"),
            follow_redirects=False,
        )
        with conn() as db:
            pid = db.execute("SELECT id FROM environment_profiles").fetchone()["id"]

        client.post(
            f"/settings/provisioning/{pid}/activate",
            data={"confirmation": "wrong"},
            follow_redirects=False,
        )
        with conn() as db:
            assert db.execute(
                "SELECT is_active FROM environment_profiles WHERE id=?", (pid,)
            ).fetchone()["is_active"] == 0

        client.post(
            f"/settings/provisioning/{pid}/activate",
            data={"confirmation": "PRODUCTION"},
            follow_redirects=False,
        )
        with conn() as db:
            state = db.execute(
                "SELECT is_active,writes_enabled FROM environment_profiles WHERE id=?", (pid,)
            ).fetchone()
        assert state["is_active"] == 1
        assert state["writes_enabled"] == 0

        client.post(
            f"/settings/provisioning/{pid}/writes",
            data={"enable": "1", "confirmation": "wrong"},
            follow_redirects=False,
        )
        with conn() as db:
            assert db.execute(
                "SELECT writes_enabled FROM environment_profiles WHERE id=?", (pid,)
            ).fetchone()["writes_enabled"] == 0

        client.post(
            f"/settings/provisioning/{pid}/writes",
            data={"enable": "1", "confirmation": "ENABLE PRODUCTION WRITES"},
            follow_redirects=False,
        )
        with conn() as db:
            assert db.execute(
                "SELECT writes_enabled FROM environment_profiles WHERE id=?", (pid,)
            ).fetchone()["writes_enabled"] == 1


def test_emergency_stop_disables_writes_and_requires_explicit_clear():
    with TestClient(app) as client:
        login(client)
        client.post(
            "/settings/provisioning/save",
            data=profile_form(),
            follow_redirects=False,
        )
        with conn() as db:
            pid = db.execute("SELECT id FROM environment_profiles").fetchone()["id"]
            db.execute(
                "UPDATE environment_profiles SET is_active=1,writes_enabled=1 WHERE id=?",
                (pid,),
            )

        client.post(
            f"/settings/provisioning/{pid}/emergency-stop",
            follow_redirects=False,
        )
        with conn() as db:
            state = db.execute(
                "SELECT emergency_stop,writes_enabled FROM environment_profiles WHERE id=?",
                (pid,),
            ).fetchone()
        assert state["emergency_stop"] == 1
        assert state["writes_enabled"] == 0

        client.post(
            f"/settings/provisioning/{pid}/clear-stop",
            data={"confirmation": "wrong"},
            follow_redirects=False,
        )
        with conn() as db:
            assert db.execute(
                "SELECT emergency_stop FROM environment_profiles WHERE id=?", (pid,)
            ).fetchone()["emergency_stop"] == 1

        client.post(
            f"/settings/provisioning/{pid}/clear-stop",
            data={"confirmation": "CLEAR STOP"},
            follow_redirects=False,
        )
        with conn() as db:
            state = db.execute(
                "SELECT emergency_stop,writes_enabled FROM environment_profiles WHERE id=?",
                (pid,),
            ).fetchone()
        assert state["emergency_stop"] == 0
        assert state["writes_enabled"] == 0
