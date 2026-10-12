import pytest
from app.clients.cloudiway import CloudiwayClient

def test_bearer_header():
    c = CloudiwayClient(token="abc", project_header="JCF")
    h = c._headers()
    assert h["Authorization"] == "Bearer abc"
    assert h["projectId"] == "JCF"

def test_extract_self_service_token():
    assert CloudiwayClient._extract_token("abc") == "abc"
    assert CloudiwayClient._extract_token({"token": "abc"}) == "abc"
    assert CloudiwayClient._extract_token({"responseData": "abc"}) == "abc"
    assert CloudiwayClient._extract_token({"responseData": {"token": "abc"}}) == "abc"


@pytest.mark.asyncio
async def test_register_source_credentials_posts_exact_username_and_password(monkeypatch):
    client = CloudiwayClient(token="abc", project_header="JCF")
    captured = {}

    async def fake_post(path, payload, error):
        captured["path"] = path
        captured["payload"] = payload
        return {"ok": True}

    monkeypatch.setattr(client, "_post", fake_post)
    await client.register_source_credentials(
        "self-service-token",
        "member@jcf.gov.jm",
        "Exact#Password2026",
    )

    assert captured["path"] == "/MailSelfService/self-service-token"
    assert captured["payload"] == {
        "userName": "member@jcf.gov.jm",
        "password": "Exact#Password2026",
    }


@pytest.mark.asyncio
async def test_restart_existing_migration_uses_same_cloudiway_object(monkeypatch):
    from app.config import settings

    client = CloudiwayClient(token="abc", project_header="JCF")
    captured = {}

    async def fake_get(path, error, include_project=True):
        captured["path"] = path
        captured["error"] = error
        return {"ok": True}

    monkeypatch.setattr(client, "_get", fake_get)
    await client.restart_migration(45821)

    assert captured["path"] == f"/Jobs/Restart/45821/{settings.cloudiway_product_type_mail}"
    assert "restart existing" in captured["error"].lower()
