import base64
import httpx
import respx
import pytest

from app.clients.rackspace import RackspaceClient
from app.config import settings


def test_signature_shape():
    client = RackspaceClient("userkey", "secretkey", "12345")
    headers = client._headers()
    assert headers["User-Agent"] == client.USER_AGENT
    parts = headers["X-Api-Signature"].split(":")
    assert parts[0] == "userkey"
    assert len(parts[1]) == 14
    assert len(base64.b64decode(parts[2])) == 20


def test_mailbox_url():
    client = RackspaceClient("u", "s", "12345")
    assert client._mailbox_url("john@example.com").endswith(
        "/customers/12345/domains/example.com/rs/mailboxes/john"
    )


@pytest.mark.asyncio
@respx.mock
async def test_username_password_identity_authentication():
    route = respx.post(RackspaceClient.IDENTITY_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access": {
                    "token": {
                        "id": "token-123",
                        "expires": "2030-01-01T00:00:00Z",
                        "tenant": {"id": "tenant-1"},
                    },
                    "serviceCatalog": [],
                }
            },
        )
    )
    client = RackspaceClient(
        auth_mode="username_password",
        username="adminuser",
        password="secretpass",
    )
    result = await client.authenticate_identity()
    assert route.called
    assert result["ok"] is True
    assert client.identity_token == "token-123"


@pytest.mark.asyncio
@respx.mock
async def test_username_password_capability_test_reports_email_api_rejection():
    respx.post(RackspaceClient.IDENTITY_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access": {
                    "token": {"id": "token-123", "expires": "2030-01-01T00:00:00Z"},
                    "serviceCatalog": [],
                }
            },
        )
    )
    respx.get(
        f"{settings.rackspace_base_url}/customers/12345/domains"
    ).mock(return_value=httpx.Response(403, text="Forbidden"))

    client = RackspaceClient(
        customer_id="12345",
        auth_mode="username_password",
        username="adminuser",
        password="secretpass",
    )
    result = await client.test_connection()
    assert result["identity_authenticated"] is True
    assert result["mailbox_admin_verified"] is False
    assert "API User Key/Secret Key" in result["message"]


@pytest.mark.asyncio
@respx.mock
async def test_username_password_capability_test_can_verify_mailbox_admin():
    respx.post(RackspaceClient.IDENTITY_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access": {
                    "token": {"id": "token-123", "expires": "2030-01-01T00:00:00Z"},
                    "serviceCatalog": [],
                }
            },
        )
    )
    route = respx.get(
        "https://api.emailsrvr.com/v1/customers/12345/domains"
    ).mock(return_value=httpx.Response(200, json={"domains": []}))

    client = RackspaceClient(
        customer_id="12345",
        auth_mode="username_password",
        username="adminuser",
        password="secretpass",
    )
    result = await client.test_connection()
    assert route.called
    assert route.calls[0].request.headers["X-Auth-Token"] == "token-123"
    assert result["mailbox_admin_verified"] is True
