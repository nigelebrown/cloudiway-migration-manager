import base64
from app.clients.rackspace import RackspaceClient

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
    assert client._mailbox_url("john@example.com").endswith("/customers/12345/domains/example.com/rs/mailboxes/john")
