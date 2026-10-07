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
