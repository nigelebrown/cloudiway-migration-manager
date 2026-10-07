import os
import inspect
from starlette.testclient import TestClient

os.environ.setdefault("APP_ADMIN_PASSWORD", "test-admin")
os.environ.setdefault("APP_ENCRYPTION_KEY", "test-encryption-secret")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("SESSION_HTTPS_ONLY", "true")

# Production uses Secure session cookies. Make pytest's default TestClient use
# HTTPS so secure-cookie behavior is exercised instead of disabled.
_original_init = TestClient.__init__
_signature = inspect.signature(_original_init)

def _https_init(self, *args, **kwargs):
    if "base_url" not in kwargs:
        kwargs["base_url"] = "https://testserver"
    return _original_init(self, *args, **kwargs)

TestClient.__init__ = _https_init
