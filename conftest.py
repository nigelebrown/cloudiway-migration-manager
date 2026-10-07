import os
from starlette.testclient import TestClient

os.environ.setdefault("APP_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("APP_ENCRYPTION_KEY", "test-encryption-secret")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("SESSION_HTTPS_ONLY", "true")

_original_init = TestClient.__init__

def _https_init(self, *args, **kwargs):
    if "base_url" not in kwargs:
        kwargs["base_url"] = "https://testserver"
    return _original_init(self, *args, **kwargs)

TestClient.__init__ = _https_init


def pytest_runtest_setup(item):
    # Isolate the in-memory login limiter between tests while production keeps
    # the limiter across requests.
    try:
        from app.main import _login_attempts
        _login_attempts.clear()
    except Exception:
        pass
