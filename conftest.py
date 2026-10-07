import os

# TestClient uses http://testserver, so disable Secure-cookie enforcement only
# during pytest. Production defaults remain HTTPS-only.
os.environ.setdefault("SESSION_HTTPS_ONLY", "false")
os.environ.setdefault("APP_ADMIN_PASSWORD", "test-admin")
os.environ.setdefault("APP_ENCRYPTION_KEY", "test-encryption-secret")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
