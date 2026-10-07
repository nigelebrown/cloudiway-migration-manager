import os
os.environ.setdefault("APP_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("APP_ENCRYPTION_KEY", "test-encryption-secret")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("DATABASE_PATH", "/tmp/cloudiway-test.db")
os.environ.setdefault("CLOUDIWAY_BASE_URL", "https://example.invalid/ap1")
os.environ.setdefault("RACKSPACE_BASE_URL", "https://example.invalid/v1")
