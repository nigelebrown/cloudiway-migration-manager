import os

os.environ.setdefault("APP_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("APP_ENCRYPTION_KEY", "test-encryption-secret")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "3306")
os.environ.setdefault("DB_NAME", "cloudiway_test")
os.environ.setdefault("DB_USER", "cloudiway")
os.environ.setdefault("DB_PASSWORD", "testpass")
os.environ.setdefault("CLOUDIWAY_BASE_URL", "https://example.invalid/ap1")
os.environ.setdefault("RACKSPACE_BASE_URL", "https://example.invalid/v1")
