import base64, hashlib, secrets, string
from cryptography.fernet import Fernet
from app.config import settings

def _fernet() -> Fernet:
    raw = settings.app_encryption_key.strip()
    if not raw:
        raise RuntimeError("APP_ENCRYPTION_KEY is required")
    try:
        return Fernet(raw.encode())
    except Exception:
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))

def encrypt_secret(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()

def decrypt_secret(value: str | None) -> str | None:
    return _fernet().decrypt(value.encode()).decode() if value else None

def generate_password(length: int = 18) -> str:
    specials = "!@#$%*-_"
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(specials),
    ]
    alphabet = string.ascii_letters + string.digits + specials
    chars.extend(secrets.choice(alphabet) for _ in range(max(0, length-4)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
