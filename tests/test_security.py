from app.security import generate_password, encrypt_secret, decrypt_secret

def test_password_is_strong_and_recoverable():
    password = generate_password()
    assert len(password) >= 12
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    encrypted = encrypt_secret(password)
    assert encrypted != password
    assert decrypt_secret(encrypted) == password
