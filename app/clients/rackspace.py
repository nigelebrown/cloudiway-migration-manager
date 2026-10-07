import base64
import hashlib
from datetime import datetime, timezone
import httpx
from app.config import settings


class RackspaceClient:
    USER_AGENT = "JCF-Cloudiway-Migration-Manager/1.0"

    def __init__(self, user_key: str, secret_key: str, customer_id: str):
        self.user_key = user_key.strip()
        self.secret_key = secret_key.strip()
        self.customer_id = customer_id.strip()

    def _headers(self) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        to_sign = f"{self.user_key}{self.USER_AGENT}{timestamp}{self.secret_key}".encode()
        digest = hashlib.sha1(to_sign).digest()
        signature = base64.b64encode(digest).decode()
        return {
            "User-Agent": self.USER_AGENT,
            "X-Api-Signature": f"{self.user_key}:{timestamp}:{signature}",
            "Accept": "application/json",
        }

    def _mailbox_url(self, email: str) -> str:
        mailbox, domain = email.split("@", 1)
        return (
            f"{settings.rackspace_base_url}/customers/{self.customer_id}"
            f"/domains/{domain}/rs/mailboxes/{mailbox}"
        )

    async def test_connection(self) -> dict:
        url = f"{settings.rackspace_base_url}/customers/{self.customer_id}/domains"
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url, headers=self._headers())
        if r.status_code >= 400:
            raise RuntimeError(self._error("Rackspace connection test failed", r))
        try:
            return r.json()
        except Exception:
            return {"status": "ok", "body": r.text[:500]}

    async def get_mailbox(self, email: str) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(self._mailbox_url(email), headers=self._headers())
        if r.status_code >= 400:
            raise RuntimeError(self._error(f"Rackspace mailbox lookup failed for {email}", r))
        return r.json() if r.content else {}

    async def reset_password(self, email: str, new_password: str) -> None:
        headers = self._headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        async with httpx.AsyncClient(timeout=45) as client:
            r = await client.put(
                self._mailbox_url(email),
                headers=headers,
                data={"password": new_password},
            )
        if r.status_code not in (200, 202, 204):
            raise RuntimeError(self._error(f"Rackspace password reset failed for {email}", r))

    @staticmethod
    def _error(prefix: str, response: httpx.Response) -> str:
        detail = response.headers.get("x-error-message") or response.text[:800]
        return f"{prefix} ({response.status_code}): {detail}"
