import httpx


class SyncAgentClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = (base_url or "").rstrip("/")
        self.token = token or ""

    async def _request(self, method: str, path: str):
        if not self.base_url:
            raise RuntimeError("Sync agent URL is not configured")
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.request(method, self.base_url + path, headers=headers)
        if response.status_code >= 400:
            raise RuntimeError(
                f"Sync agent {method} {path} failed ({response.status_code}): {response.text[:500]}"
            )
        try:
            return response.json()
        except Exception:
            return {"ok": True, "text": response.text[:500]}

    async def test_connection(self) -> dict:
        data = await self._request("GET", "/health")
        return {"ok": True, "response": data}

    async def trigger_delta_sync(self) -> dict:
        return await self._request("POST", "/sync/delta")
