import time
import requests


class GraphClient:
    """
    Minimal Microsoft Graph helper:
    - Reads auth from tenant["auth"] OR directly from the dict you pass in
    - Caches token until expiry
    - Provides .headers and .get/.post
    """

    def __init__(self, tenant: dict):
        # Allow either:
        #   GraphClient(full_tenant_dict)   where auth lives under tenant["auth"]
        # or:
        #   GraphClient(tenant["auth"])     where tenant_id/client_id/client_secret are at top level
        self.tenant = tenant
        self.auth = tenant.get("auth", tenant)

        self.token = None
        self.token_expiry = 0  # epoch seconds

    def _get_token(self) -> str:
        now = int(time.time())

        # If we still have a token that isn't close to expiring, reuse it
        if self.token and now < (self.token_expiry - 60):
            return self.token

        tenant_id = self.auth.get("tenant_id")
        client_id = self.auth.get("client_id")
        client_secret = self.auth.get("client_secret")

        if not tenant_id or not client_id or not client_secret:
            raise ValueError(
                "Missing Graph auth fields. Expected auth.tenant_id / auth.client_id / auth.client_secret "
                "(or pass tenant['auth'] directly into GraphClient)."
            )

        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }

        resp = requests.post(url, data=data, timeout=30)
        resp.raise_for_status()
        payload = resp.json()

        self.token = payload.get("access_token")
        expires_in = int(payload.get("expires_in", 3600))
        self.token_expiry = now + expires_in

        if not self.token:
            raise RuntimeError(f"Token response did not contain access_token: {payload}")

        return self.token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @property
    def headers(self) -> dict:
        # Backwards-compatible with your existing main.py usage (graph.headers)
        return self._headers()

    def get(self, path: str, params: dict | None = None):
        if path.startswith("http"):
            url = path
        else:
            url = "https://graph.microsoft.com" + path

        resp = requests.get(url, headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()

        # Some Graph calls return 204 No Content
        if resp.status_code == 204 or not resp.text.strip():
            return None

        return resp.json()

    def post(self, path: str, json_body: dict | None = None):
        if path.startswith("http"):
            url = path
        else:
            url = "https://graph.microsoft.com" + path

        resp = requests.post(url, headers=self._headers(), json=json_body, timeout=30)
        resp.raise_for_status()

        if resp.status_code == 204 or not resp.text.strip():
            return None

        return resp.json()
