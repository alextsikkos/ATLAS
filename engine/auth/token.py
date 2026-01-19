# engine/auth/token.py
import time
from msal import ConfidentialClientApplication

GRAPH_SCOPE = ["https://graph.microsoft.com/.default"]

def get_access_token(tenant: dict) -> str:
    # Simple per-run token cache stored on the tenant dict.
    # No external state, no redesign, fully backwards compatible.
    cached = tenant.get("_atlas_graph_token")
    expires_at = tenant.get("_atlas_graph_token_expires_at", 0)

    # Refresh ~60s early to avoid edge-of-expiry failures.
    if cached and time.time() < (expires_at - 60):
        return cached

    tenant_id = tenant["auth"]["tenant_id"]
    client_id = tenant["auth"]["client_id"]
    client_secret = tenant["auth"]["client_secret"]

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )

    token = app.acquire_token_for_client(scopes=GRAPH_SCOPE)
    if "access_token" not in token:
        raise RuntimeError(f"Token error: {token}")

    access_token = token["access_token"]
    expires_in = int(token.get("expires_in", 3599))

    tenant["_atlas_graph_token"] = access_token
    tenant["_atlas_graph_token_expires_at"] = time.time() + expires_in

    return access_token

def graph_headers(tenant: dict) -> dict:
    return {
        "Authorization": f"Bearer {get_access_token(tenant)}",
        "Content-Type": "application/json"
    }
