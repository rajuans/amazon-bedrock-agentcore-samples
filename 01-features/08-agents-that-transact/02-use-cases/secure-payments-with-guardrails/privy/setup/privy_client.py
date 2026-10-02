"""Minimal Privy REST client shared by the setup, demo, and probe scripts.

Auth: HTTP Basic (app id : app secret) plus the `privy-app-id` header, as in
Privy's API reference. Requests that act on an owned resource (for example,
updating a wallet that has an `owner_id`, or calling a wallet's RPC endpoint as
a signer) also need a `privy-authorization-signature`: an ECDSA P-256 / SHA-256
signature over the RFC 8785-canonicalized request, made with the authorization
private key (the same key AgentCore uses to sign payments).

Docs:
  https://docs.privy.io/api-reference
  https://docs.privy.io/controls/authorization-keys/using-owners/sign/direct-implementation
"""

import base64
import json
import os

import requests

PRIVY_BASE = os.environ.get("PRIVY_API_BASE", "https://api.privy.io").rstrip("/")

# EIP-3009 TransferWithAuthorization — the message x402 signs to move USDC.
TRANSFER_WITH_AUTHORIZATION = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]
EIP712_DOMAIN = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]


def eip3009_typed_data(with_domain_type: bool) -> dict:
    """The `typed_data` block for a policy condition.

    Privy evaluates an `ethereum_typed_data_message` condition only when this
    `types` map matches the signing request's `types` EXACTLY — including
    whether `EIP712Domain` is present, and field order. On a mismatch the
    condition is false. Clients differ on whether they send `EIP712Domain`, so
    the policy declares one rule for each shape.
    """
    types = {"TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION}
    if with_domain_type:
        types = {"EIP712Domain": EIP712_DOMAIN, **types}
    return {"types": types, "primary_type": "TransferWithAuthorization"}


def canonicalize(obj) -> str:
    """RFC 8785 JSON canonicalization for the payloads used here (objects,
    arrays, strings, integers, booleans): sorted keys, no insignificant
    whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class PrivyError(RuntimeError):
    def __init__(self, method, path, status, text):
        super().__init__(f"Privy {method} {path} -> {status}: {text}")
        self.status = status
        self.text = text


class PrivyClient:
    def __init__(self, app_id: str, app_secret: str, authorization_private_key: str = ""):
        self.app_id = app_id
        self._auth_key_b64 = (authorization_private_key or "").replace("wallet-auth:", "")
        self.session = requests.Session()
        self.session.auth = (app_id, app_secret)
        self.session.headers.update({"privy-app-id": app_id, "Content-Type": "application/json"})

    @classmethod
    def from_env(cls):
        missing = [k for k in ("PRIVY_APP_ID", "PRIVY_APP_SECRET") if not os.environ.get(k, "").strip()]
        if missing:
            raise SystemExit(f"Missing {', '.join(missing)} in .env")
        return cls(os.environ["PRIVY_APP_ID"].strip(), os.environ["PRIVY_APP_SECRET"].strip(),
                   os.environ.get("PRIVY_AUTHORIZATION_PRIVATE_KEY", "").strip())

    # ── request signing ──────────────────────────────────────────────────────
    def sign(self, method: str, url: str, body) -> str:
        if not self._auth_key_b64:
            raise SystemExit("PRIVY_AUTHORIZATION_PRIVATE_KEY is required to sign this request.")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        payload = {"version": 1, "method": method, "url": url.rstrip("/"),
                   "body": body, "headers": {"privy-app-id": self.app_id}}
        key = serialization.load_der_private_key(base64.b64decode(self._auth_key_b64), password=None)
        sig = key.sign(canonicalize(payload).encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return base64.b64encode(sig).decode()

    def _req(self, method, path, body=None, signed=False, params=None):
        url = f"{PRIVY_BASE}{path}"
        headers = {}
        if signed:
            headers["privy-authorization-signature"] = self.sign(method, url, body)
        r = self.session.request(method, url, params=params, timeout=30, headers=headers,
                                 data=None if body is None else canonicalize(body))
        if not r.ok:
            raise PrivyError(method, path, r.status_code, r.text)
        return r.json() if r.content else {}

    # ── wallets ──────────────────────────────────────────────────────────────
    def get_wallet(self, wallet_id):
        return self._req("GET", f"/v1/wallets/{wallet_id}")

    def find_wallet_by_address(self, address):
        page = self._req("GET", "/v1/wallets", params={"address": address, "chain_type": "ethereum"})
        for w in page.get("data", []):
            if (w.get("address") or "").lower() == address.lower():
                return w
        raise SystemExit(f"No Privy wallet in app {self.app_id} has address {address}. "
                         "Check that PRIVY_APP_ID is the app behind the AgentCore connector.")

    def update_wallet(self, wallet_id, body, signed):
        return self._req("PATCH", f"/v1/wallets/{wallet_id}", body=body, signed=signed)

    def rpc(self, wallet_id, body):
        """Call the wallet's RPC endpoint as the authorization-key signer."""
        return self._req("POST", f"/v1/wallets/{wallet_id}/rpc", body=body, signed=True)

    # ── condition sets and policies ──────────────────────────────────────────
    def create_condition_set(self, name, owner_id=None):
        body = {"name": name}
        if owner_id:
            body["owner_id"] = owner_id
        return self._req("POST", "/v1/condition_sets", body=body)["id"]

    def add_condition_set_items(self, set_id, addresses):
        # Matching is exact and case-sensitive: store lowercase and as-given.
        values = list(dict.fromkeys(v for a in addresses for v in (a, a.lower())))
        return self._req("POST", f"/v1/condition_sets/{set_id}/condition_set_items",
                         body=[{"value": v} for v in values])

    def delete_condition_set(self, set_id):
        return self._req("DELETE", f"/v1/condition_sets/{set_id}")

    def create_policy(self, name, rules, owner_id=None):
        body = {"version": "1.0", "name": name, "chain_type": "ethereum", "rules": rules}
        if owner_id:
            body["owner_id"] = owner_id
        return self._req("POST", "/v1/policies", body=body)["id"]

    def delete_policy(self, policy_id):
        return self._req("DELETE", f"/v1/policies/{policy_id}")


def wallet_update_mode(wallet: dict, authorization_id: str):
    """Decide how this app may update the wallet's policy_ids.

    Returns (signed: bool, problem: str | None). A wallet with no owner can be
    updated with the app secret alone. A wallet owned by the AgentCore
    authorization key needs a request signed with that key. A wallet owned by
    anyone else (for example, the end user) cannot be changed by the app.
    """
    owner = wallet.get("owner_id")
    if not owner:
        return False, None
    if authorization_id and owner == authorization_id:
        return True, None
    return False, (
        f"wallet {wallet.get('id')} is owned by {owner}, not by this app's authorization key "
        f"({authorization_id or 'unset'}). Only the owner can change its policies. Attach the "
        "policy when the wallet is delegated (Privy AgentCore SDK wallet hub), or ask the owner "
        "to sign the update."
    )
