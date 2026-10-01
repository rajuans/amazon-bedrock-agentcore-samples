"""Optional — attach a Privy signing-layer policy to the embedded wallet.

This is the fail-secure backstop of the recipient + per-transaction guardrails,
the Stripe/Privy analogue of the Coinbase CDP policy. The Privy policy engine
evaluates every signing operation against the policies attached to the wallet
(`policy_ids`) and is **fail-closed**: within a method, a request that matches no
ALLOW rule is denied, and an unlisted method defaults to DENY.

x402's EVM "exact" scheme does NOT broadcast a transaction — the wallet signs an
EIP-3009 `TransferWithAuthorization` as **EIP-712 typed data** via
`eth_signTypedData_v4`; a facilitator submits it on-chain. So the rule matches the
typed-data message fields by path:

  • `to`    -> recipient allowlist  (in_condition_set, referencing a condition set)
  • `value` -> per-transaction cap  (lte, USDC base units as hex)
  • domain `chainId` -> pin the chain (Base Sepolia 84532)

Because unmatched signing requests default to DENY, a single ALLOW rule gated on
all three conditions yields a fail-closed allowlist + cap: a payment to a
non-allowlisted recipient, above the cap, or on the wrong chain simply matches no
ALLOW rule and is refused at signing time.

CRITICAL: the typed-data `types` map must match the signing request EXACTLY, or
the condition evaluates to FALSE (it does not skip). For this ALLOW-allowlist
shape a mismatch fails closed (denies the payment) — safe. A DENY-based denylist
would instead fail OPEN on a mismatch; that is the gap the AgentCore Payments
pentest found in an OFAC `to` denylist, and why this sample uses an allowlist.

Uses the Privy REST API directly (HTTP Basic app-id:app-secret + the
`privy-app-id` header), matching Privy's documented curl examples. For the demo
the condition set and policy are created WITHOUT an owner, so the app secret
alone can manage them. In production, set PRIVY_OWNER_ID and sign owner-authorized
requests with the P-256 authorization key (`privy-authorization-signature`).

    python setup/privy_policy_setup.py            # resolve wallet id from WALLET_ADDRESS
    python setup/privy_policy_setup.py <wallet_id>

Env knobs (fall back to .env / the sample defaults):
    RECIPIENT_ALLOWLIST   comma-separated merchant `to` addresses to allow
    PER_TX_CAP_USD        per-transaction USDC cap (converted to 6-dp base units)
    PRIVY_OWNER_ID        optional owner id for the condition set + policy

Docs: https://docs.privy.io/controls/policies
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

import requests
from dotenv import load_dotenv

from utils import ENV_FILE, require_env, write_env_values

load_dotenv(ENV_FILE, override=True)

PRIVY_BASE = os.environ.get("PRIVY_API_BASE", "https://api.privy.io").rstrip("/")
CHAIN_ID = os.environ.get("CHAIN_ID", "84532")  # Base Sepolia testnet

# Merchant recipient(s) to allow — the x402 `payTo`, NOT the token contract.
RECIPIENT_ALLOWLIST = [
    a.strip()
    for a in os.environ.get(
        "RECIPIENT_ALLOWLIST", "0xA27f7cB624B57C79d7F9de03ae9F5C705c2858dB"
    ).split(",")
    if a.strip()
]
PER_TX_CAP_USD = float(os.environ.get("PER_TX_CAP_USD", "0.50"))
# USDC has 6 decimals; the typed-data `value` field is in base units. Privy
# compares typed-data uint256 fields as hex.
PER_TX_CAP_BASE_UNITS = int(round(PER_TX_CAP_USD * 1_000_000))
PER_TX_CAP_HEX = hex(PER_TX_CAP_BASE_UNITS)

OWNER_ID = os.environ.get("PRIVY_OWNER_ID", "").strip() or None

# EIP-3009 TransferWithAuthorization is the message x402 signs for USDC. The
# `types` map must match the signing request exactly or the condition is false.
EIP3009_TYPED_DATA = {
    "types": {
        "TransferWithAuthorization": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
        ]
    },
    "primary_type": "TransferWithAuthorization",
}


class PrivyClient:
    """Minimal Privy REST client (Basic auth + privy-app-id header)."""

    def __init__(self):
        self.app_id = require_env("PRIVY_APP_ID")
        self.session = requests.Session()
        self.session.auth = (self.app_id, require_env("PRIVY_APP_SECRET"))
        self.session.headers.update({
            "privy-app-id": self.app_id,
            "Content-Type": "application/json",
        })

    def _req(self, method, path, **kwargs):
        r = self.session.request(method, f"{PRIVY_BASE}{path}", timeout=30, **kwargs)
        if not r.ok:
            raise RuntimeError(f"Privy {method} {path} -> {r.status_code}: {r.text}")
        return r.json() if r.content else {}

    # ── condition sets ────────────────────────────────────────────────────────
    def create_condition_set(self, name):
        body = {"name": name}
        if OWNER_ID:
            body["owner_id"] = OWNER_ID
        return self._req("POST", "/v1/condition_sets", json=body)["id"]

    def add_condition_set_items(self, set_id, values):
        # Store both lowercase and checksummed casings — matching is case-sensitive.
        items = []
        seen = set()
        for v in values:
            for cased in (v, v.lower()):
                if cased not in seen:
                    seen.add(cased)
                    items.append({"value": cased})
        return self._req("POST", f"/v1/condition_sets/{set_id}/condition_set_items", json=items)

    # ── policies ──────────────────────────────────────────────────────────────
    def create_policy(self, rules, name="x402 recipient allowlist and per-tx cap"):
        body = {"version": "1.0", "name": name, "chain_type": "ethereum", "rules": rules}
        if OWNER_ID:
            body["owner_id"] = OWNER_ID
        return self._req("POST", "/v1/policies", json=body)["id"]

    def delete_policy(self, policy_id):
        return self._req("DELETE", f"/v1/policies/{policy_id}")

    # ── wallets ─────────────────────────────────────────────────────────────--
    def get_wallet(self, wallet_id):
        return self._req("GET", f"/v1/wallets/{wallet_id}")

    def resolve_wallet_id(self, address):
        """Find the Privy wallet id backing an EVM address (list + match)."""
        target = address.lower()
        cursor = None
        while True:
            path = "/v1/wallets?chain_type=ethereum&limit=100"
            if cursor:
                path += f"&cursor={cursor}"
            page = self._req("GET", path)
            for w in page.get("data", page.get("wallets", [])):
                if (w.get("address") or "").lower() == target:
                    return w["id"]
            cursor = page.get("next_cursor")
            if not cursor:
                raise RuntimeError(
                    f"No Privy wallet found for address {address}. Pass the Privy "
                    "wallet id explicitly: python setup/privy_policy_setup.py <wallet_id>"
                )

    def attach_policy(self, wallet_id, policy_ids):
        # Without an owner on the wallet, Basic auth suffices. With an owner, this
        # PATCH must carry a privy-authorization-signature from the P-256 key.
        return self._req("PATCH", f"/v1/wallets/{wallet_id}", json={"policy_ids": policy_ids})


def build_allowlist_rule(condition_set_id):
    """A fail-closed ALLOW rule: approved recipient + under cap + right chain."""
    return {
        "name": "Allow x402 USDC transfer to an approved recipient under the cap",
        "method": "eth_signTypedData_v4",
        "action": "ALLOW",
        "conditions": [
            {
                "field_source": "ethereum_typed_data_domain",
                "field": "chainId",
                "operator": "eq",
                "value": CHAIN_ID,
            },
            {
                "field_source": "ethereum_typed_data_message",
                "field": "to",
                "operator": "in_condition_set",
                "value": condition_set_id,
                "typed_data": EIP3009_TYPED_DATA,
            },
            {
                "field_source": "ethereum_typed_data_message",
                "field": "value",
                "operator": "lte",
                "value": PER_TX_CAP_HEX,
                "typed_data": EIP3009_TYPED_DATA,
            },
        ],
    }


def main(wallet_id_arg=None):
    privy = PrivyClient()

    wallet_id = wallet_id_arg or os.environ.get("PRIVY_WALLET_ID", "").strip()
    if not wallet_id:
        wallet_id = privy.resolve_wallet_id(require_env("WALLET_ADDRESS"))
    print(f"Target Privy wallet id: {wallet_id}")

    set_id = privy.create_condition_set("x402 approved recipients")
    privy.add_condition_set_items(set_id, RECIPIENT_ALLOWLIST)
    print(f"Created approved-recipients condition set {set_id} with {RECIPIENT_ALLOWLIST}")

    policy_id = privy.create_policy([build_allowlist_rule(set_id)])
    print(f"Created policy {policy_id}")

    # Preserve any policies already attached to the wallet.
    current = privy.get_wallet(wallet_id).get("policy_ids", [])
    privy.attach_policy(wallet_id, list(dict.fromkeys([*current, policy_id])))

    write_env_values(PRIVY_WALLET_ID=wallet_id, PRIVY_CONDITION_SET_ID=set_id,
                     PRIVY_POLICY_ID=policy_id)

    print(f"\nAttached Privy policy {policy_id} to wallet {wallet_id}")
    print(f"  method:           eth_signTypedData_v4 (fail-closed: unmatched => DENY)")
    print(f"  recipient `to` in condition set {set_id} ({RECIPIENT_ALLOWLIST})")
    print(f"  `value` <= {PER_TX_CAP_HEX} base units (${PER_TX_CAP_USD:.2f} USDC)")
    print(f"  domain chainId == {CHAIN_ID} (Base Sepolia)")
    print("\nRemove it after testing:  python setup/privy_policy_remove.py")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) == 2 else None)
