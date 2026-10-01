"""Live proof — a Coinbase CDP policy makes AgentCore `ProcessPayment` FAIL.

This is the integration story (not a standalone CDP sign call): we set up a CDP
Policy Engine rule, then drive a *real* x402 payment through AgentCore Payments
(`generate_payment_header` → `ProcessPayment` → the CDP connector signs the
EIP-3009 typed data). Because the policy refuses to sign, the payment fails —
the guardrail is enforced end-to-end through the managed payment product.

Why a **project-scoped** policy (not account-scoped): the wallet AgentCore
provisions is a CDP *end-user / embedded* account (signing op
`signEndUserEvmTypedData`). End-user accounts have no per-account policy attach
in the CDP SDK — you govern their signing with a policy at the **project** scope,
which applies to every end-user signing operation in the project. (Account-scoped
policies via `update_account` only work for CDP *server* accounts.)

The rule here allowlists a **decoy** recipient (not the merchant `payTo`), so the
real payment's `to` matches no accept rule and the fail-secure engine refuses to
sign. Flow:
  1. create a project-scoped CDP policy (allow only the decoy recipient),
  2. fetch the real 402 challenge from the paid endpoint,
  3. call `generate_payment_header` with a funded session → the CDP connector
     tries to sign → CDP policy REJECTS → ProcessPayment fails (printed verbatim),
  4. delete the policy (cleanup) so the project is unblocked.

Requires: the provisioned stack in .env (PAYMENT_MANAGER_ARN, INSTRUMENT_ID,
PAYMENT_CONNECTOR_ID), AWS creds, the CDP SDK, and CDP creds for the SAME project
the connector uses, with the `policies#manage` scope.

    python setup/cdp_policy_payment_demo.py

Env knobs:
    DECOY_RECIPIENT        the only allowed `to` (default 0x…dEaD, ≠ merchant)
    SETTLE_AFTER_REMOVE    "1" to retry after cleanup and settle real USDC (off)
"""

import asyncio
import json
import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

# A recipient that is deliberately NOT the merchant payTo, so the real payment's
# `to` field fails the allowlist and the fail-secure engine refuses to sign.
DECOY_RECIPIENT = os.environ.get("DECOY_RECIPIENT", "0x000000000000000000000000000000000000dEaD")

# Pin the rule to the decoy + the end-user signing op BEFORE importing the rule
# builder (it reads these at import time).
os.environ["RECIPIENT_ALLOWLIST"] = DECOY_RECIPIENT
os.environ.setdefault("CDP_TYPED_DATA_OP", "signEndUserEvmTypedData")

from cdp_policy_setup import RECIPIENT_ALLOWLIST, TYPED_DATA_OP, _build_rule  # noqa: E402
from utils import client_token, load_env  # noqa: E402

from bedrock_agentcore.payments import PaymentManager  # noqa: E402

PAID_ENDPOINT = os.environ.get("PAID_ENDPOINT", "https://x402-test.genesisblock.ai/api/weather")
SETTLE_AFTER_REMOVE = os.environ.get("SETTLE_AFTER_REMOVE", "0") == "1"


def _fetch_402() -> dict:
    r = requests.get(PAID_ENDPOINT, timeout=30)
    print(f"GET {PAID_ENDPOINT} -> {r.status_code}")
    if r.status_code != 402:
        raise SystemExit(f"Expected HTTP 402 from the paid endpoint; got {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:200]}
    return {"statusCode": r.status_code, "headers": dict(r.headers), "body": body}


def _try_pay(mgr, c, session_id, label) -> bool:
    """Attempt to settle the 402 via AgentCore. Returns True if a header was
    produced (payment would settle), False if it was rejected."""
    print(f"\n{label}")
    try:
        mgr.generate_payment_header(
            user_id=c["user_id"],
            payment_instrument_id=c["instrument_id"],
            payment_session_id=session_id,
            payment_required_request=_fetch_402(),
            network_preferences=["eip155:84532", "base-sepolia"],
            client_token=str(uuid.uuid4()),
            payment_connector_id=c["payment_connector_id"],
        )
        print("  -> ProcessPayment produced a payment header (payment would settle).")
        return True
    except Exception as e:  # noqa: BLE001 - surface the service's verbatim reason
        print("  -> ProcessPayment FAILED (guardrail fired):")
        print(f"     {type(e).__name__}: {e}")
        return False


async def main() -> int:
    c = load_env()
    mgr = PaymentManager(payment_manager_arn=c["payment_manager_arn"], region_name=c["region"])

    from cdp import CdpClient
    from cdp.policies.types import CreatePolicyOptions

    # The connector's CDP creds live under COINBASE_* in .env; CdpClient()
    # otherwise reads CDP_*. Pass them explicitly so either naming works.
    cdp_kwargs = {
        "api_key_id": os.environ.get("COINBASE_API_KEY_ID") or os.environ.get("CDP_API_KEY_ID"),
        "api_key_secret": os.environ.get("COINBASE_API_KEY_SECRET") or os.environ.get("CDP_API_KEY_SECRET"),
        "wallet_secret": os.environ.get("COINBASE_WALLET_SECRET") or os.environ.get("CDP_WALLET_SECRET"),
    }
    async with CdpClient(**cdp_kwargs) as cdp:
        # Guard: don't clobber an existing project policy the user may rely on.
        existing = await cdp.policies.list_policies(scope="project")
        if getattr(existing, "policies", None):
            ids = ", ".join(p.id for p in existing.policies)
            raise SystemExit(
                f"A project-scoped CDP policy already exists ({ids}). This demo would "
                "conflict with it; remove or reuse it before running."
            )

        policy = await cdp.policies.create_policy(
            policy=CreatePolicyOptions(
                scope="project",
                description="DEMO block payment recipient not allowlisted",
                rules=[_build_rule()],
            )
        )
        print(f"Created project-scoped CDP policy {policy.id}")
        print(f"  operation:      {TYPED_DATA_OP}")
        print(f"  allowed `to` in {RECIPIENT_ALLOWLIST}  (decoy — NOT the merchant)")

        # A normally-funded session, so we clear the budget check and reach the
        # CDP signing step where the policy actually fires.
        session = mgr.create_payment_session(
            user_id=c["user_id"],
            limits={"maxSpendAmount": {"value": c["session_budget_usd"], "currency": "USD"}},
            expiry_time_in_minutes=15,
            client_token=client_token(),
        )
        sid = session["paymentSessionId"]
        print(f"Payment session {sid} (budget {c['session_budget_usd']} USD — above the price)")

        rc = 0
        try:
            settled = _try_pay(
                mgr, c, sid,
                "Attempt 1 — pay the merchant WITH the CDP policy active:",
            )
            if settled:
                print("\nUNEXPECTED: the policy did not block signing.")
                rc = 1
            else:
                print("\n✅ The CDP Policy Engine refused to sign, so AgentCore ProcessPayment "
                      "failed — the guardrail held at the wallet layer.")
        finally:
            await cdp.policies.delete_policy(id=policy.id)
            print(f"\nCleanup: deleted project policy {policy.id}")

        if rc == 0 and SETTLE_AFTER_REMOVE:
            # Contrast: same call, policy gone → it now settles real testnet USDC.
            settled = _try_pay(
                mgr, c, sid,
                "Attempt 2 — same payment AFTER removing the policy (settles real USDC):",
            )
            print("  (settled)" if settled else "  (still failed — check funding/delegation)")

    return rc


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
