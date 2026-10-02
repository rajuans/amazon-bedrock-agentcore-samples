"""Live proof — a Coinbase CDP policy controls whether AgentCore `ProcessPayment` succeeds.

This is the integration story (not a standalone CDP sign call): we set up a CDP
Policy Engine rule, then drive a *real* x402 payment through AgentCore Payments
(`generate_payment_header` → `ProcessPayment` → the CDP connector signs the
EIP-3009 typed data), under two policies:

  1. NEGATIVE — a project-scoped policy that allows only a **decoy** recipient
     (not the merchant `payTo`). The real payment's `to` matches no accept rule,
     so the fail-secure engine refuses to sign and ProcessPayment must FAIL.
  2. POSITIVE CONTROL — the same rule shape allowing the real merchant.
     ProcessPayment must SUCCEED. Without this step, a rule that never matches
     the signing request (and so denies everything) would look like a working
     guardrail. The payment header is produced but never sent to the merchant,
     so no USDC moves. POSITIVE_CONTROL=0 skips it.

Each policy is deleted afterwards so the project is unblocked.

Why a **project-scoped** policy (not account-scoped): the wallet AgentCore
provisions is a CDP *end-user / embedded* account (signing op
`signEndUserEvmTypedData`). End-user accounts have no per-account policy attach
in the CDP SDK — you govern their signing with a policy at the **project** scope,
which applies to every end-user signing operation in the project. (Account-scoped
policies via `update_account` only work for CDP *server* accounts.)

Requires: the provisioned stack in .env (PAYMENT_MANAGER_ARN, INSTRUMENT_ID,
PAYMENT_CONNECTOR_ID), AWS creds, the CDP SDK, and CDP creds for the SAME project
the connector uses, with the `policies#manage` scope.

    python setup/cdp_policy_payment_demo.py

Env knobs:
    DECOY_RECIPIENT     the only allowed `to` in step 1 (default 0x…dEaD, ≠ merchant)
    POSITIVE_CONTROL    "0" to skip step 2 (default on)
"""

import asyncio
import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

os.environ.setdefault("CDP_TYPED_DATA_OP", "signEndUserEvmTypedData")

from cdp_policy_setup import TYPED_DATA_OP, _build_rule  # noqa: E402
from utils import client_token, load_env  # noqa: E402

from bedrock_agentcore.payments import PaymentManager  # noqa: E402

PAID_ENDPOINT = os.environ.get("PAID_ENDPOINT", "https://x402-test.genesisblock.ai/api/weather")
DECOY_RECIPIENT = os.environ.get("DECOY_RECIPIENT", "0x000000000000000000000000000000000000dEaD")
POSITIVE_CONTROL = os.environ.get("POSITIVE_CONTROL", "1") != "0"


def _fetch_402() -> dict:
    r = requests.get(PAID_ENDPOINT, timeout=30)
    print(f"  GET {PAID_ENDPOINT} -> {r.status_code}")
    if r.status_code != 402:
        raise SystemExit(f"Expected HTTP 402 from the paid endpoint; got {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:200]}
    return {"statusCode": r.status_code, "headers": dict(r.headers), "body": body}


def _merchant_pay_to() -> str:
    accepts = _fetch_402()["body"].get("accepts") or []
    evm = [a for a in accepts if str(a.get("network", "")).startswith("eip155")]
    if not evm:
        raise SystemExit("The 402 challenge has no EVM option.")
    return evm[0]["payTo"]


def _try_pay(mgr, c, label) -> bool:
    """Attempt to settle the 402 via AgentCore in a fresh session. True if a
    payment header was produced, False if ProcessPayment was refused."""
    print(f"\n{label}")
    session = mgr.create_payment_session(
        user_id=c["user_id"],
        limits={"maxSpendAmount": {"value": c["session_budget_usd"], "currency": "USD"}},
        expiry_time_in_minutes=15,
        client_token=client_token(),
    )
    try:
        mgr.generate_payment_header(
            user_id=c["user_id"],
            payment_instrument_id=c["instrument_id"],
            payment_session_id=session["paymentSessionId"],
            payment_required_request=_fetch_402(),
            network_preferences=["eip155:84532", "base-sepolia"],
            client_token=str(uuid.uuid4()),
            payment_connector_id=c["payment_connector_id"],
        )
        print("  -> ProcessPayment produced a payment header.")
        return True
    except Exception as e:  # noqa: BLE001 - surface the service's verbatim reason
        print(f"  -> ProcessPayment FAILED: {type(e).__name__}: {e}")
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
    merchant = _merchant_pay_to()
    async with CdpClient(**cdp_kwargs) as cdp:
        # Guard: don't clobber an existing project policy the user may rely on.
        existing = await cdp.policies.list_policies(scope="project")
        if getattr(existing, "policies", None):
            ids = ", ".join(p.id for p in existing.policies)
            raise SystemExit(
                f"A project-scoped CDP policy already exists ({ids}). This demo would "
                "conflict with it; remove or reuse it before running."
            )

        async def run_with_policy(allowed, label) -> bool:
            policy = await cdp.policies.create_policy(
                policy=CreatePolicyOptions(
                    scope="project",
                    description="DEMO x402 recipient allowlist",
                    rules=[_build_rule([allowed])],
                )
            )
            print(f"\nCreated project-scoped CDP policy {policy.id} "
                  f"({TYPED_DATA_OP}, allow `to` in [{allowed}])")
            try:
                return _try_pay(mgr, c, label)
            finally:
                await cdp.policies.delete_policy(id=policy.id)
                print(f"  Cleanup: deleted project policy {policy.id}")

        rc = 0
        if await run_with_policy(DECOY_RECIPIENT,
                                 f"1) NEGATIVE — pay merchant {merchant}; only the decoy is allowed:"):
            print("  FAIL: the policy did not block signing.")
            rc = 1
        else:
            print("  OK: the CDP Policy Engine refused to sign, so ProcessPayment failed.")

        if POSITIVE_CONTROL and rc == 0:
            if await run_with_policy(merchant,
                                     f"2) POSITIVE CONTROL — pay merchant {merchant}; merchant allowed:"):
                print("  OK: the same rule shape signs an allowed payment, so step 1 was a real "
                      "policy decision, not a blanket deny.")
            else:
                print("  FAIL: the allowed payment was refused too — the rule is denying every "
                      "payment (check the typed-data types and operation), or funding/delegation.")
                rc = 1

    print("\n✅ CDP policy enforcement confirmed end to end." if rc == 0 else "\n❌ Demo failed.")
    return rc


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
