"""Live proof — a Privy policy controls whether AgentCore `ProcessPayment` succeeds.

This drives a *real* x402 payment through AgentCore Payments
(`generate_payment_header` -> `ProcessPayment` -> the Privy connector signs the
EIP-3009 typed data) in three steps, the Stripe/Privy analogue of the Coinbase
CDP demo:

  0. BASELINE — the wallet's policies removed. ProcessPayment must SUCCEED,
     which proves that delegation, funding, and the session are in order.
     Otherwise any later refusal could have an unrelated cause, so the demo stops.
  1. NEGATIVE — a fail-closed policy that allows only a decoy recipient. The
     merchant's `payTo` matches no ALLOW rule, so Privy refuses to sign and
     ProcessPayment must FAIL with a policy error (any other error makes the
     step inconclusive).
  2. POSITIVE CONTROL — the same policy shape, allowing the real merchant.
     ProcessPayment must SUCCEED. Without this step a policy that denies
     everything (for example, because its typed-data `types` do not match what
     the signer sends) would look like a working guardrail. This step produces a
     signed payment header but never sends it to the merchant, so no USDC moves
     (it does draw $0.001 from a throwaway session budget). POSITIVE_CONTROL=0
     skips it.

The wallet's original `policy_ids` are restored at the end.

Requires: the provisioned stack in .env (PAYMENT_MANAGER_ARN, INSTRUMENT_ID,
PAYMENT_CONNECTOR_ID, WALLET_ADDRESS or PRIVY_WALLET_ID), a funded and delegated
wallet, AWS creds, and Privy app credentials.

    python setup/privy_policy_payment_demo.py
"""

import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv  # noqa: E402

from utils import ENV_FILE, client_token, load_env  # noqa: E402

load_dotenv(ENV_FILE, override=True)

from privy_client import PrivyClient, wallet_update_mode  # noqa: E402
from privy_policy_setup import build_allowlist_rules, describe_wallet, resolve_wallet  # noqa: E402

from bedrock_agentcore.payments import PaymentManager  # noqa: E402

PAID_ENDPOINT = os.environ.get("PAID_ENDPOINT", "https://x402-test.genesisblock.ai/api/weather")
DECOY_RECIPIENT = os.environ.get("DECOY_RECIPIENT", "0x000000000000000000000000000000000000dEaD")
POSITIVE_CONTROL = os.environ.get("POSITIVE_CONTROL", "1") != "0"


def fetch_402() -> dict:
    r = requests.get(PAID_ENDPOINT, timeout=30)
    print(f"  GET {PAID_ENDPOINT} -> {r.status_code}")
    if r.status_code != 402:
        raise SystemExit(f"Expected HTTP 402 from the paid endpoint; got {r.status_code}")
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:200]}
    return {"statusCode": r.status_code, "headers": dict(r.headers), "body": body}


def merchant_pay_to(challenge) -> str:
    accepts = challenge["body"].get("accepts") or []
    evm = [a for a in accepts if str(a.get("network", "")).startswith("eip155")]
    if not evm:
        raise SystemExit("The 402 challenge has no EVM option.")
    return evm[0]["payTo"]


def try_pay(mgr, c, label):
    """Attempt to settle the 402 via AgentCore in a fresh session. Returns
    (True, "") if a payment header was produced, else (False, error text)."""
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
            payment_required_request=fetch_402(),
            network_preferences=["eip155:84532", "base-sepolia"],
            client_token=str(uuid.uuid4()),
            payment_connector_id=c["payment_connector_id"],
        )
        print("  -> ProcessPayment produced a payment header.")
        return True, ""
    except Exception as e:  # noqa: BLE001 - surface the service's verbatim reason
        print(f"  -> ProcessPayment FAILED: {type(e).__name__}: {e}")
        return False, str(e)


def is_policy_refusal(err: str) -> bool:
    return "policy" in err.lower()


def main() -> int:
    c = load_env()
    mgr = PaymentManager(payment_manager_arn=c["payment_manager_arn"], region_name=c["region"])
    privy = PrivyClient.from_env()
    wallet = resolve_wallet(privy)
    describe_wallet(wallet)
    signed, problem = wallet_update_mode(wallet, os.environ.get("PRIVY_AUTHORIZATION_ID", "").strip())
    if problem:
        raise SystemExit(f"Cannot run the demo: {problem}")
    original = wallet.get("policy_ids") or []

    merchant = merchant_pay_to(fetch_402())
    created = []  # (policy_id, condition_set_id)

    def use_policy(name, allowed):
        set_id = privy.create_condition_set(name)
        privy.add_condition_set_items(set_id, [allowed])
        policy_id = privy.create_policy(name, build_allowlist_rules(set_id))
        created.append((policy_id, set_id))
        privy.update_wallet(wallet["id"], {"policy_ids": [policy_id]}, signed=signed)
        print(f"\nAttached policy {policy_id}: allow `to` == {allowed}")

    rc = 0
    try:
        privy.update_wallet(wallet["id"], {"policy_ids": []}, signed=signed)
        ok, _ = try_pay(mgr, c, f"0) BASELINE — pay merchant {merchant}; no Privy policy:")
        if not ok:
            print("  STOP: the payment fails even without a policy, so the policy steps would be "
                  "inconclusive. Fix this first (delegation, funding, session).")
            return 2
        print("  OK: delegation, funding, and session are in order.")

        use_policy("DEMO allow decoy only", DECOY_RECIPIENT)
        ok, err = try_pay(mgr, c, f"1) NEGATIVE — pay merchant {merchant}; only the decoy is allowed:")
        if ok:
            print("  FAIL: the policy did not block signing.")
            rc = 1
        elif not is_policy_refusal(err):
            print("  FAIL (inconclusive): ProcessPayment failed, but not with a policy error.")
            rc = 1
        else:
            print("  OK: Privy refused to sign, so ProcessPayment failed.")

        if POSITIVE_CONTROL and rc == 0:
            use_policy("DEMO allow merchant", merchant)
            ok, _ = try_pay(mgr, c, f"2) POSITIVE CONTROL — pay merchant {merchant}; merchant allowed:")
            if ok:
                print("  OK: the same policy shape signs an allowed payment, so step 1 was a real "
                      "policy decision, not a blanket deny.")
            else:
                print("  FAIL: the allowed payment was refused too. The policy is denying every "
                      "payment — check the typed-data `types` with setup/privy_policy_probe.py, "
                      "and check funding and delegation.")
                rc = 1
    finally:
        privy.update_wallet(wallet["id"], {"policy_ids": original}, signed=signed)
        for policy_id, set_id in created:
            privy.delete_policy(policy_id)
            privy.delete_condition_set(set_id)
        print(f"\nCleanup: restored policy_ids={original}; deleted {len(created)} demo policies.")

    print("\n✅ Privy policy enforcement confirmed end to end." if rc == 0 else "\n❌ Demo failed.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
