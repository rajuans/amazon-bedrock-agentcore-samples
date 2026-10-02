"""Live proof — the Privy policy decides whether AgentCore `ProcessPayment` succeeds.

This drives a *real* x402 payment through AgentCore Payments
(`generate_payment_header` -> `ProcessPayment` -> the Privy connector signs the
EIP-3009 typed data), the Stripe/Privy analogue of the Coinbase CDP demo.

AgentCore wallets are user-owned, so the app cannot swap the wallet's policies.
It does not need to: the policy created by `privy_policy_setup.py` screens the
recipient against a condition set that the app owns, and changing a condition
set changes the policy's behavior immediately. The demo therefore flips the
condition set and checks each outcome:

  0. ALLOWED  — the set holds the real merchant. ProcessPayment must SUCCEED.
     This proves that delegation, funding, and the session are in order AND
     that the policy's rules match what the signer sends (a policy whose
     typed-data `types` never match would refuse this payment too).
  1. NEGATIVE — the set holds only a decoy recipient. ProcessPayment must FAIL.
  2. ALLOWED  — the merchant again. ProcessPayment must SUCCEED again. Because
     only the condition set changed between steps, 0-1-2 together show the
     refusal in step 1 came from the policy.

Note: AgentCore currently reports a Privy policy refusal as a generic
`InternalServerException` ("Something went wrong in processPayment"), which the
SDK retries before giving up, rather than as a policy error (Coinbase CDP
refusals come back as `AccessDeniedException ... blocked by a policy`). The demo
therefore accepts either error in step 1, and relies on step 2 to confirm it.

The condition set's original contents are restored at the end. No payment
header is sent to the merchant, so no USDC moves (each step draws $0.001 from a
throwaway session budget).

Requires: `privy_policy_setup.py` has run (PRIVY_POLICY_ID, PRIVY_CONDITION_SET_ID)
and the policy governs the agent signer — attached to the wallet, or set as the
signer's policy at delegation. Plus a funded, delegated wallet, AWS creds, and
Privy app credentials.

    python setup/privy_policy_payment_demo.py
"""

import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv  # noqa: E402

from utils import ENV_FILE, client_token, load_env, require_env  # noqa: E402

load_dotenv(ENV_FILE, override=True)

from privy_client import PrivyClient, governing_policy_ids  # noqa: E402
from privy_policy_setup import describe_wallet, resolve_wallet  # noqa: E402

from bedrock_agentcore.payments import PaymentManager  # noqa: E402

PAID_ENDPOINT = os.environ.get("PAID_ENDPOINT", "https://x402-test.genesisblock.ai/api/weather")
DECOY_RECIPIENT = os.environ.get("DECOY_RECIPIENT", "0x000000000000000000000000000000000000dEaD")


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
    auth_id = os.environ.get("PRIVY_AUTHORIZATION_ID", "").strip()
    policy_id = require_env("PRIVY_POLICY_ID")
    set_id = require_env("PRIVY_CONDITION_SET_ID")

    wallet = resolve_wallet(privy)
    describe_wallet(wallet)
    governing = governing_policy_ids(wallet, auth_id)
    if policy_id not in governing:
        raise SystemExit(
            f"Policy {policy_id} does not govern the agent signer (governing: {governing}). "
            "Attach it first — see setup/privy_policy_setup.py.")

    merchant = merchant_pay_to(fetch_402())
    original = privy.get_condition_set_items(set_id)
    print(f"\nPolicy {policy_id} governs the agent signer; recipient condition set {set_id} "
          f"currently holds {original}")

    rc = 0
    try:
        privy.replace_condition_set_items(set_id, [merchant])
        ok, err = try_pay(mgr, c, f"0) ALLOWED — condition set = merchant {merchant}:")
        if not ok:
            if is_policy_refusal(err):
                print("  FAIL: the policy refused an allowed payment. Its typed-data `types` do not "
                      "match what the signer sends — run setup/privy_policy_probe.py.")
                return 1
            print("  STOP: the payment fails for a reason other than the policy, so the policy "
                  "steps would be inconclusive. Fix this first (delegation, funding, session).")
            return 2
        print("  OK: delegation, funding, and the policy's rules all check out for an allowed payment.")

        privy.replace_condition_set_items(set_id, [DECOY_RECIPIENT])
        ok, err = try_pay(mgr, c, f"1) NEGATIVE — condition set = decoy {DECOY_RECIPIENT} only:")
        generic = False
        if ok:
            print("  FAIL: the policy did not block signing.")
            rc = 1
        elif is_policy_refusal(err):
            print("  Refused with a policy error.")
        elif "InternalServerException" in err:
            generic = True
            print("  Refused, but AgentCore reported a generic InternalServerException rather than a "
                  "policy error. Step 2 confirms whether the policy caused it.")
        else:
            print("  FAIL (inconclusive): ProcessPayment failed with an unexpected error.")
            rc = 1

        if rc == 0:
            privy.replace_condition_set_items(set_id, [merchant])
            ok, _ = try_pay(mgr, c, f"2) ALLOWED AGAIN — condition set = merchant {merchant}:")
            if ok:
                print("  OK: allowed again. Only the condition set changed between steps, so the "
                      "refusal in step 1 was the policy's recipient rule.")
                if generic:
                    print("  NOTE: the policy is enforced, but the refusal surfaced as "
                          "InternalServerException — callers cannot tell it from an outage.")
            else:
                print("  FAIL: the allowed payment was refused after the negative step.")
                rc = 1
    finally:
        privy.replace_condition_set_items(set_id, original or [merchant])
        print(f"\nCleanup: restored condition set {set_id} to {original or [merchant]}.")

    print("\n✅ Privy policy enforcement confirmed end to end." if rc == 0 else "\n❌ Demo failed.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
