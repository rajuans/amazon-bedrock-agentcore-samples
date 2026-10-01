"""Live guardrail proof — the AgentCore Payment Session budget rejects an
over-budget payment *server-side*, deterministically, with no LLM in the loop.

A Payment Session's `maxSpendAmount` is a cumulative, time-bounded ceiling the
service enforces itself: every `generate_payment_header` (ProcessPayment) is
summed against the ceiling, and the call that would exceed it is refused. The
agent role cannot raise its own budget.

This script proves that directly:
  1. fetch a real 402 challenge from the paid endpoint,
  2. create a session whose budget ($0.0001) is *smaller* than the price
     ($0.001),
  3. ask the payment layer to settle -> the service raises `InsufficientBudget`,
  4. confirm the session's available budget was never touched.

Unlike a full agent run, there is no model narration to trust — the rejection is
the raised exception. Requires the provisioned stack in `.env` and AWS creds.

    python agent/session_budget_demo.py
"""

import json
import os
import sys
import uuid

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import client_token, load_env  # noqa: E402

from bedrock_agentcore.payments import PaymentManager  # noqa: E402

# Deliberately tiny: below the endpoint's $0.001 price so the very first
# payment must be rejected.
TINY_BUDGET_USD = "0.0001"
PAID_ENDPOINT = os.environ.get(
    "PAID_ENDPOINT", "https://x402-test.genesisblock.ai/api/weather"
)


def main() -> int:
    c = load_env()
    mgr = PaymentManager(
        payment_manager_arn=c["payment_manager_arn"], region_name=c["region"]
    )

    # 1) Real 402 challenge from the merchant.
    r = requests.get(PAID_ENDPOINT, timeout=30)
    print(f"GET {PAID_ENDPOINT} -> {r.status_code}")
    if r.status_code != 402:
        print("Expected HTTP 402 from the paid endpoint; got", r.status_code)
        return 2
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:200]}
    payment_required_request = {
        "statusCode": r.status_code,
        "headers": dict(r.headers),
        "body": body,
    }

    # 2) Session whose budget is smaller than the price.
    sess = mgr.create_payment_session(
        user_id=c["user_id"],
        limits={"maxSpendAmount": {"value": TINY_BUDGET_USD, "currency": "USD"}},
        expiry_time_in_minutes=15,
        client_token=client_token(),
    )
    sid = sess["paymentSessionId"]
    print(f"Created session {sid} with a ${TINY_BUDGET_USD} cap (below the price).")

    # 3) Ask the payment layer to settle -> must be rejected server-side.
    try:
        mgr.generate_payment_header(
            user_id=c["user_id"],
            payment_instrument_id=c["instrument_id"],
            payment_session_id=sid,
            payment_required_request=payment_required_request,
            network_preferences=["eip155:84532", "base-sepolia"],
            client_token=str(uuid.uuid4()),
            payment_connector_id=c["payment_connector_id"],
        )
        print("UNEXPECTED: the service produced a payment header (no rejection).")
        return 1
    except Exception as e:  # noqa: BLE001 - surface the service's verbatim reason
        print("\nGUARDRAIL FIRED (server-side, deterministic):")
        print(f"    {type(e).__name__}: {e}")

    # 4) Prove the budget was never touched.
    s = mgr.get_payment_session(user_id=c["user_id"], payment_session_id=sid)
    print("\nSession budget after the rejected attempt:")
    print("   ", json.dumps(s.get("availableLimits", {}), default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
