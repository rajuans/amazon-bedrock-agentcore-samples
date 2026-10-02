"""Step 2 of setup — create the per-user wallet (instrument) and a budgeted session.

Run AFTER `setup/provision_stack.py`, which provisions the shared payment stack
(IAM roles + Stripe/Privy credential provider + PaymentManager + PaymentConnector)
and writes PAYMENT_MANAGER_ARN + PAYMENT_CONNECTOR_ID into .env. (Equivalently,
you can provision the stack with the AgentCore CLI — `agentcore add
payment-manager` / `add payment-connector --provider StripePrivy` — and paste
those two values in.)

    python setup/provision_stack.py       # step 1: shared stack
    python setup/provision_payments.py     # step 2: this script

The payment instrument / session APIs are provider-agnostic — the only Privy
specifics are the delegation flow (granted through the Privy AgentCore SDK
frontend) and that the wallet is a Privy embedded wallet.

Docs: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))

from dotenv import load_dotenv

from utils import ENV_FILE, client_token, print_summary, require_env, write_env_values

load_dotenv(ENV_FILE, override=True)

from bedrock_agentcore.payments import PaymentManager

REGION = require_env("AWS_REGION")
PAYMENT_MANAGER_ARN = require_env("PAYMENT_MANAGER_ARN")
PAYMENT_CONNECTOR_ID = require_env("PAYMENT_CONNECTOR_ID")
USER_ID = require_env("USER_ID")
EMAIL = require_env("LINKED_EMAIL")
NETWORK = os.environ.get("NETWORK", "ETHEREUM")
SESSION_BUDGET_USD = os.environ.get("SESSION_BUDGET_USD", "1.00")

manager = PaymentManager(payment_manager_arn=PAYMENT_MANAGER_ARN, region_name=REGION)

# 1) Create the per-user embedded crypto wallet (payment instrument).
instrument = manager.create_payment_instrument(
    user_id=USER_ID,
    payment_connector_id=PAYMENT_CONNECTOR_ID,
    payment_instrument_type="EMBEDDED_CRYPTO_WALLET",
    payment_instrument_details={
        "embeddedCryptoWallet": {
            "network": NETWORK,  # ETHEREUM -> Base Sepolia (testnet)
            "linkedAccounts": [{"email": {"emailAddress": EMAIL}}],
        }
    },
    client_token=client_token(),
)
instrument_id = instrument["paymentInstrumentId"]
details = instrument["paymentInstrumentDetails"]["embeddedCryptoWallet"]
wallet_address = details["walletAddress"]
redirect_url = details.get("redirectUrl")
# AgentCore returns the wallet address, not Privy's internal wallet id;
# setup/privy_policy_setup.py looks the wallet up by address.

# 2) Create a budgeted, time-bounded spending session (server-enforced guardrail).
session = manager.create_payment_session(
    user_id=USER_ID,
    limits={"maxSpendAmount": {"value": SESSION_BUDGET_USD, "currency": "USD"}},
    expiry_time_in_minutes=60,
    client_token=client_token(),
)
session_id = session["paymentSessionId"]

write_env_values(
    INSTRUMENT_ID=instrument_id,
    WALLET_ADDRESS=wallet_address,
    SESSION_ID=session_id,
    PAYMENT_MANAGER_ID=PAYMENT_MANAGER_ARN.split("/")[-1],
)

print_summary(
    "Provisioned wallet + session (written to .env)",
    instrument_id=instrument_id,
    wallet_address=wallet_address,
    session_id=session_id,
    session_budget_usd=SESSION_BUDGET_USD,
)
print(
    "\nNext:\n"
    f"  1. Fund the wallet with testnet USDC at https://faucet.circle.com/  (Base Sepolia,\n"
    f"     address {wallet_address}); verify at https://sepolia.basescan.org/address/{wallet_address}\n"
    "  2. Grant delegated signing for the Privy embedded wallet. AgentCore returns a\n"
    f"     delegation flow for the end user ({EMAIL}); if a redirect URL is provided, open it:\n"
    f"       {redirect_url}\n"
    "     Otherwise use the Privy AgentCore SDK frontend "
    "(https://github.com/privy-io/aws-agentcore-sdk).\n"
    "  3. (Recommended) Attach the Privy signing-layer policy, then verify it:\n"
    "       python setup/privy_policy_setup.py && python setup/privy_policy_probe.py\n"
    "  4. Run the agent:  python agent/secure_payment_agent.py"
)
