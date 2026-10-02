# Secure Payment Agent — Strands + AgentCore Payments + Coinbase CDP

A sample **autonomous payment agent** that buys a paid (x402-gated) resource,
paying in **USDC on Base Sepolia (testnet)** through **Amazon Bedrock AgentCore
Payments** with **Coinbase CDP** as the wallet provider — wrapped in
**layered, policy-enforced spending guardrails**.

The agent never holds open-ended access to funds and cannot raise its own
limits. Every control that matters is enforced by infrastructure (a policy
engine, the wallet provider, and a budgeted session), not by the model's prompt.

> **Testnet only.** Base Sepolia with free USDC from
> [faucet.circle.com](https://faucet.circle.com/). Testnet USDC has no value.

## How it works

```
Agent (Strands + http_request)
  │  GET https://…/paid-api
  ├─► 402 Payment Required
  │        AgentCorePaymentsPlugin intercepts the 402
  │        → session budget check → sign USDC tx via Coinbase CDP → payment proof
  │        → retry with the payment header (PAYMENT-SIGNATURE for x402 v2, X-PAYMENT for v1)
  ├─► 200 OK  (agent receives the paid content)
  └─► Agent summarizes the result
```

## Layered guardrails (defense in depth)

| Layer | Enforces | Where |
|---|---|---|
| **AgentCore Policy** (Cedar + Dogwood) | per-transaction amount cap + recipient allowlist, evaluated before execution; with Dogwood temporal policies, also recipient provenance, a velocity limit, and a rolling spend cap | [`policies/agentcore_policy.cedar`](policies/agentcore_policy.cedar), [`policies/dogwood/`](policies/dogwood/) |
| **Coinbase CDP Policy Engine** | recipient `to` allowlist **+** per-transaction `value` cap on the EIP-3009 typed data, fail-secure, at signing time | [`policies/cdp_recipient_allowlist_policy.json`](policies/cdp_recipient_allowlist_policy.json) |
| **AgentCore Payment Session** | cumulative, time-bounded spend ceiling (`maxSpendAmount`) | created in [`setup/provision_payments.py`](setup/provision_payments.py) |
| **App-level check** | always-on cap + allowlist backstop | [`agent/guardrails_demo.py`](agent/guardrails_demo.py) |

> A Payment Session caps *cumulative* spend only. Rejecting a *single* high-value
> payment, or a payment to a *specific* recipient, requires the policy layers
> above — see [`docs/SECURITY.md`](docs/SECURITY.md).

## Repository layout

```
.
├── agent/
│   ├── secure_payment_agent.py   # the autonomous x402 purchase (happy path)
│   ├── guardrails_demo.py        # 3 scenarios: happy path, high amount, bad recipient
│   ├── session_budget_demo.py    # live: session budget rejects an over-budget payment
│   └── utils.py                  # env load/validate helpers
├── setup/
│   ├── provision_stack.py        # create IAM roles + CDP credential provider + manager + connector
│   ├── provision_payments.py     # create per-user wallet + budgeted session
│   ├── cdp_policy_setup.py       # attach CDP typed-data policy (recipient + cap)
│   ├── cdp_policy_remove.py      # detach + delete the CDP policy (cleanup)
│   └── cdp_policy_payment_demo.py # live: the CDP policy decides whether AgentCore ProcessPayment succeeds
├── policies/
│   ├── agentcore_policy.cedar    # per-tx cap + recipient allowlist (Cedar)
│   ├── dogwood/                  # temporal policies: provenance, velocity, rolling cap (+ tests)
│   └── cdp_recipient_allowlist_policy.json
├── docs/SECURITY.md              # threat model + the four guardrail layers
├── .env.coinbase.sample          # copy to .env; never commit real secrets
└── requirements.txt
```

## Prerequisites

- An AWS account in a region where AgentCore Payments is available
  (`us-east-1`, `us-west-2`, `eu-central-1`, `ap-southeast-2`), AWS CLI configured.
- **Python 3.10+** and **Node.js 20+** (for the AgentCore CLI).
- A **Coinbase CDP** account (API Key ID/Secret + Wallet Secret, delegated
  signing enabled) and the **Coinbase Wallets for AgentCore Payments** AWS
  Marketplace subscription.
- Amazon Bedrock model access for the agent's LLM.

## Quick start

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.coinbase.sample .env      # then fill in your values
```

**1 — Provision the shared payment stack** (IAM roles + Coinbase CDP credential
provider + PaymentManager + PaymentConnector). This raw-boto3 script mirrors the
public awslabs sample's 4-role privilege separation and writes every resulting
ARN/ID into `.env`:

```bash
python setup/provision_stack.py
```

<details><summary>Alternative: the AgentCore CLI</summary>

```bash
npm install -g @aws/agentcore
agentcore create --name PaymentSetup --framework Strands --protocol HTTP \
  --model-provider Bedrock --memory none
cd PaymentSetup
agentcore add payment-manager --name MyPaymentManager \
  --auto-payment true --default-spend-limit 1.00
agentcore add payment-connector --manager MyPaymentManager \
  --name MyCoinbaseConnector --provider CoinbaseCDP \
  --api-key-id "$COINBASE_API_KEY_ID" \
  --api-key-secret "$COINBASE_API_KEY_SECRET" \
  --wallet-secret "$COINBASE_WALLET_SECRET"
agentcore validate && agentcore deploy -y
agentcore status --type payment   # copy PAYMENT_MANAGER_ARN + PAYMENT_CONNECTOR_ID into ../.env
```
</details>

**2 — Create the per-user wallet + budgeted session:**

```bash
python setup/provision_payments.py
```

**3 — Fund the wallet + grant delegated signing** (once): fund `WALLET_ADDRESS`
at [faucet.circle.com](https://faucet.circle.com/) (Base Sepolia), then open the
printed Coinbase WalletHub URL and grant signing.

**4 — (Recommended) the CDP signing-layer policy** (recipient allowlist +
per-tx cap, fail-secure at signing). The API key needs the `policies#manage`
scope (CDP Portal). AgentCore provisions an *end-user / embedded* wallet, whose
signing is governed by a **project-scoped** policy; CDP *server* accounts use an
account-scoped policy attached with `cdp_policy_setup.py`.

```bash
# Prove it end to end through AgentCore, in three steps: (0) with no policy the
# payment must succeed — this checks delegation and funding first; (1) with a
# decoy-only project policy ProcessPayment must fail with a policy error; (2) with
# a merchant-allowed policy it must succeed again (positive control — shows the
# rule really matches, rather than denying everything). Each policy is deleted
# afterwards; no payment header is sent, so no USDC moves:
python setup/cdp_policy_payment_demo.py

# Server-account variant (attach/detach an account-scoped policy):
python setup/cdp_policy_setup.py "$WALLET_ADDRESS"   # attach
python setup/cdp_policy_remove.py "$WALLET_ADDRESS"  # detach + delete after testing
```

**4b — (Optional) test the Dogwood temporal policies locally** — no AWS
needed. Validates the policy set and replays 10 scenarios (injected recipient,
velocity, rolling spend cap, and more). See
[`policies/dogwood/README.md`](policies/dogwood/README.md) to build the CLI and
deploy the rules:

```bash
DOGWOOD=/path/to/dogwood python policies/dogwood/test_dogwood_policies.py
```

**5 — Run:**

```bash
python agent/secure_payment_agent.py   # autonomous purchase (happy path)
python agent/guardrails_demo.py         # guardrail rejections (runs offline)
python agent/session_budget_demo.py     # live: over-budget payment refused server-side
```

## Verified live (Base Sepolia)

This sample has been run end-to-end against the provisioned stack:

- **Happy path** — the agent hit the paid endpoint, got `402`, paid **0.001 USDC**
  via x402 on Base Sepolia, and received the content. Settlement tx:
  [`0xd492c57db5c77e6cfc480d47adafca4d69ce0b18993a6d7f19ccbcce82fb4090`](https://sepolia.basescan.org/tx/0xd492c57db5c77e6cfc480d47adafca4d69ce0b18993a6d7f19ccbcce82fb4090).
- **Session budget guardrail** — `session_budget_demo.py` created a session capped
  below the price and the service refused the payment **server-side** with
  `InsufficientBudget` (`Pending amount: 0.0001 USD, Transaction amount: 0.001000 USD`);
  the budget was never touched. No LLM narration involved — the rejection is the
  raised exception.
- **Session budget guardrail, re-run 2026-10-02** — same result
  (`InsufficientBudget`, budget untouched).
- **Happy path, re-run 2026-10-02** on a new wallet — paid 0.001 USDC, settlement
  tx [`0x8c23cdadb1559d17e8598c9cc0ce0f47a0ab593dbca17ab4ef95ef3263d47936`](https://sepolia.basescan.org/tx/0x8c23cdadb1559d17e8598c9cc0ce0f47a0ab593dbca17ab4ef95ef3263d47936).
- **CDP signing-layer policy, verified 2026-10-02** — `cdp_policy_payment_demo.py`
  through AgentCore `ProcessPayment`: (0) no policy → payment header produced;
  (1) decoy-only project policy → `AccessDeniedException — The request was
  blocked by a policy configured in your Coinbase Developer Platform project`;
  (2) merchant-allowed policy → payment header produced. Both policies were
  deleted afterwards. An earlier version of the demo reported a CDP refusal that
  turned out to be a lapsed delegation grant; the baseline step now catches that
  and stops.
- **Dogwood temporal policies** (`policies/dogwood/`) are validated and
  replay-tested locally with the `dogwood` 1.0 CLI against a copy of
  AgentCore's documented event schema: 10/10 scenarios pass. They have not yet
  been deployed to a live AgentCore Gateway in this sample.

## Security notes

- The `.env` pattern is for **local development only**. In deployed workloads,
  source credentials from AWS Secrets Manager / SSM Parameter Store; AgentCore
  Identity stores the provider credentials so the agent never sees long-term
  secrets. See [`docs/SECURITY.md`](docs/SECURITY.md).
- Never commit a real `.env` (it is git-ignored).

## References (public)

- AgentCore Payments — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html
- AgentCore Policy — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- AgentCore temporal policies (Dogwood) — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html
- Dogwood language guide — https://dogwood-policy.github.io/dogwood/index.html
- AWS samples — https://github.com/awslabs/agentcore-samples (`01-features/08-agents-that-transact`)
- Coinbase CDP security & policies — https://docs.cdp.coinbase.com/wallets/security-and-policies/security-overview
- x402 protocol — https://docs.cdp.coinbase.com/x402/welcome
- Strands Agents — https://strandsagents.com/

## License

MIT-0. See [LICENSE](LICENSE).
