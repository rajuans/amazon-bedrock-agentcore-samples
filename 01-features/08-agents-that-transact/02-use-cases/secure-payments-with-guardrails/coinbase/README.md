# Secure Payment Agent — Strands + AgentCore Payments + Coinbase CDP

A sample **autonomous payment agent** that buys a paid (x402-gated) resource,
paying in **USDC on Base Sepolia (testnet)** through **Amazon Bedrock AgentCore
Payments** with **Coinbase CDP** as the wallet provider — wrapped in
**layered, policy-enforced spending guardrails**.

The agent never holds open-ended access to funds and cannot raise its own limits.
Every control that matters is enforced by infrastructure (a policy engine, the
wallet provider, and a budgeted session), not by the model's prompt.

> **Testnet only.** Base Sepolia with free USDC from
> [faucet.circle.com](https://faucet.circle.com/). Testnet USDC has no value.

For a file-by-file explanation of the code, see
[`docs/CODE_WALKTHROUGH.md`](docs/CODE_WALKTHROUGH.md). For the threat model, see
[`docs/SECURITY.md`](docs/SECURITY.md).

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
| **AgentCore Policy** (Cedar + Dogwood) | per-transaction cap + recipient allowlist before execution; with Dogwood temporal policies, also recipient provenance, a velocity limit, and a rolling spend cap | [`policies/agentcore_policy.cedar`](policies/agentcore_policy.cedar), [`policies/dogwood/`](policies/dogwood/) |
| **Coinbase CDP Policy Engine** | recipient `to` allowlist **+** per-transaction `value` cap on the EIP-3009 typed data, fail-secure, at signing time | [`policies/cdp_recipient_allowlist_policy.json`](policies/cdp_recipient_allowlist_policy.json) |
| **AgentCore Payment Session** | cumulative, time-bounded spend ceiling (`maxSpendAmount`) | [`setup/provision_payments.py`](setup/provision_payments.py) |
| **App-level check** | always-on cap + allowlist backstop | [`agent/guardrails_demo.py`](agent/guardrails_demo.py) |

A Payment Session caps *cumulative* spend only. Rejecting a *single* high-value
payment, or a payment to a *specific* recipient, needs the policy layers above.

## Verified live (Base Sepolia)

| Check | Result |
|---|---|
| Agent happy path | paid 0.001 USDC; txs [`0xd492c57d…4090`](https://sepolia.basescan.org/tx/0xd492c57db5c77e6cfc480d47adafca4d69ce0b18993a6d7f19ccbcce82fb4090) and, on a new wallet 2026-10-02, [`0x8c23cdad…7936`](https://sepolia.basescan.org/tx/0x8c23cdadb1559d17e8598c9cc0ce0f47a0ab593dbca17ab4ef95ef3263d47936) |
| Session budget (`session_budget_demo.py`) | refused server-side: `InsufficientBudget … Pending amount: 0.0001 USD, Transaction amount: 0.001000 USD`; budget untouched (re-run 2026-10-02) |
| CDP policy through AgentCore (`cdp_policy_payment_demo.py`, 2026-10-02) | (0) no policy → header produced; (1) decoy-only project policy → `AccessDeniedException — The request was blocked by a policy configured in your Coinbase Developer Platform project`; (2) merchant-allowed policy → header produced |
| Dogwood temporal policies | validated and replay-tested locally (15/15 checks); not deployed to a live Gateway |

An earlier version of the payment demo reported a CDP refusal that turned out to be
a lapsed delegation grant; the demo's baseline step now catches that and stops.

## Prerequisites

- An AWS account in a Region where AgentCore Payments is available (`us-east-1`,
  `us-west-2`, `eu-central-1`, `ap-southeast-2`), with credentials configured.
- **Python 3.10+**.
- A **Coinbase CDP** project ([portal.cdp.coinbase.com](https://portal.cdp.coinbase.com/)):
  a secret API key (ID + secret) with the `policies#manage` scope, a Wallet
  Secret, and **Delegated signing** enabled under the project's wallet security
  settings.
- The **Coinbase Wallets for AgentCore Payments** subscription in AWS Marketplace.
- An email inbox for the wallet's end user.
- Amazon Bedrock model access for the agent's LLM.

## Step by step

### 1. Install

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.coinbase.sample .env
```

### 2. Configure `.env`

Fill in at least `AWS_REGION`, `COINBASE_API_KEY_ID`, `COINBASE_API_KEY_SECRET`,
`COINBASE_WALLET_SECRET`, `LINKED_EMAIL`, and `USER_ID`. Values must be bare (no
quotes or trailing `;`). The setup scripts write the remaining keys back into `.env`.

### 3. Provision the payment stack

```bash
python setup/provision_stack.py
```

Creates (idempotently) four least-privilege IAM roles, a `CoinbaseCDP` credential
provider, a payment manager, and a payment connector, and writes their IDs to
`.env`. If the account is at its payment-manager quota (default 5), set
`PAYMENT_MANAGER_ARN` to an existing manager first; the script then adds the
connector to it.

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

The CLI also offers **Quick create** (`--provision-mode QUICK_CREATE`), which
provisions the CDP credentials for you after you authorize through Coinbase.
</details>

### 4. Create the wallet and the session

```bash
python setup/provision_payments.py
```

Writes `INSTRUMENT_ID`, `WALLET_ADDRESS`, and `SESSION_ID`, and prints the
Coinbase **WalletHub** link.

### 5. Fund the wallet and grant delegated signing

1. Fund `WALLET_ADDRESS` with Base Sepolia USDC at
   [faucet.circle.com](https://faucet.circle.com/).
2. Open the WalletHub link, sign in as `LINKED_EMAIL`, and grant delegated signing.

Delegation grants can lapse; if payments start failing with
`Delegated signing grant is not active`, grant it again here.

### 6. Check the CDP policy through AgentCore

```bash
python setup/cdp_policy_payment_demo.py
```

AgentCore provisions an *end-user / embedded* CDP wallet, whose signing is governed
by a **project-scoped** policy. The demo refuses to run if your project already has
one. It then runs three steps, creating a fresh session each time and calling
`ProcessPayment` against a real 402:

| Step | Project policy | `ProcessPayment` must |
|---|---|---|
| 0 | none | succeed (otherwise it stops: delegation, funding, or session is wrong) |
| 1 | allow only a decoy recipient | fail with a policy error |
| 2 | allow the merchant | succeed (proves the rule matches the signing request) |

Each policy is deleted after its step; payment headers are never sent, so no USDC
moves. Expected end: `✅ CDP policy enforcement confirmed end to end.`

For CDP *server* accounts, attach an account-scoped policy instead:

```bash
python setup/cdp_policy_setup.py "$WALLET_ADDRESS"    # attach
python setup/cdp_policy_remove.py "$WALLET_ADDRESS"   # detach + delete
```

### 7. Run the demos and the agent

```bash
python agent/guardrails_demo.py         # offline: app-level decisions
python agent/session_budget_demo.py     # live: InsufficientBudget, budget untouched
python agent/secure_payment_agent.py    # live: the agent buys the paid content (0.001 USDC)
```

### 8. Test the AgentCore Policy rules locally (optional, no AWS)

```bash
DOGWOOD=/path/to/dogwood python policies/dogwood/test_dogwood_policies.py   # 15/15 checks
```

See [`policies/dogwood/README.md`](policies/dogwood/README.md) to build the CLI and
deploy the rules to a Gateway.

### 9. Clean up

Delete the instrument, connector, and (if you created it) the manager — see the
cleanup section of the
[AgentCore Payments quick start](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html#payments-getting-started-cleanup).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ServiceQuotaExceededException … maxManagers limit exceeded` | account at its payment-manager quota | set `PAYMENT_MANAGER_ARN` to an existing manager and re-run step 3 |
| `ValidationException … Credential provider … already exists` on re-run | provider created by an earlier run | handled — the script looks it up by name |
| `AccessDeniedException … Delegated signing grant is not active` | delegation not granted, or lapsed | step 5 |
| Payment demo stops at step 0 | delegation, funding, or session problem — not the policy | fix that first; the demo will not report a policy result until step 0 passes |
| Payment demo: `A project-scoped CDP policy already exists` | your project has a policy the demo would conflict with | remove or reuse it first |
| Connector status `AWS_MARKETPLACE_SUBSCRIPTION_REQUIRED` | Marketplace subscription missing or not yet reflected | subscribe; in our run the status stayed even after payments worked, so test with step 6 |
| WalletHub link printed as `None` | older version of `provision_payments.py` | fixed — the link is read from `embeddedCryptoWallet.redirectUrl` |

## Repository layout

```
.
├── agent/
│   ├── secure_payment_agent.py   # autonomous x402 purchase (happy path)
│   ├── guardrails_demo.py        # offline: happy path, high amount, bad recipient
│   ├── session_budget_demo.py    # live: session budget rejects an over-budget payment
│   └── utils.py                  # .env helpers, idempotent create, status polling
├── setup/
│   ├── provision_stack.py        # IAM roles + CDP credential provider + manager + connector
│   ├── provision_payments.py     # per-user wallet + budgeted session
│   ├── cdp_policy_payment_demo.py # live: baseline / decoy / merchant through ProcessPayment
│   ├── cdp_policy_setup.py       # CDP rule builder; account-scoped attach (server accounts)
│   └── cdp_policy_remove.py      # detach + delete the account-scoped policy
├── policies/
│   ├── agentcore_policy.cedar    # per-tx cap + recipient allowlist (Cedar)
│   ├── dogwood/                  # temporal policies + local test suite
│   └── cdp_recipient_allowlist_policy.json
├── docs/
│   ├── SECURITY.md               # threat model + the four layers
│   └── CODE_WALKTHROUGH.md       # file-by-file walkthrough
├── .env.coinbase.sample
└── requirements.txt
```

## Security notes

- The `.env` pattern is for **local development only**. In deployed workloads,
  source credentials from AWS Secrets Manager or SSM Parameter Store; AgentCore
  Identity stores the provider credentials so the agent never sees long-term
  secrets.
- Never commit a real `.env` (it is git-ignored).

## References

- AgentCore Payments — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/payments-getting-started.html
- AgentCore Policy — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
- AgentCore temporal policies (Dogwood) — https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html
- Dogwood language guide — https://dogwood-policy.github.io/dogwood/index.html
- Coinbase CDP Policy Engine — https://docs.cdp.coinbase.com/wallets/security-and-policies/policy-engine/overview
- x402 protocol — https://docs.cdp.coinbase.com/x402/welcome
- Strands Agents — https://strandsagents.com/

## License

MIT-0. See [LICENSE](LICENSE).
